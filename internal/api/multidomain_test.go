// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// Every other AuthConfig in this suite holds exactly one trust domain — our
// own — so IsOwn() is unconditionally true and isAdmin only ever reads domain
// zero's grants. The per-domain decisions this MR exists to add are therefore
// invisible to the rest of the suite: widening isAdmin across domains, or
// dropping the IsOwn() scoping on the self-match, leaves it entirely green.
//
// These specs drive a two-domain AuthConfig through the real mux, so the tier
// switch runs against a certificate that was *trusted* and *foreign* — the one
// combination nothing else produces.
var _ = Describe("Authorisation across trust domains", func() {
	const ownSubject = "agent1"

	var (
		ctx        context.Context
		myCA       *ca.CA
		mux        http.Handler
		caCert     *x509.Certificate
		caKey      *rsa.PrivateKey
		foreignCA  *x509.Certificate
		foreignKey *ecdsa.PrivateKey
	)

	// foreignLeaf issues a client certificate from the foreign issuer, so it
	// verifies under that domain's anchor and no other.
	foreignLeaf := func(cn string, ppCliAuth bool) *x509.Certificate {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if ppCliAuth {
			v, err := asn1.Marshal("true")
			Expect(err).NotTo(HaveOccurred())
			tmpl.ExtraExtensions = []pkix.Extension{{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39},
				Value: v,
			}}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, foreignCA, &key.PublicKey, foreignKey)
		Expect(err).NotTo(HaveOccurred())
		leaf, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return leaf
	}

	// foreignCRL is an empty, currently valid CRL from the foreign issuer.
	foreignCRL := func() *x509.RevocationList {
		GinkgoHelper()
		now := time.Now()
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Hour),
			NextUpdate: now.Add(24 * time.Hour),
		}, foreignCA, foreignKey)
		Expect(err).NotTo(HaveOccurred())
		crl, err := x509.ParseRevocationList(der)
		Expect(err).NotTo(HaveOccurred())
		return crl
	}

	// foreignCRLRevoking is a currently valid CRL from the foreign issuer that
	// lists the given serials.
	foreignCRLRevoking := func(serials ...*big.Int) *x509.RevocationList {
		GinkgoHelper()
		now := time.Now()
		var entries []x509.RevocationListEntry
		for _, sn := range serials {
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   sn,
				RevocationTime: now.Add(-time.Minute),
			})
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:                    big.NewInt(2),
			ThisUpdate:                now.Add(-time.Hour),
			NextUpdate:                now.Add(24 * time.Hour),
			RevokedCertificateEntries: entries,
		}, foreignCA, foreignKey)
		Expect(err).NotTo(HaveOccurred())
		crl, err := x509.ParseRevocationList(der)
		Expect(err).NotTo(HaveOccurred())
		return crl
	}

	// buildWithRevocation wires the same two-domain mux but lets the spec decide
	// the foreign domain's CRLs and the policy, which is what the middleware's
	// revocation arm is actually parameterised by.
	buildWithRevocation := func(crls []*x509.RevocationList, policy string) http.Handler {
		GinkgoHelper()
		// The domain grants admin to ops-admin, because a foreign client with no
		// grant is denied above the public tier anyway -- so only an admitted
		// client can show that revocation is what took the access away.
		domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
			[]*x509.Certificate{foreignCA}, map[string]bool{"ops-admin": true}, false)
		domain.SetRevocationSet(api.NewClientCRLSet(crls, []*x509.Certificate{foreignCA}))

		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			ClientRevocationPolicy: policy,
			Domains: []api.TrustDomain{
				api.OwnTrustDomain(caCert, map[string]bool{"puppet-server": true}, true),
				domain,
			},
		}
		return server.Routes()
	}

	// buildCounting is buildWithRevocation with the refusal callback wired, so a
	// spec can see which refusals the counter would record.
	buildCounting := func(crls []*x509.RevocationList, policy string, onRefusal func(string)) http.Handler {
		GinkgoHelper()
		domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
			[]*x509.Certificate{foreignCA}, map[string]bool{"ops-admin": true}, false)
		domain.SetRevocationSet(api.NewClientCRLSet(crls, []*x509.Certificate{foreignCA}))

		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			ClientRevocationPolicy: policy,
			OnRevocationRefusal:    onRefusal,
			Domains: []api.TrustDomain{
				api.OwnTrustDomain(caCert, map[string]bool{"puppet-server": true}, true),
				domain,
			},
		}
		return server.Routes()
	}

	// build wires a mux whose second trust domain is the foreign issuer, with
	// the grants under test.
	//
	// The domain is given a real, current CRL. The default revocation policy is
	// require, so without one every foreign client is rejected before the tier
	// switch is reached — which would make these specs pass for the wrong
	// reason. What is under test here is who is authorised; revocation itself is
	// clientcrl_test.go's job.
	build := func(foreignAdmins map[string]bool, foreignPpCliAuth bool) http.Handler {
		GinkgoHelper()
		domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
			[]*x509.Certificate{foreignCA}, foreignAdmins, foreignPpCliAuth)
		domain.SetRevocationSet(api.NewClientCRLSet(
			[]*x509.RevocationList{foreignCRL()}, []*x509.Certificate{foreignCA}))

		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			Domains: []api.TrustDomain{
				api.OwnTrustDomain(caCert, map[string]bool{"puppet-server": true}, true),
				domain,
			},
		}
		return server.Routes()
	}

	probe := func(handler http.Handler, method, path string, cert *x509.Certificate) int {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	BeforeEach(func() {
		ctx = context.Background()
		store := storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		block, _ := pem.Decode(cachedCrtPEM)
		var err error
		caCert, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		block, _ = pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		foreignCA, foreignKey = mintCert("Server CA", nil, nil, true)
		mux = build(nil, false)
	})

	Describe("admin authority is scoped to the domain that granted it", func() {
		It("does not let our own allow list admit a foreign certificate", func() {
			// puppet-server is an admin CN of domain zero. A foreign issuer
			// naming its client the same thing must not inherit that: a CN only
			// means something inside the namespace of the issuer that signed it.
			Expect(probe(mux, "POST", "/sign/all", foreignLeaf("puppet-server", false))).
				To(Equal(http.StatusForbidden))
		})

		It("does not let a foreign allow list admit our own certificate", func() {
			// The mirror. "ops-admin" is an admin of the foreign domain only, so
			// a certificate we issued with that name gets nothing from it.
			handler := build(map[string]bool{"ops-admin": true}, false)
			ours := issueClientCert("ops-admin", caCert, caKey)
			Expect(probe(handler, "POST", "/sign/all", ours)).To(Equal(http.StatusForbidden))
		})

		It("admits a foreign certificate named in that domain's own allow list", func() {
			// The feature working: an administrator of the Server CA, expressible
			// without trusting that name from anywhere else.
			handler := build(map[string]bool{"ops-admin": true}, false)
			Expect(probe(handler, "POST", "/sign/all", foreignLeaf("ops-admin", false))).
				NotTo(Equal(http.StatusForbidden))
		})
	})

	Describe("pp_cli_auth is honoured per domain", func() {
		It("ignores the extension from a domain that has not opted in", func() {
			// Domain zero honours pp_cli_auth by default. If that setting leaked
			// across domains, any issuer we trust for authentication could stamp
			// itself an administrator of this CA.
			Expect(probe(mux, "POST", "/sign/all", foreignLeaf("cli", true))).
				To(Equal(http.StatusForbidden))
		})

		It("honours it from a domain that has", func() {
			handler := build(nil, true)
			Expect(probe(handler, "POST", "/sign/all", foreignLeaf("cli", true))).
				NotTo(Equal(http.StatusForbidden))
		})
	})

	Describe("own-CA operations reject a trusted foreign certificate", func() {
		It("refuses renewal to a foreign client", func() {
			// tierOwnClient. The certificate authenticates — it is trusted — but
			// renewal mints a credential in our namespace from one in theirs.
			//
			// This pins the observable outcome, not the middleware gate on its
			// own: /certificate_renewal is the only tierOwnClient route, and
			// CA.Renew rejects a foreign certificate too, so removing the gate
			// here leaves this green. That is defence in depth working as
			// intended — the CA-layer gate is the primary and is pinned
			// directly in renewgate_test.go — but it does mean this spec cannot
			// tell the two apart.
			Expect(probe(mux, "POST", "/certificate_renewal", foreignLeaf(ownSubject, false))).
				To(Equal(http.StatusForbidden))
		})

		It("still allows renewal to our own client", func() {
			Expect(probe(mux, "POST", "/certificate_renewal", issueClientCert(ownSubject, caCert, caKey))).
				NotTo(Equal(http.StatusForbidden))
		})
	})

	Describe("the self-match is scoped to our own domain", func() {
		It("refuses a foreign certificate reading the same name's CSR", func() {
			// Without the IsOwn() scoping, a foreign certificate named agent1
			// could read *our* agent1's pending request — a public key and the
			// requested extensions, but the same defect class.
			Expect(probe(mux, "GET", "/certificate_request/"+ownSubject, foreignLeaf(ownSubject, false))).
				To(Equal(http.StatusForbidden))
		})

		It("still allows our own certificate to read its own CSR", func() {
			code := probe(mux, "GET", "/certificate_request/"+ownSubject,
				issueClientCert(ownSubject, caCert, caKey))
			Expect(code).NotTo(Equal(http.StatusForbidden))
		})
	})

	It("rejects a certificate no domain can verify", func() {
		// Attribution is the gate before any of the above: an issuer nobody
		// configured gets nothing, whatever its client is called.
		unrelatedCA, unrelatedKey := mintCert("Unrelated CA", nil, nil, true)
		stranger, _ := mintCert("puppet-server", unrelatedCA, unrelatedKey, false)

		Expect(probe(mux, "GET", "/certificate_status/whatever", stranger)).
			To(Equal(http.StatusForbidden))
	})

	Describe("revocation, through the middleware", func() {
		// The branch's headline guarantee is that a foreign client is checked
		// against its own issuer's CRLs. Everything that pinned it called
		// checkChainRevocation directly through the test shim, and the only
		// multi-domain fixture always installed a valid, empty CRL -- so the
		// entire revocation arm of the middleware could be deleted, or its
		// policy forced to skip, with the suite green.
		//
		// These drive the real mux, which is where the guarantee has to hold.
		It("takes admin away from a foreign administrator its issuer revoked", func() {
			admin := foreignLeaf("ops-admin", false)

			live := buildWithRevocation([]*x509.RevocationList{foreignCRL()}, "")
			Expect(probe(live, "POST", "/sign/all", admin)).NotTo(Equal(http.StatusForbidden),
				"the control: this administrator is admitted while its CRL says nothing")

			revoked := buildWithRevocation(
				[]*x509.RevocationList{foreignCRLRevoking(admin.SerialNumber)}, "")
			Expect(probe(revoked, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
		})

		It("refuses a foreign client when its issuer has no usable CRL, by default", func() {
			// The fail-closed default asserted where it is resolved rather than
			// where it is configured: this AuthConfig leaves the policy empty.
			admin := foreignLeaf("ops-admin", false)
			handler := buildWithRevocation(nil, "")
			Expect(probe(handler, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
		})

		It("admits a revoked foreign client only when the operator asked for skip", func() {
			admin := foreignLeaf("ops-admin", false)
			handler := buildWithRevocation(
				[]*x509.RevocationList{foreignCRLRevoking(admin.SerialNumber)}, api.RevocationSkip)
			Expect(probe(handler, "POST", "/sign/all", admin)).NotTo(Equal(http.StatusForbidden))
		})

		// The bulk endpoints take a list of names from the request body, and
		// CodeQL flagged both of them: handleSignMultiple and handleCleanMultiple
		// logged body.Certnames verbatim. The elements go through the same
		// sanitiser as a single CN, and the list itself is bounded, because one
		// request may carry thousands of names and a log line naming all of them
		// is write amplification bought with a single POST.
		It("sanitises and bounds a list of names from a request body", func() {
			out := api.SanitiseAllForLogForTest([]string{
				"good.example.com",
				"evil\n2026-01-01 ERROR forged log line",
				"carriage\rreturn",
			})
			Expect(out).To(HaveLen(3))
			Expect(out[0]).To(Equal("good.example.com"))
			Expect(out[1]).NotTo(ContainSubstring("\n"))
			Expect(out[2]).NotTo(ContainSubstring("\r"))

			many := make([]string, 100)
			for i := range many {
				many[i] = "node.example.com"
			}
			bounded := api.SanitiseAllForLogForTest(many)
			Expect(bounded).To(HaveLen(33), "32 names plus the elision marker")
			Expect(bounded[32]).To(Equal("…"))
		})

		It("sanitises a common name before logging it, on the branch that needs no trust", func() {
			// Every other CN log in the middleware needs a certificate that
			// verified against a configured domain. This one is on the failure
			// branch, so any client presenting any self-signed certificate
			// reaches it -- which makes it the worst member of the class, and it
			// was the one a sweep keyed on the clientCN identifier passed over.
			//
			// Pinned through captured output: the helper's own behaviour was
			// tested, but nothing asserted that any call site used it, so all six
			// could be deleted with the suite green.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(99),
				Subject:      pkix.Name{CommonName: "evil\nAuth: forged record"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			Expect(err).NotTo(HaveOccurred())
			stranger, err := x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())

			handler := buildWithRevocation([]*x509.RevocationList{foreignCRL()}, "")
			Expect(probe(handler, "GET", "/certificate_request/whatever", stranger)).
				To(Equal(http.StatusForbidden))

			// Asserting the substitution, not the absence of a raw newline:
			// slog's TextHandler quotes values, so an unsanitised CN also shows
			// no literal newline and an absence assertion passes either way.
			// That is the false-confidence shape this spec exists to avoid.
			Expect(buf.String()).To(ContainSubstring("\uFFFD"),
				"the control character must be replaced before it reaches the log")
			Expect(buf.String()).NotTo(ContainSubstring("evil\\nAuth"),
				"and not merely escaped by the handler, which a different handler need not do")
		})

		It("counts a refusal only when revocation information was missing", func() {
			// This counter drives the branch's only critical authentication
			// alert. Counting a *successful* revocation on it made that alert
			// driveable at will by the holder of a revoked certificate -- the one
			// population revocation exists to exclude -- while telling the
			// responder to refresh a CRL that was present, current and working.
			admin := foreignLeaf("ops-admin", false)

			var counted []string
			record := func(d string) { counted = append(counted, d) }

			// Revoked by a CRL that is present, current and verifying. Refused,
			// and that is the feature working: nothing to count.
			revoked := buildCounting(
				[]*x509.RevocationList{foreignCRLRevoking(admin.SerialNumber)}, "", record)
			Expect(probe(revoked, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
			Expect(counted).To(BeEmpty(),
				"a revocation that was found is not a refusal for want of a CRL")

			// No CRL at all. Same 403, entirely different cause.
			counted = nil
			missing := buildCounting(nil, "", record)
			Expect(probe(missing, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
			Expect(counted).To(ConsistOf("server-ca"))
		})

		It("neutralises the common name in a handler's own log line, not just the middleware's", func() {
			// The middleware's sanitisation was pinned through captured output.
			// The handler layer was not, so when clientCN stopped sanitising at
			// source, fourteen handler log sites reverted to raw and every spec
			// stayed green -- including the one written for the split, which
			// exercised the two helpers through export hooks and asserted nothing
			// about which one a call site chose. That is the shape the middleware
			// spec above exists to reject, repeated one layer down.
			//
			// PUT /clean is the sharp case: tierAdminOnly, reachable by a foreign
			// issuer with allow_pp_cli_auth, and its rate-limit warning is at Warn
			// so it is on by default.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(orig)

			hostile := foreignLeaf("ops\nlevel=ERROR msg=\"forged\"", true)
			handler := build(map[string]bool{}, true)

			// Six, because the rate-limit warning -- the site whose two siblings
			// were fixed and which was left raw -- only fires once the tracker
			// trips, and a single request never reaches it.
			for range 6 {
				req := httptest.NewRequest("PUT", "/clean",
					strings.NewReader(`{"certnames":["node1.test"]}`))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{hostile}}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				Expect(rec.Code).NotTo(Equal(http.StatusForbidden),
					"pp_cli_auth admits it, which is what makes the log line reachable")
			}
			// Scoped to the warning's own record, not the whole buffer: the other
			// lines in this handler already carry the neutralised name, so a
			// buffer-wide assertion passes with this one line left raw -- which
			// is exactly the line whose two siblings were fixed and it was not.
			var warned string
			for _, line := range strings.Split(buf.String(), "\n") {
				if strings.Contains(line, "High rate of destructive operations") {
					warned = line
				}
			}
			Expect(warned).NotTo(BeEmpty(),
				"the spec must actually reach the warning it exists to cover")
			Expect(warned).To(ContainSubstring("\uFFFD"))

			Expect(buf.String()).NotTo(ContainSubstring("\nlevel=ERROR"),
				"a newline must not survive to start a record of the attacker's choosing; "+
					"asserting the substitution and this, rather than the absence of a raw "+
					"newline alone, because TextHandler escapes one anyway and that check "+
					"would pass unsanitised")
		})

		It("truncates an over-long value at the documented boundary", func() {
			// The cutoff is a contract: sanitiseForLog is *not* used on
			// identities for exactly this reason -- a truncated name once cost
			// an agent with a long certname a permanent 403 on re-key renewal.
			// Asserting on both sides of the boundary is what stops the limit
			// drifting silently, which would either re-open the padding problem
			// or start truncating names that fit today.
			atLimit := strings.Repeat("a", 256)
			Expect(api.SanitiseForLog(atLimit)).To(Equal(atLimit),
				"a value exactly at the limit must survive whole")

			overLimit := strings.Repeat("a", 257)
			out := api.SanitiseForLog(overLimit)
			Expect(out).To(HaveSuffix("…"))
			Expect(strings.TrimSuffix(out, "…")).To(HaveLen(256),
				"one byte over must keep 256 and mark the cut")
		})

		It("cuts an over-long value on a rune boundary, not mid-character", func() {
			// The cut is in bytes, and this function is exported precisely for
			// values that are not ASCII by construction: a CRL's issuer DN is
			// chosen by whoever wrote the file. The spec above uses "a" repeated,
			// where every byte is a rune boundary, so it cannot see a cut landing
			// inside a multi-byte character -- and strings.Map does not repair
			// one, because a decoding error yields RuneError, which is not a
			// control character and passes straight through.
			//
			// Three-byte runes over the limit: 256 is not a multiple of 3, so a
			// naive slice at 256 lands inside the 86th character.
			overLimit := strings.Repeat("日", 100)
			Expect(len(overLimit)).To(BeNumerically(">", 256), "the fixture must exceed the cutoff")

			out := api.SanitiseForLog(overLimit)
			Expect(out).To(HaveSuffix("…"))

			body := strings.TrimSuffix(out, "…")
			Expect(utf8.ValidString(body)).To(BeTrue(),
				"a record carrying invalid UTF-8 is what a mid-rune cut produces")
			Expect(body).NotTo(ContainSubstring("\uFFFD"),
				"and the replacement character must come from sanitising a control "+
					"character, never from a cut this function made itself")
			Expect(len(body)).To(BeNumerically("<=", 256),
				"the cut may lose up to three bytes backing off, never gain any")
			Expect(len(body)).To(BeNumerically(">", 253),
				"and must back off to the nearest boundary, not further")
		})

		It("bounds a bulk list at the documented count", func() {
			// The slice form's own cutoff, separate from the per-value one: a
			// caller can pad a record with many short names as easily as one
			// long one, and only this limit stops that.
			names := make([]string, 40)
			for i := range names {
				names[i] = "node.test"
			}
			out := api.SanitiseAllForLogForTest(names)
			Expect(out).To(HaveLen(33), "32 names plus the marker")
			Expect(out[32]).To(Equal("…"))

			exact := make([]string, 32)
			for i := range exact {
				exact[i] = "node.test"
			}
			Expect(api.SanitiseAllForLogForTest(exact)).To(HaveLen(32),
				"a list exactly at the limit must not gain a marker")
		})

		It("neutralises the subject on the unauthenticated certificate fetch", func() {
			// The one subject log that precedes ValidateSubject, on the one
			// endpoint reachable with no client certificate at all. Every
			// sibling handler validates first and so logs a name the subject
			// grammar already constrains; this one cannot, because the "ca"
			// branch returns before validation and logging after it would lose
			// the line for the endpoint's commonest request.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(orig)

			handler := build(map[string]bool{}, true)
			req := httptest.NewRequest("GET",
				"/certificate/"+url.PathEscape("x\nlevel=ERROR msg=\"forged\""), nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			Expect(buf.String()).To(ContainSubstring("\uFFFD"),
				"the newline must be substituted, not merely escaped by the handler")
			Expect(buf.String()).NotTo(ContainSubstring("\nlevel=ERROR"))
		})

		It("neutralises certnames from the request body at the bulk endpoints", func() {
			// The helper had a spec; the two call sites that use it did not. A
			// certname arrives in the *body*, so unlike the CN it is not filtered
			// by certificate issuance at all -- any client permitted to call the
			// endpoint chooses it freely, which makes these the least constrained
			// injection points in the API.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(orig)

			handler := build(map[string]bool{}, true)
			admin := foreignLeaf("ops.example.com", true)

			for _, ep := range []struct{ method, path, record string }{
				{"POST", "/sign", "Signing certificates"},
				{"PUT", "/clean", "Cleaning certificates"},
			} {
				buf.Reset()
				req := httptest.NewRequest(ep.method, ep.path,
					strings.NewReader(`{"certnames":["node1.test\nlevel=ERROR msg=\"forged\""]}`))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{admin}}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				var logged string
				for _, line := range strings.Split(buf.String(), "\n") {
					if strings.Contains(line, ep.record) {
						logged = line
					}
				}
				Expect(logged).NotTo(BeEmpty(),
					"%s %s must reach the record this spec covers", ep.method, ep.path)
				Expect(logged).To(ContainSubstring("\uFFFD"),
					"the newline must be substituted, not merely escaped by the handler")
				Expect(buf.String()).NotTo(ContainSubstring("\nlevel=ERROR"))
			}
		})

		It("keeps a common name verbatim as an identity, and neutralises it only for logs", func() {
			// clientCN feeds the renewal handler's CN comparison and the subject
			// passed to Renew, so it has to be the certificate's value. It was
			// briefly sanitised at source, on the argument that a per-call-site
			// rule gets missed -- but the middleware reads the field directly
			// anyway, so the class was never closed there, and sanitiseForLog
			// truncates at 256 bytes, which this CA's certname grammar permits.
			// An agent with a long certname then got a permanent 403 on a re-key
			// renewal, its own correct CSR compared against a truncated name.
			long := strings.Repeat("a", 300) + ".example.com"
			req := httptest.NewRequest("GET", "/", nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
				Subject: pkix.Name{CommonName: long},
			}}}

			Expect(api.ClientCNForTest(req)).To(Equal(long),
				"an identity must survive intact, however long")

			// The display form is no longer a second function beside it -- that
			// left the choice at every call site -- but a method on the principal,
			// so a name reaches a record only after passing through it.
			rendered := api.PrincipalLogValueForTest("evil\nforged", nil).String()
			Expect(rendered).NotTo(ContainSubstring("\n"))
			Expect(rendered).To(ContainSubstring("\uFFFD"))
		})

		It("counts destructive operations per issuing domain, not by common name alone", func() {
			// ops-admin from our CA and ops-admin from the partner's are different
			// principals, and keyed on the bare name they shared a rate-limit
			// bucket. Five destructive operations from the partner left ours one
			// request away from an alert it had not earned -- and, read the other
			// way, either could spend the other's allowance to keep its own bulk
			// clean below the threshold.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			// Both domains grant ops-admin, which is the collision: the name is
			// admissible in each, and means a different principal in each.
			domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
				[]*x509.Certificate{foreignCA}, map[string]bool{"ops-admin": true}, false)
			domain.SetRevocationSet(api.NewClientCRLSet(
				[]*x509.RevocationList{foreignCRL()}, []*x509.Certificate{foreignCA}))
			server := api.New(myCA)
			server.AuthConfig = &api.AuthConfig{
				Domains: []api.TrustDomain{
					api.OwnTrustDomain(caCert, map[string]bool{"ops-admin": true}, true),
					domain,
				},
			}
			handler := server.Routes()

			clean := func(cert *x509.Certificate) {
				GinkgoHelper()
				req := httptest.NewRequest("PUT", "/clean",
					strings.NewReader(`{"certnames":["node1.test"]}`))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				Expect(rec.Code).NotTo(Equal(http.StatusForbidden),
					"both are administrators of the domain that named them")
			}

			// The threshold is five in a minute, so a sixth request in one bucket
			// warns. Five from theirs and one from ours is six requests across two
			// principals, neither of which has reached its own threshold.
			for range 5 {
				clean(foreignLeaf("ops-admin", false))
			}
			clean(issueClientCert("ops-admin", caCert, caKey))

			Expect(buf.String()).NotTo(ContainSubstring("High rate of destructive operations"),
				"one domain's traffic must not raise the alarm against another's administrator")
		})

		// PUT /certificate_status_by_serial was missed when the rest of the
		// handler set moved to principals, and the spec above did not notice
		// because it drives PUT /clean. One route's worth of coverage stood in
		// for the sweep.
		//
		// So these two pin the route itself, and between them every site on it:
		// the malformed-serial log, the accepted-serial log, the forced-revocation
		// audit line, and the rate-limit key. Reverting any one of the four to
		// clientCN(r) fails exactly one assertion here -- which is the point,
		// because a single spec covering the handler would leave three of them
		// free to drift back.
		Describe("revocation by serial, on every site the route has", func() {
			// A serial that is no longer the current certificate for its subject,
			// so it is revocable at all: issue, drop the record, issue again.
			supersededSerial := func(subject string) string {
				GinkgoHelper()
				res, err := myCA.Generate(ctx, subject, nil)
				Expect(err).NotTo(HaveOccurred())
				block, _ := pem.Decode(res.CertificatePEM)
				Expect(block).NotTo(BeNil())
				cert, err := x509.ParseCertificate(block.Bytes)
				Expect(err).NotTo(HaveOccurred())
				Expect(myCA.Storage.DeleteCert(ctx, subject)).To(Succeed())
				_, err = myCA.Generate(ctx, subject, nil)
				Expect(err).NotTo(HaveOccurred())
				return strings.ToUpper(cert.SerialNumber.Text(16))
			}

			// Both domains grant ops-admin, so the name alone cannot say who acted.
			twoDomainMux := func() http.Handler {
				GinkgoHelper()
				domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
					[]*x509.Certificate{foreignCA}, map[string]bool{"ops-admin": true}, false)
				domain.SetRevocationSet(api.NewClientCRLSet(
					[]*x509.RevocationList{foreignCRL()}, []*x509.Certificate{foreignCA}))
				server := api.New(myCA)
				server.AuthConfig = &api.AuthConfig{
					Domains: []api.TrustDomain{
						api.OwnTrustDomain(caCert, map[string]bool{"ops-admin": true}, true),
						domain,
					},
				}
				return server.Routes()
			}

			revokeSerialAs := func(handler http.Handler, cert *x509.Certificate, serial, body string) int {
				GinkgoHelper()
				req := httptest.NewRequest("PUT",
					"/puppet-ca/v1/certificate_status_by_serial/"+serial, strings.NewReader(body))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec.Code
			}

			It("names the vouching domain in all three of its log lines", func() {
				handler := twoDomainMux()
				serial := supersededSerial("by-serial-audit")

				var buf bytes.Buffer
				orig := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
				defer slog.SetDefault(orig)

				caller := foreignLeaf("ops-admin", false)

				// The malformed-serial branch, which returns before anything else
				// on the route runs.
				Expect(revokeSerialAs(handler, caller, "nothex", `{"desired_state":"revoked"}`)).
					To(Equal(http.StatusBadRequest))

				// And an accepted one, forced, so the audit line fires too.
				Expect(revokeSerialAs(handler, caller, serial,
					`{"desired_state":"revoked","force":true}`)).To(Equal(http.StatusNoContent))

				// Each anchored to its own message, and anchored on the CLOSING
				// quote of msg= rather than the message text alone. Without it
				// "PUT certificate_status_by_serial" is a prefix of "PUT
				// certificate_status_by_serial: malformed serial", so the
				// accepted-serial assertion would be satisfied by the
				// malformed-serial line and would survive a revert of its own
				// site -- a spec that passes by matching a different record.
				//
				// clientCN(r) renders "client=" with no domain at all, so a
				// revert of any single site fails exactly one of these three and
				// leaves the others green.
				for _, msg := range []string{
					"PUT certificate_status_by_serial: malformed serial",
					"PUT certificate_status_by_serial",
					"Forced revocation by serial",
				} {
					Expect(buf.String()).To(MatchRegexp(
						`msg="`+regexp.QuoteMeta(msg)+`"[^\n]*client\.cn=ops-admin[^\n]*client\.domain=[^\n]*server-ca`),
						"%s must name the domain that vouched for the caller", msg)
				}

				// And specifically not the bare form, anywhere on the route.
				Expect(buf.String()).NotTo(MatchRegexp(`client=ops-admin`),
					"a bare CN is not an identity once more than one issuer is trusted")
			})

			It("keys its destructive-op bucket on the principal, not the bare name", func() {
				handler := twoDomainMux()
				serial := supersededSerial("by-serial-bucket")

				var buf bytes.Buffer
				orig := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
				defer slog.SetDefault(orig)

				// Revoking the same serial again is idempotent, so this counts
				// six requests across two principals without needing six
				// certificates. Five in one bucket is under the threshold; six
				// would warn, which is what a shared bucket would produce.
				for range 5 {
					Expect(revokeSerialAs(handler, foreignLeaf("ops-admin", false), serial,
						`{"desired_state":"revoked","force":true}`)).To(Equal(http.StatusNoContent))
				}
				Expect(revokeSerialAs(handler, issueClientCert("ops-admin", caCert, caKey), serial,
					`{"desired_state":"revoked","force":true}`)).To(Equal(http.StatusNoContent))

				Expect(buf.String()).NotTo(ContainSubstring("High rate of destructive operations"),
					"the partner's ops-admin and ours must not share a rate-limit bucket here either")
			})
		})

		// Key() renders the CN with strconv.Quote. The separation of principals
		// is structural -- the domain half is itself %q-quoted, so the key is
		// injective in the CN either way -- and what the quoting buys is that
		// the key is unambiguous and printable: a CN carrying a newline, a
		// quote or a slash cannot produce a key that reads as a different
		// principal in an audit trail or a rate-limit table.
		It("renders the common name quoted, so a crafted one cannot read as another", func() {
			own := api.OwnTrustDomain(caCert, nil, false)

			Expect(api.PrincipalKeyForTest("ops-admin", &own)).
				To(ContainSubstring(`"ops-admin"`),
					"an unquoted CN would let a crafted name read as part of the key's structure")

			// The property that must hold whatever the rendering: no two names
			// share a key within one domain.
			seen := map[string]string{}
			for _, cn := range []string{
				"ops-admin", `ops-admin"`, `"ops-admin`, "ops/admin", `ops\admin`,
				"ops\nadmin", "", " ",
			} {
				key := api.PrincipalKeyForTest(cn, &own)
				Expect(seen).NotTo(HaveKey(key),
					"two names collided on one key: %q and %q", seen[key], cn)
				seen[key] = cn
			}

			// And a newline in a CN cannot break the key across lines.
			Expect(api.PrincipalKeyForTest("ops\nadmin", &own)).NotTo(ContainSubstring("\n"))
		})

		It("names the vouching domain in the record, not just the common name", func() {
			// The audit half of the same defect. A warning that a client is running
			// destructive operations at rate is actionable only if the reader can
			// tell which ops-admin it means, and the CN alone cannot say.
			own := api.OwnTrustDomain(caCert, nil, false)
			theirs := api.NewForeignTrustDomain("server-ca", nil, nil, nil, false)

			Expect(api.PrincipalKeyForTest("ops-admin", &own)).
				NotTo(Equal(api.PrincipalKeyForTest("ops-admin", &theirs)),
					"the same name from two issuers is two principals")
			Expect(api.PrincipalKeyForTest("ops-admin", nil)).
				NotTo(Equal(api.PrincipalKeyForTest("ops-admin", &own)),
					"and a name nothing has vouched for is a third")

			Expect(api.PrincipalLogValueForTest("ops-admin", &theirs).String()).
				To(ContainSubstring("server-ca"),
					"a record naming only the CN cannot say which principal acted")
		})

		It("treats an unrecognised policy as require, not as the most permissive arm", func() {
			// Validation rejects a bad policy string, but it lives two packages
			// away and runs on one construction path, so the enforcement point
			// must not read an unknown value as "check".
			admin := foreignLeaf("ops-admin", false)
			handler := buildWithRevocation(nil, "not-a-policy")
			Expect(probe(handler, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
		})
	})

})

var _ = Describe("denial logging", func() {
	// The middleware logs the request path and the client CN on every denial.
	// Both are attacker-influenced: net/http decodes %0A into a real newline, and
	// under client_ca the CN comes from an issuer the operator may not control.
	It("strips control characters from the logged path and CN", func() {
		Expect(api.SanitiseForLog("/certificate_status/a\nFAKE line")).
			To(Equal("/certificate_status/a�FAKE line"))
		Expect(api.SanitiseForLog("ops\r\nadmin")).To(Equal("ops��admin"))
	})

	It("passes an ordinary path through unchanged", func() {
		Expect(api.SanitiseForLog("/certificate_status/agent1.example.com")).
			To(Equal("/certificate_status/agent1.example.com"))
	})

	It("bounds the length, so a large request cannot pad the log", func() {
		got := api.SanitiseForLog(strings.Repeat("a", 500))
		Expect(len([]rune(got))).To(Equal(257), "256 runes plus the ellipsis")
	})

	It("passes a replacement character through unchanged", func() {
		// U+FFFD is not a control character, so it survives -- and a caller
		// supplying one produces output identical to a sanitised newline. That
		// collision is unavoidable with a single-rune replacement and is
		// accepted: what matters is that no control character reaches the log,
		// not that its origin is recoverable. The previous version of this spec
		// claimed to prevent the collision while demonstrating it, and pinned a
		// mapping branch that returned the rune it was given -- so it could not
		// have detected that branch being deleted.
		Expect(api.SanitiseForLog("a�b")).To(Equal("a�b"))
		Expect(api.SanitiseForLog("a\nb")).To(Equal("a�b"))
	})

})
