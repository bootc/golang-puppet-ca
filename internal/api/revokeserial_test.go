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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("PUT certificate_status_by_serial", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		mux    http.Handler
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-revokeserial-api-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		mux = api.New(myCA).Routes()
	})

	issue := func(subject string) string {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return strings.ToUpper(cert.SerialNumber.Text(16))
	}

	// superseded reproduces the orphan: an issued certificate that a later
	// issuance for the same subject displaced without retiring.
	superseded := func(subject string) string {
		old := issue(subject)
		Expect(store.DeleteCert(ctx, subject)).To(Succeed())
		issue(subject)
		return old
	}

	// crlSerials reads the CRL back through the API, canonically rendered.
	crlSerials := func() []string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil))
		Expect(rec.Code).To(Equal(http.StatusOK))
		block, _ := pem.Decode(rec.Body.Bytes())
		Expect(block).NotTo(BeNil())
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		out := make([]string, 0, len(crl.RevokedCertificateEntries))
		for _, e := range crl.RevokedCertificateEntries {
			out = append(out, strings.ToUpper(e.SerialNumber.Text(16)))
		}
		return out
	}

	put := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	revoke := func(serial, body string) *httptest.ResponseRecorder {
		return put("/puppet-ca/v1/certificate_status_by_serial/"+serial, body)
	}

	It("revokes the serial and answers 204", func() {
		serial := superseded("api-orphan")

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusNoContent))

		status := httptest.NewRecorder()
		mux.ServeHTTP(status, httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil))
		Expect(status.Code).To(Equal(http.StatusOK))
		block, _ := pem.Decode(status.Body.Bytes())
		Expect(block).NotTo(BeNil())
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(crl.RevokedCertificateEntries).To(HaveLen(1))
		Expect(strings.ToUpper(crl.RevokedCertificateEntries[0].SerialNumber.Text(16))).To(Equal(serial))
	})

	It("is reachable at the bare path as well as the /puppet-ca/v1 prefix", func() {
		serial := superseded("api-bare-path")

		rec := put("/certificate_status_by_serial/"+serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusNoContent))
	})

	It("answers 409 and names the remedy for the live certificate", func() {
		serial := issue("api-live")

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusConflict))
		Expect(rec.Body.String()).To(ContainSubstring("api-live"))
		// Actionable for a caller driving the API directly: the remedy is an
		// operation ("revoke that subject by name"), not a CLI flag they have no
		// way to pass. The flags follow as a parenthetical for CLI users.
		Expect(rec.Body.String()).To(ContainSubstring("revoke that subject by name"))
		Expect(rec.Body.String()).To(ContainSubstring("force set"))
	})

	It("revokes the live certificate when force is set", func() {
		serial := issue("api-forced")

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		defer slog.SetDefault(orig)

		rec := revoke(serial, `{"desired_state":"revoked","force":true}`)
		Expect(rec.Code).To(Equal(http.StatusNoContent))

		// This is the one spec here whose subject is a live credential being
		// taken out of circulation, so it asserts which serial went, not merely
		// that the request was accepted.
		Expect(crlSerials()).To(ConsistOf(serial))

		// The CA layer records the revocation but cannot see who asked for it,
		// so the handler attributes the forced case at the default level. Without
		// this the one act on this route worth reconstructing afterwards has no
		// caller in the log.
		//
		// Anchored, for the same reason as the sibling spec below: this serial is
		// a live certificate, so internal/ca writes the identical canonical value
		// into this buffer twice on its way through (the forced-live Warn and the
		// success Info). A bare ContainSubstring would hold with the handler's
		// line deleted outright.
		Expect(buf.String()).To(MatchRegexp(`Forced revocation by serial[^\n]*serial=` + serial))
	})

	It("does not emit the forced-path attribution for an ordinary revocation", func() {
		serial := superseded("api-unforced-log")

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		defer slog.SetDefault(orig)

		Expect(revoke(serial, `{"desired_state":"revoked"}`).Code).To(Equal(http.StatusNoContent))
		Expect(buf.String()).NotTo(ContainSubstring("Forced revocation by serial"))
	})

	It("carries the diagnosis, not a bare conflict, when the stored CRL is foreign", func() {
		// Same reasoning as the subject-keyed route's spec in api_test.go: the
		// status is 409 either way, so only a body assertion can see a revert.
		// This route matters more for that state than most — the docs now name
		// revocation by serial as the way to retire the certificate a failed
		// clean left behind, and this is the refusal an operator meets first.
		serial := superseded("api-foreign-crl")
		Expect(store.UpdateCRL(ctx, foreignCRL())).To(Succeed())

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusConflict))
		Expect(rec.Body.String()).To(ContainSubstring("needs a restart"))
	})

	It("answers 409, not 503, when the guard could not run", func() {
		// The stored certificate is unreadable, so the CA cannot show the serial
		// is not the one in circulation. That is a refusal of the request, not a
		// CA that cannot service it, and force is the way past it — which is
		// exactly what a 503 would tell the operator not to reach for. Without
		// this, deleting the handler's ErrSerialStateUnknown arm just falls
		// through to the catch-all and nothing notices.
		serial := issue("api-unreadable")
		Expect(os.WriteFile(store.SignedDir()+"/api-unreadable.pem",
			[]byte("not a certificate"), 0o600)).To(Succeed())

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusConflict))
		Expect(rec.Body.String()).To(ContainSubstring("api-unreadable"))
		Expect(rec.Body.String()).NotTo(ContainSubstring(tmpDir))
		Expect(crlSerials()).To(BeEmpty())

		// The phrase unique to ErrSerialStateUnknown. ErrSerialIsCurrent would
		// satisfy the assertions above too — same subject, same 409 — and it
		// also names "force set", which is why asserting that phrase
		// discriminated nothing and is no longer asserted here. Without this one
		// nothing separates "the guard could not run" from "the guard fired",
		// which is the entire reason the two sentinels exist.
		Expect(rec.Body.String()).To(ContainSubstring("retry once storage is healthy"))
	})

	It("answers 503 without leaking storage detail when the CA cannot service the request", func() {
		// The default arm. It must not be a 409: two of this route's three 409s
		// name force as the way forward (the foreign-CRL one does not), so a
		// transient storage fault answered as "conflict" would leave force the
		// likeliest thing an operator reaches for — disarming the
		// live-certificate guard for a reason that was never that guard.
		serial := superseded("api-unservable")
		// Corrupt the stored CRL so readStoredCRL fails with something that is
		// not one of the mapped sentinels.
		Expect(store.UpdateCRL(ctx, []byte("not a CRL"))).To(Succeed())

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusServiceUnavailable))
		Expect(rec.Body.String()).NotTo(ContainSubstring(tmpDir),
			"a CA-side message may name storage paths; it must stay in the log")
		Expect(rec.Body.String()).To(ContainSubstring("server log"))
	})

	It("answers 404 for a serial this CA never issued", func() {
		rec := revoke("DEADBEEF", `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusNotFound))
		Expect(rec.Body.String()).To(ContainSubstring("not found in inventory"))
	})

	It("answers 404 for an unknown serial even when force is set", func() {
		rec := revoke("DEADBEEF", `{"desired_state":"revoked","force":true}`)
		Expect(rec.Code).To(Equal(http.StatusNotFound))
		// The body, not just the status: ServeMux answers 404 for any path it has
		// no pattern for, so a status-only assertion would survive the route
		// being deleted. This is also the arm most worth pinning — ErrSerialUnknown
		// is the one refusal force must never override.
		Expect(rec.Body.String()).To(ContainSubstring("not found in inventory"))
	})

	It("answers 400 for a serial that is not hexadecimal", func() {
		rec := revoke("zzz", `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusBadRequest))
		Expect(rec.Body.String()).To(ContainSubstring("hexadecimal"))
	})

	It("logs the serial the CA acted on, not the one the caller typed", func() {
		// The handler and the CA both log this operation. If the handler logged
		// the raw path segment they would name different strings for one
		// request — "0a" against "A" — and the serial is exactly what an
		// operator greps for to correlate them.
		serial := issue("api-log-shape")

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		defer slog.SetDefault(orig)

		// Typed in a rendering the CA would canonicalise: lowercase and padded.
		typed := "000" + strings.ToLower(serial)
		rec := revoke(typed, `{"desired_state":"revoked","force":true}`)
		Expect(rec.Code).To(Equal(http.StatusNoContent))

		// Anchored to the handler's own record. A bare ContainSubstring(serial)
		// would be satisfied by the CA's lines, which log the same canonical
		// value into this buffer — so it would hold even with the handler's
		// serial attribute deleted. The Text handler puts msg and attrs on one
		// line, so the regexp ties the two together.
		Expect(buf.String()).To(MatchRegexp(`Forced revocation by serial[^\n]*serial=` + serial))
		Expect(buf.String()).NotTo(ContainSubstring(typed),
			"the raw path segment must not reach the log")
	})

	It("rejects a malformed serial at the edge, before the CA is asked", func() {
		// Validating here keeps the unvalidated segment out of *this handler's*
		// lines — not out of the log: the authorisation middleware logs
		// r.URL.Path verbatim when it denies a request, and on an admin-only
		// route that is exactly the untrusted caller. This spec cannot see that
		// either way, since api.New leaves AuthConfig nil and the middleware is
		// inert here. slog escapes regardless, so this is tidiness rather than
		// containment — but it also means the CA is never called with something
		// it would reject.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		defer slog.SetDefault(orig)

		rec := revoke("0A%0Aforged", `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusBadRequest))

		// Positive anchors first: a bare 400 plus a negative log assertion would
		// also pass if the request had failed earlier (decodeJSONBody and the
		// desired_state guard both answer 400 from this handler), or if nothing
		// had logged at all. These pin that the edge check is what fired.
		Expect(rec.Body.String()).To(ContainSubstring("hexadecimal"))
		Expect(buf.String()).To(ContainSubstring("malformed serial"))
		Expect(buf.String()).NotTo(ContainSubstring("forged"))
	})

	DescribeTable("rejects any desired_state but revoked",
		func(body string) {
			serial := superseded("api-desired-state")

			rec := revoke(serial, body)
			Expect(rec.Code).To(Equal(http.StatusBadRequest))
			// Which of the handler's three 400s fired. A regression in
			// NormaliseSerial would answer 400 at the edge before this guard was
			// reached, leaving the CRL empty and every Entry green while the
			// spec reported on a branch that never ran.
			Expect(rec.Body.String()).To(ContainSubstring("desired_state must be 'revoked'"))

			// Nothing was revoked: an unrecognised desired_state must never be
			// read as a request to revoke.
			crlRec := httptest.NewRecorder()
			mux.ServeHTTP(crlRec, httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil))
			block, _ := pem.Decode(crlRec.Body.Bytes())
			crl, err := x509.ParseRevocationList(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(crl.RevokedCertificateEntries).To(BeEmpty())
		},
		Entry("signed", `{"desired_state":"signed"}`),
		Entry("absent", `{}`),
		Entry("empty string", `{"desired_state":""}`),
		Entry("misspelt", `{"desired_state":"revoke"}`),
	)

	// The destructive-op tracker. Round three declined to cover this on the
	// grounds that it needed a repo-wide TLS-peer fixture; that was wrong. The
	// middleware is bypassed here (api.New leaves AuthConfig nil), so clientOf
	// falls back to reading the CN straight off r.TLS.PeerCertificates[0] with
	// no verification and reports it as unattributed,
	// so a bare certificate value is enough — withClientCert in auth_test.go
	// clones the request and sets that field, and nothing on the path checks it.
	// Revoking the same serial is idempotent, so repeated successful calls
	// exercise the counter without needing a certificate or an orphan per call.
	Describe("the destructive-op tracker", func() {
		var caller *x509.Certificate

		revokeAs := func(cert *x509.Certificate, serial string) *httptest.ResponseRecorder {
			req := httptest.NewRequest("PUT",
				"/puppet-ca/v1/certificate_status_by_serial/"+serial,
				strings.NewReader(`{"desired_state":"revoked"}`))
			req = withClientCert(req, cert)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			return rec
		}

		BeforeEach(func() {
			caller = &x509.Certificate{Subject: pkix.Name{CommonName: "cli-user"}}
		})

		It("warns once a caller crosses the threshold", func() {
			serial := superseded("api-destructive")

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			// Record warns above 5 in the window, so the sixth call is the one
			// that trips it.
			for i := 0; i < 6; i++ {
				Expect(revokeAs(caller, serial).Code).To(Equal(http.StatusNoContent))
			}

			// Anchored, and on the attribute KEYS: docs/ca-key-security.md
			// publishes this rendered line as a contract for operator alerting, so
			// a change to the field names would break every query built on it. A
			// bare ContainSubstring("cli-user") would not notice.
			//
			// This assertion read `client=cli-user` until the domain-scoping sweep
			// reached this route, and that is the shape worth noticing: the spec
			// was anchored to the contract the documentation publishes, but pinned
			// what this handler happened to emit -- which was not it. Every sibling
			// already logged the principal, and ca-key-security.md documents
			// client.cn/client.domain. So a green spec was holding one route on the
			// wrong side of a contract it named.
			Expect(buf.String()).To(MatchRegexp(
				`High rate of destructive operations detected[^\n]*client\.cn=cli-user[^\n]*client\.domain=unattributed[^\n]*operation=revoke`))
		})

		It("stays quiet below the threshold", func() {
			serial := superseded("api-destructive-quiet")

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			for i := 0; i < 5; i++ {
				Expect(revokeAs(caller, serial).Code).To(Equal(http.StatusNoContent))
			}

			Expect(buf.String()).NotTo(ContainSubstring("High rate of destructive operations"))
		})

		It("counts per caller, so one client cannot trip another's threshold", func() {
			serial := superseded("api-destructive-per-caller")
			other := &x509.Certificate{Subject: pkix.Name{CommonName: "other-user"}}

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			for i := 0; i < 5; i++ {
				Expect(revokeAs(caller, serial).Code).To(Equal(http.StatusNoContent))
			}
			Expect(revokeAs(other, serial).Code).To(Equal(http.StatusNoContent))

			Expect(buf.String()).NotTo(ContainSubstring("High rate of destructive operations"))
		})
	})

	It("rejects a body that is not JSON", func() {
		serial := superseded("api-bad-body")

		rec := revoke(serial, `not json`)
		Expect(rec.Code).To(Equal(http.StatusBadRequest))
		// Which of the handler's three 400s fired. Deleting decodeJSONBody's
		// rejection would leave DesiredState at its zero value, so the
		// desired_state guard answers 400 anyway and a status-only assertion
		// would not notice.
		Expect(rec.Body.String()).To(ContainSubstring("invalid request body"))
		Expect(crlSerials()).To(BeEmpty())
	})
})
