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

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// errWriter is a notices writer that always fails, standing in for a closed or
// full stderr.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// writeTempPEM writes content to a file of the given name in a fresh temp dir
// and returns its path.
func writeTempPEM(name string, content []byte) string {
	path := filepath.Join(GinkgoT().TempDir(), name)
	Expect(os.WriteFile(path, content, 0600)).To(Succeed())
	return path
}

// The three server-verification modes documented in docs/operator-cli.md
// (--ca-cert → custom trust anchor, --insecure → no verification, neither →
// system trust store) are security-relevant and all resolved here, so pin each
// one — including the precedence between --ca-cert and --insecure, which is
// otherwise only visible as an `else if`.
var _ = Describe("newTLSConfig", func() {
	var (
		caCertPEM  []byte
		caKeyPEM   []byte
		caCertPath string
		notices    *bytes.Buffer
	)

	BeforeEach(func() {
		saveCtlGlobals()
		globalCACert = ""
		globalInsecure = false
		globalClientCert = ""
		globalClientKey = ""

		var err error
		caKeyPEM, caCertPEM, _, err = testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		caCertPath = writeTempPEM("ca.pem", caCertPEM)

		notices = &bytes.Buffer{}
	})

	// verifies reports whether certPEM chains to the pool the config was built
	// with — a stronger check than "RootCAs is non-nil", and one that has to
	// answer both ways: a pool that trusts everything would pass every
	// positive assertion in this file.
	verifies := func(pool *x509.CertPool, certPEM []byte) bool {
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		_, err = cert.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		return err == nil
	}

	// trusts is the common case: does the --ca-cert CA itself verify?
	trusts := func(pool *x509.CertPool) bool { return verifies(pool, caCertPEM) }

	Context("with --ca-cert", func() {
		BeforeEach(func() { globalCACert = caCertPath })

		It("trusts the supplied CA and keeps verification on", func() {
			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.InsecureSkipVerify).To(BeFalse(),
				"InsecureSkipVerify = true; want false when --ca-cert is supplied")
			Expect(cfg.RootCAs).NotTo(BeNil(), "RootCAs = nil; want the --ca-cert pool")
			Expect(trusts(cfg.RootCAs)).To(BeTrue(),
				"the --ca-cert certificate does not verify against the resulting RootCAs pool")
			Expect(notices.String()).To(BeEmpty(),
				"notices = %q; want no notice when a trust anchor is supplied", notices.String())
		})

		// --ca-cert wins over --insecure: an operator who supplies a trust
		// anchor is never silently downgraded to "verify nothing".
		It("takes precedence over --insecure", func() {
			globalInsecure = true

			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.InsecureSkipVerify).To(BeFalse(),
				"InsecureSkipVerify = true; want --ca-cert to win over --insecure")
			Expect(trusts(cfg.RootCAs)).To(BeTrue(),
				"the --ca-cert certificate does not verify against the resulting RootCAs pool")
			Expect(notices.String()).NotTo(ContainSubstring("WARNING"),
				"notices = %q; want no --insecure warning when --ca-cert wins", notices.String())
		})

		It("returns an error when the file cannot be read", func() {
			globalCACert = filepath.Join(GinkgoT().TempDir(), "absent.pem")

			_, err := newTLSConfig(notices)
			Expect(err).To(MatchError(ContainSubstring("reading --ca-cert")))
		})

		It("returns an error when the PEM block is not a certificate", func() {
			globalCACert = writeTempPEM("junk.pem",
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))

			_, err := newTLSConfig(notices)
			Expect(err).To(MatchError(ContainSubstring("parsing --ca-cert")))
		})

		// A readable file with no PEM in it at all (a DER export, a truncated
		// download, the wrong file) must fail here and not as an opaque
		// handshake error against an empty trust pool.
		It("returns an error when the file holds no PEM certificate", func() {
			globalCACert = writeTempPEM("raw.der", []byte("not pem at all"))

			_, err := newTLSConfig(notices)
			Expect(err).To(MatchError(ContainSubstring("contains no usable certificates")))
		})

		// A CA bundle (root plus intermediates) must be trusted in full, not
		// truncated to whichever certificate happens to come first.
		It("trusts every certificate in a bundle", func() {
			_, otherCertPEM, _, err := testutil.GenerateTestCAECDSA()
			Expect(err).NotTo(HaveOccurred())
			globalCACert = writeTempPEM("bundle.pem", append(append([]byte{}, otherCertPEM...), caCertPEM...))

			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(trusts(cfg.RootCAs)).To(BeTrue(),
				"the second certificate in the bundle does not verify against the resulting RootCAs pool")
			Expect(verifies(cfg.RootCAs, otherCertPEM)).To(BeTrue(),
				"the first certificate in the bundle does not verify against the resulting RootCAs pool")
		})

		// The documented contract is that --ca-cert *replaces* the system trust
		// store. Seeding the pool from x509.SystemCertPool() instead would keep
		// every positive assertion above green while silently widening trust,
		// so pin the negative direction too.
		It("does not trust a CA outside the supplied file", func() {
			_, foreignCertPEM, _, err := testutil.GenerateTestCAECDSA()
			Expect(err).NotTo(HaveOccurred())

			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifies(cfg.RootCAs, foreignCertPEM)).To(BeFalse(),
				"a CA absent from --ca-cert verifies against the resulting RootCAs pool; the pool is wider than the file")
		})
	})

	Context("with --insecure and no --ca-cert", func() {
		BeforeEach(func() { globalInsecure = true })

		It("disables verification and warns about MITM", func() {
			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.InsecureSkipVerify).To(BeTrue(),
				"InsecureSkipVerify = false; want true for --insecure")
			Expect(cfg.RootCAs).To(BeNil(), "RootCAs = %v; want nil for --insecure", cfg.RootCAs)
			Expect(notices.String()).To(ContainSubstring("WARNING"))
			Expect(notices.String()).To(ContainSubstring("MITM"),
				"notices = %q; want the MITM warning documented in docs/operator-cli.md", notices.String())
		})

		// The stderr write is deliberately unchecked because the log record is
		// the durable second channel, so pin the record itself.
		It("logs the disabled verification", func() {
			var logged bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
			DeferCleanup(func() { slog.SetDefault(orig) })

			_, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(logged.String()).To(ContainSubstring("TLS server verification disabled"),
				"log = %q; want the warning the unchecked stderr write relies on", logged.String())
		})

		// The other half of that reasoning: a notices writer that fails must
		// not stop the command.
		It("still builds a config when the notices writer fails", func() {
			cfg, err := newTLSConfig(errWriter{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.InsecureSkipVerify).To(BeTrue())
		})
	})

	Context("with neither --ca-cert nor --insecure", func() {
		It("falls back to the system trust store with verification on", func() {
			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			// RootCAs == nil is how crypto/tls selects the system trust store.
			Expect(cfg.RootCAs).To(BeNil(),
				"RootCAs = %v; want nil so the system trust store is used", cfg.RootCAs)
			Expect(cfg.InsecureSkipVerify).To(BeFalse(),
				"InsecureSkipVerify = true; want verification on by default")
			Expect(notices.String()).To(ContainSubstring("system trust store"))
		})
	})

	// TLS 1.3 is the floor in every branch, not just the verified ones.
	DescribeTable("enforces a TLS 1.3 minimum",
		func(prepare func()) {
			prepare()
			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS13)),
				"MinVersion = %#x; want TLS 1.3", cfg.MinVersion)
		},
		Entry("with --ca-cert", func() { globalCACert = caCertPath }),
		Entry("with --insecure", func() { globalInsecure = true }),
		Entry("with neither", func() {}),
	)

	Context("with --client-cert/--client-key", func() {
		It("loads the mTLS key pair", func() {
			globalClientCert = writeTempPEM("client.pem", caCertPEM)
			globalClientKey = writeTempPEM("client-key.pem", caKeyPEM)

			cfg, err := newTLSConfig(notices)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Certificates).To(HaveLen(1),
				"Certificates = %d; want the --client-cert/--client-key pair", len(cfg.Certificates))
			// Pin which pair loaded, not merely that one did.
			block, _ := pem.Decode(caCertPEM)
			Expect(block).NotTo(BeNil())
			Expect(cfg.Certificates[0].Certificate[0]).To(Equal(block.Bytes),
				"the loaded leaf is not the certificate named by --client-cert")
		})

		// Half a key pair cannot authenticate, so it must be rejected here
		// rather than surfacing as a server-side mTLS refusal.
		DescribeTable("rejects a half-supplied pair",
			func(prepare func()) {
				prepare()

				_, err := newTLSConfig(notices)
				Expect(err).To(MatchError(ContainSubstring("must be supplied together")))
			},
			Entry("only --client-cert", func() {
				globalClientCert = writeTempPEM("client.pem", caCertPEM)
			}),
			Entry("only --client-key", func() {
				globalClientKey = writeTempPEM("client-key.pem", caKeyPEM)
			}),
		)

		It("returns an error when the key does not match the certificate", func() {
			otherKeyPEM, _, _, err := testutil.GenerateTestCAECDSA()
			Expect(err).NotTo(HaveOccurred())
			globalClientCert = writeTempPEM("client.pem", caCertPEM)
			globalClientKey = writeTempPEM("client-key.pem", otherKeyPEM)

			_, err = newTLSConfig(notices)
			Expect(err).To(MatchError(ContainSubstring("--client-cert/--client-key")))
		})
	})
})

// newClient must keep handing the resolved TLS config to its transport;
// without this the newTLSConfig specs above could pass while the binary itself
// dialled with a default (verifying, TLS 1.0 floor) config.
var _ = Describe("newClient", func() {
	BeforeEach(func() {
		saveCtlGlobals()
		globalClientCert = ""
		globalClientKey = ""
		globalInsecure = false
		globalServerURL = "https://ca.example.com:8140/"

		_, caCertPEM, _, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		globalCACert = writeTempPEM("ca.pem", caCertPEM)
	})

	It("wires the resolved TLS config into its transport", func() {
		client, err := newClient()
		Expect(err).NotTo(HaveOccurred())
		Expect(client.BaseURL).To(Equal("https://ca.example.com:8140"),
			"BaseURL = %q; want the trailing slash trimmed", client.BaseURL)

		transport, ok := client.HTTPClient.Transport.(*http.Transport)
		Expect(ok).To(BeTrue(), "Transport = %T; want *http.Transport", client.HTTPClient.Transport)
		Expect(transport.TLSClientConfig).NotTo(BeNil())
		Expect(transport.TLSClientConfig.RootCAs).NotTo(BeNil(),
			"RootCAs = nil; want the --ca-cert pool to reach the transport")
		Expect(transport.TLSClientConfig.MinVersion).To(Equal(uint16(tls.VersionTLS13)),
			"MinVersion = %#x; want TLS 1.3 to reach the transport", transport.TLSClientConfig.MinVersion)
	})

	It("propagates a --ca-cert read failure", func() {
		globalCACert = filepath.Join(GinkgoT().TempDir(), "absent.pem")

		_, err := newClient()
		Expect(err).To(MatchError(ContainSubstring("reading --ca-cert")))
	})
})
