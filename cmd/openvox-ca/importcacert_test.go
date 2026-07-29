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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// runImport executes import-ca-cert with args, returning its stderr.
func runImport(args ...string) (string, error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"import-ca-cert"}, args...))
	err := root.Execute()
	return errOut.String(), err
}

// signCSRAsParent plays the role of the external root: it signs csrPEM as a CA
// certificate and returns the resulting chain, nearest first.
func signCSRAsParent(csrPEM []byte, root *x509.Certificate, rootKey crypto.Signer, rootPEM []byte) []byte {
	GinkgoHelper()
	block, _ := pem.Decode(csrPEM)
	Expect(block).NotTo(BeNil())
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	Expect(csr.CheckSignature()).To(Succeed())

	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	skid := sha1.Sum(pubDER)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, rootKey)
	Expect(err).NotTo(HaveOccurred())

	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(append([]byte{}, interPEM...), rootPEM...)
}

var _ = Describe("openvox-ca import-ca-cert", func() {
	var (
		caDir   string
		chain   *testutil.TestChain
		bundle  string
		emptyCf string
	)

	BeforeEach(func() {
		caDir = GinkgoT().TempDir()
		emptyCf = filepath.Join(GinkgoT().TempDir(), "empty.yaml")
		Expect(os.WriteFile(emptyCf, []byte("{}\n"), 0o644)).To(Succeed())
		GinkgoT().Setenv("PUPPET_CA_CONFIG", emptyCf)

		var err error
		chain, err = testutil.GenerateTestChain("unused.example.com")
		Expect(err).NotTo(HaveOccurred())
		bundle = filepath.Join(caDir, "chain.pem")
	})

	It("completes the csr round trip against an external parent", func() {
		// The whole point of MR1: request out, parent signs, chain back in, and
		// the CA is a working intermediate.
		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		msg, err := runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg).To(ContainSubstring("2 certificates in chain"))

		// The CA now loads and can issue, which is the property that matters.
		store := storage.New(caDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
		Expect(myCA.Init(context.Background())).To(Succeed())
		Expect(myCA.CACert.Subject.CommonName).To(Equal("Puppet CA: puppet.example.com"))
		Expect(myCA.CACert.Issuer.CommonName).To(Equal("Test Root CA"))

		// Stored bundle keeps both certificates, root last.
		stored, err := store.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		certs, err := ca.ParseCABundle(stored)
		Expect(err).NotTo(HaveOccurred())
		Expect(certs).To(HaveLen(2))
		Expect(certs[1].Subject.CommonName).To(Equal("Test Root CA"))
	})

	It("refuses a certificate that does not match the CA key", func() {
		// The single check that makes importing without a private key safe.
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		// chain.Bundle binds a different key entirely.
		Expect(os.WriteFile(bundle, chain.Bundle, 0o644)).To(Succeed())
		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("does not match the certificate's public key")))
	})

	It("refuses a partial chain that stops at an intermediate", func() {
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)

		// Drop the root, leaving only our own certificate.
		certs, err := ca.ParseCABundle(signed)
		Expect(err).NotTo(HaveOccurred())
		onlyOurs := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
		Expect(os.WriteFile(bundle, onlyOurs, 0o644)).To(Succeed())

		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("not self-signed")))
	})

	It("refuses to replace an existing certificate without --force", func() {
		bootstrapCAInDir(caDir, "puppet.example.com")
		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("already exists")))
	})

	It("re-signs the CRL when --force replaces a certificate", func() {
		// The stored CRL was signed by the subject being replaced; after the
		// import nothing could verify it unless it is re-signed.
		bootstrapCAInDir(caDir, "puppet.example.com")
		store := storage.New(caDir)
		before, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())

		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle, "--force")
		Expect(err).NotTo(HaveOccurred())

		after, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(after).NotTo(Equal(before))

		// It verifies under the newly imported certificate.
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
		Expect(myCA.Init(context.Background())).To(Succeed())
		block, _ := pem.Decode(after)
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(crl.CheckSignatureFrom(myCA.CACert)).To(Succeed())
	})

	It("rejects --out together with --force", func() {
		Expect(os.WriteFile(bundle, chain.Bundle, 0o644)).To(Succeed())
		_, err := runImport("--cadir", caDir, "--cert-bundle", bundle, "--out",
			filepath.Join(caDir, "validated.pem"), "--force")
		Expect(err).To(MatchError(ContainSubstring("--out cannot be combined with --force")))
	})

	It("validates and writes the bundle without installing it under --out", func() {
		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		validated := filepath.Join(caDir, "validated.pem")
		msg, err := runImport("--cadir", caDir, "--cert-bundle", bundle, "--out", validated)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg).To(ContainSubstring("not installed"))
		Expect(mustRead(validated)).To(Equal(signed))

		// Storage is untouched: no certificate was installed.
		store := storage.New(caDir)
		has, err := store.HasCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(has).To(BeFalse())
	})

	It("refuses when no CA key exists to match against", func() {
		Expect(os.WriteFile(bundle, chain.Bundle, 0o644)).To(Succeed())
		_, err := runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("no CA key exists")))
	})
})
