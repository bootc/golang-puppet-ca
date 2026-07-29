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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// runCSR executes the csr subcommand with args, returning its stdout.
func runCSR(args ...string) (string, error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"csr"}, args...))
	err := root.Execute()
	return out.String(), err
}

var _ = Describe("openvox-ca csr", func() {
	var caDir string

	BeforeEach(func() {
		caDir = GinkgoT().TempDir()
		// Pin to an empty config file so the host's /etc/puppet-ca/config.yaml,
		// if it exists, cannot influence the result.
		emptyCfg := filepath.Join(GinkgoT().TempDir(), "empty.yaml")
		Expect(os.WriteFile(emptyCfg, []byte("{}\n"), 0o644)).To(Succeed())
		GinkgoT().Setenv("PUPPET_CA_CONFIG", emptyCfg)
		clearServerEnv()
	})

	It("refuses without a key rather than silently creating one", func() {
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).To(MatchError(ContainSubstring("--create-key")))
	})

	It("refuses without a hostname when no CA certificate exists", func() {
		// A request is handed to a third party and signed; a silently wrong CN
		// is expensive to discover afterwards.
		_, err := runCSR("--cadir", caDir, "--create-key")
		Expect(err).To(MatchError(ContainSubstring("hostname is required")))
	})

	It("creates a key and emits a request carrying the CA subject", func() {
		out, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode([]byte(out))
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("CERTIFICATE REQUEST"))

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(csr.CheckSignature()).To(Succeed())
		Expect(csr.Subject.CommonName).To(Equal("Puppet CA: puppet.example.com"))

		// No BasicConstraints: the parent sets those from its own policy, and a
		// sibling openvox-ca would reject a CSR asserting CA:TRUE outright.
		for _, ext := range csr.Extensions {
			Expect(ext.Id.String()).NotTo(Equal("2.5.29.19"))
		}
	})

	It("persists the created key so a second run reuses it", func() {
		first, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		// Without --create-key the second run must find the key from the first.
		second, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())

		firstBlock, _ := pem.Decode([]byte(first))
		secondBlock, _ := pem.Decode([]byte(second))
		firstCSR, err := x509.ParseCertificateRequest(firstBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		secondCSR, err := x509.ParseCertificateRequest(secondBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		firstPub, err := x509.MarshalPKIXPublicKey(firstCSR.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		secondPub, err := x509.MarshalPKIXPublicKey(secondCSR.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(secondPub).To(Equal(firstPub))
	})

	It("writes to --out with permissions matching public material", func() {
		outPath := filepath.Join(caDir, "request.pem")
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key", "--out", outPath)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Stat(outPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0644)))

		block, _ := pem.Decode(mustRead(outPath))
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("CERTIFICATE REQUEST"))
	})

	It("does not clobber an established key when --create-key is passed again", func() {
		// The no-clobber ordering inside LoadOrCreateCAKey is what stops a
		// second --create-key orphaning every certificate already issued. The
		// reuse spec above proves persistence, not this: transpose the checks
		// and it still passes.
		first, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		second, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		Expect(csrPublicKey(second)).To(Equal(csrPublicKey(first)))
	})

	It("reuses an established CA certificate's subject verbatim", func() {
		// The re-key case: the DN must be reproduced exactly, including fields
		// the flags cannot express, or the parent signs for a different name.
		bootstrapCAInDir(caDir, "original.example.com")

		out, err := runCSR("--cadir", caDir, "--hostname", "ignored.example.com")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode([]byte(out))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(csr.Subject.CommonName).To(Equal("Puppet CA: original.example.com"))
	})

	It("reproduces the stored DER subject byte for byte", func() {
		// Re-encoding via pkix.Name would drop any attribute it does not model
		// and reorder the rest. Agents match the issuer against what they
		// already trust, so a reconstructed DN is a different name.
		bootstrapCAInDir(caDir, "original.example.com")

		store := storage.New(caDir)
		stored, err := store.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		certs, err := ca.ParseCABundle(stored)
		Expect(err).NotTo(HaveOccurred())

		out, err := runCSR("--cadir", caDir)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode([]byte(out))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(csr.RawSubject).To(Equal(certs[0].RawSubject))
	})

	It("creates no key when the subject cannot be resolved", func() {
		// A run that cannot determine a subject must not leave a CA key behind:
		// at a provider it may not be removable with openvox-ca at all, and it
		// is the state Init now refuses to start over.
		_, err := runCSR("--cadir", caDir, "--create-key")
		Expect(err).To(HaveOccurred())

		has, err := storage.New(caDir).HasCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(has).To(BeFalse())
	})

	It("encrypts the created key at rest when configured", func() {
		// csr --create-key duplicates bootstrapCA's key handling; nothing else
		// pins the two together, and the failure mode is silent — a CA key
		// written in plaintext despite encrypt_ca_key.
		cfgPath := filepath.Join(GinkgoT().TempDir(), "enc.yaml")
		Expect(os.WriteFile(cfgPath, []byte("encrypt_ca_key: true\n"), 0o600)).To(Succeed())
		GinkgoT().Setenv("PUPPET_CA_CONFIG", cfgPath)

		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		keyPEM, err := storage.New(caDir).GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("ENCRYPTED PRIVATE KEY"))
	})
})

// csrPublicKey extracts the marshalled public key from a PEM-encoded request.
func csrPublicKey(csrPEM string) []byte {
	GinkgoHelper()
	block, _ := pem.Decode([]byte(csrPEM))
	Expect(block).NotTo(BeNil())
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	pub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	return pub
}

func mustRead(path string) []byte {
	GinkgoHelper()
	data, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	return data
}

// bootstrapCAInDir creates a fully bootstrapped CA in dir, so tests can
// exercise the paths that require an established certificate.
func bootstrapCAInDir(dir, hostname string) {
	GinkgoHelper()
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
	myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(myCA.Init(context.Background())).To(Succeed())
}

// revokeInDir issues and then revokes a certificate, so the stored CRL carries
// an entry that later operations must preserve.
func revokeInDir(dir, subject string) {
	GinkgoHelper()
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
	myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(myCA.Init(context.Background())).To(Succeed())
	_, err := myCA.Generate(context.Background(), subject, nil)
	Expect(err).NotTo(HaveOccurred())
	Expect(myCA.Revoke(context.Background(), subject)).To(Succeed())
}
