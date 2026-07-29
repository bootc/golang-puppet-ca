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
})

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
