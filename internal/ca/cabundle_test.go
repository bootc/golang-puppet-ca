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

package ca_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("CA bundle parsing and ordering", func() {
	var chain *testutil.TestChain

	BeforeEach(func() {
		var err error
		chain, err = testutil.GenerateTestChain("node.example.com")
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("ParseCABundle", func() {
		It("returns every certificate in file order", func() {
			certs, err := ca.ParseCABundle(chain.Bundle)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(HaveLen(2))
			Expect(certs[0].Subject.CommonName).To(Equal("Test Intermediate CA"))
			Expect(certs[1].Subject.CommonName).To(Equal("Test Root CA"))
		})

		It("skips non-certificate blocks rather than failing", func() {
			// A key block alongside the certificates must not break the parse:
			// operators paste bundles exported by other tools.
			mixed := append(append([]byte{}, chain.InterKeyPEM...), chain.Bundle...)
			certs, err := ca.ParseCABundle(mixed)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(HaveLen(2))
		})

		It("rejects input with no certificates", func() {
			_, err := ca.ParseCABundle(chain.InterKeyPEM)
			Expect(err).To(MatchError(ContainSubstring("no CERTIFICATE blocks")))
		})

		It("rejects a malformed certificate body", func() {
			_, err := ca.ParseCABundle([]byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"))
			Expect(err).To(MatchError(ContainSubstring("parsing certificate 1")))
		})
	})

	Describe("ValidateCABundleOrder", func() {
		It("accepts a complete chain ordered nearest-first", func() {
			certs, err := ca.ParseCABundle(chain.Bundle)
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.ValidateCABundleOrder(certs)).To(Succeed())
		})

		It("accepts a lone self-signed root", func() {
			certs, err := ca.ParseCABundle(chain.RootPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.ValidateCABundleOrder(certs)).To(Succeed())
		})

		It("rejects a reversed bundle", func() {
			// Root-first is the mistake that would pass a naive check and then
			// fail at startup, because loadCA pins the key to block 0.
			reversed := append(append([]byte{}, chain.RootPEM...), chain.InterPEM...)
			certs, err := ca.ParseCABundle(reversed)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("ordered nearest-first")))
		})

		It("rejects a partial chain that stops at an intermediate", func() {
			certs, err := ca.ParseCABundle(chain.InterPEM)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("not self-signed")))
		})

		It("rejects a bundle whose first certificate is a leaf", func() {
			certs, err := ca.ParseCABundle(chain.LeafPEM)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("IsCA=false")))
		})

		It("rejects an empty certificate list", func() {
			Expect(ca.ValidateCABundleOrder(nil)).To(MatchError(ContainSubstring("no certificates")))
		})

		It("rejects a chain whose links do not verify", func() {
			// Two unrelated roots concatenated: ordered plausibly, cryptographically
			// unrelated.
			other, err := testutil.GenerateTestChain("other.example.com")
			Expect(err).NotTo(HaveOccurred())
			mixed := append(append([]byte{}, chain.InterPEM...), other.RootPEM...)
			certs, err := ca.ParseCABundle(mixed)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("is not signed by certificate")))
		})
	})

	Describe("CASubjectName", func() {
		It("derives the common name from the hostname", func() {
			name := ca.CASubjectName("puppet.example.com", ca.CASubjectConfig{})
			Expect(name.CommonName).To(Equal("Puppet CA: puppet.example.com"))
			Expect(name.Organization).To(BeEmpty())
		})

		It("applies every optional subject field", func() {
			name := ca.CASubjectName("puppet", ca.CASubjectConfig{
				Org:      "Example Ltd",
				OrgUnit:  "Infrastructure",
				Country:  "GB",
				Locality: "London",
				Province: "Greater London",
			})
			Expect(name.Organization).To(Equal([]string{"Example Ltd"}))
			Expect(name.OrganizationalUnit).To(Equal([]string{"Infrastructure"}))
			Expect(name.Country).To(Equal([]string{"GB"}))
			Expect(name.Locality).To(Equal([]string{"London"}))
			Expect(name.Province).To(Equal([]string{"Greater London"}))
		})

		It("produces the same DN a bootstrapped CA certificate carries", func() {
			// The property the shared builder exists to guarantee: a CSR and a
			// self-signed bootstrap must agree, or the parent signs the wrong name.
			cfg := ca.CASubjectConfig{Org: "Example Ltd", Country: "GB"}
			expected := ca.CASubjectName("puppet.example.com", cfg)

			store := storage.New(GinkgoT().TempDir())
			myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
			myCA.CASubject = cfg
			myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(myCA.Init(context.Background())).To(Succeed())

			Expect(myCA.CACert.Subject.CommonName).To(Equal(expected.CommonName))
			Expect(myCA.CACert.Subject.Organization).To(Equal(expected.Organization))
			Expect(myCA.CACert.Subject.Country).To(Equal(expected.Country))
		})
	})
})
