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
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("CA RevokeSerial", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-revokeserial-test")
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
	})

	// issue signs a certificate for subject through the normal path and returns
	// its serial in the CA's canonical rendering (uppercase hex, no padding).
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

	// orphan reproduces the state the issue describes: a certificate was issued,
	// a replacement was minted for the same subject, and the record that would
	// have retired the first one never landed. The inventory still names both;
	// only the replacement is stored, so Revoke(subject) now resolves to it.
	// Returns (superseded, live).
	orphan := func(subject string) (string, string) {
		superseded := issue(subject)
		Expect(store.DeleteCert(ctx, subject)).To(Succeed())
		live := issue(subject)
		Expect(live).NotTo(Equal(superseded))
		return superseded, live
	}

	// crlSerials reports the serials currently on the CRL, canonically rendered.
	crlSerials := func() []string {
		crl := parseStoredCRL(store)
		out := make([]string, 0, len(crl.RevokedCertificateEntries))
		for _, e := range crl.RevokedCertificateEntries {
			out = append(out, strings.ToUpper(e.SerialNumber.Text(16)))
		}
		return out
	}

	Describe("the state it exists for", func() {
		It("revokes a superseded serial that revoking by subject cannot reach", func() {
			superseded, live := orphan("orphan-node")

			// The premise: by name, the CA would retire the live credential and
			// leave the superseded one valid — strictly worse than doing nothing.
			byName, err := store.LatestSerialForSubject(ctx, "orphan-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.ToUpper(byName)).To(Equal(live))

			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			Expect(crlSerials()).To(ConsistOf(superseded))
			Expect(crlSerials()).NotTo(ContainElement(live))
		})

		It("leaves the live certificate usable", func() {
			superseded, live := orphan("orphan-usable")
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			liveInt, ok := new(big.Int).SetString(live, 16)
			Expect(ok).To(BeTrue())
			revoked, err := myCA.IsRevokedSerial(ctx, liveInt)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse())
		})
	})

	Describe("the live-certificate guard", func() {
		It("refuses the serial of the certificate stored for its subject", func() {
			serial := issue("live-node")

			err := myCA.RevokeSerial(ctx, serial, false)
			Expect(err).To(MatchError(ca.ErrSerialIsCurrent))
			Expect(crlSerials()).To(BeEmpty())
		})

		It("names the subject and the remedy, so the operator can act on it", func() {
			serial := issue("live-named")

			err := myCA.RevokeSerial(ctx, serial, false)
			Expect(err.Error()).To(ContainSubstring("live-named"))
			Expect(err.Error()).To(ContainSubstring("--certname live-named"))
			Expect(err.Error()).To(ContainSubstring("--force"))
		})

		It("revokes it anyway when forced", func() {
			serial := issue("live-forced")

			Expect(myCA.RevokeSerial(ctx, serial, true)).To(Succeed())
			Expect(crlSerials()).To(ConsistOf(serial))
		})

		It("does not fire for a subject whose certificate has been deleted", func() {
			// A cleaned subject keeps its inventory rows but has no stored
			// certificate, so nothing is in circulation to protect.
			serial := issue("cleaned-node")
			Expect(store.DeleteCert(ctx, "cleaned-node")).To(Succeed())

			Expect(myCA.RevokeSerial(ctx, serial, false)).To(Succeed())
			Expect(crlSerials()).To(ConsistOf(serial))
		})

		It("fails closed when the stored certificate cannot be read", func() {
			serial := issue("unreadable-node")
			// Corrupt the stored certificate: the guard can no longer tell
			// whether this serial is the one in circulation, and guessing "it
			// is not" would drop the protection exactly when storage is sick.
			Expect(os.WriteFile(store.SignedDir()+"/unreadable-node.pem",
				[]byte("not a certificate"), 0o644)).To(Succeed())

			err := myCA.RevokeSerial(ctx, serial, false)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cannot confirm"))
			Expect(crlSerials()).To(BeEmpty())

			Expect(myCA.RevokeSerial(ctx, serial, true)).To(Succeed())
			Expect(crlSerials()).To(ConsistOf(serial))
		})
	})

	Describe("input handling", func() {
		It("rejects a serial this CA has no record of issuing", func() {
			err := myCA.RevokeSerial(ctx, "DEADBEEF", false)
			Expect(err).To(MatchError(ca.ErrSerialUnknown))
			Expect(crlSerials()).To(BeEmpty())
		})

		It("does not let force admit an unknown serial", func() {
			// A CRL entry for a serial not in the inventory can never be cleaned
			// out again: CleanupExpiredCerts drops entries only for serials it
			// finds there. Force must not be able to create one.
			err := myCA.RevokeSerial(ctx, "DEADBEEF", true)
			Expect(err).To(MatchError(ca.ErrSerialUnknown))
			Expect(crlSerials()).To(BeEmpty())
		})

		It("rejects input that is not a hexadecimal serial", func() {
			for _, bad := range []string{"", "  ", "zzz", "0x1234", "-1", "12 34"} {
				err := myCA.RevokeSerial(ctx, bad, false)
				Expect(err).To(MatchError(storage.ErrMalformedSerial), "input %q", bad)
			}
			Expect(crlSerials()).To(BeEmpty())
		})

		DescribeTable("accepts any rendering of the same serial",
			func(render func(string) string) {
				superseded, _ := orphan("render-node")
				Expect(myCA.RevokeSerial(ctx, render(superseded), false)).To(Succeed())
				Expect(crlSerials()).To(ConsistOf(superseded))
			},
			Entry("canonical", func(s string) string { return s }),
			Entry("lowercase", strings.ToLower),
			Entry("zero-padded", func(s string) string { return "0000" + s }),
			Entry("surrounded by whitespace", func(s string) string { return "  " + s + "\n" }),
		)

		It("is idempotent: a second revocation adds no second entry", func() {
			superseded, _ := orphan("idempotent-node")

			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			Expect(crlSerials()).To(ConsistOf(superseded))
		})
	})

	Describe("the state it leaves behind", func() {
		It("reports the serial as revoked over OCSP", func() {
			superseded, _ := orphan("ocsp-node")
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			serialInt, ok := new(big.Int).SetString(superseded, 16)
			Expect(ok).To(BeTrue())
			revoked, err := myCA.IsRevokedSerial(ctx, serialInt)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})

		It("survives a restart: the revocation is in the signed CRL, not just memory", func() {
			superseded, _ := orphan("restart-node")
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			reloaded := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(reloaded.Init(ctx)).To(Succeed())

			serialInt, ok := new(big.Int).SetString(superseded, 16)
			Expect(ok).To(BeTrue())
			revoked, err := reloaded.IsRevokedSerial(ctx, serialInt)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})
	})
})

var _ = Describe("StorageService SubjectForSerial", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-subjectforserial-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"0A 2026-01-01T00:00:00UTC 2027-01-01T00:00:00UTC /CN=first")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"00FF 2026-01-02T00:00:00UTC 2027-01-02T00:00:00UTC /CN=second")).To(Succeed())
	})

	It("resolves a serial to the subject that holds it", func() {
		Expect(store.SubjectForSerial(ctx, "0A")).To(Equal("CN=first"))
	})

	It("matches regardless of case or zero padding on either side", func() {
		// "00FF" is stored padded; "0a" is queried unpadded and lowercase.
		Expect(store.SubjectForSerial(ctx, "ff")).To(Equal("CN=second"))
		Expect(store.SubjectForSerial(ctx, "0000000a")).To(Equal("CN=first"))
	})

	It("wraps fs.ErrNotExist for a serial no entry carries", func() {
		_, err := store.SubjectForSerial(ctx, "BEEF")
		Expect(err).To(MatchError(fs.ErrNotExist))
	})

	It("rejects a serial that is not hexadecimal", func() {
		_, err := store.SubjectForSerial(ctx, "nope")
		Expect(err).To(MatchError(storage.ErrMalformedSerial))
	})
})
