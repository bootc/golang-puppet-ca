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

// White-box: drainDueLocked and drainOutcome are unexported, and this spec
// exists to constrain them specifically rather than the sweep around them.
package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// drainDueLocked is the seam issue #176 replaces when it batches the CRL
// re-sign. These specs pin the contract that replacement has to keep, so the
// batched version is checked against a property rather than against the shape
// of the loop it replaces.
//
// The property is drainOutcome's total: every entry handed in comes back in
// exactly one disposition. An entry that falls out of all four is a certificate
// left valid with nothing recording that it should not be — which is precisely
// the defect review round 2 found here, where deferred entries were named in
// the log line and then dropped from the write-back. A scenario spec caught
// that one after the fact; this one states the invariant it violated.
var _ = Describe("drainDueLocked", func() {
	var (
		ctx    context.Context
		store  *storage.StorageService
		myCA   *CA
		leaves []*x509.Certificate
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		leaves = nil
		for i := range 3 {
			res, err := myCA.Generate(ctx, fmt.Sprintf("drain%d.test", i), nil)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(res.CertificatePEM)
			crt, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			leaves = append(leaves, crt)
		}
	})

	// entry builds a due entry for one of the generated leaves.
	entry := func(i int) supersededEntry {
		return supersededEntry{
			Serial:   serialHexStr(leaves[i].SerialNumber),
			Subject:  fmt.Sprintf("drain%d.test", i),
			RevokeAt: time.Now().UTC().Add(-time.Hour),
		}
	}

	// drain runs one pass under the locks drainDueLocked requires.
	drain := func(passCtx context.Context, due []supersededEntry) drainOutcome {
		GinkgoHelper()
		var out drainOutcome
		Expect(store.WithLock(passCtx, lockNameCRL, func() error {
			myCA.mu.Lock()
			defer myCA.mu.Unlock()
			out = myCA.drainDueLocked(passCtx, due)
			return nil
		})).To(Succeed())
		return out
	}

	// accounted is the invariant: the four dispositions partition the input.
	accounted := func(out drainOutcome) int {
		return out.revoked + len(out.failed) + len(out.deferred) + out.discarded
	}

	It("accounts for every entry when all of them can be revoked", func() {
		due := []supersededEntry{entry(0), entry(1), entry(2)}
		out := drain(ctx, due)

		Expect(accounted(out)).To(Equal(len(due)),
			"every due entry must land in exactly one disposition; one that lands in none is a "+
				"certificate left valid with nothing recording that it should not be")
		Expect(out.revoked).To(Equal(3))
	})

	It("accounts for every entry when one can never be revoked", func() {
		due := []supersededEntry{entry(0), {Serial: "not-hex", Subject: "bad.test"}, entry(1)}
		out := drain(ctx, due)

		Expect(accounted(out)).To(Equal(len(due)))
		Expect(out.discarded).To(Equal(1))
		Expect(out.revoked).To(Equal(2),
			"a malformed serial must not stop the entries around it being revoked")
	})

	It("accounts for every entry when the budget runs out part-way", func() {
		due := []supersededEntry{entry(0), entry(1), entry(2)}
		// Below the reserve, so the loop stops after the first entry.
		shortCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out := drain(shortCtx, due)

		Expect(accounted(out)).To(Equal(len(due)),
			"entries the budget deferred must be returned, not stepped over")
		Expect(out.revoked).To(Equal(1), "a pass must always attempt at least one entry")
		Expect(out.deferred).To(HaveLen(2))
	})

	It("accounts for every entry when every revocation fails", func() {
		// An unparseable stored CRL makes revokeSerialLocked fail for all of
		// them without making any of them unrevocable.
		Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
		due := []supersededEntry{entry(0), entry(1)}
		out := drain(ctx, due)

		Expect(accounted(out)).To(Equal(len(due)))
		Expect(out.failed).To(HaveLen(2), "a failed revocation must be retried, so it stays listed")
		Expect(out.revoked).To(BeZero())
	})

	It("returns an empty outcome for no entries", func() {
		out := drain(ctx, nil)
		Expect(accounted(out)).To(BeZero())
	})

	// The dispositions are not interchangeable: two of them keep the entry on
	// the list and one drops it, so a batched implementation that reported a
	// failure as a discard would silently lose the certificate.
	It("keeps a failed entry and drops only an unrevocable one", func() {
		bad := supersededEntry{Serial: "zz-not-hex", Subject: "bad.test"}
		Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
		out := drain(ctx, []supersededEntry{entry(0), bad})

		Expect(out.discarded).To(Equal(1), "only the malformed serial may be discarded")
		Expect(out.failed).To(HaveLen(1))
		Expect(out.failed[0].Serial).To(Equal(serialHexStr(leaves[0].SerialNumber)),
			"the entry that merely failed must be the one carried forward")
	})

	// Guards the one thing #176's godoc tells a batched implementation it must
	// not do: hand a malformed serial to the batch. Here that is visible as the
	// malformed entry never reaching revokeSerialLocked — with a healthy CRL,
	// a batch containing it would have failed the valid entries too.
	It("never offers an unrevocable serial to the revocation step", func() {
		due := []supersededEntry{{Serial: "not-hex", Subject: "bad.test"}, entry(0)}
		out := drain(ctx, due)

		Expect(out.discarded).To(Equal(1))
		Expect(out.failed).To(BeEmpty(),
			"the malformed entry must be filtered out before revocation, not fail inside it")
		Expect(out.revoked).To(Equal(1),
			"and the valid entry beside it must still be revoked")
	})
})
