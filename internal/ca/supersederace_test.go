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

// White-box, for the reason renewrace_test.go gives: these specs hold the very
// lock the code under test must acquire, and lockNameCRL is the only thing that
// knows what it is called. Spelling the string a second time from outside would
// let a spec hold the wrong lock, block nothing, and still pass.
//
// "race" describes what these specs are about, not how they work. They do not
// run two operations concurrently and hope to catch an interleaving — that is
// non-deterministic and a green run would prove nothing. Instead each holds the
// contended lock from a second goroutine and asserts the operation under test
// blocks until it is released, which pins the same property (this code path
// takes that lock) as a decision rather than as a coincidence of timing. The
// suite's -race runs cover the detector's half.
package ca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The pending list's read-modify-write is mutual with the sweep's only because
// both run under the cluster CRL lock. Nothing else could provide it: two
// renewals for different subjects hold different subject locks, so an append
// landing between the sweep's read and its write would be erased — and the
// certificate that entry named would stay valid for its full remaining life
// with nothing recording that it should not be.
//
// docs/development/locking.md publishes that as the reason this feature adds no
// lock name of its own. Every other spec for delayed supersession is
// single-goroutine and sequential, so removing either WithLock would leave them
// all passing. These are what make the claim falsifiable.
//
// The barrier is placed where it can actually fail: with SupersedeAfter set, the
// immediate-revoke branch of supersedeReplaced is skipped entirely, so
// recordSuperseded's is the *only* CRL-lock acquisition on the renewal path —
// and the pre-lock gates (refuseIfRevoked's SyncCRLCache, refuseIfSuperseded's
// list read) take no cluster lock at all. A spec that blocked on some other
// acquisition would pass with the one under test deleted.
var _ = Describe("The pending-supersession list and the CRL lock", func() {
	var (
		ctx      context.Context
		storeDir string
		store    *storage.StorageService
		myCA     *CA
		ownCrt   *x509.Certificate
	)

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		store = storage.New(storeDir)
		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		myCA.SupersedeAfter = time.Hour

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		ownCrt, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	// blockedOnCRLLock holds the CRL lock, runs op on a goroutine, and asserts
	// it makes no progress until the lock is released — then that it completes.
	blockedOnCRLLock := func(op func() error) {
		GinkgoHelper()
		locked, release := make(chan struct{}), make(chan struct{})
		held := make(chan error, 1)
		var releaseOnce sync.Once
		DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
		go func() {
			defer GinkgoRecover()
			held <- store.WithLock(ctx, lockNameCRL, func() error {
				close(locked)
				<-release
				return nil
			})
		}()
		Eventually(locked).Should(BeClosed())

		done := make(chan error, 1)
		finished := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(finished)
			done <- op()
		}()
		DeferCleanup(func() {
			releaseOnce.Do(func() { close(release) })
			Eventually(finished).Should(BeClosed())
		})

		Consistently(done, 100*time.Millisecond).ShouldNot(Receive(),
			"the operation must wait for the CRL lock before touching the pending list")

		releaseOnce.Do(func() { close(release) })
		Expect(<-held).To(Succeed())
		Eventually(done).Should(Receive(BeNil()))
	}

	// pendingSerials reads the stored list. Deliberately not via readSuperseded:
	// the assertion is about what reached storage.
	pendingSerials := func() []string {
		GinkgoHelper()
		data, err := store.GetSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		var entries []supersededEntry
		Expect(json.Unmarshal(data, &entries)).To(Succeed())
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.Serial)
		}
		return out
	}

	It("makes a renewal wait for the lock before recording a supersession", func() {
		blockedOnCRLLock(func() error { _, err := myCA.AutoRenew(ctx, ownCrt); return err })

		// One-sided on its own: a renewal that never took the lock would also
		// finish after the release. Assert the locked work ran.
		Expect(pendingSerials()).To(ContainElement(serialHexStr(ownCrt.SerialNumber)),
			"the renewal must have reached the CRL-locked append it is being checked for")
	})

	// The inverse, and the promise the fast path exists to keep: an idle sweep
	// takes no cluster lock at all. Every deployment that never enables a window
	// runs this job on every replica, forever, and background_jobs.go and
	// docs/configuration.md both justify that by its cost. A refactor moving the
	// emptiness check inside WithLock would keep every other spec green while
	// quietly reinstating a cluster-lock acquisition per replica per interval.
	It("takes no lock at all when the list is empty", func() {
		Expect(store.SaveSuperseded(ctx, []byte("[]"))).To(Succeed())

		locked, release := make(chan struct{}), make(chan struct{})
		held := make(chan error, 1)
		var releaseOnce sync.Once
		DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
		go func() {
			defer GinkgoRecover()
			held <- store.WithLock(ctx, lockNameCRL, func() error {
				close(locked)
				<-release
				return nil
			})
		}()
		Eventually(locked).Should(BeClosed())

		done := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := myCA.ReconcileSuperseded(ctx)
			done <- err
		}()

		// While the lock is still held by someone else.
		Eventually(done).Should(Receive(BeNil()),
			"an idle sweep must return without waiting for the CRL lock")

		releaseOnce.Do(func() { close(release) })
		Expect(<-held).To(Succeed())
	})

	It("makes the sweep wait for the lock before rewriting the list", func() {
		// Seeded so the sweep gets past its lock-free fast path, which exists to
		// keep an idle CA from taking a cluster lock every interval and would
		// otherwise return before any acquisition.
		entry := []map[string]any{{
			"serial":    fmt.Sprintf("%X", ownCrt.SerialNumber),
			"subject":   "node1.test",
			"revoke_at": time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		}}
		data, err := json.Marshal(entry)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveSuperseded(ctx, data)).To(Succeed())

		blockedOnCRLLock(func() error { _, err := myCA.ReconcileSuperseded(ctx); return err })

		Expect(pendingSerials()).To(BeEmpty(),
			"the sweep must have reached the CRL-locked rewrite it is being checked for")
		isRevoked, err := myCA.IsRevokedSerial(ctx, ownCrt.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(isRevoked).To(BeTrue())
	})
})
