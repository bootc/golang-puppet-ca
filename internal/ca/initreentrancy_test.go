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

// White-box for the same reason lockorder_test.go is: lockNameBootstrap is the
// only thing that knows what the lock is called, and spelling it a second time
// from outside the package would let the constant drift from the invariant
// these specs pin.
package ca

import (
	"context"
	"fmt"
	"io/fs"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// reentrantInitBackend wraps a filesystem backend over an already-bootstrapped
// store so CA.Init's two seeding shapes can be driven and counted.
//
// It does two things. It can refuse the *first* read of the CA certificate,
// which is exactly Init's fast-path load — Init reads the key first and the
// certificate second, and nothing before it touches ca_cert — so the load taken
// again a few lines later under the bootstrap lock sees the real store and
// succeeds. That is the interleaving the slow path exists for: a peer finished
// bootstrapping between this replica's two loads. And it counts bootstrap
// acquisitions, tracking how many are held at once.
//
// The concrete *storage.FilesystemBackend is embedded rather than the
// storage.Backend interface, and deliberately: embedding the interface would
// stop promoting AcquireSameHostLock, WithLock would fall past both lock tiers
// to a process-local mutex, and the spec would read as exercising the
// production locking path while exercising a substitute. It still deadlocks
// under the bug either way — that is what the per-name gate does — but only the
// concrete embed reproduces the mechanism a filesystem deployment has.
type reentrantInitBackend struct {
	*storage.FilesystemBackend

	// refuseFirstCertRead arms the fast-path failure.
	refuseFirstCertRead bool

	mu        sync.Mutex
	certReads int
	refused   bool
	acquires  int
	held      int
	maxHeld   int
}

func (b *reentrantInitBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyCACert {
		b.mu.Lock()
		b.certReads++
		refuse := b.refuseFirstCertRead && b.certReads == 1
		if refuse {
			b.refused = true
		}
		b.mu.Unlock()
		if refuse {
			return nil, &fs.PathError{Op: "get", Path: storage.KeyCACert, Err: fs.ErrNotExist}
		}
	}
	return b.FilesystemBackend.Get(ctx, key)
}

func (b *reentrantInitBackend) AcquireSameHostLock(ctx context.Context, name string) (storage.Unlocker, error) {
	if name != lockNameBootstrap {
		return b.FilesystemBackend.AcquireSameHostLock(ctx, name)
	}

	// Counted *before* the acquisition, not after. A re-entrant acquisition
	// blocks in the per-name gate and never returns, so a counter advanced
	// afterwards would record nothing at all about the failure it is here to
	// describe. lockorder_test.go's observer records its edges before
	// acquiring for the same reason.
	b.mu.Lock()
	b.acquires++
	b.held++
	if b.held > b.maxHeld {
		b.maxHeld = b.held
	}
	b.mu.Unlock()

	ul, err := b.FilesystemBackend.AcquireSameHostLock(ctx, name)
	if err != nil {
		b.mu.Lock()
		b.held--
		b.mu.Unlock()
		return nil, err
	}
	return &countedUnlocker{Unlocker: ul, b: b}, nil
}

// snapshot reads the counters under the mutex. The first spec runs Init on
// another goroutine, and the unit suite is raced.
func (b *reentrantInitBackend) snapshot() (certReads int, refused bool, acquires, maxHeld int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.certReads, b.refused, b.acquires, b.maxHeld
}

type countedUnlocker struct {
	storage.Unlocker
	b *reentrantInitBackend
}

func (u *countedUnlocker) Unlock() error {
	u.b.mu.Lock()
	u.b.held--
	u.b.mu.Unlock()
	return u.Unlocker.Unlock()
}

var _ = Describe("CA.Init and the bootstrap lock", func() {
	const (
		hostname = "puppet.test"

		// Generous rather than tight. The condition under test is a deadlock —
		// the per-name gate is a plain sync.Mutex and ignores the context, so
		// the wait is unbounded — and everything Init does here is local file
		// I/O over an ECDSA P-256 key. Anything past this bound is a hang, not
		// a slow machine.
		initBudget = 30 * time.Second
	)

	// Deliberately not a shared BeforeEach fixture: each spec arms the backend
	// differently, and the arming is the interesting half.
	newCA := func(store *storage.StorageService) *CA {
		myCA := New(store, AutosignConfig{Mode: "off"}, hostname)
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		return myCA
	}

	// seedStoreWithoutCRL bootstraps a real CA into dir and then removes the
	// CRL, leaving the on-disk state this whole file is about: a certificate
	// and key that load cleanly with no CRL beside them. A replica killed
	// between bootstrapCA's certificate write and its CRL write leaves it, and
	// so does a cert+key overlay mounted over an otherwise-empty backend.
	seedStoreWithoutCRL := func(ctx context.Context, dir string) {
		store := storage.NewWithBackend(storage.NewFilesystemBackend(dir), dir)
		Expect(newCA(store).Init(ctx)).To(Succeed())
		Expect(store.Backend().Delete(ctx, storage.KeyCRL)).To(Succeed())

		// The precondition, asserted rather than assumed. If the CRL were
		// still readable, every spec below would take the loaded-CRL branch out
		// of finishLoadExisting, seed nothing, acquire no bootstrap lock — and
		// pass, having tested none of this.
		_, err := store.GetCRL(ctx)
		Expect(err).To(MatchError(fs.ErrNotExist), "the CRL survived the fixture: %v", err)
	}

	// The regression spec for
	// https://github.com/voxpupuli/openvox-ca/issues/201. Init's slow path
	// called finishLoadExisting from *inside* the bootstrap critical section,
	// and finishLoadExisting seeded through the variant that acquires bootstrap
	// again. WithLock is not reentrant at any tier, and the per-name sync.Mutex
	// in front of every implementation ignores the context, so the second
	// acquisition did not fail at LockTimeout — it hung startup for good.
	//
	// The detector is the Eventually below and nothing else: under the bug the
	// goroutine never returns, so every assertion after it is unreachable. The
	// assertions that follow are there to establish that the goroutine got as
	// far as the acquisition that used to hang.
	It("returns rather than hanging when the slow path seeds an absent CRL", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		seedStoreWithoutCRL(ctx, dir)

		be := &reentrantInitBackend{
			FilesystemBackend:   storage.NewFilesystemBackend(dir),
			refuseFirstCertRead: true,
		}
		store := storage.NewWithBackend(be, dir)
		replica := newCA(store)

		done := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			done <- replica.Init(ctx)
		}()

		// The description is a closure so its counters are read when the
		// assertion fails rather than when it is set up, where they are all
		// still zero.
		var initErr error
		Eventually(done, initBudget).Should(Receive(&initErr), func() string {
			_, refused, acquires, maxHeld := be.snapshot()
			return fmt.Sprintf(
				"CA.Init did not return within %s. The slow path re-entered the %q lock "+
					"(refused the fast-path cert read: %t; acquisitions: %d; most held at once: %d). "+
					"That is issue #201: the second acquisition blocks in the per-name gate, which "+
					"is a plain sync.Mutex and ignores the context, so it never times out.",
				initBudget, lockNameBootstrap, refused, acquires, maxHeld)
		})
		Expect(initErr).NotTo(HaveOccurred())

		certReads, refused, acquires, maxHeld := be.snapshot()

		// Why the assertion above was reached at all — four ways this spec
		// could otherwise pass having driven none of the path it names.
		//
		// The slow path was entered: the fast-path load really did fail.
		Expect(refused).To(BeTrue(),
			"the fixture never refused a read of %s, so Init took the fast path", storage.KeyCACert)
		// ...and the load *inside* the lock really did succeed. Every other
		// branch of the slow path bootstraps or errors, and none of them
		// reaches the seeding this is about.
		Expect(certReads).To(BeNumerically(">=", 2),
			"the CA certificate was read %d time(s); the slow path's in-lock load never happened", certReads)
		// The seeding really did run under the lock.
		Expect(acquires).To(Equal(1),
			"expected exactly one %q acquisition, got %d", lockNameBootstrap, acquires)
		// And the invariant itself, stated independently of the shape of the
		// fix: bootstrap is never held twice at once on one goroutine. A fix
		// that released and re-acquired sequentially would satisfy this too,
		// which is deliberate — re-entrancy is the defect, not the count.
		Expect(maxHeld).To(Equal(1), "the %q lock was held %d deep", lockNameBootstrap, maxHeld)

		// The seeding did its work, so the path ran to the end rather than
		// short-circuiting somewhere harmless along the way.
		crlPEM, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred(), "the slow path returned without seeding the CRL")
		Expect(crlPEM).NotTo(BeEmpty())
		Expect(replica.CACert).NotTo(BeNil())
	})

	// The other half of the same fix, and the reason it is a separate spec:
	// moving *both* call sites onto the ...Locked variant would make the spec
	// above pass while leaving the fast path seeding with no lock at all, so
	// two replicas mounting the same overlay would race to seed. The fast path
	// holds nothing, so it must still acquire.
	//
	// Shaped as an acquisition count rather than as a lock wait, which
	// locking.md's Tests section names as the cheaper of the two shapes when
	// the operation is not otherwise concurrent. Dropping the acquisition fails
	// on the count.
	It("still takes the bootstrap lock when the fast path seeds an absent CRL", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		seedStoreWithoutCRL(ctx, dir)

		// Not armed: the fast-path load succeeds, which is the overlay case.
		be := &reentrantInitBackend{FilesystemBackend: storage.NewFilesystemBackend(dir)}
		store := storage.NewWithBackend(be, dir)
		replica := newCA(store)

		Expect(replica.Init(ctx)).To(Succeed())

		certReads, refused, acquires, maxHeld := be.snapshot()
		Expect(refused).To(BeFalse(), "this spec must drive the fast path; the fixture refused a read")
		Expect(certReads).To(Equal(1),
			"the CA certificate was read %d times; Init did not take the fast path", certReads)
		Expect(acquires).To(Equal(1),
			"the fast path made %d %q acquisition(s); seeding without it lets two replicas race to seed",
			acquires, lockNameBootstrap)
		Expect(maxHeld).To(Equal(1), "the %q lock was held %d deep", lockNameBootstrap, maxHeld)

		crlPEM, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred(), "the fast path returned without seeding the CRL")
		Expect(crlPEM).NotTo(BeEmpty())
	})
})
