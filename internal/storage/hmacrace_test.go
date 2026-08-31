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

// White-box, like internal/ca/renewrace_test.go and for the same reason: these
// specs assert which *named* lock the HMAC-key path takes, and lockNameHMACKey
// is the only thing that knows what it is called. Spelling the string a second
// time from outside would let a rename pass a spec that no longer describes the
// code.
package storage

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// gateTimeout bounds the cold-start barrier below. Generous: it is only ever
// reached when a replica fails to arrive at all, which is a structural failure
// of the spec rather than slowness.
const gateTimeout = 30 * time.Second

// sharedStoreBackend models what several replicas actually share: one blob
// namespace and one set of named locks. Distinct StorageService values wrap it,
// so each has its own localLocks map and its own mutexes — which is the point.
// A fix that leaned on StorageService's process-local fallback would pass a
// spec built on one service and fail here, exactly as it would fail in a
// cluster.
//
// It implements Locker (as etcd, Redis and the server SQL dialects do) rather
// than SameHostLocker, because tier 1 is the tier a cross-replica cold start
// depends on.
//
// The cold-start barrier is what makes the race deterministic instead of
// hopeful, and where it sits is the whole of it: each replica reads the blob
// map *first* and only then blocks until `participants` of them have arrived.
// Gating before the read looks equivalent and is not — the replica that
// releases the cohort can win the lock and Put before a straggler has looked,
// and the straggler then takes the fast path and adopts its key. That barrier
// passes the convergence spec below against the unfixed code, which is to say
// it does not test anything. Reading before the gate makes every replica
// observe the key absent before any of them can write one, which is precisely
// the interleaving the issue describes.
//
// Later Gets — the re-read inside the lock — are not gated, or the winner could
// never make progress.
type sharedStoreBackend struct {
	mu    sync.Mutex
	blobs map[string][]byte

	// hmacPuts records every value written to KeyHMACKey, in order, so a spec
	// can assert both how many writes happened and what they were.
	hmacPuts [][]byte

	// acquired records every lock name taken through AcquireLock, in order.
	acquired []string
	locks    map[string]*sync.Mutex

	participants int
	firstGets    int
	gate         chan struct{}
	gateExpired  bool
}

func newSharedStoreBackend(participants int) *sharedStoreBackend {
	return &sharedStoreBackend{
		blobs:        map[string][]byte{},
		locks:        map[string]*sync.Mutex{},
		participants: participants,
		gate:         make(chan struct{}),
	}
}

// awaitCohort blocks the first `participants` calls until the last of them
// arrives. Calls beyond that return immediately.
func (b *sharedStoreBackend) awaitCohort() {
	b.mu.Lock()
	b.firstGets++
	n := b.firstGets
	if n == b.participants {
		close(b.gate)
	}
	b.mu.Unlock()
	if n > b.participants {
		return
	}
	select {
	case <-b.gate:
	case <-time.After(gateTimeout):
		b.mu.Lock()
		b.gateExpired = true
		b.mu.Unlock()
	}
}

func (b *sharedStoreBackend) EnsureReady(context.Context) error { return nil }

func (b *sharedStoreBackend) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	data, ok := b.blobs[key]
	if ok {
		data = bytes.Clone(data)
	}
	b.mu.Unlock()

	// After the observation, never before: see the barrier note above.
	if key == KeyHMACKey {
		b.awaitCohort()
	}

	if !ok {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
	}
	return data, nil
}

func (b *sharedStoreBackend) Put(_ context.Context, key string, data []byte, _ BlobKind) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blobs[key] = bytes.Clone(data)
	if key == KeyHMACKey {
		b.hmacPuts = append(b.hmacPuts, bytes.Clone(data))
	}
	return nil
}

func (b *sharedStoreBackend) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.blobs[key]; !ok {
		return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrNotExist}
	}
	delete(b.blobs, key)
	return nil
}

func (b *sharedStoreBackend) Exists(_ context.Context, key string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.blobs[key]
	return ok, nil
}

func (b *sharedStoreBackend) List(context.Context, string) ([]string, error) { return nil, nil }

func (b *sharedStoreBackend) AppendLine(_ context.Context, key string, data []byte, _ BlobKind) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blobs[key] = append(bytes.Clone(b.blobs[key]), data...)
	return nil
}

func (b *sharedStoreBackend) ModTime(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}

func (b *sharedStoreBackend) Close() error { return nil }

// AcquireLock is the stand-in for a cluster lock: one mutex per name, shared by
// every StorageService over this backend. Non-reentrant, like every real
// implementation, so a caller that took the same name higher up hangs here —
// which is the property the bootstrap-reentrancy spec below relies on.
func (b *sharedStoreBackend) AcquireLock(_ context.Context, name string) (Unlocker, error) {
	b.mu.Lock()
	m, ok := b.locks[name]
	if !ok {
		m = &sync.Mutex{}
		b.locks[name] = m
	}
	b.acquired = append(b.acquired, name)
	b.mu.Unlock()
	m.Lock()
	return &sharedStoreUnlocker{m: m}, nil
}

func (b *sharedStoreBackend) snapshot() (hmacPuts [][]byte, acquired []string, gateExpired bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.hmacPuts...), append([]string(nil), b.acquired...), b.gateExpired
}

type sharedStoreUnlocker struct{ m *sync.Mutex }

func (u *sharedStoreUnlocker) Unlock() error { u.m.Unlock(); return nil }

var (
	_ Backend = (*sharedStoreBackend)(nil)
	_ Locker  = (*sharedStoreBackend)(nil)
)

var _ = Describe("EnsureHMACKey on a concurrent cold start", func() {
	// The regression this file exists for. Before the fix, EnsureHMACKey read
	// the key, found it absent, generated one and wrote it with nothing
	// serialising the three steps: every replica in the cohort below wrote a
	// different key, the last write won, and the losers went on to MAC their
	// inventories under a key no other replica could reproduce. The next start
	// then failed VerifyInventoryHMAC with "inventory integrity check failed".
	//
	// The barrier makes that interleaving certain rather than likely, so this
	// spec fails on the old code on every run, not one in a hundred.
	const replicas = 4

	It("converges on a single key rather than forking", func() {
		be := newSharedStoreBackend(replicas)
		ctx := context.Background()

		keys := make([][]byte, replicas)
		errs := make([]error, replicas)
		var wg sync.WaitGroup
		for i := range replicas {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// One StorageService per replica: they share only the backend,
				// so nothing process-local can be mistaken for coordination.
				keys[i], errs[i] = NewWithBackend(be, "").EnsureHMACKey(ctx)
			}()
		}
		wg.Wait()

		hmacPuts, acquired, gateExpired := be.snapshot()
		Expect(gateExpired).To(BeFalse(), "cold-start barrier timed out: fewer than %d replicas reached their first Get(%s), so the specs below did not observe the race they claim to", replicas, KeyHMACKey)

		for i := range replicas {
			Expect(errs[i]).NotTo(HaveOccurred(), "replica %d: EnsureHMACKey: %v", i, errs[i])
			Expect(keys[i]).To(HaveLen(hmacKeyLen), "replica %d: key length = %d; want %d", i, len(keys[i]), hmacKeyLen)
		}

		// The property that matters: every replica ends up holding the same
		// key. Stated over the returned values rather than over the stored
		// blob, because the forked key is what each replica then MACs with.
		for i := 1; i < replicas; i++ {
			Expect(keys[i]).To(Equal(keys[0]), "replica %d returned a key differing from replica 0 (%x vs %x): the HMAC key forked across a concurrent cold start", i, keys[i], keys[0])
		}

		// And exactly one of them wrote. More than one write is the fork even
		// when the values happen to agree, and zero would mean no key was
		// persisted at all.
		Expect(hmacPuts).To(HaveLen(1), "Put(%s) called %d times; want exactly 1 (each extra write is a replica that generated its own key)", KeyHMACKey, len(hmacPuts))
		Expect(hmacPuts[0]).To(Equal(keys[0]), "the persisted key differs from the key the replicas returned")

		// The generation ran under the HMAC-key lock, and under nothing else.
		Expect(acquired).NotTo(BeEmpty(), "no lock was taken; the read-modify-write is still unserialised")
		for _, name := range acquired {
			Expect(name).To(Equal(lockNameHMACKey), "EnsureHMACKey took lock %q; want %q", name, lockNameHMACKey)
		}
	})

	// The end-to-end consequence, stated in the terms an operator meets it in:
	// a replica that starts later and loads the stored key must be able to
	// verify the inventory baseline the cold-start cohort wrote. This is
	// deterministic under the fix — every replica MACs an empty inventory
	// under one shared key, so the baselines are byte-identical.
	//
	// The final InitHMAC is NOT on its own a regression assertion, and it must
	// not be mistaken for one. Nothing gates the Get(inventory_hmac) that
	// VerifyInventoryHMAC issues, so against the unfixed code all four replicas
	// can read the baseline as absent, every InitHMAC returns nil, and the last
	// check passes whenever the last key write and the last baseline write
	// happen to come from the same replica. The Put count below is what makes
	// this spec fail by construction rather than by luck.
	It("leaves an inventory baseline a later replica can verify", func() {
		be := newSharedStoreBackend(replicas)
		ctx := context.Background()

		var wg sync.WaitGroup
		errs := make([]error, replicas)
		for i := range replicas {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = NewWithBackend(be, "").InitHMAC(ctx)
			}()
		}
		wg.Wait()
		for i := range replicas {
			Expect(errs[i]).NotTo(HaveOccurred(), "replica %d: InitHMAC: %v", i, errs[i])
		}

		hmacPuts, _, gateExpired := be.snapshot()
		Expect(gateExpired).To(BeFalse(), "cold-start barrier timed out; the cohort did not race")
		Expect(hmacPuts).To(HaveLen(1), "Put(%s) called %d times; want exactly 1 — the cohort forked the key, and the baseline check below cannot be trusted to catch that", KeyHMACKey, len(hmacPuts))

		later := NewWithBackend(be, "")
		Expect(later.InitHMAC(ctx)).To(Succeed(), "a replica starting after the cold-start cohort could not verify the inventory HMAC they left behind")
	})
})

var _ = Describe("EnsureHMACKey lock discipline", func() {
	// The fast path is every start after the first, so it must not pay for a
	// cross-replica round trip. A fix that wrapped the whole function in
	// WithLock would serialise every replica's startup behind one lock and
	// still pass the convergence spec above; this is what tells the two apart.
	It("takes no lock when a usable key is already stored", func() {
		be := newSharedStoreBackend(0)
		stored := bytes.Repeat([]byte{0xA5}, hmacKeyLen)
		Expect(be.Put(context.Background(), KeyHMACKey, stored, BlobPrivate)).To(Succeed())
		be.hmacPuts = nil

		key, err := NewWithBackend(be, "").EnsureHMACKey(context.Background())
		Expect(err).NotTo(HaveOccurred(), "EnsureHMACKey: %v", err)
		Expect(key).To(Equal(stored), "stored key not returned verbatim")

		hmacPuts, acquired, _ := be.snapshot()
		Expect(acquired).To(BeEmpty(), "EnsureHMACKey acquired %v on the read-only path; every replica's startup would serialise behind it", acquired)
		Expect(hmacPuts).To(BeEmpty(), "EnsureHMACKey rewrote an existing valid key")
	})

	// EnsureHMACKey is reachable from inside WithLock(migrateLockName):
	// MigrateService holds that lock across RebuildInventoryHMAC, which calls
	// EnsureHMACKey. WithLock is not reentrant at any tier (issue #201), so if
	// the HMAC key's lock shared the migration's name, a migration that met a
	// corrupt stored key would hang instead of repairing it.
	//
	// A truncated blob is what drives EnsureHMACKey down its writing path with
	// the key nominally present, which is the only way RebuildInventoryHMAC's
	// Exists guard lets that path be reached at all.
	It("does not deadlock when reached from inside the migration lock", func() {
		be := newSharedStoreBackend(0)
		ctx := context.Background()
		Expect(be.Put(ctx, KeyHMACKey, []byte("too-short"), BlobPrivate)).To(Succeed())
		be.hmacPuts = nil
		svc := NewWithBackend(be, "")

		done := make(chan error, 1)
		go func() {
			done <- svc.WithLock(ctx, migrateLockName, func() error {
				_, err := svc.EnsureHMACKey(ctx)
				return err
			})
		}()

		select {
		case err := <-done:
			Expect(err).NotTo(HaveOccurred(), "EnsureHMACKey under %q: %v", migrateLockName, err)
		case <-time.After(10 * time.Second):
			Fail(fmt.Sprintf("EnsureHMACKey deadlocked inside WithLock(%q): its own lock name must differ from the migration/bootstrap name (it is %q)", migrateLockName, lockNameHMACKey))
		}

		hmacPuts, _, _ := be.snapshot()
		Expect(hmacPuts).To(HaveLen(1), "a truncated key was not regenerated: Put(%s) called %d times, want 1", KeyHMACKey, len(hmacPuts))
	})
})
