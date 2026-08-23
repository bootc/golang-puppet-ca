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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// hmacInitBackend wraps a filesystem backend to observe and steer the one call
// CA.Init makes on its way into the inventory HMAC key: it records the context
// the backend sees for Get(hmac_key), can report the key absent so the locking
// path is reached, and can fail the lock acquisition the way a backend with no
// leader would.
type hmacInitBackend struct {
	storage.Backend

	// keyCtx is the context observed on the first Get(hmac_key). CA.Init must
	// have bounded it before this point.
	keyCtx context.Context

	// getErr, when set, is returned from Get(hmac_key) instead of delegating.
	getErr error

	// lockErr, when set, fails AcquireLock as a backend that cannot reach a
	// quorum would.
	lockErr error
}

func (b *hmacInitBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyHMACKey {
		if b.keyCtx == nil {
			b.keyCtx = ctx
		}
		if b.getErr != nil {
			return nil, b.getErr
		}
	}
	return b.Backend.Get(ctx, key)
}

func (b *hmacInitBackend) AcquireLock(_ context.Context, name string) (storage.Unlocker, error) {
	if b.lockErr != nil {
		return nil, b.lockErr
	}
	// No spec here needs a lock that succeeds, and quietly reporting the tier
	// unsupported would be worse than useless: this double embeds the
	// storage.Backend *interface*, so AcquireSameHostLock is not promoted, and
	// WithLock would fall past both lock tiers to a process-local mutex. A
	// later spec would then read as exercising cross-replica locking while
	// exercising none. Fail loudly instead of degrading silently.
	Fail(fmt.Sprintf("hmacInitBackend.AcquireLock(%q) reached with no lockErr configured: this double models lock *failure* only", name))
	return nil, nil
}

var _ = Describe("CA.Init and the inventory HMAC key", func() {
	newStore := func(be storage.Backend, dir string) *storage.StorageService {
		st := storage.NewWithBackend(be, filepath.Join(dir, "private"))
		Expect(st.EnsureDirs(context.Background())).To(Succeed())
		return st
	}

	// EnsureHMACKey can now wait on another replica's cold start, so CA.Init
	// bounds it. Without the bound a stuck lease on a crashed peer hangs
	// startup with no deadline at all — the failure this budget exists to
	// convert into an error.
	//
	// Asserted on the deadline the backend observes rather than by waiting one
	// out: Init is given a context with no deadline of its own, so a deadline
	// arriving at the backend can only have come from Init. Removing the
	// wrapper leaves the context bare and fails this immediately, where a spec
	// that merely passed in a short deadline would still pass.
	It("bounds the key step with LockTimeout even when its caller sets no deadline", func() {
		dir := GinkgoT().TempDir()
		sentinel := errors.New("backend unreachable")
		be := &hmacInitBackend{Backend: storage.NewFilesystemBackend(dir), getErr: sentinel}
		myCA := ca.New(newStore(be, dir), ca.AutosignConfig{Mode: "off"}, "puppet.test")

		before := time.Now()
		err := myCA.Init(context.Background())
		Expect(err).To(MatchError(sentinel), "Init: %v", err)

		Expect(be.keyCtx).NotTo(BeNil(), "the backend was never asked for %s", storage.KeyHMACKey)
		deadline, ok := be.keyCtx.Deadline()
		Expect(ok).To(BeTrue(), "CA.Init passed a context with no deadline into the HMAC key step; a peer holding the lock would hang startup indefinitely")
		Expect(deadline).To(BeTemporally("~", before.Add(ca.LockTimeout), 5*time.Second),
			"the key step's budget is %s from the start of Init; want LockTimeout (%s)", time.Until(deadline), ca.LockTimeout)
	})

	// "inventory integrity check failed" is this project's tampering wording.
	// Since the key step can now fail on lock contention, an ordinary backend
	// fault must not borrow it: an on-call reading that first clause escalates
	// a slow etcd as a suspected compromise.
	It("reports a failed lock acquisition as a startup fault, not as tampering", func() {
		dir := GinkgoT().TempDir()
		noLeader := errors.New("etcd: no leader")
		be := &hmacInitBackend{
			Backend: storage.NewFilesystemBackend(dir),
			getErr:  &fs.PathError{Op: "get", Path: storage.KeyHMACKey, Err: fs.ErrNotExist},
			lockErr: noLeader,
		}
		myCA := ca.New(newStore(be, dir), ca.AutosignConfig{Mode: "off"}, "puppet.test")

		err := myCA.Init(context.Background())
		Expect(err).To(MatchError(noLeader), "Init: %v", err)
		Expect(err.Error()).NotTo(ContainSubstring("integrity check failed"),
			"a lock failure is reported as %q; that phrase is reserved for a failed verification", err)
	})

	// The other arm of the same branch. Without it, inverting the condition
	// would satisfy the spec above and silently retire the tamper alarm.
	It("still reports a genuine HMAC mismatch as an integrity failure", func() {
		dir := GinkgoT().TempDir()
		ctx := context.Background()
		be := storage.NewFilesystemBackend(dir)
		st := newStore(be, dir)

		Expect(be.Put(ctx, storage.KeyHMACKey, bytes.Repeat([]byte{0x11}, 32), storage.BlobPrivate)).To(Succeed())
		Expect(be.Put(ctx, storage.KeyInventory, []byte("0x0001 2026-01-01 2027-01-01 /CN=a\n"), storage.BlobPrivate)).To(Succeed())
		Expect(be.Put(ctx, storage.KeyInventoryHMAC, []byte("not the right mac"), storage.BlobPrivate)).To(Succeed())

		myCA := ca.New(st, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		err := myCA.Init(ctx)
		Expect(err).To(MatchError(storage.ErrInventoryTampered), "Init: %v", err)
		Expect(err.Error()).To(ContainSubstring("inventory integrity check failed"),
			"a real mismatch must keep the tamper wording; got %q", err)
	})
})
