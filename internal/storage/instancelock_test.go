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

package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The single-instance rule: a backend with distributed locking may run several
// instances, every other backend exactly one.
//
// As in filelock_test.go, two backend values over one store stand in for two
// processes, and for the same reason — flock(2) is held by an open file
// description, so two independent os.OpenFile calls exclude each other whether
// or not a fork separates them. One spec below uses a real second process
// anyway, because the holder's identity is the thing being asserted and a
// same-process stand-in would report the pid of the test itself.

var _ = Describe("Store instance lock", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	svc := func(b Backend) *StorageService {
		return NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
	}

	// countLockFiles reports how many lock files exist under dir, which is how
	// the "no distributed locking" specs tell "took no lock" from "took one".
	countLockFiles := func(dir string) int {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		Expect(err).NotTo(HaveOccurred())
		n := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".lock") {
				n++
			}
		}
		return n
	}

	Describe("a backend with no distributed locking", func() {
		It("admits the first instance and refuses the second", func() {
			cadir := GinkgoT().TempDir()

			first, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).To(HaveOccurred(), "a second instance must not be admitted")

			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(),
				"the refusal must be a StoreLockedError, so callers can tell it from a lock that could not be taken")
		})

		It("admits a new instance once the first has released the store", func() {
			cadir := GinkgoT().TempDir()

			first, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(first.Unlock()).To(Succeed())

			second, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "the store must not stay locked after the holder released it")
			Expect(second.Unlock()).To(Succeed())
		})

		It("names the process holding the store, rather than timing out", func() {
			cadir := GinkgoT().TempDir()
			helper := startLockHelper(cadir, instanceLockName)

			_, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).To(HaveOccurred())

			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue())

			// The identity, which is the half a lock timeout cannot give an
			// operator. Asserting the holder's real pid — and that it is not
			// this process's — is what distinguishes a recorded holder from a
			// message that merely looks like one.
			helperPID := helper.cmd.Process.Pid
			Expect(helperPID).NotTo(Equal(os.Getpid()), "precondition: the holder is a different process")
			Expect(locked.Holder).To(ContainSubstring("pid " + strconv.Itoa(helperPID)))
			Expect(locked.Error()).To(ContainSubstring("pid " + strconv.Itoa(helperPID)))
			Expect(locked.Path).To(BeARegularFile())

			// And the reason, so an operator is not left to infer it.
			Expect(locked.Error()).To(ContainSubstring("exactly one instance"))

			helper.stop()

			// The kernel drops the flock when the holder exits, so the store is
			// free with nothing to clean up.
			after, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "the store must be free once the holding process has gone")
			Expect(after.Unlock()).To(Succeed())
		})

		It("refuses a second acquisition inside one process without deadlocking", func() {
			// flock(2) is per open file description, so without the TryLock in
			// acquireInstance this process would refuse itself and report its
			// own pid as the holder — true, and baffling.
			cadir := GinkgoT().TempDir()
			b := NewFilesystemBackend(cadir)

			first, err := svc(b).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			_, err = b.AcquireInstanceLock()
			Expect(err).To(MatchError(ContainSubstring("this process already holds")))

			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeFalse(),
				"our own second acquisition is a programming error, not another instance")
		})

		It("locks the SQLite store through the directory beside the database", func() {
			dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
			open := func() *SQLBackend {
				b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = b.Close() })
				return b
			}

			first, err := svc(open()).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			// A second value over the same DSN is a second process, as above.
			second := open()

			_, err = svc(second).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(), "SQLite permits exactly one running instance")
		})

		It("locks the base store through an overlay", func() {
			// Without OverlayBackend.AcquireInstanceLock the type assertion in
			// AcquireInstanceLock finds no InstanceLocker and silently permits
			// the second instance — a wrong answer that looks like a working
			// one, since the call still succeeds.
			ov, cadir, _, _ := overlayTestSetup()

			first, err := svc(ov).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(),
				"an overlay must exclude a second instance on the store it wraps")
		})
	})

	Describe("a backend with distributed locking", func() {
		It("permits several instances and takes no store lock at all", func() {
			// The exemption this rule turns on. Multiple instances are a
			// designed-for configuration on the HA backends, so enforcement
			// must not merely tolerate them — it must not run.
			cadir := GinkgoT().TempDir()
			lockDir := filepath.Join(cadir, fsLockDir)

			// bothLocker embeds the concrete filesystem backend, so it also
			// promotes AcquireInstanceLock: this backend *could* take the
			// store-wide flock. If the capability gate were dropped it would,
			// and the second acquisition below would be refused.
			backend := func() Backend {
				return &bothLocker{FilesystemBackend: NewFilesystemBackend(cadir)}
			}

			first, err := svc(backend()).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			second, err := svc(backend()).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "a backend that coordinates across processes may run many instances")
			DeferCleanup(func() { _ = second.Unlock() })

			Expect(countLockFiles(lockDir)).To(BeZero(),
				"a backend with distributed locking must not have a store-wide flock taken on it")
		})
	})

	Describe("when the rule cannot be enforced", func() {
		It("permits the instance when the capability probe fails", func() {
			// A probe error means a backend that does have distributed locking
			// is momentarily unreachable — the single-node backends answer
			// (false, nil) and never reach here. Refusing to start would be a
			// restriction on exactly the deployments this rule exempts.
			probeErr := errors.New("cluster unreachable")
			s := svc(&stubLocker{Backend: NewFilesystemBackend(GinkgoT().TempDir()), err: probeErr})

			_, err := s.SupportsDistributedLocking(ctx)
			Expect(err).To(MatchError(probeErr), "precondition: the probe fails for this backend")

			ul, err := s.AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "an unreachable HA backend must not be refused startup")
			Expect(ul.Unlock()).To(Succeed())
		})

		It("permits the instance when the backend offers no store lock", func() {
			// An in-memory SQLite database is private to the process that
			// opened it, so there is no second instance for a lock to exclude
			// and nothing to lock beside.
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: ":memory:"})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })

			_, err = b.AcquireInstanceLock()
			Expect(err).To(MatchError(ErrSameHostLockingUnsupported),
				"precondition: an in-memory database has no lock set")

			ul, err := svc(b).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "an unavailable lock must not be reported as a held one")
			Expect(ul.Unlock()).To(Succeed())
		})
	})

	Describe("the holder record", func() {
		It("describes this process without quoting its arguments", func() {
			record := instanceHolderRecord()

			Expect(record).To(ContainSubstring(fmt.Sprintf("pid %d", os.Getpid())))
			host, err := os.Hostname()
			Expect(err).NotTo(HaveOccurred())
			Expect(record).To(ContainSubstring(host))

			// A command line can carry a passphrase file path or another
			// operational detail, and this record is printed back in an error.
			for _, arg := range os.Args[1:] {
				if arg == "" {
					continue
				}
				Expect(record).NotTo(ContainSubstring(arg),
					"the record must name the binary only, never its arguments")
			}
			Expect(record).To(HaveLen(len(strings.TrimSpace(record))), "a record is one line")
		})

		It("replaces the previous holder's record rather than accumulating one per instance", func() {
			// The lock file outlives every process that holds it — fileUnlocker
			// deliberately never unlinks one — so an appended record would leave
			// a reader unable to tell which line is current.
			cadir := GinkgoT().TempDir()
			path := filepath.Join(cadir, fsLockDir, fileLockFileName(instanceLockName))

			for range 3 {
				ul, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ul.Unlock()).To(Succeed())
			}

			body, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(body))).NotTo(ContainSubstring("\n"))
			Expect(strings.Count(string(body), "pid ")).To(Equal(1))
		})

		It("still refuses when the holder's record is unreadable", func() {
			// A holder that was killed between taking the flock and writing its
			// record leaves an empty file. The refusal is what matters; the name
			// is what improves it.
			cadir := GinkgoT().TempDir()
			locks := newFileLocks(filepath.Join(cadir, fsLockDir))

			ul, err := locks.acquireInstance()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = ul.Unlock() })

			path := filepath.Join(cadir, fsLockDir, fileLockFileName(instanceLockName))
			Expect(os.Truncate(path, 0)).To(Succeed())

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue())
			Expect(locked.Holder).To(BeEmpty())
			Expect(locked.Error()).To(ContainSubstring("unidentified process"))
		})
	})

	Describe("the reserved lock name", func() {
		It("cannot collide with a lock a running instance takes", func() {
			// The store-wide lock is held for the whole life of the process, so
			// a collision with any name real work uses would deadlock the
			// instance against itself on its first operation.
			Expect(instanceLockName).NotTo(Equal(lockProbeName))
			Expect(instanceLockName).NotTo(Equal("bootstrap"))
			Expect(instanceLockName).NotTo(Equal("crl"))
			Expect(instanceLockName).NotTo(HavePrefix("subject:"))
		})
	})
})
