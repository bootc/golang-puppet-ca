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
	"context"
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The commands that reach storage directly must refuse while a server is
// running against it, and say who is holding it.
//
// Only these do. `list`, `sign` and `revoke` go through the admin API over
// HTTP and never open the store, so they are unaffected and must stay so — an
// operator listing certificates against a live CA is an ordinary thing to do.

var _ = Describe("openvox-ca-ctl and the store instance lock", func() {
	// holdStore takes the store's instance lock the way a running server does.
	// A separate StorageService over the same cadir is an exact stand-in for a
	// second process: flock(2) is held by an open file description.
	holdStore := func(cadir string) {
		GinkgoHelper()
		ul, err := storage.New(cadir).AcquireInstanceLock(context.Background())
		Expect(err).NotTo(HaveOccurred(), "the store must be free before the spec holds it")
		DeferCleanup(func() { _ = ul.Unlock() })
	}

	// refusal asserts the shape every one of these commands must produce: the
	// condition, the holder, and what to do about it.
	refusal := func(err error) {
		GinkgoHelper()
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("already running against this store")))
		Expect(err).To(MatchError(ContainSubstring("pid " + strconv.Itoa(os.Getpid()))))
		Expect(err).To(MatchError(ContainSubstring("stop the running one first")))
	}

	It("refuses to initialise a cadir a server is running against", func() {
		caDir := GinkgoT().TempDir()
		holdStore(caDir)

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"setup", "--cadir", caDir, "--hostname", "puppet.example.com"})

		refusal(cmd.Execute())

		// And it must have refused before doing any of the work, not after.
		Expect(filepath.Join(caDir, "ca_crt.pem")).NotTo(BeAnExistingFile(),
			"a refused setup must not have bootstrapped a CA")
	})

	It("initialises normally once the store is free", func() {
		// The control: without this, a setup that always failed would satisfy
		// the spec above.
		caDir := GinkgoT().TempDir()

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"setup", "--cadir", caDir, "--hostname", "puppet.example.com"})

		Expect(cmd.Execute()).To(Succeed())
		Expect(filepath.Join(caDir, "ca_crt.pem")).To(BeAnExistingFile())
	})

	It("refuses to import a CA into a cadir a server is running against", func() {
		caDir := GinkgoT().TempDir()

		// A real bundle, so the refusal is the lock and not a parse failure.
		setup := newRootCmd()
		setup.SetOut(GinkgoWriter)
		setup.SetErr(GinkgoWriter)
		setup.SetArgs([]string{"setup", "--cadir", caDir, "--hostname", "puppet.example.com"})
		Expect(setup.Execute()).To(Succeed())

		target := GinkgoT().TempDir()
		holdStore(target)

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{
			"import", "--cadir", target,
			"--cert-bundle", filepath.Join(caDir, "ca_crt.pem"),
			"--private-key", filepath.Join(caDir, "private", "ca_key.pem"),
		})

		refusal(cmd.Execute())
	})
})
