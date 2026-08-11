// Copyright (C) 2026 Trevor Vaughan
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/signer"
)

// pskChildEnv selects child mode when the test binary re-execs itself: the
// fd-contract specs below spawn real child processes so the ExtraFiles
// slice position ↔ fd number contract (socketpair on fd 3, PSK pipe on
// fd 4) is exercised across a genuine exec boundary.
const pskChildEnv = "OPENVOX_CA_TEST_PSK_CHILD"

func TestMain(m *testing.M) {
	if role := os.Getenv(pskChildEnv); role != "" {
		os.Exit(runPSKChild(role))
	}
	os.Exit(m.Run())
}

// runPSKChild is the child side of the fd-contract specs. It uses only the
// signer package's exported entry points — the same ones the production
// signer and frontend roles use — so fd recovery, PSK loading, and the
// mutual handshake all run exactly as they would under the real launcher.
func runPSKChild(role string) int {
	switch role {
	case "signer":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := signer.Serve(key); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "frontend":
		rs, err := signer.Dial(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer rs.Close()
		digest := sha256.Sum256([]byte("fd-contract"))
		sig, err := rs.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(sig) == 0 {
			fmt.Fprintln(os.Stderr, "empty signature")
			return 1
		}
		fmt.Println("SIGN-OK")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown %s role %q\n", pskChildEnv, role)
		return 2
	}
}

// pskChildCmd builds a re-exec of the test binary in the given child role
// with the supplied inherited files, capturing combined output.
func pskChildCmd(ctx context.Context, role string, extraFiles []*os.File, out *bytes.Buffer) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append(os.Environ(), pskChildEnv+"="+role)
	cmd.ExtraFiles = extraFiles
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd
}

var _ = Describe("launcher fd contract", func() {
	// verifies the full cross-process contract end to end: two real child
	// processes recover the socketpair from fd 3 and the PSK from the fd 4
	// pipe, complete the mutual handshake, and service a signing RPC.
	It("delivers the socketpair on fd 3 and the PSK pipe on fd 4", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")
		pskHex := hex.EncodeToString(psk)

		signerSock, frontendSock, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred(), "creating socketpair")

		signerPipe, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "creating signer PSK pipe")
		frontendPipe, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "creating frontend PSK pipe")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)

		var signerOut, frontendOut bytes.Buffer
		signerCmd := pskChildCmd(ctx, "signer", []*os.File{signerSock, signerPipe}, &signerOut)
		frontendCmd := pskChildCmd(ctx, "frontend", []*os.File{frontendSock, frontendPipe}, &frontendOut)

		// Mirror the launcher: drop the parent's copies of each child's files
		// immediately after that child starts, so only the children hold the
		// socketpair ends and pipe read ends.
		Expect(signerCmd.Start()).To(Succeed(), "starting signer child")
		// Registered before anything else can fail: a mid-spec failure aborts
		// the body by panic, so relying on the Wait calls below to reap these
		// leaves a child running whenever the spec fails -- which is exactly
		// when it matters. The sibling spec below already does this.
		DeferCleanup(func() { killAndReap(signerCmd) })
		signerSock.Close()
		signerPipe.Close()
		Expect(frontendCmd.Start()).To(Succeed(), "starting frontend child")
		DeferCleanup(func() { killAndReap(frontendCmd) })
		frontendSock.Close()
		frontendPipe.Close()

		Expect(frontendCmd.Wait()).To(Succeed(), "frontend child failed: %s", frontendOut.String())
		Expect(frontendOut.String()).To(ContainSubstring("SIGN-OK"),
			"frontend should obtain a signature over the socketpair")
		Expect(signerCmd.Wait()).To(Succeed(), "signer child failed: %s", signerOut.String())
	})

	// verifies the mandatory-handshake failure mode across the exec
	// boundary: a child whose fd 4 is not the launcher's PSK pipe must fail
	// closed rather than proceed unauthenticated.
	//
	// fd 4 is pinned to /dev/null rather than simply left out of ExtraFiles.
	// Omitting it does not guarantee the child sees fd 4 closed: exec only
	// rewrites fds 0-2 and the ExtraFiles range, so any descriptor this test
	// binary inherited without FD_CLOEXEC from its own parent stays open at
	// its original number in the child. Under a wrapper that leaks one at
	// fd 4 (lefthook's pre-push hook does, as do some CI runners) the child
	// would inherit a foreign pipe, satisfy loadPSK's S_IFIFO check, and then
	// block or fail with an unrelated read error instead of the fd-contract
	// message asserted here. A character device is never a FIFO, so this
	// drives the guard deterministically wherever the suite runs.
	It("fails closed when fd 4 is not the launcher's PSK pipe", func() {
		signerSock, frontendSock, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred(), "creating socketpair")
		DeferCleanup(func() { _ = signerSock.Close() })

		notAPipe, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred(), "opening %s", os.DevNull)
		DeferCleanup(func() { _ = notAPipe.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)

		var out bytes.Buffer
		cmd := pskChildCmd(ctx, "frontend", []*os.File{frontendSock, notAPipe}, &out)
		err = cmd.Run()
		frontendSock.Close()

		Expect(err).To(HaveOccurred(), "child without a PSK pipe on fd 4 should exit non-zero; output: %s", out.String())
		Expect(out.String()).To(ContainSubstring("not spawned by the launcher"),
			"child should report the missing PSK pipe")
	})
})

// lowestFreeFD returns the descriptor number a fresh pipe is given, which by the
// POSIX lowest-available-fd rule is the lowest free slot. Comparing it before and
// after an operation detects a descriptor the operation left open, without
// reading /dev/fd -- which is a magic directory that cannot be listed portably
// (on Darwin the listing's own descriptor invalidates the read).
func lowestFreeFD() int {
	GinkgoHelper()
	r, w, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	fd := int(r.Fd())
	Expect(r.Close()).To(Succeed())
	Expect(w.Close()).To(Succeed())
	return fd
}

var _ = Describe("spawnChild and its cleanup", func() {
	// runLauncher itself has no test and cannot easily have one -- it re-execs
	// this binary twice and then blocks on signal forwarding -- so the two rules
	// its failure path depends on are pinned on the extracted helpers instead.
	It("reaps a child rather than only signalling it", func() {
		// The launcher kills the signer when the frontend fails to start. Kill
		// alone leaves a zombie for as long as the launcher lives, and the
		// launcher does not necessarily exit straight away.
		cmd := exec.Command("/bin/sh", "-c", "sleep 300")
		Expect(cmd.Start()).To(Succeed())
		pid := cmd.Process.Pid

		killAndReap(cmd)

		// Signal 0 probes for existence. A reaped child is gone; a zombie would
		// still be found, because a zombie is still a process table entry owned
		// by this process.
		Expect(syscall.Kill(pid, 0)).To(MatchError(syscall.ESRCH),
			"the child must be waited on, not merely signalled")
	})

	It("is safe on a child that was never started", func() {
		// The frontend-failure path calls this with whatever the signer spawn
		// returned, and a spawn that failed before Start returns a nil Cmd.
		killAndReap(nil)
		killAndReap(&exec.Cmd{})
	})

	It("does not leak a PSK pipe when the child cannot start", func() {
		// A pipe is created before the fork, so a Start that fails owns the only
		// remaining reference to it. Leaking one per attempt is a descriptor
		// leak in the one code path an operator hits repeatedly: a launcher
		// crash-looping because the binary cannot exec.
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())

		sock, otherEnd, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = otherEnd.Close() })

		before := lowestFreeFD()
		cmd, err := spawnChild(filepath.Join(GinkgoT().TempDir(), "does-not-exist"),
			os.Environ(), "signer", sock, hex.EncodeToString(psk))
		Expect(err).To(HaveOccurred(), "a missing executable must not start")
		Expect(cmd).To(BeNil())
		Expect(lowestFreeFD()).To(Equal(before),
			"a pipe left open would occupy this slot, pushing the next one higher")
	})
})

var _ = Describe("pskPipe", func() {
	// verifies the returned read end yields exactly the hex PSK followed by
	// EOF, which is what a child's parsePSK relies on to drain the pipe.
	It("delivers the PSK followed by EOF", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")
		pskHex := hex.EncodeToString(psk)

		r, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "pskPipe")
		DeferCleanup(func() { _ = r.Close() })

		// ReadAll only returns once the write end is closed, so this also
		// proves pskPipe closed it before returning.
		data, err := io.ReadAll(r)
		Expect(err).NotTo(HaveOccurred(), "reading PSK pipe")
		Expect(string(data)).To(Equal(pskHex), "pipe contents should be the hex PSK")
	})
})
