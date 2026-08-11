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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/signer"
)

const (
	// defaultShutdownDrain is the frontend's graceful HTTP-drain budget when the
	// operator has not set shutdown_timeout_sec / PUPPET_CA_SHUTDOWN_TIMEOUT_SEC.
	// 25s is chosen so the launcher's derived hard-kill deadline (drain +
	// launcherShutdownHeadroom = 28s) stays under Kubernetes' 30s default
	// terminationGracePeriodSeconds, leaving the platform headroom before it
	// SIGKILLs the pod.
	defaultShutdownDrain = 25 * time.Second
	// launcherShutdownHeadroom is added to the frontend's drain budget to form
	// the launcher's hard-kill deadline. Because the launcher's timer starts
	// when it forwards SIGTERM — strictly before the frontend begins its own
	// Shutdown — this headroom guarantees the launcher always outlasts the
	// frontend's drain so the supervisor can never truncate it.
	launcherShutdownHeadroom = 3 * time.Second
	// crashShutdownTimeout bounds teardown of the surviving child when the
	// other has already exited unexpectedly. This is a failure path, not a
	// graceful drain, so it uses a shorter budget.
	crashShutdownTimeout = 5 * time.Second
)

// runLauncher is the supervisor process that spawns the isolated signer and
// frontend children, monitors them, and propagates signals for clean shutdown.
//
// Process tree:
//
//	openvox-ca (launcher/supervisor)
//	├-- openvox-ca [signer]    holds CA key, no network, socketpair only
//	└-- openvox-ca [frontend]  HTTP server, connects to signer via socketpair
//
// SECURITY: The socketpair is created before either child is spawned and
// passed via inherited file descriptors (fd 3). There is no filesystem path
// for the socket; only the two child processes hold endpoints.
//
// drain is the frontend's resolved graceful HTTP-drain budget (see
// serverConfig.shutdownDrain). The launcher waits drain+launcherShutdownHeadroom
// for both children to exit after forwarding SIGTERM before hard-killing them,
// so the frontend always gets its full drain even though the launcher's timer
// starts first.
// NIST 800-53: SC-3 (Security Function Isolation), SC-4 (Information in Shared System Resources)
func runLauncher(drain time.Duration) error {
	gracefulShutdownTimeout := drain + launcherShutdownHeadroom

	// Create the socketpair for signer ↔ frontend communication.
	signerSock, frontendSock, err := signer.Socketpair()
	if err != nil {
		return fmt.Errorf("creating signer socketpair: %w", err)
	}
	defer signerSock.Close()
	defer frontendSock.Close()

	// Generate a PSK for authenticating the socketpair endpoints.
	// Both children receive this via an inherited pipe (fd 4) and run a
	// mutual challenge-response handshake before the first RPC call: each
	// endpoint proves knowledge of the PSK to the other, so a rogue process
	// that somehow obtained a leaked fd could impersonate neither the
	// frontend nor the signer.
	//
	// SECURITY: the PSK travels over a pipe rather than an environment
	// variable because a child's exec-time environment stays visible in
	// /proc/<pid>/environ for its whole lifetime (os.Unsetenv only mutates
	// the process's own copy) and is captured verbatim by crash-dump and
	// support tooling such as systemd-coredump. A pipe is consumed once and
	// leaves no such residue.
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return fmt.Errorf("generating socketpair PSK: %w", err)
	}
	pskHex := hex.EncodeToString(psk)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	slog.Info("Starting isolated CA processes")

	// Build base environment: strip role/daemon vars to prevent inheritance
	// loops. PUPPET_CA_SIGNER_PSK is stripped defensively: the PSK travels
	// over a pipe, and a variable by that name must never reach a child.
	// spawnChild clips this before appending to it, so the two children cannot
	// share a backing array.
	baseEnv := filterEnv(os.Environ(), "PUPPET_CA_ROLE", "PUPPET_CA_DAEMON", "PUPPET_CA_SIGNER_PSK")

	signerCmd, err := spawnChild(exe, baseEnv, "signer", signerSock, pskHex)
	if err != nil {
		return err
	}

	frontendCmd, err := spawnChild(exe, baseEnv, "frontend", frontendSock, pskHex)
	if err != nil {
		// The signer is already running and nothing will ever connect to it, so
		// it has to go -- and be reaped, not merely signalled: Kill on its own
		// leaves a zombie for as long as this process lives, and the launcher
		// does not necessarily exit straight away.
		killAndReap(signerCmd)
		return err
	}

	slog.Info("CA processes started",
		"signer_pid", signerCmd.Process.Pid,
		"frontend_pid", frontendCmd.Process.Pid,
	)

	// Forward termination signals to children. The buffer matches the
	// number of registered signals so a coincident SIGTERM+SIGINT (e.g.
	// terminal Ctrl-C racing with a supervisor SIGTERM) cannot drop a
	// notification and leave the launcher hung.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Wait for either child to exit.
	type childResult struct {
		name string
		err  error
	}
	exitCh := make(chan childResult, 2)
	go func() { exitCh <- childResult{"signer", signerCmd.Wait()} }()
	go func() { exitCh <- childResult{"frontend", frontendCmd.Wait()} }()

	shutdown := func() {
		frontendCmd.Process.Signal(syscall.SIGTERM)
		signerCmd.Process.Signal(syscall.SIGTERM)
		timer := time.AfterFunc(gracefulShutdownTimeout, func() {
			frontendCmd.Process.Kill()
			signerCmd.Process.Kill()
		})
		<-exitCh
		<-exitCh
		timer.Stop()
	}

	select {
	case sig := <-sigCh:
		slog.Info("Received signal, shutting down CA processes", "signal", sig)
		shutdown()
		return nil

	case result := <-exitCh:
		slog.Error("CA child process exited unexpectedly", "process", result.name, "error", result.err)
		// Shut down the surviving child.
		frontendCmd.Process.Signal(syscall.SIGTERM)
		signerCmd.Process.Signal(syscall.SIGTERM)
		timer := time.AfterFunc(crashShutdownTimeout, func() {
			frontendCmd.Process.Kill()
			signerCmd.Process.Kill()
		})
		<-exitCh // wait for the other child
		timer.Stop()
		return fmt.Errorf("%s process exited unexpectedly: %w", result.name, result.err)
	}
}

// spawnChild starts one isolated child in the given role, handing it the
// socketpair end on fd 3 and a freshly loaded PSK pipe on fd 4.
//
// Extracted so the two spawns cannot drift apart and so the failure ordering is
// testable: the parent's copies of both descriptors must be dropped as soon as
// the child holds them, and a PSK pipe created for a child that never starts
// must not be leaked. Both rules were open-coded twice.
// pskPipeFn is the pipe constructor spawnChild uses. A variable so a spec can
// capture the descriptor the helper creates and assert directly that it was
// closed -- the fd-slot arithmetic that stood in for that could not distinguish a
// leaked pipe from a closed socket, so it passed either way.
var pskPipeFn = pskPipe

func spawnChild(exe string, baseEnv []string, role string, sock *os.File, pskHex string) (*exec.Cmd, error) {
	pskRead, err := pskPipeFn(pskHex)
	if err != nil {
		// Including here, the earliest exit: os.Pipe fails under descriptor
		// exhaustion, which is exactly the crash-looping launcher this helper's
		// other failure path reasons about. Leaving fd 3 to the caller's defer on
		// one exit and owning it on the other is the split the extraction removed.
		sock.Close()
		return nil, err
	}

	cmd := exec.Command(exe, os.Args[1:]...) //nolint:gosec // G204: re-execs this same binary (os.Executable) with the operator's own os.Args
	// Clipped to len==cap here, beside the append that depends on it: filterEnv
	// returns spare capacity whenever it stripped anything, so two spawns sharing
	// an unclipped slice would share a backing array and the second would rewrite
	// the first child's role -- leaving this process tree with no signer, or two.
	// The guard used to live in the caller, one function away from the append it
	// protects, which is how a third caller would have reintroduced it.
	baseEnv = baseEnv[:len(baseEnv):len(baseEnv)]
	cmd.Env = append(baseEnv,
		"PUPPET_CA_ROLE="+role,
		"PUPPET_CA_DAEMON=1",
	)
	cmd.ExtraFiles = []*os.File{sock, pskRead} // fd 3, fd 4
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		// Both, so the helper owns both descriptors unconditionally. Closing only
		// the pipe left fd 3 to the caller's defers, which runLauncher does have
		// -- but that is the split-ownership shape this extraction exists to
		// remove, and the second caller already got it wrong.
		pskRead.Close()
		sock.Close()
		return nil, fmt.Errorf("starting %s process: %w", role, err)
	}
	// Only the child should hold these now. The socketpair end is the
	// load-bearing one: while the launcher keeps a copy, both endpoints stay
	// alive, which falsifies the property this whole topology rests on -- that
	// only the two children hold endpoints -- and stops the signer seeing EOF
	// when the frontend dies. The PSK pipe's read end is closed for hygiene
	// rather than correctness: EOF for the child depends on the *write* end,
	// which pskPipe already closed before returning. An earlier comment here had
	// that backwards.
	sock.Close()
	pskRead.Close()
	return cmd, nil
}

// killAndReap signals a started child and waits for it, so a launcher that fails
// partway through leaves nothing behind. Errors are deliberately ignored: the
// caller is already returning a failure, and a child that has exited on its own
// is the outcome this wants anyway.
func killAndReap(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

// pskPipe returns the read end of a pipe pre-loaded with the hex-encoded
// PSK, ready to be inherited by a child via ExtraFiles. The write end is
// closed before returning, so the child reads the PSK followed immediately
// by EOF. The payload (64 bytes) is far below the kernel pipe buffer, so
// the write cannot block.
func pskPipe(pskHex string) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating PSK pipe: %w", err)
	}
	if _, err := w.WriteString(pskHex); err != nil {
		r.Close()
		w.Close()
		return nil, fmt.Errorf("writing PSK to pipe: %w", err)
	}
	if err := w.Close(); err != nil {
		r.Close()
		return nil, fmt.Errorf("closing PSK pipe write end: %w", err)
	}
	return r, nil
}

// filterEnv returns a copy of env with the named keys removed.
func filterEnv(env []string, keys ...string) []string {
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if !keySet[k] {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
