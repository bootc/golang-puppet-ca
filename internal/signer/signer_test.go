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

package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing/iotest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RemoteSigner over RPC", func() {
	// verifies that a signing request can be sent over an RPC connection and
	// returns a valid signature.
	It("round-trips a signing request", func() {
		// Generate a test key.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred(), "generating test key")

		// Create a connected socket pair for testing.
		serverConn, clientConn := net.Pipe()

		// Start RPC server in a goroutine.
		svc := &Service{key: key}
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", svc)).To(Succeed(), "registering service")
		go server.ServeConn(serverConn)

		// Create a RemoteSigner using the client end.
		rs := &RemoteSigner{
			client: rpc.NewClient(clientConn),
			pub:    key.Public(),
		}
		DeferCleanup(rs.Close)

		// Verify Public() returns the correct key.
		Expect(rs.Public()).To(Equal(key.Public()), "Public() returned wrong key")

		// Sign a test digest.
		digest := sha256.Sum256([]byte("test data"))
		sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
		Expect(err).NotTo(HaveOccurred(), "remote Sign failed")

		// Verify the signature with the public key.
		Expect(ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig)).To(BeTrue(), "signature verification failed")
	})

	// verifies that multiple concurrent signing requests work.
	It("handles concurrent signing requests", func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred(), "generating test key")

		serverConn, clientConn := net.Pipe()

		svc := &Service{key: key}
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", svc)).To(Succeed(), "registering service")
		go server.ServeConn(serverConn)

		rs := &RemoteSigner{
			client: rpc.NewClient(clientConn),
			pub:    key.Public(),
		}
		DeferCleanup(rs.Close)

		// Fire 10 concurrent signing requests.
		errs := make(chan error, 10)
		for i := range 10 {
			go func(i int) {
				digest := sha256.Sum256([]byte{byte(i)})
				sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					errs <- err
					return
				}
				if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
					errs <- fmt.Errorf("signature verification failed for i=%d", i)
					return
				}
				errs <- nil
			}(i)
		}

		for range 10 {
			Expect(<-errs).NotTo(HaveOccurred(), "concurrent sign failed")
		}
	})
})

var _ = Describe("Socketpair", func() {
	// verifies that Socketpair creates a connected pair of sockets.
	It("creates a connected pair of sockets", func() {
		s, f, err := Socketpair()
		Expect(err).NotTo(HaveOccurred(), "Socketpair")
		DeferCleanup(s.Close)
		DeferCleanup(f.Close)

		// Write on one end, read on the other.
		msg := []byte("hello")
		go func() {
			s.Write(msg)
		}()

		buf := make([]byte, len(msg))
		n, err := f.Read(buf)
		Expect(err).NotTo(HaveOccurred(), "read")
		Expect(string(buf[:n])).To(Equal(string(msg)))
	})
})

var _ = Describe("PSK handshake", func() {
	// verifies the challenge-response handshake succeeds when both sides share
	// the same PSK.
	It("succeeds when both sides share the same PSK", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")

		serverConn, clientConn := net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)

		errCh := make(chan error, 1)
		go func() {
			errCh <- serverHandshake(serverConn, psk)
		}()

		Expect(clientHandshake(clientConn, psk)).To(Succeed(), "client handshake")
		Expect(<-errCh).NotTo(HaveOccurred(), "server handshake")
	})

	// verifies the handshake fails on both sides with mismatched PSKs: the
	// server rejects the frontend's proof, and the client consequently never
	// receives a valid counter-proof.
	It("fails with mismatched PSKs", func() {
		serverPSK := make([]byte, 32)
		clientPSK := make([]byte, 32)
		rand.Read(serverPSK)
		rand.Read(clientPSK)

		serverConn, clientConn := net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)

		errCh := make(chan error, 1)
		go func() {
			err := serverHandshake(serverConn, serverPSK)
			if err != nil {
				// Close so the client's read of the never-sent counter-proof
				// fails instead of blocking forever.
				serverConn.Close()
			}
			errCh <- err
		}()

		Expect(clientHandshake(clientConn, clientPSK)).To(
			MatchError(ContainSubstring("reading signer proof")),
			"client should fail once the server aborts")
		Expect(<-errCh).To(
			MatchError(ContainSubstring("frontend proof mismatch")),
			"server should reject the mismatched frontend proof")
	})

	// verifies the frontend rejects an endpoint that holds the socketpair but
	// not the PSK — the impostor-signer case the mutual handshake exists to
	// prevent.
	It("rejects a signer that cannot prove knowledge of the PSK", func() {
		psk := make([]byte, 32)
		rand.Read(psk)

		serverConn, clientConn := net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)

		// Impostor signer: follows the message flow but forges the proof.
		go func() {
			defer GinkgoRecover()
			// Closed on the way out: without it, a failing Expect in here unwinds
			// this goroutine and leaves the spec body blocked for ever in
			// clientHandshake's ReadFull, so the suite wedges to Ginkgo's default
			// timeout instead of reporting. The mismatched-PSK spec above already
			// does this.
			defer serverConn.Close()
			nonce := make([]byte, 32)
			rand.Read(nonce)
			_, err := serverConn.Write(nonce)
			Expect(err).NotTo(HaveOccurred(), "impostor sending nonce")
			buf := make([]byte, 32+sha256.Size)
			_, err = io.ReadFull(serverConn, buf)
			Expect(err).NotTo(HaveOccurred(), "impostor reading frontend flight")
			forged := make([]byte, sha256.Size)
			rand.Read(forged)
			_, err = serverConn.Write(forged)
			Expect(err).NotTo(HaveOccurred(), "impostor sending forged proof")
		}()

		Expect(clientHandshake(clientConn, psk)).To(
			MatchError(ContainSubstring("signer proof mismatch")),
			"client should reject a forged signer proof")
	})

	// verifies the property that makes the handshake *mutual* rather than merely
	// two-way: the two directions are domain-separated, so a proof valid in one
	// direction is not valid in the other.
	//
	// The impostor spec above cannot show this. It forges a random proof, which an
	// HMAC comparison rejects whether or not the labels differ. Unify the two
	// labels and every other spec in this suite still passes -- while an attacker
	// holding a leaked socketpair descriptor and no PSK at all can impersonate the
	// signer by *reflecting* the frontend's own proof straight back, and the
	// frontend then hands CSR digests to it and accepts whatever comes back as a
	// CA signature.
	It("rejects a signer that reflects the frontend's own proof back", func() {
		psk := make([]byte, pskLen)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())

		serverConn, clientConn := net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)

		go func() {
			defer GinkgoRecover()
			defer serverConn.Close()
			nonce := make([]byte, nonceLen)
			_, err := rand.Read(nonce)
			Expect(err).NotTo(HaveOccurred())
			_, err = serverConn.Write(nonce)
			Expect(err).NotTo(HaveOccurred(), "impostor sending nonce")

			buf := make([]byte, nonceLen+sha256.Size)
			_, err = io.ReadFull(serverConn, buf)
			Expect(err).NotTo(HaveOccurred(), "impostor reading frontend flight")

			// No PSK needed: echo the frontend's proof rather than forging one.
			_, err = serverConn.Write(buf[nonceLen:])
			Expect(err).NotTo(HaveOccurred(), "impostor reflecting the proof")
		}()

		Expect(clientHandshake(clientConn, psk)).To(
			MatchError(ContainSubstring("signer proof mismatch")),
			"a reflected proof must not authenticate the signer")
	})

	// verifies signing works after a successful PSK handshake.
	It("signs after a successful PSK handshake", func() {
		psk := make([]byte, 32)
		rand.Read(psk)
		pskHex := hex.EncodeToString(psk)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred(), "generating key")

		serverConn, clientConn := net.Pipe()

		// Server side: handshake then serve RPC.
		go func() {
			if err := serverHandshake(serverConn, psk); err != nil {
				fmt.Printf("server handshake: %v\n", err)
				serverConn.Close()
				return
			}
			svc := &Service{key: key}
			srv := rpc.NewServer()
			srv.RegisterName("Signer", svc)
			srv.ServeConn(serverConn)
		}()

		// Client side: parse the PSK as the frontend would, handshake, then
		// create a RemoteSigner.
		loadedPSK, err := parsePSK(strings.NewReader(pskHex))
		Expect(err).NotTo(HaveOccurred(), "parsePSK")
		Expect(clientHandshake(clientConn, loadedPSK)).To(Succeed(), "client handshake")

		rs := &RemoteSigner{
			client: rpc.NewClient(clientConn),
			pub:    key.Public(),
		}
		DeferCleanup(rs.Close)

		digest := sha256.Sum256([]byte("psk-test"))
		sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
		Expect(err).NotTo(HaveOccurred(), "sign after PSK handshake")
		Expect(ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig)).To(BeTrue(), "signature verification failed after PSK handshake")
	})
})

var _ = Describe("parsePSK", func() {
	// verifies parsePSK drains a pre-loaded pipe to EOF, matching how the
	// launcher delivers the PSK to a child on fd 4.
	It("reads a PSK from a pre-loaded pipe", func() {
		psk := make([]byte, 32)
		rand.Read(psk)

		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred(), "creating pipe")
		DeferCleanup(func() { _ = r.Close() })
		_, err = w.WriteString(hex.EncodeToString(psk))
		Expect(err).NotTo(HaveOccurred(), "writing PSK to pipe")
		Expect(w.Close()).To(Succeed(), "closing pipe write end")

		parsed, err := parsePSK(r)
		Expect(err).NotTo(HaveOccurred(), "parsePSK")
		Expect(parsed).To(Equal(psk), "parsed PSK should round-trip")
	})

	// verifies parsePSK rejects an empty stream via the length check: the
	// handshake is mandatory, so a missing PSK must be an error rather than
	// a silent downgrade.
	It("rejects an empty stream", func() {
		_, err := parsePSK(strings.NewReader(""))
		Expect(err).To(MatchError(ContainSubstring("PSK must be 32 bytes, got 0")),
			"empty stream should fail the length check")
	})

	// verifies parsePSK rejects non-hex values via the hex decoder.
	It("rejects non-hex values", func() {
		_, err := parsePSK(strings.NewReader("not-hex-data"))
		Expect(err).To(MatchError(ContainSubstring("decoding PSK")),
			"non-hex input should fail hex decoding")
	})

	// verifies parsePSK rejects a well-formed but short PSK via the length
	// check.
	It("rejects PSKs of wrong length", func() {
		_, err := parsePSK(strings.NewReader(hex.EncodeToString([]byte("short"))))
		Expect(err).To(MatchError(ContainSubstring("PSK must be 32 bytes, got 5")),
			"short PSK should fail the length check")
	})

	// verifies parsePSK rejects trailing garbage after a valid PSK rather
	// than silently truncating it. The one-byte read overshoot makes the
	// input an odd-length hex string, so this surfaces as a decode error —
	// never as the length check.
	It("rejects trailing garbage", func() {
		psk := make([]byte, 32)
		rand.Read(psk)
		_, err := parsePSK(strings.NewReader(hex.EncodeToString(psk) + "\n"))
		Expect(err).To(MatchError(ContainSubstring("decoding PSK")),
			"trailing bytes should surface as an odd-length hex decode error")
	})

	// verifies parsePSK propagates reader failures, covering the read-error
	// branch distinctly from the validation branches.
	It("propagates read errors", func() {
		readErr := errors.New("pipe exploded")
		_, err := parsePSK(iotest.ErrReader(readErr))
		Expect(err).To(MatchError(readErr), "reader failure should propagate unwrapped")
	})
})

// trackingCloser is a minimal io.Closer used by the awaitShutdown specs
// to observe whether the helper closed the underlying connection.
type trackingCloser struct {
	mu     sync.Mutex
	closed bool
}

func (c *trackingCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *trackingCloser) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

var _ = Describe("awaitShutdown", func() {
	// is the positive path: when done is closed (i.e. ServeConn returned and
	// the caller signalled shutdown), the helper must exit without touching the
	// underlying connection. Without this property the goroutine would block on
	// sigCh forever and leak on every clean signer exit.
	It("returns on done without closing the connection", func() {
		closer := &trackingCloser{}
		sigCh := make(chan os.Signal, 1)
		done := make(chan struct{})

		finished := make(chan struct{})
		go func() {
			defer close(finished)
			awaitShutdown(closer, sigCh, done)
		}()

		close(done)

		select {
		case <-finished:
		case <-time.After(time.Second):
			Fail("awaitShutdown did not return when done was closed")
		}

		Expect(closer.Closed()).To(BeFalse(), "connection was closed even though shutdown was via done; should only close on signal")
	})

	// is the negative path: when a signal arrives on sigCh, the helper must
	// close the connection so the blocked ServeConn returns and Serve can clean
	// up.
	It("closes the connection on signal", func() {
		closer := &trackingCloser{}
		sigCh := make(chan os.Signal, 1)
		done := make(chan struct{})

		finished := make(chan struct{})
		go func() {
			defer close(finished)
			awaitShutdown(closer, sigCh, done)
		}()

		sigCh <- syscall.SIGTERM

		select {
		case <-finished:
		case <-time.After(time.Second):
			Fail("awaitShutdown did not return after signal")
		}

		Expect(closer.Closed()).To(BeTrue(), "connection was not closed after signal; ServeConn would block forever")
	})
})

var _ = Describe("handshake nonce freshness", func() {
	// The table below pins that all three inputs are *bound* into the MAC, but it
	// works on fixed fixtures, so it says nothing about what goes on the wire.
	// Leave the server nonce as 32 zero bytes and every spec in the suite stays
	// green -- both sides derive from the same value -- while the signer's
	// challenge becomes a constant and a recorded frontend flight replays.
	It("sends a different challenge on every handshake", func() {
		psk := make([]byte, pskLen)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())

		nonceOf := func() []byte {
			GinkgoHelper()
			serverConn, clientConn := net.Pipe()
			DeferCleanup(serverConn.Close)
			DeferCleanup(clientConn.Close)

			go func() {
				defer GinkgoRecover()
				defer serverConn.Close()
				_ = serverHandshake(serverConn, psk)
			}()

			nonce := make([]byte, nonceLen)
			_, err := io.ReadFull(clientConn, nonce)
			Expect(err).NotTo(HaveOccurred())
			return nonce
		}

		first, second := nonceOf(), nonceOf()
		Expect(first).NotTo(Equal(bytes.Repeat([]byte{0}, nonceLen)),
			"a constant challenge makes the frontend's proof replayable")
		Expect(first).NotTo(Equal(second), "each handshake must challenge freshly")
	})
})

var _ = DescribeTable("every handshake proof input is bound into the MAC",
	// The labels were unpinned until a reflection spec caught them; the nonces are
	// in the same position. Dropping either mac.Write leaves every handshake spec
	// green -- both sides compute proofs the same way, so success and mismatch are
	// unaffected, and the reflection spec still passes because the *labels* still
	// differ. The comment claims each proof is unique to its run; this holds it.
	func(mutate func(label, serverNonce, clientNonce []byte) ([]byte, []byte, []byte)) {
		psk := make([]byte, pskLen)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())
		serverNonce := bytes.Repeat([]byte{0xA1}, nonceLen)
		clientNonce := bytes.Repeat([]byte{0xB2}, nonceLen)

		base := handshakeProof(psk, signerProofLabel, serverNonce, clientNonce)
		label, sn, cn := mutate(signerProofLabel, serverNonce, clientNonce)
		Expect(handshakeProof(psk, label, sn, cn)).NotTo(Equal(base))
	},
	Entry("the label", func(l, sn, cn []byte) ([]byte, []byte, []byte) {
		return frontendProofLabel, sn, cn
	}),
	Entry("the server nonce", func(l, sn, cn []byte) ([]byte, []byte, []byte) {
		return l, bytes.Repeat([]byte{0xC3}, nonceLen), cn
	}),
	Entry("the client nonce", func(l, sn, cn []byte) ([]byte, []byte, []byte) {
		return l, sn, bytes.Repeat([]byte{0xD4}, nonceLen)
	}),
)

var _ = Describe("PSK read timeout", func() {
	// blockingPipe returns a pipe whose read end is blocking, as an inherited fd 4
	// is: os.Pipe hands back a non-blocking read end, and Fd() -- which
	// exec.Cmd.Start calls on every ExtraFiles entry -- clears the flag on the open
	// file description the child shares.
	//
	// It is not a complete stand-in. This file stays registered with the runtime
	// poller (os.Pipe built it as a pipe, and Fd only clears the flag), whereas the
	// child's os.NewFile on an already-blocking descriptor is not pollable at all.
	// That difference is exactly what made a read deadline appear to work here and
	// fail in production -- which is why the bound is a timer now, and why this
	// spec no longer depends on the distinction.
	blockingPipe := func() (*os.File, *os.File) {
		GinkgoHelper()
		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = r.Close(); _ = w.Close() })
		_ = r.Fd()
		return r, w
	}

	It("gives up on a pipe nobody writes to, and says why", func() {
		// A foreign FIFO at fd 4 whose write end is held open by an unrelated
		// process satisfies checkPSKFD and then never reaches EOF, and
		// io.LimitReader does not shorten a blocking read -- it only synthesises
		// EOF once its own budget is spent. Unbounded, the signer hangs before it
		// has logged anything: a wedged start with no diagnosis at all.
		r, _ := blockingPipe()

		done := make(chan error, 1)
		go func() {
			_, readErr := readPSK(r, 100*time.Millisecond)
			done <- readErr
		}()

		var readErr error
		Eventually(done, 5*time.Second).Should(Receive(&readErr),
			"the read must not block for ever on a pipe whose write end is open")
		Expect(readErr).To(MatchError(ContainSubstring("not spawned by the launcher")),
			"a timeout must report the fd contract, not a bare deadline error")
	})

	It("still reads a PSK that is already there", func() {
		// The companion: a bound that rejected everything would satisfy the
		// assertion above just as well. Same blocking provenance, and the write
		// end is closed before the read, exactly as the launcher does it.
		psk := make([]byte, pskLen)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())

		r, w := blockingPipe()
		_, err = w.WriteString(hex.EncodeToString(psk))
		Expect(err).NotTo(HaveOccurred())
		Expect(w.Close()).To(Succeed())

		got, err := readPSK(r, 10*time.Second)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(psk))
	})
})

var _ = Describe("socketpair descriptor check", func() {
	// The sibling of the fd 4 check. Without it fd 3 was wrapped, converted and
	// closed unexamined, so a role process started by hand -- with a wrapper's
	// descriptor or its own log file at fd 3, which the lowest-available-fd rule
	// makes likely -- had that descriptor closed out from under it, and reported a
	// getsockopt error naming neither the launcher nor the contract.
	It("refuses a descriptor that is not a socket", func() {
		f, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = f.Close() })

		err = checkSocketFD(int(f.Fd()))
		Expect(err).To(MatchError(ContainSubstring("is not a socket")))
		Expect(err).To(MatchError(ContainSubstring("not spawned by the launcher")))
	})

	It("refuses a descriptor that was never open", func() {
		err := checkSocketFD(900)
		Expect(err).To(MatchError(ContainSubstring("unavailable")))
		Expect(err).To(MatchError(ContainSubstring("not spawned by the launcher")))
	})

	It("accepts a socketpair end", func() {
		a, b, err := Socketpair()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = a.Close(); _ = b.Close() })

		Expect(checkSocketFD(int(a.Fd()))).To(Succeed())
	})

	It("leaves a descriptor it refuses open", func() {
		// The point of checking before wrapping: a descriptor whose provenance was
		// not established must not be consumed. connFromFD closes only after
		// net.FileConn has succeeded.
		f, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = f.Close() })

		_, err = connFromFD(int(f.Fd()))
		Expect(err).To(HaveOccurred())
		Expect(f.Close()).To(Succeed(),
			"the descriptor must still be open for us to close")
	})
})

var _ = Describe("PSK descriptor check", func() {
	// loadPSK has two independent fail-closed branches, and the end-to-end spec
	// in cmd/openvox-ca covers only the second: it hands the child /dev/null,
	// which is open but not a FIFO. The first -- fd 4 not open at all -- is what
	// an operator running the signer role by hand hits, and it cannot be reached
	// through a child process at all, because closing fd 4 there frees the slot
	// for the runtime to reuse and the check then sees whatever took it.
	It("refuses a descriptor that was never open", func() {
		// Far above anything this process has opened, so Fstat gives EBADF.
		const neverOpened = 900
		err := checkPSKFD(neverOpened)
		Expect(err).To(MatchError(ContainSubstring("unavailable")))
		Expect(err).To(MatchError(ContainSubstring("not spawned by the launcher")))
	})

	It("refuses a descriptor that is open but not a pipe", func() {
		f, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = f.Close() })

		err = checkPSKFD(int(f.Fd()))
		Expect(err).To(MatchError(ContainSubstring("is not a pipe")))
		Expect(err).To(MatchError(ContainSubstring("not spawned by the launcher")))
	})

	It("accepts a pipe", func() {
		// The companion both refusals need: a check that rejected everything
		// would satisfy them just as well.
		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = r.Close(); _ = w.Close() })

		Expect(checkPSKFD(int(r.Fd()))).To(Succeed())
	})
})
