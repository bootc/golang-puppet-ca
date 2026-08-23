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
	"context"
	"crypto"
	"crypto/rand"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// parkingSigner wraps the CA key and stops inside Sign, so a spec can hold a
// signature open and observe what the rest of the process can do meanwhile.
//
// It exists because the cost this file is about is invisible at normal speeds.
// A local ECDSA signature is microseconds, so a spec racing against one proves
// nothing either way: it would pass against the serialised arrangement often
// enough to look green. Under an ExternalSigner or ca_key_provider: openbao a
// signature is a synchronous IPC or network round trip, which is the deployment
// #197 is about, and parking is how that duration becomes controllable rather
// than hoped for. What the specs then assert is a *structural* property — the
// lock is not held here — rather than a timing one, so there is no threshold to
// tune and nothing to go flaky when CI is slow.
//
// The first parkFor calls park until release is closed; every call after that
// passes straight through. That split is load-bearing: the paths under test
// sign more than once (revoking re-signs the CRL), and a signer that parked
// unconditionally would hang the very operation a spec needs to complete while
// the OCSP signature is held open.
type parkingSigner struct {
	inner   crypto.Signer
	entered chan struct{} // one send per parked call
	release chan struct{} // closed to let every parked call return

	parked atomic.Int64 // calls currently stopped inside Sign
	remain atomic.Int64 // parks left to hand out

	mu   sync.Mutex
	peak int64 // high-water mark of parked, for the concurrency spec
}

// newParkingSigner wraps inner so that the next parkFor signatures stop until
// the returned signer is released.
func newParkingSigner(inner crypto.Signer, parkFor int) *parkingSigner {
	p := &parkingSigner{
		inner:   inner,
		entered: make(chan struct{}, parkFor),
		release: make(chan struct{}),
	}
	p.remain.Store(int64(parkFor))
	return p
}

func (p *parkingSigner) Public() crypto.PublicKey { return p.inner.Public() }

func (p *parkingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if p.remain.Add(-1) >= 0 {
		n := p.parked.Add(1)
		p.mu.Lock()
		if n > p.peak {
			p.peak = n
		}
		p.mu.Unlock()

		p.entered <- struct{}{}
		<-p.release
		p.parked.Add(-1)
	}
	return p.inner.Sign(r, digest, opts)
}

// Parked reports how many signatures are stopped inside Sign right now. A spec
// asserts on this to show that whatever else completed did so *while* the
// signature was still in flight, rather than after a late unblock — an
// end-state assertion alone is satisfied by both.
func (p *parkingSigner) Parked() int64 { return p.parked.Load() }

// Peak reports the most signatures ever parked at once.
func (p *parkingSigner) Peak() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

// Release lets every parked signature return. Safe to call more than once so a
// cleanup can guarantee it without coordinating with the spec body; without
// that guarantee a failed assertion leaks a goroutine parked forever and the
// suite hangs instead of reporting the failure.
func (p *parkingSigner) Release() {
	select {
	case <-p.release:
	default:
		close(p.release)
	}
}

// The OCSP responder signs its answers. Until #197 it did so holding c.mu
// exclusively, which made the signature a process-wide serialisation point:
// every OCSP response, and every reader of the CA's in-memory state, waited
// behind it. These specs pin that it no longer is.
//
// They are written to fail against the arrangement they replace, and were run
// against it. With the signature back inside c.mu:
//
//   - "leaves the hot authentication read path free" fails at the reader's
//     Eventually — IsRevokedSerial takes c.mu.RLock and cannot get it;
//   - "signs two responses at once" fails waiting for the second signature to
//     start, and reports a peak of 1.
//
// The third spec guards the hazard the fix introduces rather than one it
// removes, so it has a different mutation; see its own comment.
var _ = Describe("OCSP response signing and the CA lock", func() {
	var (
		ctx    context.Context
		tmpDir string
		myCA   *ca.CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-ocsp-lockscope")
		Expect(err).NotTo(HaveOccurred())
		myCA = setupOCSPCA(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	// issueFor mints a certificate and returns an OCSP request for it. The
	// certificate is issued before the signer is swapped, so issuance itself
	// never parks.
	issueFor := func(subject string) []byte {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		reqDER, err := testutil.BuildOCSPRequest(decodeCert(certPEM), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		return reqDER
	}

	// noncedFor is the same but with a fresh nonce, which bypasses the response
	// cache (RFC 8954) and so always takes the signing path.
	noncedFor := func(subject string) []byte {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		nonce := make([]byte, 16)
		_, err = rand.Read(nonce)
		Expect(err).NotTo(HaveOccurred())
		reqDER, err := testutil.BuildOCSPRequestWithNonce(decodeCert(certPEM), myCA.CACert, nonce)
		Expect(err).NotTo(HaveOccurred())
		return reqDER
	}

	// park swaps the CA key for one that stops inside the next parkFor
	// signatures. CACert/CAKey are immutable after Init in production — nothing
	// outside the Init path writes them — so assigning here is a spec taking
	// advantage of a field it knows is quiet, not a supported operation.
	park := func(parkFor int) *parkingSigner {
		signer := newParkingSigner(myCA.CAKey, parkFor)
		myCA.CAKey = signer
		DeferCleanup(signer.Release)
		return signer
	}

	It("leaves the hot authentication read path free while a response is signed", func() {
		reqDER := noncedFor("ocsp-lock-reader-node")
		signer := park(1)

		responded := make(chan error, 1)
		go func() {
			_, err := myCA.OCSPResponse(ctx, reqDER)
			responded <- err
		}()

		// Wait until the signature is genuinely under way. Everything below
		// happens while it is still stopped inside Sign.
		Eventually(signer.entered, 5*time.Second).Should(Receive(),
			"the OCSP response should have reached the signing step")

		// IsRevokedSerial is what every authenticated request runs to decide
		// whether the presented certificate is revoked. It takes c.mu.RLock,
		// so it cannot proceed while the responder holds the write lock.
		readerDone := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(readerDone)
			_, err := myCA.IsRevokedSerial(ctx, myCA.CACert.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
		}()

		Eventually(readerDone, 5*time.Second).Should(BeClosed(),
			"the authentication read path should not wait on the OCSP signature")

		// The reader finished *while* the signature was in flight. Without this
		// the spec would also pass on an arrangement that merely unblocked the
		// reader eventually, which is exactly what holding the lock does.
		Expect(signer.Parked()).To(Equal(int64(1)),
			"the signature should still have been in flight when the reader completed")

		signer.Release()
		Eventually(responded, 5*time.Second).Should(Receive(BeNil()))
	})

	It("signs two responses at once rather than queueing them", func() {
		first := noncedFor("ocsp-lock-parallel-one")
		second := noncedFor("ocsp-lock-parallel-two")
		signer := park(2)

		done := make(chan error, 2)
		for _, reqDER := range [][]byte{first, second} {
			go func() {
				_, err := myCA.OCSPResponse(ctx, reqDER)
				done <- err
			}()
		}

		// Both must reach the signer. Serialised, the second cannot start until
		// the first returns, and the first never returns while parked — so this
		// is the assertion that fails, rather than a slow one that flakes.
		Eventually(signer.entered, 5*time.Second).Should(Receive(),
			"the first OCSP response should have reached the signing step")
		Eventually(signer.entered, 5*time.Second).Should(Receive(),
			"the second OCSP response should sign concurrently with the first")
		Expect(signer.Peak()).To(Equal(int64(2)),
			"both responses should have been in the signer at the same time")

		signer.Release()
		Eventually(done, 5*time.Second).Should(Receive(BeNil()))
		Eventually(done, 5*time.Second).Should(Receive(BeNil()))
	})

	// Signing outside the lock opens a window the serialised version did not
	// have: a revocation can land between the status snapshot and the cache
	// write, and a naive restructure then stores a pre-signed `good` *after*
	// the eviction meant to remove it. It would be served for OCSPValidity —
	// four hours of vouching for a revoked certificate — which is precisely
	// what invalidateOCSPForNewlyRevokedLocked exists to prevent.
	//
	// Unlike the two above, this one does not fail against the pre-#197 code:
	// there the revocation simply waits, so the interleave is unreachable. Its
	// mutation is the guard itself — drop the re-validation before the cache
	// write in AnswerOCSP and this spec fails, reporting Good for a revoked
	// certificate.
	It("does not cache a response a revocation overtook while it was being signed", func() {
		const subject = "ocsp-lock-revoke-race"
		reqDER := issueFor(subject)
		signer := park(1)

		responded := make(chan error, 1)
		go func() {
			_, err := myCA.OCSPResponse(ctx, reqDER)
			responded <- err
		}()

		// The responder has read "not revoked" and is now signing.
		Eventually(signer.entered, 5*time.Second).Should(Receive(),
			"the OCSP response should have reached the signing step")

		// Revoke while that signature is in flight. This is the step the old
		// arrangement made impossible, and it is only reachable because the
		// responder no longer holds c.mu here.
		Expect(myCA.Revoke(ctx, subject)).To(Succeed())
		Expect(signer.Parked()).To(Equal(int64(1)),
			"the revocation should have completed while the signature was in flight")

		signer.Release()
		Eventually(responded, 5*time.Second).Should(Receive(BeNil()))

		// The request carries no nonce, so this second call is served from
		// ocspCache if anything was left there. It must not have been.
		respDER, err := myCA.OCSPResponse(ctx, reqDER)
		Expect(err).NotTo(HaveOccurred())
		parsed, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Status).To(Equal(xocsp.Revoked),
			"a response signed before the revocation must not be cached after it")
	})
})
