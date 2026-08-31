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
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// parkingSigner wraps the CA key and stops inside Sign, so a spec can hold a
// signature open and observe what the rest of the process can do meanwhile.
//
// It exists because the cost this file is about is invisible at normal speeds.
// The suite's CA key is RSA-2048, so a local signature is on the order of a
// millisecond — far too fast to race against reliably. A spec that merely
// started goroutines would pass against the serialised arrangement often enough
// to look green. Under an ExternalSigner or ca_key_provider: openbao a
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
	calls  atomic.Int64 // every Sign entry, parked or not

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
	p.calls.Add(1)
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

// Calls reports how many signatures were entered at all, parked or not. A spec
// asserting a signature did *not* happen must use this rather than Peak: with a
// park budget Peak would answer the question, but only by parking the signature
// it is trying to prove never occurred, which turns a failure into a deadlock
// instead of an assertion.
func (p *parkingSigner) Calls() int64 { return p.calls.Load() }

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

// failingSigner refuses to sign. It is the other half of what parkingSigner
// does: parking pins a signature open, this one makes it fail, and both exist
// because the interesting behaviour of AnswerOCSP is what happens around the
// signature rather than in it.
type failingSigner struct {
	inner crypto.Signer
	err   error
}

func (f *failingSigner) Public() crypto.PublicKey { return f.inner.Public() }

func (f *failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, f.err
}

// The OCSP responder signs its answers. Until #197 it did so holding c.mu
// exclusively, which made the signature a process-wide serialisation point:
// every OCSP response, and every reader of the CA's in-memory state, waited
// behind it. These specs pin that it no longer is.
//
// The first two are written to fail against the arrangement they replace, and
// were run against it. With the signature back inside c.mu:
//
//   - "leaves the hot authentication read path free" fails at the reader's
//     Eventually — IsRevokedSerial takes c.mu.RLock and cannot get it;
//   - "signs two responses at once" fails waiting for the second signature to
//     start, and reports a peak of 1.
//
// Neither of those two discriminates a hypothetical variant that signs while
// still holding c.mu.RLock, since both of their observers are themselves
// readers. The two raced-guard specs below do: each requires an operation
// needing the *write* lock — a Revoke, an index sync — to complete while the
// signature is held open. They are the reason the claim is "no CA lock" rather
// than "no write lock".
//
// Those two guard the hazard the fix introduces rather than one it removes, so
// they have their own mutations, and both were run:
//
//   - dropping the re-validation before the cache write fails both on the
//     cached status, which is asserted first for exactly that reason;
//   - decoupling MaxAge from whether the response was actually cached leaves
//     the cache correct and fails both on the advertised reuse window.
//
// Each mutation kills the specs that guard it and leaves the other two green.
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
	// signatures. Nothing rewrites CACert/CAKey in a serving process, and this
	// assignment happens before any goroutine that reads them is started, so
	// the spec is taking advantage of a field it knows is quiet rather than
	// performing a supported operation.
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
	// have: the answer can change between the status snapshot and the cache
	// write, and a naive restructure then stores a response that stopped being
	// true while it was being signed. It would be served for OCSPValidity —
	// four hours — which is precisely what invalidateOCSPForNewlyRevokedLocked
	// and dropSerialLocked exist to prevent.
	//
	// Unlike the two above, these two do not fail against the pre-#197 code:
	// there the revocation or prune simply waits, so the interleave is
	// unreachable. Their mutation is the guard itself — drop the re-validation
	// before the cache write in AnswerOCSP and both fail.
	//
	// Each also pins the *emitted* half. Declining to store the response in
	// ocspCache stops this process replaying it, but a non-zero MaxAge would
	// hand every shared proxy four hours of licence to serve it on; half a
	// guard is not a guard.
	It("does not cache or advertise a response a revocation overtook while it was being signed", func() {
		const subject = "ocsp-lock-revoke-race"
		reqDER := issueFor(subject)
		signer := park(1)

		answered := make(chan ca.OCSPAnswer, 1)
		go func() {
			defer GinkgoRecover()
			answer, err := myCA.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			answered <- answer
		}()

		// The responder has read "not revoked" and is now signing.
		Eventually(signer.entered, 5*time.Second).Should(Receive(),
			"the OCSP response should have reached the signing step")

		// Revoke while that signature is in flight. Revoke needs c.mu
		// *exclusively*, so this is what discriminates "the responder holds no
		// CA lock" from the weaker "it holds only a read lock" — and running it
		// in a goroutine with a bounded wait means a regression to either of
		// those reports a failure here rather than deadlocking the suite until
		// go test's default timeout.
		revoked := make(chan error, 1)
		go func() { revoked <- myCA.Revoke(ctx, subject) }()
		Eventually(revoked, 5*time.Second).Should(Receive(BeNil()),
			"a revocation should not wait on the OCSP signature")
		Expect(signer.Parked()).To(Equal(int64(1)),
			"the revocation should have completed while the signature was in flight")

		signer.Release()

		var answer ca.OCSPAnswer
		Eventually(answered, 5*time.Second).Should(Receive(&answer))

		// Assert the cache before the reuse window, so the two mutations this
		// spec records die on different lines: dropping the re-validation
		// poisons the cache and fails here, while decoupling MaxAge from
		// whether the write survived leaves the cache correct and fails below.
		// Ordered the other way, both would stop at the same assertion and
		// neither would demonstrate what the other guards.
		//
		// The request carries no nonce, so this second call is served from
		// ocspCache if anything was left there. It must not have been.
		respDER, err := myCA.OCSPResponse(ctx, reqDER)
		Expect(err).NotTo(HaveOccurred())
		parsed, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Status).To(Equal(xocsp.Revoked),
			"a response signed before the revocation must not be cached after it")

		// The overtaken response is still handed to the caller that asked for
		// it — AnswerOCSP says so, and this race is the only place that
		// contract is reachable, so nothing else can pin it. Without this an
		// over-correction that withheld the response entirely would satisfy
		// every other assertion here and reach the handler as an empty body.
		Expect(answer.DER).NotTo(BeEmpty(),
			"the overtaken response should still be returned to its caller")
		overtaken, err := xocsp.ParseResponse(answer.DER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(overtaken.Status).To(Equal(xocsp.Good),
			"the overtaken response should say what was true when it was signed")

		Expect(answer.MaxAge).To(BeZero(),
			"a response a revocation overtook must not be advertised as reusable")
	})

	// The signature is the expensive step, so an abandoned request should not
	// reach it.
	//
	// A park budget of zero, deliberately: the signer only counts here. Parking
	// the signature would make the guard's absence show up as a deadlock — the
	// spec blocks inside Sign until go test's timeout, with a goroutine dump
	// instead of an assertion — which is the same trap the raced-revocation spec
	// above had to be rewritten to avoid. Counting makes the mutation fail on a
	// named line in under a second.
	It("does not sign for a request whose context is already cancelled", func() {
		reqDER := issueFor("ocsp-lock-cancelled")
		signer := park(0)

		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		_, err := myCA.AnswerOCSP(cancelled, reqDER)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(context.Canceled))
		Expect(err).To(MatchError(ca.ErrInternal),
			"a cancelled request is a server-side failure, not a malformed one — "+
				"the handler must answer internalError rather than malformedRequest")
		Expect(signer.Calls()).To(BeZero(),
			"the signer should never have been entered for an abandoned request")
	})

	// A signer that fails is a *server* fault, and the classification is the
	// whole point: ErrInternal reaches the HTTP layer as RFC 6960 internalError,
	// which a verifier may retry, where malformedRequest tells it not to and
	// blames its request for an outage that was never its fault.
	//
	// Worth pinning rather than trusting, because the failure is silent in the
	// direction that matters. If this regressed, responses would still be
	// produced, nothing would error in CI, and the only symptom would be
	// verifiers declining to retry a signer outage — visible in their logs, not
	// ours. internal/api/ocsp_test.go pins the HTTP half.
	It("reports a signer failure as an internal error, not a malformed request", func() {
		reqDER := issueFor("ocsp-lock-signer-fails")
		myCA.CAKey = &failingSigner{inner: myCA.CAKey, err: errors.New("signer unavailable")}

		_, err := myCA.AnswerOCSP(ctx, reqDER)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrInternal),
			"a failed CA signature is a server fault; the handler must answer "+
				"internalError rather than malformedRequest")
		Expect(err.Error()).To(ContainSubstring("signer unavailable"),
			"the underlying signer error should survive for the operator's log")
	})

	// The prune half of the same guard, and not a duplicate of the revocation
	// case: it flips the serial out of serialIndex rather than onto the CRL, so
	// it takes decideOCSPStatus's !known early return instead of the CRL scan,
	// and the failure it prevents is different — a `good` re-inserted under a
	// serial the index has just forgotten, resurrecting the very entry
	// dropSerialLocked deleted because "a pre-signed answer derived from an
	// index entry must not outlive it".
	It("does not cache a response a prune overtook while it was being signed", func() {
		const subject = "ocsp-lock-prune-race"
		reqDER := issueFor(subject)
		signer := park(1)

		answered := make(chan ca.OCSPAnswer, 1)
		go func() {
			defer GinkgoRecover()
			answer, err := myCA.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			answered <- answer
		}()

		Eventually(signer.entered, 5*time.Second).Should(Receive(),
			"the OCSP response should have reached the signing step")

		// Prune the serial out of the index while the signature is in flight.
		// SyncSerialIndex reconciles against storage, so the inventory row has
		// to go first — PruneInventory rather than TouchInventory, which is a
		// no-op when the inventory already exists and would leave this spec
		// asserting nothing.
		dropped, err := myCA.Storage.PruneInventory(ctx, func(e storage.InventoryEntry) bool {
			return e.Subject != subject
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(dropped).To(HaveLen(1), "the inventory row for the subject should have been removed")
		pruned := make(chan error, 1)
		go func() {
			_, err := myCA.SyncSerialIndex(ctx)
			pruned <- err
		}()
		Eventually(pruned, 5*time.Second).Should(Receive(BeNil()),
			"an index sync should not wait on the OCSP signature")
		Expect(signer.Parked()).To(Equal(int64(1)),
			"the sync should have completed while the signature was in flight")

		signer.Release()

		var answer ca.OCSPAnswer
		Eventually(answered, 5*time.Second).Should(Receive(&answer))

		// Cache first, then the reuse window — see the sibling spec above for
		// why the order is what keeps the two mutations distinguishable.
		//
		// The serial is no longer in the index, so a fresh answer is `unknown`.
		// A resurrected cache entry would report Good instead.
		respDER, err := myCA.OCSPResponse(ctx, reqDER)
		Expect(err).NotTo(HaveOccurred())
		parsed, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Status).To(Equal(xocsp.Unknown),
			"a response signed before the prune must not be cached after it")

		Expect(answer.DER).NotTo(BeEmpty(),
			"the overtaken response should still be returned to its caller")
		overtaken, err := xocsp.ParseResponse(answer.DER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(overtaken.Status).To(Equal(xocsp.Good),
			"the overtaken response should say what was true when it was signed")

		Expect(answer.MaxAge).To(BeZero(),
			"a response a prune overtook must not be advertised as reusable")
	})
})
