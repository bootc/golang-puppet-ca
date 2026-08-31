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

package ca

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// publishedUpstream is unexported and both its callers now hand it bytes they
// already read, so this is the only place its own contract can be stated: the
// distinction between "nothing is published" and "nothing could be read".
// Collapsing the two is what would let a rolled-back chain file through, and it
// is one nil argument away from being reintroduced.
var _ = Describe("publishedUpstream", func() {
	It("refuses to check regressions against a chain nobody read", func() {
		c := &CA{}
		_, err := c.publishedUpstream(nil)
		Expect(err).To(MatchError(ContainSubstring("the published chain was not read")),
			"a nil blob must fail closed, not read as an empty published set")
	})

	It("accepts an empty blob as a genuinely empty published chain", func() {
		// A CA whose CRL has not been written yet. Refusing this too would stop
		// it ever publishing a chain.
		c := &CA{}
		upstream, err := c.publishedUpstream([]byte{})
		Expect(err).NotTo(HaveOccurred())
		Expect(upstream).To(BeEmpty())
	})
})

// The stranded-read ceiling. readCRLChainFile spawns a goroutine it cannot
// cancel, because os.Open and io.ReadAll are uninterruptible; under a wedged
// mount that goroutine never returns and keeps its descriptor. upstreamCRLs
// reaches this on every CRL amendment -- every revocation, cleanup and re-sign,
// not only the hourly refresh -- so without a ceiling the strandings accumulate
// without limit until the process runs out of descriptors for unrelated work,
// storage I/O included.
//
// Driven here rather than through a FIFO because a real stranded read never
// returns, so a black-box spec that filled the slots could not give them back
// and would starve every later spec in the package. The counting is done
// against whatever is free at the time, so this stays correct alongside the
// FIFO spec in crlchainstall_test.go, which does permanently strand one.
var _ = Describe("readCRLChainFile: the stranded-read ceiling", func() {
	It("refuses a new read rather than stranding one past the ceiling", func() {
		// Fill whatever is free, remembering how much, so the slots can be given
		// back exactly. Never blocks: the loop stops when the buffer is full.
		held := 0
		defer func() {
			for range held {
				<-crlChainReadSem
			}
		}()
	fill:
		for held < crlChainReadSlots {
			select {
			case crlChainReadSem <- struct{}{}:
				held++
			default:
				break fill
			}
		}
		Expect(held).To(BeNumerically(">", 0), "the ceiling must have had room to fill")

		// A path that would read instantly if it were reached at all -- so a pass
		// here is the refusal, not a timeout dressed up as one.
		_, err := readCRLChainFile(context.Background(), "/dev/null")
		Expect(err).To(MatchError(ContainSubstring("already stranded")),
			"a read past the ceiling must be refused, not spawned")
		Expect(err).NotTo(MatchError(context.DeadlineExceeded),
			"the refusal must be immediate, not the 10s timeout")
	})

	It("reads normally once a slot is free again", func() {
		// The ceiling is a ceiling, not a latch: a mount that recovers must not
		// leave the feature permanently refusing.
		data, err := readCRLChainFile(context.Background(), "/dev/null")
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(BeEmpty())
	})
})
