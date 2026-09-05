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
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/signer"
)

// noEnv is a getenv that reports every variable as unset.
func noEnv(string) string { return "" }

// envOf returns a getenv serving exactly the given pairs.
func envOf(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

// writeCgroupFile writes a cgroup v2 memory.max fixture and returns its path.
func writeCgroupFile(contents string) string {
	path := filepath.Join(GinkgoT().TempDir(), "memory.max")
	Expect(os.WriteFile(path, []byte(contents), 0o600)).To(Succeed())
	return path
}

// missingPath names a file that does not exist, standing in for a host with no
// unified cgroup hierarchy.
func missingPath() string {
	return filepath.Join(GinkgoT().TempDir(), "no-such-file")
}

var _ = Describe("dividing the memory budget across the process tree", func() {
	Describe("where the total comes from", func() {
		It("takes an explicit GOMEMLIMIT as the budget for the whole tree", func() {
			budget, ok, reason := resolveMemoryBudget(
				envOf(map[string]string{goMemLimitEnv: "256MiB"}), missingPath())

			Expect(ok).To(BeTrue(), "reason: %s", reason)
			Expect(budget.source).To(Equal("GOMEMLIMIT"))
			Expect(budget.total).To(Equal(int64(256 << 20)))
		})

		It("prefers an explicit GOMEMLIMIT over the cgroup ceiling", func() {
			// The ruling this pins: deriving must never override a deliberate
			// setting. With both present the operator's value has to win, and
			// the cgroup number must not appear anywhere in the result.
			cgroup := writeCgroupFile("1073741824\n") // 1GiB
			budget, ok, reason := resolveMemoryBudget(
				envOf(map[string]string{goMemLimitEnv: "256MiB"}), cgroup)

			Expect(ok).To(BeTrue(), "reason: %s", reason)
			Expect(budget.total).To(Equal(int64(256<<20)),
				"the operator's value must win over the cgroup ceiling")
			Expect(budget.source).To(Equal("GOMEMLIMIT"))
		})

		It("derives the budget from the cgroup when GOMEMLIMIT is unset", func() {
			budget, ok, reason := resolveMemoryBudget(noEnv, writeCgroupFile("268435456\n"))

			Expect(ok).To(BeTrue(), "reason: %s", reason)
			Expect(budget.total).To(Equal(int64(256 << 20)))
			Expect(budget.source).To(ContainSubstring("cgroup"))
		})

		It("divides nothing when the cgroup is unlimited", func() {
			_, ok, reason := resolveMemoryBudget(noEnv, writeCgroupFile("max\n"))

			Expect(ok).To(BeFalse())
			Expect(reason).To(ContainSubstring("no cgroup memory ceiling"))
		})

		It("divides nothing outside a cgroup, which is the pre-existing behaviour", func() {
			_, ok, _ := resolveMemoryBudget(noEnv, missingPath())
			Expect(ok).To(BeFalse())
		})

		It("names a malformed GOMEMLIMIT rather than falling through to the cgroup", func() {
			// Falling through would silently replace the operator's intent with a
			// derived number, and the child's runtime would refuse the value
			// anyway -- so the launcher has to be the one that says which
			// variable was wrong.
			_, ok, reason := resolveMemoryBudget(
				envOf(map[string]string{goMemLimitEnv: "240 MiB"}), writeCgroupFile("268435456\n"))

			Expect(ok).To(BeFalse())
			Expect(reason).To(ContainSubstring("GOMEMLIMIT"))
			Expect(reason).To(ContainSubstring("240 MiB"))
		})
	})

	Describe("how the total is divided", func() {
		It("gives the launcher and signer fixed reservations and the frontend the rest", func() {
			const total = 256 << 20
			budget, ok, reason := resolveMemoryBudget(
				envOf(map[string]string{goMemLimitEnv: "256MiB"}), missingPath())

			Expect(ok).To(BeTrue(), "reason: %s", reason)
			Expect(budget.launcher).To(Equal(int64(launcherMemoryReservation)))
			Expect(budget.signer).To(Equal(int64(signerMemoryReservation)))
			Expect(budget.frontend).To(Equal(int64(total - launcherMemoryReservation - signerMemoryReservation)))
		})

		It("never hands out more in total than the tree was given", func() {
			// The whole point of #304: three shares that sum above the ceiling
			// are what the inherited-GOMEMLIMIT bug produced. Asserted across a
			// range so a reservation change cannot quietly break the invariant
			// at one size while passing at another.
			for _, total := range []string{"64MiB", "128MiB", "256MiB", "1GiB", "4GiB"} {
				budget, ok, reason := resolveMemoryBudget(
					envOf(map[string]string{goMemLimitEnv: total}), missingPath())

				Expect(ok).To(BeTrue(), "%s: %s", total, reason)
				Expect(budget.launcher+budget.signer+budget.frontend).
					To(Equal(budget.total), "shares must sum to the budget at %s", total)
			}
		})

		It("refuses to divide a budget too small to leave the frontend a workable share", func() {
			// A share near a process's live heap causes continuous GC rather than
			// a failure, so an over-tight split trades a visible OOMKill for a
			// silent death spiral. Below the floor, not dividing is the better
			// outcome -- and it has to say so.
			_, ok, reason := resolveMemoryBudget(
				envOf(map[string]string{goMemLimitEnv: "32MiB"}), missingPath())

			Expect(ok).To(BeFalse())
			Expect(reason).To(ContainSubstring("too small"))
		})
	})

	DescribeTable("parsing the byte counts the Go runtime accepts",
		func(in string, want int64, valid bool) {
			got, ok := parseGoByteCount(in)
			Expect(ok).To(Equal(valid), "validity of %q", in)
			if valid {
				Expect(got).To(Equal(want), "value of %q", in)
			}
		},
		// The runtime's grammar is ^[0-9]+(([KMGT]i)?B)?$ -- anything this
		// accepts that the runtime rejects would be divided here and then
		// refused by the child; anything it rejects that the runtime accepts
		// would silently fall through to the cgroup and override the operator.
		Entry("a bare byte count", "1024", int64(1024), true),
		Entry("an explicit B suffix", "1024B", int64(1024), true),
		Entry("KiB", "1KiB", int64(1024), true),
		Entry("MiB, as the chart documents", "240MiB", int64(240<<20), true),
		Entry("GiB", "2GiB", int64(2<<30), true),
		Entry("TiB", "1TiB", int64(1<<40), true),
		Entry("zero", "0", int64(0), true),
		Entry("the empty string", "", int64(0), false),
		Entry("a decimal, which the runtime does not accept", "1.5GiB", int64(0), false),
		Entry("lowercase units", "1kib", int64(0), false),
		Entry("a lowercase B", "1Mb", int64(0), false),
		Entry("SI rather than IEC", "1MB", int64(0), false),
		Entry("a suffix with no digits", "MiB", int64(0), false),
		Entry("an unknown IEC prefix", "1XiB", int64(0), false),
		Entry("a bare i before B", "1iB", int64(0), false),
		Entry("an embedded space", "240 MiB", int64(0), false),
		Entry("a negative count", "-1", int64(0), false),
		Entry("hexadecimal", "0x10", int64(0), false),
	)

	Describe("what the child process actually receives", func() {
		// These spawn a real child through the production spawnChild and read
		// back debug.SetMemoryLimit(-1) from inside it. Asserting cmd.Env would
		// only show the string the launcher built; this shows the limit the
		// child's runtime applied, so a value that is delivered but never
		// honoured cannot pass.
		spawnReporting := func(baseEnv []string, share int64) int64 {
			GinkgoHelper()
			out := filepath.Join(GinkgoT().TempDir(), "limit")
			sock, otherEnd, err := signer.Socketpair()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = otherEnd.Close() })

			psk := make([]byte, 32)
			_, err = rand.Read(psk)
			Expect(err).NotTo(HaveOccurred())

			env := append([]string{}, baseEnv...)
			env = append(env, pskChildEnv+"=report-memlimit", memLimitOutEnv+"="+out)

			cmd, err := spawnChild(os.Args[0], env, "signer", sock, hex.EncodeToString(psk), share)
			Expect(err).NotTo(HaveOccurred())
			Expect(cmd.Wait()).To(Succeed(), "the reporting child must exit cleanly")

			raw, err := os.ReadFile(out)
			Expect(err).NotTo(HaveOccurred(), "the child must have reported a limit")
			limit, err := strconv.ParseInt(string(raw), 10, 64)
			Expect(err).NotTo(HaveOccurred())
			return limit
		}

		It("applies the share the launcher computed", func() {
			const share = 64 << 20
			Expect(spawnReporting(envWithoutMemLimit(), share)).To(Equal(int64(share)))
		})

		It("overrides a tree-wide GOMEMLIMIT the child would otherwise inherit", func() {
			// The defect itself. The child's environment carries the operator's
			// whole-tree value, exactly as it does in production; the share is
			// appended after it and must win. This is the spec that goes red if
			// spawnChild stops appending, because the child would then come up
			// on the inherited total.
			const share = 64 << 20
			inherited := append(envWithoutMemLimit(), goMemLimitEnv+"=256MiB")

			Expect(spawnReporting(inherited, share)).To(Equal(int64(share)),
				"the child's share must win over the inherited tree-wide total")
		})

		It("leaves the runtime default alone when there is no share", func() {
			// Zero means "no budget was resolved", which must not be mistaken for
			// a limit of zero -- that would collapse the child into permanent GC.
			Expect(spawnReporting(envWithoutMemLimit(), 0)).To(BeNumerically(">", int64(1)<<40),
				"an unlimited runtime reports a very large limit, not zero")
		})
	})
})

// envWithoutMemLimit is the test process's environment with GOMEMLIMIT removed,
// so a value set on the runner cannot decide the outcome of a spec about
// GOMEMLIMIT.
func envWithoutMemLimit() []string {
	return filterEnv(os.Environ(), goMemLimitEnv)
}
