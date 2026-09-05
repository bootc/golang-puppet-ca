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

// memLimitEnv returns a getenv serving GOMEMLIMIT and nothing else.
func memLimitEnv(v string) func(string) string {
	return func(k string) string {
		if k == goMemLimitEnv {
			return v
		}
		return ""
	}
}

// defaultCfg is the configuration with none of the three memory keys set, so
// the built-in defaults apply.
func defaultCfg() *serverConfig { return &serverConfig{} }

// writeCgroupFile writes a memory.max fixture and returns its path. The path is
// a file rather than a mount root, which readCgroupMemoryMax reads directly.
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

// The smallest tree budget that can be divided under the default reservations.
// Written as the sum rather than as a literal so it tracks the constants: a spec
// that hard-codes 56MiB stops testing the boundary the moment one moves.
const (
	smallestDivisibleBudget = defaultLauncherReservation + defaultSignerReservation + minFrontendMemoryShare
)

var _ = Describe("dividing the memory budget across the process tree", func() {
	Describe("where the total comes from", func() {
		It("takes an explicit GOMEMLIMIT as the budget for the whole tree", func() {
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("256MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.source).To(Equal(goMemLimitEnv))
			Expect(budget.total).To(Equal(int64(256 << 20)))
		})

		It("prefers an explicit GOMEMLIMIT over the cgroup ceiling", func() {
			// The ruling this pins: deriving must never override a deliberate
			// setting. With both present the operator's value has to win, and
			// the cgroup number must not appear anywhere in the result.
			cgroup := writeCgroupFile("1073741824\n") // 1GiB
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("256MiB"), cgroup)

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.total).To(Equal(int64(256<<20)),
				"the operator's value must win over the cgroup ceiling")
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
			Expect(budget.source).To(Equal(goMemLimitEnv))
		})

		It("derives the budget from the cgroup when GOMEMLIMIT is unset", func() {
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("268435456\n"))

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.source).To(ContainSubstring("cgroup"))
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
		})

		It("treats GOMEMLIMIT=off as no budget rather than as a malformed one", func() {
			// The Go runtime special-cases "off" ahead of its own byte-count
			// parser, so an operator who wrote it disabled the limit
			// deliberately. Reporting it as malformed would tell them their
			// value is wrong when it is not -- and falling through to the cgroup
			// would reinstate the limit they just turned off.
			cgroup := writeCgroupFile("268435456\n")
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("off"), cgroup)

			Expect(kind).To(Equal(budgetNoCeiling), "off is not an error")
			Expect(reason).To(ContainSubstring("off"))
			Expect(budget.total).To(BeZero(), "the cgroup must not be consulted once off is set")
		})

		It("reports a malformed GOMEMLIMIT rather than falling through to the cgroup", func() {
			// Falling through would silently replace the operator's intent with
			// a derived number.
			_, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("240 MiB"), writeCgroupFile("268435456\n"))

			Expect(kind).To(Equal(budgetInvalid))
			Expect(reason).To(ContainSubstring("GOMEMLIMIT"))
			Expect(reason).To(ContainSubstring("240 MiB"))
		})

		It("distinguishes no ceiling anywhere from a ceiling too small to divide", func() {
			// These two reach different log levels: one is every unlimited host
			// and unremarkable, the other is an operator who set a limit and did
			// not get the division. Collapsing them is what made the
			// too-small case invisible at the default verbosity.
			_, absent, _ := resolveMemoryBudget(defaultCfg(), noEnv, missingPath())
			Expect(absent).To(Equal(budgetNoCeiling))

			_, small, _ := resolveMemoryBudget(defaultCfg(), memLimitEnv("32MiB"), missingPath())
			Expect(small).To(Equal(budgetTooSmall))
		})

		DescribeTable("cgroup ceilings that state nothing usable",
			func(contents string) {
				_, kind, _ := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile(contents))
				Expect(kind).To(Equal(budgetNoCeiling))
			},
			Entry("the literal max", "max\n"),
			Entry("an empty file", ""),
			Entry("whitespace only", "  \n"),
			Entry("a non-numeric value", "not-a-number\n"),
			Entry("zero", "0\n"),
			Entry("a negative count", "-1\n"),
		)

		It("accepts a ceiling written without a trailing newline", func() {
			// Gives the "max" case above a sibling it is checked against: without
			// an accepted fixture, deleting the max clause would send it to
			// ParseInt, fail identically, and no assertion could tell.
			budget, kind, _ := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("268435456"))
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
		})
	})

	Describe("headroom on a derived ceiling", func() {
		It("claims only the configured percentage of a cgroup ceiling", func() {
			// GOMEMLIMIT bounds Go memory only; the binary's text, kernel memory
			// and a memory-backed cadir all count against the same cgroup from
			// outside it. Claiming the whole ceiling would apply GC pressure
			// only once the cgroup was already at the wall.
			const ceiling = int64(1) << 30
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("1073741824\n"))

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.ceiling).To(Equal(ceiling))
			// 1GiB at the default 90 percent: 1073741824 * 90 / 100.
			Expect(budget.total).To(Equal(int64(966367641)))
			Expect(budget.total).To(BeNumerically("<", ceiling), "headroom must be withheld")
		})

		It("takes an explicit GOMEMLIMIT at face value, withholding nothing", func() {
			budget, kind, _ := resolveMemoryBudget(defaultCfg(), memLimitEnv("1GiB"), missingPath())
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.total).To(Equal(budget.ceiling),
				"the operator naming a number has already chosen their headroom")
		})

		It("honours memory_budget_percent", func() {
			cfg := &serverConfig{MemoryBudgetPercent: 50}
			budget, kind, _ := resolveMemoryBudget(cfg, noEnv, writeCgroupFile("1073741824\n"))
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.total).To(Equal(int64(1) << 29))
		})

		DescribeTable("a percentage outside 1-100 falls back to the default",
			func(percent int) {
				cfg := &serverConfig{MemoryBudgetPercent: percent}
				budget, kind, _ := resolveMemoryBudget(cfg, noEnv, writeCgroupFile("1073741824\n"))
				Expect(kind).To(Equal(budgetApplied))
				Expect(budget.total).To(Equal(int64(966367641)), "must fall back to the default percentage")
			},
			Entry("zero", 0),
			Entry("negative", -10),
			Entry("above 100", 101),
		)
	})

	Describe("how the total is divided", func() {
		It("gives the launcher and signer fixed reservations and the frontend the rest", func() {
			const total = 256 << 20
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("256MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.launcher).To(Equal(int64(defaultLauncherReservation)))
			Expect(budget.signer).To(Equal(int64(defaultSignerReservation)))
			Expect(budget.frontend).To(Equal(int64(total - defaultLauncherReservation - defaultSignerReservation)))
		})

		It("never hands out more in total than the tree was given", func() {
			// The whole point of #304: three shares that sum above the ceiling
			// are what the inherited-GOMEMLIMIT bug produced. Asserted across a
			// range so a reservation change cannot quietly break the invariant
			// at one size while passing at another.
			for _, total := range []string{"64MiB", "128MiB", "256MiB", "1GiB", "4GiB"} {
				budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv(total), missingPath())

				Expect(kind).To(Equal(budgetApplied), "%s: %s", total, reason)
				Expect(budget.launcher+budget.signer+budget.frontend).
					To(Equal(budget.total), "shares must sum to the budget at %s", total)
			}
		})

		It("divides a budget of exactly the smallest divisible size", func() {
			// The accept side of the floor. Without it the refusal spec below is
			// satisfied by a frontend share of zero, so the floor's VALUE is
			// pinned by nothing and the constant could drop to a single byte
			// with every spec still green.
			budget, kind, reason := resolveMemoryBudget(defaultCfg(),
				memLimitEnv(strconv.FormatInt(smallestDivisibleBudget, 10)), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.frontend).To(Equal(int64(minFrontendMemoryShare)),
				"the frontend must land exactly on its floor")
		})

		It("refuses a budget one byte below the smallest divisible size", func() {
			// The reject side. Together with the spec above this pins both the
			// floor's value and the strictness of the comparison: a < to <= flip
			// fails one of the pair.
			_, kind, reason := resolveMemoryBudget(defaultCfg(),
				memLimitEnv(strconv.FormatInt(smallestDivisibleBudget-1, 10)), missingPath())

			Expect(kind).To(Equal(budgetTooSmall))
			Expect(reason).To(ContainSubstring(strconv.FormatInt(minFrontendMemoryShare, 10)),
				"the reason must name the floor the operator has to clear")
		})

		// The two specs above pin the STRICTNESS of the floor comparison but not
		// its value: their totals are derived from the same constants, so the
		// boundary moves with a mutation and both stay green with the floor set
		// to a single byte (verified by mutation). These two bracket it with
		// absolute totals instead, and they are the chart's own requests.memory
		// and limits.memory, so the bracket is a configuration that really
		// occurs rather than an arbitrary pair.
		It("refuses 48MiB, which clears both reservations but leaves the frontend under its floor", func() {
			// 48 - 8 launcher - 24 signer leaves 16MiB. This fails if the floor
			// drops to 16MiB or below.
			_, kind, _ := resolveMemoryBudget(defaultCfg(), memLimitEnv("48MiB"), missingPath())
			Expect(kind).To(Equal(budgetTooSmall))
		})

		It("divides 64MiB, the chart's default limit, leaving the frontend 32MiB", func() {
			// Fails if the floor rises above 32MiB. With the spec above, the
			// floor is bracketed to (16MiB, 32MiB].
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("64MiB"), missingPath())
			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.frontend).To(Equal(int64(32 << 20)))
		})

		It("names the source in the too-small reason, so the advice is actionable", func() {
			// The reason once told an operator on the derived path to "unset
			// GOMEMLIMIT" -- a variable that path only reaches because it is
			// already unset.
			_, kind, viaCgroup := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("33554432\n"))
			Expect(kind).To(Equal(budgetTooSmall))
			Expect(viaCgroup).To(ContainSubstring("cgroup"))
			Expect(viaCgroup).NotTo(ContainSubstring("unset GOMEMLIMIT"))

			_, kind, viaEnv := resolveMemoryBudget(defaultCfg(), memLimitEnv("32MiB"), missingPath())
			Expect(kind).To(Equal(budgetTooSmall))
			Expect(viaEnv).To(ContainSubstring(goMemLimitEnv))
		})

		It("honours configured reservations, which is how a large fleet reaches the signer", func() {
			// The signer's share does not scale with the tree total, so this key
			// is the only way an operator past ~60,000 certificates can give it
			// more. If this stops working the documented remedy has no effect.
			cfg := &serverConfig{MemoryReserveSigner: "64MiB", MemoryReserveLauncher: "16MiB"}
			budget, kind, reason := resolveMemoryBudget(cfg, memLimitEnv("512MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.signer).To(Equal(int64(64 << 20)))
			Expect(budget.launcher).To(Equal(int64(16 << 20)))
			Expect(budget.frontend).To(Equal(int64(512<<20 - 64<<20 - 16<<20)))
		})

		DescribeTable("a malformed reservation falls back to its default rather than failing",
			func(value string) {
				cfg := &serverConfig{MemoryReserveSigner: value}
				budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())
				Expect(kind).To(Equal(budgetApplied))
				Expect(budget.signer).To(Equal(int64(defaultSignerReservation)))
			},
			Entry("not a byte count", "enormous"),
			Entry("zero", "0"),
			Entry("negative", "-1"),
			Entry("a decimal", "1.5GiB"),
		)
	})

	Describe("which share reaches which process", func() {
		// spawnChild picks the share by the role it is already spawning, so a
		// transposition cannot be expressed. These pin the mapping itself.
		budget := memoryBudget{launcher: 1, signer: 2, frontend: 3}

		DescribeTable("shareFor maps a role to its own share",
			func(role string, want int64) {
				Expect(budget.shareFor(role)).To(Equal(want))
			},
			Entry("launcher", "launcher", int64(1)),
			Entry("signer", "signer", int64(2)),
			Entry("frontend", "frontend", int64(3)),
		)

		It("returns no limit for an unknown role", func() {
			Expect(budget.shareFor("bootstrap")).To(BeZero())
		})

		It("returns no limit for every role when no budget was resolved", func() {
			// Zero means "leave the runtime default alone". It must never be
			// handed to debug.SetMemoryLimit as a limit, which would collapse
			// the process into permanent GC.
			var none memoryBudget
			for _, role := range []string{"launcher", "signer", "frontend"} {
				Expect(none.shareFor(role)).To(BeZero(), "role %s", role)
			}
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
		// refused by the child, and anything it rejects that the runtime accepts
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
		// The shift-overflow guard. Without these the guard could be deleted
		// with every other entry still green: the largest value above is 1TiB,
		// which is nowhere near the threshold.
		Entry("the largest TiB count that does not overflow", "4194303TiB", int64(4194303)<<40, true),
		Entry("one TiB past the overflow threshold", "4194305TiB", int64(0), false),
		Entry("a count that overflows the shift wildly", "16777216TiB", int64(0), false),
		Entry("digits that overflow ParseInt itself", "99999999999999999999", int64(0), false),
	)

	Describe("what the child process actually receives", func() {
		// These spawn a real child through the production spawnChild and read
		// back debug.SetMemoryLimit(-1) from inside it. Asserting cmd.Env would
		// only show the string the launcher built; this shows the limit the
		// child's runtime applied, so a value that is delivered but never
		// honoured cannot pass.
		spawnReporting := func(baseEnv []string, budget memoryBudget, role string) int64 {
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

			cmd, err := spawnChild(os.Args[0], env, role, sock, hex.EncodeToString(psk), budget)
			Expect(err).NotTo(HaveOccurred())
			Expect(cmd.Wait()).To(Succeed(), "the reporting child must exit cleanly")

			raw, err := os.ReadFile(out)
			Expect(err).NotTo(HaveOccurred(), "the child must have reported a limit")
			limit, err := strconv.ParseInt(string(raw), 10, 64)
			Expect(err).NotTo(HaveOccurred())
			return limit
		}

		It("applies the share belonging to the role it spawned", func() {
			const signerShare = 64 << 20
			budget := memoryBudget{signer: signerShare, frontend: 512 << 20}
			Expect(spawnReporting(envWithoutMemLimit(), budget, "signer")).
				To(Equal(int64(signerShare)), "the signer must get the signer's share, not the frontend's")
		})

		It("overrides a tree-wide GOMEMLIMIT the child would otherwise inherit", func() {
			// The defect itself. The child's environment carries the operator's
			// whole-tree value, exactly as it does in production; the share is
			// appended after it and must win. This is the spec that goes red if
			// spawnChild stops appending, because the child would then come up
			// on the inherited total.
			const share = 64 << 20
			inherited := append(envWithoutMemLimit(), goMemLimitEnv+"=256MiB")

			Expect(spawnReporting(inherited, memoryBudget{signer: share}, "signer")).To(Equal(int64(share)),
				"the child's share must win over the inherited tree-wide total")
		})

		It("leaves the runtime default alone when there is no budget", func() {
			// Zero means "no budget was resolved", which must not be mistaken for
			// a limit of zero -- that would collapse the child into permanent GC.
			Expect(spawnReporting(envWithoutMemLimit(), memoryBudget{}, "signer")).
				To(BeNumerically(">", int64(1)<<40),
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
