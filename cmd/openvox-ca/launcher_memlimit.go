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
	"os"
	"strconv"
	"strings"
)

// GOMEMLIMIT is a per-process knob, but the default deployment is a process
// tree: this launcher supervises an isolated signer and a frontend. Left to
// inherit it, all three apply the operator's value independently -- so
// GOMEMLIMIT set to just under the container limit, which is what the chart
// documentation recommends, yields three times that in aggregate soft limit.
// No runtime ever feels pressure and the cgroup wall arrives first: the advice
// given to convert an OOMKill into GC pressure removes the GC pressure it was
// meant to create.
//
// The launcher is the only process that can divide the budget, because it is
// the only one that knows the tree exists.
//
// GOMAXPROCS is deliberately left alone. Since Go 1.25 the runtime derives it
// from the cgroup CPU limit when it is unset (the containermaxprocs and
// updatemaxprocs GODEBUGs), and there is no memory equivalent anywhere in the
// runtime. The asymmetry is principled rather than an oversight: CPU is
// time-sliced, so three runtimes sizing to the same quota costs parked threads
// and GC workers, whereas memory is a hard ceiling and triple-counting it is
// fatal. An operator who sets GOMAXPROCS explicitly does still have it
// inherited by all three, which is the same shape at far lower stakes.
const goMemLimitEnv = "GOMEMLIMIT"

// cgroupV2MemoryMax is the unified-hierarchy file holding this process's memory
// ceiling. It reads a decimal byte count, or the literal "max" when the cgroup
// is unlimited.
//
// cgroup v1's memory.limit_in_bytes is deliberately not consulted. It reports a
// near-int64-max sentinel rather than a word when unlimited, so a v1 reader that
// forgot the sentinel would derive an absurd budget and silently divide it --
// worse than deriving nothing. The unified hierarchy has been the default on
// every distribution this project targets for years, and an operator on v1 can
// still set GOMEMLIMIT explicitly, which takes precedence anyway.
const cgroupV2MemoryMax = "/sys/fs/cgroup/memory.max"

// The launcher's and signer's shares are absolute reservations rather than
// percentages, and the frontend takes whatever is left. Only the frontend's
// footprint grows with the fleet, so only it should absorb growth; a percentage
// split scales the two processes whose cost is roughly constant and starves them
// exactly where the total is tightest. At the chart's default 64Mi limit a 10%
// signer share would be 6.4MiB, which is below a bare Go runtime's own
// footprint.
const (
	// launcherMemoryReservation covers the supervisor, which holds two
	// os.Process handles and blocks on channels. Its live heap is a few hundred
	// KiB; the rest is headroom, because a GOMEMLIMIT set near a process's true
	// need causes continuous GC rather than a failure -- a soft limit that is
	// too low degrades silently, which is worse than one that is absent.
	launcherMemoryReservation = 8 << 20

	// signerMemoryReservation must cover the signer's *peak*, which falls during
	// ca.Init and is fleet-proportional at roughly 420 bytes per certificate:
	// buildSerialIndex plus the []CertRecord that rebuildCertIndex materialises.
	// 24MiB therefore covers on the order of 60,000 certificates.
	//
	// Note this peak is not removed by giving the signer a shorter-lived store:
	// that shrinks the steady state, not the Init peak, so this reservation
	// remains fleet-sensitive either way. Exceeding it is not fatal -- GOMEMLIMIT
	// is a soft limit, so the signer collects harder during startup.
	signerMemoryReservation = 24 << 20

	// minFrontendMemoryShare is the floor below which dividing the budget is
	// worse than leaving it undivided: the frontend is the process actually
	// serving traffic, and squeezing it into a share near its live heap trades an
	// OOMKill for a GC death spiral that reports nothing.
	minFrontendMemoryShare = 24 << 20
)

// memoryBudget is the tree's total allowance and its division between the three
// processes.
type memoryBudget struct {
	total    int64
	launcher int64
	signer   int64
	frontend int64
	// source names where total came from, for the operator-facing log line.
	source string
}

// resolveMemoryBudget determines the tree-wide budget and divides it.
//
// An explicit GOMEMLIMIT wins: the operator asked for a specific number and it
// is taken to name the budget for the whole tree, which is what the
// documentation will say it means. Only when it is unset is the cgroup
// consulted, so deriving can never override a deliberate setting.
//
// The second return value is a human-readable reason the budget was not
// applied, empty when ok is true. getenv and cgroupPath are parameters rather
// than package-level references so a spec can drive every branch without
// mutating the process environment or the filesystem.
func resolveMemoryBudget(getenv func(string) string, cgroupPath string) (budget memoryBudget, ok bool, reason string) {
	total, source, ok := treeMemoryTotal(getenv, cgroupPath)
	if !ok {
		return memoryBudget{}, false, source
	}

	frontend := total - launcherMemoryReservation - signerMemoryReservation
	if frontend < minFrontendMemoryShare {
		return memoryBudget{}, false, "the total is too small to divide: " +
			strconv.FormatInt(total, 10) + " bytes leaves the frontend below its " +
			strconv.FormatInt(minFrontendMemoryShare, 10) + "-byte floor once the " +
			"launcher and signer are reserved for; raise the limit or unset GOMEMLIMIT"
	}

	return memoryBudget{
		total:    total,
		launcher: launcherMemoryReservation,
		signer:   signerMemoryReservation,
		frontend: frontend,
		source:   source,
	}, true, ""
}

// treeMemoryTotal returns the tree's total budget and where it came from. When
// no budget is available the second string is the reason rather than a source.
func treeMemoryTotal(getenv func(string) string, cgroupPath string) (int64, string, bool) {
	if raw := strings.TrimSpace(getenv(goMemLimitEnv)); raw != "" {
		n, valid := parseGoByteCount(raw)
		if !valid {
			// Deliberately not fatal, and deliberately not silently ignored: the
			// Go runtime itself refuses to start on a malformed GOMEMLIMIT, so a
			// child would fail anyway. Reporting it here names the launcher as
			// the place the value was read.
			return 0, "GOMEMLIMIT is set to " + strconv.Quote(raw) + ", which is not a valid byte count", false
		}
		return n, "GOMEMLIMIT", true
	}

	n, found := readCgroupMemoryMax(cgroupPath)
	if !found {
		return 0, "GOMEMLIMIT is unset and no cgroup memory ceiling was found", false
	}
	return n, "cgroup " + cgroupPath, true
}

// readCgroupMemoryMax reads a cgroup v2 memory ceiling. A missing file, an
// unreadable one, the literal "max", or anything that does not parse all yield
// false -- every one of them means "no ceiling stated here", and none is worth
// failing startup over.
func readCgroupMemoryMax(path string) (int64, bool) {
	// path is a compile-time constant in production; it is a parameter only so
	// a spec can drive every branch without writing under /sys.
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// parseGoByteCount mirrors the grammar the Go runtime accepts for GOMEMLIMIT,
// ^[0-9]+(([KMGT]i)?B)?$ -- an integer with an optional IEC suffix. It is
// reimplemented rather than approximated with a general size parser because the
// value has to round-trip: anything this accepts but the runtime rejects would
// be divided here and then refused by the child, and anything the runtime
// accepts but this rejects would silently fall through to the cgroup and
// override the operator.
func parseGoByteCount(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	digits := s
	shift := 0

	switch {
	case strings.HasSuffix(s, "B"):
		digits = s[:len(s)-1]
		for i, prefix := range []string{"K", "M", "G", "T"} {
			if strings.HasSuffix(digits, prefix+"i") {
				digits = digits[:len(digits)-2]
				shift = 10 * (i + 1)
				break
			}
		}
		// A remaining "i" means a suffix like "XiB" with an unknown prefix.
		if strings.HasSuffix(digits, "i") {
			return 0, false
		}
	case s[len(s)-1] >= '0' && s[len(s)-1] <= '9':
		// Bare byte count.
	default:
		return 0, false
	}

	if digits == "" {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	// Reject an overflowing shift rather than wrapping to a negative budget.
	if shift > 0 && n > (1<<62)>>shift {
		return 0, false
	}
	return n << shift, true
}
