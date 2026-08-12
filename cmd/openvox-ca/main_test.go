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
	"io"
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

// The root command must reject stray positional arguments instead of silently
// ignoring them. The bug fix sets Args: cobra.NoArgs on the root command.
var _ = Describe("Root command", func() {
	It("rejects unexpected positional arguments", func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"stray-arg", "--cadir", GinkgoT().TempDir()})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(HaveOccurred(), "expected error for unexpected positional arg, got nil")
	})

	It("prints the release version for --version", func() {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetArgs([]string{"--version"})
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("openvox-ca version " + version.Version))
	})

	// -v must stay the shorthand for --verbosity: cobra would otherwise claim
	// it for the synthesised --version flag, silently changing what -v does.
	It("keeps -v as the shorthand for --verbosity", func() {
		cmd := newRootCmd()
		flag := cmd.Flags().ShorthandLookup("v")
		Expect(flag).NotTo(BeNil())
		Expect(flag.Name).To(Equal("verbosity"))
	})
})

// The migration guide tells operators the denial log renders as
// reason="route requires admin access" on stderr and
// "reason":"route requires admin access" when logfile is set, attributing the
// difference to the handler this function picks. The API suite pins the fields;
// this pins the half of the claim that lives here.
var _ = Describe("setupLogger handler selection", func() {
	var orig *slog.Logger

	BeforeEach(func() {
		orig = slog.Default()
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	It("writes JSON to the log file when one is configured", func() {
		path := filepath.Join(GinkgoT().TempDir(), "ca.log")
		f, err := setupLogger(&serverConfig{LogFile: path})
		Expect(err).NotTo(HaveOccurred())
		Expect(f).NotTo(BeNil())
		DeferCleanup(func() { Expect(f.Close()).To(Succeed()) })

		Expect(slog.Default().Handler()).To(BeAssignableToTypeOf(&slog.JSONHandler{}))

		slog.Warn("Request denied by authorisation middleware",
			"reason", "route requires admin access")

		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(ContainSubstring(`"reason":"route requires admin access"`))
	})

	It("writes text to stderr when no log file is configured", func() {
		// Both halves of the guide's claim: the text rendering, and that it
		// goes to stderr. The handler captures whatever os.Stderr names when
		// it is constructed, so swapping in a pipe around the call is enough
		// to read back what an operator's journal would receive.
		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		origStderr := os.Stderr
		os.Stderr = w
		f, err := setupLogger(&serverConfig{})
		os.Stderr = origStderr
		Expect(err).NotTo(HaveOccurred())
		Expect(f).To(BeNil(), "nothing to close when logging to stderr")

		Expect(slog.Default().Handler()).To(BeAssignableToTypeOf(&slog.TextHandler{}))

		slog.Warn("Request denied by authorisation middleware",
			"reason", "route requires admin access")
		Expect(w.Close()).To(Succeed())
		out, err := io.ReadAll(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Close()).To(Succeed())
		Expect(string(out)).To(ContainSubstring(`reason="route requires admin access"`))
	})

	It("refuses to start when the log file cannot be opened", func() {
		// Both callers return this straight out of the command, so a bad
		// logfile is a startup failure; the path is what an operator needs to
		// see in it.
		missing := filepath.Join(GinkgoT().TempDir(), "no-such-dir", "ca.log")
		f, err := setupLogger(&serverConfig{LogFile: missing})
		Expect(err).To(MatchError(ContainSubstring("failed to open log file")))
		Expect(err).To(MatchError(ContainSubstring(missing)))
		Expect(f).To(BeNil())
	})
})
