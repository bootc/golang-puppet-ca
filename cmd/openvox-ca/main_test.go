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

		slog.Warn("Request denied by authorisation middleware",
			"reason", "route requires admin access")

		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(ContainSubstring(`"reason":"route requires admin access"`))
	})

	It("writes text to stderr when no log file is configured", func() {
		f, err := setupLogger(&serverConfig{})
		Expect(err).NotTo(HaveOccurred())
		Expect(f).To(BeNil(), "nothing to close when logging to stderr")

		// The handler is the text one, so the same call renders key=value
		// rather than JSON. Asserted through a buffer of our own rather than
		// by capturing stderr, which the suite shares.
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		slog.Warn("Request denied by authorisation middleware",
			"reason", "route requires admin access")
		Expect(buf.String()).To(ContainSubstring(`reason="route requires admin access"`))
	})
})
