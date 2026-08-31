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
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOpenvoxCACtl(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "openvox-ca-ctl Command Suite")
}

// captureStdout runs the root command with args and returns everything it
// printed to stdout, plus the command's error.
//
// fmt.Printf resolves os.Stdout at call time, so swapping a pipe in around
// Execute is enough to read back what an operator would see. Shared by the
// output-escaping specs, which all need the same plumbing; keeping one copy
// means a future change to how the CLI is driven lands in one place.
func captureStdout(args []string) (string, error) {
	GinkgoHelper()
	r, w, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _, _ = r.Close(), w.Close() })

	origStdout := os.Stdout
	// Belt and braces with the inline restore below: if anything panics while
	// os.Stdout points at this pipe, the run's own output would vanish into it.
	defer func() { os.Stdout = origStdout }()
	os.Stdout = w

	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	execErr := cmd.Execute()

	os.Stdout = origStdout
	Expect(w.Close()).To(Succeed())
	out, readErr := io.ReadAll(r)
	Expect(readErr).NotTo(HaveOccurred())
	Expect(r.Close()).To(Succeed())
	return string(out), execErr
}
