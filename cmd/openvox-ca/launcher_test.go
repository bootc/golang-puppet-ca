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
	"crypto/rand"
	"encoding/hex"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("pskPipe", func() {
	// verifies the returned read end yields exactly the hex PSK followed by
	// EOF, which is what a child's parsePSK relies on to drain the pipe.
	It("delivers the PSK followed by EOF", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")
		pskHex := hex.EncodeToString(psk)

		r, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "pskPipe")
		DeferCleanup(func() { _ = r.Close() })

		// ReadAll only returns once the write end is closed, so this also
		// proves pskPipe closed it before returning.
		data, err := io.ReadAll(r)
		Expect(err).NotTo(HaveOccurred(), "reading PSK pipe")
		Expect(string(data)).To(Equal(pskHex), "pipe contents should be the hex PSK")
	})
})
