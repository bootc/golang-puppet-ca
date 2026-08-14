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

package storage_test

import (
	"context"
	"io/fs"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("StorageService SubjectForSerial", func() {
	var (
		ctx   = context.Background()
		store *storage.StorageService
	)

	BeforeEach(func() {
		tmpDir, err := os.MkdirTemp("", "openvox-ca-subjectforserial-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		// "00FF" is deliberately zero-padded, as an inventory written by an
		// older version with sequential serials would be; "0A" is not. Nothing
		// here goes through the CA, so both sides of the comparison are as
		// varied as a real inventory's are.
		Expect(store.AppendInventory(ctx,
			"0A 2026-01-01T00:00:00UTC 2027-01-01T00:00:00UTC /CN=first")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"00FF 2026-01-02T00:00:00UTC 2027-01-02T00:00:00UTC /CN=second")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"1b 2026-01-03T00:00:00UTC 2027-01-03T00:00:00UTC /CN=third")).To(Succeed())
	})

	It("resolves a serial to the subject that holds it", func() {
		Expect(store.SubjectForSerial(ctx, "0A")).To(Equal("CN=first"))
	})

	// The normalisation is on both sides, which is what makes the stored
	// rendering irrelevant. A lookup that compared the strings as written would
	// pass the first of these and fail the rest.
	DescribeTable("matches regardless of how either side is written",
		func(query, subject string) {
			Expect(store.SubjectForSerial(ctx, query)).To(Equal(subject))
		},
		Entry("query and entry both canonical", "0A", "CN=first"),
		Entry("query lowercase, entry uppercase", "0a", "CN=first"),
		Entry("query padded, entry unpadded", "0000000A", "CN=first"),
		Entry("query unpadded, entry padded", "FF", "CN=second"),
		Entry("query lowercase, entry padded uppercase", "ff", "CN=second"),
		Entry("query uppercase, entry lowercase", "1B", "CN=third"),
		Entry("query surrounded by whitespace", "  0A\n", "CN=first"),
	)

	It("wraps fs.ErrNotExist for a serial no entry carries", func() {
		_, err := store.SubjectForSerial(ctx, "BEEF")
		Expect(err).To(MatchError(fs.ErrNotExist))
	})

	DescribeTable("rejects input that is not a hexadecimal serial",
		func(bad string) {
			_, err := store.SubjectForSerial(ctx, bad)
			Expect(err).To(MatchError(storage.ErrMalformedSerial))
		},
		Entry("empty", ""),
		Entry("whitespace only", "   "),
		Entry("non-hex letters", "nope"),
		Entry("0x prefix", "0x0A"),
		Entry("negative", "-1"),
		Entry("embedded space", "0 A"),
	)
})
