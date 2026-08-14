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
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"strings"

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
		// A row whose serial is not hex at all. parseInventoryEntry takes
		// fields[0] verbatim with no validation, so a hand-edited row or one
		// from a foreign tool produces this. It sits BEFORE the last good row
		// on purpose: what needs pinning is that the scan continues past it.
		Expect(store.AppendInventory(ctx,
			"NOTHEX 2026-01-04T00:00:00UTC 2027-01-04T00:00:00UTC /CN=malformed")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"ZZZZ 2026-01-05T00:00:00UTC 2027-01-05T00:00:00UTC /CN=malformed-two")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"1b 2026-01-03T00:00:00UTC 2027-01-03T00:00:00UTC /CN=third")).To(Succeed())
	})

	It("skips an unparseable row and keeps scanning", func() {
		// If the skip were an abort, one bad row would make every serial after
		// it unresolvable — and so unrevokable — with nothing to say why.
		Expect(store.SubjectForSerial(ctx, "1B")).To(Equal("CN=third"))
	})

	It("reports the unparseable rows once, with a count", func() {
		// One line per bad row would be unbounded in inventory size, emitted
		// under the cluster CRL lock while an operator watches the log for the
		// outcome of a single revocation. The count is what makes the one line
		// useful, and it is why both emission sites were collapsed into one.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		_, err := store.SubjectForSerial(ctx, "BEEF")
		Expect(err).To(MatchError(fs.ErrNotExist))

		Expect(strings.Count(buf.String(), "unparseable serials")).To(Equal(1))
		Expect(buf.String()).To(ContainSubstring("count=2"))
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
