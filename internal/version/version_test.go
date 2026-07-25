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

package version_test

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

var _ = Describe("Version", func() {
	// The release workflow tags releases as "v" + Version and derives
	// artefact names from it, so the constant must always parse as a bare
	// semantic version (optionally with a pre-release suffix such as -dev
	// or -rc1) and never carry a "v" prefix of its own.
	It("is a bare semantic version", func() {
		Expect(version.Version).To(MatchRegexp(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`))
	})
})

var _ = Describe("Full", func() {
	// Test binaries are never VCS-stamped, so Full() cannot be asserted
	// against exact commit metadata here; what matters is that the release
	// version always leads and any suffix is well-formed.
	It("starts with the release version", func() {
		Expect(version.Full()).To(HavePrefix(version.Version))
	})

	It("appends either nothing or a parenthesised commit suffix", func() {
		full := version.Full()
		if full != version.Version {
			Expect(full).To(MatchRegexp(`^` + regexp.QuoteMeta(version.Version) + ` \(commit [0-9a-f]{1,12}(, [^,)]+)?(, dirty)?\)$`))
		}
	})
})
