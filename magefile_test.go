//go:build mage

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
	"bytes"
	"os"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

var _ = Describe("releaseVersion", func() {
	// go test runs with the package directory (the repository root) as the
	// working directory, so the real internal/version/version.go is read:
	// this pins the textual parse against the actual constant, catching any
	// reformatting of the Version line that would break the workflows' and
	// hook's sed-based parsers of the same shape.
	It("round-trips the real Version constant", func() {
		ver, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())
		Expect(ver).To(Equal(version.Version))
	})
})

var _ = Describe("bareSemverRe", func() {
	DescribeTable("accepts bare semver with optional pre-release suffix",
		func(v string) { Expect(bareSemverRe.MatchString(v)).To(BeTrue()) },
		Entry("release", "0.9.0"),
		Entry("release candidate", "0.9.0-rc1"),
		Entry("development version", "0.10.0-dev"),
		Entry("dotted pre-release", "1.2.3-alpha.1"),
	)

	DescribeTable("rejects anything else",
		func(v string) { Expect(bareSemverRe.MatchString(v)).To(BeFalse()) },
		Entry("v prefix", "v0.9.0"),
		Entry("two components", "0.9"),
		Entry("four components", "0.9.0.1"),
		Entry("empty", ""),
		Entry("trailing space", "0.9.0 "),
		Entry("bare suffix", "-rc1"),
	)
})

var _ = Describe("fipsCrossCC", func() {
	// The CC environment variable changes the result, so pin it to unset for
	// each spec and restore whatever the caller had afterwards.
	BeforeEach(func() {
		if orig, ok := os.LookupEnv("CC"); ok {
			Expect(os.Unsetenv("CC")).To(Succeed())
			DeferCleanup(os.Setenv, "CC", orig)
		}
	})

	It("returns empty when CC is already set in the environment", func() {
		Expect(os.Setenv("CC", "clang")).To(Succeed())
		DeferCleanup(os.Unsetenv, "CC")
		Expect(fipsCrossCC("arm64")).To(BeEmpty())
	})

	It("returns empty for an unknown architecture", func() {
		Expect(fipsCrossCC("riscv64")).To(BeEmpty())
	})

	// Pin the exact cross-compiler names: CI only ever builds each FIPS
	// variant natively, so a wrong name here would otherwise go undetected
	// until someone cross-builds locally.
	It("maps cross architectures to the GNU cross compilers", func() {
		crossCC := map[string]string{
			"amd64": "x86_64-linux-gnu-gcc",
			"arm64": "aarch64-linux-gnu-gcc",
		}
		for goarch, cc := range crossCC {
			if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
				continue // native: covered by the spec below
			}
			Expect(fipsCrossCC(goarch)).To(Equal(cc), "goarch %s", goarch)
		}
	})

	It("returns empty for a native Linux build", func() {
		if runtime.GOOS != "linux" {
			Skip("native FIPS builds only exist on Linux")
		}
		Expect(fipsCrossCC(runtime.GOARCH)).To(BeEmpty())
	})
})

var _ = Describe("repoSlugFromURL", func() {
	DescribeTable("derives owner/repo",
		func(url, want string) {
			slug, err := repoSlugFromURL(url)
			Expect(err).NotTo(HaveOccurred())
			Expect(slug).To(Equal(want))
		},
		Entry("SSH scp-like", "git@github.com:voxpupuli/openvox-ca.git", "voxpupuli/openvox-ca"),
		Entry("SSH scp-like without .git", "git@github.com:bootc/openvox-ca", "bootc/openvox-ca"),
		Entry("HTTPS", "https://github.com/voxpupuli/openvox-ca.git", "voxpupuli/openvox-ca"),
		Entry("HTTPS without .git", "https://github.com/voxpupuli/openvox-ca", "voxpupuli/openvox-ca"),
		Entry("ssh scheme", "ssh://git@github.com/owner/repo.git", "owner/repo"),
	)

	It("rejects a URL it cannot parse", func() {
		_, err := repoSlugFromURL("not-a-url")
		Expect(err).To(MatchError(ContainSubstring("could not derive owner/repo")))
	})
})

var _ = Describe("distVariants", func() {
	It("defines the four release variants with coherent build environments", func() {
		variants := distVariants()
		Expect(variants).To(HaveLen(4))

		names := map[string]bool{}
		for _, v := range variants {
			Expect(names).NotTo(HaveKey(v.name), "duplicate variant name")
			names[v.name] = true

			Expect(v.name).To(MatchRegexp(`^linux_(amd64|arm64)(_fips)?$`))
			Expect(v.env["GOOS"]).To(Equal("linux"))
			Expect(v.name).To(ContainSubstring(v.env["GOARCH"]))

			if _, fips := v.env["GOEXPERIMENT"]; fips {
				Expect(v.name).To(HaveSuffix("_fips"))
				Expect(v.env["GOEXPERIMENT"]).To(Equal("boringcrypto"))
				Expect(v.env["CGO_ENABLED"]).To(Equal("1"))
			} else {
				Expect(v.name).NotTo(HaveSuffix("_fips"))
				Expect(v.env["CGO_ENABLED"]).To(Equal("0"))
			}
		}
	})
})

var _ = Describe("Build.DistVariant", func() {
	It("rejects an unknown variant before building anything", func() {
		err := Build{}.DistVariant("nonsense")
		Expect(err).To(MatchError(ContainSubstring(`unknown dist variant "nonsense"`)))
		Expect(err).To(MatchError(ContainSubstring("linux_arm64_fips")), "error should list the known variants")
	})
})

var _ = Describe("workflowMatrixVariants", func() {
	yamlSrc := []byte(`
jobs:
  dist:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
            runner: ubuntu-latest
          - variant: linux_arm64
            runner: ubuntu-24.04-arm
  other:
    runs-on: ubuntu-latest
`)

	It("extracts the variant names from a job's matrix include list", func() {
		names, err := workflowMatrixVariants(yamlSrc, "dist")
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(Equal([]string{"linux_amd64", "linux_arm64"}))
	})

	It("errors on a missing job", func() {
		_, err := workflowMatrixVariants(yamlSrc, "absent")
		Expect(err).To(MatchError(ContainSubstring(`"absent" not found`)))
	})

	It("errors on a job without variant matrix entries", func() {
		_, err := workflowMatrixVariants(yamlSrc, "other")
		Expect(err).To(MatchError(ContainSubstring("no matrix include entries")))
	})
})

var _ = Describe("shellVariantList", func() {
	It("extracts the loop's variant names", func() {
		names, err := shellVariantList([]byte(`for variant in linux_amd64 linux_arm64_fips; do`))
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(Equal([]string{"linux_amd64", "linux_arm64_fips"}))
	})

	It("errors when no loop is present", func() {
		_, err := shellVariantList([]byte("nothing here"))
		Expect(err).To(MatchError(ContainSubstring("no 'for variant in")))
	})
})

var _ = Describe("verifyDistVariants", func() {
	// Runs against the repository's real workflow files: this is the
	// cross-check that keeps ci.yml, release.yml, and distVariants() from
	// drifting apart (it also runs as part of `mage dev:check`).
	It("finds all hand-maintained variant lists in agreement", func() {
		Expect(verifyDistVariants()).To(Succeed())
	})

	// The failure branches are what make the guard a guard: feed synthetic
	// workflow contents with exactly one list out of agreement and assert
	// the error names the disagreeing location.
	Describe("drift detection", func() {
		// Synthetic workflow fragments agreeing with distVariants()
		// (linux_amd64, linux_arm64, linux_amd64_fips, linux_arm64_fips).
		goodCI := []byte(`
jobs:
  dist:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
          - variant: linux_arm64
          - variant: linux_amd64_fips
          - variant: linux_arm64_fips
`)
		goodRel := []byte(`
jobs:
  build:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
          - variant: linux_arm64
          - variant: linux_amd64_fips
          - variant: linux_arm64_fips
  release:
    steps:
      - run: |
          for variant in linux_amd64 linux_arm64 linux_amd64_fips linux_arm64_fips; do
            ls
          done
          if [ "$tarballs" -ne 4 ]; then
            exit 1
          fi
`)

		It("accepts synthetic workflows that agree with distVariants", func() {
			Expect(verifyDistVariantsIn(goodCI, goodRel)).To(Succeed())
		})

		It("rejects a drifted ci.yml dist matrix and names it", func() {
			badCI := bytes.Replace(goodCI, []byte("- variant: linux_arm64_fips"), []byte("- variant: linux_riscv64_fips"), 1)
			Expect(verifyDistVariantsIn(badCI, goodRel)).To(MatchError(ContainSubstring("ci.yml dist job matrix")))
		})

		It("rejects a drifted release.yml build matrix and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("          - variant: linux_amd64_fips\n"), nil, 1)
			Expect(verifyDistVariantsIn(goodCI, badRel)).To(MatchError(ContainSubstring("release.yml build job matrix")))
		})

		It("rejects a drifted checksum-step shell loop and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("for variant in linux_amd64 "), []byte("for variant in "), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel)).To(MatchError(ContainSubstring("checksum-step shell loop")))
		})

		It("rejects a stale tarball-count literal and names the counts", func() {
			badRel := bytes.Replace(goodRel, []byte(`-ne 4`), []byte(`-ne 3`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel)).To(MatchError(ContainSubstring("expects 3 tarballs")))
		})
	})
})
