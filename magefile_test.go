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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
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
	DescribeTable("maps cross architectures to the GNU cross compilers",
		func(goarch, cc string) {
			if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
				Skip("native on this host: covered by the native-build spec")
			}
			Expect(fipsCrossCC(goarch)).To(Equal(cc))
		},
		Entry("amd64", "amd64", "x86_64-linux-gnu-gcc"),
		Entry("arm64", "arm64", "aarch64-linux-gnu-gcc"),
	)

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

var _ = Describe("release archive contents", func() {
	// These replace a CI job that built all four variants, unpacked each
	// tarball and grepped `tar -tvz` for the entries and their modes. The
	// properties it checked are properties of the manifest and of the archive
	// writer, neither of which needs a release build to exercise.
	Describe("distArchiveFiles", func() {
		files := distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"})

		It("ships both binaries executable and the unit not", func() {
			Expect(files).To(Equal([]archiveEntry{
				{name: "openvox-ca", mode: 0755},
				{name: "openvox-ca-ctl", mode: 0755},
				{name: "openvox-ca.service", mode: 0644},
			}))
		})

		It("names a unit that is actually in the repository", func() {
			// The manifest names a file that is copied in at build time; a
			// rename under packaging/ would otherwise break nothing until a
			// tag is pushed, at which point the tag exists and no artefacts do.
			Expect(filepath.Join("packaging", "systemd", distUnitFile)).To(BeAnExistingFile())
		})
	})

	Describe("createTarGz", func() {
		It("writes each entry with the mode the manifest asked for", func() {
			// Not the mode of the staged file: the release must extract the
			// same way whatever umask it was built under.
			srcDir := GinkgoT().TempDir()
			for _, name := range []string{"openvox-ca", "openvox-ca.service"} {
				Expect(os.WriteFile(filepath.Join(srcDir, name), []byte(name), 0600)).To(Succeed())
			}
			archive := filepath.Join(GinkgoT().TempDir(), "out.tar.gz")

			Expect(createTarGz(archive, srcDir, []archiveEntry{
				{name: "openvox-ca", mode: 0755},
				{name: "openvox-ca.service", mode: 0644},
			})).To(Succeed())

			Expect(tarEntries(archive)).To(Equal(map[string]tarEntry{
				"openvox-ca":         {mode: 0755, body: "openvox-ca"},
				"openvox-ca.service": {mode: 0644, body: "openvox-ca.service"},
			}))
		})

		It("reports a source file that is not there", func() {
			archive := filepath.Join(GinkgoT().TempDir(), "out.tar.gz")
			err := createTarGz(archive, GinkgoT().TempDir(), []archiveEntry{{name: "absent", mode: 0755}})
			Expect(err).To(MatchError(os.ErrNotExist))
		})
	})
})

// tarEntry is one unpacked archive member: the mode it would extract as and
// its contents.
type tarEntry struct {
	mode int64
	body string
}

// tarEntries reads a gzipped tarball back into a name-keyed map, so a spec can
// assert the whole archive in one comparison rather than walking it.
func tarEntries(path string) map[string]tarEntry {
	GinkgoHelper()

	f, err := os.Open(path)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()

	gz, err := gzip.NewReader(f)
	Expect(err).NotTo(HaveOccurred())
	defer gz.Close()

	entries := map[string]tarEntry{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		Expect(err).NotTo(HaveOccurred())

		body, err := io.ReadAll(tr)
		Expect(err).NotTo(HaveOccurred())
		entries[hdr.Name] = tarEntry{mode: hdr.Mode, body: string(body)}
	}
	return entries
}

var _ = Describe("Release.Prepare", func() {
	// The bare-semver guard is Prepare's first statement, returning before
	// any git, gh, or filesystem side effect, so the rejection path is
	// hermetic — this pins both the wiring and that validation stays ahead
	// of the side effects.
	It("rejects a non-bare-semver version before any side effect", func() {
		err := Release{}.Prepare("v0.9.0")
		Expect(err).To(MatchError(ContainSubstring("is not bare semver")))
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

var _ = Describe("verifyAutomergeLabelExclusion", func() {
	// Against the repository's real ci.yml: the clause must actually be there.
	It("finds the real auto-merge job excluding the signing-review label", func() {
		Expect(verifyAutomergeLabelExclusion()).To(Succeed())
	})

	Describe("drift detection", func() {
		good := []byte(`
jobs:
  automerge:
    if: >-
      github.event_name == 'pull_request'
      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')
      && github.event.pull_request.user.login == 'renovate[bot]'
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
`)

		It("accepts a merging job that excludes the label", func() {
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", good)).To(Succeed())
		})

		// The whole point: the clause is droppable in a tidy-up, and nothing
		// else in the repository would notice it had gone.
		It("rejects a merging job whose condition drops the label clause", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"), nil, 1)
			// Both clauses are gone, and the error must name both — this is
			// the spec that distinguishes "clause deleted" from the
			// partial-match case below.
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				And(ContainSubstring(`job "automerge"`),
					ContainSubstring("github.event.pull_request.labels"),
					ContainSubstring("review-signing-path"))))
		})

		// Naming the label but not reading it from the PR's labels is not an
		// exclusion, however plausibly it reads.
		It("rejects a condition that names the label without consulting the PR's labels", func() {
			bad := bytes.Replace(good,
				[]byte("!contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("github.event.pull_request.title != 'review-signing-path'"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// The clause is required whole, not in fragments. Flipping it while an
		// unrelated !contains(...) sits elsewhere leaves every fragment present
		// — the label name, the labels context, a negation — and inverts the
		// meaning anyway. This mutation passed an earlier fragment-based
		// version of the guard, which is why the contract is the whole clause.
		It("rejects an inverted clause even when another negation is present", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("      && contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"+
					"      && !contains(github.event.pull_request.title, 'WIP')"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// Exact on shape, free on spacing: the condition is a YAML block
		// scalar that people wrap and indent to taste, and a guard that failed
		// on a reflow would be reformatted away rather than obeyed.
		It("accepts the clause however it is spaced", func() {
			spaced := bytes.Replace(good,
				[]byte("!contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("!contains(  github.event.pull_request.labels.*.name,   'review-signing-path'  )"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", spaced)).To(Succeed())
		})

		// Dropping the '!' does not weaken the exclusion, it reverses it: the
		// job would then merge signing bumps unattended and nothing else. A
		// guard that passes the exact inversion of what it checks for is not
		// worth having, which is why the negation is a required clause and
		// not left to "consults, not constrains".
		It("rejects a condition whose label check is not negated", func() {
			bad := bytes.Replace(good, []byte("&& !contains("), []byte("&& contains("), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				And(ContainSubstring(`job "automerge"`), ContainSubstring("!contains("))))
			// And the reported clause is the whole expression a maintainer
			// must restore, not a fragment of it.
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("labels.*.name, 'review-signing-path')")))
		})

		// Comments never reach the parsed `if:` scalar, so naming the clauses
		// in one cannot satisfy the guard. Asserted rather than assumed: the
		// immunity comes from parsing the document instead of grepping it,
		// and a future rewrite to a text search would silently lose it.
		It("is not satisfied by a comment naming the required clauses", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"),
				[]byte(""), 1)
			bad = bytes.Replace(bad, []byte("jobs:\n"),
				[]byte("jobs:\n  # github.event.pull_request.labels review-signing-path !contains(\n"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// A guard that finds nothing to guard has abstained, not passed. If
		// auto-merge is renamed or rewritten to merge some other way, this
		// must go red rather than quiet — that is the failure mode where a
		// green check is actively misleading. The cost is accepted knowingly:
		// legitimately removing auto-merge will fail this until the guard goes
		// too. See the note at the merging == 0 branch.
		It("refuses to pass when no job merges pull requests at all", func() {
			bad := bytes.Replace(good, []byte("gh pr merge --auto --merge"), []byte("echo nothing to do"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("no job runs `gh pr merge`")))
		})
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
            ls -- openvox-ca_*_"$variant".tar.gz > /dev/null
            ls -- openvox-ca_*_"$variant".spdx.json > /dev/null
            ls -- openvox-ca_*_"$variant".cdx.json > /dev/null
          done
          if [ "$tarballs" -ne 4 ]; then
            exit 1
          fi
          if [ "$sboms" -ne 8 ]; then
            exit 1
          fi
          sha256sum -- *.tar.gz *.spdx.json *.cdx.json > checksums.txt
`)

		// The generate-sbom action's output formats, whose count must equal
		// sbomFormatsPerVariant.
		goodSBOM := []byte(`
        "$SYFT" scan "dir:$scan" \
          -o "spdx-json=dist/${base}.spdx.json" \
          -o "cyclonedx-json=dist/${base}.cdx.json"
`)

		It("accepts synthetic workflows that agree with distVariants", func() {
			Expect(verifyDistVariantsIn(goodCI, goodRel, goodSBOM)).To(Succeed())
		})

		It("rejects a drifted ci.yml dist matrix and names it", func() {
			badCI := bytes.Replace(goodCI, []byte("- variant: linux_arm64_fips"), []byte("- variant: linux_riscv64_fips"), 1)
			Expect(verifyDistVariantsIn(badCI, goodRel, goodSBOM)).To(MatchError(ContainSubstring("ci.yml dist job matrix")))
		})

		It("rejects a drifted release.yml build matrix and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("          - variant: linux_amd64_fips\n"), nil, 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("release.yml build job matrix")))
		})

		It("rejects a drifted checksum-step shell loop and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("for variant in linux_amd64 "), []byte("for variant in "), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("checksum-step shell loop")))
		})

		It("rejects a stale tarball-count literal and names the counts", func() {
			badRel := bytes.Replace(goodRel, []byte(`-ne 4`), []byte(`-ne 3`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("expects 3 tarballs")))
		})

		// The SBOM count is a multiple of the variant count rather than equal
		// to it, so it drifts independently of the tarball count: a variant
		// added everywhere else but missed in this literal lands here. (A
		// format added to generate-sbom is caught by the format-count specs
		// below, not by this one.)
		It("rejects a stale SBOM-count literal and names the counts", func() {
			badRel := bytes.Replace(goodRel, []byte(`-ne 8`), []byte(`-ne 4`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("expects 4 SBOMs")))
		})

		// -lt rather than -ne: the check is present but no longer the shape
		// the guard parses, which is the same branch a deleted line takes.
		// The message quotes the pattern it wanted, so the operator mismatch
		// is visible rather than leaving a maintainer staring at a check that
		// is plainly on screen.
		It("rejects an SBOM-count check the guard cannot parse", func() {
			badRel := bytes.Replace(goodRel, []byte(`"$sboms" -ne 8`), []byte(`"$sboms" -lt 8`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring(`no SBOMs-count check matching`)))
		})

		// sbomFormatsPerVariant is the multiplier the SBOM count is derived
		// from, and it mirrors the generate-sbom action. These two specs are
		// what stop it becoming an unchecked copy: they are the reason a
		// format added to the action alone cannot leave every other count
		// self-consistent and wrong.
		It("rejects a generate-sbom action emitting more formats than the constant", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`-o "cyclonedx-json=dist/${base}.cdx.json"`),
				[]byte("-o \"cyclonedx-json=dist/${base}.cdx.json\" \\\n          -o \"syft-json=dist/${base}.syft.json\""), 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring("emits 3 SBOM format(s)"), ContainSubstring("syft-json"))))
		})

		It("rejects a generate-sbom action emitting fewer formats than the constant", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`          -o "cyclonedx-json=dist/${base}.cdx.json"`), nil, 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(ContainSubstring("emits 1 SBOM format(s)")))
		})

		// Zero matches is not a miscount: the guard's own pattern stopped
		// matching, which is a different problem with a different fix, so it
		// gets a message naming the pattern rather than "emits 0".
		It("says which pattern stopped matching when it can see no output flags", func() {
			badSBOM := bytes.ReplaceAll(goodSBOM, []byte(`-o "`), []byte("--output "))
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring("no SBOM output flags matching"), ContainSubstring("[a-z0-9-]"))))
		})

		// The counts can agree while the names do not. Renaming one format's
		// output file leaves sbomFormatsPerVariant satisfied and still breaks
		// the release, because release.yml globs for the old extension — and
		// it breaks it at tag time, which is the failure this whole guard
		// family exists to move earlier.
		It("rejects a renamed SBOM output whose extension release.yml never globs for", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`${base}.cdx.json`), []byte(`${base}.bom.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring(".bom.json"), ContainSubstring("but release.yml names"))))
		})

		It("rejects a release.yml that globs for an extension the action never writes", func() {
			badRel := bytes.Replace(goodRel, []byte(`"$variant".cdx.json`), []byte(`"$variant".bom.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(
				ContainSubstring("but release.yml names")))
		})

		// release.yml names each document in five places. Dropping one of them
		// keeps every name valid and every count above satisfied, so nothing
		// else here would notice — but the document would go unlisted at that
		// site. Drop it from the sha256sum operands and it is published without
		// a checksum line, which means it is also missing from the attestation,
		// whose subjects are exactly those lines.
		It("rejects a release.yml that lists one SBOM document at a site but not the other", func() {
			badRel := bytes.Replace(goodRel, []byte(`sha256sum -- *.tar.gz *.spdx.json *.cdx.json`),
				[]byte(`sha256sum -- *.tar.gz *.spdx.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(
				ContainSubstring("every place that lists one SBOM document must list them all")))
		})
	})
})
