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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// -- chart version parsing ------------------------------------------------------

var _ = Describe("chartVersions", func() {
	// go test runs from the repository root, so this parses the real
	// Chart.yaml. It pins the textual shape that the pre-push hook, the
	// verify-release-tag action and the publish workflow all re-parse with sed:
	// reformat either line (or unquote appVersion) and this fails alongside
	// them rather than after them.
	It("parses the real Chart.yaml and agrees with internal/version", func() {
		version, appVersion, err := chartVersions()
		Expect(err).NotTo(HaveOccurred())

		want, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())
		Expect(version).To(Equal(want))
		Expect(appVersion).To(Equal(want))
	})
})

var _ = Describe("chartValuesFiles", func() {
	It("finds the fixtures, including the one held to the kubeVersion floor", func() {
		files, err := chartValuesFiles()
		Expect(err).NotTo(HaveOccurred())
		Expect(files).NotTo(BeEmpty())

		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, chartFixtureName(f))
		}
		// Chart.Validate keys the floor check on this name and errors if it
		// finds no such fixture; assert the pair agree so a rename fails here
		// with an obvious message too.
		Expect(names).To(ContainElement(chartFloorFixture))
	})
})

var _ = Describe("verifyChartPins", func() {
	// Runs against the repository's real files: this is the cross-check that
	// keeps Chart.yaml's advertised kubeVersion floor, the constant CI
	// validates against, and the Helm version the publish workflow packages
	// with from drifting apart. Also runs as part of `mage dev:check`.
	It("finds the real pins in agreement", func() {
		Expect(verifyChartPins()).To(Succeed())
	})

	// The failure branches are what make the guard a guard: feed synthetic
	// contents with exactly one pin out of agreement and assert the error
	// names it.
	Describe("drift detection", func() {
		goodChart := []byte("apiVersion: v2\nversion: 0.9.0-dev\nappVersion: \"0.9.0-dev\"\nkubeVersion: \">=" + kubeconformFloorVersion + "-0\"\n")
		goodCI := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
			"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{ matrix.helm }}\n")
		goodPublish := []byte("jobs:\n  publish:\n    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: v3.21.3\n")

		It("accepts synthetic files that agree", func() {
			Expect(verifyChartPinsIn(goodChart, goodCI, goodPublish)).To(Succeed())
		})

		It("rejects a kubeVersion floor the constant does not match", func() {
			bad := bytes.Replace(goodChart, []byte(kubeconformFloorVersion), []byte("1.99.0"), 1)
			Expect(verifyChartPinsIn(bad, goodCI, goodPublish)).To(
				MatchError(ContainSubstring("does not match the kubeVersion floor")))
		})

		It("rejects a packaging Helm outside the validated matrix", func() {
			bad := bytes.Replace(goodPublish, []byte("v3.21.3"), []byte("v3.20.0"), 1)
			Expect(verifyChartPinsIn(goodChart, goodCI, bad)).To(
				MatchError(ContainSubstring("not in ci.yml's chart matrix")))
		})

		It("accepts the other validated matrix entry as the packaging version", func() {
			ok := bytes.Replace(goodPublish, []byte("v3.21.3"), []byte("v4.2.3"), 1)
			Expect(verifyChartPinsIn(goodChart, goodCI, ok)).To(Succeed())
		})

		It("refuses to pass when a pin cannot be parsed at all", func() {
			Expect(verifyChartPinsIn([]byte("apiVersion: v2\n"), goodCI, goodPublish)).To(
				MatchError(ContainSubstring("could not parse the kubeVersion floor")))
			Expect(verifyChartPinsIn(goodChart, []byte("jobs: {}\n"), goodPublish)).To(
				MatchError(ContainSubstring("ci.yml has no 'chart' job")))
			Expect(verifyChartPinsIn(goodChart, goodCI, []byte("jobs: {}\n"))).To(
				MatchError(ContainSubstring("helm-chart.yml has no 'publish' job")))
		})

		// The failure mode a positional parse admits: reading a pin that
		// belongs to something else and passing anyway. Both parsers key on the
		// job (and the publish one on the action) rather than on file order, so
		// a decoy ahead of the real value must not be picked up.
		It("ignores a decoy helm matrix in another job", func() {
			decoy := []byte("jobs:\n  other:\n    strategy:\n      matrix:\n        helm: [v9.9.9]\n" +
				"  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{ matrix.helm }}\n")
			Expect(verifyChartPinsIn(goodChart, decoy, goodPublish)).To(Succeed())
		})

		It("ignores a decoy version on an earlier action step", func() {
			decoy := []byte("jobs:\n  publish:\n    steps:\n" +
				"      - uses: actions/setup-go@abc\n        with:\n          version: v9.9.9\n" +
				"      - uses: azure/setup-helm@abc\n        with:\n          version: v3.21.3\n")
			Expect(verifyChartPinsIn(goodChart, goodCI, decoy)).To(Succeed())
		})

		It("still catches the real mismatch past a decoy", func() {
			decoy := []byte("jobs:\n  publish:\n    steps:\n" +
				"      - uses: actions/setup-go@abc\n        with:\n          version: v3.21.3\n" +
				"      - uses: azure/setup-helm@abc\n        with:\n          version: v9.9.9\n")
			Expect(verifyChartPinsIn(goodChart, goodCI, decoy)).To(
				MatchError(ContainSubstring("not in ci.yml's chart matrix")))
		})

		It("refuses a publish job with no setup-helm step at all", func() {
			Expect(verifyChartPinsIn(goodChart, goodCI,
				[]byte("jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@abc\n"))).To(
				MatchError(ContainSubstring("no azure/setup-helm step")))
		})

		// setup-helm with no version installs whatever is latest, so an absent
		// pin is the realistic drift — not a malformed file.
		It("refuses a setup-helm step that pins no version", func() {
			Expect(verifyChartPinsIn(goodChart, goodCI,
				[]byte("jobs:\n  publish:\n    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          token: xyz\n"))).To(
				MatchError(ContainSubstring("sets no with.version")))
		})

		It("refuses a chart job that declares no helm matrix", func() {
			Expect(verifyChartPinsIn(goodChart,
				[]byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        other: [a]\n"), goodPublish)).To(
				MatchError(ContainSubstring("no helm matrix entries")))
		})

		// The link the matrix depends on: a literal here would make both legs
		// install the same Helm and both pass, with one leg named for a version
		// it never ran.
		It("refuses a chart job that installs a literal instead of the matrix", func() {
			bad := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: v3.21.3\n")
			Expect(verifyChartPinsIn(goodChart, bad, goodPublish)).To(
				MatchError(ContainSubstring("instead of ${{ matrix.helm }}")))
		})

		It("refuses a chart job whose matrix installs nothing", func() {
			bad := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3]\n" +
				"    steps:\n      - uses: actions/checkout@abc\n")
			Expect(verifyChartPinsIn(goodChart, bad, goodPublish)).To(
				MatchError(ContainSubstring("no azure/setup-helm step")))
		})

		// A gate whose diagnosis contradicts the file it rejected is worse than
		// no gate: it sends a maintainer looking for a step that is plainly
		// there. GitHub resolves `uses:` owner/repo case-insensitively, and
		// Azure/setup-helm is the casing the action's own README uses.
		It("accepts the action reference in the casing its own README uses", func() {
			ok := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: Azure/setup-helm@abc\n        with:\n          version: ${{ matrix.helm }}\n")
			Expect(verifyChartPinsIn(goodChart, ok, goodPublish)).To(Succeed())
		})

		// GitHub accepts an expression with no interior spaces, so rejecting it
		// would fail the gate on a workflow that installs exactly the right Helm.
		It("accepts the matrix expression without interior spaces", func() {
			ok := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{matrix.helm}}\n")
			Expect(verifyChartPinsIn(goodChart, ok, goodPublish)).To(Succeed())
		})

		// The expression must still name the helm matrix and nothing else — a
		// neighbouring key would install one version under both leg names.
		It("refuses an expression naming a different matrix key", func() {
			bad := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{ matrix.kubernetes }}\n")
			Expect(verifyChartPinsIn(goodChart, bad, goodPublish)).To(
				MatchError(ContainSubstring("instead of ${{ matrix.helm }}")))
		})

		It("reads the publish pin through the same casing tolerance", func() {
			pub := []byte("jobs:\n  publish:\n    steps:\n      - uses: Azure/setup-helm@abc\n" +
				"        with:\n          version: v3.21.3\n")
			Expect(verifyChartPinsIn(goodChart, goodCI, pub)).To(Succeed())
		})
	})
})

// -- the pre-push tag gate ------------------------------------------------------

// tagGateRepo is a throwaway git repository holding one commit, whose
// internal/version and Chart.yaml contents the caller chooses. The pre-push
// hook reads both out of the *tagged commit* via `git show`, so exercising it
// means committing them rather than just writing them to disk.
type tagGateRepo struct {
	dir string
	sha string
}

// fixtureEnv is the environment every fixture git command runs with: the
// ambient one stripped of *every* GIT_* variable, then given back only what the
// fixture chooses.
//
// Stripping is the whole point, and it is not theoretical. git exports GIT_DIR,
// GIT_WORK_TREE, GIT_INDEX_FILE and GIT_OBJECT_DIRECTORY to the hooks it runs
// (see `git rev-parse --local-env-vars`), and those outrank cmd.Dir — so a
// fixture built from os.Environ() inside a pre-push hook commits into the
// *real* repository and moves its branch. The pre-push hook runs this suite via
// its `go test -tags mage .` invocation, and that is exactly what happened: six
// fixture commits landed on the branch being pushed. Neither `mage
// test:magefile` nor CI can reproduce it — there is no hook in the picture, so
// there is no GIT_DIR to inherit — which is why it survived five green rounds
// of review.
func fixtureEnv() []string {
	env := make([]string, 0, len(os.Environ())+6)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") {
			continue
		}
		env = append(env, kv)
	}
	// No signing, no hooks, no ambient identity: the fixture must build
	// identically on a maintainer's machine and on a CI runner.
	return append(env,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
}

// gitIn runs one git command in dir with the fixture environment, and is the
// only place in this file that builds a git exec.Command. Everything else goes
// through it — including the decoy repository's own setup and inspection —
// because forgetting cmd.Env at a single site is exactly how these fixtures came
// to operate on the real repository. Output is folded into the failure message
// so a fixture that cannot build says why.
func gitIn(dir string, args ...string) string {
	GinkgoHelper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = fixtureEnv()
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "git %s in %s: %s", strings.Join(args, " "), dir, out)
	return strings.TrimSpace(string(out))
}

func newTagGateRepo(constVersion, chartVersion, chartAppVersion string) *tagGateRepo {
	dir := GinkgoT().TempDir()

	git := func(args ...string) string { return gitIn(dir, args...) }

	git("init", "--quiet")

	write := func(path, body string) {
		full := filepath.Join(dir, path)
		Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(Succeed())
		Expect(os.WriteFile(full, []byte(body), 0o644)).To(Succeed())
	}

	// Only the two lines the hook parses need to be realistic; the surrounding
	// text is there so the parse has something to skip past.
	write("internal/version/version.go", fmt.Sprintf(
		"package version\n\n// preamble\nconst Version = %q\n", constVersion))
	// apiVersion deliberately precedes version, because a careless ^version:
	// parse would match it.
	write("charts/openvox-ca/Chart.yaml", fmt.Sprintf(
		"apiVersion: v2\nname: openvox-ca\nversion: %s\nappVersion: %q\n",
		chartVersion, chartAppVersion))

	git("add", "-A")
	git("commit", "--quiet", "--no-gpg-sign", "-m", "fixture")

	return &tagGateRepo{dir: dir, sha: git("rev-parse", "HEAD")}
}

// git runs a git command inside the fixture. A read is as dangerous as a write
// here: a `rev-parse HEAD` that answers from the ambient GIT_DIR hands the gate
// a commit the fixture does not contain, which the gate then skips, passing a
// spec that exists to watch it fail.
func (r *tagGateRepo) git(args ...string) string {
	GinkgoHelper()
	return gitIn(r.dir, args...)
}

// push runs the hook the way git does: the pushed refs arrive on stdin as
// "<local-ref> <local-sha> <remote-ref> <remote-sha>".
func (r *tagGateRepo) push(remoteRef, localSHA string) (string, error) {
	script, err := filepath.Abs(filepath.Join(".lefthook", "pre-push", "verify-tags.sh"))
	Expect(err).NotTo(HaveOccurred())

	cmd := exec.Command("sh", script)
	cmd.Dir = r.dir
	// The script's own `git show` must read the fixture, not whatever repo the
	// ambient GIT_DIR names — under a real pre-push hook that is the repo being
	// pushed, so an inherited environment made every one of these specs assert
	// against the wrong commit.
	cmd.Env = fixtureEnv()
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s %s %s %s\n", remoteRef, localSHA, remoteRef, strings.Repeat("0", 40)))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

var _ = Describe("fixtureEnv", func() {
	// Pins the strip directly, rather than only through its consequences. The
	// decoy spec proves the fixtures survive a leak; this proves the mechanism
	// they survive it by, so a named-variable allow-list replacing the prefix
	// loop fails here rather than destructively somewhere else.
	It("removes every ambient GIT_ variable", func() {
		for _, k := range []string{
			"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
			"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_QUARANTINE_PATH", "GIT_PREFIX",
		} {
			GinkgoT().Setenv(k, "/should/not/survive")
		}

		kept := map[string]bool{
			"GIT_CONFIG_GLOBAL=/dev/null":          true,
			"GIT_CONFIG_SYSTEM=/dev/null":          true,
			"GIT_AUTHOR_NAME=test":                 true,
			"GIT_AUTHOR_EMAIL=test@example.com":    true,
			"GIT_COMMITTER_NAME=test":              true,
			"GIT_COMMITTER_EMAIL=test@example.com": true,
		}
		for _, kv := range fixtureEnv() {
			if strings.HasPrefix(kv, "GIT_") {
				Expect(kept).To(HaveKey(kv), "an ambient GIT_ variable survived the strip")
			}
		}
	})
})

var _ = Describe("the pre-push tag gate", func() {
	// Untested shell driving `git show` through sed pipelines is exactly the
	// kind of thing that fails open. These specs run the real script.
	const version = "0.9.0"

	It("allows a tag whose version and chart both match", func() {
		repo := newTagGateRepo(version, version, version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	// The regression that made this suite dangerous rather than merely wrong.
	// Run from a pre-push hook, os.Environ() carries the repository being pushed
	// in GIT_DIR and friends; they outrank cmd.Dir, so the fixture committed onto
	// the real branch and the specs then asserted against the real repo. A decoy
	// stands in for the hook's repository.
	//
	// All four variables the fixtureEnv comment names are planted, not just the
	// two that happened to cause the incident. A partial strip is destructive in
	// its own right: with GIT_INDEX_FILE alone leaking, `git add -A` still finds
	// the fixture's own .git, so the fixture builds and the decoy stays empty,
	// but the staged entries are written into the other repository's index —
	// destroying whatever the developer had staged when they ran git push.
	decoyLeak := func() string {
		decoy := GinkgoT().TempDir()
		gitIn(decoy, "init", "--quiet")
		// A file to stage, so a leak lands a real commit here — the harm as it
		// actually occurred — rather than failing on an empty index.
		Expect(os.WriteFile(filepath.Join(decoy, "tracked.txt"), []byte("x\n"), 0o644)).To(Succeed())

		GinkgoT().Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
		GinkgoT().Setenv("GIT_WORK_TREE", decoy)
		GinkgoT().Setenv("GIT_INDEX_FILE", filepath.Join(decoy, ".git", "index"))
		GinkgoT().Setenv("GIT_OBJECT_DIRECTORY", filepath.Join(decoy, ".git", "objects"))

		// Deferred, so the decoy is proven untouched even when an assertion in
		// the spec body fails first — otherwise the one check that looks at the
		// actual harm is the one that never runs.
		DeferCleanup(func() {
			Expect(gitIn(decoy, "rev-list", "--all", "--count")).To(Equal("0"),
				"a commit landed in the decoy repository")
			Expect(gitIn(decoy, "status", "--porcelain")).To(Equal("?? tracked.txt"),
				"the decoy's index or work tree was written to")
		})
		return decoy
	}

	It("builds and verifies its fixture in its own repository under a leaked environment", func() {
		decoyLeak()

		repo := newTagGateRepo(version, version, version)
		// The fixture must really hold its own commit: without this, a gate that
		// skipped everything would satisfy the assertions below.
		Expect(repo.git("log", "--oneline")).To(ContainSubstring("fixture"))

		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	// The allow path above cannot detect a leak at the push site on its own: the
	// gate skips any commit it cannot resolve (`git rev-parse ... || continue`),
	// so a leaked environment makes it exit zero and silent, which is precisely
	// what the allow path asserts. Only a refusal proves the script read the
	// fixture.
	It("still fails closed under a leaked environment", func() {
		decoyLeak()

		repo := newTagGateRepo("0.8.0", version, version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred(), "the gate skipped the tag instead of refusing it")
		Expect(out).To(ContainSubstring(`internal/version at the tagged commit says "0.8.0"`))
	})

	It("refuses a tag the internal/version constant disagrees with", func() {
		repo := newTagGateRepo("0.8.0", version, version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("internal/version at the tagged commit says \"0.8.0\""))
	})

	It("refuses a tag the chart version disagrees with", func() {
		repo := newTagGateRepo(version, "0.8.0", version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("Helm chart at the tagged commit"))
		Expect(out).To(ContainSubstring(`version="0.8.0"`))
	})

	It("refuses a tag the chart appVersion disagrees with", func() {
		repo := newTagGateRepo(version, version, "0.8.0")
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring(`appVersion="0.8.0"`))
	})

	It("refuses rather than passes when Chart.yaml cannot be parsed", func() {
		// An unquoted appVersion, the most likely way to break the parse. Both
		// halves must fail closed: an empty parse is a mismatch, not a pass.
		repo := newTagGateRepo(version, version, version)
		Expect(os.WriteFile(
			filepath.Join(repo.dir, "charts", "openvox-ca", "Chart.yaml"),
			[]byte("apiVersion: v2\nversion: "+version+"\nappVersion: "+version+"\n"), 0o644,
		)).To(Succeed())
		repo.git("commit", "--quiet", "--no-gpg-sign", "-a", "-m", "unquoted")

		hookOut, err := repo.push("refs/tags/v"+version, repo.git("rev-parse", "HEAD"))
		Expect(err).To(HaveOccurred())
		Expect(hookOut).To(ContainSubstring(`appVersion=""`))
	})

	It("ignores a branch push", func() {
		repo := newTagGateRepo("0.8.0", "0.7.0", "0.6.0")
		out, err := repo.push("refs/heads/main", repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	It("ignores a tag deletion", func() {
		// git signals a deletion with an all-zero local sha; there is no commit
		// to inspect, and refusing one would make a bad tag unremovable.
		repo := newTagGateRepo("0.8.0", "0.7.0", "0.6.0")
		out, err := repo.push("refs/tags/v"+version, strings.Repeat("0", 40))
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	It("ignores a non-version tag", func() {
		repo := newTagGateRepo("0.8.0", "0.7.0", "0.6.0")
		out, err := repo.push("refs/tags/nightly", repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})
})
