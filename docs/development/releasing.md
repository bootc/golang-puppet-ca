# Cutting a release

> This is a maintainer reference. It describes how to publish a tagged release
> of OpenVox CA, what the automation does, and how to rehearse the whole thing
> on a personal fork before touching the upstream repository.

A release is two actions: **land a change setting the release version, then
push an annotated `v*` tag** pointing at it. Everything else is automation —
there is no release branch and no manual artefact upload.

The `Version` constant in
[`internal/version`](../../internal/version/version.go) is the single source
of truth: artefact names embed it, both binaries report it via `--version`,
and the Release workflow refuses to publish a tag that does not equal
`"v" + Version`. Between releases the constant carries a `-dev` suffix, so a
stray tag on an unprepared commit fails the gate instead of shipping
mislabelled artefacts.

## What a release produces

| Artefact | Produced by | Where it lands |
| --- | --- | --- |
| `openvox-ca_X.Y.Z_linux_amd64.tar.gz` | `mage build:dist` | GitHub release assets |
| `openvox-ca_X.Y.Z_linux_arm64.tar.gz` | `mage build:dist` | GitHub release assets |
| `openvox-ca_X.Y.Z_linux_amd64_fips.tar.gz` | `mage build:dist` (`GOEXPERIMENT=boringcrypto`) | GitHub release assets |
| `openvox-ca_X.Y.Z_linux_arm64_fips.tar.gz` | `mage build:dist` (`GOEXPERIMENT=boringcrypto`) | GitHub release assets |
| `checksums.txt` (SHA-256) | `mage build:dist` | GitHub release assets |
| GitHub release + auto-generated notes | `gh release create --generate-notes` | Releases page |
| `ghcr.io/voxpupuli/openvox-ca:{X.Y.Z,X.Y,latest}` | *Container images* workflow | GHCR |
| `…:{X.Y.Z,X.Y,latest}-alpine` | *Container images* workflow | GHCR |

Each tarball contains both binaries, `openvox-ca` and `openvox-ca-ctl`. Only
Linux is built: there are no macOS or Windows release artefacts.

The major-only container tag (`:1`, `:2`) is deliberately suppressed while the
version is `v0.*`, because a `0.x` major carries no compatibility promise.

## The machinery

Two workflows fire independently off the same tag push. Neither waits for the
other, and neither waits for CI.

| Workflow | File | What it does on a `v*` tag |
| --- | --- | --- |
| **Release** | [`release.yml`](../../.github/workflows/release.yml) | Verifies the tag equals `"v" +` the `internal/version` constant, builds each variant on a runner native to its architecture (`mage build:distVariant`, no cross toolchain), then aggregates the tarballs, generates `checksums.txt`, and runs `gh release create` |
| **Container images** | [`container-images.yml`](../../.github/workflows/container-images.yml) | Builds both image variants on native amd64 and arm64 runners and publishes multi-arch manifests. See [publishing container images](publishing-images.md) |

> **CI does not run on tags.** [`ci.yml`](../../.github/workflows/ci.yml) is
> wired to `push: branches: [main]` and pull requests only. Beyond the
> version-match gate, tagging a broken commit will happily publish a broken
> release. Always tag a commit that has already gone green on `main`, and
> check it before you push the tag. (The artefact builds themselves are
> exercised on every PR by CI's per-variant *Release artefact build* jobs, so
> at least that step is unlikely to be the thing that breaks.)

## Before you tag

1. **Land the version bump.** Open a PR setting the `Version` constant in
   [`internal/version/version.go`](../../internal/version/version.go) to
   exactly the release version without the `v` prefix (`0.9.0` for tag
   `v0.9.0`), and merge it. The Release workflow refuses a tag whose version
   does not match the constant at the tagged commit, so this must land first.

2. **Confirm the target commit is green on `main`.**

   ```console
   $ git fetch origin
   $ git log --oneline -1 origin/main
   $ gh run list --branch main --limit 5
   ```

   The *CI success* job is the aggregate gate — that is the one that must be
   green.

3. **Check the tree builds the release artefacts.** This catches
   cross-compilation breakage before the workflow does:

   ```console
   $ mage build:dist
   $ ls -l dist/
   ```

   **This only completes on Linux.** The two pure-Go variants
   (`CGO_ENABLED=0`) cross-compile from anywhere, but the FIPS variants are
   `cgo` builds and need a Linux C toolchain per target architecture (the
   cross ones on Debian/Ubuntu: `gcc-aarch64-linux-gnu` /
   `gcc-x86-64-linux-gnu`) — on macOS the FIPS builds fail up front with
   `cgo: C compiler "x86_64-linux-gnu-gcc" not found` (and the aarch64
   equivalent), after the pure-Go tarballs have already been written, leaving
   `dist/` incomplete. That is expected, not a regression.

   From macOS, either check the pure-Go variants only:

   ```console
   $ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/...
   $ CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/...
   ```

   …and leave the FIPS builds to CI (a single variant can also be built with
   `mage build:distVariant linux_amd64`), or run the full thing in a
   container:

   ```console
   $ docker run --rm -v "$PWD:/src" -w /src golang:1-bookworm \
       sh -c 'go install github.com/magefile/mage@v1.17.2 && mage build:dist'
   ```

   The FIPS variants are the ones most likely to break, precisely because
   they are the only `cgo` builds in the set and the only ones you cannot
   casually check from a Mac.

4. **Skim the commits since the previous tag** so you know what the release
   notes ought to say (for the first release, since the start of history):

   ```console
   $ git log --oneline --no-merges v0.8.0..origin/main   # or: origin/main, for the first tag
   ```

5. **Decide whether this is a pre-release.** See
   [Pre-1.0 and pre-release tags](#pre-10-and-pre-release-tags) below —
   a `v0.9.0` tag is *not* treated as a pre-release by the automation, and
   will claim the `latest` container tag.

## Cutting the release

```console
$ git fetch origin
$ git tag -a v0.9.0 <commit-sha> -m "OpenVox CA 0.9.0"
$ git show v0.9.0                      # sanity-check the target and signature
$ git push origin v0.9.0
```

Notes:

- Use an **annotated** tag (`-a`). The workflows key off `github.ref_name`, so
  a lightweight tag technically works, but annotated tags carry the tagger,
  date, and message, and are what `git describe` prefers.
- Tags are signed automatically if you have `tag.gpgsign = true` set (this
  repository's maintainers do).
- Push the tag to **`origin` (`voxpupuli/openvox-ca`)**, not to a fork, when
  making a real release.
- `<commit-sha>` is optional; without it you tag `HEAD`, which is only correct
  if your local `main` is exactly `origin/main`. Being explicit is safer.

Then watch both workflows:

```console
$ gh run list --limit 5
$ gh run watch <run-id>
```

The release build takes a few minutes; the container build is the slower of
the two (four image builds plus two manifest merges).

## Release notes

`release.yml` calls `gh release create --generate-notes`, which asks GitHub to
build the notes from the **merged pull requests** between the previous release
tag and this one. It produces a flat "What's Changed" list plus a new
contributors section and a full changelog link.

Two consequences worth knowing:

- **On the first-ever tag there is no previous release**, so GitHub generates
  notes covering the entire history of the repository. For this repository
  that is 300-plus commits, the majority of them Renovate and Dependabot
  dependency bumps. The generated notes for `v0.9.0` will be a very long,
  very noisy list.
- **The notes are generated once, at release-creation time.** They are not
  regenerated later, so editing them afterwards is safe and permanent.

### Curating the notes after the fact

The generated notes are a starting point, not the finished product. The
expected workflow is to let the automation create the release, then edit it:

```console
$ gh release view v0.9.0                       # read what was generated
$ gh release edit v0.9.0 --notes-file NOTES.md # replace wholesale
```

For a first release in particular, write a short human summary at the top —
what OpenVox CA is, what state it is in, what the notable capabilities are —
and either trim the dependency churn or fold the auto-generated list into a
collapsed `<details>` block beneath it.

To see what GitHub *would* generate before you tag, ask for it directly:

```console
$ gh api repos/voxpupuli/openvox-ca/releases/generate-notes \
    -f tag_name=v0.9.0 -f target_commitish=main --jq .body
```

That call is read-only and creates nothing, so it is a safe dry run.

### Reducing the noise permanently

GitHub honours a `.github/release.yml` configuration file that categorises
generated notes by pull-request label and excludes chosen labels or authors
entirely — for example, dropping everything authored by `renovate[bot]` and
`dependabot[bot]` into a single collapsed "Dependencies" category instead of
listing each bump inline. This repository does not currently have one; adding
it would make every subsequent release's notes usable without hand-editing.

## Pre-1.0 and pre-release tags

Two behaviours to be aware of when tagging `v0.9.0`:

- **`gh release create` does not pass `--prerelease`.** The GitHub release will
  be marked as the latest stable release, and appear as such on the repository
  front page. If you want it flagged as a pre-release, either add the flag to
  the workflow or fix it afterwards with `gh release edit v0.9.0 --prerelease`.
- **`v0.9.0` claims the `latest` container tags.** The image workflow uses
  `latest=auto`, which means "apply `latest` to any semver tag that is not a
  semver pre-release". `v0.9.0` is not a pre-release in semver terms, so
  `ghcr.io/voxpupuli/openvox-ca:latest` and `:latest-alpine` will move to it.

If you want a rehearsal that touches neither of those, tag a genuine semver
pre-release instead — `v0.9.0-rc1`. `docker/metadata-action` recognises the
`-rc1` suffix and withholds `latest`, and `gh release create --generate-notes`
still produces full notes. The GitHub release still will not be marked
pre-release, but the container tags stay clean.

## Rehearsing on your own fork

The workflows derive everything they need from the repository they run in —
the image name is computed from `github.repository`, and the release is created
with the run's own `GITHUB_TOKEN` — so a fork is a complete, self-contained
rehearsal environment. Nothing points back at the upstream repository.

A fork run publishes to `ghcr.io/<you>/<fork-name>` and creates a release on
your fork. Both are throwaway.

### Setup (once)

1. Confirm the fork is **public** — the free `ubuntu-24.04-arm` runners used
   for the arm64 image builds are only free on public repositories. On a
   private fork the arm64 jobs queue indefinitely.
2. Confirm Actions are enabled and the four workflows are active:

   ```console
   $ gh api repos/<you>/<fork>/actions/workflows --jq '.workflows[] | {name, state}'
   ```

3. Confirm the fork's `GITHUB_TOKEN` may write packages: Settings → Actions →
   General → *Workflow permissions* → **Read and write permissions**.
4. Check your remote actually points where you think. If you renamed the fork
   on GitHub, the local remote URL may still carry the old name and work only
   via GitHub's redirect:

   ```console
   $ git remote -v
   $ git remote set-url <remote> git@github.com:<you>/<fork>.git
   ```

### The rehearsal

The version-match gate applies on the fork too, so the rehearsal needs a
throwaway commit setting the `Version` constant to the rehearsal version —
which also makes the rehearsal exercise the real process end to end:

```console
$ git checkout -b rehearsal origin/main
$ $EDITOR internal/version/version.go    # set Version = "0.9.0-test1"
$ git commit -m "Bump version to 0.9.0-test1" internal/version/version.go
$ git push <fork-remote> rehearsal
$ git tag -a v0.9.0-test1 -m "release rehearsal"
$ git push <fork-remote> v0.9.0-test1
$ gh run list --repo <you>/<fork> --limit 5
```

Use a tag name you will never want upstream (`v0.9.0-test1`, `v0.0.1-rehearsal`)
so there is no chance of it being confused with the real thing later.

Then verify the results end to end:

```console
$ gh release view v0.9.0-test1 --repo <you>/<fork>
$ gh release download v0.9.0-test1 --repo <you>/<fork> --dir /tmp/rehearsal
$ cd /tmp/rehearsal && sha256sum -c checksums.txt
$ tar tzf openvox-ca_0.9.0-test1_linux_amd64.tar.gz
$ docker run --rm ghcr.io/<you>/<fork>:0.9.0-test1 --version
```

Worth checking specifically:

- All four tarballs are present and the checksums verify.
- Each tarball contains both `openvox-ca` and `openvox-ca-ctl`, and both
  report the rehearsal version (with commit metadata) via `--version`.
- The FIPS binaries are genuinely boringcrypto builds:

  ```console
  $ go version -m openvox-ca | grep -E 'boringcrypto|GOEXPERIMENT'
  ```

- The published manifest really is multi-arch:

  ```console
  $ docker buildx imagetools inspect ghcr.io/<you>/<fork>:0.9.0-test1
  ```

### Cleaning up

```console
$ gh release delete v0.9.0-test1 --repo <you>/<fork> --yes
$ git push <fork-remote> --delete v0.9.0-test1 rehearsal
$ git tag -d v0.9.0-test1
$ git branch -D rehearsal
```

The GHCR package versions have to be deleted separately, from the package's
*Versions* page on GitHub, or with:

```console
$ gh api --method DELETE /user/packages/container/<fork-name>/versions/<version-id>
```

Deleting the rehearsal tags is not strictly necessary, but leaving them behind
means a later `git fetch --tags` from the fork pollutes your local tag list.

## Known gaps

These are current limitations of the release machinery rather than things you
can work around at release time. They are worth fixing before 1.0.

| Gap | Impact |
| --- | --- |
| **CI does not run on tags.** | Nothing prevents tagging a commit that has not passed the test suite. |
| **No `--prerelease` handling.** | Pre-1.0 and `-rc` tags are published as stable GitHub releases. |
| **No `.github/release.yml`.** | Generated notes are a flat list dominated by dependency bumps. |
| **No signing or attestation of release artefacts.** | `checksums.txt` establishes integrity against tampering in transit, but nothing establishes provenance. Image provenance attestations are also explicitly disabled, because they break the push-by-digest manifest merge. |
