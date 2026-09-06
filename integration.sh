#!/usr/bin/env bash
set -eu -o pipefail

# Rebuild the throwaway `integration` branch: merge every open PR branch into a
# worktree, apply any fixes no single branch can carry, and force-push it.
#
# Companions:
#   integration-trial.sh         which branches conflict, read-only, no worktree
#   integration-verify-merge.sh  what a resolution dropped; runs below, mid-merge
#
# The image is consumed: a deployment pins
# ghcr.io/bootc/openvox-ca:integration-alpine by digest. Report the digest after
# a push, not just that it happened.
#
# ---------------------------------------------------------------------------
# WHAT GOES IN BRANCHES
#
# Every open non-draft PR except Renovate: dependency bumps merge on their own
# and would spend the conflict budget on work that does not collide.
#
# Membership is the only thing needing an edit here. Entries are refs, not shas,
# so a head moving costs nothing; refresh when a PR opens or merges. A gap
# against `gh pr list` is expected, so check the KIND of what is left over
# rather than that the sets match:
#
#   eval "$(sed -n '/^BRANCHES=(/,/^)/p' integration.sh)"
#   comm -23 <(gh pr list --state open --json isDraft,headRefName \
#                --jq '.[] | select(.isDraft|not) | .headRefName' | sort) \
#            <(printf '%s\n' "${BRANCHES[@]}" | sed 's|^origin/||' | sort)
#
# local/integration-setup shows on the other side of that comm, by design.
#
# Order by COLLISION, not by file overlap — two branches touching one file
# usually merge cleanly. Measure it with pairwise `git merge-tree --write-tree`
# and keep any pair that truly conflicts adjacent, so it surfaces once.
#
# ---------------------------------------------------------------------------
# WHEN A BRANCH FAILS: HOLD THE BUILD, DO NOT DROP THE BRANCH
#
# A build that quietly omits a branch looks like a full integration, so a green
# result is read as evidence about a set that was never assembled. On a failure:
# stop, report which branch and why, and leave BRANCHES alone. Removing an entry
# is Chris's call.
#
# ---------------------------------------------------------------------------
# CARRIED FIXES — integration-fixes.patch, applied after the merge loop
#
# None. PATCH_PATHS is empty and there must be no patch file; the guard below
# aborts if one appears undeclared.
#
# A carried fix is a spec correct on its own branch and wrong only once another
# is merged beside it. It is scoped to a SET of branches, not to the file it
# edits. Check the owning branch before retiring or re-adding one: a fix carried
# past its owner is a duplicate declaration rather than a no-op, and "the patch
# stopped applying" usually means the owner absorbed it.
#
# ---------------------------------------------------------------------------
# HAZARD
#
# Never run `git history` here without --update-refs=head, and run
# `git branch --contains <commit>` first. It defaults to --update-refs=branches,
# which rewrites every local branch descending from the commit — and
# `integration` descends from every PR branch below. Several worktrees share the
# one object store.
#
# ---------------------------------------------------------------------------
# A GREEN BUILD IS NOT CLEARANCE TO TAG
#
# Do not push a `v*` tag until issue #250 closes (#282 is its PR). release.yml,
# container-images.yml and helm-chart.yml each trigger on `v*` independently
# with no `needs:`, so a premature tag publishes images — including the mutable
# `latest` — and the chart, regardless of release.yml failing. This build pushes
# a branch and never a tag.
#
# ---------------------------------------------------------------------------
# RESOLVING CONFLICTS
#
# rerere is not verification. It replays on matching conflict TEXT from a cache
# shared by every worktree here, so a build inherits resolutions recorded
# against trees that have since moved. integration-verify-merge.sh reports what
# a resolution dropped: advisory, and it false-positives on re-wrapped prose.
#
# The surface is the PARAGRAPH, not the file. The same few passages recur across
# locking.md, metrics.md, configuration.md and mixin/README.md, and several
# branches each amend one for their own correct reason.
#
# A branch that predates another carries the OLD claim unchanged, in a region
# the newer one never touches, so nothing conflicts. Where one side of a hunk is
# a branch's own new prose and the other the same paragraph from an older base,
# neither is takeable whole: union, then re-check every claim against the merged
# CODE.
#
# A CONFLICT BLOCK NEED NOT START OR END ON A COMPLETE CONSTRUCT. Both sides can
# end mid-construct with the closing token in the shared context AFTER the end
# marker, where it closes one side only; in mixin/tests.yaml the lines between
# two blocks can be the common PREFIX of each side's last alert rather than
# context. The tell: print the first and last line of each side and what follows
# the marker. If a last line is not a complete construct, reconstruct each side
# WHOLE — ours1 + shared + ours2 + tail, likewise theirs — then union at the
# level the file is made of: whole test groups by name, whole struct fields,
# whole sections.
#
# gofmt and `go build` catch the Go version instantly; nothing catches the YAML
# one. `mage test:mixin` runs `promtool test rules`, but a malformed union can
# still parse — assert the group count and that no two groups share a name.

BRANCHES=(
  local/integration-setup

  origin/fix/293-allow-subject-alt-names  # PR #294 — issue #293
  origin/fix/304-partition-memory-budget  # PR #307 — issue #304

  # Collide on magefile.go, so they sit together. #266 is approved and held
  # behind #282, and is far the furthest behind main.
  origin/feature/release-packaging        # PR #266
  origin/feature/package-payload          # PR #282
)


# Branches excluded for a REASON, as opposed to merely absent. Commenting one
# out of BRANCHES stops its merge and does nothing about its code: a held-out
# branch merged into one we do integrate arrives anyway, silently. The
# machinery stays when empty; both loops below are silent on an empty set.
HELD_OUT=(
)


# Ancestry catches a MERGE and not a CHERRY-PICK, and this repo cherry-picks.
# Pair each held-out branch with "ref|symbol" its defect cannot travel without.
# A marker, not a proof: a rename defeats it, and it locates code rather than
# judging it, so a hit means look.
HELD_OUT_MARKERS=(
)

git fetch origin

# Pre-flight: a held-out branch must not have reached anything we merge.
for HELD in "${HELD_OUT[@]}"; do
  git rev-parse --verify --quiet "$HELD" >/dev/null || continue
  for BRANCH in "${BRANCHES[@]}"; do
    if git merge-base --is-ancestor "$HELD" "$BRANCH" 2>/dev/null; then
      echo "$HELD is held out, but is an ancestor of $BRANCH — it would be merged anyway." >&2
      echo "Read its note in BRANCHES before going further: excluding it from the array" >&2
      echo "no longer excludes its code, so the hold has to be re-decided rather than kept." >&2
      exit 1
    fi
  done
done

# Same question by the other route: has a marker symbol been picked across?
for ENTRY in "${HELD_OUT_MARKERS[@]}"; do
  HELD=${ENTRY%%|*}
  MARKER=${ENTRY#*|}
  git rev-parse --verify --quiet "$HELD" >/dev/null || continue
  for BRANCH in "${BRANCHES[@]}"; do
    if git grep -q "$MARKER" "$BRANCH" -- internal 2>/dev/null; then
      echo "$BRANCH contains '$MARKER', a marker for held-out $HELD." >&2
      echo "Ancestry says it was not merged, so it was cherry-picked or reimplemented." >&2
      echo "Check whether the held-out defect came with it before building." >&2
      exit 1
    fi
  done
done

git worktree add ../openvox-ca-integration -B integration origin/main

cd ../openvox-ca-integration
test "$(git rev-parse --abbrev-ref HEAD)" = "integration"

for BRANCH in "${BRANCHES[@]}"; do
  if ! git merge --no-edit "$BRANCH"; then
    if [ -n "$(git diff --name-only --diff-filter=U)" ]; then
      echo "Unresolved conflicts merging $BRANCH — dropping to a shell." >&2
      echo "Resolve, 'git add' the files, then either 'git commit' yourself or just exit when staged." >&2
      export debian_chroot="CONFLICTED"
      bash -i || true
      unset debian_chroot
      if [ -n "$(git diff --name-only --diff-filter=U)" ]; then
        echo "Still unresolved conflicts merging $BRANCH — aborting" >&2
        exit 1
      fi
    fi
    # Ask git, do not stat a path: in a linked worktree .git is a file holding a
    # gitdir: pointer, so `[ -f .git/MERGE_HEAD ]` is always false and the commit
    # never ran. A hand-resolved merge was left staged, the next merge refused,
    # and the work died with the worktree — and rerere never learned any of those
    # resolutions, because it records at commit time.
    if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
      # While the index still has stages: report what the resolution dropped.
      ../openvox-ca/integration-verify-merge.sh || true
      git commit --no-edit
    fi
  fi
done

# Carried fixes ride in as a patch rather than a branch: some files they edit do
# not exist on main, so a branch would have to add them and collide with the PR
# that owns each. The patch arrives on local/integration-setup and is applied
# last, once every file it edits is merged.
#
# PATCH_PATHS declares what is carried:
#
#   non-empty  a patch is REQUIRED and may touch only these paths. Missing is an
#              abort — this runs in the WORKTREE, so the patch must be committed
#              on local/integration-setup to be here at all. The allowlist
#              exists because regeneration is a `git diff`, which cannot tell
#              the fixes from a half-resolved conflict or a stray edit.
#   empty      no fixes carried. A patch present anyway is an abort, since
#              nothing declares what it may contain.
PATCH_PATHS=""

if [ -n "$PATCH_PATHS" ] && [ ! -f integration-fixes.patch ]; then
  echo "PATCH_PATHS declares carried fixes but integration-fixes.patch is not in" >&2
  echo "this worktree, so NONE were applied. The build would look clean here and" >&2
  echo "fail under pre-push instead, in files whose own branches are blameless." >&2
  echo "Most likely it is untracked in the main checkout — commit it:" >&2
  echo "  git -C ../openvox-ca add integration-fixes.patch && git -C ../openvox-ca commit" >&2
  exit 1
elif [ -f integration-fixes.patch ]; then
  UNEXPECTED=$(git apply --numstat integration-fixes.patch | cut -f3 | while read -r p; do
    case " $PATCH_PATHS " in *" $p "*) ;; *) echo "$p" ;; esac
  done)
  if [ -n "$UNEXPECTED" ]; then
    echo "integration-fixes.patch touches paths PATCH_PATHS does not declare:" >&2
    printf '%s\n' "$UNEXPECTED" | sed 's/^/  /' >&2
    echo "Each carried fix is described at the top of this file; nothing else belongs" >&2
    echo "in the patch. If a fix has been added, declare it in PATCH_PATHS. If the" >&2
    echo "patch is stale, regenerate it with an explicit pathspec, or delete it." >&2
    exit 1
  fi
  echo "Applying integration-fixes.patch..." >&2
  # --3way so it survives churn around the hunks it does not care about. When it
  # fails, that is the signal: a branch has moved under a fix. Re-derive it —
  # and check first whether the owning branch has simply absorbed it, which is
  # the commonest cause and means the entry retires rather than being rebuilt.
  if git apply --3way integration-fixes.patch; then
    # --3way applies cleanly as a NO-OP when the patch is already in the tree, so
    # a re-run leaves nothing staged and `git commit` exits non-zero. Under set -e
    # that aborted the whole script AFTER every merge and BEFORE the push — the
    # worst place to fail, since all the expensive work was done and the only
    # thing missing was the one command that publishes it. Commit only if the
    # patch actually changed something.
    if git diff --quiet && git diff --cached --quiet; then
      echo "integration-fixes.patch was already applied; nothing to commit." >&2
    else
      git commit -qam "Carry the cross-branch test fixes this build needs"
    fi
  else
    echo "integration-fixes.patch no longer applies — a branch has moved under it." >&2
    echo "Check whether its owning branch has absorbed the fix; if so, drop the entry" >&2
    echo "from PATCH_PATHS and delete the patch. Otherwise re-derive it with:" >&2
    echo "  (cd ../openvox-ca-integration && git diff -- $PATCH_PATHS) > integration-fixes.patch" >&2
    exit 1
  fi
else
  echo "No carried fixes: PATCH_PATHS is empty and no patch is present." >&2
fi

# container-images.yml must keep BOTH contributions, lost by opposite mistakes:
#
#   - integration / type=edge,branch=main   THIS branch adds them. Without the
#     first, a push here builds no image at all and nothing fails.
#   cosign sign --yes --recursive           MAIN has this. A branch predating it
#     carries a near-identical file, so taking its side wholesale reverts the
#     signing rewrite out of the build.
#
# The second needle exists because the first does not cover it: a wholesale take
# loses the trigger too, so the trigger check fires by accident, and the obvious
# repair — re-add `- integration` — goes green with signing silently gone.
# Assert main's contribution as well as this branch's; a guard that checks only
# what YOU added cannot see what someone else's side removed.
for NEEDLE in '- integration' 'type=edge,branch=main' 'cosign sign --yes --recursive'; do
  # -- before the pattern: "- integration" starts with a dash and grep would
  # otherwise parse it as an option, which fails loudly here but would be a
  # silent always-true in a less careful form.
  if ! grep -qF -- "$NEEDLE" .github/workflows/container-images.yml; then
    echo "container-images.yml has lost \"$NEEDLE\"." >&2
    echo "A merge resolution has taken some branch's copy of that file wholesale." >&2
    echo "Restore it before pushing: this file carries both this branch's build" >&2
    echo "trigger and main's signing rewrite, and losing either is silent." >&2
    exit 1
  fi
done

git push bootc integration --force-with-lease
cd -
git worktree remove ../openvox-ca-integration/

# vim: ai ts=2 sw=2 et sts=2 ft=sh
