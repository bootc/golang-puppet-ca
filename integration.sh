#!/usr/bin/env bash
set -eu -o pipefail

# Rebuild the throwaway `integration` branch: merge every open PR branch into a
# worktree, apply the fixes no single branch can carry, and force-push it.
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
# CARRIED FIXES — integration-fixes.patch, applied after the merge loop
#
# NONE. PATCH_PATHS is empty and there must be no patch file; the guard below
# aborts if one appears, since nothing then declares what it may contain.
#
# The last was capability_test.go, retired 2026-08-31 when #212 absorbed it at
# 46bd9a4cdfd1: redis now sits inside `DescribeTable("is true for every backend
# with a structured inventory")` and the "Redis stays here until #212" comment
# is gone. Verified by which table the Entry falls in, and by the patch ceasing
# to apply.
#
# A carried fix is a spec correct on its own branch and wrong only once another
# is merged beside it. Rules this one set produced, all still load-bearing:
#
#   - Scoped to a SET of merged branches, not to the file it edits.
#   - Check the owning branch before retiring OR re-adding: a fix carried past
#     its owner is a duplicate declaration, not a no-op.
#   - "The patch stopped applying" usually means the owner absorbed it. That is
#     how this one ended.
#   - CHECK THE ENTRIES, NOT THE SHAPE. This fix was once retired wrongly after
#     confirming #189 carried "both tables" — it did, with redis still in the
#     wrong one, which is correct on #189 alone. A table can be present,
#     well-formed, and wrong for the set this build merges.
#   - A BRANCH THAT LEAVES BY MERGING DOES NOT TAKE ITS FIXES WITH IT. The
#     scoping rule above is about a branch leaving the SET; a merge moves its
#     content into the base instead, so the collision survives. #189 merged on
#     2026-08-31 without moving redis — correct, because #212 was still
#     unlanded — and reading the scoping rule as covering that would have
#     retired this fix for the second wrong time. What retires a fix is the
#     owner absorbing it, which is a fact about a file, not about a list.
#   - Grep for the entry with CONTEXT, not a closed paren: the real line is
#     `Entry("redis", func() Backend {...},` so `Entry("redis")` matches nothing
#     in a file that plainly contains it, and returns a confident zero.
#
# ---------------------------------------------------------------------------
# HAZARD
#
# Never run `git history` here without --update-refs=head, and run
# `git branch --contains <commit>` first. It defaults to --update-refs=branches,
# which rewrites every local branch descending from the commit — and
# `integration` descends from every PR branch below. Several worktrees share the
# one object store (`git worktree list`), so this is repo-wide.
#
# ---------------------------------------------------------------------------
# MERGE OBLIGATIONS THAT NO CONFLICT WILL ANNOUNCE
#
# None outstanding. The lock trio is fully merged — #259 and #264 on 2026-08-30,
# #261 on 2026-08-31 — and main was checked afterwards: `~~[#202]` and
# `~~[#203]` are both present in docs/development/locking.md, and
# reservedLockOrdinals carries exactly one `"hmac-key"` entry. Nothing here is
# waiting on a second branch to land.
#
# Keep the SHAPE, because it will recur. Both were invisible to git: a pair of
# branches each correct alone and wrong merged, with no textual conflict to
# announce it. The retirement one was checkable as "both markers PRESENT", which
# is the form to reach for — "zero conflict markers" is satisfied by either
# wrong resolution, and `grep -F` matters when a needle contains `[ ]`, since an
# unescaped grep reads it as a character class matching nothing.
#
# DO NOT RE-ADD `bootstrap` -> `hmac-key` to allowedLockNesting. It was carried
# as a live obligation for days and is not one: that pair is taken only by
# MigrateService in internal/storage, CA.Init calls InitHMAC outside the
# bootstrap lock deliberately, allowedLockNesting is package ca so no observer
# there can see it, and #264's rule 12 excludes it explicitly. Adding it makes
# the table claim coverage it does not have.
#
# The general form, three of these having now been wrong: a silent obligation is
# a claim about the CODE, so verify it against the code before honouring it.
# "Nothing goes red" fits an omission that matters and a rule that does not
# apply here equally well.
#
# ---------------------------------------------------------------------------
# WHAT A GREEN BUILD IS NOT EVIDENCE FOR
#
# #266: do NOT push a `v*` tag until issue #250 is closed — #282 is the PR for
# it and is in BRANCHES below, so watch that rather than the issue. release.yml,
# container-images.yml and helm-chart.yml each trigger on `v*` independently
# with no `needs:` between them, so a premature tag publishes images — including
# the mutable `latest` — and the chart, regardless of release.yml failing. This
# build pushes a BRANCH and never a tag, so its success says nothing either way
# about the tagging path.
#
# ---------------------------------------------------------------------------
# WHEN A BRANCH FAILS: HOLD THE BUILD, DO NOT DROP THE BRANCH
#
# Once a PR is in BRANCHES it stays in. A build that quietly omits a branch is
# worse than no build: it looks like a full integration, so a green result is
# read as evidence about a set that was never assembled, and the dropped branch
# is the one nobody then tests. Chris ruled on this after #223 was dropped so
# the rest could ship. On a failure: stop, report which branch and why, and
# leave BRANCHES alone — removing an entry is a scope decision and his call.
#
# ---------------------------------------------------------------------------
# RESOLVING CONFLICTS
#
# rerere is not verification. It replays on matching conflict TEXT from a cache
# shared by every worktree here, so a build inherits resolutions recorded
# against trees that have since moved. It has silently dropped a section-header
# comment and reverted two prose lines no test covers.
# integration-verify-merge.sh reports what a resolution dropped: advisory, and
# it false-positives on re-wrapped prose, where the content survives and only
# the line breaks moved.
#
# THE SURFACE IS THE PARAGRAPH, NOT THE FILE. The same few paragraphs recur
# across locking.md, metrics.md, configuration.md, operator-cli.md and
# mixin/README.md because they describe one behaviour from different angles, and
# several branches each amend one for their own correct reason.
#
# A BRANCH THAT PREDATES ANOTHER CARRIES THE OLD CLAIM UNCHANGED, in a region
# the newer one never touches, so nothing conflicts. Where one side of a hunk is
# a branch's own new prose and the other is the same paragraph from an older
# base, neither is takeable whole: union, then re-check every claim against the
# merged CODE.
#
# A CONFLICT BLOCK NEED NOT START OR END ON A COMPLETE CONSTRUCT, and a
# marker-strip union is only valid when it does. Both sides can end mid-construct
# with the closing token in the shared context AFTER the end marker, where it
# closes one side only — seen in Go struct literals, in an `if`/`for` pair
# sharing one `}`, and repeatedly in mixin/tests.yaml, where the lines between
# two blocks are the common PREFIX of each side's last alert rather than shared
# context. The tell: print the first and last line of each side and what follows
# the end marker. If a last line is not a complete construct, reconstruct each
# side WHOLE — ours1 + shared + ours2 + tail, likewise theirs — then union at the
# level the file is made of: whole test groups by name, whole struct fields,
# whole sections. Two markers in one file are not necessarily two independent
# conflicts.
#
# gofmt and `go build` catch the Go version instantly; nothing catches the YAML
# one. `mage test:mixin` does run `promtool test rules`, but a malformed union
# can still parse — assert the group count and that no two groups share a name.

# ---------------------------------------------------------------------------
# WHAT BELONGS IN BRANCHES: FEATURE AND FIX PRs, NOT DEPENDENCY BUMPS
#
# Renovate PRs stay OUT — Chris ruled on 2026-08-28, and the ruling is about
# KIND, so it survives those particular PRs merging. This build rehearses how
# the FEATURE branches interact; a dependency bump is independent of that by
# construction, merges on its own, and would spend the conflict budget on work
# that does not collide.
#
# So a gap between BRANCHES and `gh pr list` is EXPECTED, not drift. The check
# is not "do the sets match" but "what KIND is left over": anything that is not
# a dependency bump is a real omission, probably a held branch. A coordinator
# once read that gap as ten absent PRs and reported the build was missing a
# third of the open work; it was three, all Renovate.
#
#   eval "$(sed -n '/^BRANCHES=(/,/^)/p' integration.sh)"
#   comm -23 <(gh pr list --state open --json isDraft,headRefName \
#                --jq '.[] | select(.isDraft|not) | .headRefName' | sort) \
#            <(printf '%s\n' "${BRANCHES[@]}" | sed 's|^origin/||' | sort)
#
# eval rather than a hand-copied list, so the two cannot disagree.
# local/integration-setup shows on the other side of the comm, by design.

BRANCHES=(
  # Always keep
  local/integration-setup

  # Open non-draft PRs. origin/ refs so each build integrates what is on the PR
  # rather than a stale local copy, and so a head moving needs no edit here.
  origin/feat/one-instance-unless-distributed-locking  # PR #284
  origin/issue-258-chart-docs             # PR #296 — issue #258

  # Collide on cmd/openvox-ca/config.go, so they sit together.
  origin/fix/ocsp-signing-concurrency-bound  # PR #285
  origin/fix/293-allow-subject-alt-names  # PR #294 — issue #293

  # The packaging pair, collides on magefile.go. Last because #266 is the
  # furthest behind main by a wide margin and #282 is still moving; #266 is
  # approved and held behind #282, so they land together anyway.
  origin/feature/release-packaging        # PR #266
  origin/feature/package-payload          # PR #282
)

# LEFT THE LIST, all merged, so their code arrives via origin/main now:
# 2026-08-30  #221 #259 #262 #263 #264
# 2026-08-31  #224 #260 #261 #267 #189, then #166 #168 #212 #265
# 2026-09-02  #283 #288 #289
#
# #165 and #167 are CLOSED and not returning.
#
# MEMBERSHIP is the only thing that needs editing here. Heads move constantly
# and cost nothing, because the entries are refs rather than shas — so "wait
# until PR X settles before refreshing" is answering the wrong question: X
# settling changes no membership. Refresh when the SET changes, which is what
# leaves a build merging branches already in main, or silently omitting open
# ones. The second is the dangerous half: see the hold-the-build rule above.


# Branches excluded for a REASON, as opposed to merely not listed. Commenting a
# branch out of BRANCHES stops its merge and does nothing about its code: a
# held-out branch that merges into one we do integrate arrives anyway, silently,
# with the note above it still reading as honoured.
#
# The machinery stays even when empty: the rule outlives any one branch, and
# both loops below are silent on an empty set.
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
# not exist on main, so a branch would have to *add* them and would collide with
# whichever PR owns each. The patch arrives on local/integration-setup — a path
# no PR touches — and is applied last, once every file it edits is merged.
#
# PATCH_PATHS declares what is carried, and drives everything:
#
#   non-empty  a patch is REQUIRED and may touch only these paths. Missing is an
#              abort: this runs in the WORKTREE, so the patch must be committed
#              on local/integration-setup to be here at all — an untracked copy
#              in the main checkout does not arrive, and `[ -f ]` alone made
#              that indistinguishable from success. The allowlist exists because
#              regeneration is a `git diff`, which cannot tell the fixes from a
#              half-resolved conflict or a stray edit made in the conflict shell.
#   empty      no fixes carried, deliberately. A patch present anyway is an
#              abort, since nothing declares what it may contain.
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

# container-images.yml must keep BOTH contributions, and they are lost by
# opposite mistakes:
#
#   - integration / type=edge,branch=main   THIS branch adds them. Without the
#     first, main triggers on main and v* only, so a push here builds no image
#     at all and nothing fails.
#
#   cosign sign --yes --recursive           MAIN has this, from #239. Branches
#     predating it carry a file differing from main by ~239 lines with ONE
#     signing-related line against main's 49, so taking their side wholesale
#     reverts the entire signing rewrite out of the build.
#
# The second needle exists because the first does not cover it. A wholesale take
# loses the trigger too, so the trigger check fires — but by accident, and the
# obvious repair defeats it: take the stale file, notice no image is produced,
# re-add `- integration`, and the build goes green with signing silently gone.
# Signing runs in the merge job, so its absence looks like a job that had nothing
# to do rather than a failure. So assert main's contribution as well as this
# branch's: a guard that checks only what YOU added cannot see what someone
# else's side removed.
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
