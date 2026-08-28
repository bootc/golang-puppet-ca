#!/usr/bin/env bash
set -eu -o pipefail

# Rebuild the throwaway `integration` branch: merge every open PR branch into a
# worktree, apply the fixes no single branch can carry, and force-push it.
#
# Companion scripts:
#   integration-trial.sh         which branches conflict, read-only, no worktree
#   integration-verify-merge.sh  what a resolution dropped; runs below, mid-merge
#
# The image built from this branch is consumed: a deployment pins
# ghcr.io/bootc/openvox-ca:integration-alpine by digest and re-pins from a named
# build. Report the digest after a push, not just that it happened.
#
# ---------------------------------------------------------------------------
# CARRIED FIXES — integration-fixes.patch, applied after the merge loop
#
#   capability_test.go  #189 x #212. The file lives ONLY on #189's branch, and
#                       its "SupportsAtomicInventory is false for every backend
#                       that appends to the inventory blob" table lists redis.
#                       #212 gives RedisBackend a decomposed inventory, so the
#                       capability — a type assertion for InventoryStore —
#                       becomes true and that entry fails. The fix moves the
#                       redis Entry to the "is true" table.
#
#                       Neither branch can make it. #189's own comment says so:
#                       "Redis stays here until #212 decomposes its inventory
#                       the way #154 did etcd's; that branch moves this entry to
#                       the table below." #212 cannot, because the file does not
#                       exist there. It retires when #212 merges and #189
#                       performs the move on its own branch.
#
# A carried fix is a spec correct on its own branch and wrong only once another
# is merged beside it, so it is never a defect in the branch whose file it
# edits.
#
# Rules this set has produced:
#
#   - A fix is scoped to a SET of merged branches, not to the file it edits.
#     When a branch leaves BRANCHES, every hunk depending on it leaves in the
#     same edit, or the build fails in a file whose own branch is blameless.
#   - Retiring is two steps separated by a rebuild: it leaves the patch
#     immediately, but stays in any build that already merged the old head.
#   - Check the owning branch before retiring OR re-adding. A fix carried past
#     its owner is a duplicate declaration, not a no-op — the last one added a
#     second `grantedLock` after #168 grew its own, and failed typecheck.
#   - "The patch stopped applying" usually means the owner absorbed the fix, not
#     that the fix needs rebuilding. Check that first.
#   - CHECK THE ENTRIES, NOT THE SHAPE. The capability_test.go fix was retired
#     on 2026-08-17 after confirming #189 carried "both tables" — which it did,
#     with redis still in the false one, because on #189 alone that is correct.
#     What matters is whether the entries are right for the SET OF BRANCHES THIS
#     BUILD MERGES, and a table can be present, well-formed and wrong. It cost a
#     failed pre-push to find, which is the cheap version; the expensive version
#     is a fix retired while its collision is still live.
#
# ---------------------------------------------------------------------------
# HAZARD
#
# Never run `git history` in this repo without --update-refs=head, and run
# `git branch --contains <commit>` first. It defaults to --update-refs=branches,
# which rewrites *every* local branch descending from the commit — and
# `integration` descends from every PR branch below while checked out in
# ../openvox-ca-integration. Every agent working this repo has a worktree on the
# one object store (`git worktree list`), so this is repo-wide.
#
# ---------------------------------------------------------------------------
# DISCHARGED: the auto-merge pairing check
#
# This file carried a standing check from 2026-08-16: before merging anything
# that widened ci.yml's `pull_request:` trigger, verify in the same tree that the
# `automerge` job carried its own base condition, because the job's scoping to
# main was inherited from the trigger and widening one without pinning the other
# would let a Renovate PR merge itself into a feature branch unreviewed.
#
# #218 merged on 2026-08-24 and BOTH halves landed together. Verified on main:
# the pull_request trigger is unfiltered (0 base filters) and the automerge job
# carries base.ref (1 occurrence). The split never happened, which is what the
# check was for.
#
# What replaces it is better than a note: `mage dev:check` now enforces it, via
# verifyAutomergeBasePinIn and verifyPullRequestUnfilteredIn on main. Read the
# expression as well as running the check — the guard proves the base ref is
# CONSULTED, not that the condition is correct, so `A && (B && C || D)` contains
# the pin, passes, and still lets one bot through.
#
# ---------------------------------------------------------------------------
# THE TWO AUTO-MERGE GUARDS — now #218 versus main, not branch versus branch
#
# #239 merged (91d4e9a6cdea), so everything else this block held is discharged:
# the hold instruction, the three pre-computed resolutions, the force-push
# history, the Rekor note. The build ran it, signing verified end to end, and
# the branch is gone. This paragraph is what did NOT expire — it changed sides.
#
# Verified on main at d74253a04e4a: verifyAutomergeLabelExclusion and
# automergeRequiredClauses are there, as a SEPARATE list from the base pin, and
# magefile.go carries a note addressed to whoever rebases #218 onto it. #218 is
# still open (c19d4cd5c62e) and still has automergeBasePin of its own.
#
# So KEEP TWO GUARDS still binds, and now binds #218's rebase rather than this
# build's merge. Do not carry #218's shape toward main's or vice versa on the
# grounds that one looks stricter. They encode different contracts:
#
#   - Folding the base pin into automergeRequiredClauses as a fourth EXACT
#     string rejects `== 'main'`, a legitimate spelling #218 ruled in.
#   - Reducing the label clause to fragments reopens a decoy hole: a
#     neighbouring `!contains(...title, 'WIP')` supplies every fragment while
#     the real clause is inverted.
#   - An anti-pin is a FORBIDDEN substring and has no home in a list of required
#     ones. A list has one polarity; these need two.
#
# The class both guards converged on, which is why the fold keeps looking
# tempting: each was defeated by INVERSION, and each was found by the other's
# author within an hour. What holds is to require the upright comparison and
# SEPARATELY refuse the inverse — a decoy can supply an upright form, it cannot
# remove an inverted one.
#
# Nothing here is this build's to resolve any more. It is recorded because this
# build is where the two met first, and whoever rebases #218 inherits the
# question with only main's side of the story in front of them.
#
# ---------------------------------------------------------------------------
# MERGE OBLIGATIONS THAT NO CONFLICT WILL ANNOUNCE
#
# Two pairs among the lock branches owe an edit to whichever of them merges
# SECOND. Neither is a textual conflict, so git will merge both sides cleanly and
# say nothing. Recorded from the owning sessions' analysis and worth checking by
# hand after those merges:
#
#   #259 x #261  the second to land adds `"hmac-key": 4` to reservedLockOrdinals.
#                This one DOES fail: SQLReservedLockKeys asserts an exact Equal,
#                so a missing entry turns the suite red and names itself.
#
#   #261 x #264  the second to land adds `bootstrap` -> `hmac-key` to
#                allowedLockNesting. This one does NOT fail on current fixtures.
#                Nothing goes red, and the result is a silent divergence between
#                the documented lock graph and the code — a green build would
#                certify it.
#
# The second is the one that matters, and it is the shape this build is worst at
# seeing: integration-verify-merge.sh compares TEXT and this is a semantic
# omission, so nothing here catches it. After merging any two of #259, #261 and
# #264, read allowedLockNesting against the lock graph rather than trusting a
# green suite.
#
# #259 x #261 OWE A SECOND CHECK, in docs/development/locking.md, and this one
# has a positive test rather than an absence. Each branch retires a different
# known gap and the two retirements INTERLEAVE across the conflict boundary:
#
#     #259 (fix/sql-lock-key-aliasing)  retires #203 -> `~~[#203]`
#     #261 (fix/hmac-key-init-race)     retires #202 -> `~~[#202]`
#     main has NEITHER marker.
#
# Taking either side of that hunk whole reverts the other's retirement to an open
# gap. Verified here on 2026-08-28 by counting the markers per ref, after the
# coordinator raised it; three sessions derived it independently.
#
# The check is BOTH MARKERS PRESENT, not zero conflict markers — either wrong
# resolution satisfies the second. After merging #259 and #261:
#
#     grep -cF -- '~~[#202]' docs/development/locking.md   # want 1
#     grep -cF -- '~~[#203]' docs/development/locking.md   # want 1
#
# Note -F: both needles contain [ ] and would otherwise be a character class
# matching neither. This is the general shape worth stealing — an obligation
# stated as "this string must be present" is checkable in one command, where
# "resolve it correctly" is not.
#
# Two more found in the 2026-08-24 build, both prose, both silent, and both
# pointing the same way: a branch that predates another carries the OLD claim
# unchanged, in a region the newer branch never touches, so there is no conflict.
#
#   #264 x #189  DISCHARGED 2026-08-28 at #264 head 99018ae05246, verified
#                here, not taken on report. Was: locking.md called `Generate`
#                unlocked and hard-coded 20 + 2 = 22 WithLock sites, where #189
#                makes it locked (internal/ca/generate.go:229) and 23.
#                #264's owner took the whole thing rather than leaving it to
#                merge order: the sentence is gone, the counts are replaced by
#                the counting RULE, and the `#195` back-pointer is dropped.
#                The four surviving `#195` mentions are byte-identical on main
#                in files #264 never touches, and #189 retires all four itself
#                (api.md, locking.md x2, signing.go: main=4, #189=0). So it is
#                clean in BOTH merge orders, which a one-sided fix would not be.
#
#                Keep the shape, not the item. It found a fourth consequence
#                neither session had: post-#189 the observer's BeforeEach calls
#                Generate, which then supplies `subject:<name>` -> `crl` — the
#                very edge the table asserts — so a membership check is answered
#                by setup and four specs stayed green with Clean's entire
#                CRL-locked revoke deleted. Fixed by counting edges before and
#                after rather than testing membership. A doc claim going stale
#                and a spec quietly losing its power are the SAME merge, and
#                only the first announces itself.
#
#   #267 x main  docs/metrics.md says `openvox-ca-ctl revoke --serial` "is the
#                only way to retire a superseded certificate". #267's sweep is a
#                second way. The adjacent "not counted on that arm at all" is now
#                true only where superseded_cert_revoke_after_sec is 0.
#
# Reported to the coordinator; the edits belong on the PRs, not carried here —
# nothing about them breaks a build, which is exactly why they need writing down.
#
# THE GENERAL FORM, worth applying to every doc conflict in this repo: when one
# side of a hunk is a branch's own new prose and the other is the same paragraph
# from an older base, taking either side whole is wrong. #267 alone carried FOUR
# such paragraphs — api.md's Generate sentence (pre-#189), locking.md's lock-name
# table (pre-#212 redis, pre-#189 capability-probe, no hmac-key or
# sql-schema-migrate), metrics.md's mixin alert list (pre-#168 chain, pre-#221
# OCSP), and background_jobs_test.go's ConsistOf assertions. Union the content,
# then re-check every claim against the merged CODE.
#
# ---------------------------------------------------------------------------
# TWO THINGS A BUILD MUST NOT BE READ AS EVIDENCE FOR
#
# #263 makes the demos WARN on every start. It adds two WARN lines when
# `tls_cert` resolves to a certificate that cannot serve TLS, and compose.yml and
# docs/container-images.md still point at ca_crt.pem deliberately, for
# one-command startability. So the warnings are expected output, not a
# regression. Its author verified nothing in test/ or .github/workflows/ asserts
# on log content.
#
# #266 carries a constraint this build cannot discharge: do NOT push a `v*` tag
# until #250 lands. release.yml, container-images.yml and helm-chart.yml each
# trigger on `v*` independently with no `needs:` between them, so a premature tag
# publishes images — including the mutable `latest` — and the chart, regardless
# of release.yml failing. This build pushes a BRANCH and never a tag, so a green
# integration run says nothing either way about the tagging path. Do not let its
# success be read as clearance.
#
# ---------------------------------------------------------------------------
# WHEN A BRANCH FAILS: HOLD THE BUILD, DO NOT DROP THE BRANCH
#
# Once a PR is in BRANCHES it stays in. If it will not merge, or merges and goes
# red, the build waits for a fix — it does not ship without it. A build that
# quietly omits a branch is worse than no build: it looks like a full
# integration, so a green result is read as evidence about a set that was never
# assembled, and the branch that was dropped is the one nobody then tests.
#
# On 2026-08-22 #223 was dropped so the rest could ship. Chris ruled against it:
# hold the build instead. The pushed ec487382cf99 predates that ruling and does
# not contain #223.
#
# So on a failure: stop, report which branch and why, and leave BRANCHES alone.
# Removing an entry is a scope decision and belongs to Chris, not to whatever
# went wrong that day.
#
# ---------------------------------------------------------------------------
# RESOLVING CONFLICTS
#
# `git merge` succeeding is not evidence a resolution is right. rerere replays
# on matching conflict TEXT, and its cache is shared by every worktree here, so
# a build inherits resolutions recorded against trees that have since moved.
# integration-verify-merge.sh runs below and reports lines one side added that
# the resolution dropped; advisory, because dropping a line is often correct.
# The 2026-08-16 build lost two lines this way and passed every suite, both in
# prose no test covers.
#
# docs/development/locking.md is the surface to watch: sole conflict for most
# rebases here, and every merge into main tips two or three open branches onto
# it in a set nobody predicts. Its lock-ordering list is an enumeration of the
# world, so a take-one resolution leaves a file that reads correctly while
# documenting an order missing a path. Read both sides, and check whether a line
# only main has is being dropped.
#
# BUT THE SURFACE IS THE PARAGRAPH, NOT THE FILE. On 2026-08-23 #223's rebase
# collided twice in docs/metrics.md, one directory over from where this note
# points: it had added a same-host clause to the uncounted-revocations
# paragraph, and the branch had rewritten that same paragraph twice to separate
# the subject lock from the CRL lock. Either side taken whole drops the other.
# Naming a file trains the eye on the wrong unit — what recurs is a PARAGRAPH
# several branches are each amending for their own correct reason, and the same
# few paragraphs recur across locking.md, metrics.md, configuration.md and
# operator-cli.md because they describe the same locking behaviour from
# different angles. Ask which paragraph a branch touches, not which file.
#
# A sharper silent-revert check than diffing the whole branch, for a rebase:
# of the lines MAIN GAINED in the commits being rebased over, which does this
# branch remove?
#
#   comm -12 <(git diff <old-base>..origin/main -- "$f" | grep '^+[^+]' | sed 's/^+//' | sort -u) \
#            <(git diff origin/main            -- "$f" | grep '^-[^-]' | sed 's/^-//' | sort -u)
#
# Comparing the whole branch against main lists every line it legitimately
# rewrites — 29 in one file, all noise. This form cut the same case to five, all
# genuine. integration-verify-merge.sh answers the merge-time version of that
# question from the index stages; this is the rebase-time one.
#
# A CONFLICT BLOCK DOES NOT HAVE TO START OR END ON A COMPLETE CONSTRUCT, and a
# marker-strip union is only valid when it does. Three times in the 2026-08-24
# build the two sides ended MID-construct, with the closing token sitting in the
# shared context AFTER the end marker, where it closes one side only:
#
#   internal/metrics/collector.go  both sides ended mid struct-literal field; the
#       shared `nil, nil),` closed theirs, leaving ours' last field unterminated.
#       A second block had ours opening `for ... {` and theirs `if ... {` around a
#       SHARED closing `}` — the union nested theirs inside ours' loop.
#
#   mixin/tests.yaml  twice, on #267 and again on #166, identically. Two conflict
#       blocks separated by five lines that look like shared context and are in
#       fact the common PREFIX of each side's final alert expectation
#       (exp_alerts: / - exp_labels: / severity / job / instance). git aligns them
#       because both sides' last alert opens the same way.
#
# The tell is cheap: print the FIRST and LAST line of each side and the first
# lines after the end marker. If either side's last line is not a complete
# statement, block or list item, the shared tail belongs to one side and the
# other needs its own copy. Reconstruct each side WHOLE — ours1 + shared + ours2
# + tail, and the same for theirs — and only then union at the level the file is
# actually made of: whole test groups by name, whole struct fields, whole
# sections. Two markers in one file are not necessarily two independent
# conflicts.
#
# gofmt/`go build` catch the Go version of this instantly; nothing catches the
# YAML one except parsing the result and counting the groups. `mage test:mixin`
# does run `promtool test rules` against tests.yaml, so it is a real check —
# but a malformed union can still parse. Assert the group count and that no two
# groups share a name.

# ---------------------------------------------------------------------------
# WHAT BELONGS IN BRANCHES: FEATURE AND FIX PRs, NOT DEPENDENCY BUMPS
#
# Renovate PRs stay OUT. Chris ruled on #271, #272 and #273 on 2026-08-28, and
# the ruling is about KIND rather than those three, so it stands after they
# merge and applies to whatever Renovate opens next.
#
# The reason, because the outcome alone does not survive re-derivation: this
# build exists to rehearse how the FEATURE branches interact — where they
# collide, what they break in each other, which obligations nobody's diff
# raises. A dependency bump is independent of that by construction. It merges on
# its own, and putting it here spends the build's conflict budget on work that
# does not collide.
#
# EXPECT THIS TO LOOK LIKE DRIFT, AND DO NOT "FIX" IT. Comparing BRANCHES against
# `gh pr list` will always show some non-draft PRs absent, and the number grows
# on its own between builds. On 2026-08-28 a coordinator read that gap as ten
# absent PRs and reported the build was missing a third of the open work; it was
# three, all Renovate. Two different numbers, two different meanings — "the
# build is missing a third of the work, so its green result means much less than
# it appears" versus "the list is current on everything substantive". Only the
# second was true.
#
# So the check is not "does BRANCHES match the open PR list". It is: subtract
# the two sets and look at the KIND of what is left. Anything that is not a
# dependency bump is a real omission and probably a held branch (see the
# hold-the-build rule above); a Renovate branch is this rule working.
#
#   eval "$(sed -n '/^BRANCHES=(/,/^)/p' integration.sh)"
#   comm -23 <(gh pr list --state open --json isDraft,headRefName \
#                --jq '.[] | select(.isDraft|not) | .headRefName' | sort) \
#            <(printf '%s\n' "${BRANCHES[@]}" | sed 's|^origin/||' | sort)
#
# eval rather than a hand-copied list: the two cannot disagree that way. And
# note local/integration-setup will show on the other side of the comm — it is
# this branch, and it has no PR by design.

BRANCHES=(
  # Always keep
  local/integration-setup

  # Open non-draft PRs. origin/ refs so each build integrates what is on the PR
  # rather than a stale local copy. Two are stacked and must follow their base;
  # everything else is order-independent, so the order below is chosen rather
  # than forced — see the notes after the list.
  origin/feature/redis-inventory          # PR #212
  origin/feature/crl-chain-distribution   # PR #168
  origin/feature/offline-generate         # PR #189
  origin/fix/ocsp-index-sync              # PR #221
  origin/fix/ocsp-signing-lock-scope      # PR #265 — STACKED on #221, must follow it
  origin/fix/codeql-log-injection         # PR #224

  # The lock-ordinal trio, kept adjacent deliberately — see the merge
  # obligations below, which no conflict will announce.
  origin/fix/sql-lock-key-aliasing        # PR #259
  origin/fix/hmac-key-init-race           # PR #261
  origin/fix/lock-ordering-race           # PR #264

  origin/fix/migration-diagnostics        # PR #260
  origin/fix/k8sexport-per-target-isolation  # PR #262
  origin/fix/tls-cert-example             # PR #263
  origin/feature/release-packaging        # PR #266

  # Late on purpose: the busiest branch open, touching signing.go, storage.go,
  # revoke.go, config.go and ca.go. Merging it into the fullest tree surfaces
  # all of its collisions at once rather than a few at a time, and its 14-file
  # conflict set is the largest here by a wide margin. Its own author flagged it.
  origin/feature/delayed-supersession     # PR #267

  # Descendant of #168, so it stays after it. Last because it is stacked, not
  # because it is least important.
  origin/feature/client-trust-domains     # PR #166 — STACKED on #168

  # Drafts, still CONFLICTING, still carrying cherry-picked copies of commits
  # already in main. They want a rebase before coming off the bench.
  # feature/tls-self-provision              # PR #165
  # feature/tls-self-provision-integration  # PR #167
)


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

# Carried fixes, as a patch rather than a branch: some of the files they edit do
# not exist on main, so a branch would have to *add* them and would collide with
# whichever PR owns each one. The patch rides in on local/integration-setup — a
# path no PR touches — and is applied last, once every file it edits is merged.
#
# PATCH_PATHS is the declaration of what is carried, and drives everything:
#
#   non-empty  a patch is REQUIRED, and may touch only these paths. Missing is
#              an abort, because it runs in the WORKTREE and so must be
#              committed on local/integration-setup to be here at all — an
#              untracked copy in the main checkout does not arrive, and `[ -f ]`
#              alone made that indistinguishable from success. The path
#              allowlist exists because regeneration is a `git diff`, which
#              cannot tell the fixes from a half-resolved conflict or a stray
#              edit made in the conflict shell above, and the patch is applied
#              and committed unattended in every later build.
#   empty      no fixes are carried, deliberately. A patch present anyway is an
#              abort, since nothing declares what it may contain.
#
# Empty today. The last entry, the crlchain_test.go fixture, was absorbed by
# #168 on 2026-08-17 — which the guard below caught: the patch stopped applying
# because the fix it supplies was already there. That is the mechanism working,
# not a failure.
PATCH_PATHS="internal/storage/capability_test.go"

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

# container-images.yml must keep BOTH contributions: this branch's trigger, and
# main's signing rewrite. The two are lost by opposite mistakes, and the second
# is the bigger one.
#
#   - integration / type=edge,branch=main   THIS branch adds them. Without the
#     first, main triggers on main and v* tags only, so a push here builds no
#     image at all — the branch stops producing anything and nothing fails.
#
#   cosign sign --yes --recursive           MAIN has this, from #239. Four of the
#     open branches still carry a pre-#239 copy of the file, differing from main
#     by ~239 lines with ONE signing-related line against main's 49. Taking any
#     of their sides wholesale reverts the entire signing rewrite out of the
#     build.
#
# The second needle exists because the first does not cover it. A wholesale take
# of a stale branch's file loses the trigger too, so the trigger check fires —
# but by accident, and the obvious human repair defeats it: take the stale file,
# notice no image is produced, re-add `- integration`, and the build goes green
# with signing silently gone. Signing runs in the merge job, so its absence
# looks like a job that had nothing to do rather than like a failure.
#
# So assert main's contribution as well as this branch's. A guard that only
# checks what YOU added cannot see what someone else's side removed.
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
