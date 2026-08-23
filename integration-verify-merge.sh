#!/usr/bin/env bash
# Report lines that one side of a merge added or kept and the resolution then
# dropped. Run mid-merge, before committing, while the index still has stages.
#
# This exists because rerere replays a resolution whenever the CONFLICT TEXT
# matches, not whenever the resolution is still right. rr-cache lives in the
# shared .git and is written by every worktree on this repo, so a build inherits
# resolutions recorded against trees that have since moved. When one replays,
# git prints "Resolved 'F' using previous resolution", leaves no markers, and
# the merge looks clean — which is why "rerere resolved it" is evidence that a
# previous resolution existed for the same text, and nothing more.
#
# Two real losses from the 2026-08-16 build, both silent, both in prose that no
# suite covers:
#
#   - #213 added `RevokeSerial` to the Tier 1 `crl` row of
#     docs/development/locking.md. Its head carried the line; the merge of it
#     did not. The resolution took ours wholesale.
#   - #154 corrected "blob backends (filesystem/etcd/redis)" to
#     "(filesystem/redis)" — etcd gained a structured inventory. Merging #154
#     brought the fix in; merging #186 four steps later put the false statement
#     back, because #186 was cut before the correction and the replayed
#     resolution took theirs.
#
# Neither is a defect on any branch, and both survive a green build: the race
# suite, the mage suite and golangci-lint all passed over a tree documenting an
# etcd behaviour that had not been true for days.
#
# Usage: ./integration-verify-merge.sh [file...]     (default: every staged file
#                                                     with all three stages)
set -eu -o pipefail

cd "$(dirname "$0")/../openvox-ca-integration" 2>/dev/null || cd "$(dirname "$0")"

if ! git rev-parse -q --verify MERGE_HEAD >/dev/null; then
  echo "No merge in progress — stages are only available mid-merge." >&2
  echo "To inspect a merge already committed, re-run it: git merge --no-commit <branch>" >&2
  exit 1
fi

# Files with a full set of stages are the ones that conflicted, whether rerere
# resolved them or a human did.
if [ "$#" -gt 0 ]; then
  FILES="$*"
else
  FILES=$(git ls-files -u | awk '{print $4}' | sort -u)
fi

[ -n "$FILES" ] || { echo "No conflicted files in this merge."; exit 0; }

status=0
for f in $FILES; do
  git show ":1:$f" >/tmp/vm-base 2>/dev/null || : >/tmp/vm-base
  git show ":2:$f" >/tmp/vm-ours 2>/dev/null || : >/tmp/vm-ours
  git show ":3:$f" >/tmp/vm-theirs 2>/dev/null || : >/tmp/vm-theirs
  [ -f "$f" ] || continue

  # A line each side added relative to the base. Whitespace-only and marker
  # lines are noise; anything else that vanished is worth a human deciding on.
  ours_added=$(comm -13 <(sort -u /tmp/vm-base) <(sort -u /tmp/vm-ours) | grep -vE '^\s*$' || true)
  theirs_added=$(comm -13 <(sort -u /tmp/vm-base) <(sort -u /tmp/vm-theirs) | grep -vE '^\s*$' || true)

  lost_ours=$(comm -23 <(printf '%s\n' "$ours_added" | sort -u) <(sort -u "$f") | grep -vE '^\s*$' || true)
  lost_theirs=$(comm -23 <(printf '%s\n' "$theirs_added" | sort -u) <(sort -u "$f") | grep -vE '^\s*$' || true)

  if [ -n "$lost_ours$lost_theirs" ]; then
    status=1
    echo "── $f"
    [ -n "$lost_ours" ]   && printf '%s\n' "$lost_ours"   | sed 's/^/   dropped from OURS:   /'
    [ -n "$lost_theirs" ] && printf '%s\n' "$lost_theirs" | sed 's/^/   dropped from THEIRS: /'
    echo
  fi
done

rm -f /tmp/vm-base /tmp/vm-ours /tmp/vm-theirs

if [ "$status" -ne 0 ]; then
  cat >&2 <<'MSG'
Lines above were added by one side and are not in the resolution.

That is not automatically wrong — a resolution legitimately drops a line when
the other side rewrote the same sentence, which is most of what a real conflict
is. What it is NOT is invisible, which is the whole problem with a replayed
resolution: decide each one, rather than discovering it in a merged tree weeks
later.

To redo a file by hand:  git checkout --conflict=merge -- <file>
MSG
else
  echo "No one-sided additions were dropped."
fi
exit 0

# vim: ai ts=2 sw=2 et sts=2 ft=sh
