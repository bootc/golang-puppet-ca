#!/usr/bin/env bash
# Replay integration.sh's merge order through the object store and report which
# branches conflict, without creating a worktree, checking anything out, or
# touching the index. Safe to run at any time, including during a build.
#
# READ THE OUTPUT AS AN UPPER BOUND AFTER THE FIRST CONFLICT. `merge-tree` writes
# its tree with conflict markers left in, so each later step merges against a
# file the real build would have resolved first. Clean rows are trustworthy;
# conflicted rows may over-report both files and branches.
#
# Usage: ./integration-trial.sh [base]        (base defaults to origin/main)
set -eu -o pipefail

cd "$(dirname "$0")"
BASE=${1:-origin/main}

# Reuse integration.sh's own list so the two can never disagree.
#
# eval, not `source <(sed ...)`: under the bash 3.2 at /bin/bash, sourcing a
# process substitution this size silently sets nothing and leaves BRANCHES
# unbound. Command substitution behaves the same under both shells.
eval "$(sed -n '/^BRANCHES=(/,/^)/p' integration.sh)"

printf 'Replaying %d branches onto %s\n\n' "${#BRANCHES[@]}" "$BASE"

cur=$(git rev-parse "$BASE")
conflicted=0

for b in "${BRANCHES[@]}"; do
  if ! rev=$(git rev-parse --verify --quiet "$b"); then
    printf '  %-40s MISSING REF\n' "${b#origin/}"
    exit 1
  fi

  # merge-tree exits non-zero on conflict but still prints the tree on line 1.
  set +e
  out=$(git merge-tree --write-tree "$cur" "$rev" 2>&1)
  rc=$?
  set -e
  tree=$(printf '%s\n' "$out" | head -1)

  if [ "$rc" -eq 0 ]; then
    printf '  %-40s clean\n' "${b#origin/}"
  else
    conflicted=$((conflicted + 1))
    printf '  %-40s CONFLICT\n' "${b#origin/}"
    # Stage lines are "<mode> <oid> <stage>\t<path>"; collapse the three stages.
    printf '%s\n' "$out" | grep -oE '[0-9]+ [0-9a-f]{40} [123]'$'\t''.*' \
      | cut -f2- | sort -u | sed 's/^/        /'
  fi

  cur=$(git commit-tree "$tree" -p "$cur" -p "$rev" -m "trial: ${b#origin/}")
done

printf '\n%d of %d branches conflicted. Trial tree: %s\n' \
  "$conflicted" "${#BRANCHES[@]}" "$cur"
printf 'Nothing was written outside the object store; no ref points at that tree.\n'

# vim: ai ts=2 sw=2 et sts=2 ft=sh
