#!/usr/bin/env bash
# Replay integration.sh's merge order through the object store and report which
# branches conflict, without creating a worktree, checking anything out, or
# touching the index. Safe to run at any time, including while a build is in
# progress in ../openvox-ca-integration.
#
# This exists because the conflict table in integration.sh decays as fast as the
# branches do. Two of its entries were stale when this was first run: #157 was
# listed as carrying the #184 collision that main had since absorbed, and #168
# was listed as clean when it collides on README.md. Re-run this rather than
# trusting a table anyone wrote by hand.
#
# READ THE OUTPUT AS AN UPPER BOUND AFTER THE FIRST CONFLICT. `merge-tree`
# writes its tree with conflict markers left in, so each later step merges
# against a file the real build would have resolved first. Clean rows are
# trustworthy; conflicted rows may over-report both files and branches.
#
# Usage: ./integration-trial.sh [base]        (base defaults to origin/main)
set -eu -o pipefail

cd "$(dirname "$0")"
BASE=${1:-origin/main}

# Reuse integration.sh's own list so the two can never disagree about the order.
#
# eval, not `source <(sed ...)`. The env shebang above should find bash 5, but
# this stays portable to the bash 3.2 at /bin/bash, where sourcing a process
# substitution of this size silently sets nothing and leaves BRANCHES unbound —
# a failure that appears only when someone runs `/bin/bash integration-trial.sh`
# rather than executing it. Command substitution reads the whole block before
# the shell parses it and behaves the same under both.
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
