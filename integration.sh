#!/bin/bash
set -eu -o pipefail

BRANCHES=(
  # Always keep
  local/integration-setup

  # List of PR branches to integrate (Renovate PRs are deliberately excluded)
  origin/fix/etcd-jitter-nosemgrep  # PR #149
  origin/fix/signer-psk-pipe        # PR #150
  origin/feature/compose-reorg      # PR #145

  # Stack: #154 sits on top of #151
  origin/feature/cert-index         # PR #151
  origin/feature/etcd-inventory     # PR #154

  # Stack: #143 was cut from #142, but the two have since diverged
  origin/feature/version-stamping   # PR #142
  origin/docs/ctl-tls-flags         # PR #143
)

git fetch origin
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
    # rerere resolved everything (or you resolved it in the shell above) —
    # commit only if the merge wasn't already finished for us
    if [ -f .git/MERGE_HEAD ]; then
      git commit --no-edit
    fi
  fi
done

git push bootc integration --force-with-lease
cd -
git worktree remove ../openvox-ca-integration/

# vim: ai ts=2 sw=2 et sts=2 ft=sh
