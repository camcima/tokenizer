#!/bin/sh
# Code comments explain behaviour and reasons; they never point at the spec, the plan or the
# design documents (CLAUDE.md). This fails if a Go file contains SPEC-DECISION, a section sign
# or "design doc". Used by the pre-commit hook (lefthook.yml, on the staged content) and by
# `make comment-check` (on every tracked Go file outside vendor/), so CI enforces it too.
#
# Usage: scripts/check-comments.sh [--staged] file...
#   --staged  check each file's staged content (the index), not the working copy
set -u

staged=0
if [ "${1:-}" = "--staged" ]; then
  staged=1
  shift
fi

bad=""
for f in "$@"; do
  case "$f" in vendor/*) continue ;; esac
  if [ "$staged" -eq 1 ]; then
    content=$(git show ":$f") || { echo "comment-rule: cannot read staged $f"; exit 1; }
  else
    content=$(cat "$f") || { echo "comment-rule: cannot read $f"; exit 1; }
  fi
  if printf '%s\n' "$content" | grep -qE 'SPEC-DECISION|§|design doc'; then
    bad="$bad $f"
  fi
done

if [ -n "$bad" ]; then
  echo "comment-rule: Go files reference the spec or design documents (SPEC-DECISION, §, design doc):$bad"
  exit 1
fi
exit 0
