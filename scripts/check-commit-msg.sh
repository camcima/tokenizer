#!/bin/sh
# Checks one commit message against the project's conventional-commit rule. Used by the
# commit-msg hook (lefthook.yml, with the message file git hands it), by `make commit-check`
# (with each commit's message) and by CI on a pull request's title (the squash merge's commit
# message), so a hook skipped locally still fails CI.
#
# Usage: scripts/check-commit-msg.sh <message-file>
#        scripts/check-commit-msg.sh --message <message>
# A single argument naming an existing file is read as the message; any other single argument is
# the message itself. --message always takes the next argument as the message, never as a file
# name; callers passing text they do not control (commit messages, pull request titles) use it.
#
# Rule: the first line is "<type>[(<scope>)][!]: <subject>", type one of feat fix docs test
# refactor chore build ci perf, scope lowercase letters, digits and hyphens, subject 1-72
# characters. A Co-Authored-By trailer, when present, is "Co-Authored-By: Name <email>".
# Messages git writes itself pass unchanged: merges (in git's own wording), reverts and
# fixup!/squash!/amend! commits.
set -u

if [ $# -eq 2 ] && [ "$1" = --message ]; then
  msg=$2
elif [ $# -eq 1 ] && [ -f "$1" ]; then
  msg=$(cat "$1") || { echo "commit-msg: cannot read $1" >&2; exit 2; }
elif [ $# -eq 1 ]; then
  msg=$1
else
  echo "usage: $0 <message-file> | --message <message>" >&2
  exit 2
fi

# Lines starting with '#' are git's editor comments, never part of the message.
body=$(printf '%s\n' "$msg" | grep -v '^#')
subject=$(printf '%s\n' "$body" | sed '/./,$!d' | head -n 1)

usage() {
  echo "commit-msg: $1"
  echo "  got:   $subject"
  echo "expected: <type>[(<scope>)][!]: <subject, 1-72 characters>"
  echo "  type:  feat fix docs test refactor chore build ci perf"
  echo "  scope: lowercase letters, digits and hyphens"
  echo "  e.g.   feat: add x   |   fix(scan): reject y   |   feat!: change z"
  echo "trailer, when present: Co-Authored-By: Name <email>"
  exit 1
}

case "$subject" in
  "Merge branch '"*|"Merge branches '"*|"Merge remote-tracking branch '"*|"Merge tag '"*|\
  "Merge commit '"*|"Merge pull request #"*|"Revert \""*|"fixup! "*|"squash! "*|"amend! "*)
    exit 0 ;;
esac

printf '%s\n' "$subject" |
  grep -qE '^(feat|fix|docs|test|refactor|chore|build|ci|perf)(\([a-z0-9-]+\))?!?: .{1,72}$' ||
  usage "the first line is not a conventional commit subject"

if printf '%s\n' "$body" | grep -iE '^co-authored-by:' |
  grep -qivE '^co-authored-by: [^<>]*[^<> ] <[^<>@ ]+@[^<> ]+>$'; then
  usage "malformed Co-Authored-By trailer"
fi
exit 0
