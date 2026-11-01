#!/bin/sh
# Checks the links of the project's Markdown documentation, so a renamed file or heading cannot
# leave a dead link behind. Used by `make docs-links` (part of `make docs-check`, so of `make ci`).
#
# Usage: scripts/check-doc-links.sh [file...]
#        scripts/check-doc-links.sh --list
# With no file, it checks the documentation set: the three READMEs and every Markdown file under
# docs/ that git tracks or would track (untracked files count, ignored ones and docs/superpowers/
# do not). --list prints that set, one file per line, for other checks to reuse.
#
# Every link target, inline "[text](target)", image "![alt](target)" or reference definition
# "[ref]: target", outside fenced code blocks and inline code, must resolve:
#   - http://, https:// and mailto: targets are not checked;
#   - a path, relative to the linking file's directory (or to the repository root when it starts
#     with "/"), must exist and must not be ignored by git, since an ignored file is not on GitHub;
#   - a "#fragment", alone or after a path to a Markdown file, must name a heading of that file
#     under GitHub's anchor rule (see SCAN below) or an HTML id/name attribute in it.
# Each failure prints "file:line: broken link: target"; the exit status is 1 if any link is broken.
set -u

list_docs() {
  all=$(git ls-files --cached --others --exclude-standard -- \
    README.md README.es.md README.pt-BR.md 'docs/*.md' ':!:docs/superpowers/*') || return 1
  for f in $all; do
    # --cached also lists files deleted from the working tree.
    if [ -f "$f" ]; then printf '%s\n' "$f"; fi
  done
}

if [ "${1:-}" = "--list" ]; then
  list_docs || { echo "docs-links: cannot list the documentation files" >&2; exit 1; }
  exit 0
fi

# SCAN prints one record per line for a Markdown file:
#   H<TAB>anchor            for each heading anchor and each HTML id="..."/name="..." value
#   L<TAB>line<TAB>target   for each link target
# Lines inside fenced code blocks (``` or ~~~) are skipped, and inline code spans are removed
# before links are looked for.
#
# A heading's anchor follows GitHub: take the heading text (links reduced to their text, HTML tags
# removed), lowercase it, drop every character other than letters, digits, spaces, hyphens and
# underscores, and turn each space into a hyphen; the second heading with the same anchor gets
# "-1", the third "-2", and so on. Underscores are kept because GitHub keeps them.
#
# awk runs with LC_ALL=C so it reads bytes the same way in every awk (gawk, mawk, BSD awk); the
# letter test on UTF-8 text is then done by hand: two-byte sequences are letters (Latin, Greek,
# Cyrillic...) and kept, except the Latin-1 symbols (C2 xx, multiplication and division signs);
# three- and four-byte sequences (dashes, arrows, quotes, emoji) are dropped. Uppercase accented
# Latin-1 letters (C3 80-9E) are lowercased; other non-ASCII uppercase letters are not, which only
# matters for a heading that contains one.
SCAN='
BEGIN {
  for (i = 1; i < 256; i++) ord[sprintf("%c", i)] = i
  upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; lower = "abcdefghijklmnopqrstuvwxyz"
}

function slug(s,    out, i, n, c, b, b2) {
  out = ""; n = length(s); i = 1
  while (i <= n) {
    c = substr(s, i, 1); b = ord[c]
    if (b < 128) {
      if (index(upper, c)) out = out substr(lower, index(upper, c), 1)
      else if (c ~ /[a-z0-9_-]/) out = out c
      else if (c == " ") out = out "-"
      i++
    } else if (b >= 192 && b < 224) {
      b2 = ord[substr(s, i + 1, 1)]
      if (b == 195 && b2 >= 128 && b2 <= 158 && b2 != 151) out = out c sprintf("%c", b2 + 32)
      else if (b != 194 && !(b == 195 && (b2 == 151 || b2 == 183))) out = out c substr(s, i + 1, 1)
      i += 2
    } else if (b >= 224 && b < 240) i += 3
    else if (b >= 240) i += 4
    else i++
  }
  return out
}

# Fences: an opening line of three or more backticks or tildes (up to three spaces of indent)
# runs to a line of at least as many of the same character and nothing else.
{
  line = $0
  if (fence != "") {
    if (match(line, /^ ? ? ?(```+|~~~+)[ \t]*$/)) {
      t = line; sub(/^ */, "", t); sub(/[ \t]*$/, "", t)
      if (substr(t, 1, 1) == substr(fence, 1, 1) && length(t) >= length(fence)) fence = ""
    }
    next
  }
  if (match(line, /^ ? ? ?(```+|~~~+)/)) {
    t = substr(line, RSTART, RLENGTH); sub(/^ */, "", t); fence = t
    next
  }

  gsub(/`[^`]*`/, "", line)

  # HTML anchors, anywhere on the line.
  t = line
  while (match(t, /(id|name)="[^"]*"/)) {
    a = substr(t, RSTART, RLENGTH); sub(/^[a-z]*="/, "", a); sub(/"$/, "", a)
    print "H\t" a
    t = substr(t, RSTART + RLENGTH)
  }

  # ATX headings: "#" to "######", then a space or the end of the line.
  if (match(line, /^ ? ? ?#+([ \t]|$)/) && match(line, /^ ? ? ?#######/) == 0) {
    h = $0
    sub(/^ *#+[ \t]*/, "", h); sub(/[ \t]+#+[ \t]*$/, "", h); sub(/[ \t]+$/, "", h)
    while (match(h, /\[[^]]*\]\([^)]*\)/)) {
      a = substr(h, RSTART, RLENGTH); sub(/\]\(.*$/, "", a); sub(/^\[/, "", a)
      h = substr(h, 1, RSTART - 1) a substr(h, RSTART + RLENGTH)
    }
    gsub(/<[^>]*>/, "", h)
    s = slug(h)
    if (s in seen) { seen[s]++; s = s "-" seen[s] } else seen[s] = 0
    print "H\t" s
  }

  # Reference definitions: "[ref]: target" at the start of the line.
  if (match(line, /^ ? ? ?\[[^]]+\]:[ \t]*[^ \t]/)) {
    t = line; sub(/^ *\[[^]]+\]:[ \t]*/, "", t); sub(/[ \t].*$/, "", t); sub(/^</, "", t); sub(/>$/, "", t)
    print "L\t" NR "\t" t
  }

  # Inline links and images: every "](target)". Only the target matters, so link text that
  # itself contains brackets is handled. A title after the target ("path \"title\"") is dropped.
  t = line
  while (match(t, /\]\([^)]*\)/)) {
    a = substr(t, RSTART + 2, RLENGTH - 3)
    sub(/^[ \t]*/, "", a)
    if (substr(a, 1, 1) == "<") { sub(/^</, "", a); sub(/>.*$/, "", a) } else sub(/[ \t].*$/, "", a)
    print "L\t" NR "\t" a
    t = substr(t, RSTART + RLENGTH)
  }
}
'

scan() {
  LC_ALL=C awk "$SCAN" "$1"
}

# has_anchor FILE ANCHOR: whether FILE defines ANCHOR.
has_anchor() {
  scan "$1" | sed -n 's/^H	//p' | grep -qxF -e "$2"
}

root=$(git rev-parse --show-toplevel 2>/dev/null) || root=$(pwd)

if [ $# -gt 0 ]; then
  files=$*
else
  files=$(list_docs) || { echo "docs-links: cannot list the documentation files"; exit 1; }
fi

tab=$(printf '\t')
fail=0
nlinks=0
nfiles=0
for f in $files; do
  [ -f "$f" ] || { echo "$f: no such file"; fail=1; continue; }
  nfiles=$((nfiles + 1))
  dir=$(dirname "$f")
  links=$(scan "$f" | sed -n 's/^L	//p')
  # The loop reads a here-document, not a pipe, so fail and nlinks keep their values after it.
  while IFS="$tab" read -r line target; do
    [ -n "$line" ] || continue
    case "$target" in
      http://* | https://* | mailto:*) continue ;;
    esac
    nlinks=$((nlinks + 1))
    path=${target%%#*}
    case "$target" in
      *#*) frag=${target#*#} ;;
      *) frag="" ;;
    esac
    if [ -z "$target" ]; then
      echo "$f:$line: broken link: (empty target)"; fail=1; continue
    fi
    case "$path" in
      "") dest=$f ;;
      /*) dest=$root$path ;;
      *) dest=$dir/$path ;;
    esac
    if [ ! -e "$dest" ]; then
      echo "$f:$line: broken link: $target"; fail=1; continue
    fi
    if git check-ignore -q "$dest" 2>/dev/null; then
      echo "$f:$line: broken link: $target (ignored by git, so missing on GitHub)"; fail=1; continue
    fi
    # Fragments are checked only in Markdown files; "#L10" on a source file is GitHub's own.
    # A fragment is compared as written: a percent-encoded one fails, so write it unencoded.
    [ -n "$frag" ] || continue
    case "$dest" in
      *.md | *.MD | *.markdown) ;;
      *) continue ;;
    esac
    if ! has_anchor "$dest" "$frag"; then
      echo "$f:$line: broken link: $target"; fail=1
    fi
  done <<EOF
$links
EOF
done

[ "$fail" -eq 0 ] || exit 1
echo "docs-links: ok ($nlinks links in $nfiles files)"
