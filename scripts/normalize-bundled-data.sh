#!/usr/bin/env bash
# Prints a bundled IANA data file with comments and whitespace noise
# removed, leaving only what the parsers in src/config/mod.rs consume.
#
# Usage: normalize-bundled-data.sh <zonefile|tld-list> <file>
#
# The two formats comment differently, and each mode mirrors its parser
# exactly so that "normalized output is unchanged" means "the parsed result
# is unchanged":
#
#   zonefile   `;` starts a comment anywhere on the line, matching
#              parse_named_root (src/config/mod.rs:1047, which takes
#              `raw_line.split(';').next()`).
#   tld-list   only a line whose first non-blank character is `#` is a
#              comment, matching parse_iana_tlds (src/config/mod.rs:1114,
#              which tests `line.starts_with('#')` on the trimmed line).
#              A mid-line `#` is left in place: the parser either rejects
#              the line (`COM # note`, three tokens) or takes it literally
#              (`COM#note` becomes the TLD `com#note`). Either way it
#              changes the parsed result, so it must count as drift.
#
# Both modes then collapse runs of whitespace and drop blank lines, since
# both parsers trim and split on whitespace.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $(basename "$0") <zonefile|tld-list> <file>" >&2
  exit 2
fi

mode="$1"
file="$2"

case "$mode" in
  zonefile) strip_comments=(-e 's/;.*$//') ;;
  tld-list) strip_comments=(-e 's/^[[:blank:]]*#.*$//') ;;
  *)
    echo "$(basename "$0"): unknown mode '$mode' (expected zonefile or tld-list)" >&2
    exit 2
    ;;
esac

sed "${strip_comments[@]}" \
    -e 's/[[:space:]]\{1,\}/ /g' \
    -e 's/^ //' -e 's/ $//' \
    -e '/^$/d' \
    "$file"
