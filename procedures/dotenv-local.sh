#!/bin/sh
# keyreeve-procedure: A variable in a dotenv file on this Mac, such as a project's .env.
# param file: the file's absolute path, such as /Users/you/code/app/.env
# param variable: the variable's name in that file
#
# The value arrives on stdin, never in a command line. A check prints only the SHA-256 of the value in place.
# The file is replaced with one rename and keeps its mode, its comments and every other line. A file behind a
# link is changed at its target.

verb="${1:-}"
file="${PLACE_FILE:-}"
variable="${PLACE_VARIABLE:-}"

case "$file" in /*) ;; *) exit 64 ;; esac
case "$variable" in '' | [0-9]* | *[!A-Za-z0-9_]*) exit 64 ;; esac

# Prints the variable's last value, without one pair of surrounding quotes, or exits 3 when it is not there.
FIND='
{ body = $0; if (match(body, /^[ \t]*export[ \t]+/)) body = substr(body, RLENGTH + 1) }
index(body, name "=") == 1 { value = substr(body, length(name) + 2); found = 1 }
END {
  if (!found) exit 3
  first = substr(value, 1, 1); last = substr(value, length(value), 1)
  if (length(value) >= 2 && (first == "\"" || first == "\047") && last == first) value = substr(value, 2, length(value) - 2)
  printf "%s", value
}'

# Writes the file again with the new value in each line that sets the variable, keeping an `export` and the
# quotes it had, or adds the line at the end when there is none.
REPLACE='
{ body = $0; pre = ""
  if (match(body, /^[ \t]*export[ \t]+/)) { pre = substr(body, 1, RLENGTH); body = substr(body, RLENGTH + 1) }
  if (index(body, name "=") == 1) {
    quote = substr(body, length(name) + 2, 1)
    if (quote != "\"" && quote != "\047") quote = ""
    print pre name "=" quote ENVIRON["KEYREEVE_VALUE"] quote; done = 1; next
  }
  print
}
END { if (!done) print name "=" ENVIRON["KEYREEVE_VALUE"] }'

case "$verb" in
check)
  [ -f "$file" ] && [ -r "$file" ] || exit 66
  value=$(awk -v name="$variable" "$FIND" "$file" 2>/dev/null); found=$?
  [ "$found" -eq 3 ] && { echo absent; exit 0; }
  [ "$found" -eq 0 ] || exit 70
  if command -v sha256sum >/dev/null 2>&1; then printf %s "$value" | sha256sum | cut -c1-64
  else printf %s "$value" | shasum -a 256 | cut -c1-64; fi
  ;;
apply)
  set -eu
  value=$(cat)
  [ -n "$value" ] || exit 65
  case "$value" in *"
"*) exit 65 ;; esac
  [ -f "$file" ] || exit 66
  real=$(readlink -f "$file" 2>/dev/null || printf %s "$file")
  dir=$(dirname "$real")
  umask 077
  tmp=$(mktemp "$dir/.keyreeve.XXXXXX")
  trap 'rm -f "$tmp"' EXIT
  KEYREEVE_VALUE=$value awk -v name="$variable" "$REPLACE" "$real" > "$tmp"
  mode=$(stat -f %Lp "$real" 2>/dev/null || stat -c %a "$real")
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$real"
  trap - EXIT
  ;;
*)
  exit 64
  ;;
esac
