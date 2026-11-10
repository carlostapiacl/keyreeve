#!/bin/sh
# keyreeve-procedure: A variable in a dotenv file on a server, over ssh. Can restart a service or a compose project after.
# param host: the server as ssh knows it, such as an alias from ~/.ssh/config or user@name
# param file: the file's absolute path on the server, such as /opt/app/.env
# param variable: the variable's name in that file
# param service: (optional) a systemd service to restart after the change
# param compose_dir: (optional) a folder on the server with a docker compose project to bring up after the change
#
# The value travels on the ssh connection's stdin, never in a command line. A check computes the hash on the
# server, so the value never comes back. The file is replaced with one rename and keeps its mode, its owner,
# its comments and every other line. A file behind a link is changed at its target.

verb="${1:-}"
host="${PLACE_HOST:-}"
file="${PLACE_FILE:-}"
variable="${PLACE_VARIABLE:-}"
service="${PLACE_SERVICE:-}"
compose="${PLACE_COMPOSE_DIR:-}"

# Every parameter goes into a command the server's shell reads, so each must be plain.
case "$host" in '' | -* | *[!A-Za-z0-9._@:-]*) exit 64 ;; esac
case "$file" in /*) ;; *) exit 64 ;; esac
case "$file" in *[!A-Za-z0-9._/@+-]*) exit 64 ;; esac
case "$variable" in '' | [0-9]* | *[!A-Za-z0-9_]*) exit 64 ;; esac
case "$service" in -* | *[!A-Za-z0-9._@-]*) exit 64 ;; esac
case "$compose" in '') ;; /*) case "$compose" in *[!A-Za-z0-9._/@+-]*) exit 64 ;; esac ;; *) exit 64 ;; esac

# Quotes one word for the server's shell.
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

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

CHECK='
f=$1; name=$2
[ -f "$f" ] && [ -r "$f" ] || exit 66
value=$(awk -v name="$name" "$FIND" "$f"); found=$?
[ "$found" -eq 3 ] && { echo absent; exit 0; }
[ "$found" -eq 0 ] || exit 70
if command -v sha256sum >/dev/null 2>&1; then printf %s "$value" | sha256sum | cut -c1-64
else printf %s "$value" | shasum -a 256 | cut -c1-64; fi
'

APPLY='
set -eu
f=$1; name=$2; service=$3; compose=$4
value=$(cat)
[ -n "$value" ] || exit 65
case "$value" in *"
"*) exit 65 ;; esac
[ -f "$f" ] || exit 66
real=$(readlink -f "$f" 2>/dev/null || printf %s "$f")
dir=$(dirname "$real")
umask 077
tmp=$(mktemp "$dir/.keyreeve.XXXXXX")
trap "rm -f \"$tmp\"" EXIT
KEYREEVE_VALUE=$value awk -v name="$name" "$REPLACE" "$real" > "$tmp"
mode=$(stat -c %a "$real" 2>/dev/null || stat -f %Lp "$real")
owner=$(stat -c %u:%g "$real" 2>/dev/null || stat -f %u:%g "$real")
chmod "$mode" "$tmp"
chown "$owner" "$tmp" 2>/dev/null || true
mv -f "$tmp" "$real"
trap - EXIT
if [ -n "$service" ]; then systemctl restart "$service" >/dev/null 2>&1 || exit 75; fi
if [ -n "$compose" ]; then (cd "$compose" && docker compose up -d >/dev/null 2>&1) || exit 75; fi
'

on_server() { ssh -o BatchMode=yes -o ConnectTimeout=15 "$host" "$1"; }

case "$verb" in
check)
  on_server "FIND=$(q "$FIND"); export FIND; sh -c $(q "$CHECK") sh $(q "$file") $(q "$variable")" </dev/null 2>/dev/null
  ;;
apply)
  on_server "REPLACE=$(q "$REPLACE"); export REPLACE; sh -c $(q "$APPLY") sh $(q "$file") $(q "$variable") $(q "$service") $(q "$compose")" >/dev/null 2>&1
  ;;
*)
  exit 64
  ;;
esac
