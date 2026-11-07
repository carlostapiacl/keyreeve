#!/bin/sh
# Replaces one line of an env file on your server with the new key, which arrives on stdin and travels
# on the ssh connection's stdin, so it never appears in a command line. Copy to ~/.keyreeve/providers
# and set these values. Any failure on the server leaves its file as it was, and is reported.
host="you@your-server"
file="/path/to/app.env"
name="YOUR_VARIABLE"
if ssh -o BatchMode=yes "$host" "set -eu; umask 077; key=\$(cat); tmp=\$(mktemp); trap 'rm -f \"\$tmp\"' EXIT; test -w '$file'; { grep -v '^$name=' '$file' || test \$? -eq 1; } > \"\$tmp\"; printf '%s=%s\n' '$name' \"\$key\" >> \"\$tmp\"; cat \"\$tmp\" > '$file'" >/dev/null 2>&1; then
  echo '{"message":"Server file updated"}'
else
  echo '{"result":"no_result","message":"The server file was not updated"}'
fi
