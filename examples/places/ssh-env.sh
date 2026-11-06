#!/bin/sh
# Replaces one line of an env file on your server with the new key, which arrives on stdin and travels
# on the ssh connection's stdin, so it never appears in a command line. Copy to ~/.keyreeve/providers
# and set these values.
host="you@your-server"
file="/path/to/app.env"
name="YOUR_VARIABLE"
if ssh -o BatchMode=yes "$host" "umask 077; key=\$(cat); tmp=\$(mktemp) && grep -v '^$name=' '$file' > \"\$tmp\"; printf '%s=%s\n' '$name' \"\$key\" >> \"\$tmp\" && cat \"\$tmp\" > '$file'; rm -f \"\$tmp\"" >/dev/null 2>&1; then
  echo '{"message":"Server file updated"}'
else
  echo '{"result":"no_result","message":"The server file was not updated"}'
fi
