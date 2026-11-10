#!/bin/sh
# keyreeve-procedure: A Vercel environment variable, through the vercel command, run in a folder linked to the project. Vercel does not show a sensitive value again, so a check says only whether it is there.
# param folder: a folder on this Mac linked to the project with `vercel link`
# param variable: the variable's name
# param environment: (optional) production, preview or development; production if left out
#
# The value goes to vercel on stdin, never in a command line. Vercel has no way to replace a value in one
# step, so the old variable is removed and the new one added: between the two the variable is missing.

verb="${1:-}"
folder="${PLACE_FOLDER:-}"
variable="${PLACE_VARIABLE:-}"
environment="${PLACE_ENVIRONMENT:-production}"

case "$folder" in /*) ;; *) exit 64 ;; esac
case "$variable" in '' | [0-9]* | *[!A-Za-z0-9_]*) exit 64 ;; esac
case "$environment" in production | preview | development) ;; *) exit 64 ;; esac
cd "$folder" 2>/dev/null || exit 66

case "$verb" in
check)
  listed=$(vercel env ls "$environment" </dev/null 2>/dev/null) || exit 70
  if printf '%s\n' "$listed" | awk '{ print $1 }' | grep -qx "$variable"; then echo present; else echo absent; fi
  ;;
apply)
  value=$(cat)
  [ -n "$value" ] || exit 65
  vercel env rm "$variable" "$environment" --yes </dev/null >/dev/null 2>&1
  printf '%s' "$value" | vercel env add "$variable" "$environment" >/dev/null 2>&1
  ;;
*)
  exit 64
  ;;
esac
