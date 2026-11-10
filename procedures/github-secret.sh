#!/bin/sh
# keyreeve-procedure: A GitHub Actions secret, through the gh command you are signed in to. GitHub never shows a secret again, so a check says only whether it is there.
# param repo: the repository, as owner/name
# param name: the secret's name
# param environment: (optional) a deployment environment of the repository, for a secret of that environment
#
# The value goes to gh on stdin, never in a command line.

verb="${1:-}"
repo="${PLACE_REPO:-}"
name="${PLACE_NAME:-}"
environment="${PLACE_ENVIRONMENT:-}"

case "$repo" in -* | */*/* | *[!A-Za-z0-9._/-]*) exit 64 ;; */*) ;; *) exit 64 ;; esac
case "$name" in '' | [0-9]* | *[!A-Za-z0-9_]*) exit 64 ;; esac
case "$environment" in -* | *[!A-Za-z0-9._-]*) exit 64 ;; esac

set -- --repo "$repo"
[ -n "$environment" ] && set -- "$@" --env "$environment"

case "$verb" in
check)
  names=$(gh secret list "$@" --json name --jq '.[].name' </dev/null 2>/dev/null) || exit 70
  if printf '%s\n' "$names" | grep -qx "$name"; then echo present; else echo absent; fi
  ;;
apply)
  gh secret set "$name" "$@" >/dev/null 2>&1
  ;;
*)
  exit 64
  ;;
esac
