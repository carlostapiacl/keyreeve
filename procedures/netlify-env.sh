#!/bin/sh
# keyreeve-procedure: A Netlify environment variable of a site, through Netlify's API, with a Netlify token of yours that keyreeve puts on each request.
# param token_key: the keyreeve key that holds a Netlify token, offered to agents so `keyreeve-vault use` can use it
# param account: the team's slug or id, as Netlify shows it
# param site: the site's id
# param variable: the variable's name
# param context: (optional) all, production, deploy-preview, branch-deploy or dev; all if left out
#
# The new value goes to curl on stdin and the token never reaches this script: keyreeve-vault use gives curl a
# stand-in, and keyreeve's proxy puts the token on the way to Netlify. A check hashes the value here and prints
# only the hash. A variable marked secret at Netlify does not come back, so its check says only that it is there.

verb="${1:-}"
token_key="${PLACE_TOKEN_KEY:-}"
account="${PLACE_ACCOUNT:-}"
site="${PLACE_SITE:-}"
variable="${PLACE_VARIABLE:-}"
context="${PLACE_CONTEXT:-all}"

case "$token_key" in '' | -* | *[!a-z0-9-]*) exit 64 ;; esac
case "$account" in '' | *[!A-Za-z0-9._-]*) exit 64 ;; esac
case "$site" in '' | *[!A-Za-z0-9._-]*) exit 64 ;; esac
case "$variable" in '' | [0-9]* | *[!A-Za-z0-9_]*) exit 64 ;; esac
case "$context" in all | production | deploy-preview | branch-deploy | dev) ;; *) exit 64 ;; esac
[ -x "${KEYREEVE_VAULT:-}" ] || exit 69
command -v jq >/dev/null 2>&1 || exit 69

api="https://api.netlify.com/api/v1/accounts/$account/env"

# method, address; a body, if any, on stdin. Prints the answer, then its status on a line of its own.
request() {
  "$KEYREEVE_VAULT" use "$token_key" --reason "keyreeve place: Netlify variable $variable" --as KR_TOKEN -- \
    /bin/sh -c 'if [ "$1" = GET ]; then curl -sS -H "Authorization: Bearer $KR_TOKEN" -w "\n%{http_code}" "$2" </dev/null
      else curl -sS -X "$1" -H "Authorization: Bearer $KR_TOKEN" -H "Content-Type: application/json" --data-binary @- -w "\n%{http_code}" "$2"; fi' \
    sh "$1" "$2" 2>/dev/null
}

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }

case "$verb" in
check)
  answer=$(request GET "$api/$variable?site_id=$site") || exit 70
  status=${answer##*"
"}
  body=${answer%"
"*}
  [ "$status" = 404 ] && { echo absent; exit 0; }
  [ "$status" = 200 ] || exit 70
  found=$(printf '%s' "$body" | jq -er --arg c "$context" '[.values[]? | select(.context == $c or .context == "all")][0].value // empty' 2>/dev/null)
  if [ -n "$found" ]; then printf '%s' "$found" | sha; else echo present; fi
  ;;
apply)
  value=$(cat)
  [ -n "$value" ] || exit 65
  case "$value" in *[\"\\]* | *[[:cntrl:]]*) exit 65 ;; esac
  answer=$(printf '{"context":"%s","value":"%s"}' "$context" "$value" | request PATCH "$api/$variable?site_id=$site") || exit 70
  status=${answer##*"
"}
  if [ "$status" = 404 ]; then
    answer=$(printf '[{"key":"%s","values":[{"context":"%s","value":"%s"}]}]' "$variable" "$context" "$value" |
      request POST "$api?site_id=$site") || exit 70
    status=${answer##*"
"}
  fi
  case "$status" in 2??) exit 0 ;; *) exit 70 ;; esac
  ;;
*)
  exit 64
  ;;
esac
