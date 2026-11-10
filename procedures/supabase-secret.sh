#!/bin/sh
# keyreeve-procedure: A secret of a Supabase project's Edge Functions, through Supabase's API, with a Supabase access token of yours that keyreeve puts on each request.
# param token_key: the keyreeve key that holds a Supabase personal access token, offered to agents so `keyreeve-vault use` can use it
# param project: the project's reference, as in <project>.supabase.co
# param name: the secret's name
#
# The new value goes to curl on stdin and the token never reaches this script: keyreeve-vault use gives curl a
# stand-in, and keyreeve's proxy puts the token on the way to Supabase. Supabase lists each secret with the
# SHA-256 of its value, never the value, and a check prints that hash.

verb="${1:-}"
token_key="${PLACE_TOKEN_KEY:-}"
project="${PLACE_PROJECT:-}"
name="${PLACE_NAME:-}"

case "$token_key" in '' | -* | *[!a-z0-9-]*) exit 64 ;; esac
case "$project" in '' | *[!a-z0-9]*) exit 64 ;; esac
case "$name" in '' | [0-9]* | *[!A-Za-z0-9_]*) exit 64 ;; esac
[ -x "${KEYREEVE_VAULT:-}" ] || exit 69
command -v jq >/dev/null 2>&1 || exit 69

api="https://api.supabase.com/v1/projects/$project/secrets"

# method; a body, if any, on stdin. Prints the answer, then its status on a line of its own.
request() {
  "$KEYREEVE_VAULT" use "$token_key" --reason "keyreeve place: Supabase secret $name" --as KR_TOKEN -- \
    /bin/sh -c 'if [ "$1" = GET ]; then curl -sS -H "Authorization: Bearer $KR_TOKEN" -w "\n%{http_code}" "$2" </dev/null
      else curl -sS -X "$1" -H "Authorization: Bearer $KR_TOKEN" -H "Content-Type: application/json" --data-binary @- -w "\n%{http_code}" "$2"; fi' \
    sh "$1" "$api" 2>/dev/null
}

case "$verb" in
check)
  answer=$(request GET) || exit 70
  status=${answer##*"
"}
  body=${answer%"
"*}
  [ "$status" = 200 ] || exit 70
  listed=$(printf '%s' "$body" | jq -r --arg n "$name" '[.[] | select(.name == $n)] | length' 2>/dev/null) || exit 70
  [ "$listed" = 0 ] && { echo absent; exit 0; }
  digest=$(printf '%s' "$body" | jq -r --arg n "$name" '[.[] | select(.name == $n)][0].value // empty' 2>/dev/null)
  case "$digest" in
  [0-9a-f]*) [ ${#digest} -eq 64 ] && echo "$digest" || echo present ;;
  *) echo present ;;
  esac
  ;;
apply)
  value=$(cat)
  [ -n "$value" ] || exit 65
  case "$value" in *[\"\\]* | *[[:cntrl:]]*) exit 65 ;; esac
  answer=$(printf '[{"name":"%s","value":"%s"}]' "$name" "$value" | request POST) || exit 70
  case "${answer##*"
"}" in 2??) ;; *) exit 70 ;; esac
  ;;
*)
  exit 64
  ;;
esac
