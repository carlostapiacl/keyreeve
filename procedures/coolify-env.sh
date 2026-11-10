#!/bin/sh
# keyreeve-procedure: An environment variable of a Coolify application, through Coolify's API, with a Coolify token of yours that keyreeve puts on each request. Can restart the application after.
# param token_key: the keyreeve key that holds a Coolify API token, with its server approved and offered to agents so `keyreeve-vault use` can use it
# param server: Coolify's address, such as coolify.example.com
# param app: the application's uuid, as Coolify shows it
# param variable: the variable's name
# param restart: (optional) yes to restart the application after the change
#
# The new value goes to curl on stdin and the token never reaches this script: keyreeve-vault use gives curl a
# stand-in, and keyreeve's proxy puts the token on the way to your server. A check hashes the value here and
# prints only the hash.

verb="${1:-}"
token_key="${PLACE_TOKEN_KEY:-}"
server="${PLACE_SERVER:-}"
app="${PLACE_APP:-}"
variable="${PLACE_VARIABLE:-}"
restart="${PLACE_RESTART:-}"

case "$token_key" in '' | -* | *[!a-z0-9-]*) exit 64 ;; esac
server=${server#https://}
server=${server%/}
case "$server" in '' | -* | *[!A-Za-z0-9.:-]*) exit 64 ;; esac
case "$app" in '' | *[!A-Za-z0-9-]*) exit 64 ;; esac
case "$variable" in '' | [0-9]* | *[!A-Za-z0-9_]*) exit 64 ;; esac
case "$restart" in '' | yes | no) ;; *) exit 64 ;; esac
[ -x "${KEYREEVE_VAULT:-}" ] || exit 69
command -v jq >/dev/null 2>&1 || exit 69

api="https://$server/api/v1/applications/$app"

# method, address; a body, if any, on stdin. Prints the answer, then its status on a line of its own.
request() {
  "$KEYREEVE_VAULT" use "$token_key" --reason "keyreeve place: Coolify variable $variable" --as KR_TOKEN -- \
    /bin/sh -c 'if [ "$1" = GET ]; then curl -sS -H "Authorization: Bearer $KR_TOKEN" -w "\n%{http_code}" "$2" </dev/null
      else curl -sS -X "$1" -H "Authorization: Bearer $KR_TOKEN" -H "Content-Type: application/json" --data-binary @- -w "\n%{http_code}" "$2"; fi' \
    sh "$1" "$2" 2>/dev/null
}

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }

case "$verb" in
check)
  answer=$(request GET "$api/envs") || exit 70
  status=${answer##*"
"}
  body=${answer%"
"*}
  [ "$status" = 200 ] || exit 70
  listed=$(printf '%s' "$body" | jq -r --arg k "$variable" '[.[] | select(.key == $k and (.is_preview | not))] | length' 2>/dev/null) || exit 70
  [ "$listed" = 0 ] && { echo absent; exit 0; }
  found=$(printf '%s' "$body" | jq -r --arg k "$variable" '[.[] | select(.key == $k and (.is_preview | not))][0].value // empty' 2>/dev/null)
  if [ -n "$found" ]; then printf '%s' "$found" | sha; else echo present; fi
  ;;
apply)
  value=$(cat)
  [ -n "$value" ] || exit 65
  case "$value" in *[\"\\]* | *[[:cntrl:]]*) exit 65 ;; esac
  answer=$(printf '{"key":"%s","value":"%s"}' "$variable" "$value" | request PATCH "$api/envs") || exit 70
  status=${answer##*"
"}
  if [ "$status" = 404 ]; then
    answer=$(printf '{"key":"%s","value":"%s"}' "$variable" "$value" | request POST "$api/envs") || exit 70
    status=${answer##*"
"}
  fi
  case "$status" in 2??) ;; *) exit 70 ;; esac
  if [ "$restart" = yes ]; then
    answer=$(request GET "$api/restart") || exit 75
    case "${answer##*"
"}" in 2??) ;; *) exit 75 ;; esac
  fi
  ;;
*)
  exit 64
  ;;
esac
