#!/bin/sh
# Gets the key on stdin. Never print it, and never pass it as an argument, where `ps` would show it.
# KEYREEVE_MODE says why it was called: check, identify, or the id of an action.
key=$(cat)

status=$(printf 'header = "Authorization: Bearer %s"\n' "$key" |
  curl -K - -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com/api/me)

case "$KEYREEVE_MODE" in
  check)
    case "$status" in
      200) echo '{"result":"works"}' ;;
      401) echo '{"result":"rejected"}' ;;
      *) echo '{"result":"no_result","message":"Unexpected answer"}' ;;
    esac
    ;;
  identify) echo '{"fields":{"account":"me@example.com"}}' ;;
  *) echo '{"message":"Done"}' ;;
esac
