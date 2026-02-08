#!/usr/bin/env bash
set -euo pipefail

# MAID_SKILL_REQUEST contains JSON string payload.
request="${MAID_SKILL_REQUEST:-}"
if [[ -z "$request" ]]; then
  printf '%s\n' '{"ok":false,"message":"MAID_SKILL_REQUEST is missing","output":null,"data":null}'
  exit 0
fi

command=$(printf '%s' "$request" | sed -n 's/.*"command":"\([^"]*\)".*/\1/p')
if [[ -z "$command" ]]; then
  command="unknown"
fi

escaped=$(printf '%s' "$request" | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g')

printf '%s\n' "{\"ok\":true,\"message\":\"echo skill executed\",\"output\":\"command=$command\",\"data\":{\"raw_request\":\"$escaped\"}}"
