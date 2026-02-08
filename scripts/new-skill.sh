#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <skill-name>" >&2
  exit 1
fi

name="$1"
if [[ ! "$name" =~ ^[a-z0-9-]+$ ]]; then
  echo "skill name must match ^[a-z0-9-]+$" >&2
  exit 1
fi

root="$(dirname "$0")/../skills/$name"
if [[ -e "$root" ]]; then
  echo "skill already exists: $root" >&2
  exit 1
fi

mkdir -p "$root"
cat > "$root/skill.toml" <<TOML
name = "$name"
version = "0.1.0"
description = "TODO"
executable = "./run.sh"
capabilities = []
allowed_tools = []
timeout_seconds = 30
env_allowlist = []
TOML

cat > "$root/run.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

request="${MAID_SKILL_REQUEST:-}"
if [[ -z "$request" ]]; then
  printf '%s\n' '{"ok":false,"message":"MAID_SKILL_REQUEST is missing","output":null,"data":null}'
  exit 0
fi

printf '%s\n' '{"ok":true,"message":"skill executed","output":"TODO","data":null}'
SH

chmod +x "$root/run.sh"

echo "created skill skeleton at $root"
