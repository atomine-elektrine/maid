#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "error: required tool '${tool}' is not installed or not on PATH" >&2
    exit 1
  fi
}

require_tool cargo

echo "==> Running cargo-outdated"
cargo outdated --workspace --exit-code 1

echo "==> Running cargo-audit"
cargo audit

if [[ -f "deny.toml" ]]; then
  echo "==> Running cargo-deny"
  cargo deny check
else
  echo "==> Skipping cargo-deny (deny.toml not found)"
fi

echo "Dependency checks completed."
