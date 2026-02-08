#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
exec cargo run -p maid -- --config config.toml daemon
