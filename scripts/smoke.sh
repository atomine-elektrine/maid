#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo run -p maid -- group create smoke
cargo run -p maid -- run --group smoke --prompt "hello"
cargo run -p maid -- task create --group smoke --name smoke-hourly --schedule "FREQ=HOURLY;INTERVAL=1" --prompt "status"
cargo run -p maid -- task list --group smoke
