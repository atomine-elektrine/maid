#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <plugin-name>" >&2
  exit 1
fi

name="$1"
if [[ ! "$name" =~ ^[a-z0-9-]+$ ]]; then
  echo "plugin name must match ^[a-z0-9-]+$" >&2
  exit 1
fi

root="$(dirname "$0")/../plugins/$name"
if [[ -e "$root" ]]; then
  echo "plugin already exists: $root" >&2
  exit 1
fi

mkdir -p "$root"
cat > "$root/plugin.toml" <<TOML
name = "$name"
version = "0.1.0"
description = "Rust plugin scaffold for $name"
executable = "./run.sh"
capabilities = []
allowed_tools = []
timeout_seconds = 60
env_allowlist = []
TOML

cat > "$root/Cargo.toml" <<TOML
[package]
name = "$name"
version = "0.1.0"
edition = "2021"

[workspace]
TOML

cat > "$root/.gitignore" <<'GITIGNORE'
target/
reports/
audit-logs/
GITIGNORE

mkdir -p "$root/src"
cat > "$root/src/main.rs" <<'RS'
fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn extract_command(raw: &str) -> String {
    for marker in ["\"command\":\"", "\"command\": \""] {
        if let Some(start) = raw.find(marker) {
            let start = start + marker.len();
            if let Some(rest) = raw.get(start..) {
                if let Some(end) = rest.find('"') {
                    return rest[..end].to_string();
                }
            }
        }
    }
    "unknown".to_string()
}

fn main() {
    let raw = std::env::var("MAID_PLUGIN_REQUEST").unwrap_or_default();
    if raw.trim().is_empty() {
        println!(
            "{{\"ok\":false,\"message\":\"MAID_PLUGIN_REQUEST is missing\",\"output\":null,\"data\":null}}"
        );
        return;
    }

    let command = extract_command(&raw);
    let escaped_raw = json_escape(&raw);
    let escaped_command = json_escape(&command);
    println!(
        "{{\"ok\":true,\"message\":\"plugin executed\",\"output\":\"command={}\",\"data\":{{\"raw_request\":\"{}\"}}}}",
        escaped_command, escaped_raw
    );
}
RS

cat > "$root/run.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
exec cargo run --quiet
SH

chmod +x "$root/run.sh"

echo "created plugin skeleton at $root"
