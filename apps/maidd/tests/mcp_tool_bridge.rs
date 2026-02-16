use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{ts}"))
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("failed to create parent dir");
    }
    fs::write(path, contents).expect("failed to write file");
}

fn copy_migrations(dest_root: &Path) {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let dest = dest_root.join("migrations");
    fs::create_dir_all(&dest).expect("failed to create migrations dir");

    for entry in fs::read_dir(source).expect("failed to read migrations source") {
        let entry = entry.expect("failed to read migration entry");
        let source_path = entry.path();
        if source_path.extension().and_then(|ext| ext.to_str()) != Some("sql") {
            continue;
        }
        let file_name = source_path
            .file_name()
            .expect("migration missing file name");
        fs::copy(&source_path, dest.join(file_name)).expect("failed to copy migration");
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .expect("failed to stat script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("failed to chmod script");
}

fn run_maid(config_path: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_maid"));
    cmd.arg("--config").arg(config_path);
    cmd.args(args);
    cmd.output().expect("failed to run maid binary")
}

#[test]
fn mcp_tool_bridge_supports_list_call_and_read() {
    let root = unique_temp_dir("maid-mcp-bridge-it");
    fs::create_dir_all(&root).expect("failed to create temp root");

    let config_path = root.join("config.toml");
    let db_path = root.join("data/assistant.db");
    let group_root = root.join("groups");
    let script_path = root.join("scripts/fake-mcp.sh");

    copy_migrations(&root);

    let server_script = r#"#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r line; do
  id="$(printf '%s\n' "$line" | sed -n 's/.*"id":[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
  if [[ "$line" == *'"method":"initialize"'* ]]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"fake","version":"0.1.0"}}}\n' "$id"
    continue
  fi
  if [[ "$line" == *'"method":"notifications/initialized"'* ]]; then
    continue
  fi
  if [[ "$line" == *'"method":"tools/list"'* ]]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"Echo text","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}]}}\n' "$id"
    continue
  fi
  if [[ "$line" == *'"method":"tools/call"'* ]]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok-from-mcp"}],"isError":false}}\n' "$id"
    continue
  fi
  if [[ "$line" == *'"method":"resources/read"'* ]]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"contents":[{"uri":"file://docs/readme","mimeType":"text/plain","text":"hello-from-resource"}]}}\n' "$id"
    continue
  fi
  if [[ -n "$id" ]]; then
    printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}\n' "$id"
  fi
done
"#;
    write_file(&script_path, server_script);
    #[cfg(unix)]
    make_executable(&script_path);

    let config = format!(
        r#"
database_path = "{}"
group_root = "{}"
runtime = "docker"

[model]
provider = "echo"
api_key_env = "OPENAI_API_KEY"

[scheduler]
tick_seconds = 30
max_concurrency = 2

[mcp]
enabled = true
request_timeout_seconds = 3

[mcp.servers.fake]
transport = "stdio"
command = "{}"
enabled = true
env_allowlist = []
startup_timeout_seconds = 3
"#,
        db_path.display(),
        group_root.display(),
        script_path.display()
    );
    write_file(&config_path, &config);

    let list_output = run_maid(
        &config_path,
        &[
            "tool",
            "call",
            "--tool",
            "mcp.list_tools",
            "--arg",
            "server=fake",
        ],
    );
    assert!(
        list_output.status.success(),
        "mcp.list_tools failed: {}",
        String::from_utf8_lossy(&list_output.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        list_stdout.contains("\"echo\""),
        "expected echo tool in list output: {list_stdout}"
    );

    let call_output = run_maid(
        &config_path,
        &[
            "tool",
            "call",
            "--tool",
            "mcp.call",
            "--arg",
            "server=fake",
            "--arg",
            "name=echo",
            "--arg",
            "arg.text=hello",
        ],
    );
    assert!(
        call_output.status.success(),
        "mcp.call failed: {}",
        String::from_utf8_lossy(&call_output.stderr)
    );
    let call_stdout = String::from_utf8_lossy(&call_output.stdout);
    assert!(
        call_stdout.contains("ok-from-mcp"),
        "expected call payload in output: {call_stdout}"
    );

    let read_output = run_maid(
        &config_path,
        &[
            "tool",
            "call",
            "--tool",
            "mcp.read_resource",
            "--arg",
            "server=fake",
            "--arg",
            "uri=file://docs/readme",
        ],
    );
    assert!(
        read_output.status.success(),
        "mcp.read_resource failed: {}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    let read_stdout = String::from_utf8_lossy(&read_output.stdout);
    assert!(
        read_stdout.contains("hello-from-resource"),
        "expected resource payload in output: {read_stdout}"
    );
}
