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
fn plugin_can_call_core_tools_through_secure_bridge() {
    let root = unique_temp_dir("maid-plugin-bridge-it");
    fs::create_dir_all(&root).expect("failed to create temp root");

    let config_path = root.join("config.toml");
    let db_path = root.join("data/assistant.db");
    let group_root = root.join("groups");
    let plugin_root = root.join("plugins/bridge");

    copy_migrations(&root);
    fs::create_dir_all(&plugin_root).expect("failed to create plugin dir");

    let plugin_manifest = r#"
name = "bridge"
version = "0.1.0"
description = "bridge integration plugin"
executable = "./run.sh"
capabilities = ["bridge.run"]
allowed_tools = ["group.create"]
timeout_seconds = 30
env_allowlist = []
"#;
    write_file(
        &plugin_root.join("plugin.toml"),
        plugin_manifest.trim_start(),
    );

    let plugin_script = r#"#!/usr/bin/env bash
set -euo pipefail
"${MAID_BIN:-maid}" tool call --tool group.create --arg name=bridge-int-group >/dev/null
printf '%s\n' '{"ok":true,"message":"bridge plugin done","output":"group.create invoked","data":null}'
"#;
    let script_path = plugin_root.join("run.sh");
    write_file(&script_path, plugin_script);
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

[plugins]
directory = "{}"
enabled = ["bridge"]
tool_allowlist = ["group.create"]
tool_max_calls_per_minute = 20
validate_on_startup = true
"#,
        db_path.display(),
        group_root.display(),
        root.join("plugins").display()
    );
    write_file(&config_path, &config);

    let plugin_run = run_maid(
        &config_path,
        &["plugin", "run", "--name", "bridge", "--command", "sync"],
    );
    assert!(
        plugin_run.status.success(),
        "plugin run failed: {}",
        String::from_utf8_lossy(&plugin_run.stderr)
    );
    let stdout = String::from_utf8_lossy(&plugin_run.stdout);
    assert!(
        stdout.contains("bridge plugin done"),
        "unexpected plugin output: {stdout}"
    );

    let groups = run_maid(&config_path, &["group", "list"]);
    assert!(
        groups.status.success(),
        "group list failed: {}",
        String::from_utf8_lossy(&groups.stderr)
    );
    let group_stdout = String::from_utf8_lossy(&groups.stdout);
    assert!(
        group_stdout.contains("bridge-int-group"),
        "expected bridged tool call to create group; got: {group_stdout}"
    );
}
