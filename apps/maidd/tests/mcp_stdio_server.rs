use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

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

fn run_maid(config_path: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_maid"));
    cmd.arg("--config").arg(config_path);
    cmd.args(args);
    cmd.output().expect("failed to run maid binary")
}

fn write_framed_message(stdin: &mut std::process::ChildStdin, payload: &Value) {
    let body = serde_json::to_vec(payload).expect("failed to encode mcp payload");
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin
        .write_all(header.as_bytes())
        .expect("failed to write header");
    stdin.write_all(&body).expect("failed to write body");
    stdin.flush().expect("failed to flush stdin");
}

fn read_framed_message(stdout: &mut BufReader<std::process::ChildStdout>) -> Value {
    let mut first_line = String::new();
    loop {
        first_line.clear();
        stdout
            .read_line(&mut first_line)
            .expect("failed to read mcp header line");
        assert!(
            !first_line.is_empty(),
            "unexpected EOF while reading header"
        );
        let normalized = first_line
            .trim_end_matches(&['\r', '\n'][..])
            .to_ascii_lowercase();
        if normalized.starts_with("content-length:") {
            break;
        }
    }
    let (name, value) = first_line
        .trim_end_matches(&['\r', '\n'][..])
        .split_once(':')
        .expect("invalid mcp header");
    assert!(
        name.trim().eq_ignore_ascii_case("content-length"),
        "expected Content-Length header, got {}",
        name
    );
    let len = value
        .trim()
        .parse::<usize>()
        .expect("invalid Content-Length value");

    loop {
        let mut line = String::new();
        stdout
            .read_line(&mut line)
            .expect("failed to read mcp header terminator");
        if line.trim().is_empty() {
            break;
        }
    }

    let mut body = vec![0_u8; len];
    stdout
        .read_exact(&mut body)
        .expect("failed to read mcp body");
    serde_json::from_slice(&body).expect("invalid JSON payload")
}

#[test]
fn incoming_mcp_stdio_server_lists_and_calls_tools() {
    let root = unique_temp_dir("maid-mcp-stdio-server-it");
    fs::create_dir_all(&root).expect("failed to create temp root");

    let config_path = root.join("config.toml");
    let db_path = root.join("data/assistant.db");
    let group_root = root.join("groups");

    copy_migrations(&root);

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
"#,
        db_path.display(),
        group_root.display(),
    );
    write_file(&config_path, &config);

    let create_group = run_maid(&config_path, &["group", "create", "mcp-it"]);
    assert!(
        create_group.status.success(),
        "failed to create group: {}",
        String::from_utf8_lossy(&create_group.stderr)
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_maid"))
        .arg("--config")
        .arg(&config_path)
        .args(["mcp", "serve-stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn maid mcp server");

    let mut stdin = child.stdin.take().expect("missing stdin");
    let stdout = child.stdout.take().expect("missing stdout");
    let mut stdout = BufReader::new(stdout);

    write_framed_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }),
    );
    let init_response = read_framed_message(&mut stdout);
    assert_eq!(init_response["id"], json!(1));
    assert_eq!(init_response["result"]["serverInfo"]["name"], json!("maid"));

    write_framed_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    );

    write_framed_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    let list_response = read_framed_message(&mut stdout);
    assert_eq!(list_response["id"], json!(2));
    let tools = list_response["result"]["tools"]
        .as_array()
        .expect("tools/list result.tools must be array");
    assert!(
        tools
            .iter()
            .any(|entry| entry.get("name") == Some(&json!("group.list"))),
        "expected group.list in tools/list response: {}",
        list_response
    );

    write_framed_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "group.list",
                "arguments": {}
            }
        }),
    );
    let call_response = read_framed_message(&mut stdout);
    assert_eq!(call_response["id"], json!(3));
    assert_eq!(call_response["result"]["isError"], json!(false));
    let text = call_response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("\"groups\""),
        "expected groups payload in tools/call response: {}",
        call_response
    );

    let _ = child.kill();
    let _ = child.wait();
}
