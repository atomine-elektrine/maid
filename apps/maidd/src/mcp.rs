use std::collections::{BTreeMap, HashMap};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::config::{AppConfig, McpServerConfig};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Default)]
struct McpClientManager {
    clients: HashMap<String, Arc<Mutex<McpClient>>>,
}

struct McpClient {
    server_name: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    initialized: bool,
    next_request_id: u64,
    startup_timeout_seconds: u64,
}

static MCP_MANAGER: OnceLock<Mutex<McpClientManager>> = OnceLock::new();

fn manager() -> &'static Mutex<McpClientManager> {
    MCP_MANAGER.get_or_init(|| Mutex::new(McpClientManager::default()))
}

pub(crate) async fn execute_mcp_list_tools_tool(
    cfg: &AppConfig,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<Value> {
    let server = args
        .get("server")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing required argument: server"))?;
    let response = list_tools(cfg, &server).await?;
    let tools = response
        .get("tools")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    Ok(json!({
        "tool": tool,
        "server": server,
        "tools": tools,
        "response": response,
    }))
}

pub(crate) async fn execute_mcp_call_tool(
    cfg: &AppConfig,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<Value> {
    let server = args
        .get("server")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing required argument: server"))?;
    let name = args
        .get("name")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing required argument: name"))?;
    let arguments = parse_call_arguments(&args)?;
    let response = call_tool(cfg, &server, &name, Value::Object(arguments)).await?;
    Ok(json!({
        "tool": tool,
        "server": server,
        "name": name,
        "response": response,
    }))
}

pub(crate) async fn execute_mcp_read_resource_tool(
    cfg: &AppConfig,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<Value> {
    let server = args
        .get("server")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing required argument: server"))?;
    let uri = args
        .get("uri")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing required argument: uri"))?;
    let response = read_resource(cfg, &server, &uri).await?;
    Ok(json!({
        "tool": tool,
        "server": server,
        "uri": uri,
        "response": response,
    }))
}

async fn list_tools(cfg: &AppConfig, server_name: &str) -> Result<Value> {
    let timeout = cfg.mcp_request_timeout_seconds();
    for attempt in 0..2 {
        let handle = get_or_create_client(cfg, server_name).await?;
        let result = {
            let mut client = handle.lock().await;
            client.list_tools(timeout).await
        };
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                warn!(
                    "mcp list_tools failed for server '{}' (retrying once): {err:#}",
                    server_name
                );
                remove_client(server_name).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(anyhow!(
        "mcp list_tools failed for server '{}'",
        server_name
    ))
}

async fn call_tool(
    cfg: &AppConfig,
    server_name: &str,
    tool_name: &str,
    arguments: Value,
) -> Result<Value> {
    let timeout = cfg.mcp_request_timeout_seconds();
    for attempt in 0..2 {
        let handle = get_or_create_client(cfg, server_name).await?;
        let result = {
            let mut client = handle.lock().await;
            client
                .call_tool(tool_name, arguments.clone(), timeout)
                .await
        };
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                warn!(
                    "mcp call_tool failed for server '{}' tool '{}' (retrying once): {err:#}",
                    server_name, tool_name
                );
                remove_client(server_name).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(anyhow!(
        "mcp call_tool failed for server '{}' tool '{}'",
        server_name,
        tool_name
    ))
}

async fn read_resource(cfg: &AppConfig, server_name: &str, uri: &str) -> Result<Value> {
    let timeout = cfg.mcp_request_timeout_seconds();
    for attempt in 0..2 {
        let handle = get_or_create_client(cfg, server_name).await?;
        let result = {
            let mut client = handle.lock().await;
            client.read_resource(uri, timeout).await
        };
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                warn!(
                    "mcp read_resource failed for server '{}' uri '{}' (retrying once): {err:#}",
                    server_name, uri
                );
                remove_client(server_name).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(anyhow!(
        "mcp read_resource failed for server '{}' uri '{}'",
        server_name,
        uri
    ))
}

async fn get_or_create_client(cfg: &AppConfig, server_name: &str) -> Result<Arc<Mutex<McpClient>>> {
    if !cfg.mcp_enabled() {
        return Err(anyhow!(
            "mcp is disabled in config; set [mcp].enabled = true"
        ));
    }

    let server_cfg = cfg
        .mcp_server_config(server_name)
        .ok_or_else(|| anyhow!("mcp server not found or disabled: {}", server_name))?;

    {
        let locked = manager().lock().await;
        if let Some(existing) = locked.clients.get(server_name) {
            return Ok(existing.clone());
        }
    }
    let client = McpClient::spawn(server_name.to_string(), &server_cfg).await?;
    let handle = Arc::new(Mutex::new(client));
    let mut locked = manager().lock().await;
    if let Some(existing) = locked.clients.get(server_name) {
        return Ok(existing.clone());
    }
    locked
        .clients
        .insert(server_name.to_string(), handle.clone());
    Ok(handle)
}

async fn remove_client(server_name: &str) {
    let handle = {
        let mut locked = manager().lock().await;
        locked.clients.remove(server_name)
    };
    if let Some(handle) = handle {
        let mut client = handle.lock().await;
        if let Err(err) = client.shutdown().await {
            debug!(
                "failed to shut down mcp server '{}' cleanly: {err:#}",
                server_name
            );
        }
    }
}

impl McpClient {
    async fn spawn(server_name: String, cfg: &McpServerConfig) -> Result<Self> {
        let mut command = Command::new(&cfg.command);
        command
            .args(cfg.args.clone().unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .env_clear();

        if let Some(cwd) = &cfg.cwd {
            command.current_dir(cwd);
        }
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
        if let Ok(home) = std::env::var("HOME") {
            command.env("HOME", home);
        }
        for env_name in cfg.env_allowlist.clone().unwrap_or_default() {
            if let Ok(value) = std::env::var(&env_name) {
                command.env(env_name, value);
            }
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn mcp server '{}'", server_name))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to acquire mcp stdin for '{}'", server_name))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to acquire mcp stdout for '{}'", server_name))?;

        Ok(Self {
            server_name,
            child,
            stdin,
            stdout: BufReader::new(stdout),
            initialized: false,
            next_request_id: 1,
            startup_timeout_seconds: cfg.startup_timeout_seconds.unwrap_or(10),
        })
    }

    async fn list_tools(&mut self, timeout_seconds: u64) -> Result<Value> {
        self.ensure_initialized(timeout_seconds).await?;
        self.send_request("tools/list", json!({}), timeout_seconds)
            .await
    }

    async fn call_tool(
        &mut self,
        tool_name: &str,
        arguments: Value,
        timeout_seconds: u64,
    ) -> Result<Value> {
        self.ensure_initialized(timeout_seconds).await?;
        self.send_request(
            "tools/call",
            json!({
                "name": tool_name,
                "arguments": arguments,
            }),
            timeout_seconds,
        )
        .await
    }

    async fn read_resource(&mut self, uri: &str, timeout_seconds: u64) -> Result<Value> {
        self.ensure_initialized(timeout_seconds).await?;
        self.send_request("resources/read", json!({ "uri": uri }), timeout_seconds)
            .await
    }

    async fn shutdown(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            debug!(
                "mcp server '{}' already exited with status {}",
                self.server_name, status
            );
            return Ok(());
        }
        self.child
            .kill()
            .await
            .with_context(|| format!("failed to terminate mcp server '{}'", self.server_name))?;
        Ok(())
    }

    async fn ensure_initialized(&mut self, timeout_seconds: u64) -> Result<()> {
        self.assert_process_alive()?;
        if self.initialized {
            return Ok(());
        }

        let init_timeout = self.startup_timeout_seconds.max(timeout_seconds).max(1);
        self.send_request(
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "maid",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
            init_timeout,
        )
        .await?;
        self.send_notification("notifications/initialized", json!({}))
            .await?;
        self.initialized = true;
        Ok(())
    }

    async fn send_notification(&mut self, method: &str, params: Value) -> Result<()> {
        self.assert_process_alive()?;
        let payload = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let encoded =
            serde_json::to_string(&payload).context("failed to encode mcp notification")?;
        self.stdin
            .write_all(encoded.as_bytes())
            .await
            .with_context(|| {
                format!("failed to write mcp notification to '{}'", self.server_name)
            })?;
        self.stdin
            .write_all(b"\n")
            .await
            .with_context(|| format!("failed to write mcp newline to '{}'", self.server_name))?;
        self.stdin
            .flush()
            .await
            .with_context(|| format!("failed to flush mcp stdin '{}'", self.server_name))?;
        Ok(())
    }

    async fn send_request(
        &mut self,
        method: &str,
        params: Value,
        timeout_seconds: u64,
    ) -> Result<Value> {
        self.assert_process_alive()?;

        let request_id = self.next_request_id;
        self.next_request_id += 1;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        });
        let encoded = serde_json::to_string(&payload).context("failed to encode mcp request")?;
        self.stdin
            .write_all(encoded.as_bytes())
            .await
            .with_context(|| format!("failed to write mcp request to '{}'", self.server_name))?;
        self.stdin
            .write_all(b"\n")
            .await
            .with_context(|| format!("failed to write mcp newline to '{}'", self.server_name))?;
        self.stdin
            .flush()
            .await
            .with_context(|| format!("failed to flush mcp stdin '{}'", self.server_name))?;

        let mut line = String::new();
        loop {
            line.clear();
            let bytes = tokio::time::timeout(
                Duration::from_secs(timeout_seconds.max(1)),
                self.stdout.read_line(&mut line),
            )
            .await
            .map_err(|_| {
                anyhow!(
                    "mcp request '{}' timed out after {}s for server '{}'",
                    method,
                    timeout_seconds.max(1),
                    self.server_name
                )
            })?
            .with_context(|| format!("failed to read mcp response from '{}'", self.server_name))?;
            if bytes == 0 {
                return Err(anyhow!(
                    "mcp server '{}' closed stdout while waiting for '{}'",
                    self.server_name,
                    method
                ));
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let message: Value = serde_json::from_str(trimmed).with_context(|| {
                format!(
                    "invalid JSON-RPC message from mcp server '{}': {}",
                    self.server_name, trimmed
                )
            })?;
            let Some(message_id) = message.get("id") else {
                continue;
            };
            if message_id != &json!(request_id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(anyhow!(
                    "mcp server '{}' returned error for '{}': {}",
                    self.server_name,
                    method,
                    compact_json(error)
                ));
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    fn assert_process_alive(&mut self) -> Result<()> {
        if let Some(status) = self
            .child
            .try_wait()
            .with_context(|| format!("failed to poll mcp process '{}'", self.server_name))?
        {
            return Err(anyhow!(
                "mcp server '{}' exited with status {}",
                self.server_name,
                status
            ));
        }
        Ok(())
    }
}

fn parse_call_arguments(args: &BTreeMap<String, String>) -> Result<Map<String, Value>> {
    let mut out = Map::new();

    if let Some(raw_json) = args.get("arguments_json") {
        let parsed: Value = serde_json::from_str(raw_json)
            .context("argument 'arguments_json' must be valid JSON")?;
        let object = parsed
            .as_object()
            .ok_or_else(|| anyhow!("argument 'arguments_json' must be a JSON object"))?;
        for (key, value) in object {
            out.insert(key.clone(), value.clone());
        }
    }

    for (key, value) in args {
        let Some(arg_key) = key.strip_prefix("arg.") else {
            continue;
        };
        if arg_key.trim().is_empty() {
            return Err(anyhow!("argument key 'arg.' must include a field name"));
        }
        out.insert(arg_key.to_string(), parse_argument_value(value));
    }

    if out.is_empty() {
        for (key, value) in args {
            if key == "server" || key == "name" || key == "arguments_json" {
                continue;
            }
            out.insert(key.clone(), parse_argument_value(value));
        }
    }

    Ok(out)
}

fn parse_argument_value(value: &str) -> Value {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if trimmed.eq_ignore_ascii_case("null") {
        return Value::Null;
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
        return parsed;
    }
    Value::String(value.to_string())
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}
