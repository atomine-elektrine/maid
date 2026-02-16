mod cli;
mod config;
mod engine;
mod engine_tail;
mod mcp;
mod runtime;
mod service;
mod subagent;
mod task_commands;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, IsTerminal};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clap::Parser;
use cli::{
    AuditCommands, Cli, Commands, GroupCommands, McpCommands, PairingCommands, PluginCommands,
    PluginLockCommands, PluginRegistryCommands, PluginRouteCommands, PluginTrustCommands,
    TaskCommands, ToolCommands,
};
use config::AppConfig;
use engine::*;
use engine_tail::*;
use maid_channel_telegram::{
    TelegramActivationMode, TelegramBot, TelegramBotConfig, TelegramCommandHandler,
    TelegramDmPolicy, TelegramTask,
};
use maid_core::{
    CoreSettings, ModelProvider, ModelRunRequest, ModelRunResult, NewAudit, SandboxJobSpec,
    SandboxRuntime, Storage, TaskExecutionRequest, TaskExecutionResult, TaskExecutor, TaskStatus,
    TaskTrigger,
};
use maid_model::{EchoProvider, OpenAiConfig, OpenAiProvider};
use maid_plugin_sdk::{
    discover_plugins, generate_ed25519_keypair_pem, load_plugin, parse_kv_args,
    run_plugin_with_env, sign_plugin, verify_plugin_signature, write_plugin_signature,
    PluginContext, PluginRequest, PluginSpec,
};
use maid_sandbox::{build_runtime, RuntimeConfig, RuntimeKind};
use maid_scheduler::{Schedule, SchedulerEngine};
use maid_storage::{NewPluginInvocation, SqliteStore};
use reqwest::{Client, Url};
use runtime::{
    apply_config_path_from_env, build_scheduler_executor, build_service, build_telegram_runtime,
    format_scheduled_task_message, load_dotenv_file, parent_or_current, remediation_hint,
    run_dashboard, run_doctor, run_gateway, run_guide, run_health_checks, run_init_config,
    run_onboard, run_scheduler_daemon, run_serve, telegram_chat_id_from_group_name,
    truncate_for_telegram, write_default_config,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use service::{handle_service_command, handle_tunnel_command};
use subagent::handle_subagent_command;
use task_commands::{handle_task_command, prompt_with_default, schedule_from_human_or_rrule};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

#[derive(Clone)]
struct DynModelProvider {
    inner: Arc<dyn ModelProvider>,
}

#[async_trait]
impl ModelProvider for DynModelProvider {
    async fn run(&self, request: ModelRunRequest) -> Result<ModelRunResult> {
        self.inner.run(request).await
    }
}

#[derive(Clone)]
struct DynSandboxRuntime {
    inner: Arc<dyn SandboxRuntime>,
}

#[async_trait]
impl SandboxRuntime for DynSandboxRuntime {
    async fn run_job(&self, spec: SandboxJobSpec) -> Result<maid_core::SandboxJobResult> {
        self.inner.run_job(spec).await
    }
}

type AppService = maid_core::MaidService<SqliteStore, DynModelProvider, DynSandboxRuntime>;

#[derive(Clone)]
struct TelegramServiceAdapter {
    service: Arc<AppService>,
    cfg: AppConfig,
}

#[async_trait]
impl TelegramCommandHandler for TelegramServiceAdapter {
    async fn ensure_group_exists(&self, group_name: &str) -> Result<()> {
        self.service.ensure_group(group_name, "telegram").await?;
        Ok(())
    }

    async fn run_prompt(&self, group_name: &str, prompt: &str) -> Result<String> {
        run_prompt_with_auto_tools(
            &self.cfg,
            self.service.clone(),
            group_name,
            prompt,
            "telegram",
        )
        .await
    }

    async fn create_task(
        &self,
        group_name: &str,
        name: &str,
        schedule: &str,
        prompt: &str,
    ) -> Result<String> {
        // Keep Telegram UX closer to CLI: accept either an RRULE or a small set of human phrases
        // (e.g. "every 15 minutes") and normalize to RRULE before validation/storage.
        let schedule_rrule = schedule_from_human_or_rrule(schedule)?;
        Schedule::parse_rrule(&schedule_rrule)
            .with_context(|| format!("invalid schedule RRULE: {schedule_rrule}"))?;
        let task = self
            .service
            .create_task(group_name, name, &schedule_rrule, prompt, "telegram")
            .await?;
        Ok(task.id)
    }

    async fn list_tasks(&self, group_name: &str) -> Result<Vec<TelegramTask>> {
        let tasks = self.service.list_tasks(group_name).await?;
        Ok(tasks
            .into_iter()
            .map(|task| TelegramTask {
                id: task.id,
                name: task.name,
                status: task.status.as_str().to_string(),
                schedule: task.schedule_rrule,
            })
            .collect())
    }

    async fn delete_task(&self, task_id: &str) -> Result<bool> {
        self.service.delete_task(task_id, "telegram").await
    }

    async fn pause_task(&self, task_id: &str) -> Result<()> {
        self.service.pause_task(task_id, "telegram").await
    }

    async fn resume_task(&self, task_id: &str) -> Result<()> {
        self.service.resume_task(task_id, "telegram").await
    }

    async fn run_task_now(&self, task_id: &str) -> Result<String> {
        let result = self.service.run_task_now(task_id, "telegram").await?;
        let mut output = format!(
            "task run {} status={}",
            result.run_id,
            result.status.as_str()
        );
        if let Some(summary) = result.output_summary {
            output.push_str(&format!("\noutput:\n{summary}"));
        }
        if let Some(error) = result.error_text {
            output.push_str(&format!("\nerror:\n{error}"));
        }
        Ok(output)
    }

    async fn is_chat_authorized(&self, chat_id: i64) -> Result<bool> {
        self.service.is_telegram_chat_approved(chat_id).await
    }

    async fn issue_pairing_code(&self, chat_id: i64) -> Result<String> {
        let pairing = self
            .service
            .request_telegram_pairing(chat_id, "telegram")
            .await?;
        Ok(pairing.code)
    }

    async fn approve_pairing_code(&self, code: &str) -> Result<bool> {
        self.service
            .approve_telegram_pairing(code, "telegram")
            .await
    }
}

#[derive(Clone)]
struct SchedulerTaskExecutor {
    inner: Arc<AppService>,
    store: Arc<SqliteStore>,
    notifier: Option<TelegramNotifier>,
    events: Option<GatewayEvents>,
}

#[async_trait]
impl TaskExecutor for SchedulerTaskExecutor {
    async fn execute(&self, request: TaskExecutionRequest) -> Result<TaskExecutionResult> {
        let request_for_notify = request.clone();
        let result = self.inner.execute(request).await?;

        if !matches!(request_for_notify.trigger, TaskTrigger::Scheduled) {
            return Ok(result);
        }

        let task = match self.store.get_task(&request_for_notify.task_id).await? {
            Some(task) => task,
            None => return Ok(result),
        };
        let group = match self.store.get_group_by_id(&task.group_id).await? {
            Some(group) => group,
            None => return Ok(result),
        };

        if let Some(events) = &self.events {
            events.publish(json!({
                "type": "task.run.completed",
                "task_id": task.id,
                "task_name": task.name,
                "group": group.name,
                "run_id": result.run_id,
                "status": result.status.as_str(),
                "scheduled_for": request_for_notify.scheduled_for.map(|v| v.to_rfc3339()),
            }));
        }

        let Some(notifier) = &self.notifier else {
            return Ok(result);
        };
        let Some(chat_id) = telegram_chat_id_from_group_name(&group.name) else {
            return Ok(result);
        };

        let message = format_scheduled_task_message(&task.name, &result);
        if let Err(err) = notifier.send_message(chat_id, &message).await {
            warn!(
                "failed to push scheduled task update to telegram chat {}: {err:#}",
                chat_id
            );
        }

        Ok(result)
    }
}

#[derive(Clone)]
struct TelegramNotifier {
    client: Client,
    base_url: String,
    allowed_chat_ids: Option<std::collections::HashSet<i64>>,
}

impl TelegramNotifier {
    fn from_config(cfg: &AppConfig) -> Result<Option<Self>> {
        let Some(telegram_cfg) = &cfg.telegram else {
            return Ok(None);
        };

        let token = match std::env::var(&telegram_cfg.bot_token_env) {
            Ok(v) => v,
            Err(_) => {
                warn!(
                    "telegram notifications disabled: env var {} is not set",
                    telegram_cfg.bot_token_env
                );
                return Ok(None);
            }
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .context("failed to build telegram notifier HTTP client")?;
        Ok(Some(Self {
            client,
            base_url: format!("https://api.telegram.org/bot{token}"),
            allowed_chat_ids: telegram_cfg
                .allowed_chat_ids
                .clone()
                .map(|ids| ids.into_iter().collect()),
        }))
    }

    async fn send_message(&self, chat_id: i64, text: &str) -> Result<()> {
        if !self.is_chat_allowed(chat_id) {
            return Ok(());
        }

        let response = self
            .client
            .post(format!("{}/sendMessage", self.base_url))
            .json(&TelegramSendMessageRequest {
                chat_id,
                text: truncate_for_telegram(text),
            })
            .send()
            .await
            .context("telegram notifier sendMessage failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!(
                "telegram notifier sendMessage error ({status}): {body}"
            ));
        }

        Ok(())
    }

    fn is_chat_allowed(&self, chat_id: i64) -> bool {
        match &self.allowed_chat_ids {
            Some(ids) => ids.contains(&chat_id),
            None => true,
        }
    }
}

#[derive(Serialize)]
struct TelegramSendMessageRequest {
    chat_id: i64,
    text: String,
}

#[derive(Clone)]
struct GatewayEvents {
    tx: broadcast::Sender<String>,
}

impl GatewayEvents {
    fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    fn publish(&self, payload: serde_json::Value) {
        let _ = self.tx.send(payload.to_string());
    }

    fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

#[derive(Debug, Clone, Serialize)]
struct GatewayStatus {
    started_at: String,
    model_provider: String,
    runtime: String,
    scheduler_tick_seconds: u64,
    scheduler_max_concurrency: usize,
    telegram_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct GatewayCommand {
    cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PluginToolSession {
    version: u32,
    plugin_name: String,
    token: String,
    allowed_tools: Vec<String>,
    max_calls_per_minute: u32,
    issued_at: String,
    expires_at: String,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("Error: {err:#}");
        if let Some(hint) = remediation_hint(&err) {
            eprintln!("Fix: {hint}");
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .with_writer(io::stderr)
        .compact()
        .init();

    let mut cli = Cli::parse();
    load_dotenv_file(&PathBuf::from(".env"));
    apply_config_path_from_env(&mut cli);
    if let Some(parent) = cli.config.parent() {
        let config_env_path = parent.join(".env");
        if config_env_path != Path::new(".env") {
            load_dotenv_file(&config_env_path);
            apply_config_path_from_env(&mut cli);
        }
    }
    if matches!(&cli.command, Commands::Guide) {
        run_guide();
        return Ok(());
    }
    if let Commands::Init { template, force } = &cli.command {
        run_init_config(&cli.config, template, *force)?;
        return Ok(());
    }
    apply_config_path_from_env(&mut cli);
    std::env::set_var("MAID_CONFIG", cli.config.display().to_string());
    if matches!(&cli.command, Commands::Onboard { .. }) && !cli.config.exists() {
        write_default_config(&cli.config)?;
    }

    let cfg = AppConfig::load(&cli.config)?;

    std::fs::create_dir_all(parent_or_current(&cfg.database_path)?)
        .with_context(|| format!("failed to create db parent for {}", cfg.database_path))?;
    std::fs::create_dir_all(&cfg.group_root)
        .with_context(|| format!("failed to create group root {}", cfg.group_root))?;
    std::fs::create_dir_all(cfg.plugin_directory())
        .with_context(|| format!("failed to create plugins dir {}", cfg.plugin_directory()))?;

    let store = Arc::new(SqliteStore::connect(&cfg.database_path).await?);
    let migration_dir = cli
        .config
        .parent()
        .unwrap_or(Path::new("."))
        .join("migrations");
    store.apply_migrations_from_dir(&migration_dir).await?;

    match cli.command {
        Commands::Status { json } => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            run_status(&cfg, service, json).await?;
        }
        Commands::Guide => {
            unreachable!("handled before config load");
        }
        Commands::Init { .. } => {
            unreachable!("handled before config load");
        }
        Commands::Onboard { interactive } => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            run_onboard(&cfg, &cli.config, interactive, Some(service)).await?;
        }
        Commands::Doctor { json } => {
            run_doctor(&cfg, &cli.config, json).await?;
        }
        Commands::Plugin { command } => {
            handle_plugin_command(&cfg, &cli.config, store.clone(), command).await?;
        }
        Commands::Tool { command } => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            handle_tool_command(&cfg, service, command).await?;
        }
        Commands::Audit { command } => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            handle_audit_command(service, command).await?;
        }
        Commands::Group { command } => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            match command {
                GroupCommands::Create { name } => {
                    let group = service.create_group(&name, "cli").await?;
                    println!("created group '{}' ({})", group.name, group.id);
                }
                GroupCommands::List { json } => {
                    let groups = service.list_groups().await?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&groups)?);
                    } else if groups.is_empty() {
                        println!("no groups found");
                    } else {
                        let rows = groups
                            .into_iter()
                            .map(|group| vec![group.id, group.name, group.root_path])
                            .collect::<Vec<_>>();
                        print_table(&["ID", "NAME", "ROOT_PATH"], &rows);
                    }
                }
            }
        }
        Commands::Run { group, prompt } => {
            let service = build_service(&cfg, &cli.config, store.clone(), true)?;
            let output = run_prompt_with_auto_tools(&cfg, service, &group, &prompt, "cli").await?;
            println!("{output}");
        }
        Commands::Task { command } => {
            let needs_model = matches!(command, TaskCommands::RunNow { .. });
            let service = build_service(&cfg, &cli.config, store.clone(), needs_model)?;
            handle_task_command(service, command).await?;
        }
        Commands::Subagent { command } => {
            let service = build_service(&cfg, &cli.config, store.clone(), true)?;
            handle_subagent_command(&cfg, service, command).await?;
        }
        Commands::Pairing { command } => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            handle_pairing_command(service, command).await?;
        }
        Commands::Service { command } => {
            handle_service_command(command).await?;
        }
        Commands::Tunnel { command } => {
            handle_tunnel_command(command).await?;
        }
        Commands::Dashboard { port } => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            run_dashboard(&cfg, &cli.config, store.clone(), service, port).await?;
        }
        Commands::Health { gateway_port, json } => {
            run_health_checks(&cfg, gateway_port, json).await?;
        }
        Commands::Daemon => {
            validate_plugins_for_startup(&cfg)?;
            let service = build_service(&cfg, &cli.config, store.clone(), true)?;
            let scheduler_executor = build_scheduler_executor(&cfg, store.clone(), service, None)?;
            run_scheduler_daemon(&cfg, store.clone(), scheduler_executor).await?;
        }
        Commands::Telegram => {
            validate_plugins_for_startup(&cfg)?;
            let service = build_service(&cfg, &cli.config, store.clone(), true)?;
            let (bot, handler) = build_telegram_runtime(&cfg, service)?;
            bot.run_until_shutdown(handler).await?;
        }
        Commands::Serve => {
            validate_plugins_for_startup(&cfg)?;
            let service = build_service(&cfg, &cli.config, store.clone(), true)?;
            run_serve(&cfg, store.clone(), service, None).await?;
        }
        Commands::Gateway { port } => {
            validate_plugins_for_startup(&cfg)?;
            let service = build_service(&cfg, &cli.config, store.clone(), true)?;
            run_gateway(&cfg, store.clone(), service, port).await?;
        }
        Commands::Mcp { command } => match command {
            McpCommands::ServeStdio => {
                let service = build_service(&cfg, &cli.config, store.clone(), false)?;
                run_mcp_stdio_server(&cfg, service).await?;
            }
        },
    }

    Ok(())
}

async fn run_status(cfg: &AppConfig, service: Arc<AppService>, json: bool) -> Result<()> {
    let groups = service.list_groups().await?;
    let mut tasks_total = 0_usize;
    let mut tasks_active = 0_usize;
    let mut tasks_paused = 0_usize;
    for group in &groups {
        let tasks = service.list_tasks(&group.name).await?;
        tasks_total += tasks.len();
        for task in tasks {
            match task.status.as_str() {
                "ACTIVE" => tasks_active += 1,
                "PAUSED" => tasks_paused += 1,
                _ => {}
            }
        }
    }

    let plugins =
        discover_plugins_cached(Path::new(cfg.plugin_directory()), Duration::from_secs(5))?;
    let enabled_plugins = plugins
        .iter()
        .filter(|plugin| cfg.is_plugin_enabled(&plugin.manifest.name))
        .count();
    let enabled_plugin_names = plugins
        .iter()
        .filter(|plugin| cfg.is_plugin_enabled(&plugin.manifest.name))
        .map(|plugin| plugin.manifest.name.clone())
        .collect::<Vec<_>>();
    let pending_pairings = service.list_pending_telegram_pairings().await?.len();

    if json {
        let payload = json!({
            "runtime": cfg.runtime,
            "model_provider": cfg.model_provider_name(),
            "model_candidates": cfg.model_candidates(),
            "scheduler": {
                "tick_seconds": cfg.scheduler.tick_seconds,
                "max_concurrency": cfg.scheduler.max_concurrency,
            },
            "telegram": {
                "enabled": cfg.telegram.is_some(),
                "dm_policy": cfg.telegram_dm_policy(),
                "activation_mode": cfg.telegram_activation_mode(),
            },
            "tools_auto_router_enabled": cfg.tool_auto_router_enabled(),
            "mcp": {
                "enabled": cfg.mcp_enabled(),
                "servers": cfg.enabled_mcp_servers(),
                "request_timeout_seconds": cfg.mcp_request_timeout_seconds(),
            },
            "groups_total": groups.len(),
            "pending_pairings": pending_pairings,
            "tasks": {
                "total": tasks_total,
                "active": tasks_active,
                "paused": tasks_paused,
            },
            "plugins": {
                "directory": cfg.plugin_directory(),
                "total": plugins.len(),
                "enabled": enabled_plugins,
                "enabled_names": enabled_plugin_names,
            },
            "skills_enabled": cfg.enabled_skills(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("runtime: {}", cfg.runtime);
        println!("model_provider: {}", cfg.model_provider_name());
        println!("model_candidates: {}", cfg.model_candidates().join(", "));
        println!(
            "scheduler: tick={}s max_concurrency={}",
            cfg.scheduler.tick_seconds, cfg.scheduler.max_concurrency
        );
        println!(
            "telegram: {} (dm_policy={}, activation={})",
            if cfg.telegram.is_some() {
                "enabled"
            } else {
                "disabled"
            },
            cfg.telegram_dm_policy(),
            cfg.telegram_activation_mode()
        );
        println!(
            "tools_auto_router: {}",
            if cfg.tool_auto_router_enabled() {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "mcp: {} (servers={}, timeout={}s)",
            if cfg.mcp_enabled() {
                "enabled"
            } else {
                "disabled"
            },
            if cfg.enabled_mcp_servers().is_empty() {
                "(none)".to_string()
            } else {
                cfg.enabled_mcp_servers().join(", ")
            },
            cfg.mcp_request_timeout_seconds()
        );
        println!("groups: {}", groups.len());
        println!("pending_pairings: {}", pending_pairings);
        println!(
            "tasks: total={} active={} paused={}",
            tasks_total, tasks_active, tasks_paused
        );
        println!(
            "plugins: {} total / {} enabled ({})",
            plugins.len(),
            enabled_plugins,
            cfg.plugin_directory()
        );
        println!(
            "enabled_plugins: {}",
            if enabled_plugin_names.is_empty() {
                "(none)".to_string()
            } else {
                enabled_plugin_names.join(", ")
            }
        );
        println!("skills: {}", cfg.enabled_skills().join(", "));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct McpJsonRpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

async fn run_mcp_stdio_server(cfg: &AppConfig, service: Arc<AppService>) -> Result<()> {
    info!("starting mcp stdio server");
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut writer = tokio::io::stdout();

    while let Some(message) = read_mcp_stdin_message(&mut reader).await? {
        let response = handle_mcp_json_rpc_request(cfg, service.clone(), message).await?;
        if let Some(payload) = response {
            write_mcp_stdout_message(&mut writer, &payload).await?;
        }
    }

    info!("mcp stdio server stopped");
    Ok(())
}

async fn handle_mcp_json_rpc_request(
    cfg: &AppConfig,
    service: Arc<AppService>,
    message: Value,
) -> Result<Option<Value>> {
    let request: McpJsonRpcRequest = serde_json::from_value(message)
        .context("invalid JSON-RPC request payload for mcp stdio server")?;

    if request
        .jsonrpc
        .as_deref()
        .map(|v| v != "2.0")
        .unwrap_or(false)
    {
        return Ok(Some(mcp_error_response(
            request.id,
            -32600,
            "invalid jsonrpc version; expected '2.0'",
            None,
        )));
    }

    let method = request.method.trim();
    if method.is_empty() {
        return Ok(Some(mcp_error_response(
            request.id,
            -32600,
            "missing method",
            None,
        )));
    }

    if request.id.is_none() {
        if method == "notifications/initialized" {
            return Ok(None);
        }
        if method.starts_with("notifications/") {
            return Ok(None);
        }
    }

    let id = request.id.clone().unwrap_or(Value::Null);
    let params = request.params.unwrap_or_else(|| json!({}));

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {},
            },
            "serverInfo": {
                "name": "maid",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }),
        "ping" => json!({}),
        "tools/list" => {
            let tools = supported_tool_names()
                .iter()
                .map(|tool| {
                    json!({
                        "name": *tool,
                        "description": tool_summary(tool).unwrap_or(""),
                        "inputSchema": mcp_tool_input_schema(tool),
                    })
                })
                .collect::<Vec<_>>();
            json!({ "tools": tools })
        }
        "tools/call" => {
            let params_obj = params
                .as_object()
                .ok_or_else(|| anyhow!("mcp tools/call params must be a JSON object"))?;
            let tool_name = params_obj
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("mcp tools/call requires params.name"))?;
            let args = params_obj
                .get("arguments")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            let mut normalized_args = BTreeMap::new();
            for (key, raw_value) in args {
                if key.trim().is_empty() {
                    continue;
                }
                if let Some(value) = normalize_auto_tool_arg_value(&raw_value) {
                    normalized_args.insert(key, value);
                }
            }

            match execute_tool_call(cfg, service, tool_name, normalized_args, "mcp").await {
                Ok(payload) => json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&payload)?,
                    }],
                    "isError": false,
                    "maidResult": payload,
                }),
                Err(err) => json!({
                    "content": [{
                        "type": "text",
                        "text": format!("{err:#}"),
                    }],
                    "isError": true,
                }),
            }
        }
        "resources/list" => json!({ "resources": [] }),
        "resources/read" => json!({ "contents": [] }),
        "prompts/list" => json!({ "prompts": [] }),
        _ => {
            return Ok(Some(mcp_error_response(
                Some(id),
                -32601,
                &format!("method not found: {}", method),
                None,
            )));
        }
    };

    if request.id.is_none() {
        return Ok(None);
    }
    Ok(Some(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })))
}

fn mcp_error_response(id: Option<Value>, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error_obj = serde_json::Map::new();
    error_obj.insert("code".to_string(), json!(code));
    error_obj.insert("message".to_string(), json!(message));
    if let Some(data) = data {
        error_obj.insert("data".to_string(), data);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": Value::Object(error_obj),
    })
}

fn mcp_tool_input_schema(tool: &str) -> Value {
    let keys: &[&str] = match tool {
        "group.create" => &["name"],
        "run.prompt" => &["group", "prompt"],
        "task.list" => &["group"],
        "task.create" => &["group", "name", "schedule", "prompt"],
        "task.run_now" | "task.pause" | "task.resume" | "task.delete" => &["id"],
        "task.clear_group" => &["group"],
        "session.history" => &["group", "limit"],
        "session.send" => &["to_group", "prompt", "from_group"],
        "session.spawn" => &["name"],
        "webhook.register" => &[
            "name", "path", "group", "task_id", "prompt", "token", "enabled",
        ],
        "webhook.list" => &["include_disabled"],
        "webhook.delete" => &["id", "name", "path"],
        "fs.list" => &["group", "path", "include_hidden", "max_entries"],
        "fs.read" => &["group", "path", "max_bytes"],
        "fs.grep" => &["group", "pattern", "path", "ignore_case"],
        "fs.edit" => &["group", "path", "content", "mode"],
        "proc.start" => &["group", "command"],
        "proc.wait" => &["id", "timeout_seconds", "remove_on_exit"],
        "proc.kill" => &["id"],
        "proc.logs" => &["id", "max_bytes"],
        "ops.web_fetch" => &["url", "timeout_seconds", "max_bytes"],
        "ops.search" => &["query", "limit", "timeout_seconds"],
        "ops.grep" => &["group", "pattern", "path", "ignore_case"],
        "ops.code_analysis.latest" => &[
            "group",
            "workflow_id",
            "top_n",
            "include_markdown",
            "max_chars",
        ],
        "ops.code_analysis.list" => &["group", "limit"],
        "mcp.list_tools" => &["server"],
        "mcp.call" => &["server", "name", "arguments_json"],
        "mcp.read_resource" => &["server", "uri"],
        _ => &[],
    };

    let mut properties = serde_json::Map::new();
    for key in keys {
        properties.insert((*key).to_string(), json!({ "type": "string" }));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "additionalProperties": true,
    })
}

async fn read_mcp_stdin_message(reader: &mut BufReader<tokio::io::Stdin>) -> Result<Option<Value>> {
    let mut first_line = String::new();
    loop {
        first_line.clear();
        let read = reader.read_line(&mut first_line).await?;
        if read == 0 {
            return Ok(None);
        }
        if !first_line.trim().is_empty() {
            break;
        }
    }

    let trimmed = first_line.trim_end_matches(&['\r', '\n'][..]);
    if trimmed.starts_with('{') {
        let parsed: Value =
            serde_json::from_str(trimmed).context("failed to parse mcp JSON line payload")?;
        return Ok(Some(parsed));
    }

    let (header_name, header_value) = trimmed
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid mcp header line: {}", trimmed))?;
    if !header_name.trim().eq_ignore_ascii_case("content-length") {
        return Err(anyhow!(
            "expected Content-Length header, got {}",
            header_name
        ));
    }
    let content_length = header_value
        .trim()
        .parse::<usize>()
        .context("invalid Content-Length value")?;

    loop {
        let mut header = String::new();
        let read = reader.read_line(&mut header).await?;
        if read == 0 {
            return Err(anyhow!("unexpected EOF while reading mcp headers"));
        }
        if header.trim().is_empty() {
            break;
        }
    }

    let mut body = vec![0_u8; content_length];
    reader
        .read_exact(&mut body)
        .await
        .context("failed to read mcp frame body")?;
    let payload = String::from_utf8(body).context("mcp frame body is not valid utf-8")?;
    let parsed: Value =
        serde_json::from_str(&payload).context("failed to parse mcp JSON payload")?;
    Ok(Some(parsed))
}

async fn write_mcp_stdout_message(writer: &mut tokio::io::Stdout, payload: &Value) -> Result<()> {
    let body = serde_json::to_vec(payload).context("failed to encode mcp response")?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer
        .write_all(header.as_bytes())
        .await
        .context("failed to write mcp response header")?;
    writer
        .write_all(&body)
        .await
        .context("failed to write mcp response body")?;
    writer
        .flush()
        .await
        .context("failed to flush mcp response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_versions_prefers_higher_numeric() {
        assert_eq!(
            compare_versions("1.2.0", "1.1.9"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(compare_versions("2.0.0", "2.0.1"), std::cmp::Ordering::Less);
        assert_eq!(
            compare_versions("1.0.0", "1.0.0"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn parse_http_target_extracts_query() {
        let (path, query) = runtime::parse_http_target("/api/tasks?group=work&limit=10").unwrap();
        assert_eq!(path, "/api/tasks");
        assert_eq!(query.get("group").map(String::as_str), Some("work"));
        assert_eq!(query.get("limit").map(String::as_str), Some("10"));
    }

    #[test]
    fn select_registry_entry_chooses_latest() {
        let entries = vec![
            PluginRegistryEntry {
                name: "echo".to_string(),
                version: "0.1.0".to_string(),
                description: None,
                source: "/tmp/echo-0.1.0".to_string(),
                subdir: None,
                publisher: None,
                categories: None,
                tags: None,
                capabilities: None,
                min_maid_version: None,
                license: None,
                homepage: None,
                checksum_sha256: None,
                published_at: None,
                signing_key_id: None,
                signature: None,
                provenance: None,
                security_contact: None,
                update_channel: None,
            },
            PluginRegistryEntry {
                name: "echo".to_string(),
                version: "0.2.0".to_string(),
                description: None,
                source: "/tmp/echo-0.2.0".to_string(),
                subdir: None,
                publisher: None,
                categories: None,
                tags: None,
                capabilities: None,
                min_maid_version: None,
                license: None,
                homepage: None,
                checksum_sha256: None,
                published_at: None,
                signing_key_id: None,
                signature: None,
                provenance: None,
                security_contact: None,
                update_channel: None,
            },
        ];
        let selected = select_registry_entry(&entries, "echo", None).unwrap();
        assert_eq!(selected.version, "0.2.0");
    }

    #[test]
    fn parse_auto_action_plan_coerces_non_string_args() {
        let raw = r#"{
            "rationale":"mix tools and plugins",
            "tools":[
                {"tool":"ops.search","args":{"query":"rust sqlite","limit":3}}
            ],
            "plugins":[
                {"plugin":"code-analysis","command":"analyze","args":{"repo_path":"/tmp/repo","depth":2}}
            ]
        }"#;
        let parsed = parse_auto_action_plan(raw).unwrap();
        assert_eq!(parsed.tools.len(), 1);
        assert_eq!(parsed.plugins.len(), 1);
        assert_eq!(
            parsed.tools[0].args.get("limit").map(String::as_str),
            Some("3")
        );
        assert_eq!(
            parsed.plugins[0].args.get("depth").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn parse_subagent_plan_extracts_steps() {
        let raw = r#"{
            "rationale":"split work",
            "final_instruction":"compose final answer",
            "steps":[
                {"name":"research","prompt":"Gather facts"},
                {"name":"draft","prompt":"Draft response"}
            ]
        }"#;
        let parsed = subagent::parse_subagent_plan(raw).unwrap();
        assert_eq!(parsed.steps.len(), 2);
        assert_eq!(parsed.steps[0].name, "research");
        assert_eq!(parsed.steps[1].prompt, "Draft response");
    }

    #[test]
    fn parse_bing_rss_items_extracts_fields() {
        let xml = r#"<rss><channel>
        <item><title>One</title><link>https://example.com</link><description>Desc &amp; more</description></item>
        <item><title>Two</title><link>https://example.org</link><description>Another</description></item>
        </channel></rss>"#;
        let mut parsed = Vec::new();
        for item in xml.split("<item>").skip(1) {
            let title = extract_xml_tag(item, "title").unwrap_or_default();
            let link = extract_xml_tag(item, "link").unwrap_or_default();
            let snippet = extract_xml_tag(item, "description").unwrap_or_default();
            parsed.push((
                xml_unescape(&title),
                xml_unescape(&link),
                xml_unescape(&snippet),
            ));
        }
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "One");
        assert_eq!(parsed[0].2, "Desc & more");
        assert_eq!(parsed[1].1, "https://example.org");
    }

    #[test]
    fn schedule_parser_supports_human_phrases() {
        assert_eq!(
            schedule_from_human_or_rrule("every 15 minutes").unwrap(),
            "FREQ=MINUTELY;INTERVAL=15"
        );
        assert_eq!(
            schedule_from_human_or_rrule("every hour").unwrap(),
            "FREQ=HOURLY;INTERVAL=1"
        );
        assert_eq!(
            schedule_from_human_or_rrule("every weekday at 9am").unwrap(),
            "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;BYHOUR=9;BYMINUTE=0"
        );
    }

    #[test]
    fn parse_time_supports_am_pm_and_24h() {
        assert_eq!(task_commands::parse_time_of_day("9am").unwrap(), (9, 0));
        assert_eq!(
            task_commands::parse_time_of_day("9:30pm").unwrap(),
            (21, 30)
        );
        assert_eq!(task_commands::parse_time_of_day("06:05").unwrap(), (6, 5));
    }

    #[test]
    fn tool_name_normalizer_accepts_kebab_and_snake() {
        assert_eq!(normalize_tool_name("task.run_now"), Some("task.run_now"));
        assert_eq!(normalize_tool_name("task.run-now"), Some("task.run_now"));
        assert_eq!(
            normalize_tool_name("ops.code-analysis.latest"),
            Some("ops.code_analysis.latest")
        );
        assert_eq!(
            normalize_tool_name("mcp.list-tools"),
            Some("mcp.list_tools")
        );
        assert_eq!(normalize_tool_name("unknown.tool"), None);
    }

    #[test]
    fn tool_name_rendering_includes_aliases_for_mixed_style_tools() {
        let rendered = render_tool_name_with_aliases("task.run_now");
        assert!(rendered.contains("task.run_now"));
        assert!(rendered.contains("task.run-now"));
        assert_eq!(render_tool_name_with_aliases("group.list"), "group.list");
        let mcp_rendered = render_tool_name_with_aliases("mcp.list_tools");
        assert!(mcp_rendered.contains("mcp.list-tools"));
    }
}
