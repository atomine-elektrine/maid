mod config;

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use config::AppConfig;
use maid_channel_telegram::{
    TelegramActivationMode, TelegramBot, TelegramBotConfig, TelegramCommandHandler,
    TelegramDmPolicy, TelegramTask,
};
use maid_core::{
    CoreSettings, ModelProvider, ModelRunRequest, ModelRunResult, NewAudit, SandboxJobSpec,
    SandboxRuntime, Storage, TaskExecutionRequest, TaskExecutionResult, TaskExecutor, TaskTrigger,
};
use maid_model::{EchoProvider, OpenAiConfig, OpenAiProvider};
use maid_sandbox::{build_runtime, RuntimeConfig, RuntimeKind};
use maid_scheduler::{Schedule, SchedulerEngine};
use maid_plugin_sdk::{
    discover_plugins, generate_ed25519_keypair_pem, load_plugin, parse_kv_args, run_plugin_with_env,
    sign_plugin, verify_plugin_signature, write_plugin_signature, PluginContext, PluginRequest,
    PluginSpec,
};
use maid_storage::SqliteStore;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(name = "maid")]
#[command(about = "maid: modular local-first assistant core")]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    Group {
        #[command(subcommand)]
        command: GroupCommands,
    },
    Run {
        #[arg(long)]
        group: String,
        #[arg(long)]
        prompt: String,
    },
    Task {
        #[command(subcommand)]
        command: TaskCommands,
    },
    Subagent {
        #[command(subcommand)]
        command: SubagentCommands,
    },
    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
    },
    Tool {
        #[command(subcommand)]
        command: ToolCommands,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    Pairing {
        #[command(subcommand)]
        command: PairingCommands,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommands,
    },
    Dashboard {
        #[arg(long, default_value_t = 18790)]
        port: u16,
    },
    Health {
        #[arg(long, default_value_t = 18789)]
        gateway_port: u16,
    },
    Onboard,
    Doctor,
    Daemon,
    Telegram,
    Serve,
    Gateway {
        #[arg(long, default_value_t = 18789)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum GroupCommands {
    Create { name: String },
    List,
}

#[derive(Subcommand)]
enum TaskCommands {
    Create {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        schedule: String,
        #[arg(long)]
        prompt: String,
    },
    QuickAdd {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        every_minutes: u64,
        #[arg(long)]
        prompt: String,
    },
    List {
        #[arg(long)]
        group: String,
    },
    Pause {
        #[arg(long)]
        id: String,
    },
    Resume {
        #[arg(long)]
        id: String,
    },
    RunNow {
        #[arg(long)]
        id: String,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
    Clear {
        #[arg(long)]
        group: String,
    },
    ClearAll,
}

#[derive(Subcommand)]
enum SubagentCommands {
    Run {
        #[arg(long)]
        group: String,
        #[arg(long)]
        prompt: String,
        #[arg(long, default_value_t = 3)]
        max_steps: usize,
    },
}

#[derive(Subcommand)]
enum PluginCommands {
    Registry {
        #[command(subcommand)]
        command: PluginRegistryCommands,
    },
    Enable {
        #[arg(long)]
        name: String,
    },
    Disable {
        #[arg(long)]
        name: String,
    },
    Keygen {
        #[arg(long, default_value = "keys")]
        out_dir: PathBuf,
        #[arg(long, default_value = "plugin-signing")]
        name: String,
    },
    List {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Validate {
        #[arg(long)]
        name: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Run {
        #[arg(long)]
        name: String,
        #[arg(long)]
        command: String,
        #[arg(long = "arg")]
        args: Vec<String>,
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Sign {
        #[arg(long)]
        name: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        private_key_file: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Verify {
        #[arg(long)]
        name: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PluginRegistryCommands {
    List {
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        index: Option<PathBuf>,
    },
    Install {
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Update {
        #[arg(long)]
        name: String,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ToolCommands {
    List,
    Call {
        #[arg(long)]
        tool: String,
        #[arg(long = "arg")]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    List {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        actor: Option<String>,
    },
}

#[derive(Subcommand)]
enum PairingCommands {
    List,
    Approve {
        #[arg(long)]
        code: String,
    },
}

#[derive(Subcommand)]
enum ServiceCommands {
    Install {
        #[arg(long, default_value = "auto")]
        platform: String,
        #[arg(long, default_value = "maid")]
        name: String,
        #[arg(long, default_value_t = 18789)]
        gateway_port: u16,
        #[arg(long, default_value = "deploy/services")]
        output_dir: PathBuf,
    },
    Status,
}

#[derive(Subcommand)]
enum TunnelCommands {
    Command {
        #[arg(long, default_value = "tailscale")]
        mode: String,
        #[arg(long, default_value_t = 18789)]
        gateway_port: u16,
        #[arg(long)]
        ssh_host: Option<String>,
    },
}

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
        Schedule::parse_rrule(schedule)
            .with_context(|| format!("invalid schedule RRULE: {schedule}"))?;
        let task = self
            .service
            .create_task(group_name, name, schedule, prompt, "telegram")
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
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .compact()
        .init();

    let mut cli = Cli::parse();
    if !cli.config.exists() {
        if let Ok(from_env) = std::env::var("MAID_CONFIG") {
            let from_env_path = PathBuf::from(from_env);
            if from_env_path.exists() {
                cli.config = from_env_path;
            }
        }
    }
    if matches!(&cli.command, Commands::Onboard) && !cli.config.exists() {
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
        Commands::Status => {
            let service = build_service(&cfg, &cli.config, store.clone(), false)?;
            run_status(&cfg, service).await?;
        }
        Commands::Onboard => {
            run_onboard(&cfg, &cli.config).await?;
        }
        Commands::Doctor => {
            run_doctor(&cfg, &cli.config).await?;
        }
        Commands::Plugin { command } => {
            handle_plugin_command(&cfg, &cli.config, command).await?;
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
                GroupCommands::List => {
                    let groups = service.list_groups().await?;
                    for group in groups {
                        println!("{}\t{}\t{}", group.id, group.name, group.root_path);
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
        Commands::Health { gateway_port } => {
            run_health_checks(&cfg, gateway_port).await?;
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
    }

    Ok(())
}

async fn handle_task_command(service: Arc<AppService>, command: TaskCommands) -> Result<()> {
    match command {
        TaskCommands::Create {
            group,
            name,
            schedule,
            prompt,
        } => {
            Schedule::parse_rrule(&schedule)
                .with_context(|| format!("invalid schedule RRULE: {}", schedule))?;

            let task = service
                .create_task(&group, &name, &schedule, &prompt, "cli")
                .await?;
            println!("created task '{}' ({})", task.name, task.id);
        }
        TaskCommands::QuickAdd {
            group,
            name,
            every_minutes,
            prompt,
        } => {
            if every_minutes == 0 || every_minutes > 1_440 {
                return Err(anyhow!(
                    "--every-minutes must be between 1 and 1440 (got {every_minutes})"
                ));
            }
            let schedule = format!("FREQ=MINUTELY;INTERVAL={every_minutes}");
            Schedule::parse_rrule(&schedule)
                .with_context(|| format!("invalid generated schedule RRULE: {}", schedule))?;
            let task = service
                .create_task(&group, &name, &schedule, &prompt, "cli")
                .await?;
            println!(
                "created task '{}' ({}) with schedule {}",
                task.name, task.id, schedule
            );
        }
        TaskCommands::List { group } => {
            let tasks = service.list_tasks(&group).await?;
            for task in tasks {
                println!(
                    "{}\t{}\t{}\t{}",
                    task.id,
                    task.name,
                    task.status.as_str(),
                    task.schedule_rrule
                );
            }
        }
        TaskCommands::Pause { id } => {
            service.pause_task(&id, "cli").await?;
            println!("paused task {id}");
        }
        TaskCommands::Resume { id } => {
            service.resume_task(&id, "cli").await?;
            println!("resumed task {id}");
        }
        TaskCommands::RunNow { id } => {
            let result = service.run_task_now(&id, "cli").await?;
            println!(
                "task run {} status={}{}{}",
                result.run_id,
                result.status.as_str(),
                result
                    .output_summary
                    .as_ref()
                    .map(|s| format!("\noutput:\n{s}"))
                    .unwrap_or_default(),
                result
                    .error_text
                    .as_ref()
                    .map(|s| format!("\nerror:\n{s}"))
                    .unwrap_or_default(),
            );
        }
        TaskCommands::Delete { id } => {
            let deleted = service.delete_task(&id, "cli").await?;
            if deleted {
                println!("deleted task {id}");
            } else {
                println!("task not found: {id}");
            }
        }
        TaskCommands::Clear { group } => {
            let deleted = service.clear_tasks_for_group(&group, "cli").await?;
            println!("cleared {deleted} task(s) in group '{group}'");
        }
        TaskCommands::ClearAll => {
            let deleted = service.clear_all_tasks("cli").await?;
            println!("cleared {deleted} task(s) across all groups");
        }
    }
    Ok(())
}

async fn run_status(cfg: &AppConfig, service: Arc<AppService>) -> Result<()> {
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

    let plugins = discover_plugins(Path::new(cfg.plugin_directory()))?;
    let enabled_plugins = plugins
        .iter()
        .filter(|plugin| cfg.is_plugin_enabled(&plugin.manifest.name))
        .count();

    println!("runtime: {}", cfg.runtime);
    println!("groups: {}", groups.len());
    println!("tasks_total: {}", tasks_total);
    println!("tasks_active: {}", tasks_active);
    println!("tasks_paused: {}", tasks_paused);
    println!(
        "plugins: {} total / {} enabled ({})",
        plugins.len(),
        enabled_plugins,
        cfg.plugin_directory()
    );
    println!("skills: {}", cfg.enabled_skills().join(", "));
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct SubagentPlan {
    #[serde(default)]
    rationale: Option<String>,
    #[serde(default)]
    final_instruction: Option<String>,
    #[serde(default)]
    steps: Vec<SubagentStep>,
}

#[derive(Debug, Clone, Deserialize)]
struct SubagentStep {
    name: String,
    prompt: String,
}

async fn handle_subagent_command(
    cfg: &AppConfig,
    service: Arc<AppService>,
    command: SubagentCommands,
) -> Result<()> {
    match command {
        SubagentCommands::Run {
            group,
            prompt,
            max_steps,
        } => {
            let bounded_steps = max_steps.clamp(1, 8);
            let plan = request_subagent_plan(service.clone(), &group, &prompt, bounded_steps).await?;
            let mut steps = plan.steps;
            if steps.is_empty() {
                steps.push(SubagentStep {
                    name: "direct".to_string(),
                    prompt: prompt.clone(),
                });
            }
            steps.truncate(bounded_steps);

            let mut step_outputs = Vec::new();
            for (idx, step) in steps.iter().enumerate() {
                let step_prompt = format!(
                    "Subagent executor step {}/{}: {}\n\nTask:\n{}\n\nOriginal user goal:\n{}",
                    idx + 1,
                    steps.len(),
                    step.name,
                    step.prompt,
                    prompt
                );
                let output = run_prompt_with_auto_tools(
                    cfg,
                    service.clone(),
                    &group,
                    &step_prompt,
                    "subagent-executor",
                )
                .await?;
                step_outputs.push(json!({
                    "step": idx + 1,
                    "name": step.name,
                    "output": truncate_line(&output, 1800),
                }));
            }

            let final_instruction = plan
                .final_instruction
                .unwrap_or_else(|| "Synthesize a final answer for the user goal.".to_string());
            let final_prompt = format!(
                "You are the finalizer in a planner/executor subagent pipeline.\n\
Original user goal:\n{}\n\n\
Planner rationale:\n{}\n\n\
Executor outputs (JSON):\n{}\n\n\
Instruction:\n{}\n\n\
Return the final user-facing answer only.",
                prompt,
                plan.rationale.unwrap_or_else(|| "none".to_string()),
                serde_json::to_string_pretty(&step_outputs)?,
                final_instruction
            );
            let final_output = run_prompt_with_auto_tools(
                cfg,
                service.clone(),
                &group,
                &final_prompt,
                "subagent-finalizer",
            )
            .await?;

            let _ = service
                .store
                .insert_audit(NewAudit {
                    group_id: None,
                    action: "SUBAGENT_RUN".to_string(),
                    actor: "cli".to_string(),
                    result: "SUCCESS".to_string(),
                    created_at: Utc::now(),
                    metadata_json: Some(json!({
                        "group": group,
                        "max_steps": bounded_steps,
                        "executed_steps": step_outputs.len(),
                    })),
                })
                .await;

            println!("{final_output}");
        }
    }
    Ok(())
}

async fn request_subagent_plan(
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    max_steps: usize,
) -> Result<SubagentPlan> {
    let planner_prompt = format!(
        "You are a planning subagent.\n\
Return ONLY JSON with schema:\n\
{{\"rationale\":\"short reason\",\"final_instruction\":\"string\",\"steps\":[{{\"name\":\"short\",\"prompt\":\"exact task\"}}]}}\n\
Rules:\n\
- At most {} steps.\n\
- Keep steps concrete and executable.\n\
- If no decomposition is needed, return one direct step.\n\
- No markdown, no extra text.\n\n\
Group: {}\n\
User goal:\n{}",
        max_steps, group_name, prompt
    );

    let output = service
        .model
        .run(ModelRunRequest {
            group_name: group_name.to_string(),
            prompt: planner_prompt,
            history: Vec::new(),
        })
        .await?
        .output_text;

    parse_subagent_plan(&output)
}

fn parse_subagent_plan(raw: &str) -> Result<SubagentPlan> {
    let parsed = serde_json::from_str::<serde_json::Value>(raw.trim()).or_else(|_| {
        let extracted = extract_json_object(raw)
            .ok_or_else(|| anyhow!("subagent planner did not return valid JSON"))?;
        serde_json::from_str::<serde_json::Value>(&extracted)
            .context("failed to parse subagent planner JSON")
    })?;
    normalize_subagent_plan(parsed)
}

fn normalize_subagent_plan(value: serde_json::Value) -> Result<SubagentPlan> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("subagent planner payload must be a JSON object"))?;
    let rationale = object
        .get("rationale")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let final_instruction = object
        .get("final_instruction")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let mut steps = Vec::new();
    if let Some(items) = object.get("steps").and_then(|v| v.as_array()) {
        for item in items {
            let Some(step_obj) = item.as_object() else {
                continue;
            };
            let Some(name) = step_obj.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(prompt) = step_obj.get("prompt").and_then(|v| v.as_str()) else {
                continue;
            };
            if name.trim().is_empty() || prompt.trim().is_empty() {
                continue;
            }
            steps.push(SubagentStep {
                name: name.to_string(),
                prompt: prompt.to_string(),
            });
        }
    }

    Ok(SubagentPlan {
        rationale,
        final_instruction,
        steps,
    })
}

async fn run_prompt_with_auto_tools(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    actor: &str,
) -> Result<String> {
    let skill_context = match auto_invoke_skills_for_prompt(cfg, service.clone(), group_name, actor).await
    {
        Ok(context) => context,
        Err(err) => {
            warn!("{actor} skill context failed: {err:#}");
            None
        }
    };

    let tool_context = if cfg.tool_auto_router_enabled() {
        auto_route_tools_for_prompt(cfg, service.clone(), group_name, prompt, actor).await
    } else {
        Ok(None)
    };

    match tool_context {
        Ok(tool_context) => {
            let mut sections = Vec::new();
            if let Some(context) = skill_context {
                sections.push(("Skill context", context));
            }
            if let Some(context) = tool_context {
                sections.push(("Tool context", context));
            }
            if sections.is_empty() {
                return service.run_prompt(group_name, prompt, actor).await;
            }

            let mut augmented_prompt = prompt.to_string();
            for (label, context) in sections {
                augmented_prompt.push_str("\n\n");
                augmented_prompt.push_str(label);
                augmented_prompt.push_str(":\n");
                augmented_prompt.push_str(&context);
            }
            augmented_prompt.push_str("\n\nUse this context if relevant.");
            service.run_prompt(group_name, &augmented_prompt, actor).await
        }
        Err(err) => {
            warn!("{actor} auto-router failed: {err:#}");
            service.run_prompt(group_name, prompt, actor).await
        }
    }
}

async fn handle_pairing_command(service: Arc<AppService>, command: PairingCommands) -> Result<()> {
    match command {
        PairingCommands::List => {
            let rows = service.list_pending_telegram_pairings().await?;
            if rows.is_empty() {
                println!("no pending pairing requests");
            } else {
                for pairing in rows {
                    println!(
                        "{}\tchat={}\trequested_at={}",
                        pairing.code,
                        pairing.chat_id,
                        pairing.requested_at.to_rfc3339()
                    );
                }
            }
        }
        PairingCommands::Approve { code } => {
            let approved = service.approve_telegram_pairing(&code, "cli").await?;
            if approved {
                println!("approved pairing code {}", code.trim().to_uppercase());
            } else {
                println!("pairing code not found or already approved");
            }
        }
    }
    Ok(())
}

async fn handle_service_command(command: ServiceCommands) -> Result<()> {
    match command {
        ServiceCommands::Install {
            platform,
            name,
            gateway_port,
            output_dir,
        } => {
            install_service_templates(&platform, &name, gateway_port, &output_dir)?;
        }
        ServiceCommands::Status => {
            report_service_status().await?;
        }
    }
    Ok(())
}

async fn handle_tunnel_command(command: TunnelCommands) -> Result<()> {
    match command {
        TunnelCommands::Command {
            mode,
            gateway_port,
            ssh_host,
        } => {
            let normalized = mode.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "tailscale" => {
                    println!("tailscale tunnel commands:");
                    println!("1) tailscale serve --https=443 http://127.0.0.1:{gateway_port}");
                    println!("2) tailscale funnel 443 on   # optional public access");
                    println!("3) tailscale status");
                }
                "ssh" => {
                    let host = ssh_host.ok_or_else(|| {
                        anyhow!("--ssh-host is required when --mode ssh (example: user@host)")
                    })?;
                    println!("ssh tunnel command:");
                    println!("ssh -N -L {gateway_port}:127.0.0.1:{gateway_port} {host}");
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported tunnel mode '{}'; expected tailscale or ssh",
                        mode
                    ));
                }
            }
        }
    }
    Ok(())
}

fn install_service_templates(
    platform: &str,
    name: &str,
    gateway_port: u16,
    output_dir: &Path,
) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("service name must not be empty"));
    }

    let resolved_platform = match platform.trim().to_ascii_lowercase().as_str() {
        "auto" => {
            if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            }
        }
        "macos" | "darwin" | "launchd" => "macos",
        "linux" | "systemd" => "linux",
        other => {
            return Err(anyhow!(
                "unsupported platform '{}'; expected auto, macos, or linux",
                other
            ));
        }
    };

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let exe = std::env::current_exe().context("failed to resolve maid executable path")?;
    let config_path = std::env::var("MAID_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let runner_script = output_dir.join(format!("{name}-run.sh"));
    let health_script = output_dir.join(format!("{name}-health.sh"));

    let runner = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nexec \"{}\" --config \"{}\" gateway --port {}\n",
        exe.display(),
        config_path,
        gateway_port
    );
    std::fs::write(&runner_script, runner)
        .with_context(|| format!("failed to write {}", runner_script.display()))?;

    let health = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n\"{}\" --config \"{}\" health --gateway-port {}\n",
        exe.display(),
        config_path,
        gateway_port
    );
    std::fs::write(&health_script, health)
        .with_context(|| format!("failed to write {}", health_script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut run_perms = std::fs::metadata(&runner_script)
            .with_context(|| format!("failed to stat {}", runner_script.display()))?
            .permissions();
        run_perms.set_mode(0o755);
        std::fs::set_permissions(&runner_script, run_perms)
            .with_context(|| format!("failed to chmod {}", runner_script.display()))?;

        let mut health_perms = std::fs::metadata(&health_script)
            .with_context(|| format!("failed to stat {}", health_script.display()))?
            .permissions();
        health_perms.set_mode(0o755);
        std::fs::set_permissions(&health_script, health_perms)
            .with_context(|| format!("failed to chmod {}", health_script.display()))?;
    }

    match resolved_platform {
        "macos" => {
            let plist_path = output_dir.join(format!("{name}.plist"));
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{name}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>{script}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log_dir}/{name}.out.log</string>
  <key>StandardErrorPath</key>
  <string>{log_dir}/{name}.err.log</string>
</dict>
</plist>
"#,
                script = runner_script.display(),
                log_dir = output_dir.display()
            );
            std::fs::write(&plist_path, plist)
                .with_context(|| format!("failed to write {}", plist_path.display()))?;
            println!("generated launchd files:");
            println!("- {}", plist_path.display());
            println!("- {}", runner_script.display());
            println!("- {}", health_script.display());
            println!();
            println!("install:");
            println!("launchctl bootstrap gui/$(id -u) {}", plist_path.display());
            println!("launchctl enable gui/$(id -u)/{name}");
            println!("launchctl kickstart -k gui/$(id -u)/{name}");
        }
        "linux" => {
            let unit_path = output_dir.join(format!("{name}.service"));
            let unit = format!(
                r#"[Unit]
Description=maid gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={}
Restart=always
RestartSec=3
Environment=RUST_LOG=info
WorkingDirectory={}

[Install]
WantedBy=default.target
"#,
                runner_script.display(),
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .display()
            );
            std::fs::write(&unit_path, unit)
                .with_context(|| format!("failed to write {}", unit_path.display()))?;
            println!("generated systemd files:");
            println!("- {}", unit_path.display());
            println!("- {}", runner_script.display());
            println!("- {}", health_script.display());
            println!();
            println!("install:");
            println!("mkdir -p ~/.config/systemd/user");
            println!(
                "cp {} ~/.config/systemd/user/{}.service",
                unit_path.display(),
                name
            );
            println!("systemctl --user daemon-reload");
            println!("systemctl --user enable --now {name}.service");
        }
        _ => unreachable!(),
    }

    Ok(())
}

async fn report_service_status() -> Result<()> {
    let launchctl_uid = StdCommand::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        });
    let launchctl = if let Some(uid) = launchctl_uid {
        StdCommand::new("launchctl")
            .arg("print")
            .arg(format!("gui/{uid}/maid"))
            .output()
    } else {
        Err(std::io::Error::other("uid unavailable"))
    };
    let systemd = StdCommand::new("systemctl")
        .args(["--user", "is-active", "maid.service"])
        .output();

    match launchctl {
        Ok(out) if out.status.success() => {
            println!("launchd: active");
        }
        Ok(_) => {
            println!("launchd: inactive");
        }
        Err(_) => {
            println!("launchd: unavailable");
        }
    }

    match systemd {
        Ok(out) => {
            let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() {
                println!("systemd: {}", value);
            } else if value.is_empty() {
                println!("systemd: inactive");
            } else {
                println!("systemd: {}", value);
            }
        }
        Err(_) => {
            println!("systemd: unavailable");
        }
    }

    let gateway_ok = check_gateway_ping(18789).await;
    if gateway_ok {
        println!("gateway(127.0.0.1:18789): reachable");
    } else {
        println!("gateway(127.0.0.1:18789): unreachable");
    }

    Ok(())
}

async fn handle_plugin_command(
    cfg: &AppConfig,
    config_path: &Path,
    command: PluginCommands,
) -> Result<()> {
    match command {
        PluginCommands::Registry { command } => {
            handle_plugin_registry_command(cfg, command).await?;
        }
        PluginCommands::Enable { name } => {
            validate_plugin_name(&name)?;
            set_plugin_enabled_in_config(config_path, &name, true)?;
            println!("enabled plugin '{}' in {}", name, config_path.display());
        }
        PluginCommands::Disable { name } => {
            validate_plugin_name(&name)?;
            set_plugin_enabled_in_config(config_path, &name, false)?;
            println!("disabled plugin '{}' in {}", name, config_path.display());
        }
        PluginCommands::Keygen { out_dir, name } => {
            let (private_key, public_key) = generate_ed25519_keypair_pem()?;
            std::fs::create_dir_all(&out_dir).with_context(|| {
                format!("failed to create key output dir {}", out_dir.display())
            })?;
            let private_path = out_dir.join(format!("{name}.private.pem"));
            let public_path = out_dir.join(format!("{name}.public.pem"));
            std::fs::write(&private_path, private_key)
                .with_context(|| format!("failed to write {}", private_path.display()))?;
            std::fs::write(&public_path, public_key)
                .with_context(|| format!("failed to write {}", public_path.display()))?;
            println!("wrote private key: {}", private_path.display());
            println!("wrote public key: {}", public_path.display());
        }
        PluginCommands::List { dir } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let plugins = discover_plugins(&plugins_dir)?;
            if plugins.is_empty() {
                println!("no plugins found in {}", plugins_dir.display());
            } else {
                for plugin in plugins {
                    let enabled = if cfg.is_plugin_enabled(&plugin.manifest.name) {
                        "enabled"
                    } else {
                        "disabled"
                    };
                    println!(
                        "{}\t{}\t{}\t{}",
                        plugin.manifest.name,
                        plugin.manifest.version,
                        enabled,
                        plugin.manifest.description.unwrap_or_default()
                    );
                }
            }
        }
        PluginCommands::Validate { name, dir } => {
            ensure_plugin_enabled(cfg, &name)?;
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let plugin = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &plugin, false)?;
            println!(
                "valid plugin '{}' v{} ({})",
                plugin.manifest.name,
                plugin.manifest.version,
                plugin.manifest_path.display()
            );
        }
        PluginCommands::Sign {
            name,
            key_id,
            private_key_file,
            dir,
        } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let plugin = load_plugin(&plugins_dir, &name)?;
            if !private_key_file.exists() {
                return Err(anyhow!(
                    "private key file not found: {}",
                    private_key_file.display()
                ));
            }
            let signature = sign_plugin(&plugin, &key_id, &private_key_file)?;
            write_plugin_signature(&plugin.manifest_path, &key_id, &signature)?;
            println!(
                "signed plugin '{}' with key '{}' ({})",
                plugin.manifest.name,
                key_id,
                plugin.manifest_path.display()
            );
        }
        PluginCommands::Verify { name, dir } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let plugin = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &plugin, true)?;
            println!(
                "verified signature for plugin '{}' ({})",
                plugin.manifest.name,
                plugin.manifest_path.display()
            );
        }
        PluginCommands::Run {
            name,
            command,
            args,
            input,
            dir,
        } => {
            ensure_plugin_enabled(cfg, &name)?;
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let plugin = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &plugin, false)?;
            let args = parse_kv_args(&args)?;
            let request = PluginRequest {
                command,
                args,
                input,
                context: PluginContext {
                    actor: "cli".to_string(),
                    cwd: std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .display()
                        .to_string(),
                },
            };
            let bridge = create_plugin_tool_bridge_session(cfg, &plugin)?;
            let mut extra_env = vec![
                ("MAID_CONFIG".to_string(), config_path.display().to_string()),
                ("MAID_PLUGIN_NAME".to_string(), plugin.manifest.name.clone()),
            ];
            if let Ok(exe) = std::env::current_exe() {
                extra_env.push(("MAID_BIN".to_string(), exe.display().to_string()));
            }
            if let Some(session) = &bridge {
                extra_env.push((
                    "MAID_PLUGIN_TOOL_SESSION".to_string(),
                    session.path.display().to_string(),
                ));
                extra_env.push(("MAID_PLUGIN_TOOL_TOKEN".to_string(), session.token.clone()));
            }

            let run_result = run_plugin_with_env(&plugin, request, &extra_env).await;
            if let Some(session) = bridge {
                let _ = std::fs::remove_file(&session.path);
            }
            let response = run_result?;
            if !response.ok {
                return Err(anyhow!("plugin returned error: {}", response.message));
            }
            println!("{}", response.message);
            if let Some(output) = response.output {
                println!("{output}");
            }
            if let Some(data) = response.data {
                println!("{}", serde_json::to_string_pretty(&data)?);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct PluginRegistryFile {
    #[serde(default)]
    plugin: Vec<PluginRegistryEntry>,
    #[serde(default)]
    plugins: Vec<PluginRegistryEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginRegistryEntry {
    name: String,
    version: String,
    description: Option<String>,
    source: String,
    subdir: Option<String>,
}

async fn handle_plugin_registry_command(
    cfg: &AppConfig,
    command: PluginRegistryCommands,
) -> Result<()> {
    match command {
        PluginRegistryCommands::List { query, index } => {
            let index_path = resolve_registry_index_path(cfg, index);
            let entries = load_plugin_registry(&index_path)?;
            let needle = query.map(|v| v.to_ascii_lowercase()).unwrap_or_default();

            for entry in entries.into_iter().filter(|entry| {
                if needle.is_empty() {
                    return true;
                }
                entry.name.to_ascii_lowercase().contains(&needle)
                    || entry
                        .description
                        .as_ref()
                        .map(|d| d.to_ascii_lowercase().contains(&needle))
                        .unwrap_or(false)
            }) {
                println!(
                    "{}\t{}\t{}",
                    entry.name,
                    entry.version,
                    entry.description.unwrap_or_default()
                );
            }
        }
        PluginRegistryCommands::Install {
            name,
            version,
            index,
            dir,
        } => {
            let index_path = resolve_registry_index_path(cfg, index);
            let entries = load_plugin_registry(&index_path)?;
            let entry = select_registry_entry(&entries, &name, version.as_deref())?;
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            install_plugin_from_registry(&index_path, &plugins_dir, entry)?;
            let spec = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &spec, false)?;
            println!(
                "installed plugin '{}' v{} from {}",
                spec.manifest.name,
                spec.manifest.version,
                index_path.display()
            );
        }
        PluginRegistryCommands::Update { name, index, dir } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let installed = load_plugin(&plugins_dir, &name)?;
            let index_path = resolve_registry_index_path(cfg, index);
            let entries = load_plugin_registry(&index_path)?;
            let latest = select_registry_entry(&entries, &name, None)?;
            if compare_versions(&latest.version, &installed.manifest.version)
                != std::cmp::Ordering::Greater
            {
                println!(
                    "plugin '{}' is up to date at v{}",
                    installed.manifest.name, installed.manifest.version
                );
                return Ok(());
            }

            let stage_root = plugins_dir.join(format!(".stage-{}", maid_core::new_id()));
            std::fs::create_dir_all(&stage_root)
                .with_context(|| format!("failed to create {}", stage_root.display()))?;
            install_plugin_from_registry(&index_path, &stage_root, latest)?;

            let staged = stage_root.join(&name);
            if !staged.exists() {
                return Err(anyhow!("staged plugin missing at {}", staged.display()));
            }
            let target = plugins_dir.join(&name);
            let backup = plugins_dir.join(format!(".backup-{}-{}", name, maid_core::new_id()));
            std::fs::rename(&target, &backup).with_context(|| {
                format!(
                    "failed to move current plugin {} to backup",
                    target.display()
                )
            })?;
            std::fs::rename(&staged, &target)
                .with_context(|| format!("failed to activate {}", target.display()))?;
            std::fs::remove_dir_all(&backup).ok();
            std::fs::remove_dir_all(&stage_root).ok();

            let spec = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &spec, false)?;
            println!(
                "updated plugin '{}' from v{} to v{}",
                name, installed.manifest.version, spec.manifest.version
            );
        }
    }

    Ok(())
}

fn resolve_registry_index_path(cfg: &AppConfig, override_path: Option<PathBuf>) -> PathBuf {
    override_path.unwrap_or_else(|| PathBuf::from(cfg.plugin_registry_index_path()))
}

fn load_plugin_registry(index_path: &Path) -> Result<Vec<PluginRegistryEntry>> {
    let raw = std::fs::read_to_string(index_path)
        .with_context(|| format!("failed to read plugin registry {}", index_path.display()))?;
    let parsed: PluginRegistryFile = toml::from_str(&raw)
        .with_context(|| format!("failed to parse plugin registry {}", index_path.display()))?;
    let mut entries = parsed.plugin;
    entries.extend(parsed.plugins);
    if entries.is_empty() {
        return Err(anyhow!(
            "plugin registry has no entries: {}",
            index_path.display()
        ));
    }
    for entry in &entries {
        validate_plugin_registry_entry(entry)?;
    }
    entries.sort_by(|a, b| {
        if a.name == b.name {
            compare_versions(&b.version, &a.version)
        } else {
            a.name.cmp(&b.name)
        }
    });
    Ok(entries)
}

fn validate_plugin_registry_entry(entry: &PluginRegistryEntry) -> Result<()> {
    validate_plugin_name(&entry.name)?;
    if entry.version.trim().is_empty() {
        return Err(anyhow!("registry entry '{}' has empty version", entry.name));
    }
    if entry.source.trim().is_empty() {
        return Err(anyhow!("registry entry '{}' has empty source", entry.name));
    }
    if let Some(subdir) = &entry.subdir {
        if Path::new(subdir).is_absolute() || subdir.contains("..") {
            return Err(anyhow!(
                "registry entry '{}': subdir must be a safe relative path",
                entry.name
            ));
        }
    }
    Ok(())
}

fn select_registry_entry<'a>(
    entries: &'a [PluginRegistryEntry],
    name: &str,
    version: Option<&str>,
) -> Result<&'a PluginRegistryEntry> {
    let mut matches = entries
        .iter()
        .filter(|entry| entry.name == name)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(anyhow!("plugin '{}' not found in registry", name));
    }
    matches.sort_by(|a, b| compare_versions(&b.version, &a.version));

    if let Some(version) = version {
        return matches
            .into_iter()
            .find(|entry| entry.version == version)
            .ok_or_else(|| anyhow!("plugin '{}' version '{}' not found", name, version));
    }
    Ok(matches[0])
}

fn install_plugin_from_registry(
    index_path: &Path,
    destination_root: &Path,
    entry: &PluginRegistryEntry,
) -> Result<()> {
    std::fs::create_dir_all(destination_root)
        .with_context(|| format!("failed to create {}", destination_root.display()))?;

    let destination = destination_root.join(&entry.name);
    if destination.exists() {
        return Err(anyhow!(
            "destination already exists: {}",
            destination.display()
        ));
    }

    let source_root = resolve_registry_source(index_path, entry)?;
    let source = if let Some(subdir) = &entry.subdir {
        source_root.join(subdir)
    } else {
        source_root.clone()
    };
    if !source.exists() {
        return Err(anyhow!(
            "registry source not found for '{}': {}",
            entry.name,
            source.display()
        ));
    }

    copy_dir_recursive(&source, &destination)?;
    let spec = load_plugin(destination_root, &entry.name)?;
    if spec.manifest.version != entry.version {
        std::fs::remove_dir_all(&destination).ok();
        return Err(anyhow!(
            "registry version mismatch for '{}': index={}, manifest={}",
            entry.name,
            entry.version,
            spec.manifest.version
        ));
    }
    if is_git_source(&entry.source) {
        std::fs::remove_dir_all(source_root).ok();
    }
    Ok(())
}

fn resolve_registry_source(index_path: &Path, entry: &PluginRegistryEntry) -> Result<PathBuf> {
    let source = entry.source.trim();
    if is_git_source(source) {
        let git_url = source.strip_prefix("git+").unwrap_or(source);
        let clone_dir = std::env::temp_dir().join(format!(
            "maid-plugin-registry-{}-{}",
            entry.name,
            maid_core::new_id()
        ));
        let mut clone = StdCommand::new("git");
        clone.arg("clone").arg("--depth").arg("1");
        if !entry.version.trim().is_empty() {
            clone.arg("--branch").arg(&entry.version);
        }
        clone.arg(git_url).arg(&clone_dir);
        let output = clone
            .output()
            .with_context(|| format!("failed to run git clone for {}", git_url))?;
        if !output.status.success() {
            return Err(anyhow!(
                "git clone failed for '{}': {}",
                git_url,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(clone_dir);
    }

    let source_path = PathBuf::from(source);
    if source_path.is_absolute() {
        return Ok(source_path);
    }
    let base = index_path.parent().unwrap_or(Path::new("."));
    Ok(base.join(source_path))
}

fn is_git_source(source: &str) -> bool {
    source.starts_with("git+")
        || source.starts_with("https://")
        || source.starts_with("ssh://")
        || source.starts_with("git@")
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_dir() {
        return Err(anyhow!("source is not a directory: {}", source.display()));
    }
    std::fs::create_dir_all(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;

    for entry in std::fs::read_dir(source)
        .with_context(|| format!("failed to read directory {}", source.display()))?
    {
        let entry = entry?;
        let entry_path = entry.path();
        let file_name = entry.file_name();
        let dest_path = destination.join(file_name);
        let metadata = std::fs::symlink_metadata(&entry_path)
            .with_context(|| format!("failed to stat {}", entry_path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "symlinks are not allowed in plugin registry sources: {}",
                entry_path.display()
            ));
        }
        if metadata.is_dir() {
            copy_dir_recursive(&entry_path, &dest_path)?;
            continue;
        }
        std::fs::copy(&entry_path, &dest_path).with_context(|| {
            format!(
                "failed to copy {} to {}",
                entry_path.display(),
                dest_path.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(mode))
                .with_context(|| format!("failed to set permissions on {}", dest_path.display()))?;
        }
    }

    Ok(())
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let a = parse_semver_like(left);
    let b = parse_semver_like(right);
    for idx in 0..a.len().max(b.len()) {
        let av = *a.get(idx).unwrap_or(&0);
        let bv = *b.get(idx).unwrap_or(&0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    left.cmp(right)
}

fn parse_semver_like(value: &str) -> Vec<u64> {
    value
        .split('.')
        .map(|segment| {
            segment
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>()
        })
        .map(|segment| segment.parse::<u64>().unwrap_or(0))
        .collect()
}

fn validate_plugin_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("plugin name must not be empty"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(anyhow!(
            "plugin name must contain only lowercase letters, digits, and hyphens"
        ));
    }
    Ok(())
}

fn set_plugin_enabled_in_config(config_path: &Path, name: &str, enabled: bool) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut root: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let root_table = root
        .as_table_mut()
        .ok_or_else(|| anyhow!("config root must be a TOML table"))?;

    if !root_table.contains_key("plugins") {
        root_table.insert("plugins".to_string(), toml::Value::Table(toml::Table::new()));
    }
    let plugins_table = root_table
        .get_mut("plugins")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("plugins config must be a TOML table"))?;

    let mut enabled_values = plugins_table
        .get("enabled")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();

    if enabled {
        if !enabled_values.iter().any(|value| value == name) {
            enabled_values.push(name.to_string());
        }
    } else {
        enabled_values.retain(|value| value != name);
    }
    enabled_values.sort();

    let enabled_array = enabled_values
        .into_iter()
        .map(toml::Value::String)
        .collect::<Vec<_>>();
    plugins_table.insert("enabled".to_string(), toml::Value::Array(enabled_array));

    let updated = toml::to_string_pretty(&root)
        .with_context(|| format!("failed to serialize {}", config_path.display()))?;
    std::fs::write(config_path, updated)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
struct PluginToolBridgeSessionHandle {
    path: PathBuf,
    token: String,
}

fn create_plugin_tool_bridge_session(
    cfg: &AppConfig,
    plugin: &PluginSpec,
) -> Result<Option<PluginToolBridgeSessionHandle>> {
    let allowed_tools = resolve_allowed_plugin_tools(cfg, plugin);
    if allowed_tools.is_empty() {
        return Ok(None);
    }

    let token = maid_core::new_id();
    let session = PluginToolSession {
        version: 1,
        plugin_name: plugin.manifest.name.clone(),
        token: token.clone(),
        allowed_tools,
        max_calls_per_minute: cfg.plugin_tool_max_calls_per_minute(),
        issued_at: Utc::now().to_rfc3339(),
        expires_at: (Utc::now() + chrono::Duration::minutes(30)).to_rfc3339(),
    };

    let path = std::env::temp_dir().join(format!(
        "maid-plugin-tool-session-{}-{}.json",
        plugin.manifest.name,
        maid_core::new_id()
    ));
    let raw = serde_json::to_vec(&session).context("failed to serialize plugin tool session")?;
    std::fs::write(&path, raw)
        .with_context(|| format!("failed to write plugin tool session {}", path.display()))?;

    Ok(Some(PluginToolBridgeSessionHandle { path, token }))
}

fn resolve_allowed_plugin_tools(cfg: &AppConfig, plugin: &PluginSpec) -> Vec<String> {
    let cfg_allow = cfg.plugin_tool_allowlist();
    if cfg_allow.is_empty() {
        return Vec::new();
    }
    let plugin_allow = plugin.manifest.allowed_tools.clone().unwrap_or_default();
    if plugin_allow.is_empty() {
        return Vec::new();
    }

    plugin_allow
        .into_iter()
        .filter(|tool| cfg_allow.contains(tool))
        .filter(|tool| is_supported_plugin_tool(tool))
        .collect()
}

async fn handle_tool_command(
    cfg: &AppConfig,
    service: Arc<AppService>,
    command: ToolCommands,
) -> Result<()> {
    let session = load_plugin_tool_session_from_env_optional()?;

    match command {
        ToolCommands::List => {
            let tools = if let Some(session) = session {
                session.allowed_tools
            } else {
                supported_tool_names()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            };
            for tool in tools {
                if let Some(summary) = tool_summary(&tool) {
                    println!("{tool}\t{summary}");
                } else {
                    println!("{tool}");
                }
            }
        }
        ToolCommands::Call { tool, args } => {
            let parsed = parse_kv_args(&args)?;
            if let Some(session) = session {
                if !session.allowed_tools.iter().any(|allowed| allowed == &tool) {
                    return Err(anyhow!("tool '{}' not allowed for plugin session", tool));
                }
                let recent_count = service
                    .store
                    .count_recent_plugin_tool_calls(
                        &session.plugin_name,
                        Utc::now() - chrono::Duration::minutes(1),
                    )
                    .await?;
                if recent_count >= i64::from(session.max_calls_per_minute) {
                    return Err(anyhow!(
                        "plugin tool rate limit exceeded for '{}' (max {} calls/min)",
                        session.plugin_name,
                        session.max_calls_per_minute
                    ));
                }
                let plugin_actor = format!("plugin:{}", session.plugin_name);
                let outcome =
                    execute_tool_call(cfg, service.clone(), &tool, parsed, &plugin_actor).await;
                let (result_status, data) = match outcome {
                    Ok(data) => ("SUCCESS", data),
                    Err(err) => {
                        audit_plugin_tool_call(
                            service.clone(),
                            &session.plugin_name,
                            &tool,
                            "FAILED",
                            Some(json!({ "error": format!("{err:#}") })),
                        )
                        .await;
                        return Err(err);
                    }
                };

                audit_plugin_tool_call(
                    service.clone(),
                    &session.plugin_name,
                    &tool,
                    result_status,
                    Some(json!({ "data_preview": data })),
                )
                .await;
                println!("{}", serde_json::to_string(&data)?);
            } else {
                let outcome = execute_tool_call(cfg, service.clone(), &tool, parsed, "cli").await;
                let (result_status, data) = match outcome {
                    Ok(data) => ("SUCCESS", data),
                    Err(err) => {
                        audit_cli_tool_call(
                            service.clone(),
                            &tool,
                            "FAILED",
                            Some(json!({ "error": format!("{err:#}") })),
                        )
                        .await;
                        return Err(err);
                    }
                };
                audit_cli_tool_call(
                    service.clone(),
                    &tool,
                    result_status,
                    Some(json!({ "data_preview": data })),
                )
                .await;
                println!("{}", serde_json::to_string_pretty(&data)?);
            }
        }
    }

    Ok(())
}

async fn handle_audit_command(service: Arc<AppService>, command: AuditCommands) -> Result<()> {
    match command {
        AuditCommands::List {
            limit,
            action,
            actor,
        } => {
            let rows = service
                .store
                .list_recent_audits(limit, action.as_deref(), actor.as_deref())
                .await?;
            for audit in rows {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    audit.created_at.to_rfc3339(),
                    audit.action,
                    audit.actor,
                    audit.result,
                    audit
                        .metadata_json
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "{}".to_string())
                );
            }
        }
    }
    Ok(())
}

fn load_plugin_tool_session_from_env_optional() -> Result<Option<PluginToolSession>> {
    let session_path = std::env::var("MAID_PLUGIN_TOOL_SESSION").ok();
    let provided_token = std::env::var("MAID_PLUGIN_TOOL_TOKEN").ok();
    let (session_path, provided_token) = match (session_path, provided_token) {
        (None, None) => return Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            return Err(anyhow!(
                "incomplete tool bridge env: both MAID_PLUGIN_TOOL_SESSION and MAID_PLUGIN_TOOL_TOKEN are required"
            ));
        }
        (Some(session_path), Some(provided_token)) => (session_path, provided_token),
    };

    let raw = std::fs::read_to_string(&session_path)
        .with_context(|| format!("failed to read plugin tool session {}", session_path))?;
    let session: PluginToolSession =
        serde_json::from_str(&raw).context("invalid plugin tool session payload")?;

    if session.version != 1 {
        return Err(anyhow!("unsupported plugin tool session version"));
    }
    if session.max_calls_per_minute == 0 {
        return Err(anyhow!("invalid plugin tool session rate limit"));
    }
    if session.token != provided_token {
        return Err(anyhow!("invalid plugin tool session token"));
    }

    let expires_at = DateTime::parse_from_rfc3339(&session.expires_at)
        .context("invalid session expiration timestamp")?
        .with_timezone(&Utc);
    if Utc::now() > expires_at {
        return Err(anyhow!("plugin tool session expired"));
    }

    Ok(Some(session))
}

async fn execute_tool_call(
    cfg: &AppConfig,
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
    actor: &str,
) -> Result<serde_json::Value> {
    match tool {
        "group.list" => {
            let groups = service.list_groups().await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "groups": groups.into_iter().map(|g| json!({
                    "id": g.id,
                    "name": g.name,
                    "root_path": g.root_path,
                })).collect::<Vec<_>>(),
            }))
        }
        "group.create" => {
            let name = required_arg(&args, "name")?;
            let group = service.create_group(name, actor).await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "group": {
                    "id": group.id,
                    "name": group.name,
                    "root_path": group.root_path,
                }
            }))
        }
        "run.prompt" => {
            let group = required_arg(&args, "group")?;
            let prompt = required_arg(&args, "prompt")?;
            let output = service.run_prompt(group, prompt, actor).await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "group": group,
                "output": output,
            }))
        }
        "task.list" => {
            let group = required_arg(&args, "group")?;
            let tasks = service.list_tasks(group).await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "group": group,
                "tasks": tasks.into_iter().map(|t| json!({
                    "id": t.id,
                    "name": t.name,
                    "status": t.status.as_str(),
                    "schedule": t.schedule_rrule,
                })).collect::<Vec<_>>(),
            }))
        }
        "task.create" => {
            let group = required_arg(&args, "group")?;
            let name = required_arg(&args, "name")?;
            let schedule = required_arg(&args, "schedule")?;
            let prompt = required_arg(&args, "prompt")?;
            Schedule::parse_rrule(schedule)
                .with_context(|| format!("invalid schedule RRULE: {schedule}"))?;

            let task = service
                .create_task(group, name, schedule, prompt, actor)
                .await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "task": {
                    "id": task.id,
                    "name": task.name,
                    "status": task.status.as_str(),
                    "schedule": task.schedule_rrule,
                },
            }))
        }
        "task.run_now" => {
            let id = required_arg(&args, "id")?;
            let result = service.run_task_now(id, actor).await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "run": {
                    "id": result.run_id,
                    "status": result.status.as_str(),
                    "output_summary": result.output_summary,
                    "error_text": result.error_text,
                }
            }))
        }
        "task.pause" => {
            let id = required_arg(&args, "id")?;
            service.pause_task(id, actor).await?;
            Ok(json!({ "actor": actor, "tool": tool, "id": id, "status": "paused" }))
        }
        "task.resume" => {
            let id = required_arg(&args, "id")?;
            service.resume_task(id, actor).await?;
            Ok(json!({ "actor": actor, "tool": tool, "id": id, "status": "resumed" }))
        }
        "task.delete" => {
            let id = required_arg(&args, "id")?;
            let deleted = service.delete_task(id, actor).await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "id": id,
                "deleted": deleted
            }))
        }
        "task.clear_group" => {
            let group = required_arg(&args, "group")?;
            let deleted = service.clear_tasks_for_group(group, actor).await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "group": group,
                "deleted": deleted
            }))
        }
        "task.clear_all" => {
            let deleted = service.clear_all_tasks(actor).await?;
            Ok(json!({
                "actor": actor,
                "tool": tool,
                "deleted": deleted
            }))
        }
        "ops.web_fetch" => execute_web_fetch_tool(cfg, tool, args).await,
        "ops.search" => execute_web_search_tool(cfg, tool, args).await,
        "ops.grep" => execute_grep_tool(cfg, service, tool, args).await,
        _ => Err(anyhow!("unsupported tool '{}'", tool)),
    }
}

async fn execute_web_fetch_tool(
    cfg: &AppConfig,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let url_raw = required_arg(&args, "url")?;
    let url = validate_fetch_url(cfg, url_raw)?;
    let timeout_seconds = parse_u64_arg(
        &args,
        "timeout_seconds",
        cfg.tool_web_fetch_timeout_seconds(),
        1,
        120,
    )?;
    let max_bytes = parse_u64_arg(
        &args,
        "max_bytes",
        cfg.tool_web_fetch_max_bytes(),
        1024,
        1_048_576,
    )?;

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
        .context("failed to build web fetch client")?;
    let response = client
        .get(url.clone())
        .header("User-Agent", "maid/0.1 ops.web_fetch")
        .send()
        .await
        .with_context(|| format!("web fetch request failed: {}", url.as_str()))?;

    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_length = response.content_length();
    let bytes = response
        .bytes()
        .await
        .context("failed to read response body")?;
    let body_limit = max_bytes.min(bytes.len() as u64) as usize;
    let truncated = bytes.len() > body_limit;
    let preview = String::from_utf8_lossy(&bytes[..body_limit]).to_string();

    Ok(json!({
        "tool": tool,
        "url": url.as_str(),
        "status_code": status.as_u16(),
        "status": status.to_string(),
        "content_type": content_type,
        "content_length": content_length,
        "max_bytes": max_bytes,
        "truncated": truncated,
        "body_preview": preview,
    }))
}

async fn execute_web_search_tool(
    cfg: &AppConfig,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let query = required_arg(&args, "query")?;
    let limit = parse_u64_arg(&args, "limit", cfg.tool_search_max_results(), 1, 20)?;
    let timeout_seconds = parse_u64_arg(
        &args,
        "timeout_seconds",
        cfg.tool_web_fetch_timeout_seconds(),
        1,
        120,
    )?;

    let search_url = validate_fetch_url(cfg, "https://api.duckduckgo.com/")?;
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
        .context("failed to build web search client")?;
    let response: serde_json::Value = client
        .get(search_url)
        .query(&[
            ("q", query),
            ("format", "json"),
            ("no_redirect", "1"),
            ("no_html", "1"),
            ("skip_disambig", "1"),
        ])
        .header("User-Agent", "maid/0.1 ops.search")
        .send()
        .await
        .context("web search request failed")?
        .error_for_status()
        .context("web search returned non-success status")?
        .json()
        .await
        .context("failed to parse web search response JSON")?;

    let mut results = Vec::new();
    if let Some(text) = response
        .get("AbstractText")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        results.push(json!({
            "title": response.get("Heading").and_then(|v| v.as_str()),
            "url": response.get("AbstractURL").and_then(|v| v.as_str()),
            "snippet": text,
        }));
    }
    if let Some(related) = response.get("RelatedTopics").and_then(|v| v.as_array()) {
        collect_duckduckgo_topics(related, &mut results, limit as usize);
    }
    results.truncate(limit as usize);

    let mut provider = "duckduckgo";
    if results.is_empty() {
        match fetch_bing_rss_results(cfg, &client, query, limit as usize).await {
            Ok(fallback) if !fallback.is_empty() => {
                provider = "bing_rss_fallback";
                results = fallback;
            }
            Ok(_) => {}
            Err(err) => {
                debug!("bing rss fallback unavailable: {err:#}");
            }
        }
    }

    Ok(json!({
        "tool": tool,
        "provider": provider,
        "query": query,
        "limit": limit,
        "results": results,
    }))
}

async fn fetch_bing_rss_results(
    cfg: &AppConfig,
    client: &Client,
    query: &str,
    limit: usize,
) -> Result<Vec<serde_json::Value>> {
    let url = validate_fetch_url(cfg, "https://www.bing.com/search")?;
    let body = client
        .get(url)
        .query(&[("format", "rss"), ("q", query)])
        .header("User-Agent", "maid/0.1 ops.search")
        .send()
        .await
        .context("bing rss request failed")?
        .error_for_status()
        .context("bing rss returned non-success status")?
        .text()
        .await
        .context("failed to read bing rss response")?;

    let mut out = Vec::new();
    for item in body.split("<item>").skip(1) {
        if out.len() >= limit {
            break;
        }
        let title = extract_xml_tag(item, "title")
            .map(|v| xml_unescape(&v))
            .unwrap_or_default();
        let link = extract_xml_tag(item, "link").map(|v| xml_unescape(&v));
        let snippet = extract_xml_tag(item, "description")
            .map(|v| xml_unescape(&v))
            .unwrap_or_default();
        if title.is_empty() && snippet.is_empty() {
            continue;
        }
        out.push(json!({
            "title": title,
            "url": link,
            "snippet": snippet,
        }));
    }
    Ok(out)
}

fn extract_xml_tag(input: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = input.find(&open)? + open.len();
    let end = input[start..].find(&close)? + start;
    Some(input[start..end].trim().to_string())
}

fn xml_unescape(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn collect_duckduckgo_topics(
    topics: &[serde_json::Value],
    out: &mut Vec<serde_json::Value>,
    limit: usize,
) {
    for item in topics {
        if out.len() >= limit {
            break;
        }
        if let Some(children) = item.get("Topics").and_then(|v| v.as_array()) {
            collect_duckduckgo_topics(children, out, limit);
            continue;
        }
        let text = match item.get("Text").and_then(|v| v.as_str()) {
            Some(text) if !text.trim().is_empty() => text.trim(),
            _ => continue,
        };
        let url = item.get("FirstURL").and_then(|v| v.as_str());
        out.push(json!({
            "title": text,
            "url": url,
            "snippet": text,
        }));
    }
}

async fn execute_grep_tool(
    cfg: &AppConfig,
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let pattern = required_arg(&args, "pattern")?;
    let relative_path = args.get("path").map(String::as_str).unwrap_or(".");
    let ignore_case = parse_bool_arg(&args, "ignore_case", false)?;
    let max_file_bytes = parse_u64_arg(
        &args,
        "max_file_bytes",
        cfg.tool_grep_max_file_bytes(),
        1024,
        4_194_304,
    )?;
    let max_matches = parse_u64_arg(&args, "max_matches", cfg.tool_grep_max_matches(), 1, 1000)?;

    if Path::new(relative_path).is_absolute() {
        return Err(anyhow!("path must be relative to the group root"));
    }

    let group = service
        .store
        .get_group_by_name(group_name)
        .await?
        .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
    let group_root = fs::canonicalize(&group.root_path)
        .with_context(|| format!("failed to resolve group root {}", group.root_path))?;
    let candidate = fs::canonicalize(group_root.join(relative_path))
        .with_context(|| format!("failed to resolve path {}", relative_path))?;
    if !candidate.starts_with(&group_root) {
        return Err(anyhow!("path escapes group root"));
    }

    let mut stack = vec![candidate.clone()];
    let mut matches_out = Vec::new();
    while let Some(path) = stack.pop() {
        if matches_out.len() >= max_matches as usize {
            break;
        }

        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat path {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .with_context(|| format!("failed to read directory {}", path.display()))?
            {
                let entry = entry.with_context(|| {
                    format!("failed to read directory entry in {}", path.display())
                })?;
                stack.push(entry.path());
            }
            continue;
        }
        if !metadata.is_file() || metadata.len() > max_file_bytes {
            continue;
        }

        let raw = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let text = String::from_utf8_lossy(&raw);
        let needle = if ignore_case {
            pattern.to_lowercase()
        } else {
            pattern.to_string()
        };
        for (idx, line) in text.lines().enumerate() {
            let hay = if ignore_case {
                line.to_lowercase()
            } else {
                line.to_string()
            };
            if !hay.contains(&needle) {
                continue;
            }
            let rel = path
                .strip_prefix(&group_root)
                .unwrap_or(path.as_path())
                .display()
                .to_string();
            matches_out.push(json!({
                "path": rel,
                "line": idx + 1,
                "text": truncate_line(line, 400),
            }));
            if matches_out.len() >= max_matches as usize {
                break;
            }
        }
    }

    Ok(json!({
        "tool": tool,
        "group": group_name,
        "path": relative_path,
        "pattern": pattern,
        "ignore_case": ignore_case,
        "max_file_bytes": max_file_bytes,
        "max_matches": max_matches,
        "matches": matches_out,
    }))
}

async fn auto_invoke_skills_for_prompt(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    actor: &str,
) -> Result<Option<String>> {
    let mut rows = Vec::new();
    for skill in cfg.enabled_skills().into_iter().take(8) {
        if !is_supported_context_skill(&skill) {
            let error = format!("unsupported skill '{}'", skill);
            audit_auto_skill_context_call(
                service.clone(),
                actor,
                &skill,
                "SKIPPED",
                Some(json!({ "error": error })),
            )
            .await;
            rows.push(json!({
                "skill": skill,
                "status": "SKIPPED",
                "error": error,
            }));
            continue;
        }

        match execute_context_skill(cfg, service.clone(), group_name, &skill).await {
            Ok(payload) => {
                audit_auto_skill_context_call(
                    service.clone(),
                    actor,
                    &skill,
                    "SUCCESS",
                    Some(json!({ "preview": tool_result_preview(&payload, 600) })),
                )
                .await;
                rows.push(json!({
                    "skill": skill,
                    "status": "SUCCESS",
                    "context": payload,
                }));
            }
            Err(err) => {
                let err_text = format!("{err:#}");
                audit_auto_skill_context_call(
                    service.clone(),
                    actor,
                    &skill,
                    "FAILED",
                    Some(json!({ "error": err_text })),
                )
                .await;
                rows.push(json!({
                    "skill": skill,
                    "status": "FAILED",
                    "error": err_text,
                }));
            }
        }
    }

    if rows.is_empty() {
        return Ok(None);
    }

    let mut rendered = serde_json::to_string_pretty(&json!({ "skills": rows }))?;
    rendered = truncate_line(&rendered, cfg.skill_max_context_chars());
    Ok(Some(rendered))
}

async fn execute_context_skill(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    skill_name: &str,
) -> Result<serde_json::Value> {
    let group = service
        .store
        .get_group_by_name(group_name)
        .await?
        .ok_or_else(|| anyhow!("group not found: {group_name}"))?;

    match skill_name {
        "memory.recent" => {
            let rows = service
                .store
                .list_recent_messages(&group.id, cfg.skill_recent_message_limit())
                .await?;
            let messages = rows
                .into_iter()
                .map(|row| {
                    json!({
                        "role": row.role.as_str(),
                        "content": truncate_line(&row.content, 300),
                        "created_at": row.created_at.to_rfc3339(),
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({
                "group": group.name,
                "message_count": messages.len(),
                "messages": messages,
            }))
        }
        "tasks.snapshot" => {
            let tasks = service.list_tasks(&group.name).await?;
            let items = tasks
                .into_iter()
                .take(cfg.skill_task_limit())
                .map(|task| {
                    json!({
                        "id": task.id,
                        "name": task.name,
                        "status": task.status.as_str(),
                        "schedule": task.schedule_rrule,
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({
                "group": group.name,
                "task_count": items.len(),
                "tasks": items,
            }))
        }
        "group.profile" => Ok(json!({
            "id": group.id,
            "name": group.name,
            "root_path": group.root_path,
            "created_at": group.created_at.to_rfc3339(),
        })),
        _ => Err(anyhow!("unsupported context skill '{}'", skill_name)),
    }
}

async fn auto_route_tools_for_prompt(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    actor: &str,
) -> Result<Option<String>> {
    let allowed = cfg
        .tool_auto_router_allowlist()
        .into_iter()
        .filter(|name| is_supported_plugin_tool(name))
        .filter(|name| name != "run.prompt")
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        return Ok(None);
    }

    let plan = request_auto_tool_plan(service.clone(), group_name, prompt, &allowed).await?;
    if plan.calls.is_empty() {
        return Ok(None);
    }

    let mut rows = Vec::new();
    for call in plan.calls.into_iter().take(3) {
        if !allowed.iter().any(|name| name == &call.tool) {
            continue;
        }
        let tool = call.tool.clone();
        let args = call.args.clone();
        match execute_tool_call(cfg, service.clone(), &tool, args, actor).await {
            Ok(payload) => {
                audit_auto_router_tool_call(
                    service.clone(),
                    actor,
                    &tool,
                    "SUCCESS",
                    Some(json!({ "preview": tool_result_preview(&payload, 1200) })),
                )
                .await;
                rows.push(json!({
                    "tool": tool,
                    "status": "SUCCESS",
                    "result_preview": tool_result_preview(&payload, 1600),
                }));
            }
            Err(err) => {
                let err_text = format!("{err:#}");
                audit_auto_router_tool_call(
                    service.clone(),
                    actor,
                    &tool,
                    "FAILED",
                    Some(json!({ "error": err_text })),
                )
                .await;
                rows.push(json!({
                    "tool": tool,
                    "status": "FAILED",
                    "error": err_text,
                }));
            }
        }
    }

    if rows.is_empty() {
        return Ok(None);
    }

    Ok(Some(serde_json::to_string_pretty(&json!({
        "planner_rationale": plan.rationale,
        "calls": rows
    }))?))
}

#[derive(Debug, Clone, Deserialize)]
struct AutoToolPlan {
    #[serde(default)]
    calls: Vec<AutoToolCall>,
    #[serde(default)]
    rationale: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AutoToolCall {
    tool: String,
    args: BTreeMap<String, String>,
}

async fn request_auto_tool_plan(
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    allowed_tools: &[String],
) -> Result<AutoToolPlan> {
    let tool_catalog = allowed_tools
        .iter()
        .map(|name| {
            let summary = tool_summary(name).unwrap_or("No summary available");
            format!("- {name}: {summary}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let planner_prompt = format!(
        "You are a tool planner for a local assistant.\n\
Return ONLY JSON with this schema:\n\
{{\"rationale\":\"short reason\",\"calls\":[{{\"tool\":\"name\",\"args\":{{\"k\":\"v\"}}}}]}}\n\
Rules:\n\
- Use only tools listed below.\n\
- Choose at most 3 calls.\n\
- Prefer read operations.\n\
- If no tool is needed, return {{\"calls\":[]}}.\n\
- No markdown, no comments, no extra text.\n\n\
Group: {group_name}\n\
User request: {prompt}\n\n\
Available tools:\n{tool_catalog}\n"
    );

    let output = service
        .model
        .run(ModelRunRequest {
            group_name: group_name.to_string(),
            prompt: planner_prompt,
            history: Vec::new(),
        })
        .await?
        .output_text;

    parse_auto_tool_plan(&output)
}

fn parse_auto_tool_plan(raw: &str) -> Result<AutoToolPlan> {
    let parsed = serde_json::from_str::<serde_json::Value>(raw.trim()).or_else(|_| {
        let extracted = extract_json_object(raw)
            .ok_or_else(|| anyhow!("auto-router planner did not return valid JSON"))?;
        serde_json::from_str::<serde_json::Value>(&extracted)
            .context("failed to parse auto-router planner JSON")
    })?;
    normalize_auto_tool_plan(parsed)
}

fn normalize_auto_tool_plan(value: serde_json::Value) -> Result<AutoToolPlan> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("auto-router planner payload must be a JSON object"))?;
    let rationale = object
        .get("rationale")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let mut calls = Vec::new();
    if let Some(items) = object.get("calls").and_then(|v| v.as_array()) {
        for item in items {
            let Some(call_obj) = item.as_object() else {
                continue;
            };
            let Some(tool) = call_obj.get("tool").and_then(|v| v.as_str()) else {
                continue;
            };
            if tool.trim().is_empty() {
                continue;
            }
            let mut args = BTreeMap::new();
            if let Some(arg_obj) = call_obj.get("args").and_then(|v| v.as_object()) {
                for (key, value) in arg_obj {
                    if key.trim().is_empty() {
                        continue;
                    }
                    if let Some(normalized) = normalize_auto_tool_arg_value(value) {
                        args.insert(key.clone(), normalized);
                    }
                }
            }
            calls.push(AutoToolCall {
                tool: tool.to_string(),
                args,
            });
        }
    }

    Ok(AutoToolPlan { calls, rationale })
}

fn normalize_auto_tool_arg_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Bool(v) => Some(v.to_string()),
        serde_json::Value::Number(v) => Some(v.to_string()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Some(value.to_string()),
    }
}

fn extract_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    if end < start {
        return None;
    }
    Some(raw[start..=end].to_string())
}

fn tool_result_preview(payload: &serde_json::Value, max_chars: usize) -> String {
    truncate_line(&payload.to_string(), max_chars)
}

fn truncate_line(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out = input.chars().take(max_chars).collect::<String>();
    out.push_str("...");
    out
}

fn parse_u64_arg(
    args: &BTreeMap<String, String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64> {
    let value = match args.get(key) {
        Some(raw) => raw
            .parse::<u64>()
            .with_context(|| format!("argument '{}' must be an integer", key))?,
        None => default,
    };
    if value < min || value > max {
        return Err(anyhow!(
            "argument '{}' must be between {} and {}",
            key,
            min,
            max
        ));
    }
    Ok(value)
}

fn parse_bool_arg(args: &BTreeMap<String, String>, key: &str, default: bool) -> Result<bool> {
    let Some(raw) = args.get(key) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow!("argument '{}' must be a boolean (true/false)", key)),
    }
}

fn validate_fetch_url(cfg: &AppConfig, raw: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("invalid URL: {}", raw))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("URL scheme must be http or https"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL must include a host"))?
        .to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".local") {
        return Err(anyhow!("local hosts are not allowed"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private()
                    || ipv4.is_loopback()
                    || ipv4.is_link_local()
                    || ipv4.is_multicast()
                    || ipv4.is_broadcast()
                    || ipv4.is_documentation()
                    || ipv4.is_unspecified()
                {
                    return Err(anyhow!("private or local IP hosts are not allowed"));
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback()
                    || ipv6.is_unspecified()
                    || ipv6.is_unique_local()
                    || ipv6.is_unicast_link_local()
                    || ipv6.is_multicast()
                {
                    return Err(anyhow!("private or local IP hosts are not allowed"));
                }
            }
        }
    }

    let allowlist = cfg
        .tool_web_fetch_allowed_domains()
        .into_iter()
        .map(|d| d.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if cfg.is_production() && allowlist.is_empty() {
        return Err(anyhow!(
            "production mode requires tools.web_fetch_allowed_domains allowlist"
        ));
    }
    if !allowlist.is_empty() && !domain_matches_allowlist(&host, &allowlist) {
        return Err(anyhow!(
            "host '{}' is not in tools.web_fetch_allowed_domains",
            host
        ));
    }

    Ok(url)
}

fn domain_matches_allowlist(host: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|domain| {
        let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
        host == domain || host.ends_with(&format!(".{domain}"))
    })
}

fn required_arg<'a>(args: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    args.get(key)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow!("missing required argument: {}", key))
}

async fn audit_plugin_tool_call(
    service: Arc<AppService>,
    plugin_name: &str,
    tool: &str,
    result: &str,
    metadata_json: Option<serde_json::Value>,
) {
    let _ = service
        .store
        .insert_audit(NewAudit {
            group_id: None,
            action: "PLUGIN_TOOL_CALL".to_string(),
            actor: format!("plugin:{plugin_name}"),
            result: result.to_string(),
            created_at: Utc::now(),
            metadata_json: Some(json!({
                "plugin": plugin_name,
                "tool": tool,
                "metadata": metadata_json,
            })),
        })
        .await;
}

async fn audit_cli_tool_call(
    service: Arc<AppService>,
    tool: &str,
    result: &str,
    metadata_json: Option<serde_json::Value>,
) {
    let _ = service
        .store
        .insert_audit(NewAudit {
            group_id: None,
            action: "CLI_TOOL_CALL".to_string(),
            actor: "cli".to_string(),
            result: result.to_string(),
            created_at: Utc::now(),
            metadata_json: Some(json!({
                "tool": tool,
                "metadata": metadata_json,
            })),
        })
        .await;
}

async fn audit_auto_router_tool_call(
    service: Arc<AppService>,
    actor: &str,
    tool: &str,
    result: &str,
    metadata_json: Option<serde_json::Value>,
) {
    let _ = service
        .store
        .insert_audit(NewAudit {
            group_id: None,
            action: "AUTO_TOOL_CALL".to_string(),
            actor: actor.to_string(),
            result: result.to_string(),
            created_at: Utc::now(),
            metadata_json: Some(json!({
                "tool": tool,
                "metadata": metadata_json,
            })),
        })
        .await;
}

async fn audit_auto_skill_context_call(
    service: Arc<AppService>,
    actor: &str,
    skill: &str,
    result: &str,
    metadata_json: Option<serde_json::Value>,
) {
    let _ = service
        .store
        .insert_audit(NewAudit {
            group_id: None,
            action: "AUTO_SKILL_CONTEXT".to_string(),
            actor: actor.to_string(),
            result: result.to_string(),
            created_at: Utc::now(),
            metadata_json: Some(json!({
                "skill": skill,
                "metadata": metadata_json,
            })),
        })
        .await;
}

fn is_supported_context_skill(name: &str) -> bool {
    matches!(name, "memory.recent" | "tasks.snapshot" | "group.profile")
}

fn supported_tool_names() -> &'static [&'static str] {
    &[
        "group.list",
        "group.create",
        "run.prompt",
        "task.list",
        "task.create",
        "task.run_now",
        "task.pause",
        "task.resume",
        "task.delete",
        "task.clear_group",
        "task.clear_all",
        "ops.web_fetch",
        "ops.search",
        "ops.grep",
    ]
}

fn is_supported_plugin_tool(name: &str) -> bool {
    supported_tool_names().contains(&name)
}

fn tool_summary(name: &str) -> Option<&'static str> {
    match name {
        "group.list" => Some("List groups"),
        "group.create" => Some("Create group; args: name"),
        "run.prompt" => Some("Run prompt; args: group,prompt"),
        "task.list" => Some("List tasks; args: group"),
        "task.create" => Some("Create task; args: group,name,schedule,prompt"),
        "task.run_now" => Some("Run task now; args: id"),
        "task.pause" => Some("Pause task; args: id"),
        "task.resume" => Some("Resume task; args: id"),
        "task.delete" => Some("Delete task; args: id"),
        "task.clear_group" => Some("Clear group tasks; args: group"),
        "task.clear_all" => Some("Clear all tasks"),
        "ops.web_fetch" => Some("Fetch URL; args: url,[timeout_seconds],[max_bytes]"),
        "ops.search" => Some("Web search; args: query,[limit],[timeout_seconds]"),
        "ops.grep" => Some("Search files in group root; args: group,pattern,[path],[ignore_case]"),
        _ => None,
    }
}

fn resolve_plugins_dir(cfg: &AppConfig, override_dir: Option<PathBuf>) -> PathBuf {
    override_dir.unwrap_or_else(|| PathBuf::from(cfg.plugin_directory()))
}

fn ensure_plugin_enabled(cfg: &AppConfig, name: &str) -> Result<()> {
    if cfg.is_plugin_enabled(name) {
        return Ok(());
    }
    Err(anyhow!(
        "plugin '{}' is disabled by config.plugins.enabled",
        name
    ))
}

fn validate_plugins_for_startup(cfg: &AppConfig) -> Result<()> {
    if !cfg.validate_plugins_on_startup() {
        return Ok(());
    }

    let plugins_dir = PathBuf::from(cfg.plugin_directory());
    if let Some(enabled) = cfg.enabled_plugins() {
        info!(
            "validating {} enabled plugin(s) from {}",
            enabled.len(),
            plugins_dir.display()
        );
        for name in enabled {
            let plugin = load_plugin(&plugins_dir, name).with_context(|| {
                format!(
                    "startup plugin validation failed for '{}' in {}",
                    name,
                    plugins_dir.display()
                )
            })?;
            enforce_plugin_signature_policy(cfg, &plugin, false)?;
        }
        return Ok(());
    }

    let plugins = discover_plugins(&plugins_dir)?;
    for plugin in &plugins {
        enforce_plugin_signature_policy(cfg, plugin, false)?;
    }
    info!(
        "validated {} plugin(s) from {}",
        plugins.len(),
        plugins_dir.display()
    );
    Ok(())
}

fn enforce_plugin_signature_policy(
    cfg: &AppConfig,
    plugin: &PluginSpec,
    force_require: bool,
) -> Result<()> {
    let trusted = cfg.plugin_trusted_signing_keys();
    let require_signature = force_require || cfg.plugin_require_signatures();
    if trusted.is_empty() && !require_signature {
        return Ok(());
    }
    verify_plugin_signature(plugin, &trusted, require_signature)
}

fn parent_or_current(path: &str) -> Result<&Path> {
    Path::new(path)
        .parent()
        .ok_or_else(|| anyhow!("invalid path: {path}"))
}

fn build_model_provider(cfg: &AppConfig) -> Result<Arc<dyn ModelProvider>> {
    match cfg.model_provider_name().as_str() {
        "openai" => {
            let envs = cfg.model_api_key_envs();
            let mut api_keys = Vec::new();
            for env_name in &envs {
                if let Ok(value) = std::env::var(env_name) {
                    if !value.trim().is_empty() {
                        api_keys.push(value);
                    }
                }
            }
            if api_keys.is_empty() {
                return Err(anyhow!(
                    "missing OpenAI API key env vars (checked: {})",
                    envs.join(", ")
                ));
            }

            let provider = OpenAiProvider::new(OpenAiConfig {
                api_keys,
                models: cfg.model_candidates(),
                base_url: cfg
                    .model_base_url()
                    .unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
                max_retries: cfg.model_max_retries(),
                retry_backoff_ms: cfg.model_retry_backoff_ms(),
                requests_per_minute: cfg.model_requests_per_minute(),
                requests_per_day: cfg.model_requests_per_day(),
            })?;
            Ok(Arc::new(provider))
        }
        "echo" => Ok(Arc::new(EchoProvider)),
        other => Err(anyhow!("unsupported model provider: {other}")),
    }
}

fn build_service(
    cfg: &AppConfig,
    config_path: &Path,
    store: Arc<SqliteStore>,
    require_model_auth: bool,
) -> Result<Arc<AppService>> {
    let model = match build_model_provider(cfg) {
        Ok(provider) => provider,
        Err(err) if !require_model_auth => {
            debug!("model provider unavailable for this command, falling back to echo: {err:#}");
            Arc::new(EchoProvider)
        }
        Err(err) => return Err(err),
    };
    let runtime_kind = RuntimeKind::from_str(&cfg.runtime)?;
    let sandbox = build_runtime(runtime_kind, RuntimeConfig::default());
    let sandbox: Arc<dyn SandboxRuntime> = sandbox.into();

    Ok(Arc::new(maid_core::MaidService::new(
        store,
        Arc::new(DynModelProvider { inner: model }),
        Arc::new(DynSandboxRuntime { inner: sandbox }),
        CoreSettings {
            group_root: PathBuf::from(&cfg.group_root),
            config_path: config_path.to_path_buf(),
            default_job_timeout_secs: 120,
            max_job_timeout_secs: 900,
            allow_job_tasks_default: cfg.policy_allow_job_tasks_default(),
            allow_job_task_groups: cfg.policy_allow_job_task_groups(),
        },
    )))
}

async fn run_scheduler_daemon(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    executor: Arc<dyn TaskExecutor>,
) -> Result<()> {
    info!("starting scheduler daemon");
    let store_for_scheduler: Arc<dyn Storage> = store;
    let scheduler = SchedulerEngine::new(
        store_for_scheduler,
        executor,
        cfg.scheduler.tick_seconds,
        cfg.scheduler.max_concurrency,
    );
    scheduler.run_until_shutdown().await?;
    info!("scheduler daemon stopped");
    Ok(())
}

fn build_telegram_runtime(
    cfg: &AppConfig,
    service: Arc<AppService>,
) -> Result<(TelegramBot, Arc<dyn TelegramCommandHandler>)> {
    let telegram_cfg = cfg
        .telegram
        .as_ref()
        .ok_or_else(|| anyhow!("telegram config missing in config.toml"))?;
    let token = std::env::var(&telegram_cfg.bot_token_env).with_context(|| {
        format!(
            "missing required env var for telegram.bot_token_env: {}",
            telegram_cfg.bot_token_env
        )
    })?;

    let dm_policy = match cfg.telegram_dm_policy() {
        "open" => TelegramDmPolicy::Open,
        "pairing" => TelegramDmPolicy::Pairing,
        other => return Err(anyhow!("invalid telegram.dm_policy value: {}", other)),
    };
    let activation_mode = match cfg.telegram_activation_mode() {
        "always" => TelegramActivationMode::Always,
        "mention" => TelegramActivationMode::Mention,
        other => return Err(anyhow!("invalid telegram.activation_mode value: {}", other)),
    };

    let per_chat_activation_mode = cfg
        .telegram_per_chat_activation_mode()
        .into_iter()
        .map(|(chat_id, mode)| {
            let parsed = match mode.as_str() {
                "always" => TelegramActivationMode::Always,
                "mention" => TelegramActivationMode::Mention,
                _ => TelegramActivationMode::Always,
            };
            (chat_id, parsed)
        })
        .collect::<std::collections::HashMap<_, _>>();
    let per_chat_mention_token = cfg
        .telegram_per_chat_mention_token()
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();

    let bot = TelegramBot::new(TelegramBotConfig {
        token,
        polling_timeout_seconds: telegram_cfg.polling_timeout_seconds.unwrap_or(30),
        allowed_chat_ids: telegram_cfg.allowed_chat_ids.clone(),
        dm_policy,
        activation_mode,
        mention_token: cfg.telegram_mention_token().map(|v| v.to_string()),
        main_chat_id: cfg.telegram_main_chat_id(),
        per_chat_activation_mode: Some(per_chat_activation_mode),
        per_chat_mention_token: Some(per_chat_mention_token),
    })?;
    let handler: Arc<dyn TelegramCommandHandler> = Arc::new(TelegramServiceAdapter {
        service,
        cfg: cfg.clone(),
    });
    Ok((bot, handler))
}

fn build_scheduler_executor(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    service: Arc<AppService>,
    events: Option<GatewayEvents>,
) -> Result<Arc<dyn TaskExecutor>> {
    let notifier = TelegramNotifier::from_config(cfg)?;
    Ok(Arc::new(SchedulerTaskExecutor {
        inner: service,
        store,
        notifier,
        events,
    }))
}

async fn run_serve(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    service: Arc<AppService>,
    events: Option<GatewayEvents>,
) -> Result<()> {
    info!("starting combined service (scheduler + telegram)");

    let scheduler_executor = build_scheduler_executor(cfg, store.clone(), service.clone(), events)?;
    let scheduler = SchedulerEngine::new(
        store.clone() as Arc<dyn Storage>,
        scheduler_executor,
        cfg.scheduler.tick_seconds,
        cfg.scheduler.max_concurrency,
    );

    let (bot, handler) = build_telegram_runtime(cfg, service.clone())?;
    let (scheduler_result, telegram_result) = tokio::join!(
        scheduler.run_until_shutdown(),
        bot.run_until_shutdown(handler)
    );
    scheduler_result?;
    telegram_result?;
    info!("combined service stopped");
    Ok(())
}

async fn run_gateway(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    service: Arc<AppService>,
    port: u16,
) -> Result<()> {
    info!("starting gateway control plane on 127.0.0.1:{}", port);
    let events = GatewayEvents::new(256);
    let status = GatewayStatus {
        started_at: chrono::Utc::now().to_rfc3339(),
        model_provider: cfg.model_provider_name(),
        runtime: cfg.runtime.clone(),
        scheduler_tick_seconds: cfg.scheduler.tick_seconds,
        scheduler_max_concurrency: cfg.scheduler.max_concurrency,
        telegram_enabled: cfg.telegram.is_some(),
    };

    if cfg.telegram.is_some() {
        let serve_task = run_serve(cfg, store, service, Some(events.clone()));
        let control_task = run_gateway_control_plane(port, status, events.clone());
        let (serve_result, control_result) = tokio::join!(serve_task, control_task);
        serve_result?;
        control_result?;
        return Ok(());
    }

    let scheduler_executor =
        build_scheduler_executor(cfg, store.clone(), service.clone(), Some(events.clone()))?;
    let scheduler_task = run_scheduler_daemon(cfg, store.clone(), scheduler_executor);
    let control_task = run_gateway_control_plane(port, status, events);
    let (scheduler_result, control_result) = tokio::join!(scheduler_task, control_task);
    scheduler_result?;
    control_result?;
    Ok(())
}

async fn run_gateway_control_plane(
    port: u16,
    status: GatewayStatus,
    events: GatewayEvents,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to bind gateway control port {}", port))?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("gateway control plane stopped");
                break;
            }
            accepted = listener.accept() => {
                let (stream, addr) = accepted.context("gateway accept failed")?;
                let status_clone = status.clone();
                let events_clone = events.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_gateway_client(stream, status_clone, events_clone).await {
                        warn!("gateway client {} failed: {err:#}", addr);
                    }
                });
            }
        }
    }

    Ok(())
}

async fn run_dashboard(
    cfg: &AppConfig,
    config_path: &Path,
    store: Arc<SqliteStore>,
    service: Arc<AppService>,
    port: u16,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to bind dashboard port {}", port))?;
    info!("dashboard listening on http://127.0.0.1:{}", port);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("dashboard stopped");
                break;
            }
            accepted = listener.accept() => {
                let (stream, addr) = accepted.context("dashboard accept failed")?;
                let cfg_clone = cfg.clone();
                let config_path_clone = config_path.to_path_buf();
                let store_clone = store.clone();
                let service_clone = service.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_dashboard_client(stream, cfg_clone, config_path_clone, store_clone, service_clone).await {
                        warn!("dashboard client {} failed: {err:#}", addr);
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_dashboard_client(
    stream: TcpStream,
    cfg: AppConfig,
    config_path: PathBuf,
    store: Arc<SqliteStore>,
    service: Arc<AppService>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }
    let request_line = request_line.trim_end();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    let mut header_line = String::new();
    loop {
        header_line.clear();
        if reader.read_line(&mut header_line).await? == 0 {
            break;
        }
        let trimmed = header_line.trim_end();
        if trimmed.is_empty() {
            break;
        }
    }

    let (path, query) = parse_http_target(target)?;
    match (method, path.as_str()) {
        ("GET", "/") => {
            let body = dashboard_html();
            write_http_response(&mut write_half, "200 OK", "text/html; charset=utf-8", body)
                .await?;
        }
        ("GET", "/health") => {
            let body = serde_json::to_string_pretty(&build_health_snapshot(&cfg).await?)?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("GET", "/api/overview") => {
            let payload = build_dashboard_overview(store, service).await?;
            let body = serde_json::to_string_pretty(&payload)?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("GET", "/api/groups") => {
            let groups = service.list_groups().await?;
            let body = serde_json::to_string_pretty(&groups)?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("GET", "/api/plugins") => {
            let live_cfg = AppConfig::load(&config_path).unwrap_or(cfg.clone());
            let plugins_dir = PathBuf::from(live_cfg.plugin_directory());
            let plugins = discover_plugins(&plugins_dir)?;
            let payload = plugins
                .into_iter()
                .map(|plugin| {
                    json!({
                        "name": plugin.manifest.name,
                        "version": plugin.manifest.version,
                        "enabled": live_cfg.is_plugin_enabled(&plugin.manifest.name),
                        "description": plugin.manifest.description,
                    })
                })
                .collect::<Vec<_>>();
            write_http_response(
                &mut write_half,
                "200 OK",
                "application/json",
                serde_json::to_string_pretty(&payload)?,
            )
            .await?;
        }
        ("GET", "/api/tasks") => {
            let maybe_group = query.get("group").map(String::as_str).unwrap_or("");
            let payload = if maybe_group.is_empty() {
                let groups = service.list_groups().await?;
                let mut rows = Vec::new();
                for group in groups {
                    let tasks = service.list_tasks(&group.name).await?;
                    for task in tasks {
                        rows.push(json!({
                            "group": group.name,
                            "task": task,
                        }));
                    }
                }
                json!(rows)
            } else {
                let tasks = service.list_tasks(maybe_group).await?;
                json!(tasks)
            };
            write_http_response(
                &mut write_half,
                "200 OK",
                "application/json",
                serde_json::to_string_pretty(&payload)?,
            )
            .await?;
        }
        ("GET", "/api/runs") => {
            let limit = query
                .get("limit")
                .and_then(|raw| raw.parse::<i64>().ok())
                .unwrap_or(50)
                .clamp(1, 500);
            let runs = store.list_recent_task_runs(limit).await?;
            let body = serde_json::to_string_pretty(&runs)?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("GET", "/api/audits") => {
            let limit = query
                .get("limit")
                .and_then(|raw| raw.parse::<i64>().ok())
                .unwrap_or(50)
                .clamp(1, 500);
            let action = query.get("action").map(String::as_str);
            let actor = query.get("actor").map(String::as_str);
            let audits = store.list_recent_audits(limit, action, actor).await?;
            let body = serde_json::to_string_pretty(&audits)?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("GET", "/api/pairings/pending") => {
            let pairings = store.list_pending_telegram_pairings().await?;
            let body = serde_json::to_string_pretty(&pairings)?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/pairings/approve") => {
            let code = query
                .get("code")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: code"))?;
            let approved = service.approve_telegram_pairing(&code, "dashboard").await?;
            let body = serde_json::to_string_pretty(&json!({
                "code": code,
                "approved": approved,
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/plugins/enable") => {
            let name = query
                .get("name")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: name"))?;
            validate_plugin_name(&name)?;
            set_plugin_enabled_in_config(&config_path, &name, true)?;
            let body = serde_json::to_string_pretty(&json!({
                "name": name,
                "enabled": true
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/plugins/disable") => {
            let name = query
                .get("name")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: name"))?;
            validate_plugin_name(&name)?;
            set_plugin_enabled_in_config(&config_path, &name, false)?;
            let body = serde_json::to_string_pretty(&json!({
                "name": name,
                "enabled": false
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        _ => {
            write_http_response(
                &mut write_half,
                "404 Not Found",
                "application/json",
                "{\"error\":\"not_found\"}".to_string(),
            )
            .await?;
        }
    }

    Ok(())
}

async fn build_dashboard_overview(
    store: Arc<SqliteStore>,
    service: Arc<AppService>,
) -> Result<serde_json::Value> {
    let groups = service.list_groups().await?;
    let mut task_count = 0_u64;
    let mut active_count = 0_u64;
    let mut paused_count = 0_u64;
    for group in &groups {
        let tasks = service.list_tasks(&group.name).await?;
        for task in tasks {
            task_count += 1;
            if task.status.as_str() == "ACTIVE" {
                active_count += 1;
            } else {
                paused_count += 1;
            }
        }
    }

    let runs = store.list_recent_task_runs(20).await?;
    let audits = store.list_recent_audits(20, None, None).await?;
    let pending_pairings = store.list_pending_telegram_pairings().await?;

    Ok(json!({
        "groups_total": groups.len(),
        "tasks_total": task_count,
        "tasks_active": active_count,
        "tasks_paused": paused_count,
        "recent_runs": runs,
        "recent_audits": audits,
        "pending_pairings": pending_pairings,
    }))
}

async fn run_health_checks(cfg: &AppConfig, gateway_port: u16) -> Result<()> {
    let snapshot = build_health_snapshot(cfg).await?;

    println!(
        "config: {}",
        snapshot
            .get("config")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );
    println!(
        "runtime: {}",
        snapshot
            .get("runtime")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );
    println!(
        "model_auth: {}",
        snapshot
            .get("model_auth")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );

    let gateway_ok = check_gateway_ping(gateway_port).await;
    println!(
        "gateway(127.0.0.1:{}): {}",
        gateway_port,
        if gateway_ok {
            "reachable"
        } else {
            "unreachable"
        }
    );

    if cfg.is_production() {
        println!("security_mode: production");
    } else {
        println!("security_mode: development");
    }

    if !gateway_ok {
        return Err(anyhow!("gateway is unreachable on port {}", gateway_port));
    }

    Ok(())
}

async fn build_health_snapshot(cfg: &AppConfig) -> Result<serde_json::Value> {
    let config_status = "loaded";
    let runtime_binary = if cfg.runtime == "apple_container" {
        "container"
    } else {
        "docker"
    };
    let runtime_ok = StdCommand::new(runtime_binary)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    let model_provider = cfg.model_provider_name();
    let model_ok = if model_provider == "openai" {
        cfg.model_api_key_envs().iter().any(|env| {
            std::env::var(env)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .is_some()
        })
    } else {
        true
    };

    Ok(json!({
        "config": config_status,
        "runtime": if runtime_ok { "ok" } else { "missing" },
        "runtime_binary": runtime_binary,
        "model_provider": model_provider,
        "model_auth": if model_ok { "ok" } else { "missing" },
        "security_mode": if cfg.is_production() { "production" } else { "development" },
    }))
}

async fn check_gateway_ping(port: u16) -> bool {
    let connect = tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await;
    let Ok(Ok(stream)) = connect else {
        return false;
    };

    let (read_half, mut write_half) = stream.into_split();
    if write_half.write_all(b"ping\n").await.is_err() {
        return false;
    }
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line)).await;
    matches!(read, Ok(Ok(n)) if n > 0 && line.contains("pong"))
}

fn parse_http_target(target: &str) -> Result<(String, BTreeMap<String, String>)> {
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        Url::parse(target).with_context(|| format!("invalid request target: {}", target))?
    } else {
        Url::parse(&format!("http://localhost{}", target))
            .with_context(|| format!("invalid request target: {}", target))?
    };
    let mut query = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        query.insert(key.to_string(), value.to_string());
    }
    Ok((url.path().to_string(), query))
}

async fn write_http_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    status: &str,
    content_type: &str,
    body: String,
) -> Result<()> {
    let bytes = body.as_bytes();
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    writer.write_all(head.as_bytes()).await?;
    writer.write_all(bytes).await?;
    Ok(())
}

fn dashboard_html() -> String {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>maid dashboard</title>
  <style>
    :root { --bg:#0f172a; --panel:#111827; --text:#e5e7eb; --muted:#94a3b8; --ok:#16a34a; --warn:#d97706; --err:#dc2626; }
    body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:linear-gradient(120deg,#020617,#111827); color:var(--text); }
    main { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
    h1 { font-size: 22px; margin: 0 0 16px; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin-bottom:16px; }
    .card { background: rgba(17,24,39,0.9); border:1px solid #1f2937; border-radius:10px; padding:12px; }
    .k { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
    .v { font-size:20px; margin-top:6px; }
    pre { white-space: pre-wrap; word-break: break-word; font-size:12px; line-height:1.45; margin:0; }
    .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    @media (max-width:900px){ .row{ grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <main>
    <h1>maid control dashboard</h1>
    <div class="grid">
      <section class="card"><div class="k">Groups</div><div class="v" id="groups">-</div></section>
      <section class="card"><div class="k">Tasks Total</div><div class="v" id="tasks_total">-</div></section>
      <section class="card"><div class="k">Tasks Active</div><div class="v" id="tasks_active">-</div></section>
      <section class="card"><div class="k">Tasks Paused</div><div class="v" id="tasks_paused">-</div></section>
    </div>
    <div class="row">
      <section class="card"><div class="k">Recent Runs</div><pre id="runs">loading…</pre></section>
      <section class="card"><div class="k">Recent Audits</div><pre id="audits">loading…</pre></section>
    </div>
  </main>
  <script>
    async function refresh() {
      const res = await fetch('/api/overview');
      const data = await res.json();
      document.getElementById('groups').textContent = data.groups_total;
      document.getElementById('tasks_total').textContent = data.tasks_total;
      document.getElementById('tasks_active').textContent = data.tasks_active;
      document.getElementById('tasks_paused').textContent = data.tasks_paused;
      document.getElementById('runs').textContent = JSON.stringify(data.recent_runs, null, 2);
      document.getElementById('audits').textContent = JSON.stringify(data.recent_audits, null, 2);
    }
    refresh().catch((err) => console.error(err));
    setInterval(() => refresh().catch((err) => console.error(err)), 5000);
  </script>
</body>
</html>
"#
    .to_string()
}

async fn handle_gateway_client(
    stream: TcpStream,
    status: GatewayStatus,
    events: GatewayEvents,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let cmd = parse_gateway_command(trimmed)?;
        match cmd.as_str() {
            "ping" => {
                let payload = json!({ "ok": true, "pong": true });
                write_half.write_all(payload.to_string().as_bytes()).await?;
                write_half.write_all(b"\n").await?;
            }
            "status" => {
                let payload = json!({ "ok": true, "status": status });
                write_half.write_all(payload.to_string().as_bytes()).await?;
                write_half.write_all(b"\n").await?;
            }
            "subscribe" => {
                write_half
                    .write_all(
                        json!({"ok": true, "subscribed": true})
                            .to_string()
                            .as_bytes(),
                    )
                    .await?;
                write_half.write_all(b"\n").await?;
                let mut rx = events.subscribe();
                loop {
                    match rx.recv().await {
                        Ok(payload) => {
                            write_half.write_all(payload.as_bytes()).await?;
                            write_half.write_all(b"\n").await?;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            let warning = json!({"type":"gateway.warning","message":"lagged","skipped":skipped});
                            write_half.write_all(warning.to_string().as_bytes()).await?;
                            write_half.write_all(b"\n").await?;
                        }
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    }
                }
            }
            _ => {
                let payload = json!({ "ok": false, "error": "unknown command" });
                write_half.write_all(payload.to_string().as_bytes()).await?;
                write_half.write_all(b"\n").await?;
            }
        }
    }
}

fn parse_gateway_command(raw: &str) -> Result<String> {
    if raw == "ping" || raw == "status" || raw == "subscribe" {
        return Ok(raw.to_string());
    }
    let parsed = serde_json::from_str::<GatewayCommand>(raw).context(
        "control command must be one of: ping, status, subscribe, or JSON {\"cmd\":\"...\"}",
    )?;
    Ok(parsed.cmd)
}

async fn run_onboard(cfg: &AppConfig, config_path: &Path) -> Result<()> {
    std::fs::create_dir_all(parent_or_current(&cfg.database_path)?)
        .with_context(|| format!("failed to create db parent for {}", cfg.database_path))?;
    std::fs::create_dir_all(&cfg.group_root)
        .with_context(|| format!("failed to create group root {}", cfg.group_root))?;
    std::fs::create_dir_all(cfg.plugin_directory())
        .with_context(|| format!("failed to create plugins dir {}", cfg.plugin_directory()))?;

    let store = SqliteStore::connect(&cfg.database_path).await?;
    let migration_dir = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("migrations");
    store.apply_migrations_from_dir(&migration_dir).await?;

    let existing_main = store.get_group_by_name("main").await?;
    if existing_main.is_none() {
        let main_root = PathBuf::from(&cfg.group_root).join("main");
        std::fs::create_dir_all(&main_root)
            .with_context(|| format!("failed to create {}", main_root.display()))?;
        store
            .create_group("main", &main_root.to_string_lossy())
            .await
            .context("failed to create default main group")?;
    }

    let model_envs = cfg.model_api_key_envs();
    let model_auth_ok = model_envs.iter().any(|env| {
        std::env::var(env)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
    });

    let telegram_env = cfg
        .telegram
        .as_ref()
        .map(|t| t.bot_token_env.clone())
        .unwrap_or_else(|| "TELEGRAM_BOT_TOKEN".to_string());
    let telegram_ok = cfg.telegram.as_ref().map(|_| {
        std::env::var(&telegram_env)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
    });

    println!("onboard complete");
    println!("config: {}", config_path.display());
    println!("database: {}", cfg.database_path);
    println!("group_root: {}", cfg.group_root);
    println!("plugins: {}", cfg.plugin_directory());
    println!("skills: {}", cfg.enabled_skills().join(", "));
    println!("default_group: main");
    println!(
        "model_auth: {}",
        if model_auth_ok { "ok" } else { "missing" }
    );
    if let Some(ok) = telegram_ok {
        println!("telegram_token: {}", if ok { "ok" } else { "missing" });
    } else {
        println!("telegram: disabled");
    }
    println!();
    println!("guided next steps:");
    println!(
        "1) export {}=<your_key>",
        model_envs
            .first()
            .cloned()
            .unwrap_or_else(|| "OPENAI_API_KEY".to_string())
    );
    if let Some(telegram) = &cfg.telegram {
        println!("2) export {}=<telegram_bot_token>", telegram.bot_token_env);
    } else {
        println!("2) optional: configure [telegram] in config.toml");
    }
    println!("3) cargo run -p maid -- doctor");
    println!("4) cargo run -p maid -- gateway --port 18789");
    println!("5) cargo run -p maid -- group create work");
    println!(
        "6) cargo run -p maid -- task create --group work --name morning-brief --schedule \"FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;BYHOUR=9;BYMINUTE=0\" --prompt \"Give me a concise morning brief.\""
    );
    println!("7) cargo run -p maid -- dashboard --port 18790");
    Ok(())
}

async fn run_doctor(cfg: &AppConfig, config_path: &Path) -> Result<()> {
    let mut failed = 0_u32;

    fn report_ok(label: &str, detail: &str) {
        println!("[ok]   {label}: {detail}");
    }

    fn report_warn(label: &str, detail: &str) {
        println!("[warn] {label}: {detail}");
    }

    fn report_fail(label: &str, detail: &str) {
        println!("[fail] {label}: {detail}");
    }

    report_ok("config", &format!("loaded {}", config_path.display()));

    let db_ok = match SqliteStore::connect(&cfg.database_path).await {
        Ok(store) => {
            let migration_dir = config_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("migrations");
            store
                .apply_migrations_from_dir(&migration_dir)
                .await
                .is_ok()
        }
        Err(_) => false,
    };
    if !db_ok {
        failed += 1;
        report_fail("database", &cfg.database_path);
    } else {
        report_ok("database", &cfg.database_path);
    }

    let runtime_binary = if cfg.runtime == "apple_container" {
        "container"
    } else {
        "docker"
    };
    let runtime_ok = StdCommand::new(runtime_binary)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if runtime_ok {
        report_ok("runtime", runtime_binary);
    } else {
        report_warn("runtime", &format!("{runtime_binary} not found on PATH"));
    }

    let model_provider = cfg.model_provider_name();
    let model_ok = if model_provider == "openai" {
        cfg.model_api_key_envs().iter().any(|env| {
            std::env::var(env)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_some()
        })
    } else {
        true
    };
    if model_ok {
        report_ok("model_auth", &model_provider);
    } else {
        report_warn("model_auth", &format!("{model_provider} credentials missing"));
    }

    if let Some(telegram) = &cfg.telegram {
        let telegram_ok = std::env::var(&telegram.bot_token_env)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some();
        if telegram_ok {
            report_ok("telegram_token", &telegram.bot_token_env);
        } else {
            report_warn("telegram_token", &format!("{} missing", telegram.bot_token_env));
        }
    } else {
        report_ok("telegram", "disabled");
    }

    let plugin_ok = validate_plugins_for_startup(cfg).is_ok();
    if !plugin_ok {
        failed += 1;
        report_fail("plugins", cfg.plugin_directory());
    } else {
        report_ok("plugins", cfg.plugin_directory());
    }
    report_ok("skills", &cfg.enabled_skills().join(", "));

    if failed > 0 {
        return Err(anyhow!("doctor found {} failing check(s)", failed));
    }

    println!("doctor: all checks passed");
    Ok(())
}

fn write_default_config(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config parent {}", parent.display()))?;
    let template = r#"database_path = "data/assistant.db"
group_root = "groups"
runtime = "apple_container"

[model]
provider = "openai"
api_key_env = "OPENAI_API_KEY"
api_key_envs = ["OPENAI_API_KEY"]
base_url = "https://api.openai.com/v1"
model = "gpt-4.1-mini"
fallback_models = ["gpt-4o-mini"]
# active_profile = "primary"
# [model.profiles.primary]
# provider = "openai"
# api_key_envs = ["OPENAI_API_KEY"]
# model = "gpt-5-mini"
# fallback_models = ["gpt-4.1-mini"]
# [model.ops]
# max_retries = 2
# retry_backoff_ms = 800
# requests_per_minute = 60
# requests_per_day = 5000

[scheduler]
tick_seconds = 30
max_concurrency = 2

[telegram]
bot_token_env = "TELEGRAM_BOT_TOKEN"
polling_timeout_seconds = 30
dm_policy = "pairing"
activation_mode = "mention"
mention_token = "@maid"
# main_chat_id = 123456789
# allowed_chat_ids = [123456789]
# per_chat_activation_mode = { "123456789" = "always" }
# per_chat_mention_token = { "123456789" = "@maid" }

[skills]
enabled = ["memory.recent", "tasks.snapshot", "group.profile"]
# max_context_chars = 4000
# recent_message_limit = 8
# task_limit = 12

[plugins]
directory = "plugins"
enabled = ["echo"]
# allow_unlisted = false
# tool_allowlist = ["group.list", "group.create", "run.prompt", "task.list", "task.create", "task.run_now", "task.pause", "task.resume", "task.delete", "task.clear_group", "task.clear_all", "ops.web_fetch", "ops.search", "ops.grep"]
# tool_max_calls_per_minute = 60
validate_on_startup = true
# [plugins.registry]
# index_path = "plugins/registry.toml"
# [plugins.signing]
# require_signatures = false
# trusted_keys = { "local.dev" = "keys/local-dev.public.pem" }

[tools]
# web_fetch_timeout_seconds = 15
# web_fetch_max_bytes = 131072
# web_fetch_allowed_domains = ["example.com"]
# grep_max_file_bytes = 1048576
# grep_max_matches = 100
# search_max_results = 5
# auto_router_enabled = true
# auto_router_allowlist = ["ops.web_fetch", "ops.search"]

[policy]
allow_job_tasks = false
allow_job_task_groups = []

[security]
mode = "development"
"#;
    std::fs::write(path, template)
        .with_context(|| format!("failed to write default config {}", path.display()))?;
    Ok(())
}

fn telegram_chat_id_from_group_name(group_name: &str) -> Option<i64> {
    group_name
        .strip_prefix("telegram-")
        .and_then(|raw| raw.parse::<i64>().ok())
}

fn format_scheduled_task_message(task_name: &str, result: &TaskExecutionResult) -> String {
    let mut output = format!(
        "Scheduled task '{}' finished with status {}",
        task_name,
        result.status.as_str()
    );

    if let Some(summary) = &result.output_summary {
        output.push_str("\n\nOutput:\n");
        output.push_str(summary);
    }
    if let Some(error) = &result.error_text {
        output.push_str("\n\nError:\n");
        output.push_str(error);
    }

    output
}

fn truncate_for_telegram(input: &str) -> String {
    const MAX_CHARS: usize = 3500;
    if input.chars().count() <= MAX_CHARS {
        return input.to_string();
    }
    let mut truncated = input.chars().take(MAX_CHARS).collect::<String>();
    truncated.push_str("\n\n[truncated]");
    truncated
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
        let (path, query) = parse_http_target("/api/tasks?group=work&limit=10").unwrap();
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
            },
            PluginRegistryEntry {
                name: "echo".to_string(),
                version: "0.2.0".to_string(),
                description: None,
                source: "/tmp/echo-0.2.0".to_string(),
                subdir: None,
            },
        ];
        let selected = select_registry_entry(&entries, "echo", None).unwrap();
        assert_eq!(selected.version, "0.2.0");
    }

    #[test]
    fn parse_auto_tool_plan_coerces_non_string_args() {
        let raw = r#"{
            "rationale":"need tools",
            "calls":[
                {"tool":"ops.search","args":{"query":"rust sqlite","limit":3}},
                {"tool":"ops.grep","args":{"group":"smoke","ignore_case":true}}
            ]
        }"#;
        let parsed = parse_auto_tool_plan(raw).unwrap();
        assert_eq!(parsed.calls.len(), 2);
        assert_eq!(
            parsed.calls[0].args.get("limit").map(String::as_str),
            Some("3")
        );
        assert_eq!(
            parsed.calls[1].args.get("ignore_case").map(String::as_str),
            Some("true")
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
        let parsed = parse_subagent_plan(raw).unwrap();
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
}
