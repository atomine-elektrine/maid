use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub root_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageRole {
    User,
    Assistant,
    System,
}

impl MessageRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Assistant => "ASSISTANT",
            Self::System => "SYSTEM",
        }
    }

    pub fn from_db(value: &str) -> Result<Self> {
        match value {
            "USER" => Ok(Self::User),
            "ASSISTANT" => Ok(Self::Assistant),
            "SYSTEM" => Ok(Self::System),
            _ => Err(anyhow!("unknown message role: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub group_id: String,
    pub role: MessageRole,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    Active,
    Paused,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Paused => "PAUSED",
        }
    }

    pub fn from_db(value: &str) -> Result<Self> {
        match value {
            "ACTIVE" => Ok(Self::Active),
            "PAUSED" => Ok(Self::Paused),
            _ => Err(anyhow!("unknown task status: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub group_id: String,
    pub name: String,
    pub schedule_rrule: String,
    pub prompt_template: String,
    pub status: TaskStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskRunStatus {
    Running,
    Succeeded,
    Failed,
    Skipped,
}

impl TaskRunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Skipped => "SKIPPED",
        }
    }

    pub fn from_db(value: &str) -> Result<Self> {
        match value {
            "RUNNING" => Ok(Self::Running),
            "SUCCEEDED" => Ok(Self::Succeeded),
            "FAILED" => Ok(Self::Failed),
            "SKIPPED" => Ok(Self::Skipped),
            _ => Err(anyhow!("unknown task run status: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRun {
    pub id: String,
    pub task_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: TaskRunStatus,
    pub output_summary: Option<String>,
    pub error_text: Option<String>,
    pub scheduled_for: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audit {
    pub id: String,
    pub group_id: Option<String>,
    pub action: String,
    pub actor: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
    pub metadata_json: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TelegramPairingStatus {
    Pending,
    Approved,
}

impl TelegramPairingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Approved => "APPROVED",
        }
    }

    pub fn from_db(value: &str) -> Result<Self> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "APPROVED" => Ok(Self::Approved),
            _ => Err(anyhow!("unknown telegram pairing status: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramPairing {
    pub id: String,
    pub chat_id: i64,
    pub code: String,
    pub status: TelegramPairingStatus,
    pub requested_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewTask {
    pub group_id: String,
    pub name: String,
    pub schedule_rrule: String,
    pub prompt_template: String,
}

#[derive(Debug, Clone)]
pub struct NewTaskRun {
    pub task_id: String,
    pub started_at: DateTime<Utc>,
    pub status: TaskRunStatus,
    pub scheduled_for: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewAudit {
    pub group_id: Option<String>,
    pub action: String,
    pub actor: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
    pub metadata_json: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct TaskWithLastRun {
    pub task: Task,
    pub last_run_started_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ModelRunRequest {
    pub group_name: String,
    pub prompt: String,
    pub history: Vec<HistoryMessage>,
}

#[derive(Debug, Clone)]
pub struct ModelRunResult {
    pub output_text: String,
}

#[derive(Debug, Clone)]
pub struct SandboxJobSpec {
    pub group_root: PathBuf,
    pub config_path: PathBuf,
    pub command: Vec<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct SandboxJobResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskTrigger {
    Manual,
    Scheduled,
}

impl TaskTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "MANUAL",
            Self::Scheduled => "SCHEDULED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskExecutionRequest {
    pub task_id: String,
    pub trigger: TaskTrigger,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct TaskExecutionResult {
    pub run_id: String,
    pub status: TaskRunStatus,
    pub output_summary: Option<String>,
    pub error_text: Option<String>,
}

#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn run(&self, request: ModelRunRequest) -> Result<ModelRunResult>;
}

#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    async fn run_job(&self, spec: SandboxJobSpec) -> Result<SandboxJobResult>;
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_group(&self, name: &str, root_path: &str) -> Result<Group>;
    async fn list_groups(&self) -> Result<Vec<Group>>;
    async fn get_group_by_name(&self, name: &str) -> Result<Option<Group>>;
    async fn get_group_by_id(&self, id: &str) -> Result<Option<Group>>;

    async fn insert_message(
        &self,
        group_id: &str,
        role: MessageRole,
        content: &str,
    ) -> Result<Message>;
    async fn list_recent_messages(&self, group_id: &str, limit: i64) -> Result<Vec<Message>>;

    async fn create_task(&self, new_task: NewTask) -> Result<Task>;
    async fn list_tasks(&self, group_id: &str) -> Result<Vec<Task>>;
    async fn get_task(&self, task_id: &str) -> Result<Option<Task>>;
    async fn update_task_status(&self, task_id: &str, status: TaskStatus) -> Result<()>;
    async fn update_task(
        &self,
        task_id: &str,
        name: &str,
        schedule_rrule: &str,
        prompt_template: &str,
        status: TaskStatus,
    ) -> Result<bool>;
    async fn delete_task(&self, task_id: &str) -> Result<bool>;
    async fn clear_tasks_for_group(&self, group_id: &str) -> Result<u64>;
    async fn clear_all_tasks(&self) -> Result<u64>;

    async fn insert_task_run(&self, new_run: NewTaskRun) -> Result<TaskRun>;
    async fn finish_task_run(
        &self,
        run_id: &str,
        status: TaskRunStatus,
        output_summary: Option<&str>,
        error_text: Option<&str>,
        finished_at: DateTime<Utc>,
    ) -> Result<()>;
    async fn list_active_tasks_with_last_run(&self) -> Result<Vec<TaskWithLastRun>>;

    async fn insert_audit(&self, new_audit: NewAudit) -> Result<Audit>;

    async fn create_or_get_pending_telegram_pairing(&self, chat_id: i64)
        -> Result<TelegramPairing>;
    async fn approve_telegram_pairing_by_code(&self, code: &str) -> Result<bool>;
    async fn is_telegram_chat_approved(&self, chat_id: i64) -> Result<bool>;
    async fn list_pending_telegram_pairings(&self) -> Result<Vec<TelegramPairing>>;
}

#[async_trait]
pub trait TaskExecutor: Send + Sync {
    async fn execute(&self, request: TaskExecutionRequest) -> Result<TaskExecutionResult>;
}

#[derive(Debug, Clone)]
pub struct CoreSettings {
    pub group_root: PathBuf,
    pub config_path: PathBuf,
    pub default_job_timeout_secs: u64,
    pub max_job_timeout_secs: u64,
    pub allow_job_tasks_default: bool,
    pub allow_job_task_groups: Vec<String>,
}

impl Default for CoreSettings {
    fn default() -> Self {
        Self {
            group_root: PathBuf::from("groups"),
            config_path: PathBuf::from("config.toml"),
            default_job_timeout_secs: 120,
            max_job_timeout_secs: 900,
            allow_job_tasks_default: false,
            allow_job_task_groups: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CoreTelemetrySnapshot {
    pub prompt_runs_started_total: u64,
    pub prompt_runs_succeeded_total: u64,
    pub prompt_runs_failed_total: u64,
    pub prompt_input_chars_total: u64,
    pub prompt_output_chars_total: u64,
    pub prompt_history_messages_total: u64,
    pub prompt_elapsed_ms_total: u64,
    pub task_executions_started_total: u64,
    pub task_executions_manual_started_total: u64,
    pub task_executions_scheduled_started_total: u64,
    pub task_executions_succeeded_total: u64,
    pub task_executions_failed_total: u64,
    pub task_execution_elapsed_ms_total: u64,
    pub task_execution_output_chars_total: u64,
    pub model_tasks_started_total: u64,
    pub model_tasks_succeeded_total: u64,
    pub model_tasks_failed_total: u64,
    pub model_task_prompt_chars_total: u64,
    pub model_task_output_chars_total: u64,
    pub model_task_history_messages_total: u64,
    pub model_task_elapsed_ms_total: u64,
    pub job_tasks_started_total: u64,
    pub job_tasks_succeeded_total: u64,
    pub job_tasks_failed_total: u64,
    pub job_task_nonzero_exit_total: u64,
    pub job_task_stdout_bytes_total: u64,
    pub job_task_stderr_bytes_total: u64,
    pub job_task_elapsed_ms_total: u64,
}

struct CoreTelemetry {
    prompt_runs_started_total: AtomicU64,
    prompt_runs_succeeded_total: AtomicU64,
    prompt_runs_failed_total: AtomicU64,
    prompt_input_chars_total: AtomicU64,
    prompt_output_chars_total: AtomicU64,
    prompt_history_messages_total: AtomicU64,
    prompt_elapsed_ms_total: AtomicU64,
    task_executions_started_total: AtomicU64,
    task_executions_manual_started_total: AtomicU64,
    task_executions_scheduled_started_total: AtomicU64,
    task_executions_succeeded_total: AtomicU64,
    task_executions_failed_total: AtomicU64,
    task_execution_elapsed_ms_total: AtomicU64,
    task_execution_output_chars_total: AtomicU64,
    model_tasks_started_total: AtomicU64,
    model_tasks_succeeded_total: AtomicU64,
    model_tasks_failed_total: AtomicU64,
    model_task_prompt_chars_total: AtomicU64,
    model_task_output_chars_total: AtomicU64,
    model_task_history_messages_total: AtomicU64,
    model_task_elapsed_ms_total: AtomicU64,
    job_tasks_started_total: AtomicU64,
    job_tasks_succeeded_total: AtomicU64,
    job_tasks_failed_total: AtomicU64,
    job_task_nonzero_exit_total: AtomicU64,
    job_task_stdout_bytes_total: AtomicU64,
    job_task_stderr_bytes_total: AtomicU64,
    job_task_elapsed_ms_total: AtomicU64,
}

impl CoreTelemetry {
    const fn new() -> Self {
        Self {
            prompt_runs_started_total: AtomicU64::new(0),
            prompt_runs_succeeded_total: AtomicU64::new(0),
            prompt_runs_failed_total: AtomicU64::new(0),
            prompt_input_chars_total: AtomicU64::new(0),
            prompt_output_chars_total: AtomicU64::new(0),
            prompt_history_messages_total: AtomicU64::new(0),
            prompt_elapsed_ms_total: AtomicU64::new(0),
            task_executions_started_total: AtomicU64::new(0),
            task_executions_manual_started_total: AtomicU64::new(0),
            task_executions_scheduled_started_total: AtomicU64::new(0),
            task_executions_succeeded_total: AtomicU64::new(0),
            task_executions_failed_total: AtomicU64::new(0),
            task_execution_elapsed_ms_total: AtomicU64::new(0),
            task_execution_output_chars_total: AtomicU64::new(0),
            model_tasks_started_total: AtomicU64::new(0),
            model_tasks_succeeded_total: AtomicU64::new(0),
            model_tasks_failed_total: AtomicU64::new(0),
            model_task_prompt_chars_total: AtomicU64::new(0),
            model_task_output_chars_total: AtomicU64::new(0),
            model_task_history_messages_total: AtomicU64::new(0),
            model_task_elapsed_ms_total: AtomicU64::new(0),
            job_tasks_started_total: AtomicU64::new(0),
            job_tasks_succeeded_total: AtomicU64::new(0),
            job_tasks_failed_total: AtomicU64::new(0),
            job_task_nonzero_exit_total: AtomicU64::new(0),
            job_task_stdout_bytes_total: AtomicU64::new(0),
            job_task_stderr_bytes_total: AtomicU64::new(0),
            job_task_elapsed_ms_total: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> CoreTelemetrySnapshot {
        CoreTelemetrySnapshot {
            prompt_runs_started_total: self.prompt_runs_started_total.load(Ordering::Relaxed),
            prompt_runs_succeeded_total: self.prompt_runs_succeeded_total.load(Ordering::Relaxed),
            prompt_runs_failed_total: self.prompt_runs_failed_total.load(Ordering::Relaxed),
            prompt_input_chars_total: self.prompt_input_chars_total.load(Ordering::Relaxed),
            prompt_output_chars_total: self.prompt_output_chars_total.load(Ordering::Relaxed),
            prompt_history_messages_total: self
                .prompt_history_messages_total
                .load(Ordering::Relaxed),
            prompt_elapsed_ms_total: self.prompt_elapsed_ms_total.load(Ordering::Relaxed),
            task_executions_started_total: self
                .task_executions_started_total
                .load(Ordering::Relaxed),
            task_executions_manual_started_total: self
                .task_executions_manual_started_total
                .load(Ordering::Relaxed),
            task_executions_scheduled_started_total: self
                .task_executions_scheduled_started_total
                .load(Ordering::Relaxed),
            task_executions_succeeded_total: self
                .task_executions_succeeded_total
                .load(Ordering::Relaxed),
            task_executions_failed_total: self.task_executions_failed_total.load(Ordering::Relaxed),
            task_execution_elapsed_ms_total: self
                .task_execution_elapsed_ms_total
                .load(Ordering::Relaxed),
            task_execution_output_chars_total: self
                .task_execution_output_chars_total
                .load(Ordering::Relaxed),
            model_tasks_started_total: self.model_tasks_started_total.load(Ordering::Relaxed),
            model_tasks_succeeded_total: self.model_tasks_succeeded_total.load(Ordering::Relaxed),
            model_tasks_failed_total: self.model_tasks_failed_total.load(Ordering::Relaxed),
            model_task_prompt_chars_total: self
                .model_task_prompt_chars_total
                .load(Ordering::Relaxed),
            model_task_output_chars_total: self
                .model_task_output_chars_total
                .load(Ordering::Relaxed),
            model_task_history_messages_total: self
                .model_task_history_messages_total
                .load(Ordering::Relaxed),
            model_task_elapsed_ms_total: self.model_task_elapsed_ms_total.load(Ordering::Relaxed),
            job_tasks_started_total: self.job_tasks_started_total.load(Ordering::Relaxed),
            job_tasks_succeeded_total: self.job_tasks_succeeded_total.load(Ordering::Relaxed),
            job_tasks_failed_total: self.job_tasks_failed_total.load(Ordering::Relaxed),
            job_task_nonzero_exit_total: self.job_task_nonzero_exit_total.load(Ordering::Relaxed),
            job_task_stdout_bytes_total: self.job_task_stdout_bytes_total.load(Ordering::Relaxed),
            job_task_stderr_bytes_total: self.job_task_stderr_bytes_total.load(Ordering::Relaxed),
            job_task_elapsed_ms_total: self.job_task_elapsed_ms_total.load(Ordering::Relaxed),
        }
    }

    fn record_prompt_start(&self, prompt_len: usize) {
        self.prompt_runs_started_total
            .fetch_add(1, Ordering::Relaxed);
        self.prompt_input_chars_total
            .fetch_add(prompt_len as u64, Ordering::Relaxed);
    }

    fn record_prompt_success(&self, history_len: usize, output_len: usize, elapsed_ms: u64) {
        self.prompt_runs_succeeded_total
            .fetch_add(1, Ordering::Relaxed);
        self.prompt_history_messages_total
            .fetch_add(history_len as u64, Ordering::Relaxed);
        self.prompt_output_chars_total
            .fetch_add(output_len as u64, Ordering::Relaxed);
        self.prompt_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
    }

    fn record_prompt_failure(&self, history_len: usize, elapsed_ms: u64) {
        self.prompt_runs_failed_total
            .fetch_add(1, Ordering::Relaxed);
        self.prompt_history_messages_total
            .fetch_add(history_len as u64, Ordering::Relaxed);
        self.prompt_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
    }

    fn record_task_execution_start(&self, trigger: &str) {
        self.task_executions_started_total
            .fetch_add(1, Ordering::Relaxed);
        match trigger {
            "MANUAL" => {
                self.task_executions_manual_started_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            "SCHEDULED" => {
                self.task_executions_scheduled_started_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn record_task_execution_success(&self, summary_len: usize, elapsed_ms: u64) {
        self.task_executions_succeeded_total
            .fetch_add(1, Ordering::Relaxed);
        self.task_execution_output_chars_total
            .fetch_add(summary_len as u64, Ordering::Relaxed);
        self.task_execution_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
    }

    fn record_task_execution_failure(&self, elapsed_ms: u64) {
        self.task_executions_failed_total
            .fetch_add(1, Ordering::Relaxed);
        self.task_execution_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
    }

    fn record_model_task_start(&self, prompt_len: usize) {
        self.model_tasks_started_total
            .fetch_add(1, Ordering::Relaxed);
        self.model_task_prompt_chars_total
            .fetch_add(prompt_len as u64, Ordering::Relaxed);
    }

    fn record_model_task_success(&self, history_len: usize, output_len: usize, elapsed_ms: u64) {
        self.model_tasks_succeeded_total
            .fetch_add(1, Ordering::Relaxed);
        self.model_task_history_messages_total
            .fetch_add(history_len as u64, Ordering::Relaxed);
        self.model_task_output_chars_total
            .fetch_add(output_len as u64, Ordering::Relaxed);
        self.model_task_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
    }

    fn record_model_task_failure(&self, history_len: usize, elapsed_ms: u64) {
        self.model_tasks_failed_total
            .fetch_add(1, Ordering::Relaxed);
        self.model_task_history_messages_total
            .fetch_add(history_len as u64, Ordering::Relaxed);
        self.model_task_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
    }

    fn record_job_task_start(&self) {
        self.job_tasks_started_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_job_task_success(&self, stdout_bytes: usize, stderr_bytes: usize, elapsed_ms: u64) {
        self.job_tasks_succeeded_total
            .fetch_add(1, Ordering::Relaxed);
        self.job_task_stdout_bytes_total
            .fetch_add(stdout_bytes as u64, Ordering::Relaxed);
        self.job_task_stderr_bytes_total
            .fetch_add(stderr_bytes as u64, Ordering::Relaxed);
        self.job_task_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
    }

    fn record_job_task_failure(
        &self,
        nonzero_exit: bool,
        stdout_bytes: usize,
        stderr_bytes: usize,
        elapsed_ms: u64,
    ) {
        self.job_tasks_failed_total.fetch_add(1, Ordering::Relaxed);
        self.job_task_stdout_bytes_total
            .fetch_add(stdout_bytes as u64, Ordering::Relaxed);
        self.job_task_stderr_bytes_total
            .fetch_add(stderr_bytes as u64, Ordering::Relaxed);
        self.job_task_elapsed_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
        if nonzero_exit {
            self.job_task_nonzero_exit_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

static CORE_TELEMETRY: CoreTelemetry = CoreTelemetry::new();

pub fn telemetry_snapshot() -> CoreTelemetrySnapshot {
    CORE_TELEMETRY.snapshot()
}

pub struct MaidService<S, M, R>
where
    S: Storage,
    M: ModelProvider,
    R: SandboxRuntime,
{
    pub store: Arc<S>,
    pub model: Arc<M>,
    pub sandbox: Arc<R>,
    pub settings: CoreSettings,
}

impl<S, M, R> MaidService<S, M, R>
where
    S: Storage,
    M: ModelProvider,
    R: SandboxRuntime,
{
    pub fn new(store: Arc<S>, model: Arc<M>, sandbox: Arc<R>, settings: CoreSettings) -> Self {
        Self {
            store,
            model,
            sandbox,
            settings,
        }
    }

    pub async fn create_group(&self, name: &str, actor: &str) -> Result<Group> {
        let group_path = self.settings.group_root.join(name);
        std::fs::create_dir_all(&group_path).with_context(|| {
            format!(
                "failed to create group directory at {}",
                group_path.display()
            )
        })?;

        let group = self
            .store
            .create_group(name, &group_path.to_string_lossy())
            .await?;

        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: Some(group.id.clone()),
                action: "GROUP_CREATE".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "name": name })),
            })
            .await;

        Ok(group)
    }

    pub async fn ensure_group(&self, name: &str, actor: &str) -> Result<Group> {
        if let Some(group) = self.store.get_group_by_name(name).await? {
            return Ok(group);
        }
        self.create_group(name, actor).await
    }

    pub async fn list_groups(&self) -> Result<Vec<Group>> {
        self.store.list_groups().await
    }

    pub async fn run_prompt(&self, group_name: &str, prompt: &str, actor: &str) -> Result<String> {
        validate_prompt(prompt)?;
        let started = Instant::now();
        debug!(
            group_name,
            actor,
            prompt_len = prompt.len(),
            "prompt run started"
        );
        CORE_TELEMETRY.record_prompt_start(prompt.len());

        let group = self
            .store
            .get_group_by_name(group_name)
            .await?
            .ok_or_else(|| anyhow!("group not found: {group_name}"))?;

        self.store
            .insert_message(&group.id, MessageRole::User, prompt)
            .await?;

        let history = self
            .store
            .list_recent_messages(&group.id, 20)
            .await?
            .into_iter()
            .map(|m| HistoryMessage {
                role: m.role.as_str().to_string(),
                content: m.content,
            })
            .collect::<Vec<_>>();
        let history_len = history.len();

        let response = match self
            .model
            .run(ModelRunRequest {
                group_name: group.name.clone(),
                prompt: prompt.to_string(),
                history,
            })
            .await
        {
            Ok(response) => response,
            Err(err) => {
                CORE_TELEMETRY
                    .record_prompt_failure(history_len, started.elapsed().as_millis() as u64);
                warn!(
                    group_name,
                    actor,
                    prompt_len = prompt.len(),
                    history_len,
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %err,
                    "prompt run failed"
                );
                return Err(err);
            }
        };
        let output_len = response.output_text.len();

        self.store
            .insert_message(&group.id, MessageRole::Assistant, &response.output_text)
            .await?;

        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: Some(group.id),
                action: "PROMPT_RUN".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "prompt_length": prompt.len() })),
            })
            .await;

        CORE_TELEMETRY.record_prompt_success(
            history_len,
            output_len,
            started.elapsed().as_millis() as u64,
        );
        info!(
            group_name,
            actor,
            prompt_len = prompt.len(),
            history_len,
            output_len,
            elapsed_ms = started.elapsed().as_millis(),
            "prompt run completed"
        );
        Ok(response.output_text)
    }

    pub async fn create_task(
        &self,
        group_name: &str,
        name: &str,
        schedule_rrule: &str,
        prompt_template: &str,
        actor: &str,
    ) -> Result<Task> {
        validate_task_name(name)?;
        validate_schedule(schedule_rrule)?;
        validate_prompt(prompt_template)?;

        let group = self
            .store
            .get_group_by_name(group_name)
            .await?
            .ok_or_else(|| anyhow!("group not found: {group_name}"))?;

        if prompt_template.trim_start().starts_with("job:")
            && !self.is_job_task_allowed_for_group(&group.name)
        {
            return Err(anyhow!(
                "job tasks are disabled for group '{}' by policy",
                group.name
            ));
        }

        let task = self
            .store
            .create_task(NewTask {
                group_id: group.id.clone(),
                name: name.to_string(),
                schedule_rrule: schedule_rrule.to_string(),
                prompt_template: prompt_template.to_string(),
            })
            .await?;

        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: Some(group.id),
                action: "TASK_CREATE".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "task_id": task.id, "name": name })),
            })
            .await;

        Ok(task)
    }

    pub async fn list_tasks(&self, group_name: &str) -> Result<Vec<Task>> {
        let group = self
            .store
            .get_group_by_name(group_name)
            .await?
            .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
        self.store.list_tasks(&group.id).await
    }

    pub async fn update_task(
        &self,
        task_id: &str,
        name: &str,
        schedule_rrule: &str,
        prompt_template: &str,
        status: TaskStatus,
        actor: &str,
    ) -> Result<Option<Task>> {
        validate_task_name(name)?;
        validate_schedule(schedule_rrule)?;
        validate_prompt(prompt_template)?;

        let Some(existing) = self.store.get_task(task_id).await? else {
            let _ = self
                .store
                .insert_audit(NewAudit {
                    group_id: None,
                    action: "TASK_UPDATE".to_string(),
                    actor: actor.to_string(),
                    result: "NOT_FOUND".to_string(),
                    created_at: Utc::now(),
                    metadata_json: Some(json!({ "task_id": task_id })),
                })
                .await;
            return Ok(None);
        };

        let group = self
            .store
            .get_group_by_id(&existing.group_id)
            .await?
            .ok_or_else(|| anyhow!("group not found for task: {}", existing.group_id))?;

        if prompt_template.trim_start().starts_with("job:")
            && !self.is_job_task_allowed_for_group(&group.name)
        {
            return Err(anyhow!(
                "job tasks are disabled for group '{}' by policy",
                group.name
            ));
        }

        let status_label = status.as_str().to_string();
        self.store
            .update_task(task_id, name, schedule_rrule, prompt_template, status)
            .await?;
        let updated = self.store.get_task(task_id).await?;

        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: Some(group.id),
                action: "TASK_UPDATE".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(
                    json!({ "task_id": task_id, "name": name, "status": status_label }),
                ),
            })
            .await;

        Ok(updated)
    }

    pub async fn pause_task(&self, task_id: &str, actor: &str) -> Result<()> {
        self.store
            .update_task_status(task_id, TaskStatus::Paused)
            .await?;
        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TASK_PAUSE".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "task_id": task_id })),
            })
            .await;
        Ok(())
    }

    pub async fn resume_task(&self, task_id: &str, actor: &str) -> Result<()> {
        self.store
            .update_task_status(task_id, TaskStatus::Active)
            .await?;
        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TASK_RESUME".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "task_id": task_id })),
            })
            .await;
        Ok(())
    }

    pub async fn run_task_now(&self, task_id: &str, actor: &str) -> Result<TaskExecutionResult> {
        self.execute_task_inner(TaskExecutionRequest {
            task_id: task_id.to_string(),
            trigger: TaskTrigger::Manual,
            scheduled_for: None,
            actor: actor.to_string(),
        })
        .await
    }

    pub async fn delete_task(&self, task_id: &str, actor: &str) -> Result<bool> {
        let deleted = self.store.delete_task(task_id).await?;
        let result = if deleted { "SUCCESS" } else { "NOT_FOUND" };
        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TASK_DELETE".to_string(),
                actor: actor.to_string(),
                result: result.to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "task_id": task_id })),
            })
            .await;
        Ok(deleted)
    }

    pub async fn request_telegram_pairing(
        &self,
        chat_id: i64,
        actor: &str,
    ) -> Result<TelegramPairing> {
        let pairing = self
            .store
            .create_or_get_pending_telegram_pairing(chat_id)
            .await?;
        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TELEGRAM_PAIRING_REQUEST".to_string(),
                actor: actor.to_string(),
                result: "PENDING".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({
                    "chat_id": chat_id,
                    "code": pairing.code,
                })),
            })
            .await;
        Ok(pairing)
    }

    pub async fn approve_telegram_pairing(&self, code: &str, actor: &str) -> Result<bool> {
        let approved = self.store.approve_telegram_pairing_by_code(code).await?;
        let result = if approved { "APPROVED" } else { "NOT_FOUND" };
        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TELEGRAM_PAIRING_APPROVE".to_string(),
                actor: actor.to_string(),
                result: result.to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "code": code })),
            })
            .await;
        Ok(approved)
    }

    pub async fn is_telegram_chat_approved(&self, chat_id: i64) -> Result<bool> {
        self.store.is_telegram_chat_approved(chat_id).await
    }

    pub async fn list_pending_telegram_pairings(&self) -> Result<Vec<TelegramPairing>> {
        self.store.list_pending_telegram_pairings().await
    }

    pub async fn clear_tasks_for_group(&self, group_name: &str, actor: &str) -> Result<u64> {
        let group = self
            .store
            .get_group_by_name(group_name)
            .await?
            .ok_or_else(|| anyhow!("group not found: {group_name}"))?;

        let deleted = self.store.clear_tasks_for_group(&group.id).await?;
        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: Some(group.id),
                action: "TASK_CLEAR_GROUP".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "group_name": group_name, "deleted_count": deleted })),
            })
            .await;

        Ok(deleted)
    }

    pub async fn clear_all_tasks(&self, actor: &str) -> Result<u64> {
        let deleted = self.store.clear_all_tasks().await?;
        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TASK_CLEAR_ALL".to_string(),
                actor: actor.to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(json!({ "deleted_count": deleted })),
            })
            .await;
        Ok(deleted)
    }

    pub async fn record_missed_task_skip(
        &self,
        task_id: &str,
        scheduled_for: DateTime<Utc>,
        actor: &str,
    ) -> Result<()> {
        let run = self
            .store
            .insert_task_run(NewTaskRun {
                task_id: task_id.to_string(),
                started_at: scheduled_for,
                status: TaskRunStatus::Skipped,
                scheduled_for: Some(scheduled_for),
            })
            .await?;

        self.store
            .finish_task_run(
                &run.id,
                TaskRunStatus::Skipped,
                Some("skipped due to missed execution window"),
                None,
                Utc::now(),
            )
            .await?;

        let _ = self
            .store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TASK_SKIPPED_MISSED_WINDOW".to_string(),
                actor: actor.to_string(),
                result: "SKIPPED".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(
                    json!({ "task_id": task_id, "scheduled_for": scheduled_for.to_rfc3339() }),
                ),
            })
            .await;

        Ok(())
    }

    async fn execute_task_inner(
        &self,
        request: TaskExecutionRequest,
    ) -> Result<TaskExecutionResult> {
        let started = Instant::now();
        let task = self
            .store
            .get_task(&request.task_id)
            .await?
            .ok_or_else(|| anyhow!("task not found: {}", request.task_id))?;

        let group = self
            .store
            .get_group_by_id(&task.group_id)
            .await?
            .ok_or_else(|| anyhow!("group not found for task: {}", task.group_id))?;

        let actor = request.actor.clone();
        let trigger = request.trigger.as_str().to_string();
        debug!(
            task_id = %task.id,
            task_name = %task.name,
            group_name = %group.name,
            actor,
            trigger,
            scheduled_for = ?request.scheduled_for,
            "task execution started"
        );

        let run = self
            .store
            .insert_task_run(NewTaskRun {
                task_id: task.id.clone(),
                started_at: Utc::now(),
                status: TaskRunStatus::Running,
                scheduled_for: request.scheduled_for,
            })
            .await?;

        let outcome = if task.prompt_template.trim_start().starts_with("job:") {
            if !self.is_job_task_allowed_for_group(&group.name) {
                return Err(anyhow!(
                    "job tasks are disabled for group '{}' by policy",
                    group.name
                ));
            }
            CORE_TELEMETRY.record_task_execution_start(&trigger);
            self.execute_job_task(&task, &group).await
        } else {
            CORE_TELEMETRY.record_task_execution_start(&trigger);
            self.execute_model_task(&task, &group).await
        };

        match outcome {
            Ok(summary) => {
                let summary_len = summary.len();
                self.store
                    .finish_task_run(
                        &run.id,
                        TaskRunStatus::Succeeded,
                        Some(&summary),
                        None,
                        Utc::now(),
                    )
                    .await?;
                let _ = self
                    .store
                    .insert_audit(NewAudit {
                        group_id: Some(group.id),
                        action: "TASK_EXECUTE".to_string(),
                        actor: actor.clone(),
                        result: "SUCCESS".to_string(),
                        created_at: Utc::now(),
                        metadata_json: Some(json!({
                            "task_id": task.id,
                            "trigger": trigger.clone(),
                            "run_id": run.id,
                        })),
                    })
                    .await;
                CORE_TELEMETRY.record_task_execution_success(
                    summary_len,
                    started.elapsed().as_millis() as u64,
                );
                info!(
                    task_id = %task.id,
                    run_id = %run.id,
                    task_name = %task.name,
                    group_name = %group.name,
                    trigger,
                    summary_len,
                    elapsed_ms = started.elapsed().as_millis(),
                    "task execution succeeded"
                );
                Ok(TaskExecutionResult {
                    run_id: run.id,
                    status: TaskRunStatus::Succeeded,
                    output_summary: Some(summary),
                    error_text: None,
                })
            }
            Err(err) => {
                let err_text = format!("{err:#}");
                self.store
                    .finish_task_run(
                        &run.id,
                        TaskRunStatus::Failed,
                        None,
                        Some(&err_text),
                        Utc::now(),
                    )
                    .await?;
                let _ = self
                    .store
                    .insert_audit(NewAudit {
                        group_id: Some(group.id),
                        action: "TASK_EXECUTE".to_string(),
                        actor: actor.clone(),
                        result: "FAILED".to_string(),
                        created_at: Utc::now(),
                        metadata_json: Some(json!({
                            "task_id": task.id,
                            "trigger": trigger.clone(),
                            "run_id": run.id,
                            "error": err_text,
                        })),
                    })
                    .await;
                CORE_TELEMETRY.record_task_execution_failure(started.elapsed().as_millis() as u64);
                warn!(
                    task_id = %task.id,
                    run_id = %run.id,
                    task_name = %task.name,
                    group_name = %group.name,
                    trigger,
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %err_text,
                    "task execution failed"
                );
                Ok(TaskExecutionResult {
                    run_id: run.id,
                    status: TaskRunStatus::Failed,
                    output_summary: None,
                    error_text: Some(err_text),
                })
            }
        }
    }

    async fn execute_model_task(&self, task: &Task, group: &Group) -> Result<String> {
        let started = Instant::now();
        debug!(
            task_id = %task.id,
            task_name = %task.name,
            group_name = %group.name,
            prompt_len = task.prompt_template.len(),
            "model task started"
        );
        CORE_TELEMETRY.record_model_task_start(task.prompt_template.len());

        self.store
            .insert_message(&group.id, MessageRole::User, &task.prompt_template)
            .await?;

        let history = self
            .store
            .list_recent_messages(&group.id, 20)
            .await?
            .into_iter()
            .map(|m| HistoryMessage {
                role: m.role.as_str().to_string(),
                content: m.content,
            })
            .collect::<Vec<_>>();
        let history_len = history.len();

        let response = match self
            .model
            .run(ModelRunRequest {
                group_name: group.name.clone(),
                prompt: task.prompt_template.clone(),
                history,
            })
            .await
        {
            Ok(response) => response,
            Err(err) => {
                CORE_TELEMETRY
                    .record_model_task_failure(history_len, started.elapsed().as_millis() as u64);
                warn!(
                    task_id = %task.id,
                    task_name = %task.name,
                    group_name = %group.name,
                    prompt_len = task.prompt_template.len(),
                    history_len,
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %err,
                    "model task failed"
                );
                return Err(err);
            }
        };
        let output_len = response.output_text.len();

        self.store
            .insert_message(&group.id, MessageRole::Assistant, &response.output_text)
            .await?;

        CORE_TELEMETRY.record_model_task_success(
            history_len,
            output_len,
            started.elapsed().as_millis() as u64,
        );
        info!(
            task_id = %task.id,
            task_name = %task.name,
            group_name = %group.name,
            prompt_len = task.prompt_template.len(),
            history_len,
            output_len,
            elapsed_ms = started.elapsed().as_millis(),
            "model task completed"
        );
        Ok(response.output_text)
    }

    async fn execute_job_task(&self, task: &Task, group: &Group) -> Result<String> {
        let started = Instant::now();
        let raw = task
            .prompt_template
            .trim_start()
            .strip_prefix("job:")
            .ok_or_else(|| anyhow!("job task missing prefix"))?
            .trim();

        let cmd = shell_words::split(raw).context("failed to parse job command")?;
        if cmd.is_empty() {
            return Err(anyhow!("job command is empty"));
        }
        let command_name = cmd[0].clone();
        let argv_len = cmd.len();
        debug!(
            task_id = %task.id,
            task_name = %task.name,
            group_name = %group.name,
            command_name,
            argv_len,
            "job task started"
        );
        CORE_TELEMETRY.record_job_task_start();

        let group_root = PathBuf::from(&group.root_path);
        if !is_safe_group_root(&self.settings.group_root, &group_root)? {
            return Err(anyhow!("group root violates mount policy"));
        }

        let spec = SandboxJobSpec {
            group_root,
            config_path: self.settings.config_path.clone(),
            command: cmd,
            timeout_secs: self
                .settings
                .default_job_timeout_secs
                .min(self.settings.max_job_timeout_secs),
        };

        let result = match self.sandbox.run_job(spec).await {
            Ok(result) => result,
            Err(err) => {
                CORE_TELEMETRY.record_job_task_failure(
                    false,
                    0,
                    0,
                    started.elapsed().as_millis() as u64,
                );
                warn!(
                    task_id = %task.id,
                    task_name = %task.name,
                    group_name = %group.name,
                    command_name,
                    argv_len,
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %err,
                    "job task sandbox execution failed"
                );
                return Err(err);
            }
        };

        let summary = format!(
            "exit={}\nstdout:\n{}\nstderr:\n{}",
            result.exit_code, result.stdout, result.stderr
        );

        if result.exit_code != 0 {
            CORE_TELEMETRY.record_job_task_failure(
                true,
                result.stdout.len(),
                result.stderr.len(),
                started.elapsed().as_millis() as u64,
            );
            warn!(
                task_id = %task.id,
                task_name = %task.name,
                group_name = %group.name,
                command_name,
                argv_len,
                exit_code = result.exit_code,
                elapsed_ms = started.elapsed().as_millis(),
                "job task failed with non-zero exit"
            );
            return Err(anyhow!(
                "sandbox job failed with exit code {}",
                result.exit_code
            ));
        }

        CORE_TELEMETRY.record_job_task_success(
            result.stdout.len(),
            result.stderr.len(),
            started.elapsed().as_millis() as u64,
        );
        info!(
            task_id = %task.id,
            task_name = %task.name,
            group_name = %group.name,
            command_name,
            argv_len,
            exit_code = result.exit_code,
            stdout_bytes = result.stdout.len(),
            stderr_bytes = result.stderr.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "job task completed"
        );
        Ok(summary)
    }
}

impl<S, M, R> MaidService<S, M, R>
where
    S: Storage,
    M: ModelProvider,
    R: SandboxRuntime,
{
    fn is_job_task_allowed_for_group(&self, group_name: &str) -> bool {
        self.settings.allow_job_tasks_default
            || self
                .settings
                .allow_job_task_groups
                .iter()
                .any(|g| g == group_name)
    }
}

fn is_safe_group_root(allowed_root: &Path, candidate: &Path) -> Result<bool> {
    let root = allowed_root
        .canonicalize()
        .with_context(|| format!("failed to resolve root path {}", allowed_root.display()))?;
    let cand = candidate
        .canonicalize()
        .with_context(|| format!("failed to resolve candidate path {}", candidate.display()))?;
    Ok(cand.starts_with(root) && cand != Path::new("/"))
}

#[async_trait]
impl<S, M, R> TaskExecutor for MaidService<S, M, R>
where
    S: Storage,
    M: ModelProvider,
    R: SandboxRuntime,
{
    async fn execute(&self, request: TaskExecutionRequest) -> Result<TaskExecutionResult> {
        self.execute_task_inner(request).await
    }
}

pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn validate_prompt(prompt: &str) -> Result<()> {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("prompt must not be empty"));
    }
    if prompt.chars().count() > 8_000 {
        return Err(anyhow!("prompt exceeds 8000 characters"));
    }
    Ok(())
}

fn validate_task_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("task name must not be empty"));
    }
    if trimmed.chars().count() > 64 {
        return Err(anyhow!("task name exceeds 64 characters"));
    }
    Ok(())
}

fn validate_schedule(schedule: &str) -> Result<()> {
    if schedule.trim().is_empty() {
        return Err(anyhow!("schedule must not be empty"));
    }
    if schedule.chars().count() > 256 {
        return Err(anyhow!("schedule exceeds 256 characters"));
    }
    Ok(())
}

pub fn generate_pairing_code() -> String {
    let raw = Uuid::new_v4().simple().to_string();
    raw.chars().take(6).collect::<String>().to_uppercase()
}
