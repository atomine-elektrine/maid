use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

        let response = self
            .model
            .run(ModelRunRequest {
                group_name: group.name.clone(),
                prompt: prompt.to_string(),
                history,
            })
            .await?;

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
            self.execute_job_task(&task, &group).await
        } else {
            self.execute_model_task(&task, &group).await
        };

        match outcome {
            Ok(summary) => {
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
                        actor: request.actor,
                        result: "SUCCESS".to_string(),
                        created_at: Utc::now(),
                        metadata_json: Some(json!({
                            "task_id": task.id,
                            "trigger": request.trigger.as_str(),
                            "run_id": run.id,
                        })),
                    })
                    .await;
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
                        actor: request.actor,
                        result: "FAILED".to_string(),
                        created_at: Utc::now(),
                        metadata_json: Some(json!({
                            "task_id": task.id,
                            "trigger": request.trigger.as_str(),
                            "run_id": run.id,
                            "error": err_text,
                        })),
                    })
                    .await;
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

        let response = self
            .model
            .run(ModelRunRequest {
                group_name: group.name.clone(),
                prompt: task.prompt_template.clone(),
                history,
            })
            .await?;

        self.store
            .insert_message(&group.id, MessageRole::Assistant, &response.output_text)
            .await?;

        Ok(response.output_text)
    }

    async fn execute_job_task(&self, task: &Task, group: &Group) -> Result<String> {
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

        let result = self.sandbox.run_job(spec).await?;

        let summary = format!(
            "exit={}\nstdout:\n{}\nstderr:\n{}",
            result.exit_code, result.stdout, result.stderr
        );

        if result.exit_code != 0 {
            return Err(anyhow!(
                "sandbox job failed with exit code {}",
                result.exit_code
            ));
        }

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
