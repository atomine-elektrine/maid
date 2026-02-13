use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct TelegramBotConfig {
    pub token: String,
    pub polling_timeout_seconds: u64,
    pub allowed_chat_ids: Option<Vec<i64>>,
    pub dm_policy: TelegramDmPolicy,
    pub activation_mode: TelegramActivationMode,
    pub mention_token: Option<String>,
    pub main_chat_id: Option<i64>,
    pub per_chat_activation_mode: Option<HashMap<i64, TelegramActivationMode>>,
    pub per_chat_mention_token: Option<HashMap<i64, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramDmPolicy {
    Open,
    Pairing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramActivationMode {
    Always,
    Mention,
}

#[derive(Debug, Clone)]
pub struct TelegramTask {
    pub id: String,
    pub name: String,
    pub status: String,
    pub schedule: String,
}

#[async_trait]
pub trait TelegramCommandHandler: Send + Sync {
    async fn ensure_group_exists(&self, group_name: &str) -> Result<()>;
    async fn run_prompt(&self, group_name: &str, prompt: &str) -> Result<String>;
    async fn create_task(
        &self,
        group_name: &str,
        name: &str,
        schedule: &str,
        prompt: &str,
    ) -> Result<String>;
    async fn list_tasks(&self, group_name: &str) -> Result<Vec<TelegramTask>>;
    async fn delete_task(&self, task_id: &str) -> Result<bool>;
    async fn pause_task(&self, task_id: &str) -> Result<()>;
    async fn resume_task(&self, task_id: &str) -> Result<()>;
    async fn run_task_now(&self, task_id: &str) -> Result<String>;
    async fn is_chat_authorized(&self, chat_id: i64) -> Result<bool>;
    async fn issue_pairing_code(&self, chat_id: i64) -> Result<String>;
    async fn approve_pairing_code(&self, code: &str) -> Result<bool>;
}

pub struct TelegramBot {
    client: Client,
    base_url: String,
    polling_timeout_seconds: u64,
    allowed_chat_ids: Option<HashSet<i64>>,
    dm_policy: TelegramDmPolicy,
    activation_mode: TelegramActivationMode,
    mention_token: Option<String>,
    main_chat_id: Option<i64>,
    per_chat_activation_mode: HashMap<i64, TelegramActivationMode>,
    per_chat_mention_token: HashMap<i64, String>,
}

impl TelegramBot {
    pub fn new(config: TelegramBotConfig) -> Result<Self> {
        if config.token.trim().is_empty() {
            return Err(anyhow!("telegram token cannot be empty"));
        }
        if config.polling_timeout_seconds == 0 {
            return Err(anyhow!("polling_timeout_seconds must be greater than zero"));
        }
        let request_timeout_secs = config.polling_timeout_seconds.saturating_add(15).max(20);

        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(request_timeout_secs))
            .build()
            .context("failed to build telegram HTTP client")?;

        Ok(Self {
            client,
            base_url: format!("https://api.telegram.org/bot{}", config.token),
            polling_timeout_seconds: config.polling_timeout_seconds,
            allowed_chat_ids: config
                .allowed_chat_ids
                .map(|ids| ids.into_iter().collect::<HashSet<_>>()),
            dm_policy: config.dm_policy,
            activation_mode: config.activation_mode,
            mention_token: config.mention_token,
            main_chat_id: config.main_chat_id,
            per_chat_activation_mode: config.per_chat_activation_mode.unwrap_or_default(),
            per_chat_mention_token: config.per_chat_mention_token.unwrap_or_default(),
        })
    }

    pub async fn run_until_shutdown(&self, handler: Arc<dyn TelegramCommandHandler>) -> Result<()> {
        info!("telegram channel started");
        let mut offset: Option<i64> = None;

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("telegram channel stopped");
                    break;
                }
                poll_result = self.poll_once(offset, handler.clone()) => {
                    match poll_result {
                        Ok(next_offset) => offset = Some(next_offset),
                        Err(err) => {
                            warn!("telegram poll error: {err:#}");
                            sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn poll_once(
        &self,
        current_offset: Option<i64>,
        handler: Arc<dyn TelegramCommandHandler>,
    ) -> Result<i64> {
        let response = self.get_updates(current_offset).await?;
        let mut next_offset = current_offset.unwrap_or(0);

        for update in response.result {
            next_offset = next_offset.max(update.update_id + 1);

            let message = match update.message {
                Some(message) => message,
                None => continue,
            };

            let text = match message.text {
                Some(text) if !text.trim().is_empty() => text,
                _ => continue,
            };

            let chat_id = message.chat.id;
            if let Err(err) = self.handle_message(chat_id, text, handler.clone()).await {
                warn!("failed to process telegram message: {err:#}");
                let _ = self
                    .send_message(chat_id, "Request failed. Check server logs for details.")
                    .await;
            }
        }

        Ok(next_offset)
    }

    async fn handle_message(
        &self,
        chat_id: i64,
        text: String,
        handler: Arc<dyn TelegramCommandHandler>,
    ) -> Result<()> {
        if !self.is_chat_allowed(chat_id) {
            return Ok(());
        }

        if matches!(self.dm_policy, TelegramDmPolicy::Pairing)
            && !handler.is_chat_authorized(chat_id).await?
        {
            let code = handler.issue_pairing_code(chat_id).await?;
            let pairing_msg = format!(
                "Pairing required.\nUse this code to approve from CLI: {}\nCommand: maid pairing approve --code {}",
                code, code
            );
            self.send_message(chat_id, &pairing_msg).await?;
            return Ok(());
        }

        let Some(routed_text) = self.route_inbound_text(chat_id, &text) else {
            return Ok(());
        };

        let group_name = self.telegram_group_name(chat_id);
        handler.ensure_group_exists(&group_name).await?;

        let trimmed = routed_text.trim();
        let mut parts = trimmed.splitn(2, ' ');
        let raw_cmd = parts.next().unwrap_or("");
        let args = parts.next().unwrap_or("").trim();
        let cmd = raw_cmd.split('@').next().unwrap_or(raw_cmd);

        let response = match cmd {
            "/start" | "/help" => self.help_text(chat_id),
            "/run" => {
                if args.is_empty() {
                    "Usage: /run <prompt>".to_string()
                } else {
                    handler.run_prompt(&group_name, args).await?
                }
            }
            "/task_create" => match parse_task_create_args(args) {
                Ok((name, schedule, prompt)) => {
                    let task_id = handler
                        .create_task(&group_name, &name, &schedule, &prompt)
                        .await?;
                    format!("Created task '{name}' ({task_id})")
                }
                Err(_) => "Usage: /task_create <name>|<rrule>|<prompt>".to_string(),
            },
            "/task_list" => {
                let tasks = handler.list_tasks(&group_name).await?;
                if tasks.is_empty() {
                    "No tasks configured for this chat.".to_string()
                } else {
                    format_task_list(tasks)
                }
            }
            "/task_delete" => {
                if args.is_empty() {
                    "Usage: /task_delete <task_id>".to_string()
                } else if handler.delete_task(args).await? {
                    format!("Deleted task {args}")
                } else {
                    format!("Task not found: {args}")
                }
            }
            "/task_pause" => {
                if args.is_empty() {
                    "Usage: /task_pause <task_id>".to_string()
                } else {
                    handler.pause_task(args).await?;
                    format!("Paused task {args}")
                }
            }
            "/task_resume" => {
                if args.is_empty() {
                    "Usage: /task_resume <task_id>".to_string()
                } else {
                    handler.resume_task(args).await?;
                    format!("Resumed task {args}")
                }
            }
            "/task_run" => {
                if args.is_empty() {
                    "Usage: /task_run <task_id>".to_string()
                } else {
                    handler.run_task_now(args).await?
                }
            }
            "/pair" => {
                if args.is_empty() {
                    "Usage: /pair <code>".to_string()
                } else if handler.approve_pairing_code(args).await? {
                    "Pairing code approved.".to_string()
                } else {
                    "Invalid or already-used pairing code.".to_string()
                }
            }
            _ if cmd.starts_with('/') => {
                "Unknown command. Send /help for supported commands.".to_string()
            }
            _ => handler.run_prompt(&group_name, trimmed).await?,
        };

        self.send_message(chat_id, &truncate_for_telegram(&response))
            .await?;

        Ok(())
    }

    fn is_chat_allowed(&self, chat_id: i64) -> bool {
        match &self.allowed_chat_ids {
            Some(set) => set.contains(&chat_id),
            None => true,
        }
    }

    fn route_inbound_text(&self, chat_id: i64, text: &str) -> Option<String> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }

        if trimmed.starts_with('/') {
            return Some(trimmed.to_string());
        }

        let activation_mode = self
            .per_chat_activation_mode
            .get(&chat_id)
            .copied()
            .unwrap_or(self.activation_mode);
        let mention_token = self
            .per_chat_mention_token
            .get(&chat_id)
            .map(|token| token.as_str())
            .or(self.mention_token.as_deref());

        match activation_mode {
            TelegramActivationMode::Always => Some(trimmed.to_string()),
            TelegramActivationMode::Mention => {
                let token = mention_token.map(str::trim).filter(|t| !t.is_empty())?;
                let lowered = trimmed.to_lowercase();
                let token_lower = token.to_lowercase();
                if !lowered.starts_with(&token_lower) {
                    return None;
                }
                let rest = trimmed[token.len()..].trim();
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_string())
                }
            }
        }
    }

    fn telegram_group_name(&self, chat_id: i64) -> String {
        if self.main_chat_id == Some(chat_id) {
            return "main".to_string();
        }
        format!("telegram-{chat_id}")
    }

    fn help_text(&self, chat_id: i64) -> String {
        let activation_mode = self
            .per_chat_activation_mode
            .get(&chat_id)
            .copied()
            .unwrap_or(self.activation_mode);
        let mention_hint = match activation_mode {
            TelegramActivationMode::Always => {
                "Chat activation: always-on (any message is treated as a prompt).".to_string()
            }
            TelegramActivationMode::Mention => {
                let token = self
                    .per_chat_mention_token
                    .get(&chat_id)
                    .map(|token| token.as_str())
                    .or(self.mention_token.as_deref())
                    .unwrap_or("@maid");
                format!("Chat activation: mention required (prefix prompts with '{token} ').")
            }
        };
        let dm_policy = match self.dm_policy {
            TelegramDmPolicy::Open => "DM policy: open".to_string(),
            TelegramDmPolicy::Pairing => {
                "DM policy: pairing required for unknown chats".to_string()
            }
        };

        [
            "maid telegram help",
            &mention_hint,
            &dm_policy,
            "",
            "Commands:",
            "/help - show this message",
            "/start - same as /help",
            "/run <prompt> - run a one-off prompt",
            "/task_create <name>|<rrule>|<prompt> - create a scheduled task",
            "/task_list - list tasks for this chat",
            "/task_delete <task_id> - delete a task",
            "/task_pause <task_id> - pause a task",
            "/task_resume <task_id> - resume a task",
            "/task_run <task_id> - run a task immediately",
            "/pair <code> - approve a pairing code (typically from the main/admin chat)",
            "",
            "Examples:",
            "/run summarize my open tasks",
            "/task_create checkin|every 15 minutes|Send me a short check-in",
            "/task_create checkin|FREQ=MINUTELY;INTERVAL=15|Send me a short check-in",
            "/task_create weekday-brief|FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;BYHOUR=9;BYMINUTE=0|Daily brief",
            "",
            "Notes:",
            "Schedule can be an RRULE (FREQ=...) or a simple phrase like 'every 15 minutes' or 'every weekday at 9am'.",
            "When activation is mention-required, non-command prompts must start with the mention token.",
            "If pairing is enabled, new chats will be shown a code; approve it via CLI (maid pairing approve --code <code>) or from the main/admin chat via /pair <code>.",
        ]
        .join("\n")
    }

    async fn get_updates(&self, offset: Option<i64>) -> Result<GetUpdatesResponse> {
        let mut request = self
            .client
            .get(format!("{}/getUpdates", self.base_url))
            .query(&[("timeout", self.polling_timeout_seconds.to_string())]);

        if let Some(offset) = offset {
            request = request.query(&[("offset", offset.to_string())]);
        }

        let response = request.send().await.map_err(|err| {
            if err.is_timeout() {
                anyhow!("telegram getUpdates timed out")
            } else {
                anyhow!("telegram getUpdates request failed")
            }
        })?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!("telegram getUpdates error ({status}): {body}"));
        }

        let payload = response
            .json::<GetUpdatesResponse>()
            .await
            .context("invalid telegram getUpdates payload")?;

        if !payload.ok {
            return Err(anyhow!("telegram getUpdates returned ok=false"));
        }

        Ok(payload)
    }

    async fn send_message(&self, chat_id: i64, text: &str) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/sendMessage", self.base_url))
            .json(&SendMessageRequest { chat_id, text })
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    anyhow!("telegram sendMessage timed out")
                } else {
                    anyhow!("telegram sendMessage request failed")
                }
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!("telegram sendMessage error ({status}): {body}"));
        }

        Ok(())
    }
}

fn parse_task_create_args(input: &str) -> Result<(String, String, String)> {
    let parts = input.splitn(3, '|').map(str::trim).collect::<Vec<_>>();

    if parts.len() != 3 || parts.iter().any(|v| v.is_empty()) {
        return Err(anyhow!("invalid task_create args"));
    }

    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

fn truncate_for_telegram(input: &str) -> String {
    const MAX_CHARS: usize = 3500;
    let count = input.chars().count();
    if count <= MAX_CHARS {
        return input.to_string();
    }

    let mut trimmed = input.chars().take(MAX_CHARS).collect::<String>();
    trimmed.push_str("\n\n[truncated]");
    trimmed
}

fn format_task_list(tasks: Vec<TelegramTask>) -> String {
    let mut lines = vec!["Tasks:".to_string()];
    for task in tasks.into_iter().take(25) {
        lines.push(format!(
            "- {} | {} | {} | {}",
            task.id, task.name, task.status, task.schedule
        ));
    }
    lines.join("\n")
}

#[derive(Debug, Deserialize)]
struct GetUpdatesResponse {
    ok: bool,
    result: Vec<TelegramUpdate>,
}

#[derive(Debug, Deserialize)]
struct TelegramUpdate {
    update_id: i64,
    message: Option<TelegramMessage>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessage {
    chat: TelegramChat,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramChat {
    id: i64,
}

#[derive(Debug, Serialize)]
struct SendMessageRequest<'a> {
    chat_id: i64,
    text: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_task_create_args_happy_path() {
        let parsed = parse_task_create_args("morning|FREQ=HOURLY;INTERVAL=1|hello").unwrap();
        assert_eq!(parsed.0, "morning");
        assert_eq!(parsed.1, "FREQ=HOURLY;INTERVAL=1");
        assert_eq!(parsed.2, "hello");
    }

    #[test]
    fn parse_task_create_args_rejects_bad_input() {
        assert!(parse_task_create_args("bad").is_err());
        assert!(parse_task_create_args("a||c").is_err());
    }

    #[test]
    fn truncate_for_telegram_limits_length() {
        let source = "a".repeat(4000);
        let output = truncate_for_telegram(&source);
        assert!(output.chars().count() < 3600);
        assert!(output.contains("[truncated]"));
    }

    #[test]
    fn mention_activation_routes_only_mentioned_messages() {
        let bot = TelegramBot {
            client: Client::builder().build().unwrap(),
            base_url: "http://example.com".to_string(),
            polling_timeout_seconds: 10,
            allowed_chat_ids: None,
            dm_policy: TelegramDmPolicy::Open,
            activation_mode: TelegramActivationMode::Mention,
            mention_token: Some("@maid".to_string()),
            main_chat_id: None,
            per_chat_activation_mode: HashMap::new(),
            per_chat_mention_token: HashMap::new(),
        };

        assert_eq!(
            bot.route_inbound_text(1, "@maid summarize this").unwrap(),
            "summarize this"
        );
        assert!(bot.route_inbound_text(1, "hello").is_none());
    }
}
