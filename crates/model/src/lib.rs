use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use maid_core::{HistoryMessage, ModelProvider, ModelRunRequest, ModelRunResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct OpenAiConfig {
    pub api_keys: Vec<String>,
    pub models: Vec<String>,
    pub base_url: String,
    pub max_retries: u32,
    pub retry_backoff_ms: u64,
    pub requests_per_minute: Option<u32>,
    pub requests_per_day: Option<u32>,
}

pub struct OpenAiProvider {
    client: Client,
    config: OpenAiConfig,
    usage: Mutex<ModelUsageState>,
}

#[derive(Default)]
struct ModelUsageState {
    minute_timestamps: Vec<chrono::DateTime<Utc>>,
    day_key: String,
    day_count: u32,
}

impl OpenAiProvider {
    pub fn new(config: OpenAiConfig) -> Result<Self> {
        if config.api_keys.is_empty() {
            return Err(anyhow!("at least one OpenAI API key is required"));
        }
        if config.models.is_empty() {
            return Err(anyhow!("at least one model candidate is required"));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(45))
            .build()
            .context("failed to create HTTP client")?;
        Ok(Self {
            client,
            config,
            usage: Mutex::new(ModelUsageState::default()),
        })
    }
}

#[derive(Serialize)]
struct ChatCompletionsRequest {
    model: String,
    messages: Vec<ChatMessage>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionsResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

#[async_trait]
impl ModelProvider for OpenAiProvider {
    async fn run(&self, request: ModelRunRequest) -> Result<ModelRunResult> {
        self.check_and_record_limits().await?;

        let mut messages = vec![ChatMessage {
            role: "system".to_string(),
            content: format!(
                "You are maid, a concise assistant. Current group: {}.",
                request.group_name
            ),
        }];

        for msg in request.history {
            messages.push(history_to_chat(msg));
        }

        let already_contains_prompt = messages
            .iter()
            .rev()
            .any(|m| m.role == "user" && m.content == request.prompt);
        if !already_contains_prompt {
            messages.push(ChatMessage {
                role: "user".to_string(),
                content: request.prompt,
            });
        }

        let endpoint = format!(
            "{}/chat/completions",
            self.config.base_url.trim_end_matches('/')
        );

        let mut attempt_errors = Vec::new();
        for model in &self.config.models {
            for api_key in &self.config.api_keys {
                let mut attempt = 0_u32;
                loop {
                    match self
                        .send_with_candidate(&endpoint, api_key, model, &messages)
                        .await
                    {
                        Ok(output_text) => return Ok(ModelRunResult { output_text }),
                        Err(err) => {
                            let retryable = is_retryable_error(&err);
                            attempt_errors.push(format!("model={model} attempt={attempt}: {err}"));
                            if retryable && attempt < self.config.max_retries {
                                attempt += 1;
                                tokio::time::sleep(Duration::from_millis(
                                    self.config.retry_backoff_ms.max(1),
                                ))
                                .await;
                                continue;
                            }
                        }
                    }
                    break;
                }
            }
        }

        Err(anyhow!(
            "all model candidates failed: {}",
            attempt_errors.join(" | ")
        ))
    }
}

impl OpenAiProvider {
    async fn check_and_record_limits(&self) -> Result<()> {
        let mut usage = self.usage.lock().await;
        let now = Utc::now();

        if let Some(rpm) = self.config.requests_per_minute {
            usage
                .minute_timestamps
                .retain(|timestamp| now.signed_duration_since(*timestamp).num_seconds() < 60);
            if usage.minute_timestamps.len() as u32 >= rpm {
                return Err(anyhow!(
                    "model rate limit exceeded: {} requests/minute",
                    rpm
                ));
            }
            usage.minute_timestamps.push(now);
        }

        if let Some(rpd) = self.config.requests_per_day {
            let day_key = now.format("%Y-%m-%d").to_string();
            if usage.day_key != day_key {
                usage.day_key = day_key;
                usage.day_count = 0;
            }
            if usage.day_count >= rpd {
                return Err(anyhow!("model daily budget exceeded: {} requests/day", rpd));
            }
            usage.day_count += 1;
        }

        Ok(())
    }

    async fn send_with_candidate(
        &self,
        endpoint: &str,
        api_key: &str,
        model: &str,
        messages: &[ChatMessage],
    ) -> Result<String> {
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(api_key)
            .json(&ChatCompletionsRequest {
                model: model.to_string(),
                messages: messages.to_vec(),
            })
            .send()
            .await
            .context("request failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!("http {status}: {body}"));
        }

        let payload = response
            .json::<ChatCompletionsResponse>()
            .await
            .context("invalid response payload")?;

        payload
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| anyhow!("no choices returned"))
    }
}

fn is_retryable_error(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}");
    text.contains("http 429")
        || text.contains("http 500")
        || text.contains("http 502")
        || text.contains("http 503")
        || text.contains("http 504")
        || text.contains("request failed")
}

fn history_to_chat(msg: HistoryMessage) -> ChatMessage {
    let role = match msg.role.as_str() {
        "ASSISTANT" => "assistant",
        "SYSTEM" => "system",
        _ => "user",
    }
    .to_string();

    ChatMessage {
        role,
        content: msg.content,
    }
}

#[derive(Default)]
pub struct EchoProvider;

#[async_trait]
impl ModelProvider for EchoProvider {
    async fn run(&self, request: ModelRunRequest) -> Result<ModelRunResult> {
        Ok(ModelRunResult {
            output_text: format!("echo: {}", request.prompt),
        })
    }
}
