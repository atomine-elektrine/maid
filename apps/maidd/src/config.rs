use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub database_path: String,
    pub group_root: String,
    pub runtime: String,
    pub model: ModelConfig,
    pub scheduler: SchedulerConfig,
    pub telegram: Option<TelegramConfig>,
    pub skills: Option<SkillsConfig>,
    pub plugins: Option<PluginsConfig>,
    pub tools: Option<ToolsConfig>,
    pub policy: Option<PolicyConfig>,
    pub security: Option<SecurityConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelConfig {
    pub provider: String,
    pub api_key_env: String,
    pub api_key_envs: Option<Vec<String>>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub fallback_models: Option<Vec<String>>,
    pub active_profile: Option<String>,
    pub profiles: Option<BTreeMap<String, ModelProfileConfig>>,
    pub ops: Option<ModelOpsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelProfileConfig {
    pub provider: Option<String>,
    pub api_key_env: Option<String>,
    pub api_key_envs: Option<Vec<String>>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub fallback_models: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelOpsConfig {
    pub max_retries: Option<u32>,
    pub retry_backoff_ms: Option<u64>,
    pub requests_per_minute: Option<u32>,
    pub requests_per_day: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SchedulerConfig {
    pub tick_seconds: u64,
    pub max_concurrency: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelegramConfig {
    pub bot_token_env: String,
    pub polling_timeout_seconds: Option<u64>,
    pub allowed_chat_ids: Option<Vec<i64>>,
    pub allow_job_tasks: Option<bool>,
    pub dm_policy: Option<String>,
    pub activation_mode: Option<String>,
    pub mention_token: Option<String>,
    pub main_chat_id: Option<i64>,
    pub per_chat_activation_mode: Option<BTreeMap<String, String>>,
    pub per_chat_mention_token: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginsConfig {
    pub directory: Option<String>,
    pub enabled: Option<Vec<String>>,
    pub allow_unlisted: Option<bool>,
    pub tool_allowlist: Option<Vec<String>>,
    pub tool_max_calls_per_minute: Option<u32>,
    pub validate_on_startup: Option<bool>,
    pub signing: Option<PluginSigningConfig>,
    pub trust: Option<PluginTrustConfig>,
    pub routing: Option<PluginRoutingConfig>,
    pub registry: Option<PluginRegistryConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SkillsConfig {
    pub enabled: Option<Vec<String>>,
    pub allow_unlisted: Option<bool>,
    pub registry_enabled: Option<bool>,
    pub registry_path: Option<String>,
    pub max_candidates: Option<usize>,
    pub max_invocations: Option<usize>,
    pub max_context_chars: Option<usize>,
    pub recent_message_limit: Option<i64>,
    pub task_limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginSigningConfig {
    pub require_signatures: Option<bool>,
    pub trusted_keys: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginRegistryConfig {
    pub index_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginTrustConfig {
    pub require_signatures: Option<bool>,
    pub trusted_publishers: Option<Vec<String>>,
    pub allow_unsigned_local: Option<bool>,
    pub quarantine_untrusted: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginRoutingConfig {
    pub enabled: Option<bool>,
    pub intent_rules: Option<Vec<PluginIntentRuleConfig>>,
    pub pinned: Option<Vec<PluginPinnedCapabilityConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginIntentRuleConfig {
    pub pattern: String,
    pub plugin: String,
    pub command: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginPinnedCapabilityConfig {
    pub capability: String,
    pub plugin: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub allow_job_tasks: Option<bool>,
    pub allow_job_task_groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolsConfig {
    pub web_fetch_timeout_seconds: Option<u64>,
    pub web_fetch_max_bytes: Option<u64>,
    pub web_fetch_allowed_domains: Option<Vec<String>>,
    pub grep_max_file_bytes: Option<u64>,
    pub grep_max_matches: Option<u64>,
    pub search_max_results: Option<u64>,
    pub auto_router_enabled: Option<bool>,
    pub auto_router_allowlist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub mode: Option<String>,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let cfg = toml::from_str::<Self>(&raw).context("failed to parse TOML config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.database_path.trim().is_empty() {
            return Err(anyhow!("database_path must not be empty"));
        }
        if self.group_root.trim().is_empty() {
            return Err(anyhow!("group_root must not be empty"));
        }
        if self.runtime != "apple_container" && self.runtime != "docker" {
            return Err(anyhow!("runtime must be one of: apple_container, docker"));
        }
        if self.model.provider.trim().is_empty() {
            return Err(anyhow!("model.provider must not be empty"));
        }
        if self.model.api_key_env.trim().is_empty() {
            return Err(anyhow!("model.api_key_env must not be empty"));
        }
        if let Some(api_envs) = &self.model.api_key_envs {
            if api_envs.is_empty() {
                return Err(anyhow!("model.api_key_envs must not be empty when set"));
            }
            for env_name in api_envs {
                if env_name.trim().is_empty() {
                    return Err(anyhow!("model.api_key_envs values must not be empty"));
                }
            }
        }
        if let Some(active_profile) = &self.model.active_profile {
            if active_profile.trim().is_empty() {
                return Err(anyhow!("model.active_profile must not be empty when set"));
            }
            let profiles = self
                .model
                .profiles
                .as_ref()
                .ok_or_else(|| anyhow!("model.active_profile requires model.profiles"))?;
            let profile = profiles.get(active_profile).ok_or_else(|| {
                anyhow!(
                    "model.active_profile '{}' missing from model.profiles",
                    active_profile
                )
            })?;
            validate_model_profile(profile, active_profile)?;
        }
        if let Some(profiles) = &self.model.profiles {
            for (name, profile) in profiles {
                if name.trim().is_empty() {
                    return Err(anyhow!("model.profiles keys must not be empty"));
                }
                validate_model_profile(profile, name)?;
            }
        }
        if let Some(ops) = &self.model.ops {
            if let Some(max_retries) = ops.max_retries {
                if max_retries > 20 {
                    return Err(anyhow!("model.ops.max_retries must be <= 20"));
                }
            }
            if let Some(backoff) = ops.retry_backoff_ms {
                if backoff == 0 || backoff > 60_000 {
                    return Err(anyhow!(
                        "model.ops.retry_backoff_ms must be between 1 and 60000"
                    ));
                }
            }
            if let Some(rpm) = ops.requests_per_minute {
                if rpm == 0 {
                    return Err(anyhow!("model.ops.requests_per_minute must be > 0"));
                }
            }
            if let Some(rpd) = ops.requests_per_day {
                if rpd == 0 {
                    return Err(anyhow!("model.ops.requests_per_day must be > 0"));
                }
            }
        }
        if let Some(fallback_models) = &self.model.fallback_models {
            for model in fallback_models {
                if model.trim().is_empty() {
                    return Err(anyhow!("model.fallback_models values must not be empty"));
                }
            }
        }
        if self.scheduler.tick_seconds == 0 {
            return Err(anyhow!("scheduler.tick_seconds must be > 0"));
        }
        if self.scheduler.max_concurrency == 0 {
            return Err(anyhow!("scheduler.max_concurrency must be > 0"));
        }
        if let Some(telegram) = &self.telegram {
            if telegram.bot_token_env.trim().is_empty() {
                return Err(anyhow!("telegram.bot_token_env must not be empty"));
            }
            if let Some(timeout) = telegram.polling_timeout_seconds {
                if timeout == 0 {
                    return Err(anyhow!(
                        "telegram.polling_timeout_seconds must be > 0 when set"
                    ));
                }
            }
            if let Some(ids) = &telegram.allowed_chat_ids {
                if ids.is_empty() {
                    return Err(anyhow!(
                        "telegram.allowed_chat_ids must not be empty when set"
                    ));
                }
            }
            if let Some(policy) = &telegram.dm_policy {
                if policy != "open" && policy != "pairing" {
                    return Err(anyhow!("telegram.dm_policy must be one of: open, pairing"));
                }
            }
            if let Some(mode) = &telegram.activation_mode {
                if mode != "always" && mode != "mention" {
                    return Err(anyhow!(
                        "telegram.activation_mode must be one of: always, mention"
                    ));
                }
            }
            if matches!(telegram.activation_mode.as_deref(), Some("mention"))
                && telegram
                    .mention_token
                    .as_ref()
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true)
            {
                return Err(anyhow!(
                    "telegram.mention_token must be set when activation_mode=mention"
                ));
            }
            if let Some(per_chat) = &telegram.per_chat_activation_mode {
                for (chat_id, mode) in per_chat {
                    parse_chat_id_key(chat_id)?;
                    if mode != "always" && mode != "mention" {
                        return Err(anyhow!(
                            "telegram.per_chat_activation_mode values must be always|mention"
                        ));
                    }
                }
            }
            if let Some(per_chat_token) = &telegram.per_chat_mention_token {
                for (chat_id, token) in per_chat_token {
                    parse_chat_id_key(chat_id)?;
                    if token.trim().is_empty() {
                        return Err(anyhow!(
                            "telegram.per_chat_mention_token values must not be empty"
                        ));
                    }
                }
            }
        }
        if let Some(plugins) = &self.plugins {
            if let Some(directory) = &plugins.directory {
                if directory.trim().is_empty() {
                    return Err(anyhow!("plugins.directory must not be empty when set"));
                }
            }
            if let Some(enabled) = &plugins.enabled {
                let mut seen = std::collections::HashSet::new();
                for name in enabled {
                    validate_plugin_name(name)?;
                    if !seen.insert(name) {
                        return Err(anyhow!(
                            "plugins.enabled contains duplicate plugin name: {name}"
                        ));
                    }
                }
            }
            if let Some(tool_allowlist) = &plugins.tool_allowlist {
                let mut seen = std::collections::HashSet::new();
                for tool in tool_allowlist {
                    validate_tool_name(tool)?;
                    if !seen.insert(tool) {
                        return Err(anyhow!(
                            "plugins.tool_allowlist contains duplicate tool name: {tool}"
                        ));
                    }
                }
            }
            if let Some(max_calls) = plugins.tool_max_calls_per_minute {
                if max_calls == 0 {
                    return Err(anyhow!(
                        "plugins.tool_max_calls_per_minute must be greater than zero when set"
                    ));
                }
            }
            if let Some(registry) = &plugins.registry {
                if let Some(index_path) = &registry.index_path {
                    if index_path.trim().is_empty() {
                        return Err(anyhow!("plugins.registry.index_path must not be empty"));
                    }
                }
            }
            if let Some(signing) = &plugins.signing {
                if let Some(keys) = &signing.trusted_keys {
                    for (key_id, public_key) in keys {
                        validate_signing_key_id(key_id)?;
                        if public_key.trim().is_empty() {
                            return Err(anyhow!(
                                "plugins.signing.trusted_keys values must not be empty"
                            ));
                        }
                    }
                }
                if signing.require_signatures.unwrap_or(false)
                    && signing
                        .trusted_keys
                        .as_ref()
                        .map(|keys| keys.is_empty())
                        .unwrap_or(true)
                {
                    return Err(anyhow!(
                        "plugins.signing.require_signatures=true requires plugins.signing.trusted_keys"
                    ));
                }
            }
            if let Some(trust) = &plugins.trust {
                if let Some(publishers) = &trust.trusted_publishers {
                    let mut seen = std::collections::HashSet::new();
                    for publisher in publishers {
                        validate_publisher_name(publisher)?;
                        if !seen.insert(publisher) {
                            return Err(anyhow!(
                                "plugins.trust.trusted_publishers contains duplicate value: {publisher}"
                            ));
                        }
                    }
                }
                if trust.require_signatures.unwrap_or(false)
                    && plugins
                        .signing
                        .as_ref()
                        .and_then(|signing| signing.trusted_keys.as_ref())
                        .map(|keys| keys.is_empty())
                        .unwrap_or(true)
                    && !trust.allow_unsigned_local.unwrap_or(true)
                {
                    return Err(anyhow!(
                        "plugins.trust.require_signatures=true requires plugins.signing.trusted_keys unless allow_unsigned_local=true"
                    ));
                }
            }
            if let Some(routing) = &plugins.routing {
                if let Some(intent_rules) = &routing.intent_rules {
                    for rule in intent_rules {
                        if rule.pattern.trim().is_empty() {
                            return Err(anyhow!(
                                "plugins.routing.intent_rules pattern must not be empty"
                            ));
                        }
                        validate_plugin_name(&rule.plugin)?;
                        if rule.command.trim().is_empty() {
                            return Err(anyhow!(
                                "plugins.routing.intent_rules command must not be empty"
                            ));
                        }
                    }
                }
                if let Some(pins) = &routing.pinned {
                    let mut seen = std::collections::HashSet::new();
                    for pin in pins {
                        validate_capability_name(&pin.capability)?;
                        validate_plugin_name(&pin.plugin)?;
                        if !seen.insert(&pin.capability) {
                            return Err(anyhow!(
                                "plugins.routing.pinned contains duplicate capability: {}",
                                pin.capability
                            ));
                        }
                    }
                }
            }
        }
        if let Some(skills) = &self.skills {
            if let Some(enabled) = &skills.enabled {
                let mut seen = std::collections::HashSet::new();
                for name in enabled {
                    validate_skill_name(name)?;
                    if !seen.insert(name) {
                        return Err(anyhow!(
                            "skills.enabled contains duplicate skill name: {name}"
                        ));
                    }
                }
            }
            if let Some(path) = &skills.registry_path {
                if path.trim().is_empty() {
                    return Err(anyhow!("skills.registry_path must not be empty when set"));
                }
            }
            if let Some(limit) = skills.max_candidates {
                if limit == 0 || limit > 10_000 {
                    return Err(anyhow!(
                        "skills.max_candidates must be between 1 and 10000 when set"
                    ));
                }
            }
            if let Some(limit) = skills.max_invocations {
                if limit == 0 || limit > 100 {
                    return Err(anyhow!(
                        "skills.max_invocations must be between 1 and 100 when set"
                    ));
                }
            }
            if let Some(max_chars) = skills.max_context_chars {
                if max_chars == 0 || max_chars > 20_000 {
                    return Err(anyhow!(
                        "skills.max_context_chars must be between 1 and 20000 when set"
                    ));
                }
            }
            if let Some(limit) = skills.recent_message_limit {
                if limit == 0 || limit > 50 {
                    return Err(anyhow!(
                        "skills.recent_message_limit must be between 1 and 50 when set"
                    ));
                }
            }
            if let Some(limit) = skills.task_limit {
                if limit == 0 || limit > 100 {
                    return Err(anyhow!(
                        "skills.task_limit must be between 1 and 100 when set"
                    ));
                }
            }
        }
        if let Some(policy) = &self.policy {
            if let Some(groups) = &policy.allow_job_task_groups {
                let mut seen = std::collections::HashSet::new();
                for group in groups {
                    if group.trim().is_empty() {
                        return Err(anyhow!(
                            "policy.allow_job_task_groups values must not be empty"
                        ));
                    }
                    if !seen.insert(group) {
                        return Err(anyhow!(
                            "policy.allow_job_task_groups contains duplicate group: {group}"
                        ));
                    }
                }
            }
        }
        if let Some(tools) = &self.tools {
            if let Some(timeout) = tools.web_fetch_timeout_seconds {
                if timeout == 0 {
                    return Err(anyhow!("tools.web_fetch_timeout_seconds must be > 0"));
                }
            }
            if let Some(max_bytes) = tools.web_fetch_max_bytes {
                if max_bytes == 0 {
                    return Err(anyhow!("tools.web_fetch_max_bytes must be > 0"));
                }
            }
            if let Some(max_bytes) = tools.grep_max_file_bytes {
                if max_bytes == 0 {
                    return Err(anyhow!("tools.grep_max_file_bytes must be > 0"));
                }
            }
            if let Some(max_matches) = tools.grep_max_matches {
                if max_matches == 0 {
                    return Err(anyhow!("tools.grep_max_matches must be > 0"));
                }
            }
            if let Some(max_results) = tools.search_max_results {
                if max_results == 0 {
                    return Err(anyhow!("tools.search_max_results must be > 0"));
                }
            }
            if let Some(allowed_domains) = &tools.web_fetch_allowed_domains {
                if allowed_domains.is_empty() {
                    return Err(anyhow!(
                        "tools.web_fetch_allowed_domains must not be empty when set"
                    ));
                }
                for domain in allowed_domains {
                    if domain.trim().is_empty() {
                        return Err(anyhow!(
                            "tools.web_fetch_allowed_domains values must not be empty"
                        ));
                    }
                }
            }
            if let Some(auto_allowlist) = &tools.auto_router_allowlist {
                let mut seen = std::collections::HashSet::new();
                for tool in auto_allowlist {
                    validate_tool_name(tool)?;
                    if !seen.insert(tool) {
                        return Err(anyhow!(
                            "tools.auto_router_allowlist contains duplicate tool name: {tool}"
                        ));
                    }
                }
            }
        }
        if let Some(security) = &self.security {
            if let Some(mode) = &security.mode {
                if mode != "development" && mode != "production" {
                    return Err(anyhow!(
                        "security.mode must be one of: development, production"
                    ));
                }
            }
        }

        if self.is_production() {
            if self.enabled_plugins().is_none() && !self.allow_unlisted_plugins() {
                return Err(anyhow!(
                    "production mode requires plugins.enabled allowlist (or plugins.allow_unlisted=true)"
                ));
            }
            if !self.plugin_require_signatures() {
                return Err(anyhow!(
                    "production mode requires plugin signature enforcement"
                ));
            }
        }
        Ok(())
    }

    pub fn enabled_skills(&self) -> Vec<String> {
        self.skills
            .as_ref()
            .and_then(|skills| skills.enabled.clone())
            .unwrap_or_else(|| {
                vec![
                    "memory.recent".to_string(),
                    "tasks.snapshot".to_string(),
                    "group.profile".to_string(),
                ]
            })
    }

    pub fn skill_allow_unlisted(&self) -> bool {
        self.skills
            .as_ref()
            .and_then(|skills| skills.allow_unlisted)
            .unwrap_or(false)
    }

    pub fn skill_registry_enabled(&self) -> bool {
        self.skills
            .as_ref()
            .and_then(|skills| skills.registry_enabled)
            .unwrap_or(true)
    }

    pub fn skill_registry_path(&self) -> String {
        self.skills
            .as_ref()
            .and_then(|skills| skills.registry_path.clone())
            .unwrap_or_else(|| "skills/registry.toml".to_string())
    }

    pub fn skill_max_candidates(&self) -> usize {
        self.skills
            .as_ref()
            .and_then(|skills| skills.max_candidates)
            .unwrap_or(64)
    }

    pub fn skill_max_invocations(&self) -> usize {
        self.skills
            .as_ref()
            .and_then(|skills| skills.max_invocations)
            .unwrap_or(5)
    }

    pub fn skill_max_context_chars(&self) -> usize {
        self.skills
            .as_ref()
            .and_then(|skills| skills.max_context_chars)
            .unwrap_or(4000)
    }

    pub fn skill_recent_message_limit(&self) -> i64 {
        self.skills
            .as_ref()
            .and_then(|skills| skills.recent_message_limit)
            .unwrap_or(8)
    }

    pub fn skill_task_limit(&self) -> usize {
        self.skills
            .as_ref()
            .and_then(|skills| skills.task_limit)
            .unwrap_or(12)
    }

    pub fn plugin_directory(&self) -> &str {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.directory.as_deref())
            .unwrap_or("plugins")
    }

    pub fn enabled_plugins(&self) -> Option<&[String]> {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.enabled.as_deref())
    }

    pub fn allow_unlisted_plugins(&self) -> bool {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.allow_unlisted)
            .unwrap_or(false)
    }

    pub fn is_plugin_enabled(&self, name: &str) -> bool {
        match self.enabled_plugins() {
            Some(enabled) => enabled.iter().any(|candidate| candidate == name),
            None => self.allow_unlisted_plugins(),
        }
    }

    pub fn validate_plugins_on_startup(&self) -> bool {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.validate_on_startup)
            .unwrap_or_else(|| {
                self.plugins
                    .as_ref()
                    .and_then(|plugins| plugins.enabled.as_ref())
                    .is_some()
            })
    }

    pub fn plugin_tool_allowlist(&self) -> Vec<String> {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.tool_allowlist.clone())
            .unwrap_or_default()
    }

    pub fn plugin_tool_max_calls_per_minute(&self) -> u32 {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.tool_max_calls_per_minute)
            .unwrap_or(60)
    }

    pub fn plugin_registry_index_path(&self) -> String {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.registry.as_ref())
            .and_then(|registry| registry.index_path.clone())
            .unwrap_or_else(|| "plugins/registry.toml".to_string())
    }

    pub fn plugin_require_signatures(&self) -> bool {
        if self.is_production() {
            return true;
        }
        let signing = self
            .plugins
            .as_ref()
            .and_then(|plugins| plugins.signing.as_ref())
            .and_then(|signing| signing.require_signatures)
            .unwrap_or(false);
        let trust = self
            .plugins
            .as_ref()
            .and_then(|plugins| plugins.trust.as_ref())
            .and_then(|trust| trust.require_signatures)
            .unwrap_or(false);
        signing || trust
    }

    pub fn plugin_trusted_signing_keys(&self) -> BTreeMap<String, String> {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.signing.as_ref())
            .and_then(|signing| signing.trusted_keys.clone())
            .unwrap_or_default()
    }

    pub fn plugin_trusted_publishers(&self) -> Vec<String> {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.trust.as_ref())
            .and_then(|trust| trust.trusted_publishers.clone())
            .unwrap_or_default()
    }

    pub fn plugin_allow_unsigned_local(&self) -> bool {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.trust.as_ref())
            .and_then(|trust| trust.allow_unsigned_local)
            .unwrap_or(true)
    }

    pub fn plugin_quarantine_untrusted(&self) -> bool {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.trust.as_ref())
            .and_then(|trust| trust.quarantine_untrusted)
            .unwrap_or(false)
    }

    pub fn plugin_routing_enabled(&self) -> bool {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.routing.as_ref())
            .and_then(|routing| routing.enabled)
            .unwrap_or(false)
    }

    pub fn plugin_routing_intent_rules(&self) -> Vec<PluginIntentRuleConfig> {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.routing.as_ref())
            .and_then(|routing| routing.intent_rules.clone())
            .unwrap_or_default()
    }

    pub fn plugin_routing_pins(&self) -> Vec<PluginPinnedCapabilityConfig> {
        self.plugins
            .as_ref()
            .and_then(|plugins| plugins.routing.as_ref())
            .and_then(|routing| routing.pinned.clone())
            .unwrap_or_default()
    }

    pub fn model_api_key_envs(&self) -> Vec<String> {
        if let Some(profile) = self.active_model_profile() {
            if let Some(envs) = &profile.api_key_envs {
                return envs.clone();
            }
            if let Some(env_name) = &profile.api_key_env {
                return vec![env_name.clone()];
            }
        }
        if let Some(envs) = &self.model.api_key_envs {
            return envs.clone();
        }
        vec![self.model.api_key_env.clone()]
    }

    pub fn model_candidates(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(profile) = self.active_model_profile() {
            if let Some(model) = &profile.model {
                out.push(model.clone());
            }
            if let Some(extra) = &profile.fallback_models {
                for model in extra {
                    if !out.contains(model) {
                        out.push(model.clone());
                    }
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
        out.push(
            self.model
                .model
                .clone()
                .unwrap_or_else(|| "gpt-4.1-mini".to_string()),
        );
        if let Some(extra) = &self.model.fallback_models {
            for model in extra {
                if !out.contains(model) {
                    out.push(model.clone());
                }
            }
        }
        out
    }

    pub fn model_provider_name(&self) -> String {
        self.active_model_profile()
            .and_then(|profile| profile.provider.clone())
            .unwrap_or_else(|| self.model.provider.clone())
    }

    pub fn model_base_url(&self) -> Option<String> {
        self.active_model_profile()
            .and_then(|profile| profile.base_url.clone())
            .or_else(|| self.model.base_url.clone())
    }

    pub fn model_max_retries(&self) -> u32 {
        self.model
            .ops
            .as_ref()
            .and_then(|ops| ops.max_retries)
            .unwrap_or(2)
    }

    pub fn model_retry_backoff_ms(&self) -> u64 {
        self.model
            .ops
            .as_ref()
            .and_then(|ops| ops.retry_backoff_ms)
            .unwrap_or(800)
    }

    pub fn model_requests_per_minute(&self) -> Option<u32> {
        self.model
            .ops
            .as_ref()
            .and_then(|ops| ops.requests_per_minute)
    }

    pub fn model_requests_per_day(&self) -> Option<u32> {
        self.model.ops.as_ref().and_then(|ops| ops.requests_per_day)
    }

    pub fn telegram_dm_policy(&self) -> &str {
        self.telegram
            .as_ref()
            .and_then(|cfg| cfg.dm_policy.as_deref())
            .unwrap_or("open")
    }

    pub fn telegram_activation_mode(&self) -> &str {
        self.telegram
            .as_ref()
            .and_then(|cfg| cfg.activation_mode.as_deref())
            .unwrap_or("always")
    }

    pub fn telegram_mention_token(&self) -> Option<&str> {
        self.telegram
            .as_ref()
            .and_then(|cfg| cfg.mention_token.as_deref())
    }

    pub fn telegram_main_chat_id(&self) -> Option<i64> {
        self.telegram.as_ref().and_then(|cfg| cfg.main_chat_id)
    }

    pub fn telegram_per_chat_activation_mode(&self) -> BTreeMap<i64, String> {
        parse_chat_map_string(
            self.telegram
                .as_ref()
                .and_then(|cfg| cfg.per_chat_activation_mode.clone()),
        )
    }

    pub fn telegram_per_chat_mention_token(&self) -> BTreeMap<i64, String> {
        parse_chat_map_string(
            self.telegram
                .as_ref()
                .and_then(|cfg| cfg.per_chat_mention_token.clone()),
        )
    }

    pub fn policy_allow_job_tasks_default(&self) -> bool {
        self.policy
            .as_ref()
            .and_then(|policy| policy.allow_job_tasks)
            .or_else(|| {
                self.telegram
                    .as_ref()
                    .and_then(|telegram| telegram.allow_job_tasks)
            })
            .unwrap_or(false)
    }

    pub fn policy_allow_job_task_groups(&self) -> Vec<String> {
        self.policy
            .as_ref()
            .and_then(|policy| policy.allow_job_task_groups.clone())
            .unwrap_or_default()
    }

    pub fn tool_web_fetch_timeout_seconds(&self) -> u64 {
        self.tools
            .as_ref()
            .and_then(|tools| tools.web_fetch_timeout_seconds)
            .unwrap_or(15)
    }

    pub fn tool_web_fetch_max_bytes(&self) -> u64 {
        self.tools
            .as_ref()
            .and_then(|tools| tools.web_fetch_max_bytes)
            .unwrap_or(131_072)
    }

    pub fn tool_web_fetch_allowed_domains(&self) -> Vec<String> {
        self.tools
            .as_ref()
            .and_then(|tools| tools.web_fetch_allowed_domains.clone())
            .unwrap_or_default()
    }

    pub fn tool_grep_max_file_bytes(&self) -> u64 {
        self.tools
            .as_ref()
            .and_then(|tools| tools.grep_max_file_bytes)
            .unwrap_or(1_048_576)
    }

    pub fn tool_grep_max_matches(&self) -> u64 {
        self.tools
            .as_ref()
            .and_then(|tools| tools.grep_max_matches)
            .unwrap_or(100)
    }

    pub fn tool_search_max_results(&self) -> u64 {
        self.tools
            .as_ref()
            .and_then(|tools| tools.search_max_results)
            .unwrap_or(5)
    }

    pub fn tool_auto_router_enabled(&self) -> bool {
        self.tools
            .as_ref()
            .and_then(|tools| tools.auto_router_enabled)
            .unwrap_or(true)
    }

    pub fn tool_auto_router_allowlist(&self) -> Vec<String> {
        self.tools
            .as_ref()
            .and_then(|tools| tools.auto_router_allowlist.clone())
            .unwrap_or_else(|| vec!["ops.web_fetch".to_string(), "ops.search".to_string()])
    }

    pub fn is_production(&self) -> bool {
        self.security
            .as_ref()
            .and_then(|security| security.mode.as_deref())
            .map(|mode| mode == "production")
            .unwrap_or(false)
    }

    fn active_model_profile(&self) -> Option<&ModelProfileConfig> {
        let active = self.model.active_profile.as_ref()?;
        self.model.profiles.as_ref()?.get(active)
    }
}

fn validate_model_profile(profile: &ModelProfileConfig, profile_name: &str) -> Result<()> {
    if let Some(provider) = &profile.provider {
        if provider.trim().is_empty() {
            return Err(anyhow!(
                "model.profiles.{}.provider must not be empty",
                profile_name
            ));
        }
    }
    if let Some(api_key_env) = &profile.api_key_env {
        if api_key_env.trim().is_empty() {
            return Err(anyhow!(
                "model.profiles.{}.api_key_env must not be empty",
                profile_name
            ));
        }
    }
    if let Some(api_key_envs) = &profile.api_key_envs {
        if api_key_envs.is_empty() {
            return Err(anyhow!(
                "model.profiles.{}.api_key_envs must not be empty when set",
                profile_name
            ));
        }
        for env_name in api_key_envs {
            if env_name.trim().is_empty() {
                return Err(anyhow!(
                    "model.profiles.{}.api_key_envs values must not be empty",
                    profile_name
                ));
            }
        }
    }
    if let Some(model) = &profile.model {
        if model.trim().is_empty() {
            return Err(anyhow!(
                "model.profiles.{}.model must not be empty",
                profile_name
            ));
        }
    }
    if let Some(fallback_models) = &profile.fallback_models {
        for model in fallback_models {
            if model.trim().is_empty() {
                return Err(anyhow!(
                    "model.profiles.{}.fallback_models values must not be empty",
                    profile_name
                ));
            }
        }
    }
    Ok(())
}

fn parse_chat_id_key(value: &str) -> Result<i64> {
    value
        .parse::<i64>()
        .map_err(|_| anyhow!("invalid chat id key '{}': expected integer string", value))
}

fn parse_chat_map_string(map: Option<BTreeMap<String, String>>) -> BTreeMap<i64, String> {
    let mut out = BTreeMap::new();
    if let Some(map) = map {
        for (key, value) in map {
            if let Ok(chat_id) = key.parse::<i64>() {
                out.insert(chat_id, value);
            }
        }
    }
    out
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

fn validate_skill_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("skill name must not be empty"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Err(anyhow!(
            "skill name must contain only lowercase letters, digits, dots, and hyphens"
        ));
    }
    Ok(())
}

fn validate_tool_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("tool name must not be empty"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "tool name must contain only lowercase letters, digits, dots, underscores, and hyphens"
        ));
    }
    Ok(())
}

fn validate_capability_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("capability name must not be empty"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "capability name must contain only lowercase letters, digits, dots, underscores, and hyphens"
        ));
    }
    Ok(())
}

fn validate_publisher_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("publisher name must not be empty"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "publisher name must contain only lowercase letters, digits, dots, underscores, and hyphens"
        ));
    }
    Ok(())
}

fn validate_signing_key_id(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("signing key id must not be empty"));
    }
    if !name.chars().all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_uppercase()
            || c.is_ascii_digit()
            || c == '-'
            || c == '_'
            || c == '.'
    }) {
        return Err(anyhow!(
            "signing key id must contain only letters, digits, dots, underscores, and hyphens"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_config() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"
        api_key_envs = ["OPENAI_API_KEY", "OPENAI_API_KEY_BACKUP"]
        model = "gpt-4.1-mini"
        fallback_models = ["gpt-4o-mini"]

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [telegram]
        bot_token_env = "TELEGRAM_BOT_TOKEN"
        polling_timeout_seconds = 30
        dm_policy = "pairing"
        activation_mode = "mention"
        mention_token = "@maid"

        [skills]
        enabled = ["memory.recent", "tasks.snapshot"]
        allow_unlisted = false
        registry_enabled = true
        registry_path = "skills/registry.toml"
        max_candidates = 128
        max_invocations = 5
        max_context_chars = 3000
        recent_message_limit = 6
        task_limit = 10

        [plugins]
        directory = "plugins"
        enabled = ["echo"]
        tool_allowlist = ["group.list", "task.list", "task.create"]
        tool_max_calls_per_minute = 30
        validate_on_startup = true

        [plugins.signing]
        require_signatures = false
        trusted_keys = { "local.dev" = "BASE64_PUBLIC_KEY" }

        [plugins.trust]
        trusted_publishers = ["maid-official", "acme-security"]
        allow_unsigned_local = true
        quarantine_untrusted = true

        [plugins.routing]
        enabled = true
        intent_rules = [{ pattern = "(?i)convert.*spl.*kql", plugin = "siem-convert", command = "convert" }]
        pinned = [{ capability = "siem.query.convert.ai", plugin = "siem-convert" }]

        [tools]
        web_fetch_timeout_seconds = 20
        web_fetch_max_bytes = 200000
        web_fetch_allowed_domains = ["example.com"]
        grep_max_file_bytes = 500000
        grep_max_matches = 50
        search_max_results = 8

        [policy]
        allow_job_tasks = false
        allow_job_task_groups = ["ops"]
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        parsed.validate().unwrap();
        assert!(parsed.is_plugin_enabled("echo"));
        assert!(!parsed.is_plugin_enabled("not-enabled"));
        assert_eq!(parsed.plugin_directory(), "plugins");
        assert!(parsed.validate_plugins_on_startup());
        assert_eq!(
            parsed.plugin_tool_allowlist(),
            vec!["group.list", "task.list", "task.create"]
        );
        assert_eq!(parsed.plugin_tool_max_calls_per_minute(), 30);
        assert!(!parsed.plugin_require_signatures());
        assert_eq!(parsed.plugin_trusted_signing_keys().len(), 1);
        assert_eq!(parsed.plugin_trusted_publishers().len(), 2);
        assert!(parsed.plugin_allow_unsigned_local());
        assert!(parsed.plugin_quarantine_untrusted());
        assert!(parsed.plugin_routing_enabled());
        assert_eq!(parsed.plugin_routing_intent_rules().len(), 1);
        assert_eq!(parsed.plugin_routing_pins().len(), 1);
        assert_eq!(parsed.model_api_key_envs().len(), 2);
        assert_eq!(parsed.model_candidates().len(), 2);
        assert_eq!(parsed.telegram_dm_policy(), "pairing");
        assert_eq!(parsed.telegram_activation_mode(), "mention");
        assert_eq!(parsed.telegram_mention_token(), Some("@maid"));
        assert_eq!(
            parsed.enabled_skills(),
            vec!["memory.recent".to_string(), "tasks.snapshot".to_string()]
        );
        assert!(!parsed.skill_allow_unlisted());
        assert!(parsed.skill_registry_enabled());
        assert_eq!(parsed.skill_registry_path(), "skills/registry.toml");
        assert_eq!(parsed.skill_max_candidates(), 128);
        assert_eq!(parsed.skill_max_invocations(), 5);
        assert_eq!(parsed.skill_max_context_chars(), 3000);
        assert_eq!(parsed.skill_recent_message_limit(), 6);
        assert_eq!(parsed.skill_task_limit(), 10);
        assert!(!parsed.policy_allow_job_tasks_default());
        assert_eq!(parsed.policy_allow_job_task_groups(), vec!["ops"]);
        assert_eq!(parsed.tool_web_fetch_timeout_seconds(), 20);
        assert_eq!(parsed.tool_web_fetch_max_bytes(), 200000);
        assert_eq!(
            parsed.tool_web_fetch_allowed_domains(),
            vec!["example.com".to_string()]
        );
        assert_eq!(parsed.tool_grep_max_file_bytes(), 500000);
        assert_eq!(parsed.tool_grep_max_matches(), 50);
        assert_eq!(parsed.tool_search_max_results(), 8);
        assert!(parsed.tool_auto_router_enabled());
    }

    #[test]
    fn reject_invalid_runtime() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "host"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_telegram_timeout() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [telegram]
        bot_token_env = "TELEGRAM_BOT_TOKEN"
        polling_timeout_seconds = 0
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_empty_allowed_chat_ids() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [telegram]
        bot_token_env = "TELEGRAM_BOT_TOKEN"
        allowed_chat_ids = []
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_plugin_name() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins]
        enabled = ["BadName"]
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_tool_name_in_plugin_allowlist() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins]
        tool_allowlist = ["BadTool"]
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_plugin_tool_rate_limit() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins]
        tool_max_calls_per_minute = 0
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_telegram_policy() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [telegram]
        bot_token_env = "TELEGRAM_BOT_TOKEN"
        dm_policy = "unknown"
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn plugins_default_to_disabled_without_allowlist() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        parsed.validate().unwrap();
        assert!(!parsed.is_plugin_enabled("anything"));
        assert!(!parsed.validate_plugins_on_startup());
        assert_eq!(parsed.plugin_directory(), "plugins");
        assert_eq!(parsed.telegram_dm_policy(), "open");
        assert_eq!(parsed.telegram_activation_mode(), "always");
        assert_eq!(parsed.model_candidates(), vec!["gpt-4.1-mini"]);
        assert_eq!(parsed.plugin_tool_max_calls_per_minute(), 60);
        assert!(!parsed.plugin_require_signatures());
        assert!(parsed.plugin_trusted_signing_keys().is_empty());
        assert!(parsed.plugin_trusted_publishers().is_empty());
        assert!(parsed.plugin_allow_unsigned_local());
        assert!(!parsed.plugin_quarantine_untrusted());
        assert!(!parsed.plugin_routing_enabled());
        assert!(parsed.plugin_routing_intent_rules().is_empty());
        assert!(parsed.plugin_routing_pins().is_empty());
        assert_eq!(parsed.tool_web_fetch_timeout_seconds(), 15);
        assert_eq!(parsed.tool_web_fetch_max_bytes(), 131_072);
        assert!(parsed.tool_web_fetch_allowed_domains().is_empty());
        assert_eq!(parsed.tool_grep_max_file_bytes(), 1_048_576);
        assert_eq!(parsed.tool_grep_max_matches(), 100);
        assert_eq!(parsed.tool_search_max_results(), 5);
        assert!(parsed.tool_auto_router_enabled());
        assert_eq!(
            parsed.enabled_skills(),
            vec![
                "memory.recent".to_string(),
                "tasks.snapshot".to_string(),
                "group.profile".to_string()
            ]
        );
        assert!(!parsed.skill_allow_unlisted());
        assert!(parsed.skill_registry_enabled());
        assert_eq!(parsed.skill_registry_path(), "skills/registry.toml");
        assert_eq!(parsed.skill_max_candidates(), 64);
        assert_eq!(parsed.skill_max_invocations(), 5);
        assert_eq!(parsed.skill_max_context_chars(), 4000);
        assert_eq!(parsed.skill_recent_message_limit(), 8);
        assert_eq!(parsed.skill_task_limit(), 12);
    }

    #[test]
    fn allow_unlisted_plugins_enables_default_plugin_access() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins]
        allow_unlisted = true
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        parsed.validate().unwrap();
        assert!(parsed.is_plugin_enabled("anything"));
    }

    #[test]
    fn reject_plugin_signing_with_missing_keys() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins.signing]
        require_signatures = true
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_signing_key_id() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins.signing]
        trusted_keys = { "bad key" = "abc" }
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_trusted_publisher() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins.trust]
        trusted_publishers = ["Bad Publisher"]
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_plugin_routing_pin() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [plugins.routing]
        enabled = true
        pinned = [{ capability = "Bad Capability", plugin = "echo" }]
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_tools_limits() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [tools]
        web_fetch_timeout_seconds = 0
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_skill_config() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [skills]
        enabled = ["Memory.Recent", "memory.recent"]
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn reject_invalid_skill_registry_limits() {
        let raw = r#"
        database_path = "data/assistant.db"
        group_root = "groups"
        runtime = "docker"

        [model]
        provider = "echo"
        api_key_env = "OPENAI_API_KEY"

        [scheduler]
        tick_seconds = 30
        max_concurrency = 2

        [skills]
        max_candidates = 0
        "#;

        let parsed: AppConfig = toml::from_str(raw).unwrap();
        assert!(parsed.validate().is_err());
    }
}
