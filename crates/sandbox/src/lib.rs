use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use maid_core::{SandboxJobResult, SandboxJobSpec, SandboxRuntime};
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::warn;

#[derive(Debug, Clone)]
pub enum RuntimeKind {
    AppleContainer,
    Docker,
}

impl RuntimeKind {
    pub fn parse(value: &str) -> Result<Self> {
        Self::from_str(value)
    }
}

impl FromStr for RuntimeKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "apple_container" => Ok(Self::AppleContainer),
            "docker" => Ok(Self::Docker),
            _ => Err(anyhow!("unsupported runtime: {value}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub default_image: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            default_image: "alpine:3.20".to_string(),
        }
    }
}

pub struct AppleContainerRuntime {
    config: RuntimeConfig,
}

impl AppleContainerRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl SandboxRuntime for AppleContainerRuntime {
    async fn run_job(&self, spec: SandboxJobSpec) -> Result<SandboxJobResult> {
        validate_spec(&spec)?;
        let command = shell_words::join(spec.command.iter().map(|s| s.as_str()));

        let args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--workdir".to_string(),
            "/workspace".to_string(),
            "--volume".to_string(),
            format!("{}:/workspace", spec.group_root.display()),
            "--volume".to_string(),
            format!("{}:/app/config.toml:ro", spec.config_path.display()),
            self.config.default_image.clone(),
            "sh".to_string(),
            "-lc".to_string(),
            command,
        ];

        run_process("container", &args, spec.timeout_secs).await
    }
}

pub struct DockerRuntime {
    config: RuntimeConfig,
}

impl DockerRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl SandboxRuntime for DockerRuntime {
    async fn run_job(&self, spec: SandboxJobSpec) -> Result<SandboxJobResult> {
        validate_spec(&spec)?;
        let command = shell_words::join(spec.command.iter().map(|s| s.as_str()));

        let args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--network".to_string(),
            "none".to_string(),
            "-v".to_string(),
            format!("{}:/workspace", spec.group_root.display()),
            "-v".to_string(),
            format!("{}:/app/config.toml:ro", spec.config_path.display()),
            "-w".to_string(),
            "/workspace".to_string(),
            self.config.default_image.clone(),
            "sh".to_string(),
            "-lc".to_string(),
            command,
        ];

        run_process("docker", &args, spec.timeout_secs).await
    }
}

pub struct FallbackRuntime {
    primary: Box<dyn SandboxRuntime>,
    fallback: Box<dyn SandboxRuntime>,
}

impl FallbackRuntime {
    pub fn new(primary: Box<dyn SandboxRuntime>, fallback: Box<dyn SandboxRuntime>) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl SandboxRuntime for FallbackRuntime {
    async fn run_job(&self, spec: SandboxJobSpec) -> Result<SandboxJobResult> {
        match self.primary.run_job(spec.clone()).await {
            Ok(result) => Ok(result),
            Err(primary_err) => {
                warn!("primary runtime failed, trying fallback: {primary_err:#}");
                self.fallback
                    .run_job(spec)
                    .await
                    .context("both primary and fallback runtimes failed")
            }
        }
    }
}

pub fn build_runtime(kind: RuntimeKind, config: RuntimeConfig) -> Box<dyn SandboxRuntime> {
    match kind {
        RuntimeKind::AppleContainer => Box::new(FallbackRuntime::new(
            Box::new(AppleContainerRuntime::new(config.clone())),
            Box::new(DockerRuntime::new(config)),
        )),
        RuntimeKind::Docker => Box::new(DockerRuntime::new(config)),
    }
}

fn validate_spec(spec: &SandboxJobSpec) -> Result<()> {
    if spec.timeout_secs == 0 {
        return Err(anyhow!("timeout must be greater than zero"));
    }
    if spec.timeout_secs > 900 {
        return Err(anyhow!("timeout exceeds hard cap of 900 seconds"));
    }
    if spec.command.is_empty() {
        return Err(anyhow!("job command cannot be empty"));
    }

    std::fs::create_dir_all(&spec.group_root)
        .with_context(|| format!("failed to create group root {}", spec.group_root.display()))?;

    let canonical = spec.group_root.canonicalize().with_context(|| {
        format!(
            "failed to resolve group root path {}",
            spec.group_root.display()
        )
    })?;

    if canonical.as_path() == std::path::Path::new("/") {
        return Err(anyhow!("group root cannot be host root '/'"));
    }

    if !spec.config_path.exists() {
        return Err(anyhow!(
            "config path does not exist: {}",
            spec.config_path.display()
        ));
    }

    Ok(())
}

async fn run_process(binary: &str, args: &[String], timeout_secs: u64) -> Result<SandboxJobResult> {
    let mut command = Command::new(binary);
    command.args(args);

    let output = timeout(Duration::from_secs(timeout_secs), command.output()).await;
    match output {
        Ok(result) => {
            let output = result.with_context(|| format!("failed to launch process '{binary}'"))?;
            Ok(SandboxJobResult {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                exit_code: output.status.code().unwrap_or(-1),
            })
        }
        Err(_) => Ok(SandboxJobResult {
            stdout: String::new(),
            stderr: "process timed out".to_string(),
            exit_code: 124,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_process_times_out() {
        let args = vec!["-lc".to_string(), "sleep 2".to_string()];
        let result = run_process("sh", &args, 1).await.unwrap();
        assert_eq!(result.exit_code, 124);
        assert!(result.stderr.contains("timed out"));
    }
}
