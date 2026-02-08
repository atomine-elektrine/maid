use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;

#[derive(Debug, Clone, Deserialize)]
pub struct SkillManifest {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub executable: String,
    pub capabilities: Option<Vec<String>>,
    pub allowed_tools: Option<Vec<String>>,
    pub timeout_seconds: Option<u64>,
    pub env_allowlist: Option<Vec<String>>,
    pub signing_key_id: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SkillSpec {
    pub root_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub executable_path: PathBuf,
    pub manifest: SkillManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRequest {
    pub command: String,
    pub args: BTreeMap<String, String>,
    pub input: Option<String>,
    pub context: SkillContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillContext {
    pub actor: String,
    pub cwd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResponse {
    pub ok: bool,
    pub message: String,
    pub output: Option<String>,
    pub data: Option<Value>,
}

pub fn discover_skills(skills_dir: &Path) -> Result<Vec<SkillSpec>> {
    if !skills_dir.exists() {
        return Ok(Vec::new());
    }

    let mut specs = Vec::new();
    for entry in std::fs::read_dir(skills_dir)
        .with_context(|| format!("failed to read skills directory {}", skills_dir.display()))?
    {
        let entry = entry?;
        let entry_path = entry.path();
        if !entry_path.is_dir() {
            continue;
        }

        let manifest_path = entry_path.join("skill.toml");
        if !manifest_path.exists() {
            continue;
        }

        specs.push(load_skill_spec(&entry_path)?);
    }

    specs.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
    Ok(specs)
}

pub fn load_skill(skills_dir: &Path, name: &str) -> Result<SkillSpec> {
    let skill_dir = skills_dir.join(name);
    load_skill_spec(&skill_dir)
}

pub fn parse_kv_args(args: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for arg in args {
        let (key, value) = arg
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid --arg format: '{arg}', expected key=value"))?;
        if key.trim().is_empty() {
            return Err(anyhow!("argument key must not be empty"));
        }
        map.insert(key.trim().to_string(), value.to_string());
    }
    Ok(map)
}

pub async fn run_skill(spec: &SkillSpec, request: SkillRequest) -> Result<SkillResponse> {
    run_skill_with_env(spec, request, &[]).await
}

pub async fn run_skill_with_env(
    spec: &SkillSpec,
    request: SkillRequest,
    extra_env: &[(String, String)],
) -> Result<SkillResponse> {
    let timeout_secs = spec.manifest.timeout_seconds.unwrap_or(30).clamp(1, 600);

    let mut command = Command::new(&spec.executable_path);
    command
        .current_dir(&spec.root_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();

    if let Ok(path) = std::env::var("PATH") {
        command.env("PATH", path);
    }

    if let Ok(home) = std::env::var("HOME") {
        command.env("HOME", home);
    }

    let request_json =
        serde_json::to_string(&request).context("failed to serialize skill request")?;
    command.env("MAID_SKILL_REQUEST", request_json);

    for (key, value) in extra_env {
        command.env(key, value);
    }

    for key in spec.manifest.env_allowlist.clone().unwrap_or_default() {
        if let Ok(value) = std::env::var(&key) {
            command.env(key, value);
        }
    }

    let child = command.spawn().with_context(|| {
        format!(
            "failed to spawn skill executable {}",
            spec.executable_path.display()
        )
    })?;

    let output = timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| anyhow!("skill execution timed out after {timeout_secs}s"))?
        .context("skill process wait failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(anyhow!(
            "skill exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let payload = stdout.trim();
    if payload.is_empty() {
        return Err(anyhow!("skill returned empty stdout payload"));
    }

    let response = serde_json::from_str::<SkillResponse>(payload)
        .with_context(|| format!("invalid skill response JSON: {payload}"))?;

    Ok(response)
}

pub fn generate_ed25519_keypair_pem() -> Result<(String, String)> {
    let tmp_dir = unique_temp_dir("maid-skill-keygen");
    fs::create_dir_all(&tmp_dir)
        .with_context(|| format!("failed to create temp dir {}", tmp_dir.display()))?;
    let private_path = tmp_dir.join("private.pem");
    let public_path = tmp_dir.join("public.pem");

    run_openssl(&[
        "genpkey",
        "-algorithm",
        "ED25519",
        "-out",
        private_path
            .to_str()
            .ok_or_else(|| anyhow!("private key path is not valid UTF-8"))?,
    ])?;

    run_openssl(&[
        "pkey",
        "-in",
        private_path
            .to_str()
            .ok_or_else(|| anyhow!("private key path is not valid UTF-8"))?,
        "-pubout",
        "-out",
        public_path
            .to_str()
            .ok_or_else(|| anyhow!("public key path is not valid UTF-8"))?,
    ])?;

    let private_pem = fs::read_to_string(&private_path)
        .with_context(|| format!("failed to read {}", private_path.display()))?;
    let public_pem = fs::read_to_string(&public_path)
        .with_context(|| format!("failed to read {}", public_path.display()))?;
    fs::remove_dir_all(tmp_dir).ok();
    Ok((private_pem, public_pem))
}

pub fn sign_skill(spec: &SkillSpec, key_id: &str, private_key_path: &Path) -> Result<String> {
    validate_key_id(key_id)?;
    let payload = skill_signature_payload(spec, key_id)?;
    let payload_path = write_temp_file("maid-skill-sign-payload", &payload)?;
    let signature_path = unique_temp_file("maid-skill-signature");
    run_openssl(&[
        "pkeyutl",
        "-sign",
        "-inkey",
        private_key_path
            .to_str()
            .ok_or_else(|| anyhow!("private key path is not valid UTF-8"))?,
        "-rawin",
        "-in",
        payload_path
            .to_str()
            .ok_or_else(|| anyhow!("payload path is not valid UTF-8"))?,
        "-out",
        signature_path
            .to_str()
            .ok_or_else(|| anyhow!("signature path is not valid UTF-8"))?,
    ])?;
    let signature = fs::read(&signature_path)
        .with_context(|| format!("failed to read signature {}", signature_path.display()))?;
    fs::remove_file(payload_path).ok();
    fs::remove_file(signature_path).ok();
    Ok(hex_encode(&signature))
}

pub fn verify_skill_signature(
    spec: &SkillSpec,
    trusted_public_keys: &BTreeMap<String, String>,
    require_signature: bool,
) -> Result<()> {
    let Some(key_id) = spec.manifest.signing_key_id.as_deref() else {
        if require_signature {
            return Err(anyhow!(
                "skill '{}' is missing signing_key_id/signature",
                spec.manifest.name
            ));
        }
        return Ok(());
    };
    let Some(signature_b64) = spec.manifest.signature.as_deref() else {
        if require_signature {
            return Err(anyhow!(
                "skill '{}' is missing signing_key_id/signature",
                spec.manifest.name
            ));
        }
        return Ok(());
    };

    let trusted_key = trusted_public_keys.get(key_id).ok_or_else(|| {
        anyhow!(
            "skill '{}' uses unknown signing key id '{}'",
            spec.manifest.name,
            key_id
        )
    })?;
    let signature = hex_decode(signature_b64)?;
    let payload = skill_signature_payload(spec, key_id)?;
    let payload_path = write_temp_file("maid-skill-verify-payload", &payload)?;
    let sig_path = write_temp_file("maid-skill-verify-signature", &signature)?;
    let verified = run_openssl_checked(&[
        "pkeyutl",
        "-verify",
        "-pubin",
        "-inkey",
        trusted_key,
        "-rawin",
        "-in",
        payload_path
            .to_str()
            .ok_or_else(|| anyhow!("payload path is not valid UTF-8"))?,
        "-sigfile",
        sig_path
            .to_str()
            .ok_or_else(|| anyhow!("signature path is not valid UTF-8"))?,
    ])
    .context("failed to run openssl verification command")?;
    fs::remove_file(payload_path).ok();
    fs::remove_file(sig_path).ok();
    if !verified {
        return Err(anyhow!(
            "skill '{}' has invalid signature",
            spec.manifest.name
        ));
    }
    Ok(())
}

pub fn write_skill_signature(manifest_path: &Path, key_id: &str, signature: &str) -> Result<()> {
    validate_key_id(key_id)?;
    if signature.trim().is_empty() {
        return Err(anyhow!("signature must not be empty"));
    }

    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read skill manifest {}", manifest_path.display()))?;
    let mut value: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("failed to parse skill manifest {}", manifest_path.display()))?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| anyhow!("skill manifest must be a TOML table"))?;
    table.insert(
        "signing_key_id".to_string(),
        toml::Value::String(key_id.to_string()),
    );
    table.insert(
        "signature".to_string(),
        toml::Value::String(signature.to_string()),
    );
    let formatted = toml::to_string_pretty(&value).with_context(|| {
        format!(
            "failed to serialize skill manifest {}",
            manifest_path.display()
        )
    })?;
    std::fs::write(manifest_path, formatted)
        .with_context(|| format!("failed to write skill manifest {}", manifest_path.display()))?;
    Ok(())
}

fn load_skill_spec(skill_dir: &Path) -> Result<SkillSpec> {
    if !skill_dir.exists() {
        return Err(anyhow!(
            "skill directory not found: {}",
            skill_dir.display()
        ));
    }

    let root_dir = skill_dir
        .canonicalize()
        .with_context(|| format!("failed to resolve skill directory {}", skill_dir.display()))?;
    let manifest_path = root_dir.join("skill.toml");

    let raw = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read skill manifest {}", manifest_path.display()))?;
    let manifest = toml::from_str::<SkillManifest>(&raw)
        .with_context(|| format!("failed to parse skill manifest {}", manifest_path.display()))?;

    validate_manifest(&manifest)?;

    let executable_rel = Path::new(&manifest.executable);
    if executable_rel.is_absolute() {
        return Err(anyhow!("skill executable must be a relative path"));
    }

    let executable_path = root_dir.join(executable_rel);
    let executable_path = executable_path.canonicalize().with_context(|| {
        format!(
            "failed to resolve executable path {}",
            executable_path.display()
        )
    })?;

    if !executable_path.starts_with(&root_dir) {
        return Err(anyhow!("skill executable path escapes skill directory"));
    }

    if !executable_path.is_file() {
        return Err(anyhow!("skill executable is not a file"));
    }

    if manifest.name
        != root_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
    {
        return Err(anyhow!(
            "skill name '{}' must match directory name '{}'",
            manifest.name,
            root_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
        ));
    }

    Ok(SkillSpec {
        root_dir,
        manifest_path,
        executable_path,
        manifest,
    })
}

fn validate_manifest(manifest: &SkillManifest) -> Result<()> {
    if manifest.name.trim().is_empty() {
        return Err(anyhow!("skill name must not be empty"));
    }
    if !manifest
        .name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(anyhow!(
            "skill name must contain only lowercase letters, digits, and hyphens"
        ));
    }
    if manifest.version.trim().is_empty() {
        return Err(anyhow!("skill version must not be empty"));
    }
    if manifest.executable.trim().is_empty() {
        return Err(anyhow!("skill executable must not be empty"));
    }
    for tool in manifest.allowed_tools.clone().unwrap_or_default() {
        validate_tool_name(&tool)?;
    }
    match (
        manifest.signing_key_id.as_deref(),
        manifest.signature.as_deref(),
    ) {
        (Some(key_id), Some(signature)) => {
            validate_key_id(key_id)?;
            if signature.trim().is_empty() {
                return Err(anyhow!("skill signature must not be empty"));
            }
        }
        (None, None) => {}
        _ => {
            return Err(anyhow!(
                "skill signing fields must include both signing_key_id and signature"
            ));
        }
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

fn validate_key_id(name: &str) -> Result<()> {
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

fn skill_signature_payload(spec: &SkillSpec, key_id: &str) -> Result<Vec<u8>> {
    let capabilities = normalized_list(spec.manifest.capabilities.as_ref());
    let allowed_tools = normalized_list(spec.manifest.allowed_tools.as_ref());
    let env_allowlist = normalized_list(spec.manifest.env_allowlist.as_ref());
    let executable_bytes = std::fs::read(&spec.executable_path).with_context(|| {
        format!(
            "failed to read skill executable {}",
            spec.executable_path.display()
        )
    })?;
    let executable_fingerprint = hex_encode(&executable_bytes);

    let payload = format!(
        "maid-skill-signature-v1\nname={}\nversion={}\nkey_id={}\nexecutable={}\ntimeout_seconds={}\ncapabilities={}\nallowed_tools={}\nenv_allowlist={}\nexecutable_hex={}\n",
        spec.manifest.name,
        spec.manifest.version,
        key_id,
        spec.manifest.executable,
        spec.manifest.timeout_seconds.unwrap_or(30),
        capabilities,
        allowed_tools,
        env_allowlist,
        executable_fingerprint
    );
    Ok(payload.into_bytes())
}

fn normalized_list(values: Option<&Vec<String>>) -> String {
    let mut values = values.cloned().unwrap_or_default();
    values.sort();
    values.join(",")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
    let value = input.trim();
    if value.len() % 2 != 0 {
        return Err(anyhow!("hex value must have even length"));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for idx in (0..bytes.len()).step_by(2) {
        let high = (bytes[idx] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex value"))?;
        let low = (bytes[idx + 1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex value"))?;
        out.push(((high << 4) | low) as u8);
    }
    Ok(out)
}

fn run_openssl(args: &[&str]) -> Result<()> {
    let output = StdCommand::new("openssl")
        .args(args)
        .output()
        .with_context(|| format!("failed to run openssl {:?}", args))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(anyhow!("openssl {:?} failed: {}", args, stderr.trim()))
}

fn run_openssl_checked(args: &[&str]) -> Result<bool> {
    let output = StdCommand::new("openssl")
        .args(args)
        .output()
        .with_context(|| format!("failed to run openssl {:?}", args))?;
    if output.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("signature verification failure")
        || stderr.contains("invalid signature")
        || stderr.contains("verification failure")
    {
        return Ok(false);
    }
    Err(anyhow!("openssl {:?} failed: {}", args, stderr.trim()))
}

fn write_temp_file(prefix: &str, contents: &[u8]) -> Result<PathBuf> {
    let path = unique_temp_file(prefix);
    fs::write(&path, contents)
        .with_context(|| format!("failed to write temporary file {}", path.display()))?;
    Ok(path)
}

fn unique_temp_file(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}.tmp"))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{ts}"))
    }

    #[test]
    fn parse_kv_args_ok() {
        let args = vec!["a=1".to_string(), "b=two".to_string()];
        let parsed = parse_kv_args(&args).unwrap();
        assert_eq!(parsed.get("a").unwrap(), "1");
        assert_eq!(parsed.get("b").unwrap(), "two");
    }

    #[test]
    fn parse_kv_args_rejects_invalid() {
        let args = vec!["broken".to_string()];
        assert!(parse_kv_args(&args).is_err());
    }

    #[test]
    fn skill_signature_roundtrip() {
        let sandbox = unique_temp_dir("maid-skill-sdk-signature");
        let root = sandbox.join("signed");
        fs::create_dir_all(&root).expect("failed to create temp dir");
        fs::write(
            root.join("skill.toml"),
            r#"
name = "signed"
version = "0.1.0"
description = "signed skill"
executable = "./run.sh"
capabilities = ["bridge.run"]
allowed_tools = ["group.list"]
timeout_seconds = 30
env_allowlist = []
"#
            .trim_start(),
        )
        .expect("failed to write skill manifest");
        fs::write(root.join("run.sh"), "#!/usr/bin/env bash\necho ok\n")
            .expect("failed to write skill executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(root.join("run.sh"))
                .expect("failed to stat run.sh")
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(root.join("run.sh"), perms).expect("failed to chmod run.sh");
        }

        let spec = load_skill_spec(&root).expect("failed to load skill spec");
        let (private_key, public_key) =
            generate_ed25519_keypair_pem().expect("failed to generate keypair");
        let private_key_path = sandbox.join("private.pem");
        let public_key_path = sandbox.join("public.pem");
        fs::write(&private_key_path, private_key).expect("failed to write private key");
        fs::write(&public_key_path, public_key).expect("failed to write public key");

        let signature = sign_skill(&spec, "local.dev", &private_key_path).expect("failed to sign");
        write_skill_signature(&spec.manifest_path, "local.dev", &signature)
            .expect("failed to write signature");

        let signed_spec = load_skill_spec(&root).expect("failed to reload signed skill");
        let mut trusted = BTreeMap::new();
        trusted.insert(
            "local.dev".to_string(),
            public_key_path.display().to_string(),
        );
        verify_skill_signature(&signed_spec, &trusted, true).expect("failed to verify");

        fs::remove_dir_all(sandbox).ok();
    }
}
