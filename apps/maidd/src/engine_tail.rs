use super::*;

pub(crate) async fn handle_audit_command(
    service: Arc<AppService>,
    command: AuditCommands,
) -> Result<()> {
    match command {
        AuditCommands::List {
            limit,
            action,
            actor,
            json,
        } => {
            let rows = service
                .store
                .list_recent_audits(limit, action.as_deref(), actor.as_deref())
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if rows.is_empty() {
                println!("no audits found");
            } else {
                let lines = rows
                    .into_iter()
                    .map(|audit| {
                        let time = audit.created_at.format("%Y-%m-%d %H:%M:%S").to_string();
                        let metadata = audit
                            .metadata_json
                            .map(|v| truncate_line(&v.to_string(), 64))
                            .unwrap_or_else(|| "{}".to_string());
                        vec![
                            time,
                            truncate_line(&audit.action, 20),
                            truncate_line(&audit.actor, 16),
                            truncate_line(&audit.result, 8),
                            metadata,
                        ]
                    })
                    .collect::<Vec<_>>();
                print_table(
                    &["TIME(UTC)", "ACTION", "ACTOR", "RESULT", "METADATA"],
                    &lines,
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn load_plugin_tool_session_from_env_optional() -> Result<Option<PluginToolSession>> {
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
    let mut session: PluginToolSession =
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

    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for tool in &session.allowed_tools {
        let Some(canonical) = normalize_tool_name_owned(tool) else {
            continue;
        };
        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }
    if normalized.is_empty() {
        return Err(anyhow!(
            "plugin tool session has no supported allowed_tools entries"
        ));
    }
    session.allowed_tools = normalized;

    Ok(Some(session))
}

pub(crate) struct ManagedProcess {
    pub(crate) group: String,
    pub(crate) command: String,
    pub(crate) pid: Option<u32>,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) stdout_path: PathBuf,
    pub(crate) stderr_path: PathBuf,
    pub(crate) child: tokio::process::Child,
}

static PROCESS_REGISTRY: OnceLock<tokio::sync::Mutex<HashMap<String, ManagedProcess>>> =
    OnceLock::new();

pub(crate) fn process_registry() -> &'static tokio::sync::Mutex<HashMap<String, ManagedProcess>> {
    PROCESS_REGISTRY.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

pub(crate) async fn execute_tool_call(
    cfg: &AppConfig,
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
    actor: &str,
) -> Result<serde_json::Value> {
    let tool = normalize_tool_name(tool).ok_or_else(|| anyhow!("unsupported tool '{}'", tool))?;
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
        "session.list" => execute_session_list_tool(service, tool).await,
        "session.history" => execute_session_history_tool(service, tool, args).await,
        "session.send" => execute_session_send_tool(service, tool, args, actor).await,
        "session.spawn" => execute_session_spawn_tool(service, tool, args, actor).await,
        "webhook.register" => execute_webhook_register_tool(service, tool, args, actor).await,
        "webhook.list" => execute_webhook_list_tool(service, tool, args).await,
        "webhook.delete" => execute_webhook_delete_tool(service, tool, args, actor).await,
        "fs.list" => execute_fs_list_tool(service, tool, args).await,
        "fs.read" => execute_fs_read_tool(service, tool, args).await,
        "fs.grep" => execute_fs_grep_tool(cfg, service, tool, args).await,
        "fs.edit" => execute_fs_edit_tool(service, tool, args).await,
        "proc.start" => execute_proc_start_tool(service, tool, args).await,
        "proc.wait" => execute_proc_wait_tool(tool, args).await,
        "proc.kill" => execute_proc_kill_tool(tool, args).await,
        "proc.logs" => execute_proc_logs_tool(tool, args).await,
        "ops.web_fetch" => execute_web_fetch_tool(cfg, tool, args).await,
        "ops.search" => execute_web_search_tool(cfg, tool, args).await,
        "ops.grep" => execute_grep_tool(cfg, service, tool, args).await,
        "ops.code_analysis.latest" => {
            execute_code_analysis_latest_tool(cfg, service, tool, args).await
        }
        "ops.code_analysis.list" => execute_code_analysis_list_tool(service, tool, args).await,
        _ => Err(anyhow!("unsupported tool '{}'", tool)),
    }
}

pub(crate) async fn resolve_group_root(
    service: Arc<AppService>,
    group_name: &str,
) -> Result<(maid_core::Group, PathBuf)> {
    let group = service
        .store
        .get_group_by_name(group_name)
        .await?
        .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
    let group_root = fs::canonicalize(&group.root_path)
        .with_context(|| format!("failed to resolve group root {}", group.root_path))?;
    Ok((group, group_root))
}

pub(crate) fn resolve_existing_group_path(group_root: &Path, relative: &str) -> Result<PathBuf> {
    if Path::new(relative).is_absolute() {
        return Err(anyhow!("path must be relative to the group root"));
    }
    let candidate = fs::canonicalize(group_root.join(relative))
        .with_context(|| format!("failed to resolve path {}", relative))?;
    if !candidate.starts_with(group_root) {
        return Err(anyhow!("path escapes group root"));
    }
    Ok(candidate)
}

pub(crate) fn resolve_writable_group_file_path(
    group_root: &Path,
    relative: &str,
) -> Result<PathBuf> {
    if Path::new(relative).is_absolute() {
        return Err(anyhow!("path must be relative to the group root"));
    }
    let target = group_root.join(relative);
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("target path must include a filename"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    let parent_canonical = fs::canonicalize(parent)
        .with_context(|| format!("failed to resolve parent path {}", parent.display()))?;
    if !parent_canonical.starts_with(group_root) {
        return Err(anyhow!("path escapes group root"));
    }
    Ok(target)
}

pub(crate) async fn execute_session_list_tool(
    service: Arc<AppService>,
    tool: &str,
) -> Result<serde_json::Value> {
    let groups = service.list_groups().await?;
    Ok(json!({
        "tool": tool,
        "sessions": groups.into_iter().map(|group| json!({
            "id": group.id,
            "name": group.name,
            "root_path": group.root_path,
            "created_at": group.created_at.to_rfc3339(),
        })).collect::<Vec<_>>(),
    }))
}

pub(crate) async fn execute_session_history_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let limit = parse_u64_arg(&args, "limit", 50, 1, 500)? as i64;
    let group = service
        .store
        .get_group_by_name(group_name)
        .await?
        .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
    let messages = service.store.list_recent_messages(&group.id, limit).await?;
    Ok(json!({
        "tool": tool,
        "group": group_name,
        "limit": limit,
        "messages": messages.into_iter().map(|row| json!({
            "id": row.id,
            "role": row.role.as_str(),
            "content": row.content,
            "created_at": row.created_at.to_rfc3339(),
        })).collect::<Vec<_>>(),
    }))
}

pub(crate) async fn execute_session_send_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
    actor: &str,
) -> Result<serde_json::Value> {
    let to_group = required_arg(&args, "to_group")
        .or_else(|_| required_arg(&args, "group"))?
        .trim();
    let prompt = required_arg(&args, "prompt")?;
    let from_group = args
        .get("from_group")
        .cloned()
        .unwrap_or_else(|| "main".to_string());
    if to_group.is_empty() {
        return Err(anyhow!("to_group must not be empty"));
    }
    service.ensure_group(to_group, actor).await?;
    let output = service.run_prompt(to_group, prompt, actor).await?;
    Ok(json!({
        "tool": tool,
        "from_group": from_group,
        "to_group": to_group,
        "prompt": prompt,
        "output": output,
    }))
}

pub(crate) async fn execute_session_spawn_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
    actor: &str,
) -> Result<serde_json::Value> {
    let name = required_arg(&args, "name")
        .or_else(|_| required_arg(&args, "group"))?
        .trim();
    if name.is_empty() {
        return Err(anyhow!("name must not be empty"));
    }
    let group = service.ensure_group(name, actor).await?;
    Ok(json!({
        "tool": tool,
        "session": {
            "id": group.id,
            "name": group.name,
            "root_path": group.root_path,
            "created_at": group.created_at.to_rfc3339(),
        }
    }))
}

pub(crate) async fn execute_webhook_register_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
    actor: &str,
) -> Result<serde_json::Value> {
    let name = required_arg(&args, "name")?;
    let path = required_arg(&args, "path")?;
    let group_name = required_arg(&args, "group")?;
    let task_id = args
        .get("task_id")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string());
    let prompt_template = args
        .get("prompt")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string());
    let token = args
        .get("token")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string());
    let enabled = parse_bool_arg(&args, "enabled", true)?;
    let group = service.ensure_group(group_name, actor).await?;

    if let Some(task_id) = &task_id {
        let task = service
            .store
            .get_task(task_id)
            .await?
            .ok_or_else(|| anyhow!("task not found: {}", task_id))?;
        if task.group_id != group.id {
            return Err(anyhow!(
                "task '{}' does not belong to group '{}'",
                task_id,
                group_name
            ));
        }
    }

    let route = service
        .store
        .create_webhook_route(maid_storage::NewWebhookRoute {
            name: name.trim().to_string(),
            path: path.trim().trim_matches('/').to_string(),
            token,
            group_id: group.id.clone(),
            task_id,
            prompt_template,
            enabled,
        })
        .await?;

    let _ = service
        .store
        .insert_audit(NewAudit {
            group_id: Some(group.id),
            action: "WEBHOOK_ROUTE_CREATE".to_string(),
            actor: actor.to_string(),
            result: "SUCCESS".to_string(),
            created_at: Utc::now(),
            metadata_json: Some(json!({
                "route_id": route.id,
                "name": route.name,
                "path": route.path,
                "task_id": route.task_id,
            })),
        })
        .await;

    Ok(json!({
        "tool": tool,
        "route": {
            "id": route.id,
            "name": route.name,
            "path": route.path,
            "group_id": route.group_id,
            "task_id": route.task_id,
            "prompt_template_set": route.prompt_template.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "token_set": route.token.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "enabled": route.enabled,
            "created_at": route.created_at.to_rfc3339(),
            "updated_at": route.updated_at.to_rfc3339(),
            "last_triggered_at": route.last_triggered_at.map(|v| v.to_rfc3339()),
        }
    }))
}

pub(crate) async fn execute_webhook_list_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let include_disabled = parse_bool_arg(&args, "include_disabled", true)?;
    let routes = service.store.list_webhook_routes(include_disabled).await?;
    Ok(json!({
        "tool": tool,
        "include_disabled": include_disabled,
        "routes": routes.into_iter().map(|route| json!({
            "id": route.id,
            "name": route.name,
            "path": route.path,
            "group_id": route.group_id,
            "task_id": route.task_id,
            "prompt_template_set": route.prompt_template.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "token_set": route.token.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "enabled": route.enabled,
            "created_at": route.created_at.to_rfc3339(),
            "updated_at": route.updated_at.to_rfc3339(),
            "last_triggered_at": route.last_triggered_at.map(|v| v.to_rfc3339()),
        })).collect::<Vec<_>>(),
    }))
}

pub(crate) async fn execute_webhook_delete_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
    actor: &str,
) -> Result<serde_json::Value> {
    let key = args
        .get("id")
        .or_else(|| args.get("name"))
        .or_else(|| args.get("path"))
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing required argument: id|name|path"))?;
    let deleted = service.store.delete_webhook_route(key).await?;
    let _ = service
        .store
        .insert_audit(NewAudit {
            group_id: None,
            action: "WEBHOOK_ROUTE_DELETE".to_string(),
            actor: actor.to_string(),
            result: if deleted {
                "SUCCESS".to_string()
            } else {
                "NOT_FOUND".to_string()
            },
            created_at: Utc::now(),
            metadata_json: Some(json!({
                "key": key,
            })),
        })
        .await;
    Ok(json!({
        "tool": tool,
        "key": key,
        "deleted": deleted,
    }))
}

pub(crate) async fn execute_fs_list_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let relative_path = args.get("path").map(String::as_str).unwrap_or(".");
    let include_hidden = parse_bool_arg(&args, "include_hidden", false)?;
    let max_entries = parse_u64_arg(&args, "max_entries", 200, 1, 2_000)? as usize;
    let (_, group_root) = resolve_group_root(service, group_name).await?;
    let candidate = resolve_existing_group_path(&group_root, relative_path)?;

    let mut entries = Vec::new();
    if candidate.is_dir() {
        for entry in fs::read_dir(&candidate)
            .with_context(|| format!("failed to read directory {}", candidate.display()))?
        {
            if entries.len() >= max_entries {
                break;
            }
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !include_hidden && name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let kind = if metadata.is_dir() {
                "dir"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            };
            let rel = path
                .strip_prefix(&group_root)
                .unwrap_or(path.as_path())
                .display()
                .to_string();
            entries.push(json!({
                "name": name,
                "path": rel,
                "type": kind,
                "size_bytes": if metadata.is_file() { Some(metadata.len()) } else { None },
            }));
        }
        entries.sort_by(|a, b| {
            a.get("path")
                .and_then(|v| v.as_str())
                .cmp(&b.get("path").and_then(|v| v.as_str()))
        });
    } else {
        let metadata = fs::symlink_metadata(&candidate)?;
        let rel = candidate
            .strip_prefix(&group_root)
            .unwrap_or(candidate.as_path())
            .display()
            .to_string();
        entries.push(json!({
            "name": candidate.file_name().map(|v| v.to_string_lossy().to_string()).unwrap_or_else(|| rel.clone()),
            "path": rel,
            "type": if metadata.is_file() { "file" } else { "other" },
            "size_bytes": if metadata.is_file() { Some(metadata.len()) } else { None },
        }));
    }

    Ok(json!({
        "tool": tool,
        "group": group_name,
        "path": relative_path,
        "entries": entries,
    }))
}

pub(crate) async fn execute_fs_read_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let relative_path = required_arg(&args, "path")?;
    let max_bytes = parse_u64_arg(&args, "max_bytes", 131_072, 256, 2_097_152)? as usize;
    let (_, group_root) = resolve_group_root(service, group_name).await?;
    let candidate = resolve_existing_group_path(&group_root, relative_path)?;
    let metadata = fs::symlink_metadata(&candidate)?;
    if !metadata.is_file() {
        return Err(anyhow!("path is not a file: {}", relative_path));
    }
    let bytes = fs::read(&candidate)?;
    let total_bytes = bytes.len();
    let body_limit = max_bytes.min(total_bytes);
    let preview = String::from_utf8_lossy(&bytes[..body_limit]).to_string();
    let rel = candidate
        .strip_prefix(&group_root)
        .unwrap_or(candidate.as_path())
        .display()
        .to_string();
    Ok(json!({
        "tool": tool,
        "group": group_name,
        "path": rel,
        "max_bytes": max_bytes,
        "total_bytes": total_bytes,
        "truncated": total_bytes > body_limit,
        "content": preview,
    }))
}

pub(crate) async fn execute_fs_grep_tool(
    cfg: &AppConfig,
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    execute_grep_tool(cfg, service, tool, args).await
}

pub(crate) async fn execute_fs_edit_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let relative_path = required_arg(&args, "path")?;
    let content = required_arg(&args, "content")?;
    let mode = args
        .get("mode")
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "overwrite".to_string());
    let (_, group_root) = resolve_group_root(service, group_name).await?;
    let target = resolve_writable_group_file_path(&group_root, relative_path)?;

    let bytes_written = match mode.as_str() {
        "overwrite" => {
            fs::write(&target, content.as_bytes())
                .with_context(|| format!("failed to write {}", target.display()))?;
            content.len()
        }
        "append" => {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&target)
                .with_context(|| format!("failed to open {}", target.display()))?;
            file.write_all(content.as_bytes())
                .with_context(|| format!("failed to append {}", target.display()))?;
            content.len()
        }
        _ => {
            return Err(anyhow!(
                "invalid mode '{}'; expected overwrite or append",
                mode
            ));
        }
    };

    let rel = target
        .strip_prefix(&group_root)
        .unwrap_or(target.as_path())
        .display()
        .to_string();
    Ok(json!({
        "tool": tool,
        "group": group_name,
        "path": rel,
        "mode": mode,
        "bytes_written": bytes_written,
    }))
}

pub(crate) fn read_file_tail(path: &Path, max_bytes: usize) -> String {
    let Ok(bytes) = fs::read(path) else {
        return String::new();
    };
    if bytes.is_empty() {
        return String::new();
    }
    let start = bytes.len().saturating_sub(max_bytes);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

pub(crate) async fn execute_proc_start_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let command = required_arg(&args, "command")?.trim();
    if command.is_empty() {
        return Err(anyhow!("command must not be empty"));
    }

    let (_, group_root) = resolve_group_root(service, group_name).await?;
    let id = maid_core::new_id();
    let proc_dir = group_root.join(".maid").join("processes");
    fs::create_dir_all(&proc_dir)
        .with_context(|| format!("failed to create {}", proc_dir.display()))?;
    let stdout_path = proc_dir.join(format!("{id}.stdout.log"));
    let stderr_path = proc_dir.join(format!("{id}.stderr.log"));
    let stdout_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stdout_path)
        .with_context(|| format!("failed to open {}", stdout_path.display()))?;
    let stderr_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stderr_path)
        .with_context(|| format!("failed to open {}", stderr_path.display()))?;

    let mut child_cmd = if cfg!(target_os = "windows") {
        let mut cmd = tokio::process::Command::new("cmd");
        cmd.arg("/C").arg(command);
        cmd
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut cmd = tokio::process::Command::new(shell);
        cmd.arg("-lc").arg(command);
        cmd
    };
    child_cmd
        .current_dir(&group_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout_file))
        .stderr(std::process::Stdio::from(stderr_file));
    let child = child_cmd
        .spawn()
        .with_context(|| format!("failed to start process in {}", group_root.display()))?;
    let pid = child.id();
    let started_at = Utc::now();

    let mut registry = process_registry().lock().await;
    registry.insert(
        id.clone(),
        ManagedProcess {
            group: group_name.to_string(),
            command: command.to_string(),
            pid,
            started_at,
            stdout_path: stdout_path.clone(),
            stderr_path: stderr_path.clone(),
            child,
        },
    );
    drop(registry);

    Ok(json!({
        "tool": tool,
        "id": id,
        "pid": pid,
        "group": group_name,
        "command": command,
        "started_at": started_at.to_rfc3339(),
        "stdout_log": stdout_path.display().to_string(),
        "stderr_log": stderr_path.display().to_string(),
    }))
}

pub(crate) async fn execute_proc_wait_tool(
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let id = required_arg(&args, "id")?;
    let timeout_seconds = parse_u64_arg(&args, "timeout_seconds", 0, 0, 86_400)?;
    let max_bytes = parse_u64_arg(&args, "max_bytes", 4_096, 256, 131_072)? as usize;
    let remove_on_exit = parse_bool_arg(&args, "remove_on_exit", false)?;

    let mut registry = process_registry().lock().await;
    let Some(entry) = registry.get_mut(id) else {
        return Err(anyhow!("process not found: {}", id));
    };

    let stdout_path = entry.stdout_path.clone();
    let stderr_path = entry.stderr_path.clone();
    let status = if timeout_seconds == 0 {
        entry.child.try_wait()?
    } else {
        match tokio::time::timeout(Duration::from_secs(timeout_seconds), entry.child.wait()).await {
            Ok(waited) => Some(waited?),
            Err(_) => None,
        }
    };

    let running = status.is_none();
    let exit_code = status.and_then(|v| v.code());
    if !running && remove_on_exit {
        registry.remove(id);
    }
    drop(registry);

    Ok(json!({
        "tool": tool,
        "id": id,
        "running": running,
        "exit_code": exit_code,
        "stdout_tail": read_file_tail(&stdout_path, max_bytes),
        "stderr_tail": read_file_tail(&stderr_path, max_bytes),
    }))
}

pub(crate) async fn execute_proc_kill_tool(
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let id = required_arg(&args, "id")?;
    let mut registry = process_registry().lock().await;
    let Some(entry) = registry.get_mut(id) else {
        return Err(anyhow!("process not found: {}", id));
    };

    let already_exited = entry.child.try_wait()?.is_some();
    if !already_exited {
        entry
            .child
            .kill()
            .await
            .with_context(|| format!("failed to kill process {}", id))?;
    }
    let status = entry.child.try_wait()?;

    Ok(json!({
        "tool": tool,
        "id": id,
        "killed": !already_exited,
        "running": status.is_none(),
        "exit_code": status.and_then(|v| v.code()),
    }))
}

pub(crate) async fn execute_proc_logs_tool(
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let id = required_arg(&args, "id")?;
    let max_bytes = parse_u64_arg(&args, "max_bytes", 4_096, 256, 131_072)? as usize;
    let mut registry = process_registry().lock().await;
    let Some(entry) = registry.get_mut(id) else {
        return Err(anyhow!("process not found: {}", id));
    };
    let running = entry.child.try_wait()?.is_none();
    let stdout_path = entry.stdout_path.clone();
    let stderr_path = entry.stderr_path.clone();
    let group = entry.group.clone();
    let command = entry.command.clone();
    let pid = entry.pid;
    let started_at = entry.started_at.to_rfc3339();
    drop(registry);

    Ok(json!({
        "tool": tool,
        "id": id,
        "group": group,
        "command": command,
        "pid": pid,
        "started_at": started_at,
        "running": running,
        "stdout_tail": read_file_tail(&stdout_path, max_bytes),
        "stderr_tail": read_file_tail(&stderr_path, max_bytes),
    }))
}

pub(crate) async fn execute_web_fetch_tool(
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

pub(crate) async fn execute_web_search_tool(
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

pub(crate) async fn fetch_bing_rss_results(
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

pub(crate) fn extract_xml_tag(input: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = input.find(&open)? + open.len();
    let end = input[start..].find(&close)? + start;
    Some(input[start..end].trim().to_string())
}

pub(crate) fn xml_unescape(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

pub(crate) fn collect_duckduckgo_topics(
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

pub(crate) async fn execute_grep_tool(
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

#[derive(Debug, Deserialize)]
pub(crate) struct CodeAnalysisWorkflow {
    workflow_id: String,
    #[serde(default)]
    target_url: Option<String>,
    #[serde(default)]
    artifacts: BTreeMap<String, String>,
    #[serde(default)]
    stats: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    notes: Vec<String>,
}

pub(crate) struct LocatedWorkflow {
    workflow_path: PathBuf,
    modified_secs: u64,
}

pub(crate) async fn execute_code_analysis_list_tool(
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let limit = parse_u64_arg(&args, "limit", 10, 1, 50)? as usize;

    let group = service
        .store
        .get_group_by_name(group_name)
        .await?
        .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
    let group_root = fs::canonicalize(&group.root_path)
        .with_context(|| format!("failed to resolve group root {}", group.root_path))?;

    let workflows_dir = group_root
        .join(".maid")
        .join("code-analysis")
        .join("workflows");
    let mut rows: Vec<(u64, PathBuf)> = Vec::new();
    if workflows_dir.is_dir() {
        for entry in fs::read_dir(&workflows_dir)
            .with_context(|| format!("failed to read {}", workflows_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let modified_secs = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            rows.push((modified_secs, path));
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    rows.truncate(limit);

    let mut workflows = Vec::new();
    for (_, path) in rows {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let wf: CodeAnalysisWorkflow = serde_json::from_str(&raw)
            .with_context(|| format!("invalid workflow JSON {}", path.display()))?;
        workflows.push(json!({
            "workflow_id": wf.workflow_id,
            "target_url": wf.target_url,
            "reportable_findings": wf.stats.get("reportable_findings"),
            "supply_chain_findings": wf.stats.get("supply_chain_findings"),
            "queue_entries": wf.stats.get("queue_entries"),
            "coverage_warning": wf.stats.get("coverage_warning"),
            "notes": wf.notes.into_iter().take(3).collect::<Vec<_>>(),
        }));
    }

    Ok(json!({
        "tool": tool,
        "group": group_name,
        "workflows_dir": workflows_dir.display().to_string(),
        "workflows": workflows,
    }))
}

pub(crate) async fn execute_code_analysis_latest_tool(
    _cfg: &AppConfig,
    service: Arc<AppService>,
    tool: &str,
    args: BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let group_name = required_arg(&args, "group")?;
    let workflow_id = args
        .get("workflow_id")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let include_markdown = parse_bool_arg(&args, "include_markdown", false)?;
    let max_chars = parse_u64_arg(&args, "max_chars", 3500, 200, 12_000)? as usize;
    let top_n = parse_u64_arg(&args, "top_n", 10, 1, 50)? as usize;

    let group = service
        .store
        .get_group_by_name(group_name)
        .await?
        .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
    let group_root = fs::canonicalize(&group.root_path)
        .with_context(|| format!("failed to resolve group root {}", group.root_path))?;

    let mut search_roots = vec![group_root.join(".maid").join("code-analysis")];
    search_roots.push(PathBuf::from("/private/tmp/maid-code-analysis-sources"));

    let located = find_code_analysis_workflow(&search_roots, workflow_id.as_deref())?
        .ok_or_else(|| anyhow!("no code-analysis workflow found"))?;
    let raw = fs::read_to_string(&located.workflow_path)
        .with_context(|| format!("failed to read {}", located.workflow_path.display()))?;
    let wf: CodeAnalysisWorkflow = serde_json::from_str(&raw)
        .with_context(|| format!("invalid workflow JSON {}", located.workflow_path.display()))?;

    let markdown_path = wf.artifacts.get("markdown").cloned();
    let sarif_path = wf.artifacts.get("sarif").cloned();
    let findings_path = wf.artifacts.get("findings").cloned();

    let top_findings = if let Some(path) = findings_path.as_deref() {
        read_code_analysis_findings_preview(path, top_n).unwrap_or_else(|err| {
            vec![json!({
                "error": format!("failed to read findings: {err:#}"),
                "path": path,
            })]
        })
    } else {
        Vec::new()
    };

    let markdown_preview = if include_markdown {
        markdown_path
            .as_deref()
            .and_then(|path| read_text_preview(path, max_chars).ok())
    } else {
        None
    };

    Ok(json!({
        "tool": tool,
        "group": group_name,
        "workflow_id": wf.workflow_id,
        "target_url": wf.target_url,
        "stats": wf.stats,
        "notes": wf.notes,
        "artifacts": {
            "workflow": located.workflow_path.display().to_string(),
            "markdown": markdown_path,
            "sarif": sarif_path,
            "findings": findings_path,
        },
        "top_findings": top_findings,
        "markdown_preview": markdown_preview,
    }))
}

pub(crate) fn find_code_analysis_workflow(
    roots: &[PathBuf],
    workflow_id: Option<&str>,
) -> Result<Option<LocatedWorkflow>> {
    let mut best: Option<LocatedWorkflow> = None;

    for root in roots {
        if root.ends_with("maid-code-analysis-sources") {
            if !root.is_dir() {
                continue;
            }
            for child in
                fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))?
            {
                let child = child?;
                if !child.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let workflows_dir = child.path().join("code-analysis-reports").join("workflows");
                consider_workflows_dir(&workflows_dir, workflow_id, &mut best)?;
                if workflow_id.is_some() && best.is_some() {
                    return Ok(best);
                }
            }
            continue;
        }

        let workflows_dir = root.join("workflows");
        consider_workflows_dir(&workflows_dir, workflow_id, &mut best)?;
        if workflow_id.is_some() && best.is_some() {
            return Ok(best);
        }
    }

    Ok(best)
}

pub(crate) fn consider_workflows_dir(
    workflows_dir: &Path,
    workflow_id: Option<&str>,
    best: &mut Option<LocatedWorkflow>,
) -> Result<()> {
    if !workflows_dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(workflows_dir)
        .with_context(|| format!("failed to read {}", workflows_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        if let Some(wf) = workflow_id {
            if path.file_name().and_then(|v| v.to_str()) != Some(&format!("{wf}.json")) {
                continue;
            }
        }

        let modified_secs = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match best {
            Some(current) => {
                if workflow_id.is_some() {
                    *best = Some(LocatedWorkflow {
                        workflow_path: path,
                        modified_secs,
                    });
                    return Ok(());
                }
                if modified_secs > current.modified_secs {
                    *best = Some(LocatedWorkflow {
                        workflow_path: path,
                        modified_secs,
                    });
                }
            }
            None => {
                *best = Some(LocatedWorkflow {
                    workflow_path: path,
                    modified_secs,
                });
                if workflow_id.is_some() {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn read_text_preview(path: &str, max_chars: usize) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    if raw.chars().count() <= max_chars {
        return Ok(raw);
    }
    let mut out = raw.chars().take(max_chars).collect::<String>();
    out.push_str("\n\n[truncated]");
    Ok(out)
}

pub(crate) fn read_code_analysis_findings_preview(
    path: &str,
    top_n: usize,
) -> Result<Vec<serde_json::Value>> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let parsed: Vec<serde_json::Value> =
        serde_json::from_str(&raw).with_context(|| format!("invalid JSON {}", path))?;
    let mut out = Vec::new();
    for finding in parsed.into_iter().take(top_n) {
        let get = |k: &str| finding.get(k).cloned();
        out.push(json!({
            "id": get("id"),
            "severity": get("severity"),
            "category": get("category"),
            "vulnerability_type": get("vulnerability_type"),
            "path": get("path"),
            "sink_call": get("sink_call"),
            "witness_payload": get("witness_payload"),
            "exploit_verdict": get("exploit_verdict"),
            "impact": get("impact"),
            "remediation": get("remediation"),
            "confidence": get("confidence"),
        }));
    }
    Ok(out)
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SkillRegistryFile {
    #[serde(default)]
    skill: Vec<SkillRegistryEntry>,
    #[serde(default)]
    skills: Vec<SkillRegistryEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SkillRegistryEntry {
    id: String,
    name: Option<String>,
    description: Option<String>,
    tags: Option<Vec<String>>,
    intents: Option<Vec<String>>,
    capabilities: Option<Vec<String>>,
    source: Option<String>,
    builtin: Option<String>,
    plugin: Option<String>,
    command: Option<String>,
    #[serde(default)]
    args: BTreeMap<String, String>,
    publisher: Option<String>,
    enabled: Option<bool>,
    estimated_latency_ms: Option<u64>,
    cost_tier: Option<String>,
}

#[derive(Debug)]
pub(crate) struct SkillRegistryIndex {
    entries: Vec<SkillRegistryEntry>,
    inverted: HashMap<String, Vec<usize>>,
}

#[derive(Clone)]
pub(crate) struct SkillRegistryCacheEntry {
    index_path: String,
    loaded_at: Instant,
    index: Arc<SkillRegistryIndex>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedSkillCall {
    id: String,
    source: String,
    builtin: Option<String>,
    plugin: Option<String>,
    command: String,
    args: BTreeMap<String, String>,
    score: f64,
    reason: String,
}

static SKILL_REGISTRY_CACHE: OnceLock<Mutex<Option<SkillRegistryCacheEntry>>> = OnceLock::new();

pub(crate) async fn auto_invoke_skills_for_prompt(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    actor: &str,
) -> Result<Option<String>> {
    let show_progress = should_print_auto_action_progress(actor);
    let calls = resolve_skill_calls_for_prompt(cfg, prompt);
    let mut rows = Vec::new();

    for call in calls {
        if show_progress {
            let label = call
                .builtin
                .clone()
                .or_else(|| call.plugin.clone())
                .unwrap_or_else(|| call.id.clone());
            eprintln!(
                "[auto] -> skill {} (source={}, score={:.2})",
                label, call.source, call.score
            );
        }
        match execute_resolved_skill_call(cfg, service.clone(), group_name, prompt, &call).await {
            Ok(payload) => {
                if show_progress {
                    eprintln!("[auto] <- skill {} ok", call.id);
                }
                audit_auto_skill_context_call(
                    service.clone(),
                    actor,
                    &call.id,
                    "SUCCESS",
                    Some(json!({ "preview": tool_result_preview(&payload, 600) })),
                )
                .await;
                rows.push(json!({
                    "skill": call.id,
                    "source": call.source,
                    "score": call.score,
                    "reason": call.reason,
                    "status": "SUCCESS",
                    "context": payload,
                }));
            }
            Err(err) => {
                let err_text = format!("{err:#}");
                if show_progress {
                    eprintln!(
                        "[auto] <- skill {} failed: {}",
                        call.id,
                        truncate_line(&err_text, 200)
                    );
                }
                audit_auto_skill_context_call(
                    service.clone(),
                    actor,
                    &call.id,
                    "FAILED",
                    Some(json!({ "error": err_text })),
                )
                .await;
                rows.push(json!({
                    "skill": call.id,
                    "source": call.source,
                    "score": call.score,
                    "reason": call.reason,
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

pub(crate) fn resolve_skill_calls_for_prompt(
    cfg: &AppConfig,
    prompt: &str,
) -> Vec<ResolvedSkillCall> {
    if !cfg.skill_registry_enabled() {
        return resolve_legacy_skill_calls(cfg);
    }
    let index_path = PathBuf::from(cfg.skill_registry_path());
    let index = match load_skill_registry_index_cached(&index_path, Duration::from_secs(15)) {
        Ok(index) => index,
        Err(err) => {
            warn!(
                "failed to load skill registry {}: {err:#}; using legacy skills",
                index_path.display()
            );
            return resolve_legacy_skill_calls(cfg);
        }
    };
    resolve_registry_skill_calls(cfg, prompt, &index)
}

pub(crate) fn resolve_legacy_skill_calls(cfg: &AppConfig) -> Vec<ResolvedSkillCall> {
    cfg.enabled_skills()
        .into_iter()
        .take(cfg.skill_max_invocations())
        .map(|id| ResolvedSkillCall {
            id: id.clone(),
            source: "builtin".to_string(),
            builtin: Some(id),
            plugin: None,
            command: "context".to_string(),
            args: BTreeMap::new(),
            score: 1.0,
            reason: "legacy-enabled-skill".to_string(),
        })
        .collect()
}

pub(crate) fn resolve_registry_skill_calls(
    cfg: &AppConfig,
    prompt: &str,
    index: &SkillRegistryIndex,
) -> Vec<ResolvedSkillCall> {
    if index.entries.is_empty() {
        return resolve_legacy_skill_calls(cfg);
    }

    let terms = tokenize_skill_prompt_terms(prompt);
    let mut candidate_indices = HashSet::new();
    let candidate_limit = (cfg.skill_max_candidates().saturating_mul(6)).max(32);
    for term in &terms {
        if let Some(indices) = index.inverted.get(term) {
            for idx in indices.iter().copied().take(candidate_limit) {
                candidate_indices.insert(idx);
            }
        }
    }
    if candidate_indices.is_empty() {
        for idx in 0..index.entries.len().min(cfg.skill_max_candidates()) {
            candidate_indices.insert(idx);
        }
    }

    let allowlist = cfg.enabled_skills().into_iter().collect::<HashSet<_>>();
    let mut scored = Vec::new();
    for idx in candidate_indices {
        let Some(entry) = index.entries.get(idx) else {
            continue;
        };
        if !entry.enabled.unwrap_or(true) {
            continue;
        }
        if !cfg.skill_allow_unlisted() && !allowlist.contains(&entry.id) {
            continue;
        }
        if let Some(publisher) = &entry.publisher {
            if !cfg.plugin_trusted_publishers().is_empty()
                && !cfg
                    .plugin_trusted_publishers()
                    .iter()
                    .any(|v| v == publisher)
            {
                continue;
            }
        }
        let score = skill_registry_relevance_score(prompt, &terms, entry);
        if score <= 0.0 {
            continue;
        }
        if let Some(call) = entry_to_skill_call(entry, score) {
            scored.push(call);
        }
    }

    if scored.is_empty() {
        return resolve_legacy_skill_calls(cfg);
    }

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    scored.truncate(cfg.skill_max_invocations());
    scored
}

pub(crate) fn entry_to_skill_call(
    entry: &SkillRegistryEntry,
    score: f64,
) -> Option<ResolvedSkillCall> {
    let source = normalized_skill_source(entry);
    if source == "builtin" {
        let builtin = entry.builtin.clone().unwrap_or_else(|| entry.id.clone());
        if !is_supported_context_skill(&builtin) {
            return None;
        }
        return Some(ResolvedSkillCall {
            id: entry.id.clone(),
            source: source.to_string(),
            builtin: Some(builtin),
            plugin: None,
            command: "context".to_string(),
            args: entry.args.clone(),
            score,
            reason: "registry-match".to_string(),
        });
    }
    if source == "plugin" {
        let plugin = entry.plugin.clone()?;
        let command = entry.command.clone().unwrap_or_else(|| "help".to_string());
        return Some(ResolvedSkillCall {
            id: entry.id.clone(),
            source: source.to_string(),
            builtin: None,
            plugin: Some(plugin),
            command,
            args: entry.args.clone(),
            score,
            reason: "registry-match".to_string(),
        });
    }
    None
}

pub(crate) async fn execute_resolved_skill_call(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    call: &ResolvedSkillCall,
) -> Result<serde_json::Value> {
    match call.source.as_str() {
        "builtin" => {
            execute_context_skill(
                cfg,
                service,
                group_name,
                call.builtin.as_deref().unwrap_or(&call.id),
            )
            .await
        }
        "plugin" => {
            let plugin_name = call
                .plugin
                .as_deref()
                .ok_or_else(|| anyhow!("missing plugin name for skill '{}'", call.id))?;
            ensure_plugin_enabled(cfg, plugin_name)?;
            let plugin_dir = PathBuf::from(cfg.plugin_directory());
            let plugin = load_plugin(&plugin_dir, plugin_name)?;
            let args = render_skill_args(&call.args, group_name, prompt);
            execute_auto_plugin_call(
                cfg,
                service,
                group_name,
                &plugin,
                &call.command,
                args,
                prompt,
            )
            .await
        }
        other => Err(anyhow!(
            "unsupported skill source '{}' for '{}'",
            other,
            call.id
        )),
    }
}

pub(crate) fn render_skill_args(
    args: &BTreeMap<String, String>,
    group_name: &str,
    prompt: &str,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in args {
        let value = value
            .replace("${group}", group_name)
            .replace("${prompt}", prompt);
        out.insert(key.clone(), value);
    }
    out
}

pub(crate) fn load_skill_registry(index_path: &Path) -> Result<Vec<SkillRegistryEntry>> {
    let raw = std::fs::read_to_string(index_path)
        .with_context(|| format!("failed to read skill registry {}", index_path.display()))?;
    let parsed: SkillRegistryFile = toml::from_str(&raw)
        .with_context(|| format!("failed to parse skill registry {}", index_path.display()))?;
    let mut entries = parsed.skill;
    entries.extend(parsed.skills);
    if entries.is_empty() {
        return Err(anyhow!(
            "skill registry has no entries: {}",
            index_path.display()
        ));
    }
    for entry in &entries {
        validate_skill_registry_entry(entry)?;
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(entries)
}

pub(crate) fn validate_skill_registry_entry(entry: &SkillRegistryEntry) -> Result<()> {
    validate_plugin_name_like_identifier(&entry.id, "skill id")?;
    if entry
        .name
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(anyhow!("skill '{}' has empty name", entry.id));
    }
    if entry
        .description
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(anyhow!("skill '{}' has empty description", entry.id));
    }
    if let Some(values) = &entry.tags {
        for value in values {
            if value.trim().is_empty() {
                return Err(anyhow!("skill '{}' tags must not be empty", entry.id));
            }
        }
    }
    if let Some(values) = &entry.intents {
        for value in values {
            if value.trim().is_empty() {
                return Err(anyhow!("skill '{}' intents must not be empty", entry.id));
            }
        }
    }
    if let Some(values) = &entry.capabilities {
        for value in values {
            if value.trim().is_empty() {
                return Err(anyhow!(
                    "skill '{}' capabilities must not be empty",
                    entry.id
                ));
            }
        }
    }
    if let Some(publisher) = &entry.publisher {
        validate_plugin_name_like_identifier(publisher, "skill publisher")?;
    }
    if let Some(cost_tier) = entry.cost_tier.as_deref() {
        if !matches!(cost_tier, "free" | "low" | "medium" | "high") {
            return Err(anyhow!(
                "skill '{}' cost_tier must be one of: free, low, medium, high",
                entry.id
            ));
        }
    }

    match normalized_skill_source(entry) {
        "builtin" => {
            let builtin = entry.builtin.as_deref().unwrap_or(&entry.id);
            if !is_supported_context_skill(builtin) {
                return Err(anyhow!(
                    "skill '{}' references unsupported builtin '{}'",
                    entry.id,
                    builtin
                ));
            }
        }
        "plugin" => {
            let plugin = entry.plugin.as_deref().ok_or_else(|| {
                anyhow!("skill '{}' is plugin source but missing plugin", entry.id)
            })?;
            validate_plugin_name(plugin)?;
            if entry
                .command
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(false)
            {
                return Err(anyhow!("skill '{}' command must not be empty", entry.id));
            }
        }
        other => {
            return Err(anyhow!(
                "skill '{}' has unsupported source '{}'",
                entry.id,
                other
            ));
        }
    }

    Ok(())
}

pub(crate) fn normalized_skill_source(entry: &SkillRegistryEntry) -> &str {
    entry.source.as_deref().unwrap_or("builtin").trim()
}

pub(crate) fn load_skill_registry_index_cached(
    index_path: &Path,
    ttl: Duration,
) -> Result<Arc<SkillRegistryIndex>> {
    let key = index_path.display().to_string();
    let cache = SKILL_REGISTRY_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some(entry) = guard.as_ref() {
            if entry.index_path == key && entry.loaded_at.elapsed() <= ttl {
                return Ok(entry.index.clone());
            }
        }
    }

    let entries = load_skill_registry(index_path)?;
    let mut inverted: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        for token in skill_index_tokens(entry) {
            inverted.entry(token).or_default().push(idx);
        }
    }
    let index = Arc::new(SkillRegistryIndex { entries, inverted });
    if let Ok(mut guard) = cache.lock() {
        *guard = Some(SkillRegistryCacheEntry {
            index_path: key,
            loaded_at: Instant::now(),
            index: index.clone(),
        });
    }
    Ok(index)
}

pub(crate) fn skill_index_tokens(entry: &SkillRegistryEntry) -> Vec<String> {
    let mut tokens = HashSet::new();
    for value in [
        Some(entry.id.as_str()),
        entry.name.as_deref(),
        entry.description.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        for token in tokenize_skill_text(value) {
            tokens.insert(token);
        }
    }
    for values in [&entry.tags, &entry.intents, &entry.capabilities]
        .into_iter()
        .flatten()
    {
        for value in values {
            for token in tokenize_skill_text(value) {
                tokens.insert(token);
            }
        }
    }
    tokens.into_iter().collect()
}

pub(crate) fn tokenize_skill_prompt_terms(prompt: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for token in tokenize_skill_text(prompt) {
        if seen.insert(token.clone()) {
            out.push(token);
        }
        if out.len() >= 24 {
            break;
        }
    }
    out
}

pub(crate) fn tokenize_skill_text(text: &str) -> Vec<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_' && ch != '-')
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| token.len() >= 3)
        .collect()
}

pub(crate) fn skill_registry_relevance_score(
    prompt: &str,
    terms: &[String],
    entry: &SkillRegistryEntry,
) -> f64 {
    let mut score: f64 = 0.0;
    let prompt_lower = prompt.to_ascii_lowercase();

    if prompt_lower.contains(&entry.id.to_ascii_lowercase()) {
        score += 3.0;
    }
    if let Some(name) = &entry.name {
        if prompt_lower.contains(&name.to_ascii_lowercase()) {
            score += 2.0;
        }
    }
    if let Some(intents) = &entry.intents {
        for intent in intents {
            if prompt_lower.contains(&intent.to_ascii_lowercase()) {
                score += 2.5;
            }
        }
    }
    if let Some(tags) = &entry.tags {
        for tag in tags {
            if prompt_lower.contains(&tag.to_ascii_lowercase()) {
                score += 1.0;
            }
        }
    }
    if let Some(capabilities) = &entry.capabilities {
        for capability in capabilities {
            if prompt_lower.contains(&capability.to_ascii_lowercase()) {
                score += 1.5;
            }
        }
    }
    if let Some(description) = &entry.description {
        for term in terms {
            if description.to_ascii_lowercase().contains(term) {
                score += 0.4;
            }
        }
    }
    if let Some(latency) = entry.estimated_latency_ms {
        if latency <= 200 {
            score += 0.4;
        } else if latency <= 1000 {
            score += 0.2;
        }
    }
    if let Some(cost_tier) = entry.cost_tier.as_deref() {
        match cost_tier {
            "free" => score += 0.4,
            "low" => score += 0.2,
            "medium" => {}
            "high" => score -= 0.2,
            _ => {}
        }
    }

    score
}

pub(crate) async fn execute_context_skill(
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

#[derive(Clone)]
pub(crate) struct PluginDiscoveryCacheEntry {
    plugins_dir: String,
    loaded_at: Instant,
    plugins: Vec<PluginSpec>,
}

static PLUGIN_DISCOVERY_CACHE: OnceLock<Mutex<Option<PluginDiscoveryCacheEntry>>> = OnceLock::new();

pub(crate) fn discover_plugins_cached(
    plugins_dir: &Path,
    ttl: Duration,
) -> Result<Vec<PluginSpec>> {
    let key = plugins_dir.display().to_string();
    let cache = PLUGIN_DISCOVERY_CACHE.get_or_init(|| Mutex::new(None));

    if let Ok(guard) = cache.lock() {
        if let Some(entry) = guard.as_ref() {
            if entry.plugins_dir == key && entry.loaded_at.elapsed() <= ttl {
                return Ok(entry.plugins.clone());
            }
        }
    }

    let plugins = discover_plugins(plugins_dir)?;
    if let Ok(mut guard) = cache.lock() {
        *guard = Some(PluginDiscoveryCacheEntry {
            plugins_dir: key,
            loaded_at: Instant::now(),
            plugins: plugins.clone(),
        });
    }
    Ok(plugins)
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AutoActionPlan {
    #[serde(default)]
    pub(crate) rationale: Option<String>,
    #[serde(default)]
    pub(crate) tools: Vec<AutoToolCall>,
    #[serde(default)]
    pub(crate) plugins: Vec<AutoPluginCall>,
}

pub(crate) async fn auto_route_actions_for_prompt(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    actor: &str,
) -> Result<AutoActionContext> {
    let started = Instant::now();
    let show_progress = should_print_auto_action_progress(actor);
    let mut allowed_tools = Vec::new();
    let mut seen_tools = HashSet::new();
    for name in cfg.tool_auto_router_allowlist() {
        let Some(canonical) = normalize_tool_name_owned(&name) else {
            continue;
        };
        if canonical == "run.prompt" {
            continue;
        }
        if seen_tools.insert(canonical.clone()) {
            allowed_tools.push(canonical);
        }
    }
    let enabled_plugins =
        discover_plugins_cached(Path::new(cfg.plugin_directory()), Duration::from_secs(5))?
            .into_iter()
            .filter(|plugin| cfg.is_plugin_enabled(&plugin.manifest.name))
            .collect::<Vec<_>>();

    if allowed_tools.is_empty() && enabled_plugins.is_empty() {
        return Ok(AutoActionContext::default());
    }

    // Fast-path: deterministic report viewing requests. This makes chat interfaces (Telegram, CLI)
    // feel "universal" without relying on the planner to guess the right tool call.
    if allowed_tools
        .iter()
        .any(|name| name == "ops.code_analysis.latest")
        && looks_like_code_analysis_report_request(prompt)
    {
        let workflow_id = extract_code_analysis_workflow_id(prompt);
        let include_markdown = prompt.to_ascii_lowercase().contains("view")
            || prompt.to_ascii_lowercase().contains("report");
        let top_n = if prompt.to_ascii_lowercase().contains("findings")
            || prompt.to_ascii_lowercase().contains("explain")
        {
            "25"
        } else {
            "10"
        };
        let mut args = BTreeMap::new();
        args.insert("group".to_string(), group_name.to_string());
        args.insert("include_markdown".to_string(), include_markdown.to_string());
        args.insert("max_chars".to_string(), "3500".to_string());
        args.insert("top_n".to_string(), top_n.to_string());
        if let Some(wf) = workflow_id {
            args.insert("workflow_id".to_string(), wf);
        }

        match execute_tool_call(
            cfg,
            service.clone(),
            "ops.code_analysis.latest",
            args,
            actor,
        )
        .await
        {
            Ok(payload) => {
                let tool_context = Some(serde_json::to_string_pretty(
                    &json!({ "calls": [payload] }),
                )?);
                return Ok(AutoActionContext {
                    plugin_context: None,
                    tool_context,
                });
            }
            Err(err) => {
                warn!("{actor} ops.code_analysis.latest fast-path failed: {err:#}");
            }
        }
    }

    if let Some(decision) = resolve_deterministic_route(cfg, prompt, &enabled_plugins) {
        let Some(plugin) = enabled_plugins
            .iter()
            .find(|candidate| candidate.manifest.name == decision.plugin)
        else {
            return Ok(AutoActionContext::default());
        };
        if show_progress {
            eprintln!(
                "[auto] deterministic route -> plugin {} {} ({})",
                decision.plugin, decision.command, decision.reason
            );
        }
        match execute_auto_plugin_call(
            cfg,
            service.clone(),
            group_name,
            plugin,
            &decision.command,
            BTreeMap::new(),
            prompt,
        )
        .await
        {
            Ok(payload) => {
                let plugin_context = Some(serde_json::to_string_pretty(&json!({
                    "routing_mode": "deterministic",
                    "reason": decision.reason,
                    "calls": [{
                        "plugin": decision.plugin,
                        "command": decision.command,
                        "status": "SUCCESS",
                        "result_preview": tool_result_preview(&payload, 1600)
                    }]
                }))?);
                return Ok(AutoActionContext {
                    plugin_context,
                    tool_context: None,
                });
            }
            Err(err) => {
                let err_text = format!("{err:#}");
                audit_auto_router_plugin_call(
                    service.clone(),
                    actor,
                    &decision.plugin,
                    &decision.command,
                    "FAILED",
                    Some(json!({ "error": err_text })),
                )
                .await;
                let plugin_context = Some(serde_json::to_string_pretty(&json!({
                    "routing_mode": "deterministic",
                    "reason": decision.reason,
                    "calls": [{
                        "plugin": decision.plugin,
                        "command": decision.command,
                        "status": "FAILED",
                        "error": err_text
                    }]
                }))?);
                return Ok(AutoActionContext {
                    plugin_context,
                    tool_context: None,
                });
            }
        }
    }

    if show_progress {
        eprintln!(
            "[auto] planning actions (tools={}, plugins={})...",
            allowed_tools.len(),
            enabled_plugins.len()
        );
    }
    let plan = request_auto_action_plan(
        service.clone(),
        group_name,
        prompt,
        &allowed_tools,
        &enabled_plugins,
    )
    .await?;
    if show_progress && (!plan.tools.is_empty() || !plan.plugins.is_empty()) {
        let mut summary = Vec::new();
        if !plan.tools.is_empty() {
            let tools = plan
                .tools
                .iter()
                .map(|call| call.tool.clone())
                .collect::<Vec<_>>()
                .join(", ");
            summary.push(format!("tools=[{}]", tools));
        }
        if !plan.plugins.is_empty() {
            let plugins = plan
                .plugins
                .iter()
                .map(|call| format!("{}/{}", call.plugin, call.command))
                .collect::<Vec<_>>()
                .join(", ");
            summary.push(format!("plugins=[{}]", plugins));
        }
        if let Some(rationale) = plan
            .rationale
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            summary.push(format!("rationale={}", json_string(rationale)));
        }
        eprintln!("[auto] plan {}", summary.join(" "));
    }
    debug!(
        "{actor} auto_action_plan tools={} plugins={} duration_ms={}",
        plan.tools.len(),
        plan.plugins.len(),
        started.elapsed().as_millis()
    );

    let mut plugin_rows = Vec::new();
    for call in plan.plugins.into_iter().take(2) {
        let plugin_name = call.plugin.trim();
        if plugin_name.is_empty() {
            continue;
        }
        let Some(plugin) = enabled_plugins
            .iter()
            .find(|candidate| candidate.manifest.name.eq_ignore_ascii_case(plugin_name))
        else {
            continue;
        };
        let command = if call.command.trim().is_empty() {
            "help".to_string()
        } else {
            call.command.trim().to_string()
        };
        if show_progress {
            eprintln!(
                "[auto] -> plugin {} {} {}",
                plugin.manifest.name,
                command,
                format_plugin_call_args(&call.args)
            );
        }
        match execute_auto_plugin_call(
            cfg,
            service.clone(),
            group_name,
            plugin,
            &command,
            call.args.clone(),
            prompt,
        )
        .await
        {
            Ok(payload) => {
                if show_progress {
                    eprintln!(
                        "[auto] <- plugin {} ok{}",
                        plugin.manifest.name,
                        summarize_plugin_payload(&payload)
                            .map(|v| format!(" ({v})"))
                            .unwrap_or_default()
                    );
                }
                audit_auto_router_plugin_call(
                    service.clone(),
                    actor,
                    &plugin.manifest.name,
                    &command,
                    "SUCCESS",
                    Some(json!({ "preview": tool_result_preview(&payload, 1200) })),
                )
                .await;
                plugin_rows.push(json!({
                    "plugin": plugin.manifest.name,
                    "command": command,
                    "status": "SUCCESS",
                    "result_preview": tool_result_preview(&payload, 1600),
                }));
            }
            Err(err) => {
                let err_text = format!("{err:#}");
                if show_progress {
                    eprintln!(
                        "[auto] <- plugin {} failed: {}",
                        plugin.manifest.name,
                        truncate_line(&err_text, 240)
                    );
                }
                audit_auto_router_plugin_call(
                    service.clone(),
                    actor,
                    &plugin.manifest.name,
                    &command,
                    "FAILED",
                    Some(json!({ "error": err_text })),
                )
                .await;
                plugin_rows.push(json!({
                    "plugin": plugin.manifest.name,
                    "command": command,
                    "status": "FAILED",
                    "error": err_text,
                }));
            }
        }
    }

    let mut tool_rows = Vec::new();
    for call in plan.tools.into_iter().take(3) {
        let Some(tool) = normalize_tool_name_owned(&call.tool) else {
            continue;
        };
        if !allowed_tools.iter().any(|name| name == &tool) {
            continue;
        }
        let args = call.args.clone();
        if show_progress {
            eprintln!(
                "[auto] -> tool {} {}",
                tool,
                format_tool_call_args(&tool, &args)
            );
        }
        match execute_tool_call(cfg, service.clone(), &tool, args, actor).await {
            Ok(payload) => {
                if show_progress {
                    eprintln!(
                        "[auto] <- tool {} ok{}",
                        tool,
                        summarize_tool_payload(&tool, &payload)
                            .map(|v| format!(" ({v})"))
                            .unwrap_or_default()
                    );
                }
                audit_auto_router_tool_call(
                    service.clone(),
                    actor,
                    &tool,
                    "SUCCESS",
                    Some(json!({ "preview": tool_result_preview(&payload, 1200) })),
                )
                .await;
                tool_rows.push(json!({
                    "tool": tool,
                    "status": "SUCCESS",
                    "result_preview": tool_result_preview(&payload, 1600),
                }));
            }
            Err(err) => {
                let err_text = format!("{err:#}");
                if show_progress {
                    eprintln!(
                        "[auto] <- tool {} failed: {}",
                        tool,
                        truncate_line(&err_text, 240)
                    );
                }
                audit_auto_router_tool_call(
                    service.clone(),
                    actor,
                    &tool,
                    "FAILED",
                    Some(json!({ "error": err_text })),
                )
                .await;
                tool_rows.push(json!({
                    "tool": tool,
                    "status": "FAILED",
                    "error": err_text,
                }));
            }
        }
    }

    let plugin_context = if plugin_rows.is_empty() {
        None
    } else {
        Some(serde_json::to_string_pretty(&json!({
            "planner_rationale": plan.rationale.clone(),
            "calls": plugin_rows
        }))?)
    };
    let tool_context = if tool_rows.is_empty() {
        None
    } else {
        Some(serde_json::to_string_pretty(&json!({
            "planner_rationale": plan.rationale,
            "calls": tool_rows
        }))?)
    };

    let context = AutoActionContext {
        plugin_context,
        tool_context,
    };
    debug!(
        "{actor} auto_action_execute duration_ms={}",
        started.elapsed().as_millis()
    );
    Ok(context)
}

pub(crate) fn should_print_auto_action_progress(actor: &str) -> bool {
    // Only print progress for interactive CLI flows.
    actor == "cli" || actor.starts_with("subagent-")
}

pub(crate) fn looks_like_code_analysis_report_request(prompt: &str) -> bool {
    let lowered = prompt.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return false;
    }
    let keywords = [
        "view report",
        "show report",
        "open report",
        "explain findings",
        "show findings",
        "list findings",
        "sarif",
        "workflow",
    ];
    keywords.iter().any(|k| lowered.contains(k))
}

pub(crate) fn extract_code_analysis_workflow_id(prompt: &str) -> Option<String> {
    // Very small "parser": locate the first token that looks like wf-YYYYMMDDTHHMMSSZ.
    // We also accept any token starting with "wf-" to support future formats.
    for token in prompt
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == ')' || c == '(')
        .map(str::trim)
    {
        if token.len() < 4 {
            continue;
        }
        if token.to_ascii_lowercase().starts_with("wf-") {
            return Some(token.to_string());
        }
    }
    None
}

pub(crate) fn json_string(raw: &str) -> String {
    serde_json::to_string(raw).unwrap_or_else(|_| format!("\"{}\"", raw))
}

pub(crate) fn format_tool_call_args(tool: &str, args: &BTreeMap<String, String>) -> String {
    let tool = normalize_tool_name(tool).unwrap_or(tool);
    let keys: &[&str] = match tool {
        "ops.search" => &["query", "limit"],
        "ops.web_fetch" => &["url"],
        "ops.grep" => &["group", "pattern", "path"],
        "fs.list" => &["group", "path", "max_entries"],
        "fs.read" => &["group", "path", "max_bytes"],
        "fs.grep" => &["group", "pattern", "path"],
        "fs.edit" => &["group", "path", "mode"],
        "proc.start" => &["group", "command"],
        "proc.wait" => &["id", "timeout_seconds"],
        "proc.kill" => &["id"],
        "proc.logs" => &["id", "max_bytes"],
        "session.history" => &["group", "limit"],
        "session.send" => &["from_group", "to_group", "group"],
        "session.spawn" => &["name", "group"],
        "webhook.register" => &["name", "path", "group", "task_id"],
        "webhook.delete" => &["id", "name", "path"],
        "ops.code_analysis.latest" => &["group", "workflow_id", "top_n", "include_markdown"],
        "ops.code_analysis.list" => &["group", "limit"],
        "task.list" => &["group"],
        "task.create" => &["group", "name", "schedule"],
        "task.run_now" => &["id"],
        "task.pause" => &["id"],
        "task.resume" => &["id"],
        "task.delete" => &["id"],
        "task.clear_group" => &["group"],
        "group.create" => &["name"],
        _ => &[],
    };
    let rendered = format_args_kv(args, keys, 4);
    if rendered.is_empty() {
        "(no args)".to_string()
    } else {
        rendered
    }
}

pub(crate) fn format_plugin_call_args(args: &BTreeMap<String, String>) -> String {
    let rendered = format_args_kv(
        args,
        &[
            "repo_url",
            "repo_path",
            "repo_ref",
            "target_url",
            "output_dir",
            "categories",
        ],
        6,
    );
    if rendered.is_empty() {
        "(no args)".to_string()
    } else {
        rendered
    }
}

pub(crate) fn format_args_kv(
    args: &BTreeMap<String, String>,
    keys: &[&str],
    max_items: usize,
) -> String {
    let mut parts = Vec::new();
    for key in keys {
        if let Some(value) = args.get(*key) {
            if value.trim().is_empty() {
                continue;
            }
            parts.push(format!("{key}={}", json_string(value)));
        }
    }

    if parts.is_empty() {
        for (key, value) in args.iter().take(max_items) {
            if key.trim().is_empty() || value.trim().is_empty() {
                continue;
            }
            parts.push(format!("{key}={}", json_string(value)));
        }
    }

    truncate_line(&parts.join(" "), 220)
}

pub(crate) fn summarize_tool_payload(tool: &str, payload: &serde_json::Value) -> Option<String> {
    let tool = normalize_tool_name(tool).unwrap_or(tool);
    match tool {
        "ops.search" => payload
            .get("results")
            .and_then(|v| v.as_array())
            .map(|items| format!("results={}", items.len())),
        "ops.web_fetch" => payload
            .get("status_code")
            .and_then(|v| v.as_u64())
            .map(|code| format!("status={}", code)),
        "ops.grep" => payload
            .get("matches")
            .and_then(|v| v.as_array())
            .map(|items| format!("matches={}", items.len())),
        "fs.list" => payload
            .get("entries")
            .and_then(|v| v.as_array())
            .map(|items| format!("entries={}", items.len())),
        "fs.grep" => payload
            .get("matches")
            .and_then(|v| v.as_array())
            .map(|items| format!("matches={}", items.len())),
        "webhook.list" => payload
            .get("routes")
            .and_then(|v| v.as_array())
            .map(|items| format!("routes={}", items.len())),
        "session.list" => payload
            .get("sessions")
            .and_then(|v| v.as_array())
            .map(|items| format!("sessions={}", items.len())),
        "ops.code_analysis.latest" => payload
            .get("top_findings")
            .and_then(|v| v.as_array())
            .map(|items| format!("top_findings={}", items.len())),
        "ops.code_analysis.list" => payload
            .get("workflows")
            .and_then(|v| v.as_array())
            .map(|items| format!("workflows={}", items.len())),
        "task.list" => payload
            .get("tasks")
            .and_then(|v| v.as_array())
            .map(|items| format!("tasks={}", items.len())),
        "group.list" => payload
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|items| format!("groups={}", items.len())),
        _ => None,
    }
}

pub(crate) fn summarize_plugin_payload(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("message")
        .and_then(|v| v.as_str())
        .map(|v| format!("message={}", truncate_line(v, 100)))
}

pub(crate) async fn request_auto_action_plan(
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    allowed_tools: &[String],
    enabled_plugins: &[PluginSpec],
) -> Result<AutoActionPlan> {
    let tool_catalog = if allowed_tools.is_empty() {
        "- (none)".to_string()
    } else {
        allowed_tools
            .iter()
            .map(|name| {
                let summary = tool_summary(name).unwrap_or("No summary available");
                format!("- {name}: {summary}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let plugin_catalog = if enabled_plugins.is_empty() {
        "- (none)".to_string()
    } else {
        enabled_plugins
            .iter()
            .map(|plugin| {
                let description = plugin
                    .manifest
                    .description
                    .clone()
                    .unwrap_or_else(|| "No description".to_string());
                format!("- {}: {}", plugin.manifest.name, description)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let planner_prompt = format!(
        "You are an action planner for a local assistant.\n\
Return ONLY JSON with this schema:\n\
{{\"rationale\":\"short reason\",\"tools\":[{{\"tool\":\"name\",\"args\":{{\"k\":\"v\"}}}}],\"plugins\":[{{\"plugin\":\"name\",\"command\":\"command\",\"args\":{{\"k\":\"v\"}}}}]}}\n\
Rules:\n\
- Use only tools/plugins listed below.\n\
- At most 3 tool calls and 2 plugin calls.\n\
- Prefer read operations.\n\
- If nothing is needed, return empty arrays.\n\
- If plugin command is uncertain, use \"help\".\n\
- No markdown, no comments, no extra text.\n\n\
Group: {group_name}\n\
User request: {prompt}\n\n\
Available tools:\n{tool_catalog}\n\n\
Available plugins:\n{plugin_catalog}\n"
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

    parse_auto_action_plan(&output)
}

pub(crate) fn parse_auto_action_plan(raw: &str) -> Result<AutoActionPlan> {
    let parsed = serde_json::from_str::<serde_json::Value>(raw.trim()).or_else(|_| {
        let extracted = extract_json_object(raw)
            .ok_or_else(|| anyhow!("auto-action planner did not return valid JSON"))?;
        serde_json::from_str::<serde_json::Value>(&extracted)
            .context("failed to parse auto-action planner JSON")
    })?;
    normalize_auto_action_plan(parsed)
}

pub(crate) fn normalize_auto_action_plan(value: serde_json::Value) -> Result<AutoActionPlan> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("auto-action planner payload must be a JSON object"))?;
    let rationale = object
        .get("rationale")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let tools = object
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_object())
                .filter_map(|call_obj| {
                    let tool = call_obj.get("tool").and_then(|v| v.as_str())?;
                    if tool.trim().is_empty() {
                        return None;
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
                    Some(AutoToolCall {
                        tool: tool.to_string(),
                        args,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let plugins = object
        .get("plugins")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_object())
                .filter_map(|call_obj| {
                    let plugin = call_obj.get("plugin").and_then(|v| v.as_str())?;
                    if plugin.trim().is_empty() {
                        return None;
                    }
                    let command = call_obj
                        .get("command")
                        .and_then(|v| v.as_str())
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| "help".to_string());
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
                    Some(AutoPluginCall {
                        plugin: plugin.to_string(),
                        command,
                        args,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(AutoActionPlan {
        rationale,
        tools,
        plugins,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AutoPluginCall {
    pub(crate) plugin: String,
    pub(crate) command: String,
    pub(crate) args: BTreeMap<String, String>,
}
pub(crate) async fn execute_auto_plugin_call(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    plugin: &PluginSpec,
    command: &str,
    mut args: BTreeMap<String, String>,
    prompt: &str,
) -> Result<serde_json::Value> {
    enforce_plugin_signature_policy(cfg, plugin, false)?;
    let bridge = create_plugin_tool_bridge_session(cfg, plugin)?;

    // Make code-analysis runs chat-friendly by default: keep outputs in the group directory so
    // other channels (Telegram, CLI, etc) can later ask to "view the report" or "explain findings".
    if plugin.manifest.name.eq_ignore_ascii_case("code-analysis")
        && command.eq_ignore_ascii_case("analyze")
        && !args
            .get("output_dir")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    {
        let group = service
            .store
            .get_group_by_name(group_name)
            .await?
            .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
        let group_root = fs::canonicalize(&group.root_path)
            .with_context(|| format!("failed to resolve group root {}", group.root_path))?;
        let output_dir = group_root.join(".maid").join("code-analysis");
        args.insert("output_dir".to_string(), output_dir.display().to_string());
    }

    let mut extra_env = vec![("MAID_PLUGIN_NAME".to_string(), plugin.manifest.name.clone())];
    if let Ok(config_path) = std::env::var("MAID_CONFIG") {
        if !config_path.trim().is_empty() {
            extra_env.push(("MAID_CONFIG".to_string(), config_path));
        }
    }
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

    let request = PluginRequest {
        command: command.to_string(),
        args,
        input: Some(prompt.to_string()),
        context: PluginContext {
            actor: "auto-plugin-router".to_string(),
            cwd: std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .display()
                .to_string(),
        },
    };
    let started = Instant::now();
    let run_result = run_plugin_with_env(plugin, request, &extra_env).await;
    if let Some(session) = bridge {
        let _ = std::fs::remove_file(&session.path);
    }
    let latency_ms = started.elapsed().as_millis() as i64;
    if let Err(err) = &run_result {
        service
            .store
            .record_plugin_invocation(NewPluginInvocation {
                plugin_name: &plugin.manifest.name,
                plugin_version: &plugin.manifest.version,
                command,
                actor: "auto-plugin-router",
                ok: false,
                latency_ms,
                created_at: Utc::now(),
            })
            .await
            .ok();
        return Err(anyhow!("{err:#}"));
    }
    let response = run_result?;
    service
        .store
        .record_plugin_invocation(NewPluginInvocation {
            plugin_name: &plugin.manifest.name,
            plugin_version: &plugin.manifest.version,
            command,
            actor: "auto-plugin-router",
            ok: response.ok,
            latency_ms,
            created_at: Utc::now(),
        })
        .await
        .ok();
    if !response.ok {
        return Err(anyhow!("plugin returned error: {}", response.message));
    }
    Ok(json!({
        "message": response.message,
        "output": response.output,
        "data": response.data
    }))
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AutoToolCall {
    pub(crate) tool: String,
    pub(crate) args: BTreeMap<String, String>,
}

pub(crate) fn normalize_auto_tool_arg_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Bool(v) => Some(v.to_string()),
        serde_json::Value::Number(v) => Some(v.to_string()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Some(value.to_string()),
    }
}

pub(crate) fn extract_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    if end < start {
        return None;
    }
    Some(raw[start..=end].to_string())
}

pub(crate) fn tool_result_preview(payload: &serde_json::Value, max_chars: usize) -> String {
    truncate_line(&payload.to_string(), max_chars)
}

pub(crate) fn truncate_line(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out = input.chars().take(max_chars).collect::<String>();
    out.push_str("...");
    out
}

pub(crate) fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }
    let cols = headers.len();
    if rows.iter().any(|row| row.len() != cols) {
        for row in rows {
            println!("{}", row.join("\t"));
        }
        return;
    }

    let mut widths = headers
        .iter()
        .map(|header| header.chars().count())
        .collect::<Vec<_>>();
    for row in rows {
        for (idx, value) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(value.chars().count());
        }
    }

    let header_cells = headers
        .iter()
        .enumerate()
        .map(|(idx, header)| format!("{:<width$}", header, width = widths[idx]))
        .collect::<Vec<_>>();
    let header_line = header_cells.join("  ");
    println!("{header_line}");
    println!("{}", "-".repeat(header_line.chars().count()));

    for row in rows {
        let cells = row
            .iter()
            .enumerate()
            .map(|(idx, value)| format!("{:<width$}", value, width = widths[idx]))
            .collect::<Vec<_>>();
        println!("{}", cells.join("  "));
    }
}

pub(crate) fn parse_u64_arg(
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

pub(crate) fn parse_bool_arg(
    args: &BTreeMap<String, String>,
    key: &str,
    default: bool,
) -> Result<bool> {
    let Some(raw) = args.get(key) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow!("argument '{}' must be a boolean (true/false)", key)),
    }
}

pub(crate) fn validate_fetch_url(cfg: &AppConfig, raw: &str) -> Result<Url> {
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

pub(crate) fn domain_matches_allowlist(host: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|domain| {
        let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
        host == domain || host.ends_with(&format!(".{domain}"))
    })
}

pub(crate) fn required_arg<'a>(args: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    args.get(key)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow!("missing required argument: {}", key))
}

pub(crate) async fn audit_plugin_tool_call(
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

pub(crate) async fn audit_cli_tool_call(
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

pub(crate) async fn audit_auto_router_tool_call(
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

pub(crate) async fn audit_auto_router_plugin_call(
    service: Arc<AppService>,
    actor: &str,
    plugin: &str,
    command: &str,
    result: &str,
    metadata_json: Option<serde_json::Value>,
) {
    let _ = service
        .store
        .insert_audit(NewAudit {
            group_id: None,
            action: "AUTO_PLUGIN_CALL".to_string(),
            actor: actor.to_string(),
            result: result.to_string(),
            created_at: Utc::now(),
            metadata_json: Some(json!({
                "plugin": plugin,
                "command": command,
                "metadata": metadata_json,
            })),
        })
        .await;
}

pub(crate) async fn audit_auto_skill_context_call(
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

pub(crate) fn is_supported_context_skill(name: &str) -> bool {
    matches!(name, "memory.recent" | "tasks.snapshot" | "group.profile")
}

pub(crate) fn supported_tool_names() -> &'static [&'static str] {
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
        "session.list",
        "session.history",
        "session.send",
        "session.spawn",
        "webhook.register",
        "webhook.list",
        "webhook.delete",
        "fs.list",
        "fs.read",
        "fs.grep",
        "fs.edit",
        "proc.start",
        "proc.wait",
        "proc.kill",
        "proc.logs",
        "ops.web_fetch",
        "ops.search",
        "ops.grep",
        "ops.code_analysis.latest",
        "ops.code_analysis.list",
    ]
}

pub(crate) fn normalize_tool_name(name: &str) -> Option<&'static str> {
    let normalized = name.trim().to_ascii_lowercase().replace('-', "_");
    supported_tool_names()
        .iter()
        .copied()
        .find(|candidate| *candidate == normalized)
}

pub(crate) fn normalize_tool_name_owned(name: &str) -> Option<String> {
    normalize_tool_name(name).map(|name| name.to_string())
}

pub(crate) fn tool_aliases(name: &str) -> &'static [&'static str] {
    match name {
        "task.run_now" => &["task.run-now"],
        "task.clear_group" => &["task.clear-group"],
        "task.clear_all" => &["task.clear-all"],
        "ops.web_fetch" => &["ops.web-fetch"],
        "ops.code_analysis.latest" => &["ops.code-analysis.latest"],
        "ops.code_analysis.list" => &["ops.code-analysis.list"],
        _ => &[],
    }
}

pub(crate) fn render_tool_name_with_aliases(name: &str) -> String {
    let canonical = normalize_tool_name(name).unwrap_or(name);
    let aliases = tool_aliases(canonical);
    if aliases.is_empty() {
        canonical.to_string()
    } else {
        format!("{canonical} (alias: {})", aliases.join(", "))
    }
}

pub(crate) fn tool_summary(name: &str) -> Option<&'static str> {
    let name = normalize_tool_name(name).unwrap_or(name);
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
        "session.list" => Some("List sessions/groups"),
        "session.history" => Some("Get session history; args: group,[limit]"),
        "session.send" => Some("Send prompt to another session; args: to_group,prompt,[from_group]"),
        "session.spawn" => Some("Create or get session group; args: name"),
        "webhook.register" => Some(
            "Register webhook trigger; args: name,path,group,[task_id],[prompt],[token],[enabled]",
        ),
        "webhook.list" => Some("List webhook routes; args: [include_disabled]"),
        "webhook.delete" => Some("Delete webhook route; args: id|name|path"),
        "fs.list" => Some("List files under group root; args: group,[path],[include_hidden]"),
        "fs.read" => Some("Read file under group root; args: group,path,[max_bytes]"),
        "fs.grep" => Some("Search files under group root; args: group,pattern,[path],[ignore_case]"),
        "fs.edit" => Some("Edit file under group root; args: group,path,content,[mode]"),
        "proc.start" => Some("Start long-running process; args: group,command"),
        "proc.wait" => Some("Wait/poll process status; args: id,[timeout_seconds],[remove_on_exit]"),
        "proc.kill" => Some("Terminate process; args: id"),
        "proc.logs" => Some("Read process logs; args: id,[max_bytes]"),
        "ops.web_fetch" => Some("Fetch URL; args: url,[timeout_seconds],[max_bytes]"),
        "ops.search" => Some("Web search; args: query,[limit],[timeout_seconds]"),
        "ops.grep" => Some("Search files in group root; args: group,pattern,[path],[ignore_case]"),
        "ops.code_analysis.latest" => Some(
            "Get latest code-analysis workflow + top findings; args: group,[workflow_id],[top_n],[include_markdown],[max_chars]",
        ),
        "ops.code_analysis.list" => Some("List recent code-analysis workflows; args: group,[limit]"),
        _ => None,
    }
}

pub(crate) fn resolve_plugins_dir(cfg: &AppConfig, override_dir: Option<PathBuf>) -> PathBuf {
    override_dir.unwrap_or_else(|| PathBuf::from(cfg.plugin_directory()))
}

pub(crate) fn ensure_plugin_enabled(cfg: &AppConfig, name: &str) -> Result<()> {
    if cfg.is_plugin_enabled(name) {
        return Ok(());
    }
    Err(anyhow!(
        "plugin '{}' is disabled by config.plugins.enabled",
        name
    ))
}

pub(crate) fn validate_plugins_for_startup(cfg: &AppConfig) -> Result<()> {
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

pub(crate) fn enforce_plugin_signature_policy(
    cfg: &AppConfig,
    plugin: &PluginSpec,
    force_require: bool,
) -> Result<()> {
    let trusted = cfg.plugin_trusted_signing_keys();
    let require_signature = force_require || cfg.plugin_require_signatures();
    if require_signature
        && cfg.plugin_allow_unsigned_local()
        && plugin.manifest.signing_key_id.is_none()
        && plugin.manifest.signature.is_none()
    {
        return Ok(());
    }
    if trusted.is_empty() && !require_signature {
        return Ok(());
    }
    verify_plugin_signature(plugin, &trusted, require_signature)
}
