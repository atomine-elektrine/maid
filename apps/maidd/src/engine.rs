use super::*;

pub(crate) async fn run_prompt_with_auto_tools(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    actor: &str,
) -> Result<String> {
    const CORE_PROMPT_MAX_CHARS: usize = 7900;
    let started = Instant::now();

    // Deterministic, model-free report viewing for code-analysis.
    // This keeps "view report" / "explain findings" usable even when model credentials are missing
    // and avoids relying on the planner to choose the right tool calls.
    if looks_like_code_analysis_report_request(prompt) {
        if let Ok(rendered) =
            render_code_analysis_report(cfg, service.clone(), group_name, prompt).await
        {
            return Ok(rendered);
        }
    }

    let skill_started = Instant::now();
    let skill_context = match auto_invoke_skills_for_prompt(
        cfg,
        service.clone(),
        group_name,
        prompt,
        actor,
    )
    .await
    {
        Ok(context) => context,
        Err(err) => {
            warn!("{actor} skill context failed: {err:#}");
            None
        }
    };
    debug!(
        "{actor} prompt_pipeline stage=skills duration_ms={}",
        skill_started.elapsed().as_millis()
    );

    let action_started = Instant::now();
    let action_context = if cfg.tool_auto_router_enabled() {
        auto_route_actions_for_prompt(cfg, service.clone(), group_name, prompt, actor).await
    } else {
        Ok(AutoActionContext::default())
    };
    debug!(
        "{actor} prompt_pipeline stage=auto_actions duration_ms={}",
        action_started.elapsed().as_millis()
    );

    let model_started = Instant::now();
    let mut sections = Vec::new();
    if let Some(context) = skill_context {
        sections.push(("Skill context", context));
    }
    match action_context {
        Ok(contexts) => {
            if let Some(context) = contexts.plugin_context {
                sections.push(("Plugin context", context));
            }
            if let Some(context) = contexts.tool_context {
                sections.push(("Tool context", context));
            }
        }
        Err(err) => warn!("{actor} auto-action-router failed: {err:#}"),
    }
    let output = if sections.is_empty() {
        let prompt_for_model = clip_prompt_for_core(prompt, CORE_PROMPT_MAX_CHARS);
        if prompt_for_model != prompt {
            warn!(
                "{actor} prompt truncated from {} to {} chars",
                prompt.chars().count(),
                prompt_for_model.chars().count()
            );
        }
        service
            .run_prompt(group_name, &prompt_for_model, actor)
            .await?
    } else {
        let mut augmented_prompt = prompt.to_string();
        for (label, context) in sections {
            augmented_prompt.push_str("\n\n");
            augmented_prompt.push_str(label);
            augmented_prompt.push_str(":\n");
            augmented_prompt.push_str(&context);
        }
        augmented_prompt.push_str("\n\nUse this context if relevant.");
        let prompt_for_model = clip_prompt_for_core(&augmented_prompt, CORE_PROMPT_MAX_CHARS);
        if prompt_for_model != augmented_prompt {
            warn!(
                "{actor} augmented prompt truncated from {} to {} chars",
                augmented_prompt.chars().count(),
                prompt_for_model.chars().count()
            );
        }
        service
            .run_prompt(group_name, &prompt_for_model, actor)
            .await?
    };
    debug!(
        "{actor} prompt_pipeline stage=model duration_ms={}",
        model_started.elapsed().as_millis()
    );
    info!(
        "{actor} prompt_pipeline total_duration_ms={}",
        started.elapsed().as_millis()
    );
    Ok(output)
}

pub(crate) async fn render_code_analysis_report(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
) -> Result<String> {
    let workflow_id = extract_code_analysis_workflow_id(prompt);
    let lowered = prompt.to_ascii_lowercase();
    let include_markdown = lowered.contains("view") || lowered.contains("report");
    let top_n = if lowered.contains("findings") || lowered.contains("explain") {
        25
    } else {
        10
    };

    let mut args = BTreeMap::new();
    args.insert("group".to_string(), group_name.to_string());
    args.insert("include_markdown".to_string(), include_markdown.to_string());
    args.insert("max_chars".to_string(), "3500".to_string());
    args.insert("top_n".to_string(), top_n.to_string());
    if let Some(wf) = workflow_id {
        args.insert("workflow_id".to_string(), wf);
    }

    let payload = execute_code_analysis_latest_tool(cfg, service, "ops.code_analysis.latest", args)
        .await
        .context("code-analysis lookup failed")?;
    format_code_analysis_latest_payload(&payload)
}

pub(crate) fn format_code_analysis_latest_payload(payload: &serde_json::Value) -> Result<String> {
    let workflow_id = payload
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let target_url = payload
        .get("target_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let stats = payload.get("stats").and_then(|v| v.as_object());
    let findings = stats
        .and_then(|s| s.get("reportable_findings"))
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "?".to_string());
    let supply_chain = stats
        .and_then(|s| s.get("supply_chain_findings"))
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "?".to_string());
    let queue_entries = stats
        .and_then(|s| s.get("queue_entries"))
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "?".to_string());
    let coverage_warning = stats
        .and_then(|s| s.get("coverage_warning"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    let mut lines = Vec::new();
    lines.push(format!(
        "Code analysis report\nworkflow={workflow_id} findings={findings} supply_chain={supply_chain} queue_entries={queue_entries}"
    ));
    if !target_url.is_empty() {
        lines.push(format!("target_url={target_url}"));
    }
    if let Some(warning) = coverage_warning {
        lines.push(format!("coverage_warning={}", truncate_line(warning, 220)));
    }

    if let Some(top) = payload.get("top_findings").and_then(|v| v.as_array()) {
        if !top.is_empty() {
            lines.push("top_findings:".to_string());
            for item in top.iter().take(25) {
                let sev = item.get("severity").and_then(|v| v.as_str()).unwrap_or("?");
                let cat = item.get("category").and_then(|v| v.as_str()).unwrap_or("?");
                let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("?");
                lines.push(format!("- {sev} {cat} {id} {path}"));
            }
        }
    }

    if let Some(preview) = payload
        .get("markdown_preview")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        lines.push("".to_string());
        lines.push("report_preview:".to_string());
        lines.push(preview.to_string());
    }

    Ok(lines.join("\n"))
}

pub(crate) fn clip_prompt_for_core(input: &str, max_chars: usize) -> String {
    let input_len = input.chars().count();
    if input_len <= max_chars {
        return input.to_string();
    }
    let reserve = 80usize;
    let keep = max_chars.saturating_sub(reserve);
    let mut truncated = input.chars().take(keep).collect::<String>();
    truncated.push_str("\n\n[truncated to fit prompt limit]");
    truncated
}

#[derive(Default)]
pub(crate) struct AutoActionContext {
    pub(crate) plugin_context: Option<String>,
    pub(crate) tool_context: Option<String>,
}

pub(crate) struct PluginSearchRequest<'a> {
    pub(crate) query: Option<&'a str>,
    pub(crate) category: Option<&'a str>,
    pub(crate) tag: Option<&'a str>,
    pub(crate) capability: Option<&'a str>,
    pub(crate) ranked: bool,
    pub(crate) json_output: bool,
}

pub(crate) struct PluginSearchFilters<'a> {
    pub(crate) query: Option<&'a str>,
    pub(crate) category: Option<&'a str>,
    pub(crate) tag: Option<&'a str>,
    pub(crate) capability: Option<&'a str>,
}

pub(crate) struct PluginSearchCorpus<'a> {
    pub(crate) name: &'a str,
    pub(crate) description: &'a str,
    pub(crate) categories: &'a [String],
    pub(crate) tags: &'a [String],
    pub(crate) capabilities: &'a [String],
}

pub(crate) async fn handle_pairing_command(
    service: Arc<AppService>,
    command: PairingCommands,
) -> Result<()> {
    match command {
        PairingCommands::List { json } => {
            let rows = service.list_pending_telegram_pairings().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if rows.is_empty() {
                println!("no pending pairing requests");
            } else {
                let lines = rows
                    .into_iter()
                    .map(|pairing| {
                        vec![
                            pairing.code,
                            pairing.chat_id.to_string(),
                            pairing.requested_at.to_rfc3339(),
                        ]
                    })
                    .collect::<Vec<_>>();
                print_table(&["CODE", "CHAT_ID", "REQUESTED_AT"], &lines);
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

pub(crate) async fn handle_plugin_command(
    cfg: &AppConfig,
    config_path: &Path,
    store: Arc<SqliteStore>,
    command: PluginCommands,
) -> Result<()> {
    match command {
        PluginCommands::Registry { command } => {
            handle_plugin_registry_command(cfg, store.clone(), command).await?;
        }
        PluginCommands::Search {
            query,
            category,
            tag,
            capability,
            ranked,
            json,
            index,
            dir,
        } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let index_path = resolve_registry_index_path(cfg, index);
            let request = PluginSearchRequest {
                query: query.as_deref(),
                category: category.as_deref(),
                tag: tag.as_deref(),
                capability: capability.as_deref(),
                ranked,
                json_output: json,
            };
            handle_plugin_search_command(cfg, store.clone(), &plugins_dir, &index_path, &request)
                .await?;
        }
        PluginCommands::Info {
            name,
            version,
            index,
            dir,
        } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let index_path = resolve_registry_index_path(cfg, index);
            handle_plugin_info_command(cfg, &plugins_dir, &index_path, &name, version.as_deref())?;
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
        PluginCommands::List { json, dir } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let plugins = discover_plugins(&plugins_dir)?;
            if json {
                let payload = plugins
                    .into_iter()
                    .map(|plugin| {
                        let enabled = cfg.is_plugin_enabled(&plugin.manifest.name);
                        let compatibility = is_maid_compatible(
                            plugin.manifest.min_maid_version.as_deref(),
                            plugin
                                .manifest
                                .compatibility
                                .as_ref()
                                .and_then(|v| v.maid.as_deref()),
                        );
                        json!({
                            "name": plugin.manifest.name,
                            "version": plugin.manifest.version,
                            "enabled": enabled,
                            "compatibility": if compatibility { "compatible" } else { "incompatible" },
                            "description": plugin.manifest.description,
                        })
                    })
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&payload)?);
                return Ok(());
            }
            if plugins.is_empty() {
                println!("no plugins found in {}", plugins_dir.display());
            } else {
                let mut rows = Vec::new();
                for plugin in plugins {
                    let enabled = if cfg.is_plugin_enabled(&plugin.manifest.name) {
                        "enabled"
                    } else {
                        "disabled"
                    };
                    let compatible = if is_maid_compatible(
                        plugin.manifest.min_maid_version.as_deref(),
                        plugin
                            .manifest
                            .compatibility
                            .as_ref()
                            .and_then(|v| v.maid.as_deref()),
                    ) {
                        "compatible"
                    } else {
                        "incompatible"
                    };
                    rows.push(vec![
                        plugin.manifest.name,
                        plugin.manifest.version,
                        enabled.to_string(),
                        compatible.to_string(),
                        plugin.manifest.description.unwrap_or_default(),
                    ]);
                }
                print_table(
                    &["NAME", "VERSION", "STATUS", "COMPATIBILITY", "DESCRIPTION"],
                    &rows,
                );
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
        PluginCommands::Trust { command } => match command {
            PluginTrustCommands::List => {
                println!(
                    "require_signatures={}",
                    if cfg.plugin_require_signatures() {
                        "true"
                    } else {
                        "false"
                    }
                );
                println!(
                    "allow_unsigned_local={}",
                    if cfg.plugin_allow_unsigned_local() {
                        "true"
                    } else {
                        "false"
                    }
                );
                println!(
                    "quarantine_untrusted={}",
                    if cfg.plugin_quarantine_untrusted() {
                        "true"
                    } else {
                        "false"
                    }
                );
                let publishers = cfg.plugin_trusted_publishers();
                if publishers.is_empty() {
                    println!("trusted_publishers=(none)");
                } else {
                    println!("trusted_publishers={}", publishers.join(","));
                }
            }
            PluginTrustCommands::AddPublisher { name } => {
                validate_plugin_name_like_identifier(&name, "publisher name")?;
                set_trusted_publisher_in_config(config_path, &name, true)?;
                println!(
                    "added trusted publisher '{}' in {}",
                    name,
                    config_path.display()
                );
            }
            PluginTrustCommands::RemovePublisher { name } => {
                validate_plugin_name_like_identifier(&name, "publisher name")?;
                set_trusted_publisher_in_config(config_path, &name, false)?;
                println!(
                    "removed trusted publisher '{}' in {}",
                    name,
                    config_path.display()
                );
            }
        },
        PluginCommands::Lock { command } => match command {
            PluginLockCommands::Refresh { index, dir } => {
                let plugins_dir = resolve_plugins_dir(cfg, dir);
                let index_path = resolve_registry_index_path(cfg, index);
                let entries = load_plugin_registry(&index_path).unwrap_or_default();
                refresh_plugin_lockfile(&plugins_dir, &entries)?;
                println!(
                    "refreshed plugin lockfile at {}",
                    plugins_dir.join("lock.toml").display()
                );
            }
        },
        PluginCommands::Update {
            all,
            name,
            channel,
            index,
            dir,
        } => {
            if let Some(channel) = channel.as_deref() {
                validate_update_channel(channel)?;
            }
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let index_path = resolve_registry_index_path(cfg, index);
            let entries = load_plugin_registry(&index_path)?;
            if all {
                let updated = update_all_plugins(
                    cfg,
                    store.clone(),
                    &plugins_dir,
                    &index_path,
                    &entries,
                    channel.as_deref(),
                )
                .await?;
                println!("updated {} plugin(s)", updated);
            } else {
                let target =
                    name.ok_or_else(|| anyhow!("--name is required unless --all is set"))?;
                let updated = update_one_plugin(
                    cfg,
                    store.clone(),
                    &plugins_dir,
                    &index_path,
                    &entries,
                    &target,
                    channel.as_deref(),
                )
                .await?;
                if updated {
                    println!("updated plugin '{}'", target);
                } else {
                    println!("plugin '{}' is up to date", target);
                }
            }
            refresh_plugin_lockfile(&plugins_dir, &entries).ok();
        }
        PluginCommands::Outdated { json, index, dir } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let index_path = resolve_registry_index_path(cfg, index);
            let entries = load_plugin_registry(&index_path)?;
            let outdated = collect_outdated_plugins(&plugins_dir, &entries)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&outdated)?);
                return Ok(());
            }
            if outdated.is_empty() {
                println!("all plugins are up to date");
            } else {
                let rows = outdated
                    .into_iter()
                    .map(|row| vec![row.name, row.current_version, row.latest_version])
                    .collect::<Vec<_>>();
                print_table(&["NAME", "CURRENT", "LATEST"], &rows);
            }
        }
        PluginCommands::Rollback {
            name,
            to_version,
            index,
            dir,
        } => {
            validate_plugin_name(&name)?;
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let index_path = resolve_registry_index_path(cfg, index);
            let entries = load_plugin_registry(&index_path)?;
            let entry = select_registry_entry(&entries, &name, Some(&to_version))?;
            enforce_registry_entry_trust_policy(cfg, entry)?;
            replace_installed_plugin(&plugins_dir, &index_path, entry)?;
            let spec = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &spec, false)?;
            store
                .record_plugin_install(
                    &spec.manifest.name,
                    &spec.manifest.version,
                    &entry.source,
                    "cli-rollback",
                    Utc::now(),
                )
                .await
                .ok();
            refresh_plugin_lockfile(&plugins_dir, &entries).ok();
            println!("rolled back '{}' to v{}", name, spec.manifest.version);
        }
        PluginCommands::Route { command } => match command {
            PluginRouteCommands::Explain { prompt, dir } => {
                let plugins_dir = resolve_plugins_dir(cfg, dir);
                handle_plugin_route_explain(cfg, &plugins_dir, &prompt)?;
            }
            PluginRouteCommands::Pin { capability, plugin } => {
                validate_plugin_name(&plugin)?;
                validate_plugin_capability(&capability)?;
                set_route_pin_in_config(config_path, &capability, Some(&plugin))?;
                println!(
                    "pinned capability '{}' to plugin '{}' in {}",
                    capability,
                    plugin,
                    config_path.display()
                );
            }
            PluginRouteCommands::Unpin { capability } => {
                validate_plugin_capability(&capability)?;
                set_route_pin_in_config(config_path, &capability, None)?;
                println!(
                    "unpinned capability '{}' in {}",
                    capability,
                    config_path.display()
                );
            }
        },
        PluginCommands::Health { name, days, json } => {
            let rows = store.plugin_health_days(&name, days).await?;
            if json {
                let payload = rows
                    .iter()
                    .map(|row| {
                        json!({
                            "day": row.day,
                            "plugin": row.plugin_name,
                            "runs": row.run_count,
                            "success_rate": row.success_rate,
                            "p50_ms": row.p50_latency_ms,
                            "p95_ms": row.p95_latency_ms,
                        })
                    })
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&payload)?);
                return Ok(());
            }
            if rows.is_empty() {
                println!("no plugin health rows found for '{}'", name);
            } else {
                let lines = rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            row.day,
                            row.plugin_name,
                            row.run_count.to_string(),
                            format!("{:.2}", row.success_rate),
                            row.p50_latency_ms.to_string(),
                            row.p95_latency_ms.to_string(),
                        ]
                    })
                    .collect::<Vec<_>>();
                print_table(
                    &["DAY", "PLUGIN", "RUNS", "SUCCESS_RATE", "P50_MS", "P95_MS"],
                    &lines,
                );
            }
        }
        PluginCommands::Stats { top, days, json } => {
            let since = Utc::now() - chrono::Duration::days(days.clamp(1, 365));
            let rows = store.list_plugin_stats(top, since).await?;
            if json {
                let payload = rows
                    .iter()
                    .map(|row| {
                        json!({
                            "plugin": row.plugin_name,
                            "runs": row.run_count,
                            "success_rate": row.success_rate,
                            "avg_ms": row.avg_latency_ms,
                            "p95_ms": row.p95_latency_ms,
                            "last_seen": row.last_seen.map(|v| v.to_rfc3339()),
                        })
                    })
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&payload)?);
                return Ok(());
            }
            if rows.is_empty() {
                println!("no plugin invocation stats found");
            } else {
                let lines = rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            row.plugin_name,
                            row.run_count.to_string(),
                            format!("{:.2}", row.success_rate),
                            row.avg_latency_ms.to_string(),
                            row.p95_latency_ms.to_string(),
                            row.last_seen
                                .map(|v| v.to_rfc3339())
                                .unwrap_or_else(|| "-".to_string()),
                        ]
                    })
                    .collect::<Vec<_>>();
                print_table(
                    &[
                        "PLUGIN",
                        "RUNS",
                        "SUCCESS_RATE",
                        "AVG_MS",
                        "P95_MS",
                        "LAST_SEEN",
                    ],
                    &lines,
                );
            }
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
        PluginCommands::Verify { name, deep, dir } => {
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            let plugin = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &plugin, true)?;
            if deep {
                run_plugin_deep_verify(cfg, &plugin)?;
            }
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
            eprintln!(
                "[plugin] running {} v{}...",
                plugin.manifest.name, plugin.manifest.version
            );
            let started = Instant::now();
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
            let latency_ms = started.elapsed().as_millis() as i64;
            if let Err(err) = &run_result {
                store
                    .record_plugin_invocation(NewPluginInvocation {
                        plugin_name: &plugin.manifest.name,
                        plugin_version: &plugin.manifest.version,
                        command: "cli.run",
                        actor: "cli",
                        ok: false,
                        latency_ms,
                        created_at: Utc::now(),
                    })
                    .await
                    .ok();
                return Err(anyhow!("{err:#}"));
            }
            let response = run_result?;
            store
                .record_plugin_invocation(NewPluginInvocation {
                    plugin_name: &plugin.manifest.name,
                    plugin_version: &plugin.manifest.version,
                    command: "cli.run",
                    actor: "cli",
                    ok: response.ok,
                    latency_ms,
                    created_at: Utc::now(),
                })
                .await
                .ok();
            if !response.ok {
                return Err(anyhow!("plugin returned error: {}", response.message));
            }
            eprintln!("[plugin] done {} ok", plugin.manifest.name);
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PluginRegistryFile {
    #[serde(default)]
    plugin: Vec<PluginRegistryEntry>,
    #[serde(default)]
    plugins: Vec<PluginRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PluginRegistryEntry {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) description: Option<String>,
    pub(crate) source: String,
    pub(crate) subdir: Option<String>,
    pub(crate) publisher: Option<String>,
    pub(crate) categories: Option<Vec<String>>,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) capabilities: Option<Vec<String>>,
    pub(crate) min_maid_version: Option<String>,
    pub(crate) license: Option<String>,
    pub(crate) homepage: Option<String>,
    pub(crate) checksum_sha256: Option<String>,
    pub(crate) published_at: Option<String>,
    pub(crate) signing_key_id: Option<String>,
    pub(crate) signature: Option<String>,
    pub(crate) provenance: Option<String>,
    pub(crate) security_contact: Option<String>,
    pub(crate) update_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PluginLockFile {
    #[serde(default)]
    plugin: Vec<PluginLockEntry>,
    #[serde(default)]
    plugins: Vec<PluginLockEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PluginLockEntry {
    name: String,
    version: String,
    source: String,
    checksum_sha256: Option<String>,
    installed_at: String,
    channel: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OutdatedPluginRow {
    name: String,
    current_version: String,
    latest_version: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PluginRouteDecision {
    pub(crate) plugin: String,
    pub(crate) command: String,
    pub(crate) reason: String,
}

pub(crate) async fn handle_plugin_registry_command(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    command: PluginRegistryCommands,
) -> Result<()> {
    match command {
        PluginRegistryCommands::List { query, json, index } => {
            let index_path = resolve_registry_index_path(cfg, index);
            let entries = load_plugin_registry(&index_path)?;
            let needle = query.map(|v| v.to_ascii_lowercase()).unwrap_or_default();
            let filtered = entries
                .into_iter()
                .filter(|entry| {
                    if needle.is_empty() {
                        return true;
                    }
                    entry.name.to_ascii_lowercase().contains(&needle)
                        || entry
                            .description
                            .as_ref()
                            .map(|d| d.to_ascii_lowercase().contains(&needle))
                            .unwrap_or(false)
                })
                .collect::<Vec<_>>();
            if json {
                println!("{}", serde_json::to_string_pretty(&filtered)?);
            } else {
                let rows = filtered
                    .into_iter()
                    .map(|entry| {
                        vec![
                            entry.name,
                            entry.version,
                            entry.description.unwrap_or_default(),
                        ]
                    })
                    .collect::<Vec<_>>();
                print_table(&["NAME", "VERSION", "DESCRIPTION"], &rows);
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
            enforce_registry_entry_trust_policy(cfg, entry)?;
            let plugins_dir = resolve_plugins_dir(cfg, dir);
            install_plugin_from_registry(&index_path, &plugins_dir, entry)?;
            let spec = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &spec, false)?;
            store
                .record_plugin_install(
                    &spec.manifest.name,
                    &spec.manifest.version,
                    &entry.source,
                    "cli-install",
                    Utc::now(),
                )
                .await
                .ok();
            refresh_plugin_lockfile(&plugins_dir, &entries).ok();
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

            enforce_registry_entry_trust_policy(cfg, latest)?;
            replace_installed_plugin(&plugins_dir, &index_path, latest)?;
            let spec = load_plugin(&plugins_dir, &name)?;
            enforce_plugin_signature_policy(cfg, &spec, false)?;
            store
                .record_plugin_install(
                    &spec.manifest.name,
                    &spec.manifest.version,
                    &latest.source,
                    "cli-update",
                    Utc::now(),
                )
                .await
                .ok();
            refresh_plugin_lockfile(&plugins_dir, &entries).ok();
            println!(
                "updated plugin '{}' from v{} to v{}",
                name, installed.manifest.version, spec.manifest.version
            );
        }
    }

    Ok(())
}

pub(crate) fn resolve_registry_index_path(
    cfg: &AppConfig,
    override_path: Option<PathBuf>,
) -> PathBuf {
    override_path.unwrap_or_else(|| PathBuf::from(cfg.plugin_registry_index_path()))
}

pub(crate) fn load_plugin_registry(index_path: &Path) -> Result<Vec<PluginRegistryEntry>> {
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

pub(crate) fn validate_plugin_registry_entry(entry: &PluginRegistryEntry) -> Result<()> {
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
    if let Some(publisher) = &entry.publisher {
        validate_plugin_name_like_identifier(publisher, "publisher")?;
    }
    for label in [
        ("categories", &entry.categories),
        ("tags", &entry.tags),
        ("capabilities", &entry.capabilities),
    ] {
        if let Some(values) = label.1 {
            for value in values {
                if value.trim().is_empty() {
                    return Err(anyhow!(
                        "registry entry '{}': {} values must not be empty",
                        entry.name,
                        label.0
                    ));
                }
            }
        }
    }
    if let Some(channel) = entry.update_channel.as_deref() {
        validate_update_channel(channel)?;
    }
    match (entry.signing_key_id.as_deref(), entry.signature.as_deref()) {
        (Some(key), Some(signature)) => {
            validate_plugin_name_like_identifier(key, "signing key id")?;
            if signature.trim().is_empty() {
                return Err(anyhow!(
                    "registry entry '{}': signature must not be empty",
                    entry.name
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(anyhow!(
                "registry entry '{}': signing_key_id and signature must be set together",
                entry.name
            ));
        }
    }
    Ok(())
}

pub(crate) fn select_registry_entry<'a>(
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

pub(crate) fn replace_installed_plugin(
    plugins_dir: &Path,
    index_path: &Path,
    entry: &PluginRegistryEntry,
) -> Result<()> {
    let stage_root = plugins_dir.join(format!(".stage-{}", maid_core::new_id()));
    std::fs::create_dir_all(&stage_root)
        .with_context(|| format!("failed to create {}", stage_root.display()))?;
    install_plugin_from_registry(index_path, &stage_root, entry)?;

    let staged = stage_root.join(&entry.name);
    if !staged.exists() {
        return Err(anyhow!("staged plugin missing at {}", staged.display()));
    }
    let target = plugins_dir.join(&entry.name);
    let backup = plugins_dir.join(format!(".backup-{}-{}", entry.name, maid_core::new_id()));
    if target.exists() {
        std::fs::rename(&target, &backup).with_context(|| {
            format!(
                "failed to move current plugin {} to backup",
                target.display()
            )
        })?;
    }
    std::fs::rename(&staged, &target)
        .with_context(|| format!("failed to activate {}", target.display()))?;
    std::fs::remove_dir_all(&backup).ok();
    std::fs::remove_dir_all(&stage_root).ok();
    Ok(())
}

pub(crate) fn install_plugin_from_registry(
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

pub(crate) fn resolve_registry_source(
    index_path: &Path,
    entry: &PluginRegistryEntry,
) -> Result<PathBuf> {
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

pub(crate) fn is_git_source(source: &str) -> bool {
    source.starts_with("git+")
        || source.starts_with("https://")
        || source.starts_with("ssh://")
        || source.starts_with("git@")
}

pub(crate) fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<()> {
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

pub(crate) async fn handle_plugin_search_command(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    plugins_dir: &Path,
    index_path: &Path,
    request: &PluginSearchRequest<'_>,
) -> Result<()> {
    let local_plugins = discover_plugins(plugins_dir).unwrap_or_default();
    let registry_entries = load_plugin_registry(index_path).unwrap_or_default();
    let query_lower = request.query.map(|v| v.to_ascii_lowercase());
    let category_lower = request.category.map(|v| v.to_ascii_lowercase());
    let tag_lower = request.tag.map(|v| v.to_ascii_lowercase());
    let capability_lower = request.capability.map(|v| v.to_ascii_lowercase());
    let filters = PluginSearchFilters {
        query: query_lower.as_deref(),
        category: category_lower.as_deref(),
        tag: tag_lower.as_deref(),
        capability: capability_lower.as_deref(),
    };

    #[derive(Debug, Clone)]
    struct SearchRow {
        name: String,
        version: String,
        description: String,
        installed: bool,
        trusted: bool,
        compatible: bool,
        published_at: Option<DateTime<Utc>>,
        relevance: f64,
    }

    let mut rows_by_name: BTreeMap<String, SearchRow> = BTreeMap::new();

    for entry in registry_entries {
        let description = entry.description.clone().unwrap_or_default();
        let categories = entry.categories.clone().unwrap_or_default();
        let tags = entry.tags.clone().unwrap_or_default();
        let capabilities = entry.capabilities.clone().unwrap_or_default();
        let relevance = text_relevance_score(
            filters.query,
            &entry.name,
            &description,
            &categories,
            &tags,
            &capabilities,
        );
        if !search_filters_match(
            &filters,
            &PluginSearchCorpus {
                name: &entry.name,
                description: &description,
                categories: &categories,
                tags: &tags,
                capabilities: &capabilities,
            },
        ) {
            continue;
        }

        let compatible = is_maid_compatible(entry.min_maid_version.as_deref(), None);
        let trusted = is_registry_entry_trusted(cfg, &entry);
        let published_at = entry
            .published_at
            .as_deref()
            .and_then(parse_registry_timestamp);
        let channel = entry.update_channel.as_deref();
        let row = SearchRow {
            name: entry.name.clone(),
            version: entry.version.clone(),
            description,
            installed: false,
            trusted,
            compatible,
            published_at,
            relevance,
        };

        match rows_by_name.get(&entry.name) {
            Some(existing) => {
                if compare_versions(&entry.version, &existing.version)
                    == std::cmp::Ordering::Greater
                    && update_channel_matches(channel, None)
                {
                    rows_by_name.insert(entry.name.clone(), row);
                }
            }
            None => {
                rows_by_name.insert(entry.name.clone(), row);
            }
        }
    }

    for plugin in local_plugins {
        let mut description = plugin.manifest.description.clone().unwrap_or_default();
        if description.trim().is_empty() {
            description = "installed local plugin".to_string();
        }
        let categories = plugin.manifest.categories.clone().unwrap_or_default();
        let tags = plugin.manifest.tags.clone().unwrap_or_default();
        let capabilities = plugin.manifest.capabilities.clone().unwrap_or_default();
        let relevance = text_relevance_score(
            filters.query,
            &plugin.manifest.name,
            &description,
            &categories,
            &tags,
            &capabilities,
        );
        if !search_filters_match(
            &filters,
            &PluginSearchCorpus {
                name: &plugin.manifest.name,
                description: &description,
                categories: &categories,
                tags: &tags,
                capabilities: &capabilities,
            },
        ) {
            continue;
        }

        let compatible = is_maid_compatible(
            plugin.manifest.min_maid_version.as_deref(),
            plugin
                .manifest
                .compatibility
                .as_ref()
                .and_then(|v| v.maid.as_deref()),
        );
        let trusted = is_local_plugin_trusted(cfg, &plugin);
        rows_by_name.insert(
            plugin.manifest.name.clone(),
            SearchRow {
                name: plugin.manifest.name.clone(),
                version: plugin.manifest.version.clone(),
                description,
                installed: true,
                trusted,
                compatible,
                published_at: None,
                relevance,
            },
        );
    }

    let mut rows = rows_by_name.into_values().collect::<Vec<_>>();
    if rows.is_empty() {
        if request.json_output {
            println!("[]");
        } else {
            println!("no plugins matched filters");
        }
        return Ok(());
    }
    if request.ranked {
        let since = Utc::now() - chrono::Duration::days(30);
        let mut scored = Vec::with_capacity(rows.len());
        for row in rows {
            let health_score = store
                .plugin_success_rate_since(&row.name, since)
                .await?
                .unwrap_or(0.5);
            let recency = row
                .published_at
                .map(|ts| recency_score(ts, Utc::now()))
                .unwrap_or(0.3);
            let trust = if row.trusted { 1.0 } else { 0.0 };
            let compatibility = if row.compatible { 1.0 } else { 0.0 };
            let rank = (row.relevance * 0.35)
                + (trust * 0.20)
                + (compatibility * 0.20)
                + (health_score * 0.20)
                + (recency * 0.05);
            scored.push((row, rank));
        }
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.name.cmp(&b.0.name))
        });
        if request.json_output {
            let payload = scored
                .into_iter()
                .map(|(row, rank)| {
                    json!({
                        "name": row.name,
                        "version": row.version,
                        "rank": rank,
                        "source": if row.installed { "installed" } else { "registry" },
                        "compatibility": if row.compatible { "compatible" } else { "incompatible" },
                        "trusted": row.trusted,
                        "description": row.description,
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&payload)?);
            return Ok(());
        }
        let lines = scored
            .into_iter()
            .map(|(row, rank)| {
                vec![
                    row.name,
                    row.version,
                    format!("{rank:.2}"),
                    if row.installed {
                        "installed".to_string()
                    } else {
                        "registry".to_string()
                    },
                    if row.compatible {
                        "compatible".to_string()
                    } else {
                        "incompatible".to_string()
                    },
                    row.description,
                ]
            })
            .collect::<Vec<_>>();
        print_table(
            &[
                "NAME",
                "VERSION",
                "RANK",
                "SOURCE",
                "COMPATIBILITY",
                "DESCRIPTION",
            ],
            &lines,
        );
        return Ok(());
    }

    rows.sort_by(|a, b| a.name.cmp(&b.name));
    if request.json_output {
        let payload = rows
            .into_iter()
            .map(|row| {
                json!({
                    "name": row.name,
                    "version": row.version,
                    "source": if row.installed { "installed" } else { "registry" },
                    "compatibility": if row.compatible { "compatible" } else { "incompatible" },
                    "trusted": row.trusted,
                    "description": row.description,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }
    let lines = rows
        .into_iter()
        .map(|row| {
            vec![
                row.name,
                row.version,
                if row.installed {
                    "installed".to_string()
                } else {
                    "registry".to_string()
                },
                if row.compatible {
                    "compatible".to_string()
                } else {
                    "incompatible".to_string()
                },
                row.description,
            ]
        })
        .collect::<Vec<_>>();
    print_table(
        &["NAME", "VERSION", "SOURCE", "COMPATIBILITY", "DESCRIPTION"],
        &lines,
    );
    Ok(())
}

pub(crate) fn handle_plugin_info_command(
    cfg: &AppConfig,
    plugins_dir: &Path,
    index_path: &Path,
    name: &str,
    version: Option<&str>,
) -> Result<()> {
    validate_plugin_name(name)?;
    let local = load_plugin(plugins_dir, name).ok();
    let registry_entries = load_plugin_registry(index_path).unwrap_or_default();
    let registry = select_registry_entry(&registry_entries, name, version)
        .ok()
        .cloned();

    if local.is_none() && registry.is_none() {
        return Err(anyhow!(
            "plugin '{}' not found in local plugins or registry",
            name
        ));
    }

    if let Some(plugin) = &local {
        let compatible = is_maid_compatible(
            plugin.manifest.min_maid_version.as_deref(),
            plugin
                .manifest
                .compatibility
                .as_ref()
                .and_then(|v| v.maid.as_deref()),
        );
        println!("name: {}", plugin.manifest.name);
        println!("installed_version: {}", plugin.manifest.version);
        println!(
            "display_name: {}",
            plugin
                .manifest
                .display_name
                .clone()
                .unwrap_or_else(|| plugin.manifest.name.clone())
        );
        println!(
            "description: {}",
            plugin.manifest.description.clone().unwrap_or_default()
        );
        println!(
            "publisher: {}",
            plugin
                .manifest
                .publisher
                .clone()
                .unwrap_or_else(|| "(unknown)".to_string())
        );
        println!(
            "categories: {}",
            join_or_none(plugin.manifest.categories.clone().unwrap_or_default())
        );
        println!(
            "tags: {}",
            join_or_none(plugin.manifest.tags.clone().unwrap_or_default())
        );
        println!(
            "capabilities: {}",
            join_or_none(plugin.manifest.capabilities.clone().unwrap_or_default())
        );
        println!(
            "schema_version: {}",
            plugin.manifest.schema_version.unwrap_or(1)
        );
        println!(
            "compatibility: {}",
            if compatible {
                "compatible"
            } else {
                "incompatible"
            }
        );
    }

    if let Some(entry) = &registry {
        println!("registry_version: {}", entry.version);
        println!(
            "registry_source: {}",
            if let Some(subdir) = &entry.subdir {
                format!("{} (subdir={})", entry.source, subdir)
            } else {
                entry.source.clone()
            }
        );
        println!(
            "registry_publisher: {}",
            entry
                .publisher
                .clone()
                .unwrap_or_else(|| "(unknown)".to_string())
        );
        println!(
            "registry_license: {}",
            entry
                .license
                .clone()
                .unwrap_or_else(|| "(unknown)".to_string())
        );
        println!(
            "registry_homepage: {}",
            entry
                .homepage
                .clone()
                .unwrap_or_else(|| "(none)".to_string())
        );
        println!(
            "registry_published_at: {}",
            entry
                .published_at
                .clone()
                .unwrap_or_else(|| "(unknown)".to_string())
        );
        println!(
            "registry_compatible: {}",
            if is_maid_compatible(entry.min_maid_version.as_deref(), None) {
                "compatible"
            } else {
                "incompatible"
            }
        );
        println!(
            "registry_trusted: {}",
            if is_registry_entry_trusted(cfg, entry) {
                "yes"
            } else {
                "no"
            }
        );
    }

    Ok(())
}

pub(crate) fn join_or_none(values: Vec<String>) -> String {
    if values.is_empty() {
        "(none)".to_string()
    } else {
        values.join(", ")
    }
}

pub(crate) fn search_filters_match(
    filters: &PluginSearchFilters<'_>,
    corpus: &PluginSearchCorpus<'_>,
) -> bool {
    if let Some(needle) = filters.query {
        let haystack = format!(
            "{} {} {} {} {}",
            corpus.name,
            corpus.description,
            corpus.categories.join(" "),
            corpus.tags.join(" "),
            corpus.capabilities.join(" ")
        )
        .to_ascii_lowercase();
        if !haystack.contains(needle) {
            return false;
        }
    }
    if let Some(category) = filters.category {
        if !corpus
            .categories
            .iter()
            .any(|candidate| candidate.to_ascii_lowercase() == category)
        {
            return false;
        }
    }
    if let Some(tag) = filters.tag {
        if !corpus
            .tags
            .iter()
            .any(|candidate| candidate.to_ascii_lowercase() == tag)
        {
            return false;
        }
    }
    if let Some(capability) = filters.capability {
        if !corpus
            .capabilities
            .iter()
            .any(|candidate| candidate.to_ascii_lowercase() == capability)
        {
            return false;
        }
    }
    true
}

pub(crate) fn text_relevance_score(
    query: Option<&str>,
    name: &str,
    description: &str,
    categories: &[String],
    tags: &[String],
    capabilities: &[String],
) -> f64 {
    let Some(query) = query else {
        return 0.5;
    };
    let q = query.to_ascii_lowercase();
    let mut score: f64 = 0.0;
    if name.to_ascii_lowercase().contains(&q) {
        score += 1.0;
    }
    if description.to_ascii_lowercase().contains(&q) {
        score += 0.6;
    }
    if categories
        .iter()
        .any(|candidate| candidate.to_ascii_lowercase().contains(&q))
    {
        score += 0.4;
    }
    if tags
        .iter()
        .any(|candidate| candidate.to_ascii_lowercase().contains(&q))
    {
        score += 0.4;
    }
    if capabilities
        .iter()
        .any(|candidate| candidate.to_ascii_lowercase().contains(&q))
    {
        score += 0.5;
    }
    score.min(1.0)
}

pub(crate) fn recency_score(published_at: DateTime<Utc>, now: DateTime<Utc>) -> f64 {
    let age_days = (now - published_at).num_days().max(0);
    if age_days <= 7 {
        1.0
    } else if age_days <= 30 {
        0.8
    } else if age_days <= 90 {
        0.5
    } else {
        0.2
    }
}

pub(crate) fn parse_registry_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|v| v.with_timezone(&Utc))
}

pub(crate) fn is_maid_compatible(
    min_maid_version: Option<&str>,
    compat_range: Option<&str>,
) -> bool {
    let current = env!("CARGO_PKG_VERSION");
    if let Some(range) = compat_range {
        if !version_matches_constraint(current, range) {
            return false;
        }
    }
    if let Some(min_required) = min_maid_version {
        if !version_matches_constraint(current, &format!(">={min_required}")) {
            return false;
        }
    }
    true
}

pub(crate) fn version_matches_constraint(current: &str, raw: &str) -> bool {
    let current = current.trim();
    let raw = raw.trim();
    if raw.is_empty() {
        return true;
    }
    for clause in raw.split(',') {
        let clause = clause.trim();
        if clause.is_empty() {
            continue;
        }
        let (op, version) = if let Some(rest) = clause.strip_prefix(">=") {
            (">=", rest.trim())
        } else if let Some(rest) = clause.strip_prefix("<=") {
            ("<=", rest.trim())
        } else if let Some(rest) = clause.strip_prefix('>') {
            (">", rest.trim())
        } else if let Some(rest) = clause.strip_prefix('<') {
            ("<", rest.trim())
        } else if let Some(rest) = clause.strip_prefix("==") {
            ("==", rest.trim())
        } else if let Some(rest) = clause.strip_prefix('=') {
            ("=", rest.trim())
        } else {
            ("=", clause)
        };
        let cmp = compare_versions(current, version);
        let ok = match op {
            ">=" => matches!(cmp, std::cmp::Ordering::Greater | std::cmp::Ordering::Equal),
            "<=" => matches!(cmp, std::cmp::Ordering::Less | std::cmp::Ordering::Equal),
            ">" => cmp == std::cmp::Ordering::Greater,
            "<" => cmp == std::cmp::Ordering::Less,
            "=" | "==" => cmp == std::cmp::Ordering::Equal,
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

pub(crate) fn is_local_plugin_trusted(cfg: &AppConfig, plugin: &PluginSpec) -> bool {
    let publishers = cfg.plugin_trusted_publishers();
    if publishers.is_empty() {
        return true;
    }
    if cfg.plugin_allow_unsigned_local() {
        return true;
    }
    plugin
        .manifest
        .publisher
        .as_ref()
        .map(|publisher| publishers.iter().any(|trusted| trusted == publisher))
        .unwrap_or(false)
}

pub(crate) fn is_registry_entry_trusted(cfg: &AppConfig, entry: &PluginRegistryEntry) -> bool {
    let trusted_publishers = cfg.plugin_trusted_publishers();
    if trusted_publishers.is_empty() {
        return true;
    }
    entry
        .publisher
        .as_ref()
        .map(|publisher| {
            trusted_publishers
                .iter()
                .any(|trusted| trusted == publisher)
        })
        .unwrap_or(false)
}

pub(crate) fn enforce_registry_entry_trust_policy(
    cfg: &AppConfig,
    entry: &PluginRegistryEntry,
) -> Result<()> {
    let source_requires_signature =
        is_git_source(&entry.source) || !cfg.plugin_allow_unsigned_local();
    let missing_signature = entry
        .signature
        .as_ref()
        .map(|v| v.trim().is_empty())
        .unwrap_or(true);
    if cfg.plugin_require_signatures() && missing_signature && source_requires_signature {
        return Err(anyhow!(
            "registry plugin '{}' is unsigned and signature policy requires signatures",
            entry.name
        ));
    }

    if !is_registry_entry_trusted(cfg, entry) && cfg.plugin_quarantine_untrusted() {
        return Err(anyhow!(
            "registry plugin '{}' publisher is not trusted",
            entry.name
        ));
    }
    Ok(())
}

pub(crate) fn plugin_lockfile_path(plugins_dir: &Path) -> PathBuf {
    plugins_dir.join("lock.toml")
}

pub(crate) fn load_plugin_lockfile(path: &Path) -> Result<Vec<PluginLockEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read plugin lockfile {}", path.display()))?;
    let parsed: PluginLockFile = toml::from_str(&raw)
        .with_context(|| format!("failed to parse plugin lockfile {}", path.display()))?;
    let mut entries = parsed.plugin;
    entries.extend(parsed.plugins);
    Ok(entries)
}

pub(crate) fn write_plugin_lockfile(path: &Path, entries: &[PluginLockEntry]) -> Result<()> {
    let file = PluginLockFile {
        plugin: entries.to_vec(),
        plugins: Vec::new(),
    };
    let raw = toml::to_string_pretty(&file).context("failed to serialize plugin lockfile")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(path, raw)
        .with_context(|| format!("failed to write plugin lockfile {}", path.display()))?;
    Ok(())
}

pub(crate) fn refresh_plugin_lockfile(
    plugins_dir: &Path,
    registry_entries: &[PluginRegistryEntry],
) -> Result<()> {
    let plugins = discover_plugins(plugins_dir).unwrap_or_default();
    let lock_path = plugin_lockfile_path(plugins_dir);
    let existing = load_plugin_lockfile(&lock_path).unwrap_or_default();
    let existing_by_name = existing
        .into_iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect::<BTreeMap<_, _>>();

    let mut rows = Vec::new();
    for plugin in plugins {
        let registry = registry_entries.iter().find(|entry| {
            entry.name == plugin.manifest.name && entry.version == plugin.manifest.version
        });
        let prior = existing_by_name.get(&plugin.manifest.name);
        let installed_at = prior
            .filter(|entry| entry.version == plugin.manifest.version)
            .map(|entry| entry.installed_at.clone())
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        rows.push(PluginLockEntry {
            name: plugin.manifest.name.clone(),
            version: plugin.manifest.version.clone(),
            source: registry
                .map(|entry| entry.source.clone())
                .unwrap_or_else(|| "local".to_string()),
            checksum_sha256: registry.and_then(|entry| entry.checksum_sha256.clone()),
            installed_at,
            channel: plugin
                .manifest
                .update_channel
                .clone()
                .or_else(|| registry.and_then(|entry| entry.update_channel.clone())),
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    write_plugin_lockfile(&lock_path, &rows)
}

pub(crate) fn collect_outdated_plugins(
    plugins_dir: &Path,
    entries: &[PluginRegistryEntry],
) -> Result<Vec<OutdatedPluginRow>> {
    let plugins = discover_plugins(plugins_dir)?;
    let mut rows = Vec::new();
    for plugin in plugins {
        let latest = select_registry_entry(entries, &plugin.manifest.name, None).ok();
        let Some(latest) = latest else {
            continue;
        };
        if compare_versions(&latest.version, &plugin.manifest.version)
            == std::cmp::Ordering::Greater
        {
            rows.push(OutdatedPluginRow {
                name: plugin.manifest.name.clone(),
                current_version: plugin.manifest.version.clone(),
                latest_version: latest.version.clone(),
            });
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

pub(crate) fn update_channel_matches(entry_channel: Option<&str>, selected: Option<&str>) -> bool {
    let channel = entry_channel.unwrap_or("stable");
    match selected {
        Some(selected) => channel == selected,
        None => true,
    }
}

pub(crate) async fn update_all_plugins(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    plugins_dir: &Path,
    index_path: &Path,
    entries: &[PluginRegistryEntry],
    channel: Option<&str>,
) -> Result<usize> {
    let plugins = discover_plugins(plugins_dir)?;
    let mut updated = 0usize;
    for plugin in plugins {
        let did = update_one_plugin(
            cfg,
            store.clone(),
            plugins_dir,
            index_path,
            entries,
            &plugin.manifest.name,
            channel,
        )
        .await?;
        if did {
            updated += 1;
        }
    }
    Ok(updated)
}

pub(crate) async fn update_one_plugin(
    cfg: &AppConfig,
    store: Arc<SqliteStore>,
    plugins_dir: &Path,
    index_path: &Path,
    entries: &[PluginRegistryEntry],
    name: &str,
    channel: Option<&str>,
) -> Result<bool> {
    validate_plugin_name(name)?;
    let installed = load_plugin(plugins_dir, name)?;
    let mut candidates = entries
        .iter()
        .filter(|entry| entry.name == name)
        .filter(|entry| update_channel_matches(entry.update_channel.as_deref(), channel))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(false);
    }
    candidates.sort_by(|a, b| compare_versions(&b.version, &a.version));
    let latest = candidates[0];
    if compare_versions(&latest.version, &installed.manifest.version) != std::cmp::Ordering::Greater
    {
        return Ok(false);
    }
    enforce_registry_entry_trust_policy(cfg, latest)?;
    replace_installed_plugin(plugins_dir, index_path, latest)?;
    let spec = load_plugin(plugins_dir, name)?;
    enforce_plugin_signature_policy(cfg, &spec, false)?;
    store
        .record_plugin_install(
            &spec.manifest.name,
            &spec.manifest.version,
            &latest.source,
            "cli-update",
            Utc::now(),
        )
        .await
        .ok();
    Ok(true)
}

pub(crate) fn run_plugin_deep_verify(cfg: &AppConfig, plugin: &PluginSpec) -> Result<()> {
    let compatibility_ok = is_maid_compatible(
        plugin.manifest.min_maid_version.as_deref(),
        plugin
            .manifest
            .compatibility
            .as_ref()
            .and_then(|v| v.maid.as_deref()),
    );
    println!(
        "deep.compatibility={}",
        if compatibility_ok { "ok" } else { "fail" }
    );
    let trusted = is_local_plugin_trusted(cfg, plugin);
    println!("deep.trusted={}", if trusted { "yes" } else { "no" });
    println!(
        "deep.publisher={}",
        plugin
            .manifest
            .publisher
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string())
    );
    println!(
        "deep.api_version={}",
        plugin
            .manifest
            .api_version
            .clone()
            .unwrap_or_else(|| "v1".to_string())
    );
    if !trusted && cfg.plugin_quarantine_untrusted() {
        return Err(anyhow!(
            "plugin '{}' is untrusted under quarantine policy",
            plugin.manifest.name
        ));
    }
    if !compatibility_ok {
        return Err(anyhow!(
            "plugin '{}' is not compatible with maid {}",
            plugin.manifest.name,
            env!("CARGO_PKG_VERSION")
        ));
    }
    Ok(())
}

pub(crate) fn handle_plugin_route_explain(
    cfg: &AppConfig,
    plugins_dir: &Path,
    prompt: &str,
) -> Result<()> {
    let enabled_plugins = discover_plugins(plugins_dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|plugin| cfg.is_plugin_enabled(&plugin.manifest.name))
        .collect::<Vec<_>>();

    println!(
        "routing.enabled={}",
        if cfg.plugin_routing_enabled() {
            "true"
        } else {
            "false"
        }
    );
    if !cfg.plugin_routing_enabled() {
        println!("routing.reason=plugins.routing.enabled is false");
        return Ok(());
    }

    if let Some(decision) = resolve_deterministic_route(cfg, prompt, &enabled_plugins) {
        println!("routing.mode=deterministic");
        println!("routing.plugin={}", decision.plugin);
        println!("routing.command={}", decision.command);
        println!("routing.reason={}", decision.reason);
        return Ok(());
    }

    if let Some(plugin) = best_heuristic_route_plugin(prompt, &enabled_plugins) {
        println!("routing.mode=heuristic");
        println!("routing.plugin={}", plugin.manifest.name);
        println!("routing.command=help");
        println!("routing.reason=best match from plugin routing metadata");
    } else {
        println!("routing.mode=model");
        println!("routing.reason=no deterministic rule hit");
    }
    Ok(())
}

pub(crate) fn resolve_deterministic_route(
    cfg: &AppConfig,
    prompt: &str,
    enabled_plugins: &[PluginSpec],
) -> Option<PluginRouteDecision> {
    if !cfg.plugin_routing_enabled() {
        return None;
    }
    let prompt_lower = prompt.to_ascii_lowercase();

    for pin in cfg.plugin_routing_pins() {
        if prompt_lower.contains(&pin.capability.to_ascii_lowercase())
            && enabled_plugins
                .iter()
                .any(|plugin| plugin.manifest.name == pin.plugin)
        {
            return Some(PluginRouteDecision {
                plugin: pin.plugin,
                command: "help".to_string(),
                reason: format!("capability pin matched '{}'", pin.capability),
            });
        }
    }

    for rule in cfg.plugin_routing_intent_rules() {
        if !enabled_plugins
            .iter()
            .any(|plugin| plugin.manifest.name == rule.plugin)
        {
            continue;
        }
        if intent_pattern_matches(&rule.pattern, &prompt_lower) {
            return Some(PluginRouteDecision {
                plugin: rule.plugin,
                command: rule.command,
                reason: format!("intent rule pattern '{}'", rule.pattern),
            });
        }
    }
    None
}

pub(crate) fn best_heuristic_route_plugin<'a>(
    prompt: &str,
    enabled_plugins: &'a [PluginSpec],
) -> Option<&'a PluginSpec> {
    let prompt_lower = prompt.to_ascii_lowercase();
    enabled_plugins
        .iter()
        .map(|plugin| {
            let mut score = 0_i64;
            if prompt_lower.contains(&plugin.manifest.name) {
                score += 5;
            }
            if let Some(routing) = &plugin.manifest.routing {
                for intent in routing.intents.clone().unwrap_or_default() {
                    if prompt_lower.contains(&intent.to_ascii_lowercase()) {
                        score += 3;
                    }
                }
                for example in routing.examples.clone().unwrap_or_default() {
                    if prompt_lower.contains(&example.to_ascii_lowercase()) {
                        score += 2;
                    }
                }
            }
            for capability in plugin.manifest.capabilities.clone().unwrap_or_default() {
                if prompt_lower.contains(&capability.to_ascii_lowercase()) {
                    score += 2;
                }
            }
            (plugin, score)
        })
        .filter(|(_, score)| *score > 0)
        .max_by_key(|(_, score)| *score)
        .map(|(plugin, _)| plugin)
}

pub(crate) fn intent_pattern_matches(pattern: &str, prompt_lower: &str) -> bool {
    let normalized = pattern.trim().trim_start_matches("(?i)");
    for alt in normalized.split('|') {
        let token = alt.trim();
        if token.is_empty() {
            continue;
        }
        if token.contains(".*") {
            let mut cursor = 0usize;
            let mut all = true;
            for segment in token.split(".*") {
                let part = segment
                    .trim()
                    .trim_matches('(')
                    .trim_matches(')')
                    .to_ascii_lowercase();
                if part.is_empty() {
                    continue;
                }
                if let Some(found) = prompt_lower[cursor..].find(&part) {
                    cursor += found + part.len();
                } else {
                    all = false;
                    break;
                }
            }
            if all {
                return true;
            }
            continue;
        }
        let clean = token
            .trim_matches('(')
            .trim_matches(')')
            .to_ascii_lowercase();
        if prompt_lower.contains(&clean) {
            return true;
        }
    }
    false
}

pub(crate) fn set_trusted_publisher_in_config(
    config_path: &Path,
    name: &str,
    enabled: bool,
) -> Result<()> {
    let mut root = load_config_toml_value(config_path)?;
    let publishers = ensure_plugins_trust_publishers_mut(&mut root)?;
    let mut values = publishers
        .iter()
        .filter_map(|value| value.as_str().map(|v| v.to_string()))
        .collect::<Vec<_>>();
    if enabled {
        if !values.iter().any(|value| value == name) {
            values.push(name.to_string());
        }
    } else {
        values.retain(|value| value != name);
    }
    values.sort();
    *publishers = values.into_iter().map(toml::Value::String).collect();
    write_config_toml_value(config_path, &root)
}

pub(crate) fn set_route_pin_in_config(
    config_path: &Path,
    capability: &str,
    plugin: Option<&str>,
) -> Result<()> {
    let mut root = load_config_toml_value(config_path)?;
    let pins = ensure_plugins_routing_pins_mut(&mut root)?;
    let mut values = pins
        .iter()
        .filter_map(|value| value.as_table().cloned())
        .filter_map(|table| {
            let capability_value = table.get("capability")?.as_str()?.to_string();
            let plugin_value = table.get("plugin")?.as_str()?.to_string();
            Some((capability_value, plugin_value))
        })
        .collect::<Vec<_>>();
    values.retain(|(cap, _)| cap != capability);
    if let Some(plugin) = plugin {
        values.push((capability.to_string(), plugin.to_string()));
    }
    values.sort_by(|a, b| a.0.cmp(&b.0));
    let mut new_array = Vec::with_capacity(values.len());
    for (capability, plugin) in values {
        let mut table = toml::Table::new();
        table.insert("capability".to_string(), toml::Value::String(capability));
        table.insert("plugin".to_string(), toml::Value::String(plugin));
        new_array.push(toml::Value::Table(table));
    }
    *pins = new_array;
    write_config_toml_value(config_path, &root)
}

pub(crate) fn load_config_toml_value(config_path: &Path) -> Result<toml::Value> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse {}", config_path.display()))
}

pub(crate) fn write_config_toml_value(config_path: &Path, root: &toml::Value) -> Result<()> {
    let updated = toml::to_string_pretty(root)
        .with_context(|| format!("failed to serialize {}", config_path.display()))?;
    std::fs::write(config_path, updated)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(())
}

pub(crate) fn ensure_plugins_table_mut(root: &mut toml::Value) -> Result<&mut toml::Table> {
    let root_table = root
        .as_table_mut()
        .ok_or_else(|| anyhow!("config root must be a TOML table"))?;
    if !root_table.contains_key("plugins") {
        root_table.insert(
            "plugins".to_string(),
            toml::Value::Table(toml::Table::new()),
        );
    }
    root_table
        .get_mut("plugins")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("plugins config must be a TOML table"))
}

pub(crate) fn ensure_plugins_trust_publishers_mut(
    root: &mut toml::Value,
) -> Result<&mut Vec<toml::Value>> {
    let plugins_table = ensure_plugins_table_mut(root)?;
    if !plugins_table.contains_key("trust") {
        plugins_table.insert("trust".to_string(), toml::Value::Table(toml::Table::new()));
    }
    let trust_table = plugins_table
        .get_mut("trust")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("plugins.trust config must be a TOML table"))?;
    if !trust_table.contains_key("trusted_publishers") {
        trust_table.insert(
            "trusted_publishers".to_string(),
            toml::Value::Array(Vec::new()),
        );
    }
    trust_table
        .get_mut("trusted_publishers")
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| anyhow!("plugins.trust.trusted_publishers must be an array"))
}

pub(crate) fn ensure_plugins_routing_pins_mut(
    root: &mut toml::Value,
) -> Result<&mut Vec<toml::Value>> {
    let plugins_table = ensure_plugins_table_mut(root)?;
    if !plugins_table.contains_key("routing") {
        plugins_table.insert(
            "routing".to_string(),
            toml::Value::Table(toml::Table::new()),
        );
    }
    let routing_table = plugins_table
        .get_mut("routing")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("plugins.routing config must be a TOML table"))?;
    if !routing_table.contains_key("pinned") {
        routing_table.insert("pinned".to_string(), toml::Value::Array(Vec::new()));
    }
    routing_table
        .get_mut("pinned")
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| anyhow!("plugins.routing.pinned must be an array"))
}

pub(crate) fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
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

pub(crate) fn parse_semver_like(value: &str) -> Vec<u64> {
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

pub(crate) fn validate_plugin_name(name: &str) -> Result<()> {
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

pub(crate) fn validate_plugin_name_like_identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }
    if !value.chars().all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_uppercase()
            || c.is_ascii_digit()
            || c == '-'
            || c == '.'
            || c == '_'
    }) {
        return Err(anyhow!(
            "{label} must contain only letters, digits, dots, underscores, and hyphens"
        ));
    }
    Ok(())
}

pub(crate) fn validate_plugin_capability(value: &str) -> Result<()> {
    validate_plugin_name_like_identifier(value, "capability")
}

pub(crate) fn validate_update_channel(channel: &str) -> Result<()> {
    if !matches!(channel, "stable" | "beta" | "edge") {
        return Err(anyhow!("update channel must be one of: stable, beta, edge"));
    }
    Ok(())
}

pub(crate) fn set_plugin_enabled_in_config(
    config_path: &Path,
    name: &str,
    enabled: bool,
) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut root: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let root_table = root
        .as_table_mut()
        .ok_or_else(|| anyhow!("config root must be a TOML table"))?;

    if !root_table.contains_key("plugins") {
        root_table.insert(
            "plugins".to_string(),
            toml::Value::Table(toml::Table::new()),
        );
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
pub(crate) struct PluginToolBridgeSessionHandle {
    pub(crate) path: PathBuf,
    pub(crate) token: String,
}

pub(crate) fn create_plugin_tool_bridge_session(
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

pub(crate) fn resolve_allowed_plugin_tools(cfg: &AppConfig, plugin: &PluginSpec) -> Vec<String> {
    let cfg_allow = cfg
        .plugin_tool_allowlist()
        .into_iter()
        .filter_map(|name| normalize_tool_name_owned(&name))
        .collect::<HashSet<_>>();
    if cfg_allow.is_empty() {
        return Vec::new();
    }
    let plugin_allow = plugin.manifest.allowed_tools.clone().unwrap_or_default();
    if plugin_allow.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for tool in plugin_allow {
        let Some(canonical) = normalize_tool_name_owned(&tool) else {
            continue;
        };
        if !cfg_allow.contains(&canonical) {
            continue;
        }
        if seen.insert(canonical.clone()) {
            out.push(canonical);
        }
    }
    out
}

pub(crate) async fn handle_tool_command(
    cfg: &AppConfig,
    service: Arc<AppService>,
    command: ToolCommands,
) -> Result<()> {
    let session = load_plugin_tool_session_from_env_optional()?;

    match command {
        ToolCommands::List { json } => {
            let tools = if let Some(session) = session {
                session.allowed_tools
            } else {
                supported_tool_names()
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            };
            if json {
                let payload = tools
                    .into_iter()
                    .map(|tool| {
                        let canonical = normalize_tool_name(&tool).unwrap_or(&tool);
                        json!({
                            "tool": canonical,
                            "aliases": tool_aliases(canonical),
                            "summary": tool_summary(canonical),
                        })
                    })
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                for tool in tools {
                    let rendered = render_tool_name_with_aliases(&tool);
                    if let Some(summary) = tool_summary(&tool) {
                        println!("{rendered}\t{summary}");
                    } else {
                        println!("{rendered}");
                    }
                }
            }
        }
        ToolCommands::Call { tool, args } => {
            let canonical_tool = normalize_tool_name_owned(&tool)
                .ok_or_else(|| anyhow!("unsupported tool '{}'", tool))?;
            let parsed = parse_kv_args(&args)?;
            if let Some(session) = session {
                if !session
                    .allowed_tools
                    .iter()
                    .any(|allowed| allowed == &canonical_tool)
                {
                    return Err(anyhow!(
                        "tool '{}' not allowed for plugin session",
                        canonical_tool
                    ));
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
                    execute_tool_call(cfg, service.clone(), &canonical_tool, parsed, &plugin_actor)
                        .await;
                let (result_status, data) = match outcome {
                    Ok(data) => ("SUCCESS", data),
                    Err(err) => {
                        audit_plugin_tool_call(
                            service.clone(),
                            &session.plugin_name,
                            &canonical_tool,
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
                    &canonical_tool,
                    result_status,
                    Some(json!({ "data_preview": data })),
                )
                .await;
                println!("{}", serde_json::to_string(&data)?);
            } else {
                let outcome =
                    execute_tool_call(cfg, service.clone(), &canonical_tool, parsed, "cli").await;
                let (result_status, data) = match outcome {
                    Ok(data) => ("SUCCESS", data),
                    Err(err) => {
                        audit_cli_tool_call(
                            service.clone(),
                            &canonical_tool,
                            "FAILED",
                            Some(json!({ "error": format!("{err:#}") })),
                        )
                        .await;
                        return Err(err);
                    }
                };
                audit_cli_tool_call(
                    service.clone(),
                    &canonical_tool,
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
