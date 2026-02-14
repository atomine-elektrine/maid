use super::*;

pub(crate) fn parent_or_current(path: &str) -> Result<&Path> {
    Path::new(path)
        .parent()
        .ok_or_else(|| anyhow!("invalid path: {path}"))
}

pub(crate) fn load_dotenv_file(path: &Path) {
    match dotenvy::from_path(path) {
        Ok(_) => info!("loaded environment file {}", path.display()),
        Err(dotenvy::Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => warn!("failed to load environment file {}: {err}", path.display()),
    }
}

pub(crate) fn apply_config_path_from_env(cli: &mut Cli) {
    if cli.config.exists() {
        return;
    }
    if let Ok(from_env) = std::env::var("MAID_CONFIG") {
        let from_env_path = PathBuf::from(from_env);
        if from_env_path.exists() {
            cli.config = from_env_path;
        }
    }
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

pub(crate) fn build_service(
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
    let runtime_kind = RuntimeKind::parse(&cfg.runtime)?;
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

pub(crate) async fn run_scheduler_daemon(
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

pub(crate) fn build_telegram_runtime(
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

pub(crate) fn build_scheduler_executor(
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

pub(crate) async fn run_serve(
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

pub(crate) async fn run_gateway(
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
        let serve_task = run_serve(cfg, store, service.clone(), Some(events.clone()));
        let control_task = run_gateway_control_plane(port, status, events.clone(), service.clone());
        let (serve_result, control_result) = tokio::join!(serve_task, control_task);
        serve_result?;
        control_result?;
        return Ok(());
    }

    let scheduler_executor =
        build_scheduler_executor(cfg, store.clone(), service.clone(), Some(events.clone()))?;
    let scheduler_task = run_scheduler_daemon(cfg, store.clone(), scheduler_executor);
    let control_task = run_gateway_control_plane(port, status, events, service.clone());
    let (scheduler_result, control_result) = tokio::join!(scheduler_task, control_task);
    scheduler_result?;
    control_result?;
    Ok(())
}

async fn run_gateway_control_plane(
    port: u16,
    status: GatewayStatus,
    events: GatewayEvents,
    service: Arc<AppService>,
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
                let service_clone = service.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_gateway_client(stream, status_clone, events_clone, service_clone).await {
                        warn!("gateway client {} failed: {err:#}", addr);
                    }
                });
            }
        }
    }

    Ok(())
}

pub(crate) async fn run_dashboard(
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

    let headers = read_http_headers(&mut reader).await?;
    let content_length = headers
        .get("content-length")
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > 1_048_576 {
        write_http_response(
            &mut write_half,
            "413 Payload Too Large",
            "application/json",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "payload_too_large",
                "max_bytes": 1_048_576,
            }))?,
        )
        .await?;
        return Ok(());
    }
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }

    let (path, query) = parse_http_target(target)?;
    match (method, path.as_str()) {
        ("GET", "/") => {
            let body = dashboard_html();
            write_http_response(&mut write_half, "200 OK", "text/html; charset=utf-8", body)
                .await?;
        }
        ("GET", "/assets/tailwind.css") => {
            write_http_response(
                &mut write_half,
                "200 OK",
                "text/css; charset=utf-8",
                dashboard_tailwind_css().to_string(),
            )
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
        ("POST", "/api/assistant/execute") => {
            let group = query
                .get("group")
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or("main")
                .to_string();
            let input = query
                .get("input")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: input"))?;
            let payload =
                execute_dashboard_input(&cfg, service.clone(), group.as_str(), input.as_str())
                    .await?;
            let body = serde_json::to_string_pretty(&payload)?;
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
        (method, path) if parse_dashboard_plugin_api_route(method, path).is_some() => {
            let route = parse_dashboard_plugin_api_route(method, path).expect("route is checked");

            let parsed = if route.expects_body {
                match parse_dashboard_plugin_body(&body) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        write_http_response(
                            &mut write_half,
                            "400 Bad Request",
                            "application/json",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": format!("{err:#}"),
                            }))?,
                        )
                        .await?;
                        return Ok(());
                    }
                }
            } else {
                DashboardPluginBody::default()
            };

            let command = match route.command {
                Some(ref value) => value.clone(),
                None => parsed
                    .command
                    .clone()
                    .unwrap_or_else(|| "execute".to_string())
                    .trim()
                    .to_string(),
            };
            if command.is_empty() {
                write_http_response(
                    &mut write_half,
                    "400 Bad Request",
                    "application/json",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": "missing command in request body",
                    }))?,
                )
                .await?;
                return Ok(());
            }

            let payload = match run_dashboard_plugin_command(
                &cfg,
                &config_path,
                store.clone(),
                &route.plugin,
                &command,
                parsed.args,
                parsed.input,
                "dashboard-api",
            )
            .await
            {
                Ok(payload) => payload,
                Err(err) => {
                    write_http_response(
                        &mut write_half,
                        "400 Bad Request",
                        "application/json",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": format!("{err:#}"),
                        }))?,
                    )
                    .await?;
                    return Ok(());
                }
            };
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
        ("POST", "/api/tasks/create") => {
            let group = query
                .get("group")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: group"))?;
            let name = query
                .get("name")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: name"))?;
            let schedule_input = query
                .get("schedule")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: schedule"))?;
            let prompt = query
                .get("prompt")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: prompt"))?;
            let schedule_rrule = schedule_from_human_or_rrule(&schedule_input)?;
            let task = service
                .create_task(&group, &name, &schedule_rrule, &prompt, "dashboard")
                .await?;
            let body = serde_json::to_string_pretty(&json!({
                "created": true,
                "group": group,
                "task": task,
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/tasks/update") => {
            let id = query
                .get("id")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: id"))?;
            let name = query
                .get("name")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: name"))?;
            let schedule_input = query
                .get("schedule")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: schedule"))?;
            let prompt = query
                .get("prompt")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: prompt"))?;
            let status_raw = query
                .get("status")
                .cloned()
                .unwrap_or_else(|| "ACTIVE".to_string())
                .to_ascii_uppercase();
            let status = TaskStatus::from_db(&status_raw)?;
            let schedule_rrule = schedule_from_human_or_rrule(&schedule_input)?;
            let task = service
                .update_task(&id, &name, &schedule_rrule, &prompt, status, "dashboard")
                .await?;
            let body = serde_json::to_string_pretty(&json!({
                "id": id,
                "updated": task.is_some(),
                "task": task,
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/tasks/pause") => {
            let id = query
                .get("id")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: id"))?;
            service.pause_task(&id, "dashboard").await?;
            let body = serde_json::to_string_pretty(&json!({
                "id": id,
                "status": "PAUSED",
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/tasks/resume") => {
            let id = query
                .get("id")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: id"))?;
            service.resume_task(&id, "dashboard").await?;
            let body = serde_json::to_string_pretty(&json!({
                "id": id,
                "status": "ACTIVE",
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/tasks/run-now") => {
            let id = query
                .get("id")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: id"))?;
            let run = service.run_task_now(&id, "dashboard").await?;
            let body = serde_json::to_string_pretty(&json!({
                "id": id,
                "run": {
                    "id": run.run_id,
                    "status": run.status.as_str(),
                    "output_summary": run.output_summary,
                    "error_text": run.error_text,
                }
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
        }
        ("POST", "/api/tasks/delete") => {
            let id = query
                .get("id")
                .cloned()
                .ok_or_else(|| anyhow!("missing query param: id"))?;
            let deleted = service.delete_task(&id, "dashboard").await?;
            let body = serde_json::to_string_pretty(&json!({
                "id": id,
                "deleted": deleted,
            }))?;
            write_http_response(&mut write_half, "200 OK", "application/json", body).await?;
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

async fn execute_dashboard_input(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    input: &str,
) -> Result<serde_json::Value> {
    let group_name = group_name.trim();
    let input = input.trim();
    if group_name.is_empty() {
        return Err(anyhow!("group cannot be empty"));
    }
    if input.is_empty() {
        return Err(anyhow!("input cannot be empty"));
    }

    service.ensure_group(group_name, "dashboard").await?;

    if let Some(command) = input.strip_prefix('/') {
        return execute_dashboard_command(cfg, service, group_name, command).await;
    }

    let output = run_prompt_with_auto_tools(cfg, service, group_name, input, "dashboard").await?;
    Ok(json!({
        "mode": "chat",
        "group": group_name,
        "prompt": input,
        "output": output,
    }))
}

async fn execute_dashboard_command(
    cfg: &AppConfig,
    service: Arc<AppService>,
    group_name: &str,
    command: &str,
) -> Result<serde_json::Value> {
    let command = command.trim();
    if command.is_empty() || command.eq_ignore_ascii_case("help") {
        return Ok(json!({
            "mode": "help",
            "group": group_name,
            "help": dashboard_command_help(),
        }));
    }

    if command.eq_ignore_ascii_case("run") {
        return Err(anyhow!("usage: /run <prompt>"));
    }
    if command.to_ascii_lowercase().starts_with("run ") {
        let prompt = command["run ".len()..].trim();
        if prompt.is_empty() {
            return Err(anyhow!("usage: /run <prompt>"));
        }
        let output =
            run_prompt_with_auto_tools(cfg, service.clone(), group_name, prompt, "dashboard")
                .await?;
        return Ok(json!({
            "mode": "chat",
            "group": group_name,
            "prompt": prompt,
            "output": output,
        }));
    }

    let (tool_raw, arg_tokens) = parse_dashboard_tool_command(command)?;
    let tool = normalize_tool_name_owned(&tool_raw).ok_or_else(|| {
        anyhow!(
            "unknown command '{}'. use /help or /tool <tool> key=value...",
            tool_raw
        )
    })?;

    let mut args = if tool == "run.prompt" && arg_tokens.iter().all(|token| !token.contains('=')) {
        if arg_tokens.is_empty() {
            return Err(anyhow!("usage: /run.prompt <prompt> or /run <prompt>"));
        }
        let mut args = BTreeMap::new();
        args.insert("group".to_string(), group_name.to_string());
        args.insert("prompt".to_string(), arg_tokens.join(" "));
        args
    } else {
        parse_kv_args(&arg_tokens)?
    };

    if dashboard_tool_supports_default_group(&tool) && !args.contains_key("group") {
        args.insert("group".to_string(), group_name.to_string());
    }

    let result = execute_tool_call(cfg, service, &tool, args, "dashboard").await?;
    Ok(json!({
        "mode": "command",
        "group": group_name,
        "command": command,
        "tool": tool,
        "result": result,
    }))
}

fn parse_dashboard_tool_command(command: &str) -> Result<(String, Vec<String>)> {
    let tokens = command
        .split_whitespace()
        .map(|part| part.to_string())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err(anyhow!("empty command"));
    }

    if tokens[0].eq_ignore_ascii_case("tool") {
        if tokens.len() < 2 {
            return Err(anyhow!("usage: /tool <name> key=value..."));
        }
        return Ok((tokens[1].clone(), tokens[2..].to_vec()));
    }

    if tokens.len() >= 2 {
        let dotted = format!("{}.{}", tokens[0], tokens[1]);
        if normalize_tool_name(&dotted).is_some() {
            return Ok((dotted, tokens[2..].to_vec()));
        }
    }

    Ok((tokens[0].clone(), tokens[1..].to_vec()))
}

fn dashboard_tool_supports_default_group(tool: &str) -> bool {
    matches!(
        normalize_tool_name(tool).unwrap_or(tool),
        "run.prompt"
            | "task.list"
            | "task.create"
            | "task.clear_group"
            | "session.history"
            | "ops.grep"
            | "fs.list"
            | "fs.read"
            | "fs.grep"
            | "fs.edit"
            | "proc.start"
            | "ops.code_analysis.latest"
            | "ops.code_analysis.list"
    )
}

fn dashboard_command_help() -> &'static str {
    "Natural language:\n\
Type anything and maid will answer in the selected group context.\n\n\
Commands (prefix with /):\n\
- /run <prompt>\n\
- /tool <tool_name> key=value ...\n\
- /task.list\n\
- /task.list group=main\n\
- /task.run_now id=<task_id>\n\
- /task.pause id=<task_id>\n\
- /task.resume id=<task_id>\n\
- /group.list\n\
- /session.list\n\
- /session.history group=main limit=20\n\
- /webhook.list\n\
- /fs.list path=.\n\
- /ops.search query=latest+rust+release limit=3\n\n\
Tip: /task list maps to /task.list automatically."
}

#[derive(Debug, Clone)]
struct DashboardPluginApiRoute {
    plugin: String,
    command: Option<String>,
    expects_body: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct DashboardPluginBody {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: BTreeMap<String, String>,
    #[serde(default)]
    input: Option<String>,
}

fn parse_dashboard_plugin_api_route(method: &str, path: &str) -> Option<DashboardPluginApiRoute> {
    let suffix = path.strip_prefix("/api/plugins/")?;
    let segments = suffix
        .split('/')
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>();

    match segments.as_slice() {
        [plugin, "describe"] if method.eq_ignore_ascii_case("GET") => {
            Some(DashboardPluginApiRoute {
                plugin: (*plugin).to_string(),
                command: Some("describe".to_string()),
                expects_body: false,
            })
        }
        [plugin, "execute"] if method.eq_ignore_ascii_case("POST") => {
            Some(DashboardPluginApiRoute {
                plugin: (*plugin).to_string(),
                command: None,
                expects_body: true,
            })
        }
        [plugin, "command", command] if method.eq_ignore_ascii_case("POST") => {
            Some(DashboardPluginApiRoute {
                plugin: (*plugin).to_string(),
                command: Some((*command).to_string()),
                expects_body: true,
            })
        }
        _ => None,
    }
}

fn parse_dashboard_plugin_body(raw: &[u8]) -> Result<DashboardPluginBody> {
    if raw.is_empty() {
        return Ok(DashboardPluginBody::default());
    }

    serde_json::from_slice::<DashboardPluginBody>(raw)
        .context("invalid JSON body, expected {\"command\"?,\"args\"?,\"input\"?}")
}

async fn run_dashboard_plugin_command(
    cfg: &AppConfig,
    config_path: &Path,
    store: Arc<SqliteStore>,
    plugin_name: &str,
    command: &str,
    args: BTreeMap<String, String>,
    input: Option<String>,
    actor: &str,
) -> Result<serde_json::Value> {
    validate_plugin_name(plugin_name)?;
    let live_cfg = AppConfig::load(config_path).unwrap_or_else(|_| cfg.clone());
    ensure_plugin_enabled(&live_cfg, plugin_name)?;
    let plugins_dir = resolve_plugins_dir(&live_cfg, None);
    let plugin = load_plugin(&plugins_dir, plugin_name).with_context(|| {
        format!(
            "plugin '{}' not found in {}",
            plugin_name,
            plugins_dir.display()
        )
    })?;
    enforce_plugin_signature_policy(&live_cfg, &plugin, false)?;

    let bridge = create_plugin_tool_bridge_session(&live_cfg, &plugin)?;
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

    let request = PluginRequest {
        command: command.to_string(),
        args,
        input,
        context: PluginContext {
            actor: actor.to_string(),
            cwd: std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .display()
                .to_string(),
        },
    };

    let started = Instant::now();
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
                command,
                actor,
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
            command,
            actor,
            ok: response.ok,
            latency_ms,
            created_at: Utc::now(),
        })
        .await
        .ok();

    Ok(json!({
        "ok": response.ok,
        "plugin": plugin.manifest.name,
        "version": plugin.manifest.version,
        "command": command,
        "message": response.message,
        "output": response.output,
        "data": response.data
    }))
}

pub(crate) async fn run_health_checks(
    cfg: &AppConfig,
    gateway_port: u16,
    json: bool,
) -> Result<()> {
    let snapshot = build_health_snapshot(cfg).await?;

    let gateway_ok = check_gateway_ping(gateway_port).await;

    if json {
        let payload = json!({
            "gateway_port": gateway_port,
            "gateway_reachable": gateway_ok,
            "ok": gateway_ok,
            "snapshot": snapshot,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
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

pub(crate) async fn check_gateway_ping(port: u16) -> bool {
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

pub(crate) fn parse_http_target(target: &str) -> Result<(String, BTreeMap<String, String>)> {
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
    r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>maid control dashboard</title>
  <link rel="stylesheet" href="/assets/tailwind.css" />
  <style>
    :root {
      color-scheme: light dark;
      --bg-spot-1: rgba(0, 0, 0, 0.06);
      --bg-spot-2: rgba(0, 0, 0, 0.05);
      --bg-1: #fcfcfc;
      --bg-2: #f1f1f1;
      --bg-3: #ededed;
      --panel: rgba(255, 255, 255, 0.96);
      --panel-border: rgba(0, 0, 0, 0.14);
      --panel-head-bg: linear-gradient(180deg, rgba(0, 0, 0, 0.07), rgba(0, 0, 0, 0));
      --text: #0f0f0f;
      --text-strong: #111111;
      --muted: #4d4d4d;
      --line: rgba(0, 0, 0, 0.14);
      --pill-bg: rgba(0, 0, 0, 0.04);
      --pill-ok-text: #111111;
      --pill-ok-border: rgba(0, 0, 0, 0.36);
      --pill-ok-bg: rgba(0, 0, 0, 0.08);
      --pill-err-text: #ffffff;
      --pill-err-border: rgba(0, 0, 0, 0.88);
      --pill-err-bg: rgba(0, 0, 0, 0.9);
      --btn-border: rgba(0, 0, 0, 0.82);
      --btn-hover-border: rgba(0, 0, 0, 1);
      --btn-top: rgba(0, 0, 0, 0.9);
      --btn-bottom: rgba(0, 0, 0, 0.82);
      --btn-warn-border: rgba(0, 0, 0, 0.7);
      --btn-warn-top: rgba(34, 34, 34, 0.9);
      --btn-warn-bottom: rgba(34, 34, 34, 0.8);
      --btn-danger-border: rgba(0, 0, 0, 1);
      --btn-danger-top: rgba(0, 0, 0, 1);
      --btn-danger-bottom: rgba(0, 0, 0, 0.92);
      --btn-text: #ffffff;
      --th-bg: rgba(245, 245, 245, 0.98);
      --mono: #222222;
      --chip-bg: rgba(0, 0, 0, 0.06);
      --chip-text: #1a1a1a;
      --chip-active-border: rgba(0, 0, 0, 0.52);
      --chip-active-bg: rgba(0, 0, 0, 0.12);
      --chip-running-border: rgba(0, 0, 0, 0.42);
      --chip-running-bg: rgba(0, 0, 0, 0.09);
      --chip-bad-border: rgba(0, 0, 0, 0.76);
      --chip-bad-bg: rgba(0, 0, 0, 0.78);
      --chip-bad-text: #ffffff;
      --plugin-bg: rgba(0, 0, 0, 0.03);
      --field-bg: rgba(255, 255, 255, 0.98);
      --assistant-log-bg: rgba(0, 0, 0, 0.03);
      --assistant-msg-bg: rgba(255, 255, 255, 1);
      --assistant-user-bg: rgba(0, 0, 0, 0.92);
      --assistant-user-border: rgba(0, 0, 0, 0.82);
      --assistant-user-text: #ffffff;
      --assistant-error-bg: rgba(0, 0, 0, 0.14);
      --assistant-error-border: rgba(0, 0, 0, 0.75);
      --shadow: 0 14px 32px rgba(0, 0, 0, 0.08);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg-spot-1: rgba(255, 255, 255, 0.04);
        --bg-spot-2: rgba(255, 255, 255, 0.025);
        --bg-1: #050505;
        --bg-2: #0a0a0a;
        --bg-3: #0f0f10;
        --panel: rgba(12, 12, 13, 0.95);
        --panel-border: rgba(255, 255, 255, 0.14);
        --panel-head-bg: linear-gradient(180deg, rgba(255, 255, 255, 0.08), rgba(255, 255, 255, 0));
        --text: #ececec;
        --text-strong: #ffffff;
        --muted: #b7b7b9;
        --line: rgba(255, 255, 255, 0.14);
        --pill-bg: rgba(255, 255, 255, 0.08);
        --pill-ok-text: #ffffff;
        --pill-ok-border: rgba(255, 255, 255, 0.28);
        --pill-ok-bg: rgba(255, 255, 255, 0.12);
        --pill-err-text: #ffffff;
        --pill-err-border: rgba(255, 255, 255, 0.45);
        --pill-err-bg: rgba(255, 255, 255, 0.2);
        --btn-border: rgba(255, 255, 255, 0.26);
        --btn-hover-border: rgba(255, 255, 255, 0.44);
        --btn-top: rgba(38, 38, 40, 0.98);
        --btn-bottom: rgba(22, 22, 24, 0.98);
        --btn-warn-border: rgba(255, 255, 255, 0.34);
        --btn-warn-top: rgba(64, 64, 66, 0.98);
        --btn-warn-bottom: rgba(46, 46, 48, 0.98);
        --btn-danger-border: rgba(255, 255, 255, 0.38);
        --btn-danger-top: rgba(74, 74, 76, 0.98);
        --btn-danger-bottom: rgba(54, 54, 56, 0.98);
        --btn-text: #ffffff;
        --th-bg: rgba(17, 17, 18, 0.98);
        --mono: #d0d0d2;
        --chip-bg: rgba(255, 255, 255, 0.1);
        --chip-text: #efefef;
        --chip-active-border: rgba(255, 255, 255, 0.24);
        --chip-active-bg: rgba(255, 255, 255, 0.16);
        --chip-running-border: rgba(255, 255, 255, 0.2);
        --chip-running-bg: rgba(255, 255, 255, 0.13);
        --chip-bad-border: rgba(255, 255, 255, 0.42);
        --chip-bad-bg: rgba(255, 255, 255, 0.22);
        --chip-bad-text: #ffffff;
        --plugin-bg: rgba(255, 255, 255, 0.04);
        --field-bg: rgba(5, 5, 6, 0.92);
        --assistant-log-bg: rgba(255, 255, 255, 0.04);
        --assistant-msg-bg: rgba(16, 16, 17, 0.92);
        --assistant-user-bg: rgba(255, 255, 255, 0.12);
        --assistant-user-border: rgba(255, 255, 255, 0.22);
        --assistant-user-text: #ffffff;
        --assistant-error-bg: rgba(255, 255, 255, 0.16);
        --assistant-error-border: rgba(255, 255, 255, 0.3);
        --shadow: 0 16px 36px rgba(0, 0, 0, 0.36);
      }
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 0% -10%, var(--bg-spot-1), transparent 40%),
        radial-gradient(circle at 100% 0%, var(--bg-spot-2), transparent 36%),
        linear-gradient(145deg, var(--bg-1) 0%, var(--bg-2) 54%, var(--bg-3) 100%);
      min-height: 100vh;
    }

    .app {
      max-width: 1300px;
      margin: 0 auto;
      padding: 18px 16px 40px;
    }

    .topbar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 16px;
      align-items: flex-end;
    }

    .eyebrow {
      margin: 0;
      font: 700 12px/1.2 "IBM Plex Mono", "Fira Code", monospace;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
    }

    h1 {
      margin: 4px 0 0;
      font-size: clamp(26px, 4vw, 36px);
      line-height: 1.1;
      letter-spacing: -0.02em;
    }

    .subtitle {
      margin: 6px 0 0;
      color: var(--muted);
      max-width: 640px;
      font-size: 14px;
    }

    .quickstart {
      margin: 0 0 14px;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: var(--panel);
      box-shadow: var(--shadow);
      color: var(--muted);
      font: 600 12px/1.45 "IBM Plex Mono", "Fira Code", monospace;
      letter-spacing: 0.02em;
    }

    .quickstart strong { color: var(--text-strong); }

    .controls {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }

    .pill {
      font: 700 12px/1 "IBM Plex Mono", "Fira Code", monospace;
      border-radius: 999px;
      padding: 8px 10px;
      border: 1px solid var(--line);
      background: var(--pill-bg);
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .pill.ok {
      color: var(--pill-ok-text);
      border-color: var(--pill-ok-border);
      background: var(--pill-ok-bg);
    }

    .pill.err {
      color: var(--pill-err-text);
      border-color: var(--pill-err-border);
      background: var(--pill-err-bg);
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      vertical-align: middle;
      white-space: nowrap;
      min-height: 34px;
      border: 1px solid var(--btn-border);
      background: linear-gradient(180deg, var(--btn-top), var(--btn-bottom));
      color: var(--btn-text);
      border-radius: 10px;
      padding: 8px 12px;
      font: 700 13px/1 "IBM Plex Mono", "Fira Code", monospace;
      cursor: pointer;
      transition: border-color 120ms ease, opacity 120ms ease;
      text-decoration: none;
    }

    .btn:hover { border-color: var(--btn-hover-border); }
    .btn:disabled { opacity: 0.5; cursor: wait; }
    .btn.small { min-height: 28px; padding: 6px 8px; font-size: 11px; }
    .btn.ghost {
      background: transparent;
      color: var(--text);
    }
    .btn.warn {
      border-color: var(--btn-warn-border);
      background: linear-gradient(180deg, var(--btn-warn-top), var(--btn-warn-bottom));
    }
    .btn.danger {
      border-color: var(--btn-danger-border);
      background: linear-gradient(180deg, var(--btn-danger-top), var(--btn-danger-bottom));
    }

    .stamp {
      font: 500 12px/1 "IBM Plex Mono", "Fira Code", monospace;
      color: var(--muted);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .stats {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      margin-bottom: 14px;
    }

    .stat {
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 14px;
      padding: 12px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(8px);
    }

    .stat .k {
      margin: 0;
      color: var(--muted);
      font: 600 11px/1.3 "IBM Plex Mono", "Fira Code", monospace;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }

    .stat .v {
      margin: 8px 0 0;
      font: 700 clamp(24px, 3vw, 34px)/1 "IBM Plex Sans", "Avenir Next", sans-serif;
      letter-spacing: -0.03em;
    }

    .grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(12, minmax(0, 1fr));
    }

    .panel {
      grid-column: span 12;
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 14px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .panel.wide { grid-column: span 8; }
    .panel.tall { grid-column: span 4; }

    .panel-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-head-bg);
    }

    .panel h2 {
      margin: 0;
      font-size: 15px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      font-family: "IBM Plex Mono", "Fira Code", monospace;
      color: var(--text-strong);
    }

    .meta {
      color: var(--muted);
      font-size: 12px;
      font-family: "IBM Plex Mono", "Fira Code", monospace;
      text-transform: uppercase;
    }

    .table-wrap {
      overflow-x: auto;
      max-height: 320px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      min-width: 620px;
    }

    th, td {
      text-align: left;
      padding: 9px 12px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }

    th {
      color: var(--muted);
      font: 600 11px/1.2 "IBM Plex Mono", "Fira Code", monospace;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      position: sticky;
      top: 0;
      background: var(--th-bg);
      z-index: 1;
    }

    .mono {
      font-family: "IBM Plex Mono", "Fira Code", monospace;
      font-size: 12px;
      color: var(--mono);
    }

    .status {
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 8px;
      font: 700 11px/1 "IBM Plex Mono", "Fira Code", monospace;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      background: var(--chip-bg);
      color: var(--chip-text);
      white-space: nowrap;
    }

    .status.active,
    .status.succeeded,
    .status.approved { border-color: var(--chip-active-border); color: var(--chip-text); background: var(--chip-active-bg); }
    .status.running,
    .status.pending { border-color: var(--chip-running-border); color: var(--chip-text); background: var(--chip-running-bg); }
    .status.paused,
    .status.failed { border-color: var(--chip-bad-border); color: var(--chip-bad-text); background: var(--chip-bad-bg); }

    .plugin-list {
      display: grid;
      gap: 10px;
      padding: 10px 12px 12px;
      max-height: 320px;
      overflow-y: auto;
    }

    .plugin {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      background: var(--plugin-bg);
    }

    .plugin-head {
      display: flex;
      gap: 8px;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .plugin-name {
      margin: 0;
      font-weight: 700;
      font-size: 14px;
      letter-spacing: 0.01em;
    }

    .plugin-note {
      margin: 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.4;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
    }

    .form {
      padding: 12px;
      display: grid;
      gap: 10px;
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    .form label {
      display: grid;
      gap: 6px;
      font-size: 12px;
      color: var(--muted);
      font-family: "IBM Plex Mono", "Fira Code", monospace;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .field {
      display: grid;
      gap: 6px;
    }

    .field-label {
      font-size: 12px;
      color: var(--muted);
      font-family: "IBM Plex Mono", "Fira Code", monospace;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .hint {
      margin: 0;
      color: var(--muted);
      font: 500 12px/1.45 "IBM Plex Mono", "Fira Code", monospace;
    }

    .form input,
    .form select,
    .form textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--field-bg);
      color: var(--text);
      font: 500 13px/1.4 "IBM Plex Sans", "Avenir Next", sans-serif;
      padding: 8px 10px;
    }

    .form textarea {
      min-height: 92px;
      resize: vertical;
    }

    .assistant-log {
      border-top: 1px solid var(--line);
      padding: 10px 12px 12px;
      display: grid;
      gap: 8px;
      max-height: 320px;
      overflow-y: auto;
      background: var(--assistant-log-bg);
    }

    .assistant-msg {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px 10px;
      background: var(--assistant-msg-bg);
    }

    .assistant-msg.user {
      border-color: var(--assistant-user-border);
      background: var(--assistant-user-bg);
      color: var(--assistant-user-text);
    }

    .assistant-msg.user .assistant-head,
    .assistant-msg.user .assistant-body {
      color: var(--assistant-user-text);
    }

    .assistant-msg.error {
      border-color: var(--assistant-error-border);
      background: var(--assistant-error-bg);
    }

    .assistant-head {
      margin: 0 0 6px;
      color: var(--muted);
      font: 700 11px/1 "IBM Plex Mono", "Fira Code", monospace;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .assistant-body {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font: 500 13px/1.45 "IBM Plex Mono", "Fira Code", monospace;
      color: var(--text-strong);
    }

    .empty {
      padding: 16px 12px;
      color: var(--muted);
      font-family: "IBM Plex Mono", "Fira Code", monospace;
      font-size: 12px;
    }

    @media (max-width: 1180px) {
      .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .panel.wide, .panel.tall { grid-column: span 12; }
    }

    @media (max-width: 700px) {
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .app { padding: 14px 10px 28px; }
      .panel-head { padding: 10px 10px; }
      th, td { padding: 8px 8px; }
      table { min-width: 520px; }
      .form-grid { grid-template-columns: 1fr; }
      .controls { width: 100%; }
      .controls .btn { flex: 1; }
    }
  </style>
</head>
<body>
  <main class="app">
    <header class="topbar">
      <div>
        <p class="eyebrow">maid</p>
        <h1>Control Dashboard</h1>
      </div>
      <div class="controls">
        <span id="refresh_status" class="pill">syncing</span>
        <button id="refresh_btn" class="btn" type="button">Refresh</button>
        <a href="#task_builder" class="btn ghost" role="button">New Task</a>
        <a href="#assistant_panel" class="btn ghost" role="button">Ask Assistant</a>
        <span id="last_refresh" class="stamp">never</span>
      </div>
    </header>
    <p class="quickstart">Start here: build or edit tasks in <strong>Task Builder</strong>, verify status in <strong>Scheduled Tasks</strong>, and use <strong>Assistant</strong> for quick command-driven actions.</p>

    <section class="stats">
      <article class="stat"><p class="k">Groups</p><p class="v" id="metric_groups">-</p></article>
      <article class="stat"><p class="k">Tasks Total</p><p class="v" id="metric_tasks_total">-</p></article>
      <article class="stat"><p class="k">Tasks Active</p><p class="v" id="metric_tasks_active">-</p></article>
      <article class="stat"><p class="k">Tasks Paused</p><p class="v" id="metric_tasks_paused">-</p></article>
      <article class="stat"><p class="k">Pending Pairings</p><p class="v" id="metric_pairings">-</p></article>
      <article class="stat"><p class="k">Enabled Plugins</p><p class="v" id="metric_plugins">-</p></article>
    </section>

    <section class="grid">
      <article class="panel" id="assistant_panel">
        <div class="panel-head">
          <h2>Assistant</h2>
          <span id="assistant_meta" class="meta">Natural text, /help, or /tool calls</span>
        </div>
        <form id="assistant_form" class="form">
          <div class="form-grid">
            <label>
              Group
              <select id="assistant_group"></select>
            </label>
            <div class="field">
              <span class="field-label">Run Assistant</span>
              <button id="assistant_send" class="btn" type="submit">Send Request</button>
            </div>
          </div>
          <label>
            Prompt
            <textarea id="assistant_input" placeholder="Example: /task.list --group main"></textarea>
          </label>
          <p class="hint">Tip: Press Cmd/Ctrl + Enter to run the prompt.</p>
          <div class="actions">
            <button id="assistant_clear" class="btn" type="button">Clear output</button>
          </div>
        </form>
        <section id="assistant_history" class="assistant-log">
          <div class="empty">No assistant output yet.</div>
        </section>
      </article>

      <article class="panel wide" id="tasks_panel">
        <div class="panel-head">
          <h2>Scheduled Tasks</h2>
          <span id="tasks_meta" class="meta">loading tasks</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Group</th>
                <th>Name</th>
                <th>Status</th>
                <th>Schedule</th>
                <th>ID</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="tasks_tbody"></tbody>
          </table>
        </div>
      </article>

      <article class="panel tall" id="task_builder">
        <div class="panel-head">
          <h2>Task Builder</h2>
          <span id="task_form_mode" class="meta">create</span>
        </div>
        <form id="task_form" class="form">
          <div class="form-grid">
            <label>
              Group
              <select id="task_group" required></select>
            </label>
            <label>
              Status
              <select id="task_status" required>
                <option value="ACTIVE">ACTIVE</option>
                <option value="PAUSED">PAUSED</option>
              </select>
            </label>
          </div>
          <label>
            Name
            <input id="task_name" maxlength="120" required />
          </label>
          <label>
            Schedule
            <input id="task_schedule" placeholder="FREQ=HOURLY;INTERVAL=1" required />
          </label>
          <label>
            Prompt
            <textarea id="task_prompt" required></textarea>
          </label>
          <div class="actions">
            <button id="task_submit" class="btn" type="submit">Create task</button>
            <button id="task_cancel" class="btn" type="button" hidden>Cancel edit</button>
          </div>
        </form>
      </article>

      <article class="panel tall">
        <div class="panel-head">
          <h2>Plugins</h2>
          <span id="plugins_meta" class="meta">loading</span>
        </div>
        <div id="plugins_list" class="plugin-list"></div>
      </article>

      <article class="panel wide">
        <div class="panel-head">
          <h2>Recent Runs</h2>
          <span id="runs_meta" class="meta">latest 20</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Status</th>
                <th>Task ID</th>
                <th>Summary / Error</th>
              </tr>
            </thead>
            <tbody id="runs_tbody"></tbody>
          </table>
        </div>
      </article>

      <article class="panel tall">
        <div class="panel-head">
          <h2>Pending Pairings</h2>
          <span id="pairings_meta" class="meta">loading</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Code</th>
                <th>Chat</th>
                <th>Requested</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="pairings_tbody"></tbody>
          </table>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <h2>Recent Audits</h2>
          <span id="audits_meta" class="meta">latest 20</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Created</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Result</th>
                <th>Group</th>
              </tr>
            </thead>
            <tbody id="audits_tbody"></tbody>
          </table>
        </div>
      </article>
    </section>
  </main>
  <script>
    const REFRESH_MS = 8000;
    const inflight = new Map();
    const htmlCache = new Map();
    const dashboardState = {
      plugins: [],
      pendingPairings: [],
      tasks: [],
      groups: [],
      editingTaskId: null,
      assistantMessages: [],
      assistantBusy: false,
    };

    const el = (id) => document.getElementById(id);
    const encodeParams = (pairs) => {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(pairs)) {
        if (value != null) {
          params.set(key, String(value));
        }
      }
      return params.toString();
    };
    const escapeHtml = (value) => String(value == null ? "" : value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll("\"", "&quot;")
      .replaceAll("'", "&#39;");
    const toDate = (value) => {
      if (!value) return "-";
      const d = new Date(value);
      if (Number.isNaN(d.getTime())) return String(value);
      return d.toLocaleString();
    };
    const trim = (value, max = 120) => {
      const text = value == null ? "" : String(value);
      return text.length > max ? `${text.slice(0, max - 1)}...` : text;
    };
    const normalizeTaskStatus = (value) => {
      const raw = String(value || "").toUpperCase();
      return raw.includes("PAUS") ? "PAUSED" : "ACTIVE";
    };
    const statusClass = (value) => String(value || "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
    const statusBadge = (value) => `<span class="status ${statusClass(value)}">${escapeHtml(String(value || "UNKNOWN"))}</span>`;
    const setNodeHtml = (id, html) => {
      if (htmlCache.get(id) === html) return;
      el(id).innerHTML = html;
      htmlCache.set(id, html);
    };

    function setRefreshState(kind, label) {
      const node = el("refresh_status");
      node.textContent = label;
      node.classList.remove("ok", "err");
      if (kind === "ok") node.classList.add("ok");
      if (kind === "err") node.classList.add("err");
    }

    function renderEmptyRow(targetId, cols, message) {
      setNodeHtml(
        targetId,
        `<tr><td class="empty" colspan="${cols}">${escapeHtml(message)}</td></tr>`,
      );
    }

    function renderGroups(groups) {
      const items = groups || [];
      dashboardState.groups = items;
      const sortedOptionsHtml = items
        .slice()
        .sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")))
        .map((group) => `<option value="${escapeHtml(group.name)}">${escapeHtml(group.name)}</option>`)
        .join("");
      const emptyOptions = `<option value="">No groups</option>`;
      ["task_group", "assistant_group"].forEach((id) => {
        const select = el(id);
        const current = select.value;
        if (!items.length) {
          if (select.innerHTML !== emptyOptions) {
            select.innerHTML = emptyOptions;
          }
          select.disabled = true;
          return;
        }
        select.disabled = false;
        const optionsHtml =
          id === "assistant_group"
            ? `<option value="">Auto (main)</option>${sortedOptionsHtml}`
            : sortedOptionsHtml;
        if (select.innerHTML !== optionsHtml) {
          select.innerHTML = optionsHtml;
        }
        if (items.some((group) => group.name === current)) {
          select.value = current;
        } else if (id === "assistant_group" && current === "") {
          select.value = "";
        } else if (items[0]?.name) {
          select.value = id === "assistant_group" ? "" : items[0].name;
        }
      });
    }

    function setTaskFormMode(task) {
      const formMode = el("task_form_mode");
      const submit = el("task_submit");
      const cancel = el("task_cancel");
      const status = el("task_status");
      if (!task) {
        dashboardState.editingTaskId = null;
        formMode.textContent = "create";
        submit.textContent = "Create task";
        cancel.hidden = true;
        status.value = "ACTIVE";
        el("task_name").value = "";
        el("task_schedule").value = "";
        el("task_prompt").value = "";
        return;
      }
      dashboardState.editingTaskId = task.id;
      formMode.textContent = "edit";
      submit.textContent = "Update task";
      cancel.hidden = false;
      el("task_group").value = task.group || "";
      el("task_name").value = task.name || "";
      el("task_schedule").value = task.schedule || "";
      el("task_prompt").value = task.prompt || "";
      status.value = normalizeTaskStatus(task.status);
      window.scrollTo({ top: 0, behavior: "smooth" });
    }

    function renderAssistantHistory() {
      const items = dashboardState.assistantMessages;
      if (!items.length) {
        setNodeHtml("assistant_history", `<div class="empty">No assistant output yet.</div>`);
        return;
      }
      const html = items.map((item) => `
        <article class="assistant-msg ${escapeHtml(item.role)}">
          <p class="assistant-head">${escapeHtml(item.label)}</p>
          <pre class="assistant-body">${escapeHtml(item.text)}</pre>
        </article>
      `).join("");
      setNodeHtml("assistant_history", html);
      const history = el("assistant_history");
      history.scrollTop = history.scrollHeight;
    }

    function appendAssistantMessage(role, text) {
      const label = role === "user" ? "You" : role === "error" ? "Error" : "maid";
      dashboardState.assistantMessages.push({
        role,
        label,
        text: String(text == null ? "" : text),
      });
      if (dashboardState.assistantMessages.length > 40) {
        dashboardState.assistantMessages = dashboardState.assistantMessages.slice(-40);
      }
      renderAssistantHistory();
    }

    function renderMetrics(overview, plugins) {
      el("metric_groups").textContent = overview.groups_total ?? "-";
      el("metric_tasks_total").textContent = overview.tasks_total ?? "-";
      el("metric_tasks_active").textContent = overview.tasks_active ?? "-";
      el("metric_tasks_paused").textContent = overview.tasks_paused ?? "-";
      el("metric_pairings").textContent = (overview.pending_pairings || []).length;

      const totalPlugins = plugins.length;
      const enabledPlugins = plugins.filter((p) => p.enabled).length;
      el("metric_plugins").textContent = `${enabledPlugins}/${totalPlugins}`;
    }

    function renderTasks(tasks) {
      const normalized = (tasks || []).map((item) => {
        if (item && item.task) {
          return {
            group: item.group || "-",
            id: item.task.id,
            name: item.task.name,
            status: normalizeTaskStatus(item.task.status),
            schedule: item.task.schedule_rrule || item.task.schedule || "-",
            prompt: item.task.prompt_template || "",
          };
        }
        return {
          group: item?.group || "-",
          id: item?.id || "-",
          name: item?.name || "-",
          status: normalizeTaskStatus(item?.status || "-"),
          schedule: item?.schedule_rrule || item?.schedule || "-",
          prompt: item?.prompt_template || item?.prompt || "",
        };
      });
      normalized.sort((a, b) => `${a.group}/${a.name}`.localeCompare(`${b.group}/${b.name}`));
      dashboardState.tasks = normalized;
      el("tasks_meta").textContent = `${normalized.length} total`;
      if (!normalized.length) {
        renderEmptyRow("tasks_tbody", 6, "No tasks found.");
        return;
      }
      const rows = normalized.slice(0, 200).map((task, idx) => `
        <tr>
          <td>${escapeHtml(task.group)}</td>
          <td>${escapeHtml(task.name)}</td>
          <td>${statusBadge(task.status)}</td>
          <td class="mono">${escapeHtml(task.schedule || "-")}</td>
          <td class="mono">${escapeHtml(trim(task.id, 22))}</td>
          <td>
            <div class="actions">
              <button class="btn small task-edit" data-index="${idx}" type="button">Edit</button>
              <button class="btn small warn task-toggle" data-index="${idx}" type="button">${task.status === "ACTIVE" ? "Pause" : "Resume"}</button>
              <button class="btn small task-run" data-index="${idx}" type="button">Run now</button>
              <button class="btn small danger task-delete" data-index="${idx}" type="button">Delete</button>
            </div>
          </td>
        </tr>
      `).join("");
      setNodeHtml("tasks_tbody", rows);
    }

    function renderRuns(runs) {
      const items = runs || [];
      el("runs_meta").textContent = `latest ${items.length}`;
      if (!items.length) {
        renderEmptyRow("runs_tbody", 4, "No task runs recorded.");
        return;
      }
      const rows = items.map((run) => {
        const summary = trim(run.output_summary || run.error_text || "-", 180);
        return `
          <tr>
            <td class="mono">${escapeHtml(toDate(run.started_at))}</td>
            <td>${statusBadge(run.status)}</td>
            <td class="mono">${escapeHtml(trim(run.task_id, 22))}</td>
            <td>${escapeHtml(summary)}</td>
          </tr>
        `;
      }).join("");
      setNodeHtml("runs_tbody", rows);
    }

    function renderAudits(audits) {
      const items = audits || [];
      el("audits_meta").textContent = `latest ${items.length}`;
      if (!items.length) {
        renderEmptyRow("audits_tbody", 5, "No audits found.");
        return;
      }
      const rows = items.map((audit) => `
        <tr>
          <td class="mono">${escapeHtml(toDate(audit.created_at))}</td>
          <td>${escapeHtml(audit.action || "-")}</td>
          <td>${escapeHtml(audit.actor || "-")}</td>
          <td>${escapeHtml(audit.result || "-")}</td>
          <td class="mono">${escapeHtml(audit.group_id || "-")}</td>
        </tr>
      `).join("");
      setNodeHtml("audits_tbody", rows);
    }

    function renderPairings(pairings) {
      const items = (pairings || []).filter((p) => statusClass(p.status) === "pending");
      dashboardState.pendingPairings = items;
      el("pairings_meta").textContent = `${items.length} pending`;
      if (!items.length) {
        renderEmptyRow("pairings_tbody", 4, "No pending pairings.");
        return;
      }
      const rows = items.map((pairing, idx) => `
        <tr>
          <td class="mono">${escapeHtml(pairing.code)}</td>
          <td class="mono">${escapeHtml(pairing.chat_id)}</td>
          <td class="mono">${escapeHtml(toDate(pairing.requested_at))}</td>
          <td><button class="btn approve-pairing" data-index="${idx}" type="button">Approve</button></td>
        </tr>
      `).join("");
      setNodeHtml("pairings_tbody", rows);
    }

    function renderPlugins(plugins) {
      const items = plugins || [];
      dashboardState.plugins = items;
      const enabled = items.filter((p) => p.enabled).length;
      el("plugins_meta").textContent = `${enabled}/${items.length} enabled`;
      if (!items.length) {
        setNodeHtml("plugins_list", `<div class="empty">No plugins found.</div>`);
        return;
      }
      const pluginHtml = items.map((plugin, idx) => {
        const action = plugin.enabled ? "disable" : "enable";
        const label = plugin.enabled ? "Disable" : "Enable";
        return `
          <section class="plugin">
            <div class="plugin-head">
              <p class="plugin-name">${escapeHtml(plugin.name)}</p>
              ${statusBadge(plugin.enabled ? "ACTIVE" : "PAUSED")}
            </div>
            <p class="plugin-note mono">v${escapeHtml(plugin.version || "-")}</p>
            <p class="plugin-note">${escapeHtml(trim(plugin.description || "No description.", 240))}</p>
            <div style="margin-top:8px">
              <button class="btn plugin-toggle" data-index="${idx}" data-action="${action}" type="button">${label}</button>
            </div>
          </section>
        `;
      }).join("");
      setNodeHtml("plugins_list", pluginHtml);
    }

    async function fetchJson(url, options = {}) {
      const response = await fetch(url, options);
      if (!response.ok) {
        const text = await response.text();
        throw new Error(`${response.status} ${response.statusText}: ${trim(text, 120)}`);
      }
      return response.json();
    }

    async function refreshDashboard(options = {}) {
      const silent = !!options.silent;
      if (inflight.get("refresh")) return;
      inflight.set("refresh", true);
      if (!silent) {
        setRefreshState("busy", "syncing");
        el("refresh_btn").disabled = true;
      }
      try {
        const [overview, plugins, tasks, groups] = await Promise.all([
          fetchJson("/api/overview"),
          fetchJson("/api/plugins"),
          fetchJson("/api/tasks"),
          fetchJson("/api/groups"),
        ]);
        renderGroups(groups);
        renderMetrics(overview, plugins);
        renderTasks(tasks);
        renderRuns(overview.recent_runs);
        renderAudits(overview.recent_audits);
        renderPairings(overview.pending_pairings);
        renderPlugins(plugins);
        setRefreshState("ok", "live");
        el("last_refresh").textContent = `updated ${new Date().toLocaleTimeString()}`;
      } catch (error) {
        setRefreshState("err", "error");
        el("last_refresh").textContent = trim(error && error.message ? error.message : String(error), 96);
      } finally {
        inflight.delete("refresh");
        if (!silent) {
          el("refresh_btn").disabled = false;
        }
      }
    }

    async function togglePlugin(name, action, button) {
      if (!name || !action) return;
      button.disabled = true;
      try {
        await fetchJson(`/api/plugins/${action}?name=${encodeURIComponent(name)}`, { method: "POST" });
        await refreshDashboard();
      } catch (error) {
        setRefreshState("err", trim(`plugin ${action} failed`, 24));
        el("last_refresh").textContent = trim(error && error.message ? error.message : String(error), 96);
      } finally {
        button.disabled = false;
      }
    }

    async function approvePairing(code, button) {
      if (!code) return;
      button.disabled = true;
      try {
        await fetchJson(`/api/pairings/approve?code=${encodeURIComponent(code)}`, { method: "POST" });
        await refreshDashboard();
      } catch (error) {
        setRefreshState("err", "pairing error");
        el("last_refresh").textContent = trim(error && error.message ? error.message : String(error), 96);
      } finally {
        button.disabled = false;
      }
    }

    async function deleteTask(task, button) {
      if (!task || !task.id) return;
      if (!window.confirm(`Delete task "${task.name}"?`)) return;
      button.disabled = true;
      try {
        await fetchJson(`/api/tasks/delete?id=${encodeURIComponent(task.id)}`, { method: "POST" });
        await refreshDashboard();
      } catch (error) {
        setRefreshState("err", "delete error");
        el("last_refresh").textContent = trim(error && error.message ? error.message : String(error), 96);
      } finally {
        button.disabled = false;
      }
    }

    async function pauseResumeTask(task, button) {
      if (!task || !task.id) return;
      const action = normalizeTaskStatus(task.status) === "ACTIVE" ? "pause" : "resume";
      button.disabled = true;
      try {
        await fetchJson(`/api/tasks/${action}?id=${encodeURIComponent(task.id)}`, { method: "POST" });
        await refreshDashboard();
      } catch (error) {
        setRefreshState("err", "task update error");
        el("last_refresh").textContent = trim(error && error.message ? error.message : String(error), 96);
      } finally {
        button.disabled = false;
      }
    }

    async function runTaskNow(task, button) {
      if (!task || !task.id) return;
      button.disabled = true;
      try {
        const result = await fetchJson(`/api/tasks/run-now?id=${encodeURIComponent(task.id)}`, { method: "POST" });
        const runStatus = result?.run?.status || "UNKNOWN";
        el("last_refresh").textContent = `task ${task.name}: ${runStatus}`;
        await refreshDashboard();
      } catch (error) {
        setRefreshState("err", "task run error");
        el("last_refresh").textContent = trim(error && error.message ? error.message : String(error), 96);
      } finally {
        button.disabled = false;
      }
    }

    async function submitTaskForm(event) {
      event.preventDefault();
      const group = el("task_group").value.trim();
      const name = el("task_name").value.trim();
      const schedule = el("task_schedule").value.trim();
      const prompt = el("task_prompt").value.trim();
      const status = normalizeTaskStatus(el("task_status").value);
      if (!group || !name || !schedule || !prompt) {
        setRefreshState("err", "missing fields");
        el("last_refresh").textContent = "Task form requires group, name, schedule, and prompt.";
        return;
      }
      const submit = el("task_submit");
      submit.disabled = true;
      try {
        if (dashboardState.editingTaskId) {
          const query = encodeParams({
            id: dashboardState.editingTaskId,
            name,
            schedule,
            prompt,
            status,
          });
          await fetchJson(`/api/tasks/update?${query}`, { method: "POST" });
        } else {
          const query = encodeParams({ group, name, schedule, prompt });
          const created = await fetchJson(`/api/tasks/create?${query}`, { method: "POST" });
          if (status === "PAUSED" && created?.task?.id) {
            await fetchJson(`/api/tasks/pause?id=${encodeURIComponent(created.task.id)}`, { method: "POST" });
          }
        }
        setTaskFormMode(null);
        await refreshDashboard();
      } catch (error) {
        setRefreshState("err", "task save error");
        el("last_refresh").textContent = trim(error && error.message ? error.message : String(error), 96);
      } finally {
        submit.disabled = false;
      }
    }

    async function submitAssistantForm(event) {
      event.preventDefault();
      if (dashboardState.assistantBusy) return;
      const group = el("assistant_group").value.trim() || "main";
      const input = el("assistant_input").value.trim();
      if (!group || !input) {
        setRefreshState("err", "missing fields");
        el("last_refresh").textContent = "Assistant requires group and input.";
        return;
      }

      dashboardState.assistantBusy = true;
      const send = el("assistant_send");
      send.disabled = true;
      appendAssistantMessage("user", input);
      el("assistant_input").value = "";

      try {
        const query = encodeParams({ group, input });
        const payload = await fetchJson(`/api/assistant/execute?${query}`, { method: "POST" });
        if (payload.mode === "chat") {
          appendAssistantMessage("assistant", payload.output || "");
        } else if (payload.mode === "help") {
          appendAssistantMessage("assistant", payload.help || "");
        } else {
          const commandText = payload.tool
            ? `${payload.tool}\n${JSON.stringify(payload.result, null, 2)}`
            : JSON.stringify(payload, null, 2);
          appendAssistantMessage("assistant", commandText);
        }
        setRefreshState("ok", "live");
        el("last_refresh").textContent = `assistant ${new Date().toLocaleTimeString()}`;
        await refreshDashboard({ silent: true });
      } catch (error) {
        const message = trim(error && error.message ? error.message : String(error), 240);
        appendAssistantMessage("error", message);
        setRefreshState("err", "assistant error");
        el("last_refresh").textContent = message;
      } finally {
        dashboardState.assistantBusy = false;
        send.disabled = false;
      }
    }

    document.addEventListener("click", (event) => {
      const editButton = event.target.closest(".task-edit");
      if (editButton) {
        const index = Number.parseInt(editButton.dataset.index || "-1", 10);
        const task = Number.isNaN(index) ? null : dashboardState.tasks[index];
        if (task) {
          setTaskFormMode(task);
        }
        return;
      }
      const toggleButton = event.target.closest(".task-toggle");
      if (toggleButton) {
        const index = Number.parseInt(toggleButton.dataset.index || "-1", 10);
        const task = Number.isNaN(index) ? null : dashboardState.tasks[index];
        if (task) {
          pauseResumeTask(task, toggleButton);
        }
        return;
      }
      const runButton = event.target.closest(".task-run");
      if (runButton) {
        const index = Number.parseInt(runButton.dataset.index || "-1", 10);
        const task = Number.isNaN(index) ? null : dashboardState.tasks[index];
        if (task) {
          runTaskNow(task, runButton);
        }
        return;
      }
      const deleteButton = event.target.closest(".task-delete");
      if (deleteButton) {
        const index = Number.parseInt(deleteButton.dataset.index || "-1", 10);
        const task = Number.isNaN(index) ? null : dashboardState.tasks[index];
        if (task) {
          deleteTask(task, deleteButton);
        }
        return;
      }
      const pluginButton = event.target.closest(".plugin-toggle");
      if (pluginButton) {
        const index = Number.parseInt(pluginButton.dataset.index || "-1", 10);
        const plugin = Number.isNaN(index) ? null : dashboardState.plugins[index];
        if (plugin) {
          togglePlugin(plugin.name, pluginButton.dataset.action, pluginButton);
        }
        return;
      }
      const pairingButton = event.target.closest(".approve-pairing");
      if (pairingButton) {
        const index = Number.parseInt(pairingButton.dataset.index || "-1", 10);
        const pairing = Number.isNaN(index) ? null : dashboardState.pendingPairings[index];
        if (pairing) {
          approvePairing(pairing.code, pairingButton);
        }
      }
    });

    el("assistant_form").addEventListener("submit", submitAssistantForm);
    el("assistant_clear").addEventListener("click", () => {
      dashboardState.assistantMessages = [];
      renderAssistantHistory();
    });
    el("assistant_input").addEventListener("keydown", (event) => {
      if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        el("assistant_form").requestSubmit();
      }
    });
    el("task_form").addEventListener("submit", submitTaskForm);
    el("task_cancel").addEventListener("click", () => setTaskFormMode(null));
    el("refresh_btn").addEventListener("click", () => {
      refreshDashboard();
    });

    setTaskFormMode(null);
    renderAssistantHistory();
    refreshDashboard();
    setInterval(() => refreshDashboard({ silent: true }), REFRESH_MS);
  </script>
</body>
</html>
"##
    .to_string()
}

fn dashboard_tailwind_css() -> &'static str {
    include_str!("../assets/tailwind.css")
}

async fn handle_gateway_client(
    stream: TcpStream,
    status: GatewayStatus,
    events: GatewayEvents,
    service: Arc<AppService>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).await? == 0 {
        return Ok(());
    }
    let first_trimmed = first_line.trim_end_matches(['\r', '\n']).trim();
    if first_trimmed.is_empty() {
        return Ok(());
    }

    if first_trimmed.contains("HTTP/") {
        return handle_gateway_http_request(
            first_trimmed,
            &mut reader,
            &mut write_half,
            &status,
            &events,
            service,
        )
        .await;
    }

    handle_gateway_command_line(first_trimmed, &status, &events, &mut write_half).await?;

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
        handle_gateway_command_line(trimmed, &status, &events, &mut write_half).await?;
    }
}

async fn handle_gateway_command_line(
    raw: &str,
    status: &GatewayStatus,
    events: &GatewayEvents,
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    let cmd = parse_gateway_command(raw)?;
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
                        let warning =
                            json!({"type":"gateway.warning","message":"lagged","skipped":skipped});
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
    Ok(())
}

async fn read_http_headers(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<BTreeMap<String, String>> {
    let mut headers = BTreeMap::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok(headers)
}

async fn handle_gateway_http_request(
    request_line: &str,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    status: &GatewayStatus,
    events: &GatewayEvents,
    service: Arc<AppService>,
) -> Result<()> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let headers = read_http_headers(reader).await?;
    let content_length = headers
        .get("content-length")
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > 1_048_576 {
        write_http_response(
            write_half,
            "413 Payload Too Large",
            "application/json",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "payload_too_large",
                "max_bytes": 1_048_576,
            }))?,
        )
        .await?;
        return Ok(());
    }
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }

    let (path, query) = parse_http_target(target)?;
    match (method, path.as_str()) {
        ("GET", "/health") => {
            write_http_response(
                write_half,
                "200 OK",
                "application/json",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "status": status,
                }))?,
            )
            .await?;
        }
        ("POST", _) if path.starts_with("/webhook/") => {
            let hook_path = path
                .trim_start_matches("/webhook/")
                .trim_matches('/')
                .to_string();
            if hook_path.is_empty() {
                write_http_response(
                    write_half,
                    "404 Not Found",
                    "application/json",
                    "{\"ok\":false,\"error\":\"not_found\"}".to_string(),
                )
                .await?;
                return Ok(());
            }

            let Some(route) = service.store.get_webhook_route_by_path(&hook_path).await? else {
                write_http_response(
                    write_half,
                    "404 Not Found",
                    "application/json",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": "route_not_found",
                        "path": hook_path,
                    }))?,
                )
                .await?;
                return Ok(());
            };

            if let Some(expected) = route.token.as_deref().filter(|v| !v.trim().is_empty()) {
                let provided = query
                    .get("token")
                    .map(String::as_str)
                    .or_else(|| headers.get("x-maid-webhook-token").map(String::as_str))
                    .unwrap_or("");
                if provided != expected {
                    write_http_response(
                        write_half,
                        "401 Unauthorized",
                        "application/json",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": "invalid_token",
                            "path": hook_path,
                        }))?,
                    )
                    .await?;
                    return Ok(());
                }
            }

            let now = Utc::now();
            service
                .store
                .mark_webhook_route_triggered(&route.id, now)
                .await?;

            let body_text = String::from_utf8_lossy(&body).to_string();
            let group = service
                .store
                .get_group_by_id(&route.group_id)
                .await?
                .ok_or_else(|| anyhow!("group not found for webhook route {}", route.id))?;

            let actor = format!("webhook:{}", route.path);
            let mut triggered = Vec::new();
            let mut failures = 0_u64;

            if let Some(task_id) = route.task_id.clone() {
                match service.run_task_now(&task_id, &actor).await {
                    Ok(run) => triggered.push(json!({
                        "type": "task",
                        "task_id": task_id,
                        "run_id": run.run_id,
                        "status": run.status.as_str(),
                    })),
                    Err(err) => {
                        failures += 1;
                        triggered.push(json!({
                            "type": "task",
                            "task_id": task_id,
                            "status": "FAILED",
                            "error": format!("{err:#}"),
                        }));
                    }
                }
            }
            if let Some(template) = route.prompt_template.clone() {
                let prompt = template
                    .replace("{{body}}", &body_text)
                    .replace("{{path}}", &route.path)
                    .replace("{{group}}", &group.name)
                    .replace("{{timestamp}}", &now.to_rfc3339());
                match service.run_prompt(&group.name, &prompt, &actor).await {
                    Ok(output) => triggered.push(json!({
                        "type": "prompt",
                        "group": group.name,
                        "status": "SUCCEEDED",
                        "output_preview": truncate_line(&output, 400),
                    })),
                    Err(err) => {
                        failures += 1;
                        triggered.push(json!({
                            "type": "prompt",
                            "group": group.name,
                            "status": "FAILED",
                            "error": format!("{err:#}"),
                        }));
                    }
                }
            }

            let result = if failures == 0 { "SUCCESS" } else { "FAILED" };
            let _ = service
                .store
                .insert_audit(NewAudit {
                    group_id: Some(group.id.clone()),
                    action: "WEBHOOK_TRIGGER".to_string(),
                    actor: actor.clone(),
                    result: result.to_string(),
                    created_at: now,
                    metadata_json: Some(json!({
                        "route_id": route.id,
                        "path": route.path,
                        "body_bytes": body.len(),
                        "triggered": triggered,
                    })),
                })
                .await;

            events.publish(json!({
                "type": "webhook.triggered",
                "path": route.path,
                "group": group.name,
                "result": result,
            }));

            write_http_response(
                write_half,
                if failures == 0 {
                    "200 OK"
                } else {
                    "500 Internal Server Error"
                },
                "application/json",
                serde_json::to_string_pretty(&json!({
                    "ok": failures == 0,
                    "route": {
                        "id": route.id,
                        "name": route.name,
                        "path": route.path,
                    },
                    "group": group.name,
                    "triggered": triggered,
                    "body_bytes": body.len(),
                }))?,
            )
            .await?;
        }
        _ => {
            write_http_response(
                write_half,
                "404 Not Found",
                "application/json",
                "{\"ok\":false,\"error\":\"not_found\"}".to_string(),
            )
            .await?;
        }
    }
    Ok(())
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

pub(crate) fn run_guide() {
    println!("maid command guide");
    println!();
    println!("Chat + Groups:");
    println!("  maid run --group <name> --prompt \"...\"");
    println!("  maid group create <name>");
    println!("  maid group list");
    println!();
    println!("Automation:");
    println!("  maid task wizard");
    println!(
        "  maid task create --group <name> --name <task> --schedule \"FREQ=...\" --prompt \"...\""
    );
    println!(
        "  maid task cron-add --group <name> --name <task> --every-minutes 15 --prompt \"...\""
    );
    println!("  maid task cron-list --group <name>");
    println!("  maid task cron-remove --id <task_id>");
    println!("  maid task list --group <name>");
    println!("  maid task run-now --id <task_id>");
    println!("  maid daemon");
    println!();
    println!("Operations:");
    println!("  maid status");
    println!("  maid onboard --interactive");
    println!("  maid doctor");
    println!("  maid dashboard --port 18790");
    println!();
    println!("Extensions:");
    println!("  maid plugin list");
    println!("  maid plugin registry list");
    println!("  maid plugin registry install --name <plugin>");
    println!("  maid plugin run --name <plugin> --command help");
    println!();
    println!("Naming:");
    println!("  - Skills: auto context providers before model calls");
    println!("  - Plugins: executable packages (local or registry) with optional tool bridge");
}

pub(crate) async fn run_onboard(
    cfg: &AppConfig,
    config_path: &Path,
    interactive: bool,
    service: Option<Arc<AppService>>,
) -> Result<()> {
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
    println!("1) set credentials in .env (preferred) or export them in your shell");
    println!(
        "   model key env: {}",
        model_envs
            .first()
            .cloned()
            .unwrap_or_else(|| "OPENAI_API_KEY".to_string())
    );
    if let Some(telegram) = &cfg.telegram {
        println!("   telegram key env: {}", telegram.bot_token_env);
    } else {
        println!("   telegram: optional, configure [telegram] in config.toml");
    }
    println!("2) cargo run -p maid -- doctor");
    println!("3) cargo run -p maid -- gateway --port 18789");
    println!("4) cargo run -p maid -- group create work");
    println!("5) cargo run -p maid -- task wizard");
    println!("6) cargo run -p maid -- dashboard --port 18790");

    if interactive {
        if !io::stdin().is_terminal() {
            println!("interactive mode skipped: stdin is not a terminal");
            return Ok(());
        }
        println!();
        println!("interactive setup");
        let group_name = prompt_with_default("Create/select first group", "work")?;
        if let Some(service) = &service {
            service.ensure_group(&group_name, "onboard").await?;
            println!("group ready: {}", group_name);

            let should_create_task = prompt_with_default("Create first task now? (y/n)", "y")?;
            if should_create_task.trim().eq_ignore_ascii_case("y") {
                let task_name = prompt_with_default("Task name", "morning-brief")?;
                let schedule_input = prompt_with_default("Schedule", "every weekday at 9am")?;
                let schedule = schedule_from_human_or_rrule(&schedule_input)
                    .with_context(|| format!("invalid schedule: {}", schedule_input))?;
                let task_prompt =
                    prompt_with_default("Task prompt", "Give me a concise morning brief.")?;
                let task = service
                    .create_task(&group_name, &task_name, &schedule, &task_prompt, "onboard")
                    .await?;
                println!("created task '{}' ({})", task.name, task.id);
                println!("schedule: {}", schedule);
            }
        }
    }
    Ok(())
}

pub(crate) async fn run_doctor(cfg: &AppConfig, config_path: &Path, json: bool) -> Result<()> {
    let mut failed = 0_u32;
    let mut checks = Vec::new();
    let mut report = |level: &str, label: &str, detail: String| {
        checks.push(json!({
            "level": level,
            "label": label,
            "detail": detail,
        }));
        if !json {
            let tag = match level {
                "ok" => "[ok]   ",
                "warn" => "[warn] ",
                "fail" => "[fail] ",
                _ => "[info] ",
            };
            println!("{tag}{label}: {detail}");
        }
    };

    report("ok", "config", format!("loaded {}", config_path.display()));

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
        report("fail", "database", cfg.database_path.clone());
    } else {
        report("ok", "database", cfg.database_path.clone());
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
        report("ok", "runtime", runtime_binary.to_string());
    } else {
        report(
            "warn",
            "runtime",
            format!("{runtime_binary} not found on PATH"),
        );
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
        report("ok", "model_auth", model_provider.clone());
    } else {
        report(
            "warn",
            "model_auth",
            format!("{model_provider} credentials missing"),
        );
    }

    if let Some(telegram) = &cfg.telegram {
        let telegram_ok = std::env::var(&telegram.bot_token_env)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some();
        if telegram_ok {
            report("ok", "telegram_token", telegram.bot_token_env.clone());
        } else {
            report(
                "warn",
                "telegram_token",
                format!("{} missing", telegram.bot_token_env),
            );
        }
    } else {
        report("ok", "telegram", "disabled".to_string());
    }

    let plugin_check = validate_plugins_for_startup(cfg);
    let plugin_ok = plugin_check.is_ok();
    if !plugin_ok {
        failed += 1;
        let detail = plugin_check
            .err()
            .map(|err| truncate_line(&format!("{} ({err:#})", cfg.plugin_directory()), 220))
            .unwrap_or_else(|| cfg.plugin_directory().to_string());
        report("fail", "plugins", detail);
    } else {
        report("ok", "plugins", cfg.plugin_directory().to_string());
    }
    report("ok", "skills", cfg.enabled_skills().join(", "));

    if json {
        let payload = json!({
            "ok": failed == 0,
            "failed_checks": failed,
            "checks": checks,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }

    if failed > 0 {
        return Err(anyhow!("doctor found {} failing check(s)", failed));
    }

    if !json {
        println!("doctor: all checks passed");
    }
    Ok(())
}

pub(crate) fn write_default_config(path: &Path) -> Result<()> {
    run_init_config(path, "personal", true)
}

pub(crate) fn run_init_config(path: &Path, template: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "config already exists at {} (use --force to overwrite)",
            path.display()
        ));
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config parent {}", parent.display()))?;

    let rendered = render_config_template(template)?;
    std::fs::write(path, rendered)
        .with_context(|| format!("failed to write config {}", path.display()))?;
    println!("wrote {} template to {}", template, path.display());
    println!("next: cargo run -p maid -- onboard --interactive");
    Ok(())
}

fn render_config_template(template: &str) -> Result<&'static str> {
    let lower = template.trim().to_ascii_lowercase();
    let personal = r#"database_path = "data/assistant.db"
group_root = "groups"
runtime = "apple_container"

[model]
provider = "openai"
api_key_env = "OPENAI_API_KEY"
api_key_envs = ["OPENAI_API_KEY"]
base_url = "https://api.openai.com/v1"
model = "gpt-5.2"
fallback_models = ["gpt-5-mini", "gpt-4.1-mini"]
# active_profile = "primary"
# [model.profiles.primary]
# provider = "openai"
# api_key_envs = ["OPENAI_API_KEY"]
# model = "gpt-5.2"
# fallback_models = ["gpt-5-mini", "gpt-4.1-mini"]
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
# allow_unlisted = false
# registry_enabled = true
# registry_path = "skills/registry.toml"
# max_candidates = 64
# max_invocations = 5
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
# [plugins.trust]
# require_signatures = false
# trusted_publishers = ["maid-official"]
# allow_unsigned_local = true
# quarantine_untrusted = false
# [plugins.routing]
# enabled = false
# intent_rules = [{ pattern = "(?i)convert.*spl.*kql", plugin = "siem-convert", command = "convert" }]
# pinned = [{ capability = "siem.query.convert.ai", plugin = "siem-convert" }]

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
    let work = r#"database_path = "data/assistant.db"
group_root = "groups"
runtime = "apple_container"

[model]
provider = "openai"
api_key_env = "OPENAI_API_KEY"
api_key_envs = ["OPENAI_API_KEY"]
base_url = "https://api.openai.com/v1"
model = "gpt-5.2"
fallback_models = ["gpt-5-mini", "gpt-4.1-mini"]

[scheduler]
tick_seconds = 30
max_concurrency = 4

[telegram]
bot_token_env = "TELEGRAM_BOT_TOKEN"
polling_timeout_seconds = 30
dm_policy = "pairing"
activation_mode = "mention"
mention_token = "@maid"

[skills]
enabled = ["memory.recent", "tasks.snapshot", "group.profile"]
# allow_unlisted = false
# registry_enabled = true
# registry_path = "skills/registry.toml"
# max_candidates = 64
# max_invocations = 5

[plugins]
directory = "plugins"
enabled = ["echo"]
validate_on_startup = true
# [plugins.trust]
# trusted_publishers = ["maid-official"]
# [plugins.routing]
# enabled = true
# intent_rules = [{ pattern = "(?i)convert.*spl.*kql", plugin = "siem-convert", command = "convert" }]

[tools]
auto_router_enabled = true
auto_router_allowlist = ["ops.web_fetch", "ops.search", "ops.grep", "ops.code_analysis.latest", "ops.code_analysis.list", "task.list", "group.list"]

[policy]
allow_job_tasks = false
allow_job_task_groups = []

[security]
mode = "development"
"#;
    let security = r#"database_path = "data/assistant.db"
group_root = "groups"
runtime = "apple_container"

[model]
provider = "openai"
api_key_env = "OPENAI_API_KEY"
api_key_envs = ["OPENAI_API_KEY"]
base_url = "https://api.openai.com/v1"
model = "gpt-5.2"
fallback_models = ["gpt-5-mini", "gpt-4.1-mini"]

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
enabled = ["memory.recent", "tasks.snapshot", "group.profile"]
allow_unlisted = false
registry_enabled = true
registry_path = "skills/registry.toml"
max_candidates = 64
max_invocations = 5

[plugins]
directory = "plugins"
enabled = ["echo", "code-analysis"]
validate_on_startup = true
[plugins.signing]
require_signatures = true
trusted_keys = { "maid-official" = "keys/maid-official.public.pem" }
[plugins.trust]
require_signatures = true
trusted_publishers = ["maid-official"]
allow_unsigned_local = false
quarantine_untrusted = true

[tools]
auto_router_enabled = true
auto_router_allowlist = ["ops.web_fetch", "ops.search", "ops.grep", "ops.code_analysis.latest", "ops.code_analysis.list", "task.list", "group.list"]

[policy]
allow_job_tasks = false
allow_job_task_groups = []

[security]
mode = "production"
"#;

    match lower.as_str() {
        "personal" => Ok(personal),
        "work" => Ok(work),
        "security" => Ok(security),
        _ => Err(anyhow!(
            "unknown template '{}'; expected personal, work, or security",
            template
        )),
    }
}

pub(crate) fn remediation_hint(err: &anyhow::Error) -> Option<String> {
    let text = format!("{err:#}").to_ascii_lowercase();
    if text.contains("group not found") {
        return Some("create it first: maid group create <group-name>".to_string());
    }
    if text.contains("invalid schedule rrule") || text.contains("unsupported schedule phrase") {
        return Some(
            "use `maid task wizard` or pass a valid RRULE (example: FREQ=HOURLY;INTERVAL=1)"
                .to_string(),
        );
    }
    if text.contains("missing openai api key") || text.contains("credentials missing") {
        return Some(
            "set OPENAI_API_KEY in .env (or export it) then retry (or run `maid doctor`)"
                .to_string(),
        );
    }
    if text.contains("plugin") && text.contains("disabled") {
        return Some("enable it in config or run: maid plugin enable --name <plugin>".to_string());
    }
    if text.contains("telegram") && text.contains("env") {
        return Some("set TELEGRAM_BOT_TOKEN in .env (or export it) then retry".to_string());
    }
    if text.contains("config already exists") {
        return Some("re-run with --force if you want to overwrite the file".to_string());
    }
    Some("run `maid doctor` for a full environment check".to_string())
}

pub(crate) fn telegram_chat_id_from_group_name(group_name: &str) -> Option<i64> {
    group_name
        .strip_prefix("telegram-")
        .and_then(|raw| raw.parse::<i64>().ok())
}

pub(crate) fn format_scheduled_task_message(
    task_name: &str,
    result: &TaskExecutionResult,
) -> String {
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

pub(crate) fn truncate_for_telegram(input: &str) -> String {
    const MAX_CHARS: usize = 3500;
    if input.chars().count() <= MAX_CHARS {
        return input.to_string();
    }
    let mut truncated = input.chars().take(MAX_CHARS).collect::<String>();
    truncated.push_str("\n\n[truncated]");
    truncated
}
