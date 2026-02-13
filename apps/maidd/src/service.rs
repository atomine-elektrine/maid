use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use anyhow::{anyhow, Context, Result};

use crate::cli::{ServiceCommands, TunnelCommands};
use crate::runtime::check_gateway_ping;

pub(crate) async fn handle_service_command(command: ServiceCommands) -> Result<()> {
    match command {
        ServiceCommands::Install {
            platform,
            name,
            gateway_port,
            output_dir,
        } => {
            install_service_templates(&platform, &name, gateway_port, &output_dir)?;
        }
        ServiceCommands::Status => {
            report_service_status().await?;
        }
    }
    Ok(())
}

pub(crate) async fn handle_tunnel_command(command: TunnelCommands) -> Result<()> {
    match command {
        TunnelCommands::Command {
            mode,
            gateway_port,
            ssh_host,
        } => {
            let normalized = mode.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "tailscale" => {
                    println!("tailscale tunnel commands:");
                    println!("1) tailscale serve --https=443 http://127.0.0.1:{gateway_port}");
                    println!("2) tailscale funnel 443 on   # optional public access");
                    println!("3) tailscale status");
                }
                "ssh" => {
                    let host = ssh_host.ok_or_else(|| {
                        anyhow!("--ssh-host is required when --mode ssh (example: user@host)")
                    })?;
                    println!("ssh tunnel command:");
                    println!("ssh -N -L {gateway_port}:127.0.0.1:{gateway_port} {host}");
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported tunnel mode '{}'; expected tailscale or ssh",
                        mode
                    ));
                }
            }
        }
    }
    Ok(())
}

fn install_service_templates(
    platform: &str,
    name: &str,
    gateway_port: u16,
    output_dir: &Path,
) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("service name must not be empty"));
    }

    let resolved_platform = match platform.trim().to_ascii_lowercase().as_str() {
        "auto" => {
            if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            }
        }
        "macos" | "darwin" | "launchd" => "macos",
        "linux" | "systemd" => "linux",
        other => {
            return Err(anyhow!(
                "unsupported platform '{}'; expected auto, macos, or linux",
                other
            ));
        }
    };

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let exe = std::env::current_exe().context("failed to resolve maid executable path")?;
    let config_path = std::env::var("MAID_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let runner_script = output_dir.join(format!("{name}-run.sh"));
    let health_script = output_dir.join(format!("{name}-health.sh"));

    let runner = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nexec \"{}\" --config \"{}\" gateway --port {}\n",
        exe.display(),
        config_path,
        gateway_port
    );
    std::fs::write(&runner_script, runner)
        .with_context(|| format!("failed to write {}", runner_script.display()))?;

    let health = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n\"{}\" --config \"{}\" health --gateway-port {}\n",
        exe.display(),
        config_path,
        gateway_port
    );
    std::fs::write(&health_script, health)
        .with_context(|| format!("failed to write {}", health_script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut run_perms = std::fs::metadata(&runner_script)
            .with_context(|| format!("failed to stat {}", runner_script.display()))?
            .permissions();
        run_perms.set_mode(0o755);
        std::fs::set_permissions(&runner_script, run_perms)
            .with_context(|| format!("failed to chmod {}", runner_script.display()))?;

        let mut health_perms = std::fs::metadata(&health_script)
            .with_context(|| format!("failed to stat {}", health_script.display()))?
            .permissions();
        health_perms.set_mode(0o755);
        std::fs::set_permissions(&health_script, health_perms)
            .with_context(|| format!("failed to chmod {}", health_script.display()))?;
    }

    match resolved_platform {
        "macos" => {
            let plist_path = output_dir.join(format!("{name}.plist"));
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{name}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>{script}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log_dir}/{name}.out.log</string>
  <key>StandardErrorPath</key>
  <string>{log_dir}/{name}.err.log</string>
</dict>
</plist>
"#,
                script = runner_script.display(),
                log_dir = output_dir.display()
            );
            std::fs::write(&plist_path, plist)
                .with_context(|| format!("failed to write {}", plist_path.display()))?;
            println!("generated launchd files:");
            println!("- {}", plist_path.display());
            println!("- {}", runner_script.display());
            println!("- {}", health_script.display());
            println!();
            println!("install:");
            println!("launchctl bootstrap gui/$(id -u) {}", plist_path.display());
            println!("launchctl enable gui/$(id -u)/{name}");
            println!("launchctl kickstart -k gui/$(id -u)/{name}");
        }
        "linux" => {
            let unit_path = output_dir.join(format!("{name}.service"));
            let unit = format!(
                r#"[Unit]
Description=maid gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={}
Restart=always
RestartSec=3
Environment=RUST_LOG=info
WorkingDirectory={}

[Install]
WantedBy=default.target
"#,
                runner_script.display(),
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .display()
            );
            std::fs::write(&unit_path, unit)
                .with_context(|| format!("failed to write {}", unit_path.display()))?;
            println!("generated systemd files:");
            println!("- {}", unit_path.display());
            println!("- {}", runner_script.display());
            println!("- {}", health_script.display());
            println!();
            println!("install:");
            println!("mkdir -p ~/.config/systemd/user");
            println!(
                "cp {} ~/.config/systemd/user/{}.service",
                unit_path.display(),
                name
            );
            println!("systemctl --user daemon-reload");
            println!("systemctl --user enable --now {name}.service");
        }
        _ => unreachable!(),
    }

    Ok(())
}

async fn report_service_status() -> Result<()> {
    let launchctl_uid = StdCommand::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        });
    let launchctl = if let Some(uid) = launchctl_uid {
        StdCommand::new("launchctl")
            .arg("print")
            .arg(format!("gui/{uid}/maid"))
            .output()
    } else {
        Err(std::io::Error::other("uid unavailable"))
    };
    let systemd = StdCommand::new("systemctl")
        .args(["--user", "is-active", "maid.service"])
        .output();

    match launchctl {
        Ok(out) if out.status.success() => {
            println!("launchd: active");
        }
        Ok(_) => {
            println!("launchd: inactive");
        }
        Err(_) => {
            println!("launchd: unavailable");
        }
    }

    match systemd {
        Ok(out) => {
            let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() {
                println!("systemd: {}", value);
            } else if value.is_empty() {
                println!("systemd: inactive");
            } else {
                println!("systemd: {}", value);
            }
        }
        Err(_) => {
            println!("systemd: unavailable");
        }
    }

    let gateway_ok = check_gateway_ping(18789).await;
    if gateway_ok {
        println!("gateway(127.0.0.1:18789): reachable");
    } else {
        println!("gateway(127.0.0.1:18789): unreachable");
    }

    Ok(())
}
