use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "maid")]
#[command(about = "maid: modular local-first assistant core")]
pub(crate) struct Cli {
    #[arg(long, default_value = "config.toml")]
    pub(crate) config: PathBuf,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    #[command(visible_alias = "info")]
    Status {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(visible_alias = "quickstart")]
    Guide,
    #[command(visible_aliases = ["setup", "bootstrap"])]
    Init {
        #[arg(long, default_value = "personal")]
        template: String,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    #[command(visible_alias = "groups")]
    Group {
        #[command(subcommand)]
        command: GroupCommands,
    },
    #[command(visible_aliases = ["ask", "chat"])]
    Run {
        #[arg(long)]
        group: String,
        #[arg(long)]
        prompt: String,
    },
    #[command(visible_alias = "tasks")]
    Task {
        #[command(subcommand)]
        command: TaskCommands,
    },
    #[command(visible_alias = "agent")]
    Subagent {
        #[command(subcommand)]
        command: SubagentCommands,
    },
    #[command(visible_alias = "plugins")]
    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
    },
    #[command(visible_alias = "tools")]
    Tool {
        #[command(subcommand)]
        command: ToolCommands,
    },
    #[command(visible_alias = "audits")]
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    #[command(visible_alias = "pair")]
    Pairing {
        #[command(subcommand)]
        command: PairingCommands,
    },
    #[command(visible_alias = "svc")]
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommands,
    },
    #[command(visible_alias = "ui")]
    Dashboard {
        #[arg(long, default_value_t = 18790)]
        port: u16,
    },
    #[command(visible_alias = "check")]
    Health {
        #[arg(long, default_value_t = 18789)]
        gateway_port: u16,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(visible_alias = "onboarding")]
    Onboard {
        #[arg(long, default_value_t = false)]
        interactive: bool,
    },
    #[command(visible_alias = "diag")]
    Doctor {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(visible_alias = "scheduler")]
    Daemon,
    #[command(visible_alias = "tg")]
    Telegram,
    #[command(visible_alias = "all")]
    Serve,
    #[command(visible_alias = "api")]
    Gateway {
        #[arg(long, default_value_t = 18789)]
        port: u16,
    },
}

#[derive(Subcommand)]
pub(crate) enum GroupCommands {
    #[command(visible_alias = "new")]
    Create { name: String },
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum TaskCommands {
    #[command(visible_aliases = ["add", "new"])]
    Create {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        schedule: String,
        #[arg(long)]
        prompt: String,
    },
    #[command(visible_alias = "interactive")]
    Wizard {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        schedule: Option<String>,
        #[arg(long)]
        prompt: Option<String>,
    },
    #[command(visible_alias = "quick")]
    QuickAdd {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        every_minutes: u64,
        #[arg(long)]
        prompt: String,
    },
    #[command(visible_alias = "ls")]
    List {
        #[arg(long)]
        group: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Pause {
        #[arg(long)]
        id: String,
    },
    Resume {
        #[arg(long)]
        id: String,
    },
    #[command(visible_alias = "run")]
    RunNow {
        #[arg(long)]
        id: String,
    },
    #[command(visible_alias = "rm")]
    Delete {
        #[arg(long)]
        id: String,
    },
    Clear {
        #[arg(long)]
        group: String,
    },
    #[command(visible_alias = "purge")]
    ClearAll,
}

#[derive(Subcommand)]
pub(crate) enum SubagentCommands {
    Run {
        #[arg(long)]
        group: String,
        #[arg(long)]
        prompt: String,
        #[arg(long, default_value_t = 3)]
        max_steps: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum PluginCommands {
    #[command(visible_alias = "market")]
    Registry {
        #[command(subcommand)]
        command: PluginRegistryCommands,
    },
    #[command(visible_alias = "find")]
    Search {
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        capability: Option<String>,
        #[arg(long, default_value_t = false)]
        ranked: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    #[command(visible_alias = "show")]
    Info {
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Enable {
        #[arg(long)]
        name: String,
    },
    Disable {
        #[arg(long)]
        name: String,
    },
    Keygen {
        #[arg(long, default_value = "keys")]
        out_dir: PathBuf,
        #[arg(long, default_value = "plugin-signing")]
        name: String,
    },
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    #[command(visible_alias = "check")]
    Validate {
        #[arg(long)]
        name: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Trust {
        #[command(subcommand)]
        command: PluginTrustCommands,
    },
    Lock {
        #[command(subcommand)]
        command: PluginLockCommands,
    },
    #[command(visible_alias = "upgrade")]
    Update {
        #[arg(long, default_value_t = false)]
        all: bool,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        channel: Option<String>,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    #[command(visible_alias = "updates")]
    Outdated {
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Rollback {
        #[arg(long)]
        name: String,
        #[arg(long)]
        to_version: String,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    #[command(visible_alias = "routes")]
    Route {
        #[command(subcommand)]
        command: PluginRouteCommands,
    },
    Health {
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 14)]
        days: i64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(visible_alias = "metrics")]
    Stats {
        #[arg(long, default_value_t = 20)]
        top: i64,
        #[arg(long, default_value_t = 14)]
        days: i64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(visible_alias = "exec")]
    Run {
        #[arg(long)]
        name: String,
        #[arg(long)]
        command: String,
        #[arg(long = "arg")]
        args: Vec<String>,
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Sign {
        #[arg(long)]
        name: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        private_key_file: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    #[command(visible_alias = "check-signature")]
    Verify {
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = false)]
        deep: bool,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PluginRegistryCommands {
    #[command(visible_alias = "ls")]
    List {
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long)]
        index: Option<PathBuf>,
    },
    #[command(visible_aliases = ["add", "get"])]
    Install {
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    #[command(visible_alias = "upgrade")]
    Update {
        #[arg(long)]
        name: String,
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PluginTrustCommands {
    #[command(visible_alias = "ls")]
    List,
    #[command(visible_alias = "add")]
    AddPublisher {
        #[arg(long)]
        name: String,
    },
    #[command(visible_alias = "rm")]
    RemovePublisher {
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PluginLockCommands {
    #[command(visible_alias = "sync")]
    Refresh {
        #[arg(long)]
        index: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PluginRouteCommands {
    #[command(visible_alias = "why")]
    Explain {
        #[arg(long)]
        prompt: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Pin {
        #[arg(long)]
        capability: String,
        #[arg(long)]
        plugin: String,
    },
    #[command(visible_alias = "rm")]
    Unpin {
        #[arg(long)]
        capability: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ToolCommands {
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(visible_alias = "run")]
    Call {
        #[arg(long)]
        tool: String,
        #[arg(long = "arg")]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuditCommands {
    List {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PairingCommands {
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Approve {
        #[arg(long)]
        code: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ServiceCommands {
    Install {
        #[arg(long, default_value = "auto")]
        platform: String,
        #[arg(long, default_value = "maid")]
        name: String,
        #[arg(long, default_value_t = 18789)]
        gateway_port: u16,
        #[arg(long, default_value = "deploy/services")]
        output_dir: PathBuf,
    },
    Status,
}

#[derive(Subcommand)]
pub(crate) enum TunnelCommands {
    Command {
        #[arg(long, default_value = "tailscale")]
        mode: String,
        #[arg(long, default_value_t = 18789)]
        gateway_port: u16,
        #[arg(long)]
        ssh_host: Option<String>,
    },
}
