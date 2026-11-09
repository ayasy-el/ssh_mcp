use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

mod config;
mod history;
mod mcp;
mod security;
mod ssh;
mod tui;

use config::{Config, HitlMode};
use mcp::{HitlRequest, LiveLogEntry, McpServer};
use ssh::{AuthMethod, HostKeyStatus, SshClient};

#[derive(Parser, Debug)]
#[command(
    name = "ssh-mcp",
    version,
    about = "SSH & SFTP Model Context Protocol (MCP) server with TUI dashboard and command controls"
)]
struct Cli {
    /// Run in background/headless mode (without TUI)
    #[arg(short = 'b', long)]
    background: bool,

    /// Run in stdio transport mode (for subprocess spawning)
    #[arg(long)]
    stdio: bool,

    /// Path to TOML configuration file
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// Remote host address
    #[arg(short = 'H', long)]
    host: Option<String>,

    /// Remote SSH port
    #[arg(short = 'P', long)]
    port: Option<u16>,

    /// Remote SSH username
    #[arg(short = 'u', long)]
    user: Option<String>,

    /// Path to private key file
    #[arg(short = 'k', long)]
    key: Option<String>,

    /// MCP server HTTP port
    #[arg(long)]
    mcp_port: Option<u16>,

    /// Security policy mode: high_risk, strict, read_only, autonomous/no_approval
    #[arg(long)]
    policy: Option<String>,

    /// Run in Autonomous mode: execute all commands without asking for permission/approval
    #[arg(long, visible_alias = "no-approval")]
    no_approval: bool,

    /// Automatically accept new or changed host keys (equivalent to StrictHostKeyChecking=accept-new)
    #[arg(long, visible_alias = "accept-host-key", visible_alias = "insecure-accept-host-key")]
    accept_host_key: bool,

    /// Install the /ssh command extension into Pi Coding Agent (~/.pi/agent/extensions/ssh.ts)
    #[arg(long)]
    install_pi: bool,

    /// Register/install this MCP server into Pi's mcp.json (default: global ~/.pi/agent/mcp.json)
    #[arg(long)]
    install_mcp: bool,

    /// Used with --install-mcp to install into local project (.pi/mcp.json) instead of global
    #[arg(short = 'l', long)]
    local: bool,
}

const PI_EXTENSION_CODE: &str = include_str!("../pi-extension/ssh.ts");
const SSH_SKILL_MD: &str = include_str!("../skills/ssh/SKILL.md");

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check for --install-pi
    if cli.install_pi {
        install_pi_extension()?;
        return Ok(());
    }

    // Check for --install-mcp
    if cli.install_mcp {
        let (config, _) = Config::load_or_default(cli.config.as_deref());
        let mcp_port = cli.mcp_port.unwrap_or(config.general.mcp_port);
        let mcp_bind = config.general.mcp_bind;
        let url = format!("http://{}:{}/mcp", mcp_bind, mcp_port);
        install_mcp_config(cli.local, &url)?;
        return Ok(());
    }

    // 1. Load Configuration
    let (mut config, loaded_from) = Config::load_or_default(cli.config.as_deref());

    // Apply CLI overrides
    if let Some(p) = cli.mcp_port {
        config.general.mcp_port = p;
    }
    if let Some(pol) = &cli.policy {
        config.security.hitl_mode = match pol.to_lowercase().as_str() {
            "strict" => HitlMode::Strict,
            "read_only" | "readonly" => HitlMode::ReadOnly,
            "autonomous" | "no_approval" | "no-approval" | "noapproval" | "audit_only" | "auditonly" | "auto" | "unrestricted" | "none" => {
                HitlMode::Autonomous
            }
            _ => HitlMode::HighRisk,
        };
    }
    if cli.no_approval {
        config.security.hitl_mode = HitlMode::Autonomous;
    }
    if cli.accept_host_key {
        config.security.tofu_auto_accept = true;
        config.security.accept_host_key_changes = true;
    }

    // Determine execution mode
    let is_headless = cli.background || cli.stdio || config.general.mode == "headless";

    // 2. Setup Communication Channels
    let (hitl_tx, hitl_rx) = mpsc::channel::<HitlRequest>(32);
    let (live_log_tx, live_log_rx) = mpsc::channel::<LiveLogEntry>(100);

    // 3. Optional Direct Connection in Headless / CLI mode
    let mut initial_client: Option<Arc<SshClient>> = None;
    if let Some(host) = &cli.host {
        let port = cli.port.unwrap_or(22);
        let user = cli.user.as_deref().unwrap_or_else(|| {
            if let Ok(u) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
                Box::leak(u.into_boxed_str())
            } else {
                "ubuntu"
            }
        });

        let auth_method = if cli.key.is_some() {
            AuthMethod::KeyFile
        } else {
            AuthMethod::Agent
        };

        let password = std::env::var("SSH_PASSWORD").ok().map(Zeroizing::new);

        match SshClient::connect_and_check_host_key(host, port) {
            Ok((session, HostKeyStatus::Trusted)) => {
                let client = SshClient::authenticate(
                    session,
                    host,
                    port,
                    user,
                    &auth_method,
                    password,
                    cli.key.as_deref(),
                    None,
                )?;
                initial_client = Some(Arc::new(client));
            }
            Ok((session, HostKeyStatus::NewHost { host, port, raw_key, key_type, .. })) => {
                if config.security.tofu_auto_accept || !is_headless {
                    SshClient::save_known_host(&session, &host, port, &raw_key, key_type)?;
                    let client = SshClient::authenticate(
                        session,
                        &host,
                        port,
                        user,
                        &auth_method,
                        password,
                        cli.key.as_deref(),
                        None,
                    )?;
                    initial_client = Some(Arc::new(client));
                } else {
                    return Err(anyhow!(
                        "Host key for {}:{} not verified in known_hosts. Run interactively or set tofu_auto_accept=true.",
                        host, port
                    ));
                }
            }
            Ok((session, HostKeyStatus::Mismatch { host, port, raw_key, key_type, fingerprint_sha256, key_type_name })) => {
                if config.security.accept_host_key_changes || cli.accept_host_key {
                    let _ = SshClient::save_known_host(&session, &host, port, &raw_key, key_type);
                    let client = SshClient::authenticate(
                        session,
                        &host,
                        port,
                        user,
                        &auth_method,
                        password,
                        cli.key.as_deref(),
                        None,
                    )?;
                    initial_client = Some(Arc::new(client));
                } else {
                    return Err(anyhow!(
                        "SECURITY ERROR: Host key mismatch detected for {}:{} ({}) [{}]!\n\
                         Run interactively to inspect and accept, or use '--accept-host-key' to update known_hosts.",
                        host, port, key_type_name, fingerprint_sha256
                    ));
                }
            }
            Err(e) => {
                if is_headless {
                    return Err(e);
                }
            }
        }
    }

    // 4. Initialize MCP Server
    let mcp_server = McpServer::new(
        initial_client,
        config.clone(),
        hitl_tx,
        live_log_tx,
    );

    // 5. Spawn Axum HTTP/SSE server in background
    let bind_addr = format!("{}:{}", config.general.mcp_bind, config.general.mcp_port);
    let app_router = mcp_server.clone().build_router();
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind MCP server to {}", bind_addr))?;

    tokio::spawn(async move {
        let _ = axum::serve(listener, app_router).await;
    });

    // 6. Branch according to mode
    if cli.stdio {
        run_stdio_mode(mcp_server).await?;
    } else if is_headless {
        run_headless_mode(&config, loaded_from.as_deref(), &bind_addr).await?;
    } else {
        tui::run_tui(config, mcp_server, hitl_rx, live_log_rx).await?;
    }

    Ok(())
}

async fn run_stdio_mode(mcp_server: McpServer) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(req) = serde_json::from_str::<mcp::JsonRpcRequest>(trimmed) {
            if let Some(resp) = mcp_server.handle_jsonrpc(req).await {
                if let Ok(json_str) = serde_json::to_string(&resp) {
                    stdout.write_all(json_str.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
            }
        }
    }

    Ok(())
}

async fn run_headless_mode(
    config: &Config,
    loaded_config: Option<&Path>,
    bind_addr: &str,
) -> Result<()> {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       SSH-MCP Server (Headless Daemon Mode)                   ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    if let Some(path) = loaded_config {
        println!(" Configuration:   Loaded from {:?}", path);
    } else {
        println!(" Configuration:   Defaults (no config file specified)");
    }
    println!(" MCP Streamable:  http://{}/mcp", bind_addr);
    println!(" MCP SSE Stream:  http://{}/sse", bind_addr);
    println!(" Security Policy: {}", config.security.hitl_mode.display_label());
    println!(" Audit Trail Log: {}", config.security.audit_log_path);
    println!("\n💡 Connect from Pi Coding Agent:");
    println!("   pi mcp add -l ssh --url http://{}/mcp", bind_addr);
    println!("\nPress Ctrl+C to terminate the server.\n");

    tokio::signal::ctrl_c().await?;
    println!("\nShutting down ssh-mcp server gracefully...");
    Ok(())
}

fn install_pi_extension() -> Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not resolve user home directory"))?;
    
    // 1. Install Extension
    let ext_dir = home.join(".pi").join("agent").join("extensions");
    std::fs::create_dir_all(&ext_dir)?;
    let target_file = ext_dir.join("ssh.ts");
    std::fs::write(&target_file, PI_EXTENSION_CODE)?;

    // 2. Install Skill (~/.agents/skills/ssh/SKILL.md and ~/.pi/agent/skills/ssh/SKILL.md)
    let agent_skill_dir = home.join(".agents").join("skills").join("ssh");
    std::fs::create_dir_all(&agent_skill_dir)?;
    let agent_skill_file = agent_skill_dir.join("SKILL.md");
    std::fs::write(&agent_skill_file, SSH_SKILL_MD)?;

    let pi_skill_dir = home.join(".pi").join("agent").join("skills").join("ssh");
    std::fs::create_dir_all(&pi_skill_dir)?;
    let pi_skill_file = pi_skill_dir.join("SKILL.md");
    std::fs::write(&pi_skill_file, SSH_SKILL_MD)?;

    println!("✅ Successfully installed Pi extension and SSH skill!");
    println!("   • Extension: {:?}", target_file);
    println!("   • Skill:     {:?}", agent_skill_file);
    println!("\nUsage inside Pi Coding Agent:");
    println!("  1. Launch Pi in your terminal: `pi`");
    println!("  2. Type `/ssh` to open the interactive SSH Management menu!");
    println!("  3. Type `/skill:ssh` or prompt naturally to trigger the SSH skill!");
    println!("  4. Available subcommands:");
    println!("     • /ssh status      - Check SSH MCP health and active remote connection");
    println!("     • /ssh info        - View remote system specs (OS, CPU, RAM, Disk)");
    println!("     • /ssh exec <cmd>  - Run remote shell command and inspect output");
    println!("     • /ssh read <path> - View remote file via SFTP");
    println!("     • /ssh dir [path]  - List remote directory contents");
    println!("     • /ssh connect     - Auto-connect or reconnect SSH MCP in Pi");
    println!("     • /ssh disconnect  - Unregister SSH MCP server");
    println!("     • /ssh menu        - Open interactive menu selector");

    Ok(())
}

fn install_mcp_config(local: bool, url: &str) -> Result<()> {
    let (target_path, scope_label) = if local {
        (PathBuf::from(".pi").join("mcp.json"), "Project-Local (.pi/mcp.json)")
    } else {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not resolve user home directory"))?;
        (home.join(".pi").join("agent").join("mcp.json"), "Global (~/.pi/agent/mcp.json)")
    };

    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut root_json: serde_json::Value = if target_path.is_file() {
        let content = std::fs::read_to_string(&target_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({ "mcpServers": {} }))
    } else {
        serde_json::json!({ "mcpServers": {} })
    };

    if !root_json.is_object() {
        root_json = serde_json::json!({ "mcpServers": {} });
    }

    if root_json.get("mcpServers").is_none() || !root_json["mcpServers"].is_object() {
        root_json["mcpServers"] = serde_json::json!({});
    }

    root_json["mcpServers"]["ssh"] = serde_json::json!({
        "url": url,
        "description": "Security-hardened SSH & SFTP remote server tools",
        "exposure": "direct"
    });

    let pretty_str = serde_json::to_string_pretty(&root_json)?;
    std::fs::write(&target_path, pretty_str)?;

    println!("✅ Successfully configured SSH MCP server in {}!", scope_label);
    println!("   Server Name: \"ssh\"");
    println!("   URL:         {}", url);
    println!("   File:        {:?}", target_path);
    println!("\n💡 Test in Pi:");
    println!("   pi mcp list");
    println!("   pi");

    Ok(())
}
