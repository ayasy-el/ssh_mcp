use crate::config::{Config, HitlMode};
use crate::mcp::types::{JsonRpcRequest, JsonRpcResponse, ToolCallResult};
use crate::security::{classify_command, mask_secrets, AuditEvent, AuditLogger, RiskTier};
use crate::ssh::SshClient;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use futures_util::stream;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tower_http::cors::CorsLayer;

#[derive(Debug, Clone)]
pub enum HitlDecision {
    ApproveOnce,
    Deny,
    ApproveSession,
}

pub struct HitlRequest {
    pub tool_name: String,
    pub command_or_target: String,
    pub risk_tier: RiskTier,
    pub reason: String,
    pub responder: oneshot::Sender<HitlDecision>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LiveLogEntry {
    pub timestamp: String,
    pub tool: String,
    pub detail: String,
    pub risk: RiskTier,
    pub status: String,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub output_bytes: usize,
}

pub struct ServerContext {
    pub client: Arc<RwLock<Option<Arc<SshClient>>>>,
    pub config: Arc<RwLock<Config>>,
    pub audit_logger: Arc<AuditLogger>,
    pub hitl_tx: mpsc::Sender<HitlRequest>,
    pub live_log_tx: mpsc::Sender<LiveLogEntry>,
    pub session_allowed_commands: Arc<parking_lot::Mutex<HashSet<String>>>,
}

#[derive(Clone)]
pub struct McpServer {
    ctx: Arc<ServerContext>,
}

impl McpServer {
    pub fn new(
        client: Option<Arc<SshClient>>,
        config: Config,
        hitl_tx: mpsc::Sender<HitlRequest>,
        live_log_tx: mpsc::Sender<LiveLogEntry>,
    ) -> Self {
        let audit_logger = Arc::new(AuditLogger::new(&config.security.audit_log_path));
        let ctx = ServerContext {
            client: Arc::new(RwLock::new(client)),
            config: Arc::new(RwLock::new(config)),
            audit_logger,
            hitl_tx,
            live_log_tx,
            session_allowed_commands: Arc::new(parking_lot::Mutex::new(HashSet::new())),
        };
        Self { ctx: Arc::new(ctx) }
    }

    pub fn set_client(&self, client: Arc<SshClient>) {
        *self.ctx.client.write() = Some(client);
    }

    pub fn update_policy_mode(&self, new_mode: HitlMode) {
        self.ctx.config.write().security.hitl_mode = new_mode;
    }

    #[allow(dead_code)]
    pub fn current_policy_mode(&self) -> HitlMode {
        self.ctx.config.read().security.hitl_mode
    }

    pub async fn handle_jsonrpc(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let id = req.id;
        match req.method.as_str() {
            "initialize" => {
                let init_result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "ssh-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": "SSH MCP Server enables AI agents to run shell commands, inspect directories, transfer files via SFTP, and query remote system metrics securely."
                });
                Some(JsonRpcResponse::success(id, init_result))
            }

            "notifications/initialized" => {
                // Notifications do not receive a response
                None
            }

            "ping" => Some(JsonRpcResponse::success(id, json!({}))),

            "tools/list" => {
                let tools = self.get_tool_definitions();
                Some(JsonRpcResponse::success(id, json!({ "tools": tools })))
            }

            "tools/call" => {
                let params = req.params.unwrap_or_else(|| json!({}));
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

                let result = self.execute_tool(name, args).await;
                Some(JsonRpcResponse::success(
                    id,
                    serde_json::to_value(result).unwrap_or_else(|_| json!({})),
                ))
            }

            _ => Some(JsonRpcResponse::error(
                id,
                -32601,
                &format!("Method not found: {}", req.method),
            )),
        }
    }

    fn get_tool_definitions(&self) -> Vec<Value> {
        vec![
            json!({
                "name": "ssh_exec",
                "description": "Execute a shell command on the remote SSH server. Includes output limiting, timeout protection, and risk classification.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to run on the remote machine."
                        },
                        "cwd": {
                            "type": "string",
                            "description": "Remote working directory to execute the command in (optional)."
                        },
                        "timeout_secs": {
                            "type": "number",
                            "description": "Execution timeout in seconds (default: 60)."
                        },
                        "max_bytes": {
                            "type": "number",
                            "description": "Maximum output bytes before truncating (default: 32768 = 32KB)."
                        },
                        "max_lines": {
                            "type": "number",
                            "description": "Maximum output lines before truncating (default: 1500)."
                        },
                        "approved": {
                            "type": "boolean",
                            "description": "Set to true if operator has already approved this command in the agent's UI."
                        },
                        "allow_session": {
                            "type": "boolean",
                            "description": "Set to true if operator allowed this command for the rest of the session."
                        }
                    },
                    "required": ["command"]
                }
            }),
            json!({
                "name": "ssh_read_file",
                "description": "Read contents of a file on the remote server via SFTP. Supports offset and limit for token-efficient pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the remote file."
                        },
                        "offset": {
                            "type": "number",
                            "description": "Line number to start reading from (1-indexed, default: 1)."
                        },
                        "limit": {
                            "type": "number",
                            "description": "Maximum lines to read (default: 500)."
                        }
                    },
                    "required": ["path"]
                }
            }),
            json!({
                "name": "ssh_write_file",
                "description": "Write, create, or append content to a remote file via SFTP.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the remote file."
                        },
                        "content": {
                            "type": "string",
                            "description": "Content string to write into the file."
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["overwrite", "append", "create_new"],
                            "description": "Write mode (default: overwrite)."
                        },
                        "approved": {
                            "type": "boolean",
                            "description": "Set to true if operator has already approved this write in the agent's UI."
                        },
                        "allow_session": {
                            "type": "boolean",
                            "description": "Set to true if operator allowed writing to this path for the rest of the session."
                        }
                    },
                    "required": ["path", "content"]
                }
            }),
            json!({
                "name": "ssh_list_dir",
                "description": "List files and subdirectories in a remote directory with structured metadata (sizes, permissions, timestamps).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Remote directory path (default: current directory)."
                        }
                    }
                }
            }),
            json!({
                "name": "ssh_system_info",
                "description": "Fetch a high-level system overview of the remote server (OS release, kernel, CPU cores, RAM usage, root disk usage, uptime).",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }),
            json!({
                "name": "ssh_stat",
                "description": "Inspect metadata and status of a remote file or directory without reading contents.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to inspect."
                        }
                    },
                    "required": ["path"]
                }
            }),
        ]
    }

    async fn execute_tool(&self, name: &str, args: Value) -> ToolCallResult {
        let client_opt = self.ctx.client.read().clone();
        let client = match client_opt {
            Some(c) => c,
            None => {
                return ToolCallResult::error(
                    "SSH MCP Server is not yet connected to a remote host. Please configure and connect via TUI or CLI.".to_string(),
                );
            }
        };

        let start_time = Instant::now();
        let config = self.ctx.config.read().clone();

        match name {
            "ssh_exec" => {
                let cmd = match args.get("command").and_then(|v| v.as_str()) {
                    Some(c) => c,
                    None => return ToolCallResult::error("Missing required parameter: 'command'".to_string()),
                };

                let cwd = args.get("cwd").and_then(|v| v.as_str());
                let timeout_secs = args
                    .get("timeout_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(config.security.command_timeout_secs);
                let max_bytes = args
                    .get("max_bytes")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(config.security.max_output_bytes);
                let max_lines = args
                    .get("max_lines")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(config.security.max_output_lines);

                // Risk classification
                let (risk_tier, risk_reason) = classify_command(
                    cmd,
                    &config.security.forbidden_commands,
                    &config.security.high_risk_commands,
                    &config.security.safe_commands,
                );

                // Security Policy Enforcement
                if risk_tier == RiskTier::Forbidden {
                    let err_msg = format!("Security Violation: Command blocked permanently ({})", risk_reason);
                    self.log_and_emit(name, cmd, risk_tier, "FORBIDDEN", start_time.elapsed().as_millis() as u64, Some(126), 0).await;
                    return ToolCallResult::error(err_msg);
                }

                if config.security.hitl_mode == HitlMode::ReadOnly && (risk_tier == RiskTier::Mutating || risk_tier == RiskTier::HighRisk) {
                    let err_msg = "Command rejected: Server is operating in Read-Only mode.".to_string();
                    self.log_and_emit(name, cmd, risk_tier, "DENIED_READONLY", start_time.elapsed().as_millis() as u64, Some(126), 0).await;
                    return ToolCallResult::error(err_msg);
                }

                let is_pre_approved = args.get("approved").and_then(|v| v.as_bool()).unwrap_or(false);
                let is_allow_session = args.get("allow_session").and_then(|v| v.as_bool()).unwrap_or(false);

                if is_allow_session {
                    self.ctx.session_allowed_commands.lock().insert(cmd.to_string());
                }

                // Check if session always-allowed or approved from agent
                let is_session_allowed = is_pre_approved || self.ctx.session_allowed_commands.lock().contains(cmd);

                let requires_approval = !is_session_allowed && match config.security.hitl_mode {
                    HitlMode::HighRisk => risk_tier == RiskTier::HighRisk,
                    HitlMode::Strict => risk_tier == RiskTier::HighRisk || risk_tier == RiskTier::Mutating,
                    HitlMode::ReadOnly => true,
                    HitlMode::Autonomous => false,
                };

                if requires_approval {
                    let (hitl_tx, hitl_rx) = oneshot::channel();
                    let hitl_req = HitlRequest {
                        tool_name: name.to_string(),
                        command_or_target: cmd.to_string(),
                        risk_tier,
                        reason: risk_reason.to_string(),
                        responder: hitl_tx,
                    };

                    if self.ctx.hitl_tx.send(hitl_req).await.is_err() {
                        let err_msg = format!(
                            "Execution rejected: '{}' requires operator approval ({}), but ssh-mcp is running headless. Re-run with '--no-approval' to allow autonomous execution.",
                            cmd, risk_reason
                        );
                        self.log_and_emit(name, cmd, risk_tier, "DENIED_HEADLESS", start_time.elapsed().as_millis() as u64, Some(1), 0).await;
                        return ToolCallResult::error(err_msg);
                    }

                    let hitl_timeout = std::time::Duration::from_secs(15);
                    match tokio::time::timeout(hitl_timeout, hitl_rx).await {
                        Ok(Ok(HitlDecision::ApproveOnce)) => {
                            // Proceed
                        }
                        Ok(Ok(HitlDecision::ApproveSession)) => {
                            self.ctx.session_allowed_commands.lock().insert(cmd.to_string());
                        }
                        Ok(Ok(HitlDecision::Deny)) => {
                            let err_msg = format!("Execution denied by operator: {}", cmd);
                            self.log_and_emit(name, cmd, risk_tier, "DENIED", start_time.elapsed().as_millis() as u64, Some(1), 0).await;
                            return ToolCallResult::error(err_msg);
                        }
                        Ok(Err(_)) => {
                            let err_msg = "Approval channel was aborted.".to_string();
                            return ToolCallResult::error(err_msg);
                        }
                        Err(_) => {
                            let err_msg = format!(
                                "Approval required for command '{}' ({}).\n\
                                 Timed out waiting for operator response in ssh-mcp terminal.\n\
                                 To approve: press [Y] (once) or [A] (session) in ssh-mcp, or restart with '--no-approval'.",
                                cmd, risk_reason
                            );
                            self.log_and_emit(name, cmd, risk_tier, "APPROVAL_TIMEOUT", start_time.elapsed().as_millis() as u64, Some(1), 0).await;
                            return ToolCallResult::error(err_msg);
                        }
                    }
                }

                // Execute command
                let exec_res = client.exec(cmd, cwd, timeout_secs, max_bytes, max_lines);
                let duration_ms = start_time.elapsed().as_millis() as u64;

                match exec_res {
                    Ok(mut res) => {
                        if config.security.mask_secrets {
                            res.stdout = mask_secrets(&res.stdout);
                            res.stderr = mask_secrets(&res.stderr);
                        }

                        let total_bytes = res.stdout.len() + res.stderr.len();
                        self.log_and_emit(name, cmd, risk_tier, "OK", duration_ms, Some(res.exit_code), total_bytes).await;

                        let formatted_output = json!({
                            "stdout": res.stdout,
                            "stderr": res.stderr,
                            "exit_code": res.exit_code,
                            "duration_ms": res.duration_ms,
                            "truncated": res.truncated
                        });
                        ToolCallResult::text(serde_json::to_string_pretty(&formatted_output).unwrap())
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        self.log_and_emit(name, cmd, risk_tier, "ERROR", duration_ms, Some(1), 0).await;
                        ToolCallResult::error(format!("Execution failed: {}", err_str))
                    }
                }
            }

            "ssh_read_file" => {
                let path = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return ToolCallResult::error("Missing required parameter: 'path'".to_string()),
                };
                let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(500) as usize;

                let read_res = client.read_file(path, offset, limit);
                let duration_ms = start_time.elapsed().as_millis() as u64;

                match read_res {
                    Ok(mut res) => {
                        if config.security.mask_secrets {
                            res.content = mask_secrets(&res.content);
                        }
                        self.log_and_emit(name, path, RiskTier::Safe, "OK", duration_ms, Some(0), res.content.len()).await;
                        ToolCallResult::text(serde_json::to_string_pretty(&res).unwrap())
                    }
                    Err(e) => {
                        self.log_and_emit(name, path, RiskTier::Safe, "ERROR", duration_ms, Some(1), 0).await;
                        ToolCallResult::error(format!("Failed to read file {}: {}", path, e))
                    }
                }
            }

            "ssh_write_file" => {
                let path = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return ToolCallResult::error("Missing required parameter: 'path'".to_string()),
                };
                let content = match args.get("content").and_then(|v| v.as_str()) {
                    Some(c) => c,
                    None => return ToolCallResult::error("Missing required parameter: 'content'".to_string()),
                };
                let mode = args.get("mode").and_then(|v| v.as_str()).unwrap_or("overwrite");

                if config.security.hitl_mode == HitlMode::ReadOnly {
                    return ToolCallResult::error("File write rejected: Server is in Read-Only mode.".to_string());
                }

                let is_pre_approved = args.get("approved").and_then(|v| v.as_bool()).unwrap_or(false);
                let is_allow_session = args.get("allow_session").and_then(|v| v.as_bool()).unwrap_or(false);

                if is_allow_session {
                    self.ctx.session_allowed_commands.lock().insert(path.to_string());
                }

                // Check HITL for modifying critical system files or if in Strict mode
                let is_critical_path = path.starts_with("/etc") || path.contains("authorized_keys") || path.starts_with("/boot");
                let risk_tier = if is_critical_path { RiskTier::HighRisk } else { RiskTier::Mutating };

                let is_session_allowed = is_pre_approved || self.ctx.session_allowed_commands.lock().contains(path);

                let requires_write_approval = !is_session_allowed && match config.security.hitl_mode {
                    HitlMode::Autonomous => false,
                    HitlMode::HighRisk => risk_tier == RiskTier::HighRisk,
                    HitlMode::Strict => true,
                    HitlMode::ReadOnly => true,
                };

                if requires_write_approval {
                    let (hitl_tx, hitl_rx) = oneshot::channel();
                    let hitl_req = HitlRequest {
                        tool_name: name.to_string(),
                        command_or_target: format!("{} to {}", mode, path),
                        risk_tier,
                        reason: "Writing file via SFTP".to_string(),
                        responder: hitl_tx,
                    };

                    if self.ctx.hitl_tx.send(hitl_req).await.is_err() {
                        let err_msg = format!(
                            "Write rejected: Writing to '{}' requires operator approval, but ssh-mcp is running headless. Re-run with '--no-approval' to allow autonomous execution.",
                            path
                        );
                        self.log_and_emit(name, path, risk_tier, "DENIED_HEADLESS", start_time.elapsed().as_millis() as u64, Some(1), 0).await;
                        return ToolCallResult::error(err_msg);
                    }

                    let hitl_timeout = std::time::Duration::from_secs(15);
                    match tokio::time::timeout(hitl_timeout, hitl_rx).await {
                        Ok(Ok(HitlDecision::ApproveOnce)) => {
                            // Proceed
                        }
                        Ok(Ok(HitlDecision::ApproveSession)) => {
                            self.ctx.session_allowed_commands.lock().insert(path.to_string());
                        }
                        Ok(Ok(HitlDecision::Deny)) => {
                            return ToolCallResult::error(format!("File write denied by operator: {}", path));
                        }
                        Ok(Err(_)) => {
                            return ToolCallResult::error("File write approval was aborted.".to_string());
                        }
                        Err(_) => {
                            let err_msg = format!(
                                "Approval required for writing to '{}'.\n\
                                 Timed out waiting for operator response in ssh-mcp terminal.\n\
                                 To approve: press [Y] (once) or [A] (session) in ssh-mcp, or restart with '--no-approval'.",
                                path
                            );
                            self.log_and_emit(name, path, risk_tier, "APPROVAL_TIMEOUT", start_time.elapsed().as_millis() as u64, Some(1), 0).await;
                            return ToolCallResult::error(err_msg);
                        }
                    }
                }

                let write_res = client.write_file(path, content, mode);
                let duration_ms = start_time.elapsed().as_millis() as u64;

                match write_res {
                    Ok(bytes) => {
                        self.log_and_emit(name, path, risk_tier, "OK", duration_ms, Some(0), bytes).await;
                        ToolCallResult::text(serde_json::to_string_pretty(&json!({
                            "path": path,
                            "bytes_written": bytes,
                            "mode": mode
                        })).unwrap())
                    }
                    Err(e) => {
                        self.log_and_emit(name, path, risk_tier, "ERROR", duration_ms, Some(1), 0).await;
                        ToolCallResult::error(format!("Failed writing to {}: {}", path, e))
                    }
                }
            }

            "ssh_list_dir" => {
                let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
                let list_res = client.list_dir(path);
                let duration_ms = start_time.elapsed().as_millis() as u64;

                match list_res {
                    Ok(entries) => {
                        let json_val = json!({
                            "path": path,
                            "entries": entries
                        });
                        self.log_and_emit(name, path, RiskTier::Safe, "OK", duration_ms, Some(0), 100).await;
                        ToolCallResult::text(serde_json::to_string_pretty(&json_val).unwrap())
                    }
                    Err(e) => {
                        self.log_and_emit(name, path, RiskTier::Safe, "ERROR", duration_ms, Some(1), 0).await;
                        ToolCallResult::error(format!("Failed to list directory {}: {}", path, e))
                    }
                }
            }

            "ssh_system_info" => {
                let info_res = client.system_info();
                let duration_ms = start_time.elapsed().as_millis() as u64;

                match info_res {
                    Ok(info) => {
                        self.log_and_emit(name, "system_info", RiskTier::Safe, "OK", duration_ms, Some(0), 200).await;
                        ToolCallResult::text(serde_json::to_string_pretty(&info).unwrap())
                    }
                    Err(e) => {
                        self.log_and_emit(name, "system_info", RiskTier::Safe, "ERROR", duration_ms, Some(1), 0).await;
                        ToolCallResult::error(format!("Failed to retrieve system info: {}", e))
                    }
                }
            }

            "ssh_stat" => {
                let path = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return ToolCallResult::error("Missing required parameter: 'path'".to_string()),
                };

                let stat_res = client.stat(path);
                let duration_ms = start_time.elapsed().as_millis() as u64;

                match stat_res {
                    Ok(st) => {
                        self.log_and_emit(name, path, RiskTier::Safe, "OK", duration_ms, Some(0), 50).await;
                        ToolCallResult::text(serde_json::to_string_pretty(&st).unwrap())
                    }
                    Err(e) => {
                        self.log_and_emit(name, path, RiskTier::Safe, "ERROR", duration_ms, Some(1), 0).await;
                        ToolCallResult::error(format!("Failed to stat path {}: {}", path, e))
                    }
                }
            }

            _ => ToolCallResult::error(format!("Unknown tool: {}", name)),
        }
    }

    async fn log_and_emit(
        &self,
        tool: &str,
        target: &str,
        risk: RiskTier,
        status: &str,
        duration_ms: u64,
        exit_code: Option<i32>,
        output_bytes: usize,
    ) {
        let now = Utc::now();
        let event = AuditEvent {
            timestamp: now,
            tool: tool.to_string(),
            command_or_target: target.to_string(),
            risk_tier: risk,
            hitl_decision: Some(status.to_string()),
            duration_ms,
            exit_code,
            output_bytes,
        };

        // Write to audit.jsonl
        self.ctx.audit_logger.log(&event);

        // Send to live TUI display
        let entry = LiveLogEntry {
            timestamp: now.format("%H:%M:%S").to_string(),
            tool: tool.to_string(),
            detail: target.to_string(),
            risk,
            status: status.to_string(),
            duration_ms,
            exit_code,
            output_bytes,
        };
        let _ = self.ctx.live_log_tx.send(entry).await;
    }

    /// Builds the Axum router supporting Streamable HTTP, SSE, and health endpoints.
    pub fn build_router(self) -> Router {
        Router::new()
            .route("/mcp", post(handle_post_mcp).get(handle_sse_mcp))
            .route("/sse", get(handle_sse_mcp).post(handle_post_mcp))
            .route("/policy", get(handle_get_policy).post(handle_set_policy))
            .route("/health", get(handle_health))
            .route("/", get(handle_health))
            .layer(CorsLayer::permissive())
            .with_state(self)
    }
}

// HTTP handler for POST /mcp (Streamable HTTP / JSON-RPC)
async fn handle_post_mcp(
    State(server): State<McpServer>,
    _headers: HeaderMap,
    Json(payload): Json<JsonRpcRequest>,
) -> Response {
    if let Some(resp) = server.handle_jsonrpc(payload).await {
        (StatusCode::OK, Json(resp)).into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

// HTTP handler for GET /mcp or GET /sse (Server-Sent Events)
async fn handle_sse_mcp(State(_server): State<McpServer>) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    // Initial endpoint announcement event according to MCP SSE specification
    let initial_event = Event::default().event("endpoint").data("/mcp");
    let stream = stream::once(async move { Ok(initial_event) });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// HTTP handler for GET /health
async fn handle_health(State(server): State<McpServer>) -> impl IntoResponse {
    let client_connected = server.ctx.client.read().is_some();
    let host_info = if let Some(c) = server.ctx.client.read().as_ref() {
        format!("{}@{}:{}", c.username(), c.host(), c.port())
    } else {
        "disconnected".to_string()
    };
    let current_policy = server.ctx.config.read().security.hitl_mode;

    Json(json!({
        "status": "ok",
        "service": "ssh-mcp",
        "version": env!("CARGO_PKG_VERSION"),
        "connected": client_connected,
        "remote_host": host_info,
        "mcp_spec": "2024-11-05",
        "policy": current_policy.display_label()
    }))
}

#[derive(Deserialize)]
struct PolicyPayload {
    mode: String,
}

// HTTP handler for GET /policy
async fn handle_get_policy(State(server): State<McpServer>) -> impl IntoResponse {
    let mode = server.ctx.config.read().security.hitl_mode;
    Json(json!({
        "status": "ok",
        "policy": mode.display_label()
    }))
}

// HTTP handler for POST /policy
async fn handle_set_policy(
    State(server): State<McpServer>,
    Json(payload): Json<PolicyPayload>,
) -> impl IntoResponse {
    let mode = match payload.mode.to_lowercase().as_str() {
        "strict" => HitlMode::Strict,
        "read_only" | "readonly" => HitlMode::ReadOnly,
        "autonomous" | "no_approval" | "no-approval" | "auto" | "audit_only" | "unrestricted" => {
            HitlMode::Autonomous
        }
        _ => HitlMode::HighRisk,
    };
    server.update_policy_mode(mode);
    Json(json!({
        "status": "ok",
        "policy": mode.display_label()
    }))
}
