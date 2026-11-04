# Technical Specification: SSH MCP Server (`ssh-mcp`)

## 1. Executive Summary

`ssh-mcp` is an SSH & SFTP Model Context Protocol (MCP) server written in Rust. It connects Large Language Model (LLM) coding agents (such as **Pi Coding Agent**, Claude Desktop, Cursor, and Zed) with remote servers via SSH and SFTP.

The server operates out-of-the-box as a **single binary** with an interactive **Foreground Terminal User Interface (TUI)** by default, while supporting a **Background/Headless Daemon mode** (`-b` / `--background`) and a **Subprocess Stdio mode** (`--stdio`). Configuration via TOML (`config.toml`) is supported but entirely optional—interactive prompts and sensible defaults allow zero-config execution.

---

## 2. System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                             ssh-mcp Single Binary                           │
├─────────────────────────────────────┬───────────────────────────────────────┤
│          Terminal Frontend          │             Core Backend              │
│  ┌───────────────────────────────┐  │  ┌─────────────────────────────────┐  │
│  │     Ratatui Interactive       │  │  │        Tokio Async Engine       │  │
│  │          TUI Layer            │  │  │  (Event Loop & Task Scheduling) │  │
│  │ ───────────────────────────── │  │  └────────────────┬────────────────┘  │
│  │ • Connection & Auth Form      │  │                   │                   │
│  │ • Live Dashboard & Sysinfo    │  │  ┌────────────────┴────────────────┐  │
│  │ • Real-time Audit Table       │  │  │         Security Engine         │  │
│  │ • Human-in-the-Loop (HITL)    │◄─┼──┤ • Risk Tier Classification      │  │
│  │   Modal Approval Dialog       │  │  │ • Secret Masking / Redaction    │  │
│  │ • Policy Mode Switcher        │  │  │ • Output Limiting & Truncation  │  │
│  └───────────────▲───────────────┘  │  │ • Append-only Audit Log         │  │
│                  │ (Events/State)   │  └────────────────┬────────────────┘  │
│                  │                  │                   │                   │
│  ┌───────────────┴───────────────┐  │  ┌────────────────┴────────────────┐  │
│  │         TUI Transports        │  │  │        SSH & SFTP Engine        │  │
│  │ (crossterm, raw mode, stdout) │  │  │ • libssh2 / ssh2 Rust bindings  │  │
│  └───────────────────────────────┘  │  │ • Host Key / TOFU Verification │  │
│                                     │  │ • Zeroize Credential Hygiene   │  │
│                                     │  │ • Keep-alive & Signal Handling │  │
│                                     │  └────────────────┬────────────────┘  │
│                                     │                   │                   │
│  ┌───────────────────────────────┐  │  ┌────────────────┴────────────────┐  │
│  │       MCP Protocol Server     │  │  │        Dual Transports          │  │
│  │ • JSON-RPC 2.0 Handler        │  │  │ • Streamable HTTP (POST /mcp)   │  │
│  │ • tools/list & tools/call     │◄─┼──┤ • SSE Endpoint (GET /sse,/mcp)  │  │
│  │ • 6 Optimized Agent Tools     │  │  │ • Stdio Pipe (stdin/stdout)     │  │
│  └───────────────────────────────┘  │  └─────────────────────────────────┘  │
└──────────────────┬──────────────────┴───────────────────┬───────────────────┘
                   │                                      │
                   ▼ (HTTP/SSE or Stdio)                  ▼ (Encrypted SSH / SFTP)
          ┌──────────────────┐                  ┌──────────────────┐
          │     AI Agent     │                  │   Remote Host    │
          │ (Pi, Claude, etc)│                  │  (Linux Server)  │
          └──────────────────┘                  └──────────────────┘
```

---

## 3. SSH Security Architecture

### 3.1 Host Key Verification & Anti-MITM (Man-in-the-Middle)
1. **Known Hosts Check:** On connection initiation, `ssh-mcp` reads `~/.ssh/known_hosts`.
2. **Match Evaluation:**
   * **`Match`:** Connection proceeds without interruption.
   * **`NotFound` (New Host):** Rather than blindly accepting, `ssh-mcp` calculates the host's public key SHA-256 fingerprint (`SHA256:xxxx...`).
     * In TUI mode: Prompts a **Trust-On-First-Use (TOFU) confirmation dialog** showing the remote host IP, port, and fingerprint (`[y/n]`).
     * In Headless mode: Rejects connection unless `tofu_auto_accept = true` is explicitly configured in `config.toml`.
   * **`Mismatch` (Changed Key / MITM Warning):** Triggers a high-priority security alert. The connection is halted immediately.

### 3.2 Credential Hygiene & Memory Zeroization
* Passwords and private key passphrases entered interactively are stored in `zeroize::Zeroizing<String>`.
* The allocated memory buffers are guaranteed to be cryptographically scrubbed (overwritten with zeroes) immediately after authentication completes or fails.
* Plaintext passwords are **never written to disk** or serialized into `config.toml`.

### 3.3 Multiple Authentication Methods
1. **Interactive Password Authentication:** Input is masked with asterisks/bullets (`••••••`).
2. **SSH Public Key Authentication:** Supports `id_ed25519`, `id_rsa`, `id_ecdsa` with optional passphrase.
3. **SSH Agent Integration:** Uses `SSH_AUTH_SOCK` to authenticate without private keys touching the application.

### 3.4 Connection Integrity & Anti-Zombie Keepalive
* Sets TCP keepalive probes every 15 seconds to detect dropped links.
* If a remote execution times out or is canceled by the operator, the server attempts sending a remote `SIGINT`/`SIGTERM` to the remote channel before closing to prevent orphaned zombie processes.

---

## 4. AI Agent Security & Guardrails

### 4.1 Four-Tier Risk Classification Engine

Every incoming tool call (especially `ssh_exec`) is parsed and classified before execution:

| Risk Tier | Label | Command Examples | Action / Behavior |
|---|---|---|---|
| **Tier 0** | `SAFE` | `ls`, `cat`, `head`, `tail`, `grep`, `find`, `pwd`, `whoami`, `uptime`, `free`, `df`, `ps`, `uname`, `stat`, `date`, `wc` | **Auto-Allowed** in all operational modes (except Read-Only if writing). |
| **Tier 1** | `MUTATING` | `mkdir`, `touch`, `cp`, `mv`, `git`, `npm`, `cargo`, `pip`, `tar`, `unzip`, `sed -i` | Auto-allowed in `HighRiskHITL` mode; prompts in `StrictHITL` mode; rejected in `ReadOnly` mode. |
| **Tier 2** | `HIGH_RISK` | `rm -rf`, `sudo`, `su`, `chmod 777`, `chown`, `kill`, `systemctl stop/restart`, `reboot`, `shutdown`, `iptables`, `ufw`, writes to `/etc/*` or `~/.ssh/authorized_keys`, piping commands (`curl ... \| bash`) | **Prompts Human-in-the-Loop (HITL) confirmation modal** in TUI. In headless mode, rejected unless pre-authorized. |
| **Tier 3** | `FORBIDDEN` | `:(){ :\|:& };:`, `mkfs.*`, `dd if=/dev/zero of=/dev/sd*`, raw disk writes | **Permanently Blocked.** Returns immediate structured error response to the LLM. |

### 4.2 Dynamic Policy Modes (TUI Switchable via `[p]`)
* **`HighRiskHITL` (Default):** Safe commands and standard build mutations run freely. Destructive and root actions require explicit human approval.
* **`StrictHITL`:** Every mutating or executing command requires user confirmation.
* **`ReadOnly`:** Pure inspection mode. Mutating commands, file writing, and system modifications are blocked.
* **`AuditOnly`:** Full autonomous mode. All commands (except Tier 3) execute immediately, with every action recorded to the audit log.

### 4.3 Output Limiting & Anti-Context Window Flooding
* Default max output size: `32 KB` (32,768 bytes).
* Default max output lines: `1,500 lines`.
* Truncation Strategy: Keeps the head of the output and appends an actionable explanation:
  ```text
  [Output truncated by SSH MCP: showing first 1500 lines (32 KB) of 284 KB total.
   Remote command produced more output. Use 'grep', 'tail', or tool 'ssh_read_file'
   with offset/limit to inspect further content without flooding context.]
  ```

### 4.4 Secret Redaction (Masking)
* Automatically redacts sensitive patterns in both TUI logs and agent outputs:
  * OpenSSH / RSA / EC private key headers: `-----BEGIN [A-Z ]+ PRIVATE KEY-----`
  * Bearer tokens / JWTs: `Bearer eyJ...`
  * GitHub Personal Access Tokens: `ghp_[a-zA-Z0-9]{36}`
  * Generic API keys and password parameters: `password=...`, `token=...`

### 4.5 Structured Audit Logging
* Writes every transaction to an append-only file (default: `audit.jsonl`).
* Fields recorded:
  ```json
  {
    "timestamp": "2025-05-18T10:15:30.123Z",
    "tool": "ssh_exec",
    "command": "systemctl restart nginx",
    "risk_tier": "HIGH_RISK",
    "hitl_status": "APPROVED",
    "approved_by": "operator",
    "duration_ms": 342,
    "exit_code": 0,
    "output_bytes": 102
  }
  ```

---

## 5. MCP Tool Definitions & Schemas

The server implements Model Context Protocol version `2024-11-05` and exposes 6 specialized tools.

### 5.1 `ssh_exec`
Executes an arbitrary shell command on the remote host with output limiting, timeout handling, and environment isolation.

* **Parameters:**
  * `command` (`string`, required): The shell command line to run.
  * `cwd` (`string`, optional): Working directory for the command.
  * `timeout_secs` (`number`, optional, default 60): Maximum execution time in seconds.
  * `max_bytes` (`number`, optional, default 32768): Output byte limit before truncation.
  * `max_lines` (`number`, optional, default 1500): Output line limit before truncation.
* **Returns:**
  ```json
  {
    "stdout": "...",
    "stderr": "...",
    "exit_code": 0,
    "duration_ms": 142,
    "truncated": false
  }
  ```

### 5.2 `ssh_read_file`
Reads remote file contents via SFTP with token-efficient pagination.

* **Parameters:**
  * `path` (`string`, required): Absolute or relative remote file path.
  * `offset` (`number`, optional, default 1): Line number to start reading from (1-indexed).
  * `limit` (`number`, optional, default 500): Maximum number of lines to return.
* **Returns:**
  ```json
  {
    "path": "/etc/nginx/nginx.conf",
    "content": "...",
    "total_lines": 120,
    "start_line": 1,
    "end_line": 120,
    "has_more": false
  }
  ```

### 5.3 `ssh_write_file`
Writes or appends content to a remote file via SFTP with atomic guarantees.

* **Parameters:**
  * `path` (`string`, required): Remote destination path.
  * `content` (`string`, required): Content string to write.
  * `mode` (`string`, optional, default `"overwrite"`): One of `"overwrite"`, `"append"`, `"create_new"`.
* **Returns:**
  ```json
  {
    "path": "/var/www/index.html",
    "bytes_written": 2048,
    "mode": "overwrite"
  }
  ```

### 5.4 `ssh_list_dir`
Returns structured metadata for items in a remote directory, avoiding text parsing of `ls`.

* **Parameters:**
  * `path` (`string`, optional, default `"."`): Remote directory path.
* **Returns:**
  ```json
  {
    "path": "/var/log",
    "entries": [
      {
        "name": "nginx",
        "is_dir": true,
        "size": 4096,
        "permissions": "0755",
        "modified": 1716024930
      }
    ]
  }
  ```

### 5.5 `ssh_system_info`
Fetches a high-level snapshot of the remote server's health and architecture in a single call.

* **Parameters:** None.
* **Returns:**
  ```json
  {
    "hostname": "ubuntu-vps",
    "os_release": "Ubuntu 24.04 LTS (Noble Numbat)",
    "kernel": "Linux 6.8.0-31-generic",
    "cpu_model": "AMD EPYC 7763 64-Core Processor",
    "cpu_cores": 4,
    "memory_total_mb": 8192,
    "memory_free_mb": 4510,
    "disk_root_used": "18G",
    "disk_root_avail": "62G",
    "disk_root_pct": "23%",
    "uptime": "14 days, 3 hours",
    "load_average": "0.12, 0.08, 0.05"
  }
  ```

### 5.6 `ssh_stat`
Inspects remote file/directory attributes without reading content.

* **Parameters:**
  * `path` (`string`, required): Remote path to stat.
* **Returns:**
  ```json
  {
    "path": "/etc/hosts",
    "exists": true,
    "is_dir": false,
    "is_file": true,
    "size": 256,
    "permissions": "0644",
    "modified": 1715000000
  }
  ```

---

## 6. Terminal User Interface (TUI) Specification

The TUI is built using `ratatui` with the `crossterm` backend. It handles terminal resizing, Unicode rendering, and mouse/keyboard navigation.

### 6.1 Screen 1: Connection & Authentication Form
* Rendered when started without active credentials or when switching servers.
* Fields:
  1. **Preset Selector:** Dropdown/list of presets loaded from `config.toml`.
  2. **Host:** Text input (e.g. `10.0.0.50` or `vps.example.com`).
  3. **Port:** Numeric input (default: `22`).
  4. **Username:** Text input (defaults to local `$USER`).
  5. **Auth Method:** Tabbed selection: `[Password]` | `[Key File]` | `[SSH Agent]`.
  6. **Key Path:** Path input (shown when `Key File` is selected, default `~/.ssh/id_ed25519`).
  7. **Passphrase / Password:** Masked input field (`••••••••`).
* Actions: `[Enter]` Connect, `[Tab]` Next Field, `[Esc]` Quit.
* **TOFU Modal:** Pops up if the remote host key is not in `~/.ssh/known_hosts`, showing the SHA-256 fingerprint with `[y] Accept & Save` and `[n] Abort`.

### 6.2 Screen 2: Live Operational Dashboard
* **Header Bar:**
  * Status indicator: `🟢 CONNECTED` or `🔴 DISCONNECTED`.
  * Remote host: `username@hostname:port`.
  * Latency estimate and active Security Policy mode.
* **MCP Server Information Panel:**
  * Endpoint URL: `http://127.0.0.1:8765/mcp`.
  * Pi Agent Quick Setup snippet: `pi mcp add -l ssh --url http://127.0.0.1:8765/mcp`.
  * Active MCP clients count and total processed tool calls.
* **Remote System Quick Stats:**
  * OS distro, CPU cores, RAM usage gauge, disk space free, load average.
* **Live Audit Stream Table:**
  * Columns: `Time`, `Tool`, `Risk`, `Command/Detail`, `Status`, `Duration`.
  * Visual badges: `[SAFE]` (green), `[MUTATE]` (cyan), `[HIGH RISK]` (red/bold), `[BLOCKED]` (magenta).
* **Human-in-the-Loop (HITL) Modal Dialog:**
  * When a high-risk tool call arrives, execution pauses asynchronously and an attention-grabbing modal is displayed centered on screen:
    ```text
    ┌────────────────────── ⚠️ HUMAN APPROVAL REQUIRED ──────────────────────┐
    │                                                                       │
    │  The AI Agent is requesting to execute a high-risk command:           │
    │                                                                       │
    │  > rm -rf /var/www/html/cache/*                                       │
    │                                                                       │
    │  Risk Assessment: HIGH (Destructive File Deletion)                    │
    │  Origin Client:   Pi Coding Agent (127.0.0.1)                         │
    │                                                                       │
    │  [Y] Approve Once   [N] Deny Request   [A] Always Allow (This Session)│
    └───────────────────────────────────────────────────────────────────────┘
    ```
  * Resolves the pending async tool call immediately upon keypress.
* **Global Footer Keybindings:**
  * `[p]` Cycle Security Policy Mode
  * `[r]` Refresh System Information
  * `[c]` Clear Audit Table
  * `[q]` / `[Ctrl+C]` Graceful Shutdown

---

## 7. Configuration Specification (`config.toml`)

The configuration file is **optional**. If absent, defaults are applied.

```toml
# config.toml
[general]
mode = "tui"              # "tui" or "headless"
mcp_port = 8765           # Local port for MCP Streamable HTTP / SSE server
mcp_bind = "127.0.0.1"    # Loopback bind address for local security

[security]
hitl_mode = "high_risk"   # "high_risk" | "strict" | "read_only" | "audit_only"
command_timeout_secs = 60
max_output_bytes = 32768  # 32 KB safety ceiling
max_output_lines = 1500
audit_log_path = "audit.jsonl"
tofu_auto_accept = false  # If true, auto-accepts new host keys in headless mode
mask_secrets = true

forbidden_commands = [
    ":(){ :|:& };:",
    "mkfs",
    "dd if=/dev/zero"
]

# Preset remote hosts selectable in TUI
[servers.example-server]
host = "ssh.example.com"
port = 22
username = "user"
auth_method = "agent"

# [servers.production-vps]
# host = "vps.example.com"
# port = 2222
# username = "user"
# auth_method = "key"
# key_path = "~/.ssh/id_ed25519"
# Note: Passwords are NEVER saved to TOML!
```

---

## 8. CLI Arguments & Dual-Mode Execution

* `./ssh-mcp` (Default): Runs in foreground with interactive TUI.
* `./ssh-mcp -b` or `./ssh-mcp --background`: Runs as a background daemon (headless, no TUI).
* `./ssh-mcp --stdio`: Operates in stdio transport mode for MCP clients spawning subprocesses directly.
* CLI options override `config.toml` options:
  * `-c, --config <PATH>`
  * `-H, --host <HOST>`
  * `-P, --port <PORT>`
  * `-u, --user <USER>`
  * `-k, --key <KEY_PATH>`
  * `--mcp-port <PORT>`
  * `--policy <POLICY>`
