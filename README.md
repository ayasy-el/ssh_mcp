<div align="center">

# ssh-mcp

### SSH & SFTP Model Context Protocol (MCP) Server with Interactive TUI

[![Release](https://img.shields.io/github/v/release/ayasy-el/ssh_mcp?color=7aa2f7&style=flat-square)](https://github.com/ayasy-el/ssh_mcp/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/ayasy-el/ssh_mcp/release.yml?branch=main&label=CI&style=flat-square)](https://github.com/ayasy-el/ssh_mcp/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-9ece6a.svg?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-e0af68?logo=rust&logoColor=white&style=flat-square)](Cargo.toml)
[![MCP](https://img.shields.io/badge/MCP-JSON--RPC%202.0-7dcfff?style=flat-square)](https://modelcontextprotocol.io/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-bb9af7?style=flat-square)](#-quickstart--installation)

<br />

<img src="docs/demo.gif" alt="ssh-mcp Interactive TUI Demo" width="900" style="max-width: 100%;">

<p>
  <i>Interactive TUI: Session history selection, masked password entry, live command auditing, and HITL approval dialog.</i>
</p>

<br />

<p align="center">
  <b>ssh-mcp</b> is a Model Context Protocol (MCP) server written in Rust that allows AI coding assistants (such as <b>Pi Coding Agent</b>, Claude Desktop, Cursor, and Zed) to execute shell commands, inspect directories, and edit files on remote servers via SSH and SFTP.<br /><br />
  It runs as a <b>single static binary</b> featuring an interactive <b>Terminal User Interface (Ratatui, Tokyo Night)</b> by default, with secure credential handling (memory zeroization), live command auditing, customizable Human-in-the-Loop (HITL) safety tiers, and headless daemon / stdio modes.
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quickstart--installation">Quickstart</a> •
  <a href="#-connecting-to-ai-agents">Connecting Agents</a> •
  <a href="#-example-prompts">Example Prompts</a> •
  <a href="#-tui-dashboard--keybindings">Keybindings</a> •
  <a href="#-security-policies--custom-rules">Security & HITL</a> •
  <a href="#-cli-reference">CLI Reference</a>
</p>

</div>

---

## ✨ Features

* 🖥️ **Interactive Terminal UI:** Built with Ratatui in a Tokyo Night palette. Enter credentials securely with masked typing (`••••`), monitor remote server resource usage, and inspect agent activity in real time.
* 🕒 **Session History:** Automatically saves connection targets (host, port, username, auth method) after each successful session. Instantly select from recent sessions with `[Space]` or `[←]`/`[→]`—no need to re-type or edit config files, while passwords remain strictly manual.
* 🛡️ **SSH Security & Credential Hygiene:**
  * **Known Hosts & TOFU:** Checks `~/.ssh/known_hosts`. Prompts an interactive Trust-On-First-Use (TOFU) SHA-256 fingerprint verification dialog before connecting to unknown hosts. Aborts immediately if host keys change.
  * **Memory Zeroization:** Interactive passwords and passphrases are handled using `zeroize` and scrubbed from RAM immediately after authentication completes.
  * **No Plaintext Passwords on Disk:** Configuration files never store plaintext passwords.
  * **Secret Redaction:** Automatically masks private keys, JWTs, and API credentials from command outputs and display logs.
* 🤖 **Command Safety & Approval Modes:**
  * **Risk Engine:** Classifies incoming commands into risk tiers (`SAFE`, `MUTATING`, `HIGH_RISK`, `FORBIDDEN`).
  * **Human-in-the-Loop (HITL) Dialog:** In HITL modes, destructive actions (`rm -rf`, `sudo`, `kill`, `chmod 777`) pause for operator approval in the TUI (`[Y]` Approve, `[N]` Deny, `[A]` Allow for session).
  * **Autonomous Mode:** Run with `--no-approval` for fully automated workflows without permission prompts.
  * **Anti-Context Flooding:** Truncates excessive command outputs (default: 32 KB / 1,500 lines) with actionable continuation instructions to protect the LLM context window.
* 🧰 **MCP Tool Suite:**
  * `ssh_exec`: Run shell commands with directory (`cwd`), timeout, and environment isolation.
  * `ssh_read_file`: Token-efficient paginated file reading via SFTP (`offset` and `limit`).
  * `ssh_write_file`: Atomic file writing and appending via SFTP.
  * `ssh_list_dir`: Structured directory listing with file sizes, permissions, and timestamps.
  * `ssh_system_info`: Snapshot of remote OS, CPU cores, RAM, and root disk usage.
  * `ssh_stat`: Inspect file or directory attributes without reading contents.
* ⚙️ **Dual Execution Modes:**
  * **Foreground TUI (Default):** Interactive dashboard with full operator oversight.
  * **Background Daemon (`-b` / `--background`):** Headless execution for servers and automated scripts.
  * **Subprocess Stdio (`--stdio`):** Pipe-based transport for standard MCP spawners.
* 🌐 **Streamable HTTP & SSE Transport:** Fully compatible with Pi Agent's Streamable HTTP (`http://127.0.0.1:8765/mcp`) and standard SSE clients.

---

## 🚀 Quickstart & Installation

Pre-built binaries are available for Linux, macOS, and Windows via GitHub Releases.

### 1. ⚡ One-Line Installer (Recommended)

#### Linux & macOS:
```bash
curl -fsSL https://raw.githubusercontent.com/ayasy-el/ssh_mcp/main/install.sh | bash
```
*Detects your OS and architecture, downloads the release binary to `~/.local/bin`, and configures Pi Coding Agent integrations.*

#### Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/ayasy-el/ssh_mcp/main/install.ps1 | iex
```

---

### 2. 📦 Manual Download from GitHub Releases

Download the archive matching your platform from the [Releases Page](https://github.com/ayasy-el/ssh_mcp/releases):

| Platform | Architecture | Archive |
|---|---|---|
| **Linux** | x86_64 (Intel/AMD) | `ssh-mcp-linux-x86_64.tar.gz` |
| **Linux** | ARM64 / aarch64 | `ssh-mcp-linux-aarch64.tar.gz` |
| **macOS** | Apple Silicon (M1/M2/M3/M4) | `ssh-mcp-macos-arm64.tar.gz` |
| **macOS** | Intel | `ssh-mcp-macos-x86_64.tar.gz` |
| **Windows** | x86_64 | `ssh-mcp-windows-x86_64.zip` |

Extract the archive and place `ssh-mcp` (or `ssh-mcp.exe` on Windows) in your system `PATH` (such as `~/.local/bin` or `/usr/local/bin`).

---

### 3. (Optional) Build from Source

Requirements: Rust toolchain 1.75+ (`cargo` and `rustc`).

```bash
git clone https://github.com/ayasy-el/ssh_mcp.git
cd ssh_mcp
cargo build --release
# Compiled binary located at: target/release/ssh-mcp
```

---

### 4. Running the Server

Run without arguments to start the interactive TUI:
```bash
ssh-mcp
```
1. Enter the remote **Host**, **Port**, **Username**, and select the authentication method (**Password**, **Key File**, or **SSH Agent**).
2. Enter your password or passphrase (masked).
3. Press `[Enter]` to connect.
4. Once connected, the TUI switches to the **Live Dashboard**, and the MCP server starts listening on `http://127.0.0.1:8765/mcp`.

---

## 🔌 Connecting to AI Agents

Default server endpoint: **`http://127.0.0.1:8765/mcp`**

### A. Pi Coding Agent — Zero-Noise Dynamic Setup (Recommended)

Install the companion extension and skill in one command:
```bash
ssh-mcp --install-pi
```
**Why this is the best setup:**
* **Zero Clutter:** When `ssh-mcp` is not running, Pi stays 100% clean—no startup warnings (`Warning: MCP servers need attention`) and no unwanted offline badges.
* **Auto-Connection:** Whenever you launch `ssh-mcp`, Pi automatically detects it and activates tools under `direct` exposure with a status badge (`SSH: 🟢 user@host`).
* **Interactive `/ssh` Controls:**
  * Type `/ssh` to open the interactive management menu.
  * Subcommands: `/ssh status`, `/ssh policy [mode]`, `/ssh info`, `/ssh exec <cmd>`, `/ssh read <path>`, `/ssh dir [path]`, `/ssh connect`, `/ssh disconnect`.
* **Agent Skills Integration:**
  * Automatically installs `SKILL.md` to `~/.agents/skills/ssh/SKILL.md` for intelligent tool routing, or manually force it via `/skill:ssh`.

---

### B. Pi Coding Agent — Static Configuration via `mcp.json` (Optional)
If you prefer declaring the server statically in `mcp.json`:
* **Global (`~/.pi/agent/mcp.json`):**
  ```bash
  ssh-mcp --install-mcp
  # Or via pi CLI:
  pi mcp add --exposure direct ssh --url http://127.0.0.1:8765/mcp
  ```
* **Project-Local (`.pi/mcp.json` in current repo):**
  ```bash
  ssh-mcp --install-mcp --local
  # Or via pi CLI:
  pi mcp add -l --exposure direct ssh --url http://127.0.0.1:8765/mcp
  ```
*(Note: If configured statically in `mcp.json`, Pi will warn you if the server is offline when starting a session).*

---

### C. Claude Desktop
Add the server entry to `~/.config/Claude/claude_desktop_config.json` (or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):
```json
{
  "mcpServers": {
    "ssh": {
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

---

### D. Cursor & Zed
* **Cursor:** Navigate to Settings ➔ Features ➔ MCP Servers ➔ Add Server (Type: `SSE` or `HTTP`, URL: `http://127.0.0.1:8765/mcp`).
* **Zed:** Add the server configuration to your `settings.json` under `context_servers`:
  ```json
  "context_servers": {
    "ssh": {
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
  ```

---

## 💡 Example Prompts

Once connected, your AI assistant has full access to the SSH & SFTP tool suite:

### 1. Server Health & Architecture Inspection
> **Prompt:** *"Check the health of our remote server. What OS is it running, how much RAM is free, and is root disk usage okay?"*
* **Tools invoked by agent:** `ssh_system_info`
* **Result:** Agent receives structured OS release, kernel, CPU cores, RAM, and disk metrics in a single call without wasting shell execution tokens.

### 2. Remote Directory Navigation & Log Analysis
> **Prompt:** *"List the contents of `/var/log/nginx/` and check the last 50 lines of the error log."*
* **Tools invoked by agent:** `ssh_list_dir` (inspects directory metadata), followed by `ssh_read_file` or `ssh_exec` with `tail -n 50`.
* **Safety:** Automatically classified as `[SAFE]` — executes immediately.

### 3. Remote File Editing via SFTP
> **Prompt:** *"Inspect `/etc/nginx/sites-available/default` and update the client_max_body_size setting to 50M."*
* **Tools invoked by agent:** `ssh_read_file` (fetches existing configuration), followed by `ssh_write_file` (writes updated configuration via SFTP).
* **Safety:** If in `High-Risk HITL` mode, writing to `/etc/*` triggers an approval dialog on your TUI. In `Autonomous` mode, it applies immediately.

### 4. Git Repository & Deployment Workflows
> **Prompt:** *"Go to `/var/www/my-app`, pull the latest main branch, and restart the systemd service."*
* **Tools invoked by agent:** `ssh_exec` with `cwd: "/var/www/my-app"` running `git pull origin main`, followed by `sudo systemctl restart my-app`.
* **Safety:** `git pull` runs automatically (`[MUTATE]`). `sudo systemctl` triggers a `[HIGH RISK]` approval popup in the TUI (or runs directly if in `Autonomous` mode).

### 5. Process Monitoring & Troubleshooting
> **Prompt:** *"Check which process is consuming the most memory on the remote server and kill it if it's orphaned."*
* **Tools invoked by agent:** `ssh_exec` with `ps aux --sort=-%mem | head -n 10`. If a `kill` command is generated, it is classified as `[HIGH RISK]` and prompts for operator confirmation.

---

## 💻 TUI Dashboard & Keybindings

The live dashboard includes a navigable audit table for inspecting, filtering, and exporting commands:

| Keybinding | Action |
|---|---|
| `[↑]` / `[k]` | Move selection to the previous log entry |
| `[↓]` / `[j]` | Move selection to the next log entry |
| `[Enter]` / `[d]` | **Inspect Log:** Open modal showing complete command string, exit code, execution time, and output size |
| `[/]` / `[f]` | **Filter Logs:** Search and filter log entries in real time by tool, command, risk, or status |
| `[e]` | **Export Logs:** Export all live activity logs to a timestamped JSON file (`ssh-mcp-logs-*.json`) |
| `[?]` | **Help Dialog:** Toggle quick reference of keyboard shortcuts and controls |
| `[p]` | **Cycle Security Policy:** Switch between `High-Risk HITL` ➔ `Strict HITL` ➔ `Read-Only` ➔ `Autonomous (No Approval)` |
| `[r]` | Refresh remote server metrics (CPU, RAM, Disk) |
| `[c]` | Clear active search filter, or clear log display stream |
| `[y]` / `[n]` / `[a]` | Approve Once / Deny / Allow for Session on pending approval modals |
| `[Esc]` | Close active modal / return to dashboard |
| `[q]` | Disconnect and quit |

---

## 🛡️ Security Policies & Custom Rules

### Policy Modes
1. **`Autonomous (No Approval)` (`hitl_mode = "no_approval"` or `--no-approval`):**
   * Executes all commands automatically without confirmation dialogs.
   * Actions remain logged to `audit.jsonl` and visible on the TUI dashboard.
   * Recommended for automated testing, development containers, and unattended headless environments.
2. **`High-Risk HITL` (Default - `hitl_mode = "high_risk"`):**
   * Safe read-only commands (`ls`, `cat`, `grep`, `pwd`) and regular workspace modifications (`mkdir`, `git`, `cargo`, `npm`) execute automatically.
   * Destructive actions (`sudo`, `rm -rf`, `kill`, `chmod 777`, `reboot`, editing `/etc/*`) pause for human confirmation.
3. **`Strict HITL` (`hitl_mode = "strict"`):**
   * Every command that modifies files or system state requires explicit confirmation.
4. **`Read-Only` (`hitl_mode = "read_only"`):**
   * Blocks file writing (`ssh_write_file`) and any shell command altering system state. Ideal for diagnostics and security audits.

### Customizing Command Rules in `config.toml`
Create a `config.toml` file (or copy `config.example.toml`):

```toml
[security]
hitl_mode = "high_risk"

# 1. Custom Safe Commands:
# Always allowed without approval prompts
safe_commands = [
    "docker ps",
    "pm2 status",
    "cargo test",
    "pytest",
    "git diff"
]

# 2. Custom High-Risk Commands:
# Always trigger human approval before execution
high_risk_commands = [
    "kubectl delete",
    "terraform apply",
    "npm publish",
    "docker rm",
    "./deploy.sh"
]

# 3. Forbidden Commands:
# Immediately rejected under all policy modes
forbidden_commands = [
    ":(){ :|:& };:",
    "mkfs",
    "dd if=/dev/zero"
]

# Optional Host Presets:
[servers.example-server]
host = "ssh.example.com"
port = 22
username = "user"
auth_method = "agent"   # Options: "password", "key", "agent"
```

---

## 🛠️ CLI Reference

```text
Usage: ssh-mcp [OPTIONS]

Options:
  -b, --background           Run in background/headless mode (without TUI)
      --stdio                Run in stdio transport mode (for subprocess spawning)
  -c, --config <CONFIG>      Path to TOML configuration file
  -H, --host <HOST>          Remote host address
  -P, --port <PORT>          Remote SSH port [default: 22]
  -u, --user <USER>          Remote SSH username
  -k, --key <KEY>            Path to private key file
      --mcp-port <PORT>      MCP server HTTP port [default: 8765]
      --policy <POLICY>      Security policy mode [high_risk | strict | read_only | autonomous]
      --no-approval          Run in Autonomous mode (execute all commands without approval)
      --install-mcp          Register this MCP server in Pi's ~/.pi/agent/mcp.json
  -l, --local                Used with --install-mcp to configure project-local .pi/mcp.json
      --install-pi           Install the /ssh command extension into ~/.pi/agent/extensions/ssh.ts
  -h, --help                 Print help
  -V, --version              Print version
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/ayasy-el/ssh_mcp/issues).

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feat/AmazingFeature`)
3. Commit your Changes (`git commit -m 'feat: Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feat/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
