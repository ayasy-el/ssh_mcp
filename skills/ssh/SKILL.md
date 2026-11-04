---
name: ssh
description: Interact with remote servers via SSH & SFTP tools (mcp__ssh__ssh_exec, mcp__ssh__ssh_system_info, mcp__ssh__ssh_read_file, mcp__ssh__ssh_write_file, mcp__ssh__ssh_list_dir, mcp__ssh__ssh_stat). Use when the user asks to inspect a remote server, run commands on an SSH host, view remote logs, transfer or edit remote files, or perform remote deployments and troubleshooting.
allowed-tools:
  - mcp__ssh__ssh_exec
  - mcp__ssh__ssh_system_info
  - mcp__ssh__ssh_read_file
  - mcp__ssh__ssh_write_file
  - mcp__ssh__ssh_list_dir
  - mcp__ssh__ssh_stat
---

# Remote Server Management via SSH & SFTP

This skill provides operational guidance, workflows, and tool instructions for administering remote servers connected through `ssh-mcp`.

## Direct Tool Invocation (Zero-Discovery)

All tools are immediately accessible under the `mcp__ssh__*` namespace.
**Do NOT call `searchTools()` or search discovery functions.** Invoke the tools directly:

| Tool Name | Purpose | Example Parameters |
|---|---|---|
| `mcp__ssh__ssh_system_info` | Snapshot of OS, kernel, CPU cores, RAM, and root disk | `{}` |
| `mcp__ssh__ssh_exec` | Execute shell command on remote machine | `{ command: "uptime", cwd?: "/var/www" }` |
| `mcp__ssh__ssh_read_file` | Read remote file via SFTP (paginated) | `{ path: "/etc/os-release", limit: 50 }` |
| `mcp__ssh__ssh_write_file` | Write or append file via SFTP | `{ path: "/tmp/test.txt", content: "...", mode: "overwrite" }` |
| `mcp__ssh__ssh_list_dir` | Structured directory listing (JSON metadata) | `{ path: "/var/log" }` |
| `mcp__ssh__ssh_stat` | Check file existence, size, and permissions | `{ path: "/etc/hosts" }` |

### Calling from Codemode
If executing inside a `codemode` script, invoke `tools.mcp__ssh__<name>` directly:
```javascript
// Example: Run uptime directly
const res = await tools.mcp__ssh__ssh_exec({ command: "uptime" });
const out = JSON.parse(res.content[0].text);
text(out.stdout);

// Example: Get system info
const info = await tools.mcp__ssh__ssh_system_info({});
text(JSON.stringify(info, null, 2));
```

---

## Standard Workflows & Best Practices

### 1. Server Reconnaissance & Health Checks
- For uptime, specs, memory, or disk usage, call `mcp__ssh__ssh_system_info` or `mcp__ssh__ssh_exec({ command: "uptime" })` on your first turn.
- Reports OS distribution, kernel, CPU cores, free RAM, and root disk in a single turn without wasting shell execution tokens.

### 2. File Inspection & Token-Efficient Reading
- Use `mcp__ssh__ssh_list_dir` instead of `mcp__ssh__ssh_exec({ command: "ls -la" })` to get clean JSON with sizes, permissions, and timestamps.
- When viewing logs or config files, call `mcp__ssh__ssh_read_file` with `limit: 50` or `100` rather than running `cat`. This prevents flooding your context window on large files.
- To read next chunks, pass `offset: <next_line>` based on the `has_more` response.

### 3. File Modification & Deployment
- Always inspect the existing file content using `mcp__ssh__ssh_read_file` before writing.
- Use `mcp__ssh__ssh_write_file` with `mode: "overwrite"` or `"append"`.
- For git or project directories, use `mcp__ssh__ssh_exec` with the `cwd` parameter pointing to the project folder rather than chaining multiple `cd <dir> && ...` commands.

### 4. Handling High-Risk Operations
- Commands matching high-risk signatures (e.g. `sudo`, `systemctl restart`, `kill`, recursive deletions, or modifications to `/etc/*`) will pause for operator approval in the `ssh-mcp` TUI if running in `High-Risk HITL` mode.
- Explain clearly what actions you are about to take so the operator can review and approve them on their terminal interface.
- If the server is in `Autonomous (No Approval)` mode, all actions execute immediately.
