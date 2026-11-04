import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

interface HealthResponse {
  status: string;
  service: string;
  version: string;
  connected: boolean;
  remote_host: string;
  mcp_spec: string;
}

function normalizeBaseUrl(input: string): string {
  let u = input.trim();
  if (!u) return DEFAULT_BASE_URL;
  if (!u.startsWith("http://") && !u.startsWith("https://")) {
    u = `http://${u}`;
  }
  u = u.replace(/\/mcp\/?$/, "");
  u = u.replace(/\/sse\/?$/, "");
  u = u.replace(/\/+$/, "");
  return u;
}

const DEFAULT_MCP_HOST = "127.0.0.1";
const DEFAULT_MCP_PORT = 8765;
const DEFAULT_BASE_URL = `http://${DEFAULT_MCP_HOST}:${DEFAULT_MCP_PORT}`;

export default function sshExtension(pi: ExtensionAPI) {
  let activeUrl = DEFAULT_BASE_URL;

  // 1. Auto-discover SSH MCP server on session start (Zero-Noise: silent when offline)
  pi.on("session_start", async (_event, ctx) => {
    try {
      const health = await fetchHealth(activeUrl);
      if (health && health.status === "ok") {
        registerServer(pi, activeUrl);
        if (health.connected) {
          ctx.ui.setStatus("ssh", `SSH: 🟢 ${health.remote_host}`);
        } else {
          ctx.ui.setStatus("ssh", undefined);
        }
      } else {
        ctx.ui.setStatus("ssh", undefined);
      }
    } catch {
      ctx.ui.setStatus("ssh", undefined);
    }
  });

  // 2. Interactive Human-in-the-Loop (HITL) directly in Pi Agent TUI
  // Supports: Allow (Approve Once), Allow this Session, Deny
  const sessionAllowedCommands = new Set<string>();

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName === "mcp__ssh__ssh_exec") {
      const input = event.input as { command?: string; approved?: boolean; allow_session?: boolean };
      const cmd = (input?.command || "").trim();

      if (!cmd || sessionAllowedCommands.has(cmd) || input.approved) {
        return;
      }

      if (isHighRiskCommand(cmd) && ctx.hasUI) {
        const promptTitle = cmd.length > 90 ? `${cmd.slice(0, 87)}...` : cmd;
        const options = [
          "Allow once",
          "Allow for session",
          "Deny",
        ];

        const choice = await ctx.ui.select(`Execute on remote: ${promptTitle}`, options);

        if (choice === "Allow once") {
          input.approved = true;
        } else if (choice === "Allow for session") {
          sessionAllowedCommands.add(cmd);
          input.approved = true;
          input.allow_session = true;
        } else {
          return {
            block: true,
            reason: `Execution denied: ${cmd}`,
          };
        }
      }
    } else if (event.toolName === "mcp__ssh__ssh_write_file") {
      const input = event.input as { path?: string; mode?: string; approved?: boolean; allow_session?: boolean };
      const path = (input?.path || "").trim();
      const isCritical = path.startsWith("/etc") || path.includes("authorized_keys") || path.startsWith("/boot");

      if (isCritical && !sessionAllowedCommands.has(path) && !input.approved && ctx.hasUI) {
        const options = [
          "Allow once",
          "Allow for session",
          "Deny",
        ];

        const choice = await ctx.ui.select(`Write remote file: ${path}`, options);

        if (choice === "Allow once") {
          input.approved = true;
        } else if (choice === "Allow for session") {
          sessionAllowedCommands.add(path);
          input.approved = true;
          input.allow_session = true;
        } else {
          return {
            block: true,
            reason: `Write denied: ${path}`,
          };
        }
      }
    }
  });

  // 3. Register the /ssh slash command
  pi.registerCommand("ssh", {
    description: "Manage SSH MCP server, inspect remote system, or execute commands",
    getArgumentCompletions: (prefix) => {
      const subcommands = [
        { value: "status", label: "status - Check SSH MCP server health and connection" },
        { value: "policy", label: "policy [mode] - View or change security policy (autonomous, high_risk, strict, read_only)" },
        { value: "info", label: "info - Show remote OS, CPU, RAM, and Disk metrics" },
        { value: "exec", label: "exec <cmd> - Run a shell command on remote server" },
        { value: "read", label: "read <path> - View remote file via SFTP" },
        { value: "dir", label: "dir [path] - List remote directory" },
        { value: "connect", label: "connect [url] - Register/reconnect SSH MCP in Pi" },
        { value: "disconnect", label: "disconnect - Unregister SSH MCP from Pi" },
        { value: "launch", label: "launch - Guide to start ssh-mcp daemon / TUI" },
        { value: "menu", label: "menu - Open interactive menu" },
      ];
      const filtered = subcommands.filter((s) => s.value.startsWith(prefix));
      return filtered.length > 0 ? filtered : null;
    },
    handler: async (args, ctx) => {
      const trimmed = args.trim();
      const parts = trimmed.split(/\s+/);
      const subcommand = parts[0]?.toLowerCase() || "";
      const rest = parts.slice(1).join(" ");

      switch (subcommand) {
        case "status":
          await handleStatus(ctx, activeUrl);
          break;

        case "policy":
          if (rest) {
            await setPolicy(ctx, activeUrl, rest);
          } else {
            await handleSelectPolicy(ctx, activeUrl);
          }
          break;

        case "info":
          await handleSystemInfo(ctx, activeUrl);
          break;

        case "exec":
          if (!rest) {
            const cmd = await ctx.ui.input("Remote command to execute:", "uptime");
            if (cmd) await handleExec(ctx, activeUrl, cmd);
          } else {
            await handleExec(ctx, activeUrl, rest);
          }
          break;

        case "read":
          if (!rest) {
            const path = await ctx.ui.input("Remote file path to read:", "/etc/os-release");
            if (path) await handleReadFile(ctx, activeUrl, path);
          } else {
            await handleReadFile(ctx, activeUrl, rest);
          }
          break;

        case "dir":
          await handleListDir(ctx, activeUrl, rest || ".");
          break;

        case "connect":
          activeUrl = normalizeBaseUrl(rest);
          await handleConnect(pi, ctx, activeUrl);
          break;

        case "disconnect":
          handleDisconnect(pi, ctx);
          break;

        case "launch":
          await handleLaunchGuide(ctx);
          break;

        case "menu":
        case "":
          await handleInteractiveMenu(pi, ctx, activeUrl, (newUrl) => {
            activeUrl = newUrl;
          });
          break;

        default:
          ctx.ui.notify(`Unknown subcommand: '${subcommand}'. Use /ssh for interactive menu.`, "warning");
          break;
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Helpers & Handlers
// ---------------------------------------------------------------------------

function registerServer(pi: ExtensionAPI, baseUrl: string) {
  try {
    pi.registerMcpServer("ssh", {
      url: `${baseUrl}/mcp`,
      description: "SSH & SFTP remote server execution and inspection",
      exposure: "direct",
    });
  } catch {
    // Already registered or replaced
  }
}

async function fetchHealth(baseUrl: string): Promise<HealthResponse | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);
  try {
    const res = await fetch(`${baseUrl}/health`, { signal: controller.signal });
    if (!res.ok) return null;
    return (await res.json()) as HealthResponse;
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function callJsonRpcTool(baseUrl: string, name: string, args: Record<string, unknown> = {}): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 65000);
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: Date.now(),
        method: "tools/call",
        params: {
          name,
          arguments: args,
        },
      }),
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`HTTP error ${res.status}: ${res.statusText}`);
    }

    const data: any = await res.json();
    if (data.error) {
      throw new Error(data.error.message || "JSON-RPC error");
    }

    const content = data.result?.content?.[0]?.text;
    if (data.result?.isError) {
      throw new Error(content || "Tool returned error");
    }

    return content ? JSON.parse(content) : data.result;
  } finally {
    clearTimeout(timeout);
  }
}

async function handleStatus(ctx: ExtensionCommandContext, baseUrl: string) {
  const health = await fetchHealth(baseUrl);
  if (!health) {
    ctx.ui.notify(`SSH MCP server is not running on ${baseUrl}.\nStart it with 'ssh-mcp' when you need SSH.`, "info");
    ctx.ui.setStatus("ssh", undefined);
    return;
  }

  const lines = [
    `=== SSH MCP Server Status ===`,
    `Endpoint:    ${baseUrl}/mcp`,
    `Service:     ${health.service} v${health.version}`,
    `Connection:  ${health.connected ? `🟢 Connected to ${health.remote_host}` : "🟡 Standby (No active host)"}`,
    `MCP Spec:    ${health.mcp_spec}`,
  ];

  ctx.ui.notify(lines.join("\n"), health.connected ? "info" : "warning");
  if (health.connected) {
    ctx.ui.setStatus("ssh", `SSH: 🟢 ${health.remote_host}`);
  } else {
    ctx.ui.setStatus("ssh", undefined);
  }
}

async function handleConnect(pi: ExtensionAPI, ctx: ExtensionCommandContext, baseUrl: string) {
  const health = await fetchHealth(baseUrl);
  if (!health) {
    ctx.ui.notify(`Cannot reach SSH MCP at ${baseUrl}. Is 'ssh-mcp' running?`, "error");
    return;
  }

  registerServer(pi, baseUrl);
  const hostLabel = health.connected ? health.remote_host : "standby";
  ctx.ui.setStatus("ssh", `SSH: 🟢 ${hostLabel}`);
  ctx.ui.notify(`Connected to SSH MCP server (${baseUrl}). Tools are now ready for the agent!`, "info");
}

function handleDisconnect(pi: ExtensionAPI, ctx: ExtensionCommandContext) {
  try {
    pi.unregisterMcpServer("ssh");
    ctx.ui.setStatus("ssh", undefined);
    ctx.ui.notify("SSH MCP server unregistered from Pi session.", "info");
  } catch (err: any) {
    ctx.ui.notify(`Failed to disconnect: ${err.message}`, "error");
  }
}

async function handleSystemInfo(ctx: ExtensionCommandContext, baseUrl: string) {
  try {
    ctx.ui.notify("Querying remote system info...", "info");
    const info = await callJsonRpcTool(baseUrl, "ssh_system_info");
    const report = [
      `Hostname:    ${info.hostname}`,
      `OS Release:  ${info.os_release}`,
      `Kernel:      ${info.kernel}`,
      `CPU Cores:   ${info.cpu_cores}`,
      `Memory:      ${info.memory_free_mb} MB free / ${info.memory_total_mb} MB total`,
      `Disk /:      ${info.disk_root_used} used / ${info.disk_root_avail} free (${info.disk_root_pct})`,
      `Uptime:      ${info.uptime}`,
    ].join("\n");

    await ctx.ui.editor("Remote Server Specs & Health", report);
  } catch (err: any) {
    ctx.ui.notify(`Failed getting system info: ${err.message}`, "error");
  }
}

async function handleExec(ctx: ExtensionCommandContext, baseUrl: string, command: string) {
  try {
    ctx.ui.notify(`Executing on remote: '${command}'...`, "info");
    const res = await callJsonRpcTool(baseUrl, "ssh_exec", { command });

    const output = [
      `=== Exit Code: ${res.exit_code} (${res.duration_ms}ms) ===`,
      res.stdout ? `\n[stdout]\n${res.stdout}` : "",
      res.stderr ? `\n[stderr]\n${res.stderr}` : "",
    ]
      .filter(Boolean)
      .join("\n");

    await ctx.ui.editor(`Output of: ${command}`, output);
  } catch (err: any) {
    ctx.ui.notify(`Exec error: ${err.message}`, "error");
  }
}

async function handleReadFile(ctx: ExtensionCommandContext, baseUrl: string, path: string) {
  try {
    ctx.ui.notify(`Reading remote file: ${path}...`, "info");
    const res = await callJsonRpcTool(baseUrl, "ssh_read_file", { path, offset: 1, limit: 1000 });
    await ctx.ui.editor(`Remote File: ${res.path} (${res.total_lines} lines)`, res.content);
  } catch (err: any) {
    ctx.ui.notify(`Read file error: ${err.message}`, "error");
  }
}

async function handleListDir(ctx: ExtensionCommandContext, baseUrl: string, path: string) {
  try {
    ctx.ui.notify(`Listing directory: ${path}...`, "info");
    const res = await callJsonRpcTool(baseUrl, "ssh_list_dir", { path });
    const formatted = res.entries
      .map((e: any) => `${e.is_dir ? "📁 [DIR] " : "📄 [FILE]"} ${e.permissions} ${String(e.size).padStart(10)} B  ${e.name}`)
      .join("\n");

    await ctx.ui.editor(`Directory: ${res.path}`, formatted || "(empty directory)");
  } catch (err: any) {
    ctx.ui.notify(`List directory error: ${err.message}`, "error");
  }
}

async function getPolicy(baseUrl: string): Promise<string | null> {
  try {
    const res = await fetch(`${baseUrl}/policy`);
    if (!res.ok) return null;
    const data: any = await res.json();
    return data.policy || null;
  } catch {
    return null;
  }
}

async function setPolicy(ctx: ExtensionCommandContext, baseUrl: string, mode: string) {
  try {
    const res = await fetch(`${baseUrl}/policy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data: any = await res.json();
    ctx.ui.notify(`Security Policy updated to: ${data.policy}`, "info");
  } catch (err: any) {
    ctx.ui.notify(`Failed setting policy: ${err.message}`, "error");
  }
}

async function handleSelectPolicy(ctx: ExtensionCommandContext, baseUrl: string) {
  const current = await getPolicy(baseUrl);
  const options = [
    "⚡ Autonomous (No Approval) - Auto-allow all actions",
    "⚠️ High-Risk HITL - Ask approval only for destructive/root commands (Default)",
    "🔒 Strict HITL - Ask approval for all mutating commands",
    "📖 Read-Only - Block all mutations and file modifications",
  ];

  const selection = await ctx.ui.select(`Current Policy: [${current || "unknown"}]`, options);
  if (!selection) return;

  let mode = "high_risk";
  if (selection.startsWith("⚡ Autonomous")) mode = "autonomous";
  else if (selection.startsWith("🔒 Strict")) mode = "strict";
  else if (selection.startsWith("📖 Read-Only")) mode = "read_only";

  await setPolicy(ctx, baseUrl, mode);
}

async function handleLaunchGuide(ctx: ExtensionCommandContext) {
  const guide = [
    `=== How to Launch SSH-MCP ===`,
    ``,
    `Option 1: Interactive TUI (Recommended)`,
    `  $ ./target/release/ssh-mcp`,
    `  (Enter password interactively in the TUI)`,
    ``,
    `Option 2: Headless Daemon (Background)`,
    `  $ ./target/release/ssh-mcp -b -H <host> -u <user> --key ~/.ssh/id_ed25519`,
    ``,
    `Option 3: Using presets in config.toml`,
    `  $ ./target/release/ssh-mcp -c config.toml`,
    ``,
    `Once running, return to Pi and type:`,
    `  /ssh connect`,
  ].join("\n");

  await ctx.ui.editor("SSH-MCP Launch Guide", guide);
}

async function handleInteractiveMenu(
  pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
  baseUrl: string,
  setUrl: (url: string) => void,
) {
  const health = await fetchHealth(baseUrl);
  const statusLabel = health
    ? health.connected
      ? `🟢 Connected (${health.remote_host})`
      : "🟡 Standby (MCP running, no remote host)"
    : "⚪ Offline (ssh-mcp not running)";

  const options = [
    `📊 Server Status [${statusLabel}]`,
    `🛡️ Security Policy Mode`,
    `🖥️ Remote System Specs & Health`,
    `⚡ Execute Remote Command`,
    `📁 Read Remote File (SFTP)`,
    `📂 List Remote Directory (SFTP)`,
    `🔄 Reconnect / Register Server in Pi`,
    `🚀 Launch & Setup Instructions`,
    `❌ Disconnect Server from Pi`,
  ];

  const selection = await ctx.ui.select(`SSH MCP Management (${baseUrl})`, options);
  if (!selection) return;

  if (selection.startsWith("📊 Server Status")) {
    await handleStatus(ctx, baseUrl);
  } else if (selection.startsWith("🛡️ Security Policy")) {
    await handleSelectPolicy(ctx, baseUrl);
  } else if (selection.startsWith("🖥️ Remote System Specs")) {
    await handleSystemInfo(ctx, baseUrl);
  } else if (selection.startsWith("⚡ Execute Remote Command")) {
    const cmd = await ctx.ui.input("Enter remote command to execute:", "uptime");
    if (cmd) await handleExec(ctx, baseUrl, cmd);
  } else if (selection.startsWith("📁 Read Remote File")) {
    const path = await ctx.ui.input("Enter remote file path:", "/etc/os-release");
    if (path) await handleReadFile(ctx, baseUrl, path);
  } else if (selection.startsWith("📂 List Remote Directory")) {
    const path = await ctx.ui.input("Enter remote directory:", ".");
    if (path) await handleListDir(ctx, baseUrl, path);
  } else if (selection.startsWith("🔄 Reconnect")) {
    const customUrl = await ctx.ui.input("MCP Server URL (press Enter for default http://127.0.0.1:8765/mcp):", baseUrl);
    const resolved = normalizeBaseUrl(customUrl || baseUrl);
    setUrl(resolved);
    await handleConnect(pi, ctx, resolved);
  } else if (selection.startsWith("🚀 Launch")) {
    await handleLaunchGuide(ctx);
  } else if (selection.startsWith("❌ Disconnect")) {
    handleDisconnect(pi, ctx);
  }
}

function isHighRiskCommand(cmd: string): boolean {
  const trimmed = cmd.trim();
  const highRiskPatterns = [
    "sudo", "su ", "doas", "rm -r", "rm -f", "--recursive", "reboot", "shutdown",
    "poweroff", "init 0", "kill", "pkill", "killall", "systemctl stop", "systemctl restart",
    "systemctl disable", "service ", "iptables", "ufw", "nft", "chmod 777", "-R 777",
    "chown ", "/etc/shadow", "/etc/passwd", "/etc/sudoers", "authorized_keys"
  ];
  return highRiskPatterns.some((pattern) => trimmed.includes(pattern));
}
