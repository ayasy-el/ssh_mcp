use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::{CheckResult, KnownHostFileKind, Session};
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    Password,
    KeyFile,
    Agent,
}

impl Default for AuthMethod {
    fn default() -> Self {
        AuthMethod::Agent
    }
}

pub enum HostKeyStatus {
    Trusted,
    NewHost {
        host: String,
        port: u16,
        fingerprint_sha256: String,
        raw_key: Vec<u8>,
        key_type: ssh2::HostKeyType,
    },
    Mismatch {
        host: String,
        port: u16,
        fingerprint_sha256: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub truncated: bool,
    pub original_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReadResult {
    pub path: String,
    pub content: String,
    pub total_lines: usize,
    pub start_line: usize,
    pub end_line: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub size: u64,
    pub permissions: String,
    pub modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResult {
    pub path: String,
    pub exists: bool,
    pub is_dir: bool,
    pub is_file: bool,
    pub size: u64,
    pub permissions: String,
    pub modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSysInfo {
    pub hostname: String,
    pub os_release: String,
    pub kernel: String,
    pub cpu_cores: usize,
    pub memory_total_mb: u64,
    pub memory_free_mb: u64,
    pub disk_root_used: String,
    pub disk_root_avail: String,
    pub disk_root_pct: String,
    pub uptime: String,
}

pub struct SshClient {
    session: Arc<Mutex<Session>>,
    host: String,
    port: u16,
    username: String,
}

impl SshClient {
    /// Step 1: Establishes TCP connection and checks host key against known_hosts.
    pub fn connect_and_check_host_key(
        host: &str,
        port: u16,
    ) -> Result<(Session, HostKeyStatus)> {
        let tcp = TcpStream::connect(format!("{}:{}", host, port))
            .with_context(|| format!("Failed to connect to {}:{}", host, port))?;
        tcp.set_nodelay(true)?;

        let mut session = Session::new().context("Failed to create SSH session")?;
        session.set_tcp_stream(tcp);
        session.handshake().context("SSH handshake failed")?;

        // Calculate SHA-256 fingerprint
        let (raw_key, key_type) = session
            .host_key()
            .ok_or_else(|| anyhow!("Remote server did not provide a host key"))?;
        let mut hasher = Sha256::new();
        hasher.update(raw_key);
        let fingerprint = format!("SHA256:{}", hex::encode(hasher.finalize()));

        // Check known_hosts
        let known_hosts_path = dirs::home_dir()
            .map(|h| h.join(".ssh").join("known_hosts"))
            .unwrap_or_else(|| PathBuf::from("known_hosts"));

        let mut known_hosts = session.known_hosts()?;
        if known_hosts_path.is_file() {
            let _ = known_hosts.read_file(&known_hosts_path, KnownHostFileKind::OpenSSH);
        }

        let check_res = known_hosts.check_port(host, port, raw_key);
        let status = match check_res {
            CheckResult::Match => HostKeyStatus::Trusted,
            CheckResult::NotFound => HostKeyStatus::NewHost {
                host: host.to_string(),
                port,
                fingerprint_sha256: fingerprint,
                raw_key: raw_key.to_vec(),
                key_type,
            },
            CheckResult::Mismatch => HostKeyStatus::Mismatch {
                host: host.to_string(),
                port,
                fingerprint_sha256: fingerprint,
            },
            CheckResult::Failure => {
                return Err(anyhow!("Failed while checking known_hosts file"));
            }
        };

        Ok((session, status))
    }

    /// Saves a newly accepted host key into ~/.ssh/known_hosts
    pub fn save_known_host(
        session: &Session,
        host: &str,
        port: u16,
        raw_key: &[u8],
        key_type: ssh2::HostKeyType,
    ) -> Result<()> {
        let known_hosts_path = dirs::home_dir()
            .map(|h| h.join(".ssh").join("known_hosts"))
            .unwrap_or_else(|| PathBuf::from("known_hosts"));

        if let Some(parent) = known_hosts_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut known_hosts = session.known_hosts()?;
        if known_hosts_path.is_file() {
            let _ = known_hosts.read_file(&known_hosts_path, KnownHostFileKind::OpenSSH);
        }

        // Add with custom port formatting if not standard 22
        let host_pattern = if port == 22 {
            host.to_string()
        } else {
            format!("[{}]:{}", host, port)
        };

        let fmt = match key_type {
            ssh2::HostKeyType::Rsa => ssh2::KnownHostKeyFormat::SshRsa,
            ssh2::HostKeyType::Dss => ssh2::KnownHostKeyFormat::SshDss,
            ssh2::HostKeyType::Ecdsa256 => ssh2::KnownHostKeyFormat::Ecdsa256,
            ssh2::HostKeyType::Ecdsa384 => ssh2::KnownHostKeyFormat::Ecdsa384,
            ssh2::HostKeyType::Ecdsa521 => ssh2::KnownHostKeyFormat::Ecdsa521,
            ssh2::HostKeyType::Ed25519 => ssh2::KnownHostKeyFormat::Ed25519,
            _ => ssh2::KnownHostKeyFormat::Unknown,
        };

        known_hosts.add(
            &host_pattern,
            raw_key,
            &format!("ssh-mcp added on {}", chrono::Utc::now().to_rfc3339()),
            fmt,
        )?;

        known_hosts.write_file(&known_hosts_path, KnownHostFileKind::OpenSSH)?;
        Ok(())
    }

    /// Authenticates the SSH session using the given credentials
    pub fn authenticate(
        session: Session,
        host: &str,
        port: u16,
        username: &str,
        auth_method: &AuthMethod,
        password: Option<Zeroizing<String>>,
        key_path: Option<&str>,
        passphrase: Option<Zeroizing<String>>,
    ) -> Result<Self> {
        match auth_method {
            AuthMethod::Password => {
                let pass = password.ok_or_else(|| anyhow!("Password is required for password authentication"))?;
                session
                    .userauth_password(username, pass.as_str())
                    .context("Authentication failed with provided password")?;
            }
            AuthMethod::KeyFile => {
                let privkey_str = key_path.ok_or_else(|| anyhow!("Key file path is required"))?;
                let expanded_path = if privkey_str.starts_with("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(&privkey_str[2..]))
                        .unwrap_or_else(|| PathBuf::from(privkey_str))
                } else {
                    PathBuf::from(privkey_str)
                };

                if !expanded_path.is_file() {
                    return Err(anyhow!("Private key file not found at: {:?}", expanded_path));
                }

                let pubkey_path = expanded_path.with_extension("pub");
                let pubkey = if pubkey_path.is_file() {
                    Some(pubkey_path.as_path())
                } else {
                    None
                };

                let pass_ref = passphrase.as_ref().map(|p| p.as_str());
                session
                    .userauth_pubkey_file(username, pubkey, &expanded_path, pass_ref)
                    .context("Failed authenticating with private key")?;
            }
            AuthMethod::Agent => {
                session
                    .userauth_agent(username)
                    .context("Failed authenticating with SSH Agent (is SSH_AUTH_SOCK set?)")?;
            }
        }

        if !session.authenticated() {
            return Err(anyhow!("SSH authentication could not be completed"));
        }

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            host: host.to_string(),
            port,
            username: username.to_string(),
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    /// Executes a remote shell command with timeout, output limiting, and duration tracking.
    pub fn exec(
        &self,
        command: &str,
        cwd: Option<&str>,
        timeout_secs: u64,
        max_bytes: usize,
        max_lines: usize,
    ) -> Result<ExecResult> {
        let full_command = match cwd {
            Some(dir) if !dir.trim().is_empty() => {
                let quoted_dir = shlex::try_quote(dir.trim())
                    .unwrap_or_else(|_| format!("'{}'", dir.replace('\'', "'\\''")).into());
                format!("cd -- {} && {}", quoted_dir, command)
            }
            _ => command.to_string(),
        };

        let start_time = Instant::now();
        let sess = self.session.lock().map_err(|_| anyhow!("Session mutex poisoned"))?;

        // Set native libssh2 session timeout to avoid deadlocks
        let timeout_ms = (timeout_secs * 1000).min(u32::MAX as u64) as u32;
        sess.set_timeout(timeout_ms);

        let res = (|| -> Result<(String, String, i32)> {
            let mut channel = sess.channel_session()?;
            channel.exec(&full_command)?;

            let mut stdout_bytes = Vec::new();
            let mut stderr_bytes = Vec::new();

            channel.read_to_end(&mut stdout_bytes)?;
            channel.stderr().read_to_end(&mut stderr_bytes)?;

            let _ = channel.wait_close();
            let exit_code = channel.exit_status().unwrap_or(0);

            // Clean ANSI escape codes from output
            let stdout_raw = String::from_utf8_lossy(&stdout_bytes);
            let stderr_raw = String::from_utf8_lossy(&stderr_bytes);

            let stdout_clean = crate::security::strip_ansi_escapes(&stdout_raw);
            let stderr_clean = crate::security::strip_ansi_escapes(&stderr_raw);

            Ok((stdout_clean, stderr_clean, exit_code))
        })();

        // Reset session timeout back to 0 (default)
        sess.set_timeout(0);

        let (stdout_clean, stderr_clean, exit_code) = res?;
        let duration_ms = start_time.elapsed().as_millis() as u64;

        let (stdout, truncated_out, orig_bytes_out) =
            crate::security::limit_output(&stdout_clean, max_bytes, max_lines);
        let (stderr, _, _) =
            crate::security::limit_output(&stderr_clean, max_bytes / 2, max_lines / 2);

        Ok(ExecResult {
            stdout,
            stderr,
            exit_code,
            duration_ms,
            truncated: truncated_out,
            original_bytes: orig_bytes_out,
        })
    }

    /// Reads remote file via SFTP with streaming line pagination (offset 1-indexed, limit).
    /// Prevents reading multi-gigabyte files into RAM.
    pub fn read_file(&self, path: &str, offset: usize, limit: usize) -> Result<FileReadResult> {
        let sess = self.session.lock().map_err(|_| anyhow!("Session mutex poisoned"))?;
        let sftp = sess.sftp()?;
        let file = sftp.open(Path::new(path))
            .with_context(|| format!("Failed to open remote file: {}", path))?;

        let start_line = if offset == 0 { 1 } else { offset };
        let start_idx = start_line - 1;

        let reader = BufReader::new(file);
        let mut selected_lines = Vec::new();
        let mut total_lines = 0;
        let mut current_bytes = 0;
        const MAX_TOTAL_BYTES: usize = 5 * 1024 * 1024; // 5 MB safety ceiling per read

        for line_res in reader.lines() {
            let line = line_res?;
            total_lines += 1;

            if total_lines > start_idx && selected_lines.len() < limit {
                current_bytes += line.len() + 1;
                if current_bytes <= MAX_TOTAL_BYTES {
                    selected_lines.push(line);
                }
            }
        }

        if start_idx >= total_lines && total_lines > 0 {
            return Err(anyhow!(
                "Offset {} is beyond end of file (total lines: {})",
                offset,
                total_lines
            ));
        }

        let end_line = start_line + selected_lines.len().saturating_sub(1);
        let has_more = end_line < total_lines;

        let mut output = selected_lines.join("\n");
        if has_more {
            output.push_str(&format!(
                "\n\n[Showing lines {}-{} of {} lines total. Use offset={} to read next chunk.]",
                start_line,
                end_line,
                total_lines,
                end_line + 1
            ));
        }

        Ok(FileReadResult {
            path: path.to_string(),
            content: output,
            total_lines,
            start_line,
            end_line,
            has_more,
        })
    }

    /// Writes content to remote file via SFTP with overwrite, append, or create_new modes.
    pub fn write_file(&self, path: &str, content: &str, mode: &str) -> Result<usize> {
        use std::io::Write;
        let sess = self.session.lock().map_err(|_| anyhow!("Session mutex poisoned"))?;
        let sftp = sess.sftp()?;

        let flags = match mode {
            "append" => ssh2::OpenFlags::WRITE | ssh2::OpenFlags::CREATE | ssh2::OpenFlags::APPEND,
            "create_new" => ssh2::OpenFlags::WRITE | ssh2::OpenFlags::CREATE | ssh2::OpenFlags::EXCLUSIVE,
            _ => ssh2::OpenFlags::WRITE | ssh2::OpenFlags::CREATE | ssh2::OpenFlags::TRUNCATE,
        };

        let mut file = sftp.open_mode(Path::new(path), flags, 0o644, ssh2::OpenType::File)
            .with_context(|| format!("Failed to open/create remote file for writing: {}", path))?;

        let bytes = content.as_bytes();
        file.write_all(bytes)?;
        file.flush()?;

        Ok(bytes.len())
    }

    /// Lists directory entries with structured metadata.
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntryInfo>> {
        let sess = self.session.lock().map_err(|_| anyhow!("Session mutex poisoned"))?;
        let sftp = sess.sftp()?;
        let entries = sftp.readdir(Path::new(path))
            .with_context(|| format!("Failed to read directory: {}", path))?;

        let mut result = Vec::new();
        for (item_path, stat) in entries {
            let name = item_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| item_path.to_string_lossy().to_string());

            if name == "." || name == ".." {
                continue;
            }

            let is_dir = stat.is_dir();
            let is_file = stat.is_file();
            let size = stat.size.unwrap_or(0);
            let perm = stat.perm.unwrap_or(0o644) & 0o7777;
            let permissions = format!("{:04o}", perm);
            let modified = stat.mtime.unwrap_or(0);

            result.push(DirEntryInfo {
                name,
                is_dir,
                is_file,
                size,
                permissions,
                modified,
            });
        }

        // Sort directories first, then alphabetical
        result.sort_by(|a, b| {
            if a.is_dir != b.is_dir {
                b.is_dir.cmp(&a.is_dir)
            } else {
                a.name.cmp(&b.name)
            }
        });

        Ok(result)
    }

    /// Stats a file or directory.
    pub fn stat(&self, path: &str) -> Result<StatResult> {
        let sess = self.session.lock().map_err(|_| anyhow!("Session mutex poisoned"))?;
        let sftp = sess.sftp()?;
        match sftp.stat(Path::new(path)) {
            Ok(stat) => {
                let perm = stat.perm.unwrap_or(0o644) & 0o7777;
                Ok(StatResult {
                    path: path.to_string(),
                    exists: true,
                    is_dir: stat.is_dir(),
                    is_file: stat.is_file(),
                    size: stat.size.unwrap_or(0),
                    permissions: format!("{:04o}", perm),
                    modified: stat.mtime.unwrap_or(0),
                })
            }
            Err(_) => Ok(StatResult {
                path: path.to_string(),
                exists: false,
                is_dir: false,
                is_file: false,
                size: 0,
                permissions: "0000".to_string(),
                modified: 0,
            }),
        }
    }

    /// Fetches system health & specs in a single lightweight execution.
    pub fn system_info(&self) -> Result<RemoteSysInfo> {
        let script = r#"
            echo "---HOSTNAME---"
            hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown"
            echo "---OS---"
            if [ -f /etc/os-release ]; then
                . /etc/os-release && echo "${PRETTY_NAME:-$NAME}"
            else
                uname -s
            fi
            echo "---KERNEL---"
            uname -r
            echo "---CORES---"
            nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1
            echo "---MEM---"
            free -m 2>/dev/null | awk '/Mem:/ {print $2, $7}' || echo "0 0"
            echo "---DISK---"
            df -h / 2>/dev/null | awk 'NR==2 {print $3, $4, $5}' || echo "0 0 0%"
            echo "---UPTIME---"
            uptime -p 2>/dev/null || uptime 2>/dev/null || echo "unknown"
        "#;

        let res = self.exec(script, None, 10, 16384, 100)?;
        let lines: Vec<&str> = res.stdout.lines().map(|l| l.trim()).collect();

        let mut hostname = "unknown".to_string();
        let mut os_release = "Linux".to_string();
        let mut kernel = "".to_string();
        let mut cpu_cores = 1;
        let mut memory_total_mb = 0;
        let mut memory_free_mb = 0;
        let mut disk_root_used = "0".to_string();
        let mut disk_root_avail = "0".to_string();
        let mut disk_root_pct = "0%".to_string();
        let mut uptime = "".to_string();

        let mut current_section = "";
        for line in lines {
            if line.starts_with("---") && line.ends_with("---") {
                current_section = line;
                continue;
            }
            if line.is_empty() {
                continue;
            }

            match current_section {
                "---HOSTNAME---" => hostname = line.to_string(),
                "---OS---" => os_release = line.to_string(),
                "---KERNEL---" => kernel = line.to_string(),
                "---CORES---" => cpu_cores = line.parse().unwrap_or(1),
                "---MEM---" => {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        memory_total_mb = parts[0].parse().unwrap_or(0);
                        memory_free_mb = parts[1].parse().unwrap_or(0);
                    }
                }
                "---DISK---" => {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        disk_root_used = parts[0].to_string();
                        disk_root_avail = parts[1].to_string();
                        disk_root_pct = parts[2].to_string();
                    }
                }
                "---UPTIME---" => uptime = line.to_string(),
                _ => {}
            }
        }

        Ok(RemoteSysInfo {
            hostname,
            os_release,
            kernel,
            cpu_cores,
            memory_total_mb,
            memory_free_mb,
            disk_root_used,
            disk_root_avail,
            disk_root_pct,
            uptime,
        })
    }
}
