use crate::config::{Config, HitlMode, ServerPreset};
use crate::mcp::{HitlDecision, HitlRequest, LiveLogEntry};
use crate::ssh::{AuthMethod, RemoteSysInfo, SshClient};
use std::sync::Arc;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Connect,
    Dashboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectField {
    History,
    Preset,
    Host,
    Port,
    Username,
    AuthMethod,
    KeyPath,
    Password,
    ConnectButton,
}

impl ConnectField {
    pub fn next(&self, auth: &AuthMethod) -> Self {
        match self {
            ConnectField::History => ConnectField::Preset,
            ConnectField::Preset => ConnectField::Host,
            ConnectField::Host => ConnectField::Port,
            ConnectField::Port => ConnectField::Username,
            ConnectField::Username => ConnectField::AuthMethod,
            ConnectField::AuthMethod => match auth {
                AuthMethod::Password => ConnectField::Password,
                AuthMethod::KeyFile => ConnectField::KeyPath,
                AuthMethod::Agent => ConnectField::ConnectButton,
            },
            ConnectField::KeyPath => ConnectField::Password, // Passphrase
            ConnectField::Password => ConnectField::ConnectButton,
            ConnectField::ConnectButton => ConnectField::History,
        }
    }

    pub fn prev(&self, auth: &AuthMethod) -> Self {
        match self {
            ConnectField::History => ConnectField::ConnectButton,
            ConnectField::Preset => ConnectField::History,
            ConnectField::Host => ConnectField::Preset,
            ConnectField::Port => ConnectField::Host,
            ConnectField::Username => ConnectField::Port,
            ConnectField::AuthMethod => ConnectField::Username,
            ConnectField::KeyPath => ConnectField::AuthMethod,
            ConnectField::Password => match auth {
                AuthMethod::KeyFile => ConnectField::KeyPath,
                _ => ConnectField::AuthMethod,
            },
            ConnectField::ConnectButton => match auth {
                AuthMethod::Agent => ConnectField::AuthMethod,
                _ => ConnectField::Password,
            },
        }
    }
}

pub struct TofuState {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub raw_key: Vec<u8>,
    pub key_type: ssh2::HostKeyType,
    pub session: ssh2::Session,
}

pub struct MitmState {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
}

pub struct App {
    pub config: Config,
    pub screen: Screen,

    // Connect Screen State
    pub focused_field: ConnectField,
    pub history: Vec<crate::history::SessionHistoryEntry>,
    pub selected_history: Option<usize>,
    pub presets: Vec<(String, ServerPreset)>,
    pub selected_preset: Option<usize>,
    pub host: String,
    pub port: String,
    pub username: String,
    pub auth_method: AuthMethod,
    pub key_path: String,
    pub password: Zeroizing<String>,
    pub status_message: Option<(String, bool)>, // (message, is_error)
    pub is_connecting: bool,
    pub tofu_dialog: Option<TofuState>,
    pub mitm_dialog: Option<MitmState>,

    // Dashboard State
    pub client: Option<Arc<SshClient>>,
    pub remote_info: Option<RemoteSysInfo>,
    pub live_logs: Vec<LiveLogEntry>,
    pub selected_log_index: usize,
    pub log_detail_dialog: Option<LiveLogEntry>,
    pub log_filter: String,
    pub is_filtering: bool,
    pub export_notification: Option<(String, bool)>, // (message, is_error)
    pub show_help_dialog: bool,
    pub pending_hitl: Option<HitlRequest>,
    pub total_calls: usize,
    pub should_quit: bool,

    // Communication channels
    pub hitl_rx: mpsc::Receiver<HitlRequest>,
    pub live_log_rx: mpsc::Receiver<LiveLogEntry>,
}

impl App {
    pub fn new(
        config: Config,
        hitl_rx: mpsc::Receiver<HitlRequest>,
        live_log_rx: mpsc::Receiver<LiveLogEntry>,
    ) -> Self {
        let presets: Vec<(String, ServerPreset)> = config.servers.clone().into_iter().collect();
        let default_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "ubuntu".to_string());

        let history = crate::history::SessionHistoryEntry::load_history();
        let has_history = !history.is_empty();

        let mut app = Self {
            config,
            screen: Screen::Connect,
            focused_field: if has_history { ConnectField::Password } else { ConnectField::Host },
            history,
            selected_history: None,
            presets,
            selected_preset: None,
            host: "127.0.0.1".to_string(),
            port: "22".to_string(),
            username: default_user,
            auth_method: AuthMethod::Password,
            key_path: "~/.ssh/id_ed25519".to_string(),
            password: Zeroizing::new(String::new()),
            status_message: None,
            is_connecting: false,
            tofu_dialog: None,
            mitm_dialog: None,

            client: None,
            remote_info: None,
            live_logs: Vec::new(),
            selected_log_index: 0,
            log_detail_dialog: None,
            log_filter: String::new(),
            is_filtering: false,
            export_notification: None,
            show_help_dialog: false,
            pending_hitl: None,
            total_calls: 0,
            should_quit: false,

            hitl_rx,
            live_log_rx,
        };

        // If history exists, auto-populate the most recent session!
        if has_history {
            app.select_history(0);
        } else if !app.presets.is_empty() {
            // Otherwise if presets exist, load the first one by default
            app.select_preset(0);
        }

        app
    }

    pub fn select_history(&mut self, idx: usize) {
        if let Some(entry) = self.history.get(idx) {
            self.selected_history = Some(idx);
            self.host = entry.host.clone();
            self.port = entry.port.to_string();
            self.username = entry.username.clone();
            self.auth_method = match entry.auth_method.as_str() {
                "password" => AuthMethod::Password,
                "key" => AuthMethod::KeyFile,
                _ => AuthMethod::Agent,
            };
            if let Some(kp) = &entry.key_path {
                self.key_path = kp.clone();
            }
            // Password is NEVER loaded from history - user must enter it manually
            self.password = Zeroizing::new(String::new());
        }
    }

    pub fn cycle_history_next(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let next_idx = match self.selected_history {
            Some(i) => (i + 1) % self.history.len(),
            None => 0,
        };
        self.select_history(next_idx);
    }

    pub fn cycle_history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let prev_idx = match self.selected_history {
            Some(0) | None => self.history.len() - 1,
            Some(i) => i - 1,
        };
        self.select_history(prev_idx);
    }

    pub fn select_preset(&mut self, idx: usize) {
        if let Some((_, preset)) = self.presets.get(idx) {
            self.selected_preset = Some(idx);
            self.host = preset.host.clone();
            self.port = preset.port.to_string();
            self.username = preset.username.clone();
            self.auth_method = match preset.auth_method.as_str() {
                "password" => AuthMethod::Password,
                "key" => AuthMethod::KeyFile,
                _ => AuthMethod::Agent,
            };
            if let Some(kp) = &preset.key_path {
                self.key_path = kp.clone();
            }
        }
    }

    pub fn cycle_preset(&mut self) {
        if self.presets.is_empty() {
            return;
        }
        let next_idx = match self.selected_preset {
            Some(i) => (i + 1) % self.presets.len(),
            None => 0,
        };
        self.select_preset(next_idx);
    }

    pub fn cycle_auth_method(&mut self) {
        self.auth_method = match self.auth_method {
            AuthMethod::Password => AuthMethod::KeyFile,
            AuthMethod::KeyFile => AuthMethod::Agent,
            AuthMethod::Agent => AuthMethod::Password,
        };
    }

    pub fn cycle_policy_mode(&mut self) -> HitlMode {
        let new_mode = self.config.security.hitl_mode.next();
        self.config.security.hitl_mode = new_mode;
        new_mode
    }

    /// Process any pending async channel events without blocking
    pub fn poll_channels(&mut self) {
        // Poll for incoming live logs
        while let Ok(entry) = self.live_log_rx.try_recv() {
            self.total_calls += 1;
            if self.live_logs.len() >= 500 {
                self.live_logs.remove(0);
            }
            self.live_logs.push(entry);
        }

        // Poll for incoming HITL approval requests
        if self.pending_hitl.is_none() {
            if let Ok(req) = self.hitl_rx.try_recv() {
                self.pending_hitl = Some(req);
            }
        }
    }

    pub fn filtered_logs(&self) -> Vec<&LiveLogEntry> {
        let query = self.log_filter.trim().to_lowercase();
        self.live_logs
            .iter()
            .filter(|log| {
                if query.is_empty() {
                    true
                } else {
                    log.detail.to_lowercase().contains(&query)
                        || log.tool.to_lowercase().contains(&query)
                        || log.status.to_lowercase().contains(&query)
                        || log.risk.badge().to_lowercase().contains(&query)
                }
            })
            .collect()
    }

    pub fn export_logs(&mut self) -> Result<String, String> {
        if self.live_logs.is_empty() {
            return Err("No log entries available to export".to_string());
        }
        let now_str = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let filename = format!("ssh-mcp-logs-{}.json", now_str);
        match serde_json::to_string_pretty(&self.live_logs) {
            Ok(json_str) => match std::fs::write(&filename, json_str) {
                Ok(_) => Ok(format!("Exported {} log(s) to {}", self.live_logs.len(), filename)),
                Err(e) => Err(format!("File write error: {}", e)),
            },
            Err(e) => Err(format!("Serialization error: {}", e)),
        }
    }

    pub fn resolve_pending_hitl(&mut self, decision: HitlDecision) {
        if let Some(req) = self.pending_hitl.take() {
            let _ = req.responder.send(decision);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::RiskTier;

    #[test]
    fn test_log_filtering_and_export() {
        let (tx, rx) = mpsc::channel(10);
        let (_ltx, lrx) = mpsc::channel(10);
        let mut app = App::new(Config::default(), rx, lrx);

        app.live_logs.push(LiveLogEntry {
            timestamp: "12:00:00".to_string(),
            tool: "ssh_exec".to_string(),
            detail: "git status".to_string(),
            risk: RiskTier::Mutating,
            status: "OK".to_string(),
            duration_ms: 50,
            exit_code: Some(0),
            output_bytes: 120,
        });

        app.live_logs.push(LiveLogEntry {
            timestamp: "12:00:05".to_string(),
            tool: "ssh_exec".to_string(),
            detail: "sudo reboot".to_string(),
            risk: RiskTier::HighRisk,
            status: "DENIED".to_string(),
            duration_ms: 10,
            exit_code: Some(1),
            output_bytes: 0,
        });

        // No filter
        assert_eq!(app.filtered_logs().len(), 2);

        // Filter by command text
        app.log_filter = "reboot".to_string();
        assert_eq!(app.filtered_logs().len(), 1);
        assert_eq!(app.filtered_logs()[0].detail, "sudo reboot");

        // Filter by status
        app.log_filter = "denied".to_string();
        assert_eq!(app.filtered_logs().len(), 1);

        // Filter no match
        app.log_filter = "nonexistent".to_string();
        assert_eq!(app.filtered_logs().len(), 0);

        // Clear filter
        app.log_filter.clear();
        assert_eq!(app.filtered_logs().len(), 2);

        // Test export logs
        let res = app.export_logs();
        assert!(res.is_ok());
        let msg = res.unwrap();
        assert!(msg.contains("Exported 2 log(s)"));
        // Clean up test file
        let parts: Vec<&str> = msg.split_whitespace().collect();
        if let Some(filename) = parts.last() {
            let _ = std::fs::remove_file(filename);
        }
        drop(tx);
    }
}
