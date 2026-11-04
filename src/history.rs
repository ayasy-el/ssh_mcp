use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionHistoryEntry {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String, // "password", "key", "agent"
    pub key_path: Option<String>,
    pub last_connected: chrono::DateTime<chrono::Utc>,
}

impl SessionHistoryEntry {
    pub fn display_label(&self) -> String {
        format!("{}@{}:{} ({})", self.username, self.host, self.port, self.auth_method)
    }

    pub fn history_file_path() -> PathBuf {
        if let Some(config_dir) = dirs::config_dir() {
            let dir = config_dir.join("ssh-mcp");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("history.json")
        } else {
            PathBuf::from(".history.json")
        }
    }

    /// Loads history from ~/.config/ssh-mcp/history.json (or local fallback).
    /// Sorted by most recently connected first.
    pub fn load_history() -> Vec<Self> {
        let path = Self::history_file_path();
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(mut entries) = serde_json::from_str::<Vec<SessionHistoryEntry>>(&content) {
                    entries.sort_by(|a, b| b.last_connected.cmp(&a.last_connected));
                    return entries;
                }
            }
        }
        Vec::new()
    }

    /// Records a successful connection into history.
    /// Deduplicates by (host, port, username) and keeps up to 20 recent items.
    /// Note: Passwords/passphrases are NEVER stored.
    pub fn record(host: &str, port: u16, username: &str, auth_method: &str, key_path: Option<&str>) {
        let mut entries = Self::load_history();

        // Remove existing entry for the same host+port+username to keep latest on top
        entries.retain(|e| !(e.host == host && e.port == port && e.username == username));

        let new_entry = SessionHistoryEntry {
            host: host.to_string(),
            port,
            username: username.to_string(),
            auth_method: auth_method.to_string(),
            key_path: key_path.map(|s| s.to_string()),
            last_connected: chrono::Utc::now(),
        };

        entries.insert(0, new_entry);
        if entries.len() > 20 {
            entries.truncate(20);
        }

        let path = Self::history_file_path();
        if let Ok(json_str) = serde_json::to_string_pretty(&entries) {
            let _ = std::fs::write(path, json_str);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_history_display_label() {
        let entry = SessionHistoryEntry {
            host: "10.0.0.1".to_string(),
            port: 22,
            username: "root".to_string(),
            auth_method: "password".to_string(),
            key_path: None,
            last_connected: chrono::Utc::now(),
        };
        assert_eq!(entry.display_label(), "root@10.0.0.1:22 (password)");
    }

    #[test]
    fn test_session_history_serialization() {
        let entry = SessionHistoryEntry {
            host: "10.0.0.1".to_string(),
            port: 22,
            username: "root".to_string(),
            auth_method: "key".to_string(),
            key_path: Some("~/.ssh/id_rsa".to_string()),
            last_connected: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&vec![entry.clone()]).unwrap();
        let deserialized: Vec<SessionHistoryEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 1);
        assert_eq!(deserialized[0].host, "10.0.0.1");
        assert_eq!(deserialized[0].key_path.as_deref(), Some("~/.ssh/id_rsa"));
    }
}
