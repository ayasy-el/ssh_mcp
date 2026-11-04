use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub servers: HashMap<String, ServerPreset>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            security: SecurityConfig::default(),
            servers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_mode")]
    pub mode: String, // "tui" or "headless"
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,
    #[serde(default = "default_mcp_bind")]
    pub mcp_bind: String,
}

fn default_mode() -> String {
    "tui".to_string()
}

fn default_mcp_port() -> u16 {
    8765
}

fn default_mcp_bind() -> String {
    "127.0.0.1".to_string()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            mcp_port: default_mcp_port(),
            mcp_bind: default_mcp_bind(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HitlMode {
    HighRisk,
    Strict,
    ReadOnly,
    #[serde(alias = "audit_only", alias = "no_approval", alias = "auto", alias = "unrestricted")]
    Autonomous,
}

impl HitlMode {
    pub fn display_label(&self) -> &'static str {
        match self {
            HitlMode::HighRisk => "High-Risk HITL",
            HitlMode::Strict => "Strict HITL",
            HitlMode::ReadOnly => "Read-Only",
            HitlMode::Autonomous => "Autonomous (No Approval)",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            HitlMode::HighRisk => HitlMode::Strict,
            HitlMode::Strict => HitlMode::ReadOnly,
            HitlMode::ReadOnly => HitlMode::Autonomous,
            HitlMode::Autonomous => HitlMode::HighRisk,
        }
    }
}

impl Default for HitlMode {
    fn default() -> Self {
        HitlMode::HighRisk
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub hitl_mode: HitlMode,
    #[serde(default = "default_timeout")]
    pub command_timeout_secs: u64,
    #[serde(default = "default_max_bytes")]
    pub max_output_bytes: usize,
    #[serde(default = "default_max_lines")]
    pub max_output_lines: usize,
    #[serde(default = "default_audit_path")]
    pub audit_log_path: String,
    #[serde(default)]
    pub tofu_auto_accept: bool,
    #[serde(default = "default_true")]
    pub mask_secrets: bool,
    #[serde(default = "default_forbidden")]
    pub forbidden_commands: Vec<String>,
    #[serde(default)]
    pub high_risk_commands: Vec<String>,
    #[serde(default)]
    pub safe_commands: Vec<String>,
}

fn default_timeout() -> u64 {
    60
}

fn default_max_bytes() -> usize {
    32 * 1024 // 32 KB
}

fn default_max_lines() -> usize {
    1500
}

fn default_audit_path() -> String {
    "audit.jsonl".to_string()
}

fn default_true() -> bool {
    true
}

fn default_forbidden() -> Vec<String> {
    vec![
        ":(){ :|:& };:".to_string(),
        "mkfs".to_string(),
        "dd if=/dev/zero".to_string(),
        "chmod -R 777 /".to_string(),
        "rm -rf /".to_string(),
    ]
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            hitl_mode: HitlMode::default(),
            command_timeout_secs: default_timeout(),
            max_output_bytes: default_max_bytes(),
            max_output_lines: default_max_lines(),
            audit_log_path: default_audit_path(),
            tofu_auto_accept: false,
            mask_secrets: default_true(),
            forbidden_commands: default_forbidden(),
            high_risk_commands: Vec::new(),
            safe_commands: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPreset {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    #[serde(default = "default_auth_method")]
    pub auth_method: String, // "password", "key", "agent"
    pub key_path: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_auth_method() -> String {
    "agent".to_string()
}

impl Config {
    /// Loads configuration from given path, or fallback search locations.
    /// Returns default config if no file is found.
    pub fn load_or_default(explicit_path: Option<&Path>) -> (Self, Option<PathBuf>) {
        if let Some(p) = explicit_path {
            if let Ok(content) = std::fs::read_to_string(p) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return (cfg, Some(p.to_path_buf()));
                }
            }
        }

        // Try ./config.toml
        let local_path = PathBuf::from("config.toml");
        if local_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&local_path) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return (cfg, Some(local_path));
                }
            }
        }

        // Try ~/.config/ssh-mcp/config.toml
        if let Some(config_dir) = dirs::config_dir() {
            let user_cfg = config_dir.join("ssh-mcp").join("config.toml");
            if user_cfg.is_file() {
                if let Ok(content) = std::fs::read_to_string(&user_cfg) {
                    if let Ok(cfg) = toml::from_str::<Config>(&content) {
                        return (cfg, Some(user_cfg));
                    }
                }
            }
        }

        (Config::default(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_example_config() {
        let path = Path::new("config.example.toml");
        assert!(path.exists());
        let (cfg, _) = Config::load_or_default(Some(path));
        assert_eq!(cfg.general.mcp_port, 8765);
        assert_eq!(cfg.security.hitl_mode, HitlMode::HighRisk);
        assert!(cfg.servers.contains_key("example-server"));
        assert_eq!(cfg.servers["example-server"].host, "ssh.example.com");
    }

    #[test]
    fn test_hitl_mode_aliases() {
        let toml_auto = r#"hitl_mode = "no_approval""#;
        #[derive(Deserialize)]
        struct Wrapper { hitl_mode: HitlMode }
        let w: Wrapper = toml::from_str(toml_auto).unwrap();
        assert_eq!(w.hitl_mode, HitlMode::Autonomous);

        let toml_audit = r#"hitl_mode = "audit_only""#;
        let w2: Wrapper = toml::from_str(toml_audit).unwrap();
        assert_eq!(w2.hitl_mode, HitlMode::Autonomous);
    }
}
