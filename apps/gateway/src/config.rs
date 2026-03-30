//! Rules file loading.
//!
//! The gateway reads its initial rules from a JSON file whose format is
//! identical to the `RulesSnapshot` wire format used by the control socket.
//! This means the same JSON can be POSTed to the control socket or written
//! to the file — no translation layer.
//!
//! File locations follow XDG and FHS conventions:
//! - `$XDG_CONFIG_HOME/onecli/rules.json` (non-root, XDG_CONFIG_HOME defaults to `~/.config`)
//! - `/etc/onecli/rules.json` (root)
//!
//! Override with `--rules <path>`.

use std::path::PathBuf;

use anyhow::{Context as _, Result};

use crate::rules::RulesSnapshot;

// ── Path resolution ──────────────────────────────────────────────────────

/// Return the path to the rules config file.
///
/// Priority order:
/// 1. `override_path` if given (from `--rules` CLI flag)
/// 2. `/etc/onecli/rules.json` when running as root (uid 0)
/// 3. `$XDG_CONFIG_HOME/onecli/rules.json` (defaults to `~/.config/onecli/rules.json`)
pub(crate) fn resolve_rules_path(override_path: Option<&std::path::Path>) -> PathBuf {
    if let Some(p) = override_path {
        return p.to_path_buf();
    }

    if is_root() {
        return PathBuf::from("/etc/onecli/rules.json");
    }

    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".config")
        });

    config_home.join("onecli").join("rules.json")
}

/// Load a `RulesSnapshot` from a JSON file.
/// Returns an empty snapshot if the file does not exist.
pub(crate) async fn load_rules_from_file(path: &std::path::Path) -> Result<RulesSnapshot> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RulesSnapshot::default());
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading rules file {}", path.display()));
        }
    };

    serde_json::from_str(&content).with_context(|| format!("parsing rules file {}", path.display()))
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|uid| uid.parse::<u32>().ok())
        })
        .map(|uid| uid == 0)
        .unwrap_or(false)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::Injection;
    use crate::rules::{AgentRules, HostRule, InjectionRuleConfig};

    #[tokio::test]
    async fn missing_file_returns_empty_snapshot() {
        let snap = load_rules_from_file(std::path::Path::new("/nonexistent/rules.json"))
            .await
            .unwrap();
        assert!(snap.agents.is_empty());
    }

    #[tokio::test]
    async fn existing_file_is_parsed() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let snap = RulesSnapshot {
            agents: vec![AgentRules {
                token: None,
                account_id: None,
                host_rules: vec![HostRule {
                    host_pattern: "api.anthropic.com".to_string(),
                    injection_rules: vec![InjectionRuleConfig {
                        path_pattern: "*".to_string(),
                        injections: vec![Injection::SetHeader {
                            name: "x-api-key".to_string(),
                            value: "sk-test".to_string(),
                        }],
                    }],
                }],
                policy_rules: vec![],
                app_connections: vec![],
            }],
        };
        write!(f, "{}", serde_json::to_string(&snap).unwrap()).unwrap();
        let loaded = load_rules_from_file(f.path()).await.unwrap();
        assert_eq!(loaded.agents.len(), 1);
        assert_eq!(loaded.agents[0].host_rules.len(), 1);
    }

    #[tokio::test]
    async fn invalid_json_returns_error() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "this is not json").unwrap();
        assert!(load_rules_from_file(f.path()).await.is_err());
    }
}
