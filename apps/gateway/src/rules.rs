//! In-memory rules store and snapshot type.
//!
//! The gateway holds a `tokio::sync::watch` channel carrying an `Arc<RulesSnapshot>`.
//! All writers (config file load, SIGHUP, control socket) replace the snapshot atomically.
//! The proxy handler reads via `borrow()` with zero I/O.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::inject::{Injection, InjectionRule};
use crate::policy::{PolicyAction, PolicyRule};

// ── Wire types (JSON serializable) ───────────────────────────────────────

/// Full snapshot of all agent rules, pushed atomically into the gateway.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RulesSnapshot {
    pub agents: Vec<AgentRules>,
}

/// Rules for a single agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AgentRules {
    /// Agent access token. `None` for the anonymous / standalone agent.
    pub token: Option<String>,
    /// Account ID — used for app connection credential lookup.
    pub account_id: Option<String>,
    /// Per-host injection rules.
    pub host_rules: Vec<HostRule>,
    /// Policy rules for this agent (host filtering happens at resolve time).
    pub policy_rules: Vec<PolicyRuleConfig>,
    /// App connections (OAuth providers) linked to this agent.
    #[serde(default)]
    pub app_connections: Vec<AppConnectionConfig>,
}

/// Injection rules for a specific host pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HostRule {
    pub host_pattern: String,
    pub injection_rules: Vec<InjectionRuleConfig>,
}

/// A single injection rule: a path pattern plus the injections to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InjectionRuleConfig {
    pub path_pattern: String,
    pub injections: Vec<Injection>,
}

/// An app connection configuration (OAuth provider linked to this agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AppConnectionConfig {
    pub provider: String,
}

/// A policy rule configuration (host-level, not yet host-filtered).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PolicyRuleConfig {
    /// Stable identifier used as the rate-limit cache key prefix.
    pub rule_id: String,
    pub host_pattern: String,
    pub path_pattern: Option<String>,
    pub method: Option<String>,
    pub action: String,
    pub rate_limit: Option<u64>,
    pub rate_limit_window: Option<String>,
}

// ── Resolution ───────────────────────────────────────────────────────────

/// Result of resolving rules for a single CONNECT request.
pub(crate) struct ResolvedRules {
    pub intercept: bool,
    pub injection_rules: Vec<InjectionRule>,
    pub policy_rules: Vec<PolicyRule>,
    pub account_id: Option<String>,
    pub app_connections: Vec<AppConnectionConfig>,
}

impl RulesSnapshot {
    /// Resolve rules for the given agent token and hostname.
    ///
    /// Returns `None` when a non-`None` token is not found in the snapshot
    /// (the caller should respond with 407). Returns `Some` with empty rules
    /// when no token is provided and no anonymous agent is configured (plain
    /// tunnel).
    pub(crate) fn resolve(&self, token: Option<&str>, hostname: &str) -> Option<ResolvedRules> {
        let agent = self.find_agent(token)?;

        let injection_rules: Vec<InjectionRule> = agent
            .host_rules
            .iter()
            .filter(|hr| host_matches(hostname, &hr.host_pattern))
            .flat_map(|hr| hr.injection_rules.iter())
            .map(|ir| InjectionRule {
                path_pattern: ir.path_pattern.clone(),
                injections: ir.injections.clone(),
            })
            .collect();

        let policy_rules: Vec<PolicyRule> = agent
            .policy_rules
            .iter()
            .filter(|pr| host_matches(hostname, &pr.host_pattern))
            .filter_map(|pr| {
                let action = match pr.action.as_str() {
                    "block" => PolicyAction::Block,
                    "rate_limit" => {
                        let max_requests = pr.rate_limit.filter(|&v| v > 0)?;
                        let window_secs = match pr.rate_limit_window.as_deref()? {
                            "minute" => 60,
                            "hour" => 3600,
                            "day" => 86400,
                            _ => return None,
                        };
                        PolicyAction::RateLimit {
                            rule_id: pr.rule_id.clone(),
                            max_requests,
                            window_secs,
                        }
                    }
                    _ => return None,
                };
                Some(PolicyRule {
                    path_pattern: pr.path_pattern.clone().unwrap_or_else(|| "*".to_string()),
                    method: pr.method.clone(),
                    action,
                })
            })
            .collect();

        let intercept = !injection_rules.is_empty() || !policy_rules.is_empty();

        Some(ResolvedRules {
            intercept,
            injection_rules,
            policy_rules,
            account_id: agent.account_id.clone(),
            app_connections: agent.app_connections.clone(),
        })
    }

    fn find_agent(&self, token: Option<&str>) -> Option<&AgentRules> {
        self.agents.iter().find(|a| a.token.as_deref() == token)
    }
}

// ── Security checks ─────────────────────────────────────────────────────

/// Returns `Err` with an actionable message if the snapshot contains an
/// anonymous agent and the gateway is bound to a non-loopback address,
/// unless `allow_public_anonymous` is set.
pub(crate) fn check_anonymous_public(
    snapshot: &RulesSnapshot,
    bind_addr: std::net::IpAddr,
    allow_public_anonymous: bool,
) -> Result<(), String> {
    if allow_public_anonymous || bind_addr.is_loopback() {
        return Ok(());
    }
    if snapshot.agents.iter().any(|a| a.token.is_none()) {
        return Err(format!(
            "anonymous agent (\"token\": null) is not allowed when the gateway is bound \
             to a public address ({bind_addr}). Anyone who can reach the port would be \
             able to use your credentials. Either bind to 127.0.0.1 with --bind, add \
             tokens to all agents, or pass --allow-public-anonymous to override this check."
        ));
    }
    Ok(())
}

// ── Channel ──────────────────────────────────────────────────────────────

pub(crate) fn channel() -> (
    watch::Sender<Arc<RulesSnapshot>>,
    watch::Receiver<Arc<RulesSnapshot>>,
) {
    watch::channel(Arc::new(RulesSnapshot::default()))
}

// ── Host matching ────────────────────────────────────────────────────────

/// Check if a requested hostname matches a host pattern.
/// Supports exact match and wildcard prefix (`*.example.com` matches `api.example.com`).
pub(crate) fn host_matches(request_host: &str, pattern: &str) -> bool {
    if request_host == pattern {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return request_host.ends_with(suffix) && request_host.len() > suffix.len();
    }
    false
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::Injection;

    fn snapshot_with_token(
        token: Option<&str>,
        host: &str,
        injections: Vec<Injection>,
    ) -> RulesSnapshot {
        RulesSnapshot {
            agents: vec![AgentRules {
                token: token.map(str::to_string),
                account_id: Some("acc1".to_string()),
                host_rules: vec![HostRule {
                    host_pattern: host.to_string(),
                    injection_rules: vec![InjectionRuleConfig {
                        path_pattern: "*".to_string(),
                        injections,
                    }],
                }],
                policy_rules: vec![],
                app_connections: vec![],
            }],
        }
    }

    #[test]
    fn resolve_matching_token_and_host() {
        let snap = snapshot_with_token(
            Some("aoc_test"),
            "api.anthropic.com",
            vec![Injection::SetHeader {
                name: "x-api-key".to_string(),
                value: "sk-ant".to_string(),
            }],
        );
        let result = snap.resolve(Some("aoc_test"), "api.anthropic.com");
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.intercept);
        assert_eq!(r.injection_rules.len(), 1);
    }

    #[test]
    fn resolve_unknown_token_returns_none() {
        let snap = snapshot_with_token(Some("aoc_real"), "api.anthropic.com", vec![]);
        let result = snap.resolve(Some("aoc_unknown"), "api.anthropic.com");
        assert!(result.is_none());
    }

    #[test]
    fn resolve_no_token_uses_anonymous_agent() {
        let snap = snapshot_with_token(
            None,
            "api.anthropic.com",
            vec![Injection::SetHeader {
                name: "x-api-key".to_string(),
                value: "sk-ant".to_string(),
            }],
        );
        let result = snap.resolve(None, "api.anthropic.com");
        assert!(result.is_some());
        assert!(result.unwrap().intercept);
    }

    #[test]
    fn resolve_no_anonymous_agent_returns_none() {
        let snap = snapshot_with_token(Some("aoc_real"), "api.anthropic.com", vec![]);
        // No token, no anonymous entry
        let result = snap.resolve(None, "api.anthropic.com");
        assert!(result.is_none());
    }

    #[test]
    fn resolve_host_mismatch_no_intercept() {
        let snap = snapshot_with_token(
            Some("aoc_test"),
            "api.anthropic.com",
            vec![Injection::SetHeader {
                name: "x-api-key".to_string(),
                value: "sk-ant".to_string(),
            }],
        );
        let result = snap.resolve(Some("aoc_test"), "api.openai.com");
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(!r.intercept);
        assert!(r.injection_rules.is_empty());
    }

    // ── host_matches ────────────────────────────────────────────────────

    #[test]
    fn host_exact_match() {
        assert!(host_matches("api.anthropic.com", "api.anthropic.com"));
        assert!(!host_matches("api.anthropic.com", "other.com"));
    }

    #[test]
    fn host_wildcard_match() {
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("sub.example.com", "*.example.com"));
        assert!(!host_matches("example.com", "*.example.com"));
        assert!(!host_matches("api.other.com", "*.example.com"));
    }

    #[test]
    fn host_wildcard_no_match_without_dot() {
        assert!(!host_matches("notexample.com", "*.example.com"));
    }

    // ── check_anonymous_public ──────────────────────────────────────────

    fn anon_snapshot() -> RulesSnapshot {
        RulesSnapshot {
            agents: vec![AgentRules {
                token: None,
                account_id: None,
                host_rules: vec![],
                policy_rules: vec![],
                app_connections: vec![],
            }],
        }
    }

    fn token_snapshot() -> RulesSnapshot {
        RulesSnapshot {
            agents: vec![AgentRules {
                token: Some("aoc_test".to_string()),
                account_id: None,
                host_rules: vec![],
                policy_rules: vec![],
                app_connections: vec![],
            }],
        }
    }

    #[test]
    fn anon_on_loopback_is_ok() {
        let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(check_anonymous_public(&anon_snapshot(), lo, false).is_ok());
    }

    #[test]
    fn anon_on_public_is_rejected() {
        let public: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        assert!(check_anonymous_public(&anon_snapshot(), public, false).is_err());
    }

    #[test]
    fn anon_on_public_with_override_is_ok() {
        let public: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        assert!(check_anonymous_public(&anon_snapshot(), public, true).is_ok());
    }

    #[test]
    fn token_agents_on_public_is_ok() {
        let public: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        assert!(check_anonymous_public(&token_snapshot(), public, false).is_ok());
    }

    #[test]
    fn empty_snapshot_on_public_is_ok() {
        let public: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        assert!(check_anonymous_public(&RulesSnapshot::default(), public, false).is_ok());
    }

    // ── Policy rule resolution ──────────────────────────────────────────

    fn snapshot_with_policy(
        host: &str,
        action: &str,
        rate_limit: Option<u64>,
        window: Option<&str>,
    ) -> RulesSnapshot {
        RulesSnapshot {
            agents: vec![AgentRules {
                token: None,
                account_id: Some("acc1".to_string()),
                host_rules: vec![],
                app_connections: vec![],
                policy_rules: vec![PolicyRuleConfig {
                    rule_id: "r1".to_string(),
                    host_pattern: host.to_string(),
                    path_pattern: Some("/v1/*".to_string()),
                    method: Some("POST".to_string()),
                    action: action.to_string(),
                    rate_limit,
                    rate_limit_window: window.map(str::to_string),
                }],
            }],
        }
    }

    #[test]
    fn resolve_block_policy_rule() {
        let snap = snapshot_with_policy("api.example.com", "block", None, None);
        let r = snap.resolve(None, "api.example.com").unwrap();
        assert!(r.intercept);
        assert_eq!(r.policy_rules.len(), 1);
        assert_eq!(r.policy_rules[0].action, crate::policy::PolicyAction::Block);
        assert_eq!(r.policy_rules[0].path_pattern, "/v1/*");
        assert_eq!(r.policy_rules[0].method.as_deref(), Some("POST"));
    }

    #[test]
    fn resolve_rate_limit_policy_rule() {
        let snap = snapshot_with_policy("api.example.com", "rate_limit", Some(100), Some("hour"));
        let r = snap.resolve(None, "api.example.com").unwrap();
        assert_eq!(r.policy_rules.len(), 1);
        match &r.policy_rules[0].action {
            crate::policy::PolicyAction::RateLimit {
                rule_id,
                max_requests,
                window_secs,
            } => {
                assert_eq!(rule_id, "r1");
                assert_eq!(*max_requests, 100);
                assert_eq!(*window_secs, 3600);
            }
            other => panic!("expected RateLimit, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rate_limit_zero_is_skipped() {
        let snap = snapshot_with_policy("api.example.com", "rate_limit", Some(0), Some("hour"));
        let r = snap.resolve(None, "api.example.com").unwrap();
        assert!(r.policy_rules.is_empty());
        assert!(!r.intercept);
    }

    #[test]
    fn resolve_unknown_action_is_skipped() {
        let snap = snapshot_with_policy("api.example.com", "allow", None, None);
        let r = snap.resolve(None, "api.example.com").unwrap();
        assert!(r.policy_rules.is_empty());
    }

    #[test]
    fn resolve_policy_host_mismatch_filtered() {
        let snap = snapshot_with_policy("api.example.com", "block", None, None);
        let r = snap.resolve(None, "other.com").unwrap();
        assert!(r.policy_rules.is_empty());
        assert!(!r.intercept);
    }

    #[test]
    fn resolve_policy_no_path_defaults_to_wildcard() {
        let snap = RulesSnapshot {
            agents: vec![AgentRules {
                token: None,
                account_id: None,
                host_rules: vec![],
                policy_rules: vec![PolicyRuleConfig {
                    rule_id: "r2".to_string(),
                    host_pattern: "*.example.com".to_string(),
                    path_pattern: None,
                    method: None,
                    action: "block".to_string(),
                    rate_limit: None,
                    rate_limit_window: None,
                }],
                app_connections: vec![],
            }],
        };
        let r = snap.resolve(None, "api.example.com").unwrap();
        assert_eq!(r.policy_rules[0].path_pattern, "*");
        assert!(r.policy_rules[0].method.is_none());
    }

    // ── Multi-agent selection ───────────────────────────────────────────

    #[test]
    fn resolve_selects_correct_agent_from_multiple() {
        let snap = RulesSnapshot {
            agents: vec![
                AgentRules {
                    token: Some("aoc_alpha".to_string()),
                    account_id: Some("acc_a".to_string()),
                    host_rules: vec![HostRule {
                        host_pattern: "api.anthropic.com".to_string(),
                        injection_rules: vec![InjectionRuleConfig {
                            path_pattern: "*".to_string(),
                            injections: vec![Injection::SetHeader {
                                name: "x-api-key".to_string(),
                                value: "sk-alpha".to_string(),
                            }],
                        }],
                    }],
                    policy_rules: vec![],
                    app_connections: vec![],
                },
                AgentRules {
                    token: Some("aoc_beta".to_string()),
                    account_id: Some("acc_b".to_string()),
                    host_rules: vec![HostRule {
                        host_pattern: "api.openai.com".to_string(),
                        injection_rules: vec![InjectionRuleConfig {
                            path_pattern: "*".to_string(),
                            injections: vec![Injection::SetHeader {
                                name: "authorization".to_string(),
                                value: "Bearer sk-beta".to_string(),
                            }],
                        }],
                    }],
                    policy_rules: vec![],
                    app_connections: vec![],
                },
            ],
        };

        // Alpha agent resolves its own host rules.
        let r = snap
            .resolve(Some("aoc_alpha"), "api.anthropic.com")
            .unwrap();
        assert!(r.intercept);
        assert_eq!(r.account_id.as_deref(), Some("acc_a"));
        assert_eq!(r.injection_rules.len(), 1);

        // Alpha agent, wrong host, no intercept.
        let r = snap.resolve(Some("aoc_alpha"), "api.openai.com").unwrap();
        assert!(!r.intercept);

        // Beta agent resolves its own host rules.
        let r = snap.resolve(Some("aoc_beta"), "api.openai.com").unwrap();
        assert!(r.intercept);
        assert_eq!(r.account_id.as_deref(), Some("acc_b"));

        // Unknown agent returns None.
        assert!(snap
            .resolve(Some("aoc_unknown"), "api.anthropic.com")
            .is_none());
    }

    // ── account_id propagation ──────────────────────────────────────────

    #[test]
    fn resolve_propagates_account_id() {
        let snap = snapshot_with_token(
            Some("aoc_test"),
            "api.anthropic.com",
            vec![Injection::SetHeader {
                name: "x-api-key".to_string(),
                value: "sk-ant".to_string(),
            }],
        );
        let r = snap.resolve(Some("aoc_test"), "api.anthropic.com").unwrap();
        assert_eq!(r.account_id.as_deref(), Some("acc1"));
    }

    #[test]
    fn resolve_account_id_none_when_not_set() {
        let snap = RulesSnapshot {
            agents: vec![AgentRules {
                token: None,
                account_id: None,
                host_rules: vec![],
                policy_rules: vec![],
                app_connections: vec![],
            }],
        };
        let r = snap.resolve(None, "anything.com").unwrap();
        assert!(r.account_id.is_none());
        assert!(!r.intercept);
    }
}
