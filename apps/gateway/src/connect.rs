//! Policy resolution for CONNECT requests.
//!
//! Reads rules from the in-memory watch channel with zero I/O — no database
//! queries, no cache lookups. The watch channel is updated by the config file
//! loader (startup / SIGHUP) and the control socket (web UI push).

use std::sync::Arc;

use tokio::sync::watch;

use crate::inject::InjectionRule;
use crate::policy::PolicyRule;
use crate::rules::{AppConnectionConfig, ResolvedRules, RulesSnapshot};

// ── Data types ───────────────────────────────────────────────────────────

/// Result of policy resolution for a CONNECT request.
#[derive(Debug)]
pub(crate) struct ConnectResponse {
    pub intercept: bool,
    pub injection_rules: Vec<InjectionRule>,
    pub policy_rules: Vec<PolicyRule>,
    pub account_id: Option<String>,
    pub app_connections: Vec<AppConnectionConfig>,
}

/// Errors from the connect resolution.
#[derive(Debug)]
pub(crate) enum ConnectError {
    /// Agent token was provided but not found in the rules snapshot.
    InvalidToken,
}

// ── Resolution ───────────────────────────────────────────────────────────

/// Resolve what to do for an agent token + hostname pair.
///
/// Borrows the current snapshot from the watch channel (zero I/O) and
/// delegates to `RulesSnapshot::resolve`.
///
/// - Token provided and found → `Ok(ConnectResponse)`
/// - Token provided but not found → `Err(ConnectError::InvalidToken)` (→ 407)
/// - No token and anonymous agent configured → `Ok(ConnectResponse)` (standalone mode)
/// - No token and no anonymous agent → `Ok` with `intercept = false` (plain tunnel)
pub(crate) fn resolve(
    agent_token: Option<&str>,
    hostname: &str,
    rules_rx: &watch::Receiver<Arc<RulesSnapshot>>,
) -> Result<ConnectResponse, ConnectError> {
    let snapshot = rules_rx.borrow();

    match snapshot.resolve(agent_token, hostname) {
        Some(ResolvedRules {
            intercept,
            injection_rules,
            policy_rules,
            account_id,
            app_connections,
        }) => Ok(ConnectResponse {
            intercept,
            injection_rules,
            policy_rules,
            account_id,
            app_connections,
        }),
        None => {
            if agent_token.is_some() {
                // Token was given but not found.
                Err(ConnectError::InvalidToken)
            } else {
                // No token, no anonymous agent entry — plain pass-through tunnel.
                Ok(ConnectResponse {
                    intercept: false,
                    injection_rules: vec![],
                    policy_rules: vec![],
                    account_id: None,
                    app_connections: vec![],
                })
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::Injection;
    use crate::rules::{AgentRules, HostRule, InjectionRuleConfig};

    fn make_rx(snapshot: RulesSnapshot) -> watch::Receiver<Arc<RulesSnapshot>> {
        let (tx, rx) = watch::channel(Arc::new(snapshot));
        drop(tx);
        rx
    }

    fn snapshot_with_agent(token: Option<&str>, host: &str) -> RulesSnapshot {
        RulesSnapshot {
            agents: vec![AgentRules {
                token: token.map(str::to_string),
                account_id: Some("acc1".to_string()),
                host_rules: vec![HostRule {
                    host_pattern: host.to_string(),
                    injection_rules: vec![InjectionRuleConfig {
                        path_pattern: "*".to_string(),
                        injections: vec![Injection::SetHeader {
                            name: "x-api-key".to_string(),
                            value: "sk-ant".to_string(),
                        }],
                    }],
                }],
                policy_rules: vec![],
                app_connections: vec![],
            }],
        }
    }

    #[test]
    fn valid_token_matching_host_intercepts() {
        let rx = make_rx(snapshot_with_agent(Some("aoc_test"), "api.anthropic.com"));
        let resp = resolve(Some("aoc_test"), "api.anthropic.com", &rx).unwrap();
        assert!(resp.intercept);
        assert_eq!(resp.injection_rules.len(), 1);
    }

    #[test]
    fn invalid_token_returns_error() {
        let rx = make_rx(snapshot_with_agent(Some("aoc_real"), "api.anthropic.com"));
        let err = resolve(Some("aoc_wrong"), "api.anthropic.com", &rx).unwrap_err();
        assert!(matches!(err, ConnectError::InvalidToken));
    }

    #[test]
    fn no_token_with_anon_agent_intercepts() {
        let rx = make_rx(snapshot_with_agent(None, "api.anthropic.com"));
        let resp = resolve(None, "api.anthropic.com", &rx).unwrap();
        assert!(resp.intercept);
    }

    #[test]
    fn no_token_no_anon_agent_tunnels() {
        // Snapshot has only a named agent — no anonymous entry.
        let rx = make_rx(snapshot_with_agent(Some("aoc_real"), "api.anthropic.com"));
        let resp = resolve(None, "api.anthropic.com", &rx).unwrap();
        assert!(!resp.intercept);
        assert!(resp.injection_rules.is_empty());
    }

    #[test]
    fn empty_snapshot_tunnels_without_token() {
        let rx = make_rx(RulesSnapshot::default());
        let resp = resolve(None, "api.anthropic.com", &rx).unwrap();
        assert!(!resp.intercept);
    }

    #[test]
    fn empty_snapshot_rejects_token() {
        let rx = make_rx(RulesSnapshot::default());
        let err = resolve(Some("aoc_x"), "api.anthropic.com", &rx).unwrap_err();
        assert!(matches!(err, ConnectError::InvalidToken));
    }
}
