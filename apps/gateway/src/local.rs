//! Local mode: load injection rules from a TOML file instead of the web API.
//!
//! In local mode the gateway reads rules at startup, resolves `value-file` references
//! into in-memory strings, and matches incoming CONNECT hostnames against those rules.
//! No web API or auth tokens are involved.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::inject::{ConnectRule, Injection};

// ── TOML schema ─────────────────────────────────────────────────────────

/// Top-level rules file.
#[derive(Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<TomlRule>,
}

/// A single rule entry in the TOML file.
#[derive(Deserialize)]
struct TomlRule {
    host: String,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default)]
    inject: Vec<TomlInjection>,
}

fn default_path() -> String {
    "*".to_string()
}

/// A single injection action in the TOML file.
#[derive(Deserialize)]
struct TomlInjection {
    action: String,
    name: String,
    /// Inline literal value.
    #[serde(default)]
    value: Option<String>,
    /// Path to a file containing the value (read at startup).
    #[serde(default, rename = "value-file")]
    value_file: Option<String>,
    /// Optional format string — `{value}` is replaced with the resolved value.
    #[serde(default, rename = "value-format")]
    value_format: Option<String>,
}

// ── Resolved types ──────────────────────────────────────────────────────

/// A fully resolved rule ready for runtime matching.
#[derive(Debug)]
pub(crate) struct ResolvedLocalRule {
    pub host_pattern: String,
    pub connect_rules: Vec<ConnectRule>,
}

// ── Loading ─────────────────────────────────────────────────────────────

/// Parse the rules TOML file and resolve all value-file references.
/// Fails fast on missing files or parse errors.
pub(crate) fn load(path: &Path) -> Result<Vec<ResolvedLocalRule>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading rules file {}", path.display()))?;
    let file: RulesFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let mut resolved = Vec::with_capacity(file.rules.len());
    for rule in file.rules {
        let injections = resolve_injections(&rule.inject, path)?;
        let connect_rule = ConnectRule {
            path_pattern: rule.path,
            injections,
        };
        resolved.push(ResolvedLocalRule {
            host_pattern: rule.host,
            connect_rules: vec![connect_rule],
        });
    }
    Ok(resolved)
}

/// Resolve a list of TOML injection entries into `Injection` values.
fn resolve_injections(entries: &[TomlInjection], rules_path: &Path) -> Result<Vec<Injection>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry.action.as_str() {
            "set_header" => {
                let raw_value = resolve_value(entry, rules_path)?;
                let value = match &entry.value_format {
                    Some(fmt) => fmt.replace("{value}", &raw_value),
                    None => raw_value,
                };
                out.push(Injection::SetHeader {
                    name: entry.name.clone(),
                    value,
                });
            }
            "remove_header" => {
                out.push(Injection::RemoveHeader {
                    name: entry.name.clone(),
                });
            }
            other => bail!("unknown injection action {:?} in {}", other, rules_path.display()),
        }
    }
    Ok(out)
}

/// Resolve the value for a set_header injection: inline `value` or `value-file`.
fn resolve_value(entry: &TomlInjection, rules_path: &Path) -> Result<String> {
    if let Some(ref v) = entry.value {
        return Ok(v.clone());
    }
    if let Some(ref file_path) = entry.value_file {
        let expanded = expand_tilde(file_path);
        let content = std::fs::read_to_string(&expanded)
            .with_context(|| format!("reading value-file {} (for header {:?}) referenced from {}", expanded.display(), entry.name, rules_path.display()))?;
        return Ok(content.trim().to_string());
    }
    bail!(
        "injection for header {:?} in {} has neither `value` nor `value-file`",
        entry.name,
        rules_path.display()
    );
}

// ── Runtime resolution ──────────────────────────────────────────────────

/// Find all rules matching a hostname. Returns `(intercept, rules)`.
/// If no rules match, returns `(false, vec![])` — the connection will be tunnelled.
pub(crate) fn resolve(hostname: &str, rules: &[ResolvedLocalRule]) -> (bool, Vec<ConnectRule>) {
    let mut matched = Vec::new();
    for rule in rules {
        if host_matches(hostname, &rule.host_pattern) {
            matched.extend(rule.connect_rules.iter().cloned());
        }
    }
    if matched.is_empty() {
        (false, vec![])
    } else {
        (true, matched)
    }
}

/// Check if a hostname matches a pattern.
/// Supports exact match and `*.suffix` wildcard (e.g. `*.example.com` matches `api.example.com`).
fn host_matches(hostname: &str, pattern: &str) -> bool {
    if pattern == hostname {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // *.example.com matches foo.example.com but not example.com itself
        return hostname.ends_with(suffix)
            && hostname.len() > suffix.len()
            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.';
    }
    false
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(path.strip_prefix("~/").unwrap_or(""));
        }
    }
    PathBuf::from(path)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // ── host_matches ────────────────────────────────────────────────────

    #[test]
    fn host_exact_match() {
        assert!(host_matches("api.anthropic.com", "api.anthropic.com"));
        assert!(!host_matches("api.anthropic.com", "other.com"));
    }

    #[test]
    fn host_wildcard_match() {
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("sub.api.example.com", "*.example.com"));
    }

    #[test]
    fn host_wildcard_no_match_bare_domain() {
        // *.example.com should NOT match example.com itself
        assert!(!host_matches("example.com", "*.example.com"));
    }

    #[test]
    fn host_wildcard_no_match_different_domain() {
        assert!(!host_matches("api.other.com", "*.example.com"));
    }

    #[test]
    fn host_wildcard_no_partial_match() {
        // "notexample.com" should not match "*.example.com"
        assert!(!host_matches("notexample.com", "*.example.com"));
    }

    // ── resolve ─────────────────────────────────────────────────────────

    #[test]
    fn resolve_no_match_returns_tunnel() {
        let rules = vec![ResolvedLocalRule {
            host_pattern: "api.anthropic.com".to_string(),
            connect_rules: vec![ConnectRule {
                path_pattern: "*".to_string(),
                injections: vec![Injection::SetHeader {
                    name: "x-api-key".to_string(),
                    value: "sk-123".to_string(),
                }],
            }],
        }];

        let (intercept, matched) = resolve("other.com", &rules);
        assert!(!intercept);
        assert!(matched.is_empty());
    }

    #[test]
    fn resolve_match_returns_rules() {
        let rules = vec![ResolvedLocalRule {
            host_pattern: "api.anthropic.com".to_string(),
            connect_rules: vec![ConnectRule {
                path_pattern: "*".to_string(),
                injections: vec![Injection::SetHeader {
                    name: "x-api-key".to_string(),
                    value: "sk-123".to_string(),
                }],
            }],
        }];

        let (intercept, matched) = resolve("api.anthropic.com", &rules);
        assert!(intercept);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].injections.len(), 1);
    }

    #[test]
    fn resolve_wildcard_match() {
        let rules = vec![ResolvedLocalRule {
            host_pattern: "*.anthropic.com".to_string(),
            connect_rules: vec![ConnectRule {
                path_pattern: "*".to_string(),
                injections: vec![],
            }],
        }];

        let (intercept, _) = resolve("api.anthropic.com", &rules);
        assert!(intercept);
    }

    // ── load (TOML parsing + value-file resolution) ─────────────────────

    #[test]
    fn load_inline_value() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "api.anthropic.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value = "sk-inline-123"
"#,
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].host_pattern, "api.anthropic.com");
        assert_eq!(rules[0].connect_rules.len(), 1);
        assert_eq!(rules[0].connect_rules[0].path_pattern, "*");
        match &rules[0].connect_rules[0].injections[0] {
            Injection::SetHeader { name, value } => {
                assert_eq!(name, "x-api-key");
                assert_eq!(value, "sk-inline-123");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_value_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.key");
        std::fs::write(&secret_path, "sk-from-file-456\n").unwrap();

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "api.anthropic.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value-file = "{}"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        match &rules[0].connect_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => {
                assert_eq!(value, "sk-from-file-456"); // trimmed
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_value_format() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("token.key");
        std::fs::write(&secret_path, "hf_abc123\n").unwrap();

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "huggingface.co"
[[rules.inject]]
action = "set_header"
name = "authorization"
value-file = "{}"
value-format = "Bearer {{value}}"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        match &rules[0].connect_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => {
                assert_eq!(value, "Bearer hf_abc123");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_remove_header() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "example.com"
[[rules.inject]]
action = "remove_header"
name = "authorization"
"#,
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        match &rules[0].connect_rules[0].injections[0] {
            Injection::RemoveHeader { name } => assert_eq!(name, "authorization"),
            other => panic!("expected RemoveHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_custom_path_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "api.anthropic.com"
path = "/v1/*"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value = "sk-123"
"#,
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        assert_eq!(rules[0].connect_rules[0].path_pattern, "/v1/*");
    }

    #[test]
    fn load_missing_file_fails() {
        let path = Path::new("/tmp/nonexistent-rules-12345.toml");
        assert!(load(path).is_err());
    }

    #[test]
    fn load_missing_value_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "example.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value-file = "/tmp/nonexistent-secret-12345.key"
"#,
        )
        .unwrap();

        let err = load(&rules_path).unwrap_err();
        assert!(
            format!("{err:?}").contains("nonexistent-secret"),
            "error should mention missing file: {err:?}"
        );
    }

    #[test]
    fn load_no_value_or_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "example.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
"#,
        )
        .unwrap();

        let err = load(&rules_path).unwrap_err();
        assert!(
            format!("{err:?}").contains("neither"),
            "error should say no value source: {err:?}"
        );
    }

    #[test]
    fn load_empty_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(&rules_path, "").unwrap();

        let rules = load(&rules_path).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn load_multiple_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "api.anthropic.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value = "sk-ant"

[[rules]]
host = "huggingface.co"
[[rules.inject]]
action = "set_header"
name = "authorization"
value = "Bearer hf-tok"
"#,
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].host_pattern, "api.anthropic.com");
        assert_eq!(rules[1].host_pattern, "huggingface.co");
    }
}
