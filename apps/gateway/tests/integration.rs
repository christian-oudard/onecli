//! Integration tests for the onecli-gateway.
//!
//! **Standalone tests** (no DATABASE_URL needed) start the gateway with a
//! `--rules` JSON file and verify tunneling, token auth, and CA persistence.
//!
//! **DB-dependent tests** require DATABASE_URL + SECRET_ENCRYPTION_KEY and
//! are gated behind those env vars (silently skip when unset).

use base64::Engine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

/// Encode an agent token as a Basic auth header value: `Basic base64(x:{token})`.
fn basic_auth(token: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("x:{token}"));
    format!("Basic {encoded}")
}

/// Start the gateway binary with custom CLI args and environment variables.
fn start_gateway(
    tmp_dir: &Path,
    extra_args: &[&str],
    envs: &[(&str, &str)],
) -> (u16, std::process::Child) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let bin = env!("CARGO_BIN_EXE_onecli-gateway");

    let mut cmd = std::process::Command::new(bin);
    cmd.arg("--port")
        .arg(port.to_string())
        .arg("--data-dir")
        .arg(tmp_dir.to_str().expect("valid utf8 path"))
        .arg("--no-control-socket");

    for arg in extra_args {
        cmd.arg(arg);
    }

    for (key, val) in envs {
        cmd.env(key, val);
    }

    let child = cmd
        .env("RUST_LOG", "warn")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start gateway process");

    // Wait for gateway to accept TCP connections.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::time::Instant::now() > deadline {
            panic!("gateway failed to start within 5 seconds");
        }
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    (port, child)
}

/// Write a rules.json file and return its path.
fn write_rules(dir: &Path, json: &str) -> std::path::PathBuf {
    let path = dir.join("rules.json");
    std::fs::write(&path, json).expect("write rules.json");
    path
}

// ── Standalone tests (no database) ──────────────────────────────────────

#[test]
fn standalone_non_connect_returns_400() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let (port, mut child) = start_gateway(tmp.path(), &[], &[]);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    stream.write_all(req.as_bytes()).expect("send");

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("HTTP/1.1 400"), "expected 400, got: {resp}");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn standalone_connect_without_token_tunnels() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    // Rules with a named agent only, no anonymous entry.
    let rules_path = write_rules(
        tmp.path(),
        r#"{"agents":[{"token":"aoc_test","host_rules":[],"policy_rules":[]}]}"#,
    );
    let rules_arg = format!("--rules={}", rules_path.display());
    let (port, mut child) = start_gateway(tmp.path(), &[&rules_arg], &[]);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    stream.write_all(req.as_bytes()).expect("send CONNECT");

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200"), "expected 200 (tunnel), got: {resp}");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn standalone_invalid_token_returns_407() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let rules_path = write_rules(
        tmp.path(),
        r#"{"agents":[{"token":"aoc_real","host_rules":[],"policy_rules":[]}]}"#,
    );
    let rules_arg = format!("--rules={}", rules_path.display());
    let (port, mut child) = start_gateway(tmp.path(), &[&rules_arg], &[]);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let auth = basic_auth("aoc_wrong");
    let req = format!(
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nProxy-Authorization: {auth}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("send CONNECT");

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("407"), "expected 407, got: {resp}");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn standalone_valid_token_returns_200() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let rules_path = write_rules(
        tmp.path(),
        r#"{"agents":[{"token":"aoc_mytoken","host_rules":[{"host_pattern":"api.anthropic.com","injection_rules":[{"path_pattern":"*","injections":[{"action":"set_header","name":"x-api-key","value":"sk-test"}]}]}],"policy_rules":[]}]}"#,
    );
    let rules_arg = format!("--rules={}", rules_path.display());
    let (port, mut child) = start_gateway(tmp.path(), &[&rules_arg], &[]);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let auth = basic_auth("aoc_mytoken");
    let req = format!(
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nProxy-Authorization: {auth}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("send CONNECT");

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("200"),
        "expected 200 (intercept), got: {resp}"
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn standalone_anonymous_agent_intercepts() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let rules_path = write_rules(
        tmp.path(),
        r#"{"agents":[{"token":null,"host_rules":[{"host_pattern":"api.anthropic.com","injection_rules":[{"path_pattern":"*","injections":[{"action":"set_header","name":"x-api-key","value":"sk-anon"}]}]}],"policy_rules":[]}]}"#,
    );
    let rules_arg = format!("--rules={}", rules_path.display());
    let (port, mut child) = start_gateway(tmp.path(), &[&rules_arg], &[]);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    // No Proxy-Authorization header. Anonymous agent should match.
    let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    stream.write_all(req.as_bytes()).expect("send CONNECT");

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("200"),
        "expected 200 (intercept), got: {resp}"
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn standalone_ca_persists_across_restarts() {
    let tmp = tempfile::tempdir().expect("create temp dir");

    // First start, generates CA.
    let (_, mut child1) = start_gateway(tmp.path(), &[], &[]);
    child1.kill().ok();
    child1.wait().ok();

    let ca_key = tmp.path().join("gateway").join("ca.key");
    let ca_cert = tmp.path().join("gateway").join("ca.pem");
    assert!(ca_key.exists(), "ca.key should exist after first run");
    assert!(ca_cert.exists(), "ca.pem should exist after first run");
    let cert_1 = std::fs::read_to_string(&ca_cert).expect("read ca.pem");

    // Second start, should load existing CA.
    let (_, mut child2) = start_gateway(tmp.path(), &[], &[]);
    child2.kill().ok();
    child2.wait().ok();

    let cert_2 = std::fs::read_to_string(&ca_cert).expect("read ca.pem again");
    assert_eq!(cert_1, cert_2, "CA cert should persist across restarts");
}

#[test]
fn standalone_empty_rules_tunnels_everything() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    // No --rules flag, no config file exists. Gateway starts with empty snapshot.
    let (port, mut child) = start_gateway(tmp.path(), &[], &[]);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    stream.write_all(req.as_bytes()).expect("send CONNECT");

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200"), "expected 200 (tunnel), got: {resp}");

    child.kill().ok();
    child.wait().ok();
}

// ── DB-dependent tests (skip when DATABASE_URL not set) ─────────────────

fn require_db_env() -> Option<(String, String)> {
    let db_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    let key = std::env::var("SECRET_ENCRYPTION_KEY")
        .ok()
        .filter(|s| !s.is_empty())?;
    Some((db_url, key))
}

#[test]
fn connect_with_invalid_token_returns_401() {
    let Some((db_url, key)) = require_db_env() else {
        eprintln!("skipping: DATABASE_URL or SECRET_ENCRYPTION_KEY not set");
        return;
    };
    let tmp = tempfile::tempdir().expect("create temp dir");
    let (port, mut child) = start_gateway(
        tmp.path(),
        &[],
        &[("DATABASE_URL", &db_url), ("SECRET_ENCRYPTION_KEY", &key)],
    );

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let auth = basic_auth("aoc_nonexistent_token");
    let req = format!(
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nProxy-Authorization: {auth}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("send CONNECT");

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("407"), "expected 407, got: {resp}");

    child.kill().ok();
    child.wait().ok();
}
