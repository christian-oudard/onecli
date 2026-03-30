//! Control socket: a small HTTP server bound to a Unix domain socket.
//!
//! The web UI connects and POSTs a full `RulesSnapshot` whenever config
//! changes in the database. The gateway replaces its in-memory state
//! atomically and returns 200.
//!
//! Socket location: `$XDG_RUNTIME_DIR/onecli/control.sock`
//! Directory mode: 0700 — socket mode: 0600 (kernel-enforced, same-user only).

use std::convert::Infallible;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::rules::RulesSnapshot;

// ── Socket path ──────────────────────────────────────────────────────────

/// Return the control socket path, derived from `$XDG_RUNTIME_DIR`.
///
/// Returns `None` if `XDG_RUNTIME_DIR` is not set and a fallback cannot
/// be determined. The path is not user-configurable so that the bwrap
/// mount namespace can reliably exclude it.
pub(crate) fn socket_path() -> Option<PathBuf> {
    // Prefer the environment variable (set by login managers / pam_systemd).
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(dir).join("onecli").join("control.sock"));
    }

    // Fallback: /run/user/{euid} — read UID from /proc on Linux.
    if let Some(uid) = effective_uid() {
        return Some(
            PathBuf::from(format!("/run/user/{uid}"))
                .join("onecli")
                .join("control.sock"),
        );
    }

    None
}

// ── Server ───────────────────────────────────────────────────────────────

/// Start the control socket server. Runs until the process exits.
///
/// Creates the socket directory (mode 0700) and socket file (mode 0600),
/// then accepts connections and dispatches `POST /rules`.
pub(crate) async fn run(
    socket_path: PathBuf,
    rules_tx: watch::Sender<Arc<RulesSnapshot>>,
    bind_addr: IpAddr,
    allow_public_anonymous: bool,
) -> Result<()> {
    // Create parent directory with secure permissions.
    let parent = socket_path
        .parent()
        .expect("socket path must have a parent");
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating control socket directory {}", parent.display()))?;
    tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .await
        .with_context(|| {
            format!(
                "setting permissions on control socket directory {}",
                parent.display()
            )
        })?;

    // Remove a stale socket file from a previous run.
    let _ = tokio::fs::remove_file(&socket_path).await;

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding Unix socket {}", socket_path.display()))?;

    // Restrict socket access to the owning user.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", socket_path.display()))?;

    info!(path = %socket_path.display(), "control socket listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "control socket accept error");
                continue;
            }
        };

        let tx = rules_tx.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                handle_request(req, tx.clone(), bind_addr, allow_public_anonymous)
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                warn!(error = %e, "control socket connection error");
            }
        });
    }
}

// ── Request handler ──────────────────────────────────────────────────────

async fn handle_request(
    req: Request<Incoming>,
    rules_tx: watch::Sender<Arc<RulesSnapshot>>,
    bind_addr: IpAddr,
    allow_public_anonymous: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::POST || req.uri().path() != "/rules" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    let body = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                &format!("failed to read body: {e}"),
            ));
        }
    };

    let snapshot = match serde_json::from_slice::<RulesSnapshot>(&body) {
        Ok(s) => s,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                &format!("invalid rules snapshot: {e}"),
            ));
        }
    };

    if let Err(msg) =
        crate::rules::check_anonymous_public(&snapshot, bind_addr, allow_public_anonymous)
    {
        return Ok(error_response(StatusCode::BAD_REQUEST, &msg));
    }

    let agent_count = snapshot.agents.len();
    rules_tx.send(Arc::new(snapshot)).ok();
    info!(
        agents = agent_count,
        "rules snapshot updated via control socket"
    );
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Read the effective UID from `/proc/self/status` (Linux only).
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Line format: "Uid: real effective saved filesystem"
            return rest.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}
