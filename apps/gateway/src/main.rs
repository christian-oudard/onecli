#[cfg(not(feature = "cloud"))]
#[allow(dead_code)]
mod auth;

#[cfg(feature = "cloud")]
#[path = "cloud/auth.rs"]
mod auth;

mod ca;
mod config;
mod connect;
mod control;

#[cfg(not(feature = "cloud"))]
mod cache;

#[cfg(feature = "cloud")]
#[path = "cloud/cache.rs"]
mod cache;

mod apps;
#[cfg(not(feature = "cloud"))]
mod crypto;

#[cfg(feature = "cloud")]
#[path = "cloud/crypto.rs"]
mod crypto;

#[allow(dead_code)]
mod db;
mod gateway;
mod inject;
mod policy;
mod rules;
mod token_state;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::ca::CertificateAuthority;
use crate::gateway::GatewayServer;

#[derive(Parser)]
#[command(
    name = "onecli-gateway",
    about = "OneCLI MITM gateway for credential injection"
)]
struct Cli {
    /// Address to bind the proxy listener to.
    /// Defaults to 127.0.0.1. Use 0.0.0.0 to accept connections from other
    /// hosts, but note that anonymous agents (token: null) are rejected on
    /// non-loopback addresses unless --allow-public-anonymous is also set.
    #[arg(long, default_value = "127.0.0.1")]
    bind: IpAddr,

    /// Port to listen on.
    #[arg(long, default_value = "10255")]
    port: u16,

    /// Data directory for CA certificates and persistent state.
    #[arg(long, default_value = default_data_dir())]
    data_dir: PathBuf,

    /// Path to the rules JSON config file.
    /// Defaults to $XDG_CONFIG_HOME/onecli/rules.json (non-root)
    /// or /etc/onecli/rules.json (root).
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Disable the Unix domain control socket.
    /// By default the gateway listens for rule pushes from the web UI.
    #[arg(long)]
    no_control_socket: bool,

    /// Allow anonymous agents (token: null) when bound to a non-loopback
    /// address. By default the gateway refuses to start in this configuration
    /// because any host that can reach the port would be able to use your
    /// credentials without authentication.
    #[arg(long)]
    allow_public_anonymous: bool,
}

fn default_data_dir() -> &'static str {
    if cfg!(target_os = "linux") && Path::new("/app/data").exists() {
        "/app/data"
    } else {
        "~/.onecli"
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install ring as the default rustls CryptoProvider (required by reqwest)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Initialize logging — JSON for production (CloudWatch), text for dev
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_target(true)
            .flatten_event(true)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    let cli = Cli::parse();
    let data_dir = expand_tilde(&cli.data_dir);

    info!(data_dir = %data_dir.display(), "starting onecli-gateway");

    // Load or generate CA
    let ca = CertificateAuthority::load_or_generate(&data_dir).await?;

    // ── Rules watch channel ─────────────────────────────────────────────

    let (rules_tx, rules_rx) = rules::channel();

    // Load initial rules from config file.
    let rules_path = config::resolve_rules_path(cli.rules.as_deref());
    match config::load_rules_from_file(&rules_path).await {
        Ok(snapshot) => {
            let agent_count = snapshot.agents.len();
            rules::check_anonymous_public(&snapshot, cli.bind, cli.allow_public_anonymous)
                .map_err(|msg| anyhow::anyhow!("{msg}"))?;
            rules_tx.send(Arc::new(snapshot)).ok();
            if agent_count > 0 {
                info!(path = %rules_path.display(), agents = agent_count, "loaded rules from config");
            } else {
                info!(path = %rules_path.display(), "config file not found; starting with empty rules");
            }
        }
        Err(e) => {
            warn!(error = ?e, "failed to load rules config; starting with empty rules");
        }
    }

    // SIGHUP handler: reload the config file.
    {
        let tx = rules_tx.clone();
        let path = rules_path.clone();
        let bind = cli.bind;
        let allow_public_anonymous = cli.allow_public_anonymous;
        tokio::spawn(async move {
            let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("registering SIGHUP handler");
            loop {
                sighup.recv().await;
                match config::load_rules_from_file(&path).await {
                    Ok(snapshot) => {
                        if let Err(msg) =
                            rules::check_anonymous_public(&snapshot, bind, allow_public_anonymous)
                        {
                            warn!("SIGHUP: rejecting reload: {msg}");
                            continue;
                        }
                        tx.send(Arc::new(snapshot)).ok();
                        info!(path = %path.display(), "reloaded rules on SIGHUP");
                    }
                    Err(e) => {
                        warn!(error = %e, "SIGHUP: failed to reload rules; keeping current rules");
                    }
                }
            }
        });
    }

    // ── Control socket ──────────────────────────────────────────────────

    if !cli.no_control_socket {
        match control::socket_path() {
            Some(path) => {
                let tx = rules_tx.clone();
                let bind = cli.bind;
                let allow_public_anonymous = cli.allow_public_anonymous;
                tokio::spawn(async move {
                    if let Err(e) = control::run(path, tx, bind, allow_public_anonymous).await {
                        warn!(error = %e, "control socket stopped");
                    }
                });
            }
            None => {
                warn!(
                    "XDG_RUNTIME_DIR not set and /proc/self/status not readable; \
                     control socket disabled (use --no-control-socket to suppress this warning)"
                );
            }
        }
    }

    // ── Optional database (browser auth only) ─────────────────────────

    let db_pool = match std::env::var("DATABASE_URL").ok().or_else(|| {
        let host = std::env::var("DB_HOST").ok()?;
        let port = std::env::var("DB_PORT").unwrap_or_else(|_| "5432".to_string());
        let user = std::env::var("DB_USERNAME").ok()?;
        let pass = std::env::var("DB_PASSWORD").ok()?;
        let name = std::env::var("DB_NAME").unwrap_or_else(|_| "onecli".to_string());
        Some(format!("postgresql://{user}:{pass}@{host}:{port}/{name}"))
    }) {
        Some(url) => match db::create_pool(&url).await {
            Ok(pool) => {
                info!("database connection established (browser auth enabled)");
                Some(pool)
            }
            Err(e) => {
                warn!(error = %e, "database connection failed; browser auth disabled");
                None
            }
        },
        None => None,
    };

    // ── Cache store ──────────────────────────────────────────────────────

    let cache = cache::create_store().await?;

    // ── Token state store (OAuth runtime credentials) ────────────────────

    let token_store = match crypto::CryptoService::from_env().await {
        Ok(crypto) => match token_state::TokenStateStore::open(&data_dir, crypto).await {
            Ok(store) => {
                info!("token state store opened (OAuth app connections enabled)");
                Some(Arc::new(store))
            }
            Err(e) => {
                warn!(error = ?e, "failed to open token state store; OAuth app connections disabled");
                None
            }
        },
        Err(_) => {
            info!("SECRET_ENCRYPTION_KEY not set; OAuth app connections disabled");
            None
        }
    };

    info!(port = cli.port, "gateway ready");

    // Start the gateway server (blocks forever)
    let state = gateway::GatewayState {
        ca: Arc::new(ca),
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(
                std::env::var("GATEWAY_DANGER_ACCEPT_INVALID_CERTS").is_ok(),
            )
            .build()
            .expect("build HTTP client"),
        rules: rules_rx,
        cache,
        db_pool,
        token_store,
    };
    let server = GatewayServer::new(cli.bind, cli.port, state);
    server.run().await
}

/// Expand `~` at the start of a path to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") || s == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(s.strip_prefix("~/").unwrap_or(""));
        }
    }
    path.to_path_buf()
}
