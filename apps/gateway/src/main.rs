mod ca;
mod connect;
mod gateway;
mod inject;
mod local;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::ca::CertificateAuthority;
use crate::gateway::{GatewayServer, Mode};

#[derive(Parser)]
#[command(
    name = "onecli-gateway",
    about = "OneCLI MITM gateway for credential injection"
)]
struct Cli {
    /// Port to listen on.
    #[arg(long, default_value = "10255")]
    port: u16,

    /// Address to bind to.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Data directory for CA certificates and persistent state.
    /// Default: $XDG_DATA_HOME/onecli, falling back to ~/.onecli if it exists.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Local mode: load rules from a TOML file instead of the web API.
    /// No auth tokens needed — rules are resolved entirely from the local file.
    #[arg(long)]
    local: bool,

    /// Path to the local rules TOML file (used with --local).
    /// Default: $XDG_CONFIG_HOME/onecli/rules.toml, falling back to ~/.onecli/rules.toml.
    #[arg(long)]
    rules_file: Option<PathBuf>,

    /// OneCLI web API base URL (for credential fetching in API mode).
    #[arg(long, default_value = "http://localhost:10254")]
    api_url: String,

    /// Path to the gateway–API shared secret file.
    /// The secret is used to authenticate credential requests to the web API.
    /// Can also be set via the GATEWAY_SECRET environment variable (takes precedence).
    #[arg(long)]
    gateway_secret_file: Option<PathBuf>,
}

// ── XDG / legacy path resolution ────────────────────────────────────────

/// Resolve the data directory: explicit flag > /app/data (Docker) > XDG > legacy ~/.onecli.
fn resolve_data_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return expand_tilde(p);
    }
    if cfg!(target_os = "linux") && Path::new("/app/data").exists() {
        return PathBuf::from("/app/data");
    }
    let legacy = expand_tilde(Path::new("~/.onecli"));
    if legacy.is_dir() {
        return legacy;
    }
    xdg_data_home().join("onecli")
}

/// Resolve the rules file: explicit flag > /app/data (Docker) > XDG > legacy.
fn resolve_rules_file(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return expand_tilde(p);
    }
    if cfg!(target_os = "linux") && Path::new("/app/data").exists() {
        return PathBuf::from("/app/data/rules.toml");
    }
    let legacy = expand_tilde(Path::new("~/.onecli/rules.toml"));
    if legacy.is_file() {
        return legacy;
    }
    xdg_config_home().join("onecli").join("rules.toml")
}

/// Resolve the gateway secret file: explicit flag > /app/data (Docker) > XDG > legacy.
fn resolve_gateway_secret_file(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return expand_tilde(p);
    }
    if cfg!(target_os = "linux") && Path::new("/app/data").exists() {
        return PathBuf::from("/app/data/gateway-secret");
    }
    let legacy = expand_tilde(Path::new("~/.onecli/gateway-secret"));
    if legacy.is_file() {
        return legacy;
    }
    xdg_data_home().join("onecli").join("gateway-secret")
}

fn xdg_data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| expand_tilde(Path::new("~/.local/share")))
}

fn xdg_config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| expand_tilde(Path::new("~/.config")))
}

// ── main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Install ring as the default rustls CryptoProvider (required by reqwest)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let data_dir = resolve_data_dir(cli.data_dir.as_deref());

    info!(data_dir = %data_dir.display(), "starting onecli-gateway");

    // Load or generate CA
    let ca = CertificateAuthority::load_or_generate(&data_dir).await?;

    // Build mode
    let (mode, rules_path) = if cli.local {
        let rules_path = resolve_rules_file(cli.rules_file.as_deref());
        let rules = local::load(&rules_path)?;
        info!(
            rules_file = %rules_path.display(),
            rule_count = rules.len(),
            "local mode: loaded rules (send SIGHUP to reload)"
        );
        (Mode::Local(std::sync::RwLock::new(rules)), Some(rules_path))
    } else {
        let secret_path = resolve_gateway_secret_file(cli.gateway_secret_file.as_deref());
        let gateway_secret = load_gateway_secret(&secret_path);
        info!(
            api_url = %cli.api_url,
            gateway_secret_loaded = gateway_secret.is_some(),
            "API mode (send SIGHUP to clear cache)"
        );
        (Mode::Api {
            api_url: cli.api_url.into(),
            gateway_secret: gateway_secret.map(|s| s.into()),
        }, None)
    };

    info!(port = cli.port, bind = %cli.bind, "gateway ready");

    // Start the gateway server (blocks forever)
    let server = GatewayServer::new(ca, cli.port, cli.bind, mode, rules_path);
    server.run().await
}

/// Load the gateway–API shared secret.
/// Checks `GATEWAY_SECRET` env var first (cloud), then reads from file (OSS).
/// Returns `None` if neither is available (credential fetching will be disabled).
fn load_gateway_secret(secret_file: &Path) -> Option<String> {
    // Cloud: env var takes precedence
    if let Ok(secret) = std::env::var("GATEWAY_SECRET") {
        let secret = secret.trim().to_string();
        if !secret.is_empty() {
            info!("loaded gateway secret from GATEWAY_SECRET env var");
            return Some(secret);
        }
    }

    match std::fs::read_to_string(secret_file) {
        Ok(contents) => {
            let secret = contents.trim().to_string();
            if secret.is_empty() {
                warn!(path = %secret_file.display(), "gateway secret file is empty");
                None
            } else {
                info!(path = %secret_file.display(), "loaded gateway secret from file");
                Some(secret)
            }
        }
        Err(_) => {
            warn!(
                path = %secret_file.display(),
                "gateway secret file not found — credential fetching will be unavailable until the web API generates it"
            );
            None
        }
    }
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
