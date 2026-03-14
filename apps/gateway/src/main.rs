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
    #[arg(long, default_value = default_data_dir())]
    data_dir: PathBuf,

    /// Local mode: load rules from a TOML file instead of the web API.
    /// No auth tokens needed — rules are resolved entirely from the local file.
    #[arg(long)]
    local: bool,

    /// Path to the local rules TOML file (used with --local).
    #[arg(long, default_value = default_rules_file())]
    rules_file: PathBuf,

    /// OneCLI web API base URL (for credential fetching in API mode).
    #[arg(long, default_value = "http://localhost:10254")]
    api_url: String,

    /// Path to the gateway–API shared secret file.
    /// The secret is used to authenticate credential requests to the web API.
    /// Can also be set via the GATEWAY_SECRET environment variable (takes precedence).
    #[arg(long, default_value = default_gateway_secret_file())]
    gateway_secret_file: PathBuf,
}

fn default_data_dir() -> &'static str {
    if cfg!(target_os = "linux") && Path::new("/app/data").exists() {
        "/app/data"
    } else {
        "~/.onecli"
    }
}

fn default_gateway_secret_file() -> &'static str {
    if cfg!(target_os = "linux") && Path::new("/app/data").exists() {
        "/app/data/gateway-secret"
    } else {
        "~/.onecli/gateway-secret"
    }
}

fn default_rules_file() -> &'static str {
    if cfg!(target_os = "linux") && Path::new("/app/data").exists() {
        "/app/data/rules.toml"
    } else {
        "~/.onecli/rules.toml"
    }
}

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

    // Expand ~ in data dir
    let data_dir = expand_tilde(&cli.data_dir);

    info!(data_dir = %data_dir.display(), "starting onecli-gateway");

    // Load or generate CA
    let ca = CertificateAuthority::load_or_generate(&data_dir).await?;

    // Build mode
    let mode = if cli.local {
        let rules_path = expand_tilde(&cli.rules_file);
        let rules = local::load(&rules_path)?;
        info!(
            rules_file = %rules_path.display(),
            rule_count = rules.len(),
            "local mode: loaded rules"
        );
        Mode::Local(rules)
    } else {
        let gateway_secret = load_gateway_secret(&cli.gateway_secret_file);
        info!(
            api_url = %cli.api_url,
            gateway_secret_loaded = gateway_secret.is_some(),
            "API mode"
        );
        Mode::Api {
            api_url: cli.api_url.into(),
            gateway_secret: gateway_secret.map(|s| s.into()),
        }
    };

    info!(port = cli.port, bind = %cli.bind, "gateway ready");

    // Start the gateway server (blocks forever)
    let server = GatewayServer::new(ca, cli.port, cli.bind, mode);
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

    // OSS: read from file
    let path = expand_tilde(secret_file);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let secret = contents.trim().to_string();
            if secret.is_empty() {
                warn!(path = %path.display(), "gateway secret file is empty");
                None
            } else {
                info!(path = %path.display(), "loaded gateway secret from file");
                Some(secret)
            }
        }
        Err(_) => {
            warn!(
                path = %path.display(),
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
