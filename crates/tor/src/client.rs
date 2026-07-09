// ─────────────────────────────────────────────────────────────
// Tor client connection — connects to .onion addresses
// ─────────────────────────────────────────────────────────────

use anyhow::{Context, Result};
use arti_client::{TorClient, TorClientConfig, DataStream};
use arti_client::config::CfgPath;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct TorConnection {
    state_dir: PathBuf,
    cache_dir: PathBuf,
}

impl TorConnection {
    pub fn new(data_dir: &Path) -> Self {
        TorConnection {
            state_dir: data_dir.join("tor_client_state"),
            cache_dir: data_dir.join("tor_client_cache"),
        }
    }

    /// Connect to an onion address using embedded Arti.
    /// Returns a concrete DataStream (implements AsyncRead + AsyncWrite).
    pub async fn connect_to_onion(
        &self,
        onion_address: &str,
        port: u16,
    ) -> Result<DataStream> {
        std::fs::create_dir_all(&self.state_dir)?;
        std::fs::create_dir_all(&self.cache_dir)?;

        let mut builder = TorClientConfig::builder();
        builder.storage()
            .state_dir(CfgPath::new_literal(&self.state_dir))
            .cache_dir(CfgPath::new_literal(&self.cache_dir));

        let config = builder.build()
            .context("Failed to build Tor client config")?;

        info!("Bootstrapping Tor client...");
        let client = TorClient::create_bootstrapped(config)
            .await
            .context("Failed to bootstrap Tor client")?;

        info!("Connecting to {}:{}", onion_address, port);

        let addr = format!("{}:{}", onion_address, port);
        let stream = client
            .connect(&addr)
            .await
            .context("Failed to connect to onion service")?;

        info!("Connected to onion service");
        Ok(stream)
    }
}

/// Fallback: connect through a running SOCKS proxy
pub async fn connect_via_socks(
    socks_addr: &str,
    target_onion: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream> {
    use tokio_socks::tcp::Socks5Stream;

    info!(
        "Connecting to {} via SOCKS proxy {}",
        target_onion, socks_addr
    );

    let stream = Socks5Stream::connect(
        socks_addr,
        (target_onion, target_port),
    )
    .await
    .context("SOCKS5 connection failed")?;

    Ok(stream.into_inner())
}
