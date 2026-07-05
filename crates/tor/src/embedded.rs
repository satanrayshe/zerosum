// ─────────────────────────────────────────────────────────────
// Embedded Tor hidden service (server-side)
// ─────────────────────────────────────────────────────────────

use anyhow::{Context, Result};
use arti_client::{TorClient, TorClientConfig};
use arti_client::config::CfgPath;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{info, warn};
use futures::StreamExt;

pub struct TorServiceConfig {
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub local_port: u16,
    pub hs_port: u16,
}

impl Default for TorServiceConfig {
    fn default() -> Self {
        TorServiceConfig {
            state_dir: PathBuf::from("zerosum_tor_state"),
            cache_dir: PathBuf::from("zerosum_tor_cache"),
            local_port: 18080,
            hs_port: 80,
        }
    }
}

pub struct EmbeddedTorService {
    config: TorServiceConfig,
    onion_address: Option<String>,
    /// Keep the running onion service alive — dropping this kills the service!
    _running_svc: Option<Arc<tor_hsservice::RunningOnionService>>,
    /// Keep the TorClient alive too
    _tor_client: Option<TorClient<tor_rtcompat::PreferredRuntime>>,
}

impl EmbeddedTorService {
    pub fn new(config: TorServiceConfig) -> Self {
        EmbeddedTorService {
            config,
            onion_address: None,
            _running_svc: None,
            _tor_client: None,
        }
    }

    pub async fn start(&mut self) -> Result<String> {
        info!("Bootstrapping embedded Tor...");

        std::fs::create_dir_all(&self.config.state_dir)?;
        std::fs::create_dir_all(&self.config.cache_dir)?;

        let mut builder = TorClientConfig::builder();
        builder.storage()
            .state_dir(CfgPath::new_literal(&self.config.state_dir))
            .cache_dir(CfgPath::new_literal(&self.config.cache_dir));

        let tor_config = builder.build()
            .context("Failed to build TorClientConfig")?;

        let tor_client = TorClient::create_bootstrapped(tor_config)
            .await
            .context("Failed to bootstrap Tor client")?;

        info!("Tor bootstrapped successfully");

        let svc_builder: tor_hsservice::config::OnionServiceConfigBuilder = serde_json::from_str(
            r#"{"nickname": "zerosum"}"#
        ).context("Failed to deserialize onion service config builder")?;
        let svc_config = svc_builder.build()
            .context("Failed to build onion service config")?;

        // Launch onion service
        let (svc, rend_request_stream) = tor_client
            .launch_onion_service(svc_config)
            .context("Failed to launch onion service")?;

        // Get the onion address — onion_address() already returns the HsId
        // which formats as "xxxxx.onion", so DON'T add .onion again
        let onion_addr = svc
            .onion_address()
            .map(|name| {
                let s = format!("{}", name);
                // If it already ends with .onion, use as-is; otherwise append
                if s.ends_with(".onion") {
                    s
                } else {
                    format!("{}.onion", s)
                }
            })
            .unwrap_or_else(|| "unknown.onion".to_string());

        info!("Onion service active: {}", onion_addr);
        self.onion_address = Some(onion_addr.clone());

        // IMPORTANT: Keep the RunningOnionService and TorClient alive!
        // Dropping either one kills the onion service.
        self._running_svc = Some(svc);
        self._tor_client = Some(tor_client);

        // Spawn task to handle incoming connections
        let local_port = self.config.local_port;
        tokio::spawn(async move {
            let mut stream_requests = tor_hsservice::handle_rend_requests(rend_request_stream);
            while let Some(stream_req) = stream_requests.next().await {
                let local_port = local_port;
                tokio::spawn(async move {
                    match Self::handle_stream_request(stream_req, local_port).await {
                        Ok(_) => {},
                        Err(e) => warn!("Onion stream error: {}", e),
                    }
                });
            }
            warn!("Onion service stream ended");
        });

        Ok(onion_addr)
    }

    async fn handle_stream_request(
        stream_req: tor_hsservice::StreamRequest,
        local_port: u16,
    ) -> Result<()> {
        use tor_proto::stream::IncomingStreamRequest;
        use tor_cell::relaycell::msg::Connected;

        match stream_req.request() {
            IncomingStreamRequest::Begin(_) => {},
            _ => return Ok(()),
        }

        let mut data_stream = stream_req
            .accept(Connected::new_empty())
            .await
            .context("Failed to accept onion stream")?;

        let mut local = TcpStream::connect(format!("127.0.0.1:{}", local_port))
            .await
            .context("Failed to connect to local server")?;

        tokio::io::copy_bidirectional(&mut data_stream, &mut local).await?;
        Ok(())
    }

    pub fn onion_address(&self) -> Option<&str> {
        self.onion_address.as_deref()
    }
}

pub async fn start_tor_hidden_service(
    state_dir: &Path,
    local_port: u16,
) -> Result<(EmbeddedTorService, String)> {
    let config = TorServiceConfig {
        state_dir: state_dir.join("tor_state"),
        cache_dir: state_dir.join("tor_cache"),
        local_port,
        hs_port: 80,
    };

    let mut service = EmbeddedTorService::new(config);
    let address = service.start().await?;
    Ok((service, address))
}
