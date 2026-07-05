// ─────────────────────────────────────────────────────────────
//  ███████╗███████╗██████╗  ██████╗ ███████╗██╗   ██╗███╗   ███╗
//  ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║████╗ ████║
//    ███╔╝ █████╗  ██████╔╝██║   ██║███████╗██║   ██║██╔████╔██║
//   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║╚════██║██║   ██║██║╚██╔╝██║
//  ███████╗███████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║ ╚═╝ ██║
//  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝
//
//  SERVER — friend-to-friend encrypted relay
// ─────────────────────────────────────────────────────────────
// Run this on any machine. It spins up its own Tor hidden service.
// Share the .onion address with your friend. That's it.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn, error};
use tracing_subscriber::EnvFilter;

use zerosum_server::db::Database;
use zerosum_server::handler::{ClientHandler, OnlineClients};

const BANNER: &str = r#"
 ███████╗███████╗██████╗  ██████╗ ███████╗██╗   ██╗███╗   ███╗
 ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║████╗ ████║
   ███╔╝ █████╗  ██████╔╝██║   ██║███████╗██║   ██║██╔████╔██║
  ███╔╝  ██╔══╝  ██╔══██╗██║   ██║╚════██║██║   ██║██║╚██╔╝██║
 ███████╗███████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║ ╚═╝ ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝
"#;

#[derive(Parser, Debug)]
#[command(name = "zerosum-server", about = "ZeroSum server — encrypted relay with embedded Tor")]
struct Args {
    /// Disable Tor hidden service (local-only mode)
    #[arg(long)]
    no_tor: bool,

    /// Server bind port
    #[arg(short, long, default_value = "18080")]
    port: u16,

    /// Data directory
    #[arg(short, long)]
    data_dir: Option<PathBuf>,
}

/// Check if ZEROSUM_NO_TOR env var is set to a truthy value
fn env_no_tor() -> bool {
    match std::env::var("ZEROSUM_NO_TOR") {
        Ok(val) => matches!(val.to_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    eprintln!("\x1b[31m{}\x1b[0m", BANNER);
    eprintln!("\x1b[90m  server v{}\x1b[0m", env!("CARGO_PKG_VERSION"));

    // Data directory
    let data_dir = args.data_dir
        .or_else(|| std::env::var("ZEROSUM_DATA_DIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("zerosum_server_data"));

    std::fs::create_dir_all(&data_dir)?;

    // Open database
    let db_path = data_dir.join("zerosum.db");
    let db = Arc::new(Database::open(&db_path)?);
    info!("Database opened: {}", db_path.display());

    // Shared map of online clients for direct message delivery
    let online_clients: OnlineClients = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    // Determine mode: Tor is ON by default, disabled only by explicit --no-tor flag or ZEROSUM_NO_TOR=1
    let use_tor = !args.no_tor && !env_no_tor();
    let bind_port = args.port;
    let bind_addr = format!("127.0.0.1:{}", bind_port);

    eprintln!();

    // This must live for the entire process — dropping it kills the onion service
    let mut _tor_service: Option<zerosum_tor::EmbeddedTorService> = None;

    if use_tor {
        // Start embedded Tor hidden service
        eprintln!("\x1b[33m  ⏳ Starting embedded Tor hidden service...\x1b[0m");
        eprintln!("\x1b[90m  This may take 30-60 seconds on first run.\x1b[0m");
        eprintln!("\x1b[90m  Use --no-tor to skip and run local-only.\x1b[0m");
        eprintln!();

        match zerosum_tor::start_tor_hidden_service(&data_dir, bind_port).await {
            Ok((service, onion_addr)) => {
                eprintln!("\x1b[32m  ✓ Tor hidden service active\x1b[0m");
                eprintln!();
                eprintln!("\x1b[1;36m  ╔══════════════════════════════════════════════════════════════╗\x1b[0m");
                eprintln!("\x1b[1;36m  ║  ONION ADDRESS:                                             ║\x1b[0m");
                eprintln!("\x1b[1;33m  ║  {}  ║\x1b[0m", onion_addr);
                eprintln!("\x1b[1;36m  ╚══════════════════════════════════════════════════════════════╝\x1b[0m");
                eprintln!();
                eprintln!("\x1b[90m  Share this address with your friend.\x1b[0m");
                eprintln!("\x1b[90m  They connect with: zerosum-client --server {}\x1b[0m", onion_addr);

                // Save to file
                std::fs::write(data_dir.join("onion_address.txt"), &onion_addr)?;

                // KEEP THE SERVICE ALIVE for the lifetime of the server
                _tor_service = Some(service);
            }
            Err(e) => {
                error!("Failed to start Tor: {}", e);
                eprintln!("\x1b[31m  ✗ Tor failed: {}\x1b[0m", e);
                eprintln!("\x1b[33m  Falling back to local-only mode.\x1b[0m");
                eprintln!("\x1b[33m  Use --no-tor to suppress this warning.\x1b[0m");
            }
        }
    } else {
        if args.no_tor {
            eprintln!("\x1b[33m  ⚠ Tor disabled (--no-tor flag)\x1b[0m");
        } else {
            eprintln!("\x1b[33m  ⚠ Tor disabled (ZEROSUM_NO_TOR=1)\x1b[0m");
        }
        eprintln!("\x1b[33m  Server will only be reachable on the local network.\x1b[0m");
        eprintln!("\x1b[90m  Remove the flag or unset the env var to enable Tor.\x1b[0m");
    }

    eprintln!();

    // Bind TCP listener
    let listener = TcpListener::bind(&bind_addr)
        .await
        .context(format!("Failed to bind {}", bind_addr))?;

    eprintln!("\x1b[32m  ✓ Listening on {}\x1b[0m", bind_addr);
    eprintln!("\x1b[90m  Press Ctrl+C to stop.\x1b[0m");
    eprintln!();

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                let db = db.clone();
                let oc = online_clients.clone();

                tokio::spawn(async move {
                    let mut handler = ClientHandler::new(db, oc);
                    let mut stream = stream;
                    if let Err(e) = handler.handle(&mut stream).await {
                        warn!("Connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}
