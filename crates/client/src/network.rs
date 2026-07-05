// ─────────────────────────────────────────────────────────────
// Network layer — connects to server, handles all I/O
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use std::path::Path;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::info;

use zerosum_protocol::*;

type BoxRead = Pin<Box<dyn AsyncRead + Unpin + Send>>;
type BoxWrite = Pin<Box<dyn AsyncWrite + Unpin + Send>>;

#[derive(Debug, Clone)]
pub enum NetEvent {
    Connected,
    Disconnected(String),
    RegisterOk,
    RegisterFail(String),
    LoginOk,
    LoginFail(String),

    /// Incoming chat request
    IncomingChatRequest {
        from: String,
        identity_public_key: Vec<u8>,
        ephemeral_pub: Vec<u8>,
        otpk_index: Option<u32>,
    },

    /// Our chat request was accepted
    ChatRequestAccepted {
        from: String,
        identity_public_key: Vec<u8>,
    },

    /// Our chat request was rejected
    ChatRequestRejected { from: String },

    ChatAck { ok: bool, error: Option<String> },

    /// Bundle fetched (for internal use during chat request flow)
    BundleReceived {
        username: String,
        identity_public_key: Vec<u8>,
        signed_prekey: Vec<u8>,
        signed_prekey_signature: Vec<u8>,
        one_time_prekey: Option<Vec<u8>>,
        otpk_index: Option<u32>,
    },
    BundleError(String, String),

    /// Incoming encrypted message
    MessageReceived {
        from: String,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        timestamp: u64,
    },

    FileReceived {
        from: String,
        filename: String,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        timestamp: u64,
    },

    MessageSent,
    SendFail(String),

    HeartbeatAck { pending: u32 },
    Error(String),
    SystemMessage(String),
}

#[derive(Debug)]
pub enum NetCommand {
    Register {
        username: String,
        password_hash: Vec<u8>,
        identity_public_key: Vec<u8>,
        signed_prekey: Vec<u8>,
        signed_prekey_signature: Vec<u8>,
        one_time_prekeys: Vec<Vec<u8>>,
    },
    Login {
        username: String,
        password_hash: Vec<u8>,
    },
    FetchBundle { target: String },
    ChatRequest {
        to: String,
        identity_public_key: Vec<u8>,
        ephemeral_pub: Vec<u8>,
        otpk_index: Option<u32>,
    },
    ChatAccept { to: String },
    ChatReject { to: String },
    SendMessage {
        to: String,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    },
    Heartbeat,
    Disconnect,
}

pub async fn network_task(
    server_addr: String,
    use_tor: bool,
    data_dir: std::path::PathBuf,
    mut cmd_rx: mpsc::Receiver<NetCommand>,
    event_tx: mpsc::Sender<NetEvent>,
) {
    loop {
        let _ = event_tx.send(NetEvent::SystemMessage(format!("Connecting to {}...", server_addr))).await;

        let (mut reader, mut writer): (BoxRead, BoxWrite) = if use_tor {
            match connect_with_tor(&server_addr, &data_dir).await {
                Ok(pair) => pair,
                Err(e) => {
                    let _ = event_tx.send(NetEvent::Disconnected(format!("Tor connection failed: {}", e))).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
        } else {
            match TcpStream::connect(&server_addr).await {
                Ok(s) => { let (r, w) = tokio::io::split(s); (Box::pin(r) as BoxRead, Box::pin(w) as BoxWrite) }
                Err(e) => {
                    let _ = event_tx.send(NetEvent::Disconnected(format!("Connection failed: {}", e))).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
        };

        let _ = event_tx.send(NetEvent::Connected).await;

        if let Err(e) = write_frame(&mut writer, &ClientMessage::Hello { version: PROTOCOL_VERSION }).await {
            let _ = event_tx.send(NetEvent::Disconnected(format!("Handshake failed: {}", e))).await;
            continue;
        }

        match read_frame::<_, ServerMessage>(&mut reader).await {
            Ok(ServerMessage::HelloAck { ok: true, .. }) => { info!("Handshake OK"); }
            Ok(ServerMessage::HelloAck { ok: false, version }) => {
                let _ = event_tx.send(NetEvent::Disconnected(format!("Version mismatch (server: {})", version))).await;
                return;
            }
            _ => {
                let _ = event_tx.send(NetEvent::Disconnected("Bad handshake".into())).await;
                continue;
            }
        }

        let result = message_loop(&mut reader, &mut writer, &mut cmd_rx, &event_tx).await;
        if let Err(e) = result {
            let _ = event_tx.send(NetEvent::Disconnected(format!("Connection lost: {}", e))).await;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
}

async fn message_loop(
    reader: &mut BoxRead, writer: &mut BoxWrite,
    cmd_rx: &mut mpsc::Receiver<NetCommand>,
    event_tx: &mpsc::Sender<NetEvent>,
) -> Result<()> {
    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            server_msg = read_frame::<_, ServerMessage>(reader) => {
                match server_msg {
                    Ok(msg) => handle_server_message(msg, event_tx).await?,
                    Err(ProtoError::ConnectionClosed) => return Err(anyhow::anyhow!("Server closed connection")),
                    Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetCommand::Disconnect) => { let _ = write_frame(writer, &ClientMessage::Goodbye).await; return Ok(()); }
                    Some(cmd) => handle_command(cmd, writer).await?,
                    None => { let _ = write_frame(writer, &ClientMessage::Goodbye).await; return Ok(()); }
                }
            }
            _ = heartbeat_interval.tick() => {
                let jitter = rand::random::<u64>() % 3000;
                tokio::time::sleep(tokio::time::Duration::from_millis(jitter)).await;
                write_frame(writer, &ClientMessage::Heartbeat).await?;
            }
        }
    }
}

async fn handle_server_message(msg: ServerMessage, tx: &mpsc::Sender<NetEvent>) -> Result<()> {
    match msg {
        ServerMessage::RegisterAck { ok, error } => {
            let _ = tx.send(if ok { NetEvent::RegisterOk } else { NetEvent::RegisterFail(error.unwrap_or_default()) }).await;
        }
        ServerMessage::LoginAck { ok, error } => {
            let _ = tx.send(if ok { NetEvent::LoginOk } else { NetEvent::LoginFail(error.unwrap_or_default()) }).await;
        }
        ServerMessage::HeartbeatAck { pending_messages } => {
            let _ = tx.send(NetEvent::HeartbeatAck { pending: pending_messages }).await;
        }
        ServerMessage::Bundle { username, identity_public_key, signed_prekey, signed_prekey_signature, one_time_prekey, otpk_index } => {
            let _ = tx.send(NetEvent::BundleReceived { username, identity_public_key, signed_prekey, signed_prekey_signature, one_time_prekey, otpk_index }).await;
        }
        ServerMessage::BundleError { username, error } => {
            let _ = tx.send(NetEvent::BundleError(username, error)).await;
        }
        ServerMessage::IncomingChatRequest { from, identity_public_key, ephemeral_pub, otpk_index } => {
            let _ = tx.send(NetEvent::IncomingChatRequest { from, identity_public_key, ephemeral_pub, otpk_index }).await;
        }
        ServerMessage::ChatRequestAccepted { from, identity_public_key } => {
            let _ = tx.send(NetEvent::ChatRequestAccepted { from, identity_public_key }).await;
        }
        ServerMessage::ChatRequestRejected { from } => {
            let _ = tx.send(NetEvent::ChatRequestRejected { from }).await;
        }
        ServerMessage::ChatAck { ok, error } => {
            let _ = tx.send(NetEvent::ChatAck { ok, error }).await;
        }
        ServerMessage::SendAck { ok, error } => {
            let _ = tx.send(if ok { NetEvent::MessageSent } else { NetEvent::SendFail(error.unwrap_or_default()) }).await;
        }
        ServerMessage::IncomingMessage { from, ciphertext, nonce, server_timestamp } => {
            let _ = tx.send(NetEvent::MessageReceived { from, ciphertext, nonce, timestamp: server_timestamp }).await;
        }
        ServerMessage::IncomingFile { from, filename, chunk_index, total_chunks, ciphertext, nonce: _, server_timestamp } => {
            let _ = tx.send(NetEvent::FileReceived { from, filename, chunk_index, total_chunks, data: ciphertext, timestamp: server_timestamp }).await;
        }
        ServerMessage::RefillAck { ok, count } => {
            let _ = tx.send(NetEvent::SystemMessage(format!("Prekey refill: ok={}, count={}", ok, count))).await;
        }
        ServerMessage::PresenceUpdate { .. } => {}
        ServerMessage::Error { message } => { let _ = tx.send(NetEvent::Error(message)).await; }
        ServerMessage::HelloAck { .. } | ServerMessage::GoodbyeAck => {}
    }
    Ok(())
}

async fn handle_command(cmd: NetCommand, writer: &mut BoxWrite) -> Result<()> {
    match cmd {
        NetCommand::Register { username, password_hash, identity_public_key, signed_prekey, signed_prekey_signature, one_time_prekeys } => {
            write_frame(writer, &ClientMessage::Register { username, password_hash, identity_public_key, signed_prekey, signed_prekey_signature, one_time_prekeys }).await?;
        }
        NetCommand::Login { username, password_hash } => {
            write_frame(writer, &ClientMessage::Login { username, password_hash }).await?;
        }
        NetCommand::FetchBundle { target } => {
            write_frame(writer, &ClientMessage::FetchBundle { target_username: target }).await?;
        }
        NetCommand::ChatRequest { to, identity_public_key, ephemeral_pub, otpk_index } => {
            write_frame(writer, &ClientMessage::ChatRequest { to, identity_public_key, ephemeral_pub, otpk_index }).await?;
        }
        NetCommand::ChatAccept { to } => {
            write_frame(writer, &ClientMessage::ChatAccept { to }).await?;
        }
        NetCommand::ChatReject { to } => {
            write_frame(writer, &ClientMessage::ChatReject { to }).await?;
        }
        NetCommand::SendMessage { to, ciphertext, nonce } => {
            write_frame(writer, &ClientMessage::SendMessage { to, ciphertext, nonce }).await?;
        }
        NetCommand::Heartbeat => {
            write_frame(writer, &ClientMessage::Heartbeat).await?;
        }
        NetCommand::Disconnect => {
            write_frame(writer, &ClientMessage::Goodbye).await?;
        }
    }
    Ok(())
}

async fn connect_with_tor(server_addr: &str, data_dir: &Path) -> Result<(BoxRead, BoxWrite)> {
    let (host, port) = if server_addr.contains(':') {
        let parts: Vec<&str> = server_addr.rsplitn(2, ':').collect();
        (parts[1].to_string(), parts[0].parse().unwrap_or(80))
    } else {
        (server_addr.to_string(), 80u16)
    };

    let socks_addr = std::env::var("ZEROSUM_SOCKS_ADDR").unwrap_or_else(|_| "127.0.0.1:9050".to_string());
    match zerosum_tor::connect_via_socks(&socks_addr, &host, port).await {
        Ok(stream) => { info!("Connected via SOCKS"); let (r, w) = tokio::io::split(stream); return Ok((Box::pin(r), Box::pin(w))); }
        Err(e) => { info!("SOCKS not available ({}), trying embedded Tor...", e); }
    }

    let tor_conn = zerosum_tor::TorConnection::new(data_dir);
    let stream = tor_conn.connect_to_onion(&host, port).await?;
    info!("Connected via embedded Arti");
    let (r, w) = tokio::io::split(stream);
    Ok((Box::pin(r), Box::pin(w)))
}
