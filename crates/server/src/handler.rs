// ─────────────────────────────────────────────────────────────
// Server connection handler — processes client messages
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use zerosum_protocol::*;
use crate::db::Database;

/// Channel for delivering messages directly to online clients
pub type ClientSender = mpsc::Sender<ServerMessage>;
/// Shared map of online users → their direct delivery channels
pub type OnlineClients = Arc<Mutex<HashMap<String, ClientSender>>>;

/// Per-connection state
pub struct ClientHandler {
    db: Arc<Database>,
    username: Option<String>,
    online_clients: OnlineClients,
}

impl ClientHandler {
    pub fn new(db: Arc<Database>, online_clients: OnlineClients) -> Self {
        ClientHandler { db, username: None, online_clients }
    }

    pub async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        stream: &mut S,
    ) -> Result<()> {
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Version handshake
        let hello: ClientMessage = read_frame(&mut reader).await?;
        match hello {
            ClientMessage::Hello { version } => {
                let ok = version == PROTOCOL_VERSION;
                write_frame(&mut writer, &ServerMessage::HelloAck {
                    version: PROTOCOL_VERSION, ok,
                }).await?;
                if !ok { return Ok(()); }
            }
            _ => {
                write_frame(&mut writer, &ServerMessage::Error {
                    message: "Expected Hello".into(),
                }).await?;
                return Ok(());
            }
        }

        // Create a channel for direct message delivery to this client
        let (direct_tx, mut direct_rx) = mpsc::channel::<ServerMessage>(256);

        // Main message loop — select between incoming frames and direct deliveries
        loop {
            tokio::select! {
                // Messages from the network (client → server)
                frame = read_frame::<_, ClientMessage>(&mut reader) => {
                    match frame {
                        Ok(msg) => {
                            let should_break = self.handle_msg(msg, &mut writer, &direct_tx).await?;
                            if should_break { break; }
                        }
                        Err(ProtoError::ConnectionClosed) => {
                            info!("Client disconnected");
                            break;
                        }
                        Err(e) => {
                            warn!("Read error: {}", e);
                            break;
                        }
                    }
                }

                // Direct delivery messages (from other clients via OnlineClients map)
                direct_msg = direct_rx.recv() => {
                    if let Some(msg) = direct_msg {
                        if let Err(e) = write_frame(&mut writer, &msg).await {
                            warn!("Direct delivery write error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        // Cleanup: mark offline and remove from online clients map
        if let Some(ref username) = self.username {
            self.db.set_online(username, false).ok();
            self.online_clients.lock().await.remove(username);
            info!("User went offline: {}", username);
        }

        Ok(())
    }

    /// Handle a single client message. Returns true if we should break the loop.
    async fn handle_msg(
        &mut self,
        msg: ClientMessage,
        writer: &mut (impl AsyncWrite + Unpin + Send),
        direct_tx: &ClientSender,
    ) -> Result<bool> {
        match msg {
            ClientMessage::Hello { .. } => { /* ignore duplicate hellos */ }

            ClientMessage::Register {
                username, password_hash, identity_public_key,
                signed_prekey, signed_prekey_signature, one_time_prekeys,
            } => {
                match self.db.register_user(&username, &password_hash, &identity_public_key,
                    &signed_prekey, &signed_prekey_signature, &one_time_prekeys)
                {
                    Ok(_) => {
                        self.username = Some(username.clone());
                        self.db.set_online(&username, true).ok();
                        self.online_clients.lock().await.insert(username.clone(), direct_tx.clone());
                        info!("User registered: {}", username);
                        write_frame(writer, &ServerMessage::RegisterAck { ok: true, error: None }).await?;
                        // Deliver any queued items
                        self.deliver_queue(writer).await?;
                    }
                    Err(e) => {
                        write_frame(writer, &ServerMessage::RegisterAck { ok: false, error: Some(e.to_string()) }).await?;
                    }
                }
            }

            ClientMessage::Login { username, password_hash } => {
                match self.db.authenticate(&username, &password_hash) {
                    Ok(true) => {
                        self.username = Some(username.clone());
                        self.db.set_online(&username, true).ok();
                        self.online_clients.lock().await.insert(username.clone(), direct_tx.clone());
                        info!("User logged in: {}", username);
                        write_frame(writer, &ServerMessage::LoginAck { ok: true, error: None }).await?;
                        self.deliver_queue(writer).await?;
                    }
                    Ok(false) => {
                        write_frame(writer, &ServerMessage::LoginAck { ok: false, error: Some("Invalid credentials".into()) }).await?;
                    }
                    Err(e) => {
                        write_frame(writer, &ServerMessage::LoginAck { ok: false, error: Some(e.to_string()) }).await?;
                    }
                }
            }

            ClientMessage::Heartbeat => {
                if let Some(ref username) = self.username {
                    self.db.set_online(username, true).ok();
                    let pending = self.db.pending_count(username);
                    write_frame(writer, &ServerMessage::HeartbeatAck { pending_messages: pending }).await?;
                    if pending > 0 {
                        self.deliver_queue(writer).await?;
                    }
                }
            }

            ClientMessage::FetchBundle { target_username } => {
                match self.db.fetch_bundle(&target_username) {
                    Ok((ik, spk, spk_sig, otpk, otpk_idx)) => {
                        write_frame(writer, &ServerMessage::Bundle {
                            username: target_username, identity_public_key: ik,
                            signed_prekey: spk, signed_prekey_signature: spk_sig,
                            one_time_prekey: otpk, otpk_index: otpk_idx,
                        }).await?;
                    }
                    Err(e) => {
                        write_frame(writer, &ServerMessage::BundleError {
                            username: target_username, error: e.to_string(),
                        }).await?;
                    }
                }
            }

            ClientMessage::ChatRequest { to, identity_public_key, ephemeral_pub, otpk_index } => {
                let from = self.username.clone().unwrap_or_default();

                if !self.db.user_exists(&to) {
                    write_frame(writer, &ServerMessage::ChatAck {
                        ok: false, error: Some("User not found".into()),
                    }).await?;
                    return Ok(false);
                }

                let incoming = ServerMessage::IncomingChatRequest {
                    from: from.clone(),
                    identity_public_key,
                    ephemeral_pub,
                    otpk_index,
                };

                // Try direct delivery first, then queue
                if self.try_deliver_direct(&to, incoming.clone()).await {
                    info!("Chat request {} → {} delivered directly", from, to);
                } else {
                    self.db.queue_control(&to, &from, "chat_request", &bincode::serialize(&incoming)?)?;
                    info!("Chat request {} → {} queued", from, to);
                }

                write_frame(writer, &ServerMessage::ChatAck { ok: true, error: None }).await?;
            }

            ClientMessage::ChatAccept { to } => {
                let from = self.username.clone().unwrap_or_default();

                // Fetch our identity key to send to the initiator
                let our_ik = self.db.get_identity_key(&from).unwrap_or_default();

                let accepted = ServerMessage::ChatRequestAccepted {
                    from: from.clone(),
                    identity_public_key: our_ik,
                };

                if self.try_deliver_direct(&to, accepted.clone()).await {
                    info!("Chat accept {} → {} delivered directly", from, to);
                } else {
                    self.db.queue_control(&to, &from, "chat_accept", &bincode::serialize(&accepted)?)?;
                    info!("Chat accept {} → {} queued", from, to);
                }

                write_frame(writer, &ServerMessage::ChatAck { ok: true, error: None }).await?;
            }

            ClientMessage::ChatReject { to } => {
                let from = self.username.clone().unwrap_or_default();

                let rejected = ServerMessage::ChatRequestRejected { from: from.clone() };

                if self.try_deliver_direct(&to, rejected.clone()).await {
                    info!("Chat reject {} → {} delivered directly", from, to);
                } else {
                    self.db.queue_control(&to, &from, "chat_reject", &bincode::serialize(&rejected)?)?;
                }

                write_frame(writer, &ServerMessage::ChatAck { ok: true, error: None }).await?;
            }

            ClientMessage::SendMessage { to, ciphertext, nonce } => {
                let from = self.username.clone().unwrap_or_default();

                if !self.db.user_exists(&to) {
                    write_frame(writer, &ServerMessage::SendAck {
                        ok: false, error: Some("User not found".into()),
                    }).await?;
                    return Ok(false);
                }

                let timestamp = chrono::Utc::now().timestamp() as u64;

                let incoming = ServerMessage::IncomingMessage {
                    from: from.clone(),
                    ciphertext: ciphertext.clone(),
                    nonce: nonce.clone(),
                    server_timestamp: timestamp,
                };

                // Try direct delivery, fall back to queue
                if self.try_deliver_direct(&to, incoming).await {
                    // Delivered immediately
                } else {
                    self.db.queue_message(&to, &from, &ciphertext, &nonce, timestamp)?;
                }

                write_frame(writer, &ServerMessage::SendAck { ok: true, error: None }).await?;
            }

            ClientMessage::SendFile { to, filename, chunk_index, total_chunks, ciphertext, nonce } => {
                let from = self.username.clone().unwrap_or_default();

                if !self.db.user_exists(&to) {
                    write_frame(writer, &ServerMessage::SendAck {
                        ok: false, error: Some("User not found".into()),
                    }).await?;
                    return Ok(false);
                }

                let timestamp = chrono::Utc::now().timestamp() as u64;

                let incoming = ServerMessage::IncomingFile {
                    from: from.clone(), filename: filename.clone(),
                    chunk_index, total_chunks,
                    ciphertext: ciphertext.clone(), nonce: nonce.clone(),
                    server_timestamp: timestamp,
                };

                if !self.try_deliver_direct(&to, incoming).await {
                    self.db.queue_file(&to, &from, &filename, chunk_index, total_chunks, &ciphertext, &nonce)?;
                }

                write_frame(writer, &ServerMessage::SendAck { ok: true, error: None }).await?;
            }

            ClientMessage::RefillPrekeys { one_time_prekeys } => {
                if let Some(ref username) = self.username {
                    match self.db.add_prekeys(username, &one_time_prekeys) {
                        Ok(count) => {
                            write_frame(writer, &ServerMessage::RefillAck { ok: true, count }).await?;
                        }
                        Err(_) => {
                            write_frame(writer, &ServerMessage::RefillAck { ok: false, count: 0 }).await?;
                        }
                    }
                }
            }

            ClientMessage::Goodbye => {
                write_frame(writer, &ServerMessage::GoodbyeAck).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Try to deliver a message directly to an online client. Returns true if delivered.
    async fn try_deliver_direct(&self, to: &str, msg: ServerMessage) -> bool {
        let clients = self.online_clients.lock().await;
        if let Some(sender) = clients.get(to) {
            sender.send(msg).await.is_ok()
        } else {
            false
        }
    }

    /// Drain all queued messages and deliver them through the writer
    async fn deliver_queue<W: AsyncWrite + Unpin + Send>(
        &self,
        writer: &mut W,
    ) -> Result<()> {
        if let Some(ref username) = self.username {
            // Deliver control messages (chat requests, accepts, rejects)
            if let Ok(controls) = self.db.drain_control_queue(username) {
                for (msg_type, data) in controls {
                    match msg_type.as_str() {
                        "chat_request" => {
                            if let Ok(msg) = bincode::deserialize::<ServerMessage>(&data) {
                                write_frame(writer, &msg).await?;
                            }
                        }
                        "chat_accept" => {
                            if let Ok(msg) = bincode::deserialize::<ServerMessage>(&data) {
                                write_frame(writer, &msg).await?;
                            }
                        }
                        "chat_reject" => {
                            if let Ok(msg) = bincode::deserialize::<ServerMessage>(&data) {
                                write_frame(writer, &msg).await?;
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Deliver queued messages
            if let Ok(messages) = self.db.drain_queue(username) {
                for qm in messages {
                    if qm.msg_type == "file" {
                        write_frame(writer, &ServerMessage::IncomingFile {
                            from: qm.sender, filename: qm.filename.unwrap_or_default(),
                            chunk_index: qm.chunk_index.unwrap_or(0),
                            total_chunks: qm.total_chunks.unwrap_or(1),
                            ciphertext: qm.ciphertext, nonce: qm.nonce,
                            server_timestamp: qm.timestamp,
                        }).await?;
                    } else {
                        write_frame(writer, &ServerMessage::IncomingMessage {
                            from: qm.sender, ciphertext: qm.ciphertext,
                            nonce: qm.nonce, server_timestamp: qm.timestamp,
                        }).await?;
                    }
                }
            }
        }
        Ok(())
    }
}
