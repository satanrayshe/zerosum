// ─────────────────────────────────────────────────────────────
//  ZEROSUM CLIENT — friend-to-friend encrypted messenger
// ─────────────────────────────────────────────────────────────

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use zerosum_client::commands::Command;
use zerosum_client::contacts::ContactStore;
use zerosum_client::history::{Direction, HistoryStore};
use zerosum_client::network::{NetCommand, NetEvent, network_task};
use zerosum_client::panic::execute_panic;
use zerosum_client::stealth;
use zerosum_client::tui::{AppState, ContactDisplay, draw_ui, handle_key_event};
use zerosum_crypto::identity::Identity;
use zerosum_crypto::encrypt::hash_password;
use zerosum_crypto::fingerprint::safety_number;
use zerosum_crypto::ratchet::SessionRatchet;
use zerosum_crypto::store::SessionStore;
use zerosum_crypto::x3dh;

const BANNER: &str = r#"
 ███████╗███████╗██████╗  ██████╗ ███████╗██╗   ██╗███╗   ███╗
 ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║████╗ ████║
   ███╔╝ █████╗  ██████╔╝██║   ██║███████╗██║   ██║██╔████╔██║
  ███╔╝  ██╔══╝  ██╔══██╗██║   ██║╚════██║██║   ██║██║╚██╔╝██║
 ███████╗███████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║ ╚═╝ ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝
"#;

#[derive(Parser, Debug)]
#[command(name = "zerosum", about = "ZeroSum — friend-to-friend encrypted messaging")]
struct Args {
    #[arg(short, long)]
    server: Option<String>,
    #[arg(short, long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    no_tor: bool,
    #[arg(long)]
    history: bool,
    #[arg(short, long)]
    username: Option<String>,
}

/// Pending incoming chat request (stored until user /accept or /reject)
#[derive(Clone)]
struct PendingRequest {
    #[allow(dead_code)]
    from: String,
    identity_public_key: Vec<u8>,
    ephemeral_pub: Vec<u8>,
    otpk_index: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let stealth_report = stealth::apply_stealth();

    eprintln!("\x1b[31m{}\x1b[0m", BANNER);
    eprintln!("\x1b[90m  v{}\x1b[0m", env!("CARGO_PKG_VERSION"));
    for r in &stealth_report { eprintln!("\x1b[90m  {}\x1b[0m", r); }
    eprintln!();

    let data_dir = args.data_dir.unwrap_or_else(|| {
        dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("zerosum")
    });
    std::fs::create_dir_all(&data_dir)?;

    let password = rpassword::prompt_password("\x1b[36m  Password: \x1b[0m").context("Failed to read password")?;
    if password.is_empty() { eprintln!("\x1b[31m  Error: Password cannot be empty\x1b[0m"); std::process::exit(1); }

    let identity_path = data_dir.join("identity.enc");
    let (identity, is_new) = if identity_path.exists() {
        eprintln!("\x1b[90m  Loading identity...\x1b[0m");
        match Identity::decrypt_from_bytes(&password, &std::fs::read(&identity_path)?) {
            Ok(id) => (id, false),
            Err(_) => { eprintln!("\x1b[31m  Wrong password or corrupt identity.\x1b[0m"); std::process::exit(1); }
        }
    } else {
        eprintln!("\x1b[33m  Generating new identity...\x1b[0m");
        let id = Identity::generate(100);
        std::fs::write(&identity_path, id.encrypt_to_bytes(&password)?)?;
        eprintln!("\x1b[32m  ✓ Identity created\x1b[0m");
        (id, true)
    };

    let username = if let Some(u) = args.username { u } else {
        eprint!("\x1b[36m  Username: \x1b[0m");
        let mut u = String::new(); io::stdin().read_line(&mut u)?; u.trim().to_string()
    };
    if username.is_empty() { eprintln!("\x1b[31m  Username cannot be empty\x1b[0m"); std::process::exit(1); }

    let server_addr = if let Some(s) = args.server { s }
    else if let Ok(s) = std::env::var("ZEROSUM_SERVER_ADDR") { s }
    else { eprint!("\x1b[36m  Server address: \x1b[0m"); let mut a = String::new(); io::stdin().read_line(&mut a)?; a.trim().to_string() };

    let use_tor = !args.no_tor && server_addr.contains(".onion");
    eprintln!("\x1b[90m  User: {} | Server: {} | Tor: {}\x1b[0m", username, server_addr, if use_tor { "on" } else { "off" });

    let mut session_store = SessionStore::load_or_new(&SessionStore::default_path(&data_dir), &password);
    let mut contact_store = ContactStore::load_or_new(&ContactStore::default_path(&data_dir), &password);
    let mut history_store = HistoryStore::new(HistoryStore::default_path(&data_dir), password.clone(), args.history);

    let (cmd_tx, cmd_rx) = mpsc::channel::<NetCommand>(256);
    let (event_tx, mut event_rx) = mpsc::channel::<NetEvent>(256);

    let net_addr = server_addr.clone();
    let net_dir = data_dir.clone();
    tokio::spawn(async move { network_task(net_addr, use_tor, net_dir, cmd_rx, event_tx).await; });

    let password_hash = hash_password(&password);
    if is_new {
        cmd_tx.send(NetCommand::Register {
            username: username.clone(), password_hash,
            identity_public_key: identity.identity_public_key(),
            signed_prekey: identity.spk_public().as_bytes().to_vec(),
            signed_prekey_signature: identity.sign_spk(),
            one_time_prekeys: identity.otpk_publics(),
        }).await?;
    } else {
        cmd_tx.send(NetCommand::Login { username: username.clone(), password_hash }).await?;
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new(username.clone());
    state.history_enabled = args.history;
    for c in contact_store.list() {
        state.contacts.push(ContactDisplay { username: c.username.clone(), alias: c.alias.clone(), online: false, verified: c.verified, unread: 0 });
    }
    state.add_system_message("Welcome to ZeroSum v2. Type /help for commands.");
    state.add_system_message("Use /request <username> to start chatting with someone.");

    // Pending incoming requests waiting for /accept or /reject
    let mut pending_requests: HashMap<String, PendingRequest> = HashMap::new();

    // Main event loop
    loop {
        terminal.draw(|f| draw_ui(f, &mut state))?;

        tokio::select! {
            event = tokio::task::spawn_blocking(|| {
                if event::poll(std::time::Duration::from_millis(50)).unwrap_or(false) { event::read().ok() } else { None }
            }) => {
                if let Ok(Some(Event::Key(key))) = event {
                    if key.kind != KeyEventKind::Press { continue; }
                    if let Some(cmd) = handle_key_event(&mut state, key) {
                        handle_command(cmd, &mut state, &cmd_tx, &identity, &mut session_store,
                            &mut contact_store, &mut history_store, &data_dir, &mut pending_requests).await?;
                        if state.should_quit {
                            let _ = cmd_tx.send(NetCommand::Disconnect).await;
                            break;
                        }
                    }
                }
            }
            net_event = event_rx.recv() => {
                if let Some(evt) = net_event {
                    handle_net_event(evt, &mut state, &cmd_tx, &identity, &mut session_store,
                        &mut contact_store, &mut history_store, &mut pending_requests).await?;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    let _ = session_store.save(&SessionStore::default_path(&data_dir), &password);
    let _ = contact_store.save(&ContactStore::default_path(&data_dir), &password);
    let _ = history_store.save();
    let mut pw = password; pw.zeroize();
    Ok(())
}

async fn handle_command(
    cmd: Command, state: &mut AppState, cmd_tx: &mpsc::Sender<NetCommand>,
    identity: &Identity, session_store: &mut SessionStore,
    contact_store: &mut ContactStore, history_store: &mut HistoryStore,
    data_dir: &PathBuf, pending_requests: &mut HashMap<String, PendingRequest>,
) -> Result<()> {
    match cmd {
        Command::Message(text) => {
            if text.is_empty() { return Ok(()); }
            if let Some(ref peer) = state.active_peer.clone() {
                if let Some(session) = session_store.get_session_mut(peer) {
                    let padded = zerosum_protocol::pad_payload(text.as_bytes());
                    match session.encrypt(&padded) {
                        Ok((ct, nonce)) => {
                            cmd_tx.send(NetCommand::SendMessage { to: peer.clone(), ciphertext: ct, nonce }).await?;
                            state.add_chat_message(peer, &state.username.clone(), &text);
                            history_store.add(peer, Direction::Sent, &text);
                        }
                        Err(e) => state.add_system_message(&format!("Encryption failed: {}", e)),
                    }
                } else {
                    state.add_system_message(&format!("No session with {}. Use /request {} first.", peer, peer));
                }
            } else {
                state.add_system_message("No contact selected. Use /select <username>");
            }
        }

        Command::Request(target) => {
            // Step 1: Fetch their bundle from the server
            state.add_system_message(&format!("Sending chat request to {}...", target));
            cmd_tx.send(NetCommand::FetchBundle { target: target.clone() }).await?;
            // The bundle response handler will complete the request (see handle_net_event)
        }

        Command::Accept(from) => {
            if let Some(req) = pending_requests.remove(&from) {
                // Perform X3DH as responder
                let our_x_secret = x3dh::ed25519_secret_to_x25519(
                    &identity.signing_key_bytes.as_slice().try_into().unwrap()
                );
                let their_ik_x = x3dh::ed25519_pub_to_x25519(
                    &req.identity_public_key.clone().try_into().unwrap_or([0u8; 32])
                );
                let eph: [u8; 32] = req.ephemeral_pub.clone().try_into().unwrap_or([0u8; 32]);

                let otpk_secret = req.otpk_index.and_then(|idx| identity.otpk_secret_at(idx));

                match x3dh::x3dh_respond(
                    &our_x_secret, &identity.spk_secret(),
                    otpk_secret.as_ref(), &their_ik_x, &eph,
                ) {
                    Ok(shared_secret) => {
                        let session = SessionRatchet::new(&shared_secret, false); // responder
                        session_store.put_session(from.clone(), session);

                        // Add to contacts
                        contact_store.add(&from);
                        contact_store.set_identity_key(&from, req.identity_public_key);
                        if !state.contacts.iter().any(|c| c.username == from) {
                            state.contacts.push(ContactDisplay {
                                username: from.clone(), alias: None, online: true, verified: false, unread: 0,
                            });
                        }

                        // Send accept to server → relayed to the initiator
                        cmd_tx.send(NetCommand::ChatAccept { to: from.clone() }).await?;

                        state.add_system_message(&format!("✓ Accepted chat request from {}. Session established!", from));
                        state.add_system_message(&format!("  Use /select {} to start chatting.", from));
                    }
                    Err(e) => {
                        state.add_system_message(&format!("Key exchange failed with {}: {}", from, e));
                    }
                }
            } else {
                state.add_system_message(&format!("No pending request from {}. Use /requests to see pending.", from));
            }
        }

        Command::Reject(from) => {
            if pending_requests.remove(&from).is_some() {
                cmd_tx.send(NetCommand::ChatReject { to: from.clone() }).await?;
                state.add_system_message(&format!("Rejected chat request from {}.", from));
            } else {
                state.add_system_message(&format!("No pending request from {}.", from));
            }
        }

        Command::Select(username) => {
            if session_store.has_session(&username) || contact_store.has(&username) {
                state.active_peer = Some(username.clone());
                if let Some(idx) = state.contacts.iter().position(|c| c.username == username) {
                    state.selected_contact.select(Some(idx));
                    state.contacts[idx].unread = 0;
                }
            } else {
                state.add_system_message(&format!("{} is not a contact. Use /request {} first.", username, username));
            }
        }

        Command::Alias(username, alias) => {
            contact_store.set_alias(&username, &alias);
            if let Some(c) = state.contacts.iter_mut().find(|c| c.username == username) { c.alias = Some(alias.clone()); }
            state.add_system_message(&format!("Alias: {} → {}", username, alias));
        }

        Command::Verify(maybe_peer) => {
            let peer = maybe_peer.or_else(|| state.active_peer.clone()).unwrap_or_default();
            if peer.is_empty() { state.add_system_message("Usage: /verify <username>"); return Ok(()); }
            if let Some(contact) = contact_store.get(&peer) {
                if let Some(ref key) = contact.identity_key {
                    let sn = safety_number(&identity.identity_public_key(), key);
                    state.add_system_message(&format!("Safety number with {}: {}", peer, sn));
                    state.add_system_message("Compare this over a separate channel (voice, in person).");
                    contact_store.verify(&peer);
                    if let Some(c) = state.contacts.iter_mut().find(|c| c.username == peer) { c.verified = true; }
                } else { state.add_system_message(&format!("No key known for {}.", peer)); }
            } else { state.add_system_message(&format!("Contact not found: {}", peer)); }
        }

        Command::Clear => {
            if let Some(ref peer) = state.active_peer { state.messages.remove(peer); }
            else { state.system_messages.clear(); }
        }
        Command::History(on) => {
            if on { history_store.enable(); state.history_enabled = true; state.add_system_message("History ON."); }
            else { history_store.disable(); state.history_enabled = false; state.add_system_message("History OFF."); }
        }
        Command::Purge => { history_store.purge().ok(); state.add_system_message("History purged."); }
        Command::File(path) => { state.add_system_message(&format!("File sharing: {} (TODO)", path)); }
        Command::Help => { state.show_help = true; }
        Command::Panic => {
            state.add_system_message("!!! PANIC !!!");
            let _ = cmd_tx.send(NetCommand::Disconnect).await;
            let _ = history_store.purge();
            let _ = execute_panic(data_dir);
            state.should_quit = true;
        }
        Command::Quit => { state.should_quit = true; }
        Command::Contacts => {
            state.add_system_message("── Contacts ──");
            let lines: Vec<String> = state.contacts.iter().map(|c| {
                let s = if c.online { "●" } else { "○" };
                let v = if c.verified { "✓" } else { "✗" };
                format!("  {} {} {}", s, v, c.alias.as_deref().unwrap_or(&c.username))
            }).collect();
            if lines.is_empty() { state.add_system_message("  No contacts. Use /request <username>"); }
            else { for l in lines { state.add_system_message(&l); } }
        }
        Command::Requests => {
            state.add_system_message("── Pending Chat Requests ──");
            if pending_requests.is_empty() {
                state.add_system_message("  No pending requests.");
            } else {
                let names: Vec<String> = pending_requests.keys().cloned().collect();
                for name in names {
                    state.add_system_message(&format!("  📩 {} — /accept {} or /reject {}", name, name, name));
                }
            }
        }
        Command::Status => {
            state.add_system_message(&format!("Connected: {} | Sessions: {} | Pending: {}",
                state.connected, session_store.peers().len(), pending_requests.len()));
        }
        Command::Reconnect => { state.add_system_message("Auto-reconnecting..."); }
        Command::Lock => { state.add_system_message("Lock: not yet implemented"); }
        Command::Unknown(msg) => { state.add_system_message(&msg); }
    }
    Ok(())
}

async fn handle_net_event(
    event: NetEvent, state: &mut AppState, cmd_tx: &mpsc::Sender<NetCommand>,
    identity: &Identity, session_store: &mut SessionStore,
    contact_store: &mut ContactStore, history_store: &mut HistoryStore,
    pending_requests: &mut HashMap<String, PendingRequest>,
) -> Result<()> {
    match event {
        NetEvent::Connected => { state.connected = true; state.add_system_message("Connected to server."); }
        NetEvent::Disconnected(r) => { state.connected = false; state.add_system_message(&format!("Disconnected: {}", r)); }
        NetEvent::RegisterOk => { state.add_system_message("✓ Registered successfully!"); }
        NetEvent::RegisterFail(e) => { state.add_system_message(&format!("Registration failed: {}", e)); }
        NetEvent::LoginOk => { state.add_system_message("✓ Logged in!"); }
        NetEvent::LoginFail(e) => { state.add_system_message(&format!("Login failed: {}", e)); }

        NetEvent::BundleReceived { username, identity_public_key, signed_prekey, signed_prekey_signature: _, one_time_prekey, otpk_index } => {
            // This is triggered by /request — complete the X3DH initiation and send the chat request
            let ik_bytes: [u8; 32] = identity_public_key.clone().try_into().unwrap_or([0u8; 32]);
            let spk_bytes: [u8; 32] = signed_prekey.try_into().unwrap_or([0u8; 32]);
            let our_x_secret = x3dh::ed25519_secret_to_x25519(&identity.signing_key_bytes.as_slice().try_into().unwrap());
            let their_x_pub = x3dh::ed25519_pub_to_x25519(&ik_bytes);
            let otpk_bytes: Option<[u8; 32]> = one_time_prekey.as_ref().and_then(|k| k.clone().try_into().ok());

            match x3dh::x3dh_initiate(&our_x_secret, &their_x_pub, &spk_bytes, otpk_bytes.as_ref()) {
                Ok(result) => {
                    // Store the session as initiator (will be usable once the other side accepts)
                    let session = SessionRatchet::new(&result.shared_secret, true);
                    session_store.put_session(username.clone(), session);

                    // Send chat request with our identity key and ephemeral key
                    cmd_tx.send(NetCommand::ChatRequest {
                        to: username.clone(),
                        identity_public_key: identity.identity_public_key(),
                        ephemeral_pub: result.ephemeral_public.to_vec(),
                        otpk_index,
                    }).await?;

                    state.add_system_message(&format!("📤 Chat request sent to {}. Waiting for them to accept...", username));
                }
                Err(e) => {
                    state.add_system_message(&format!("Key exchange failed with {}: {}", username, e));
                }
            }
        }
        NetEvent::BundleError(username, error) => {
            state.add_system_message(&format!("User '{}' not found: {}", username, error));
        }

        NetEvent::IncomingChatRequest { from, identity_public_key, ephemeral_pub, otpk_index } => {
            // Store the pending request — user needs to /accept or /reject
            pending_requests.insert(from.clone(), PendingRequest {
                from: from.clone(), identity_public_key, ephemeral_pub, otpk_index,
            });
            state.add_system_message(&format!(""));
            state.add_system_message(&format!("📩 Chat request from: {}", from));
            state.add_system_message(&format!("   Type /accept {} or /reject {}", from, from));
            state.add_system_message(&format!(""));
        }

        NetEvent::ChatRequestAccepted { from, identity_public_key } => {
            // The other side accepted — our session is already established from the initiation step
            contact_store.add(&from);
            contact_store.set_identity_key(&from, identity_public_key);
            if !state.contacts.iter().any(|c| c.username == from) {
                state.contacts.push(ContactDisplay {
                    username: from.clone(), alias: None, online: true, verified: false, unread: 0,
                });
            }
            state.add_system_message(&format!("✓ {} accepted your chat request! Session is live.", from));
            state.add_system_message(&format!("  Use /select {} to start chatting.", from));
        }

        NetEvent::ChatRequestRejected { from } => {
            // Remove the session we created during initiation
            session_store.remove_session(&from);
            state.add_system_message(&format!("✗ {} rejected your chat request.", from));
        }

        NetEvent::ChatAck { ok, error } => {
            if !ok {
                state.add_system_message(&format!("Chat request failed: {}", error.unwrap_or_default()));
            }
        }

        NetEvent::MessageReceived { from, ciphertext, nonce, timestamp: _ } => {
            if let Some(session) = session_store.get_session_mut(&from) {
                match session.decrypt(&ciphertext, &nonce) {
                    Ok(padded) => {
                        let text = if let Some(unpadded) = zerosum_protocol::unpad_payload(&padded) {
                            String::from_utf8_lossy(&unpadded).to_string()
                        } else {
                            String::from_utf8_lossy(&padded).to_string()
                        };
                        state.add_chat_message(&from, &from, &text);
                        history_store.add(&from, Direction::Received, &text);
                    }
                    Err(e) => {
                        state.add_system_message(&format!("⚠ Decrypt failed from {}: {}", from, e));
                    }
                }
            } else {
                state.add_system_message(&format!("Message from {} but no session. They may need to /request you.", from));
            }
        }

        NetEvent::FileReceived { from, filename, chunk_index, total_chunks, .. } => {
            state.add_system_message(&format!("File from {}: {} ({}/{})", from, filename, chunk_index + 1, total_chunks));
        }
        NetEvent::MessageSent => {}
        NetEvent::SendFail(e) => { state.add_system_message(&format!("Send failed: {}", e)); }
        NetEvent::HeartbeatAck { pending } => {
            if pending > 0 { state.add_system_message(&format!("{} pending message(s)", pending)); }
        }
        NetEvent::Error(msg) => { state.add_system_message(&format!("Server error: {}", msg)); }
        NetEvent::SystemMessage(msg) => { state.add_system_message(&msg); }
    }
    Ok(())
}
