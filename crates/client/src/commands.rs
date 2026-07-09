// ─────────────────────────────────────────────────────────────
// Command parsing — all TUI commands
// ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Command {
    Message(String),
    /// /request <username> — send a chat request
    Request(String),
    /// /accept <username> — accept a pending chat request
    Accept(String),
    /// /reject <username> — reject a pending chat request
    Reject(String),
    Select(String),
    Alias(String, String),
    Verify(Option<String>),
    Clear,
    History(bool),
    Purge,
    File(String),
    Help,
    Panic,
    Quit,
    Contacts,
    /// /requests — show pending incoming chat requests
    Requests,
    Status,
    Reconnect,
    Lock,
    Unknown(String),
}

impl Command {
    pub fn parse(input: &str) -> Self {
        let trimmed = input.trim();
        if trimmed.is_empty() { return Command::Message(String::new()); }
        if trimmed == "!panic" { return Command::Panic; }
        if !trimmed.starts_with('/') { return Command::Message(trimmed.to_string()); }

        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
        let cmd = parts[0].to_lowercase();

        match cmd.as_str() {
            "/request" | "/req" | "/add" => {
                if parts.len() >= 2 { Command::Request(parts[1].to_string()) }
                else { Command::Unknown("Usage: /request <username>".into()) }
            }
            "/accept" => {
                if parts.len() >= 2 { Command::Accept(parts[1].to_string()) }
                else { Command::Unknown("Usage: /accept <username>".into()) }
            }
            "/reject" | "/deny" => {
                if parts.len() >= 2 { Command::Reject(parts[1].to_string()) }
                else { Command::Unknown("Usage: /reject <username>".into()) }
            }
            "/select" | "/s" | "/chat" => {
                if parts.len() >= 2 { Command::Select(parts[1].to_string()) }
                else { Command::Unknown("Usage: /select <username>".into()) }
            }
            "/alias" => {
                if parts.len() >= 3 { Command::Alias(parts[1].to_string(), parts[2].to_string()) }
                else { Command::Unknown("Usage: /alias <username> <alias>".into()) }
            }
            "/verify" | "/v" => {
                if parts.len() >= 2 { Command::Verify(Some(parts[1].to_string())) }
                else { Command::Verify(None) }
            }
            "/clear" | "/cls" => Command::Clear,
            "/history" => {
                if parts.len() >= 2 {
                    match parts[1].to_lowercase().as_str() {
                        "on" | "enable" | "true" | "1" => Command::History(true),
                        "off" | "disable" | "false" | "0" => Command::History(false),
                        _ => Command::Unknown("Usage: /history on|off".into()),
                    }
                } else { Command::Unknown("Usage: /history on|off".into()) }
            }
            "/purge" => Command::Purge,
            "/file" | "/f" | "/send" => {
                if parts.len() >= 2 { Command::File(trimmed[parts[0].len()..].trim().to_string()) }
                else { Command::Unknown("Usage: /file <path>".into()) }
            }
            "/help" | "/h" | "/?" => Command::Help,
            "/quit" | "/exit" | "/q!" => Command::Quit,
            "/contacts" | "/c" | "/list" => Command::Contacts,
            "/requests" | "/pending" => Command::Requests,
            "/status" => Command::Status,
            "/reconnect" => Command::Reconnect,
            "/lock" => Command::Lock,
            _ => Command::Unknown(format!("Unknown command: {}", cmd)),
        }
    }
}

pub fn help_text() -> Vec<String> {
    vec![
        "╔══════════════════════════════════════════════════════╗".into(),
        "║              ZEROSUM COMMAND REFERENCE               ║".into(),
        "╠══════════════════════════════════════════════════════╣".into(),
        "║  CHAT REQUESTS                                       ║".into(),
        "║  /request <user>    Send a chat request              ║".into(),
        "║  /accept <user>     Accept a chat request            ║".into(),
        "║  /reject <user>     Reject a chat request            ║".into(),
        "║  /requests          Show pending requests            ║".into(),
        "║                                                      ║".into(),
        "║  MESSAGING                                           ║".into(),
        "║  /select <user>     Select contact to chat with      ║".into(),
        "║  /alias <user> <n>  Set display name for contact     ║".into(),
        "║  /file <path>       Send an encrypted file           ║".into(),
        "║  /contacts          List all contacts                ║".into(),
        "║                                                      ║".into(),
        "║  SECURITY                                            ║".into(),
        "║  /verify [user]     Show safety number               ║".into(),
        "║  /lock              Lock screen                      ║".into(),
        "║  !panic             ⚠ DESTROY ALL LOCAL DATA         ║".into(),
        "║                                                      ║".into(),
        "║  HISTORY                                             ║".into(),
        "║  /history on|off    Toggle local history storage     ║".into(),
        "║  /purge             Securely delete history file     ║".into(),
        "║  /clear             Clear chat display               ║".into(),
        "║                                                      ║".into(),
        "║  SYSTEM                                              ║".into(),
        "║  /status            Show connection status           ║".into(),
        "║  /help              Show this help                   ║".into(),
        "║  /quit              Exit ZeroSum                     ║".into(),
        "╚══════════════════════════════════════════════════════╝".into(),
    ]
}
