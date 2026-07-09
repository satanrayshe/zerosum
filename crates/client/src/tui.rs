// ─────────────────────────────────────────────────────────────
// Terminal UI — ratatui-based interactive chat interface
// ─────────────────────────────────────────────────────────────

use crossterm::event::{KeyCode, KeyModifiers, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap, Clear},
    Frame,
};

use crate::commands::{Command, help_text};

#[allow(dead_code)]
const BANNER_LARGE: &str = r#" ███████╗███████╗██████╗  ██████╗ ███████╗██╗   ██╗███╗   ███╗
 ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║████╗ ████║
   ███╔╝ █████╗  ██████╔╝██║   ██║███████╗██║   ██║██╔████╔██║
  ███╔╝  ██╔══╝  ██╔══██╗██║   ██║╚════██║██║   ██║██║╚██╔╝██║
 ███████╗███████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║ ╚═╝ ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝"#;

/// Compact banner for narrow terminals
#[allow(dead_code)]
const BANNER_SMALL: &str = r#"╔═══╗───────
╠═══╬═╦═╦══╗
╠══╗║═╣╩╣╬║║
╚═══╩═╩═╩══╝"#;

/// A chat message for display
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub timestamp: String,
    pub sender: String,
    pub content: String,
    pub is_system: bool,
}

/// State for the TUI
pub struct AppState {
    /// Current input buffer
    pub input: String,
    /// Cursor position in input
    pub cursor_pos: usize,
    /// Currently selected contact index
    pub selected_contact: ListState,
    /// Active chat peer (username)
    pub active_peer: Option<String>,
    /// Chat messages per peer
    pub messages: std::collections::HashMap<String, Vec<ChatMessage>>,
    /// System messages (global log)
    pub system_messages: Vec<ChatMessage>,
    /// Contact list
    pub contacts: Vec<ContactDisplay>,
    /// Connection status
    pub connected: bool,
    /// Username
    pub username: String,
    /// Show help overlay
    pub show_help: bool,
    /// Scroll offset for chat
    pub chat_scroll: u16,
    /// Whether the app should quit
    pub should_quit: bool,
    /// History enabled
    pub history_enabled: bool,
    /// Input history for up/down arrow
    pub input_history: Vec<String>,
    pub input_history_idx: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ContactDisplay {
    pub username: String,
    pub alias: Option<String>,
    pub online: bool,
    pub verified: bool,
    pub unread: u32,
}

impl AppState {
    pub fn new(username: String) -> Self {
        AppState {
            input: String::new(),
            cursor_pos: 0,
            selected_contact: ListState::default(),
            active_peer: None,
            messages: std::collections::HashMap::new(),
            system_messages: Vec::new(),
            contacts: Vec::new(),
            connected: false,
            username,
            show_help: false,
            chat_scroll: 0,
            should_quit: false,
            history_enabled: false,
            input_history: Vec::new(),
            input_history_idx: None,
        }
    }

    pub fn add_system_message(&mut self, msg: &str) {
        self.system_messages.push(ChatMessage {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            sender: "system".into(),
            content: msg.to_string(),
            is_system: true,
        });
    }

    pub fn add_chat_message(&mut self, peer: &str, sender: &str, content: &str) {
        let msg = ChatMessage {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            sender: sender.to_string(),
            content: content.to_string(),
            is_system: false,
        };
        self.messages
            .entry(peer.to_string())
            .or_default()
            .push(msg);

        // Increment unread if not active peer
        if self.active_peer.as_deref() != Some(peer) {
            if let Some(contact) = self.contacts.iter_mut().find(|c| c.username == peer) {
                contact.unread += 1;
            }
        }
    }

    pub fn active_messages(&self) -> &[ChatMessage] {
        if let Some(ref peer) = self.active_peer {
            self.messages.get(peer).map(|v| v.as_slice()).unwrap_or(&[])
        } else {
            &self.system_messages
        }
    }
}

/// Draw the full UI
pub fn draw_ui(f: &mut Frame, state: &mut AppState) {
    let size = f.area();

    // Main layout: [sidebar | chat area]
    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(24.min(size.width / 4)),
            Constraint::Min(40),
        ])
        .split(size);

    // Draw sidebar (contacts)
    draw_sidebar(f, state, main_layout[0]);

    // Right side: [header | messages | input]
    let right_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),   // Messages
            Constraint::Length(3), // Input
        ])
        .split(main_layout[1]);

    // Header
    draw_header(f, state, right_layout[0]);

    // Messages
    draw_messages(f, state, right_layout[1]);

    // Input
    draw_input(f, state, right_layout[2]);

    // Help overlay
    if state.show_help {
        draw_help_overlay(f, size);
    }
}

fn draw_sidebar(f: &mut Frame, state: &mut AppState, area: Rect) {
    let items: Vec<ListItem> = state
        .contacts
        .iter()
        .map(|c| {
            let status = if c.online { "●" } else { "○" };
            let verified = if c.verified { "✓" } else { " " };
            let name = c.alias.as_deref().unwrap_or(&c.username);
            let unread = if c.unread > 0 {
                format!(" ({})", c.unread)
            } else {
                String::new()
            };

            let style = if c.online {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", status), style),
                Span::styled(format!("{}{}", verified, name), Style::default().fg(Color::White)),
                Span::styled(unread, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            ]))
        })
        .collect();

    let title = format!(" {} ", state.username);
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(title, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
        )
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White));

    f.render_stateful_widget(list, area, &mut state.selected_contact);
}

fn draw_header(f: &mut Frame, state: &AppState, area: Rect) {
    let status = if state.connected { "🔗" } else { "⛓" };
    let peer_info = if let Some(ref peer) = state.active_peer {
        let verified = state
            .contacts
            .iter()
            .find(|c| c.username == *peer)
            .map(|c| if c.verified { " ✓verified" } else { " ⚠unverified" })
            .unwrap_or("");
        format!(" chatting with: {}{} ", peer, verified)
    } else {
        " system log ".to_string()
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" ZEROSUM ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", status), Style::default().fg(if state.connected { Color::Green } else { Color::Red })),
        Span::styled(peer_info, Style::default().fg(Color::Cyan)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(header, area);
}

fn draw_messages(f: &mut Frame, state: &AppState, area: Rect) {
    let messages = state.active_messages();

    let items: Vec<ListItem> = messages
        .iter()
        .map(|m| {
            if m.is_system {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("[{}] ", m.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(&m.content, Style::default().fg(Color::Yellow)),
                ]))
            } else {
                let sender_color = if m.sender == state.username {
                    Color::Cyan
                } else {
                    Color::Green
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("[{}] ", m.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{}: ", m.sender),
                        Style::default().fg(sender_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&m.content, Style::default().fg(Color::White)),
                ]))
            }
        })
        .collect();

    let msg_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " messages ",
            Style::default().fg(Color::DarkGray),
        ));

    let list = List::new(items).block(msg_block);

    f.render_widget(list, area);
}

fn draw_input(f: &mut Frame, state: &AppState, area: Rect) {
    let input_style = if state.connected {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let input = Paragraph::new(Line::from(vec![
        Span::styled("› ", Style::default().fg(Color::Red)),
        Span::styled(&state.input, input_style),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                if state.history_enabled { " input [history:on] " } else { " input " },
                Style::default().fg(Color::DarkGray),
            )),
    );

    f.render_widget(input, area);

    // Set cursor position
    f.set_cursor_position((
        area.x + 3 + state.cursor_pos as u16,
        area.y + 1,
    ));
}

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    // Center the help overlay
    let help_width = 58u16.min(area.width.saturating_sub(4));
    let help_height = 28u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(help_width)) / 2;
    let y = (area.height.saturating_sub(help_height)) / 2;
    let overlay_area = Rect::new(x, y, help_width, help_height);

    f.render_widget(Clear, overlay_area);

    let help_lines: Vec<Line> = help_text()
        .into_iter()
        .map(|l| Line::from(Span::styled(l, Style::default().fg(Color::Cyan))))
        .collect();

    let help = Paragraph::new(help_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .title(Span::styled(
                    " HELP — press Esc to close ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(help, overlay_area);
}

/// Handle keyboard input, return the command if the user pressed Enter
pub fn handle_key_event(state: &mut AppState, key: KeyEvent) -> Option<Command> {
    // Help overlay intercepts Escape
    if state.show_help {
        if key.code == KeyCode::Esc {
            state.show_help = false;
        }
        return None;
    }

    match key.code {
        KeyCode::Enter => {
            if state.input.is_empty() {
                return None;
            }
            let input = state.input.clone();
            state.input_history.push(input.clone());
            state.input_history_idx = None;
            state.input.clear();
            state.cursor_pos = 0;
            Some(Command::parse(&input))
        }
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                match c {
                    'c' | 'q' => return Some(Command::Quit),
                    'l' => return Some(Command::Clear),
                    'h' => {
                        state.show_help = true;
                        return None;
                    }
                    _ => {}
                }
            }
            state.input.insert(state.cursor_pos, c);
            state.cursor_pos += 1;
            None
        }
        KeyCode::Backspace => {
            if state.cursor_pos > 0 {
                state.cursor_pos -= 1;
                state.input.remove(state.cursor_pos);
            }
            None
        }
        KeyCode::Delete => {
            if state.cursor_pos < state.input.len() {
                state.input.remove(state.cursor_pos);
            }
            None
        }
        KeyCode::Left => {
            if state.cursor_pos > 0 {
                state.cursor_pos -= 1;
            }
            None
        }
        KeyCode::Right => {
            if state.cursor_pos < state.input.len() {
                state.cursor_pos += 1;
            }
            None
        }
        KeyCode::Home => {
            state.cursor_pos = 0;
            None
        }
        KeyCode::End => {
            state.cursor_pos = state.input.len();
            None
        }
        KeyCode::Up => {
            // Navigate input history
            if !state.input_history.is_empty() {
                let idx = match state.input_history_idx {
                    Some(i) if i > 0 => i - 1,
                    Some(i) => i,
                    None => state.input_history.len() - 1,
                };
                state.input_history_idx = Some(idx);
                state.input = state.input_history[idx].clone();
                state.cursor_pos = state.input.len();
            }
            None
        }
        KeyCode::Down => {
            if let Some(idx) = state.input_history_idx {
                if idx + 1 < state.input_history.len() {
                    let new_idx = idx + 1;
                    state.input_history_idx = Some(new_idx);
                    state.input = state.input_history[new_idx].clone();
                    state.cursor_pos = state.input.len();
                } else {
                    state.input_history_idx = None;
                    state.input.clear();
                    state.cursor_pos = 0;
                }
            }
            None
        }
        KeyCode::Tab => {
            // Cycle through contacts
            if !state.contacts.is_empty() {
                let next = match state.selected_contact.selected() {
                    Some(i) => (i + 1) % state.contacts.len(),
                    None => 0,
                };
                state.selected_contact.select(Some(next));
                state.active_peer = Some(state.contacts[next].username.clone());
                // Clear unread
                state.contacts[next].unread = 0;
            }
            None
        }
        KeyCode::Esc => {
            state.active_peer = None;
            state.selected_contact.select(None);
            None
        }
        KeyCode::F(1) => {
            state.show_help = true;
            None
        }
        _ => None,
    }
}
