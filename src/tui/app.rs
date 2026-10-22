//! TUI state machine (README, "Interactive mode"): keys and pastes change the state; network and
//! disk work is queued as an operation and run between frames (`perform`), so tests drive the app
//! without a terminal (ratatui `TestBackend`) and with a local test server.

use super::clipboard::{Clip, Unavailable, Via};
use super::input::Input;
use crate::api::CliError;
use crate::format;
use crate::ops::Client;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const ACCENT: Color = Color::Rgb(52, 139, 255);
pub const MUTED: Color = Color::Rgb(105, 116, 122);
pub const DANGER: Color = Color::Rgb(236, 73, 61);
pub const OK: Color = Color::Rgb(0, 164, 117);

pub const HOME_ITEMS: [&str; 4] = ["New secret", "Open a link", "Check status", "Quit"];
pub const TTLS: [(&str, u32); 3] = [("1 hour", 3600), ("24 hours", 86400), ("7 days", 604800)];
/// How long a copied secret text stays in the system clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(60);
/// Retry interval when the clipboard is unavailable at removal time.
pub const CLEAR_RETRY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFocus {
    Text,
    Path,
    Files,
    Ttl,
    UsePass,
    Pass,
    Create,
}

pub struct PickedFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
}

pub struct NewForm {
    pub text: Input,
    pub path: Input,
    pub files: Vec<PickedFile>,
    pub file_sel: usize,
    pub ttl: usize,
    pub use_pass: bool,
    pub pass: Input,
    pub focus: NewFocus,
    pub generated: bool,
}

impl NewForm {
    fn new() -> NewForm {
        NewForm {
            text: Input::new(true),
            path: Input::new(false),
            files: Vec::new(),
            file_sel: 0,
            ttl: 1,
            use_pass: false,
            pass: Input::new(false),
            focus: NewFocus::Text,
            generated: false,
        }
    }

    fn order(&self) -> Vec<NewFocus> {
        let mut v = vec![NewFocus::Text, NewFocus::Path];
        if !self.files.is_empty() {
            v.push(NewFocus::Files);
        }
        v.extend([NewFocus::Ttl, NewFocus::UsePass]);
        if self.use_pass {
            v.push(NewFocus::Pass);
        }
        v.push(NewFocus::Create);
        v
    }

    fn step(&mut self, back: bool) {
        let order = self.order();
        let i = order.iter().position(|f| *f == self.focus).unwrap_or(0);
        let n = order.len();
        self.focus = order[if back { (i + n - 1) % n } else { (i + 1) % n }];
    }
}

pub struct CreatedView {
    pub recipient: Zeroizing<String>,
    pub owner: Zeroizing<String>,
    pub expires: String,
    pub passphrase: bool,
    pub show_owner: bool,
}

pub enum Screen {
    Home {
        selected: usize,
    },
    New(Box<NewForm>),
    Created(CreatedView),
    /// Not implemented yet (step 26).
    Todo(&'static str),
}

/// Work queued by a key and run between frames.
pub enum Op {
    Create,
}

/// A copied secret text to remove from the clipboard later: when, and a hash to recognise it.
struct PendingClear {
    at: Instant,
    hash: [u8; 32],
}

pub struct App {
    pub screen: Screen,
    pub quit: bool,
    /// Error (true) or note shown above the footer until the next key.
    pub message: Option<(bool, String)>,
    pub pending: Option<Op>,
    clip: Box<dyn Clip>,
    clip_warned: bool,
    clear: Option<PendingClear>,
    now: Instant,
}

const CLIP_WARNING: &str =
    "Clipboard managers may keep a history of what you copy. Press the key again to copy.";

impl App {
    pub fn new(clip: Box<dyn Clip>) -> App {
        App {
            screen: Screen::Home { selected: 0 },
            quit: false,
            message: None,
            pending: None,
            clip,
            clip_warned: false,
            clear: None,
            now: Instant::now(),
        }
    }

    fn note(&mut self, m: impl Into<String>) {
        self.message = Some((false, m.into()));
    }

    fn error(&mut self, m: impl Into<String>) {
        self.message = Some((true, m.into()));
    }

    /// Copy with a one-time warning about clipboard history. `secret`: a secret text, removed from
    /// the system clipboard after `CLEAR_AFTER` if it is still there (links are not removed).
    pub fn copy(&mut self, text: &str, what: &str, secret: bool) {
        if !self.clip_warned {
            self.clip_warned = true;
            self.note(CLIP_WARNING);
            return;
        }
        match self.clip.copy(text) {
            Ok(Via::System) => {
                if secret {
                    self.clear = Some(PendingClear {
                        at: self.now + CLEAR_AFTER,
                        hash: Sha256::digest(text.as_bytes()).into(),
                    });
                    self.note(format!("{what} copied; it is removed from the clipboard in 60 seconds."));
                } else {
                    self.note(format!("{what} copied."));
                }
            }
            Ok(Via::Terminal) => self.note(format!(
                "{what} sent to the terminal clipboard (OSC 52). If nothing was copied, select it on the screen."
            )),
            Err(e) => self.error(format!("Could not copy: {e}. Select it on the screen.")),
        }
    }

    /// Remove the copied secret text if the clipboard still holds it. Done (true) when removed
    /// or replaced by something else; false when the clipboard was unavailable (try again).
    fn try_clear(&mut self, hash: [u8; 32]) -> bool {
        match self.clip.read() {
            Ok(Some(cur)) if <[u8; 32]>::from(Sha256::digest(cur.as_bytes())) == hash => {
                self.clip.clear().is_ok()
            }
            Ok(_) => true,
            Err(Unavailable) => false,
        }
    }

    /// Time passes: remove a copied secret text from the clipboard when due, if unchanged; if the
    /// clipboard is unavailable, retry later instead of forgetting it.
    pub fn tick(&mut self, now: Instant) {
        self.now = now;
        if let Some(c) = &self.clear
            && now >= c.at
        {
            let hash = c.hash;
            if self.try_clear(hash) {
                self.clear = None;
            } else if let Some(c) = &mut self.clear {
                c.at = now + CLEAR_RETRY;
            }
        }
    }

    /// Leaving (quit, error or panic): a copied secret text still waiting is removed now.
    pub fn on_quit(&mut self) {
        if let Some(c) = self.clear.take() {
            self.try_clear(c.hash);
        }
    }

    pub fn key(&mut self, k: KeyEvent) {
        self.message = None;
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match &mut self.screen {
            Screen::Home { selected } => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    *selected = (*selected + HOME_ITEMS.len() - 1) % HOME_ITEMS.len();
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    *selected = (*selected + 1) % HOME_ITEMS.len();
                }
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                KeyCode::Enter => match *selected {
                    0 => self.screen = Screen::New(Box::new(NewForm::new())),
                    1 => self.screen = Screen::Todo("Open a link"),
                    2 => self.screen = Screen::Todo("Check status"),
                    _ => self.quit = true,
                },
                _ => {}
            },
            Screen::New(_) => self.key_new(k),
            Screen::Created(_) => self.key_created(k),
            Screen::Todo(_) => {
                if k.code == KeyCode::Esc {
                    self.screen = Screen::Home { selected: 0 };
                }
            }
        }
    }

    pub fn paste(&mut self, text: &str) {
        if let Screen::New(f) = &mut self.screen {
            match f.focus {
                NewFocus::Text => {
                    f.text.insert(text);
                    f.generated = false;
                }
                NewFocus::Path => f.path.insert(text),
                NewFocus::Pass => f.pass.insert(text),
                _ => {}
            }
        }
    }

    fn key_new(&mut self, k: KeyEvent) {
        let Screen::New(f) = &mut self.screen else {
            return;
        };
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Esc => {
                self.screen = Screen::Home { selected: 0 };
                return;
            }
            KeyCode::Tab => return f.step(false),
            KeyCode::BackTab => return f.step(true),
            KeyCode::Char('g') if ctrl => {
                f.text.set(&crate::password::generate());
                f.generated = true;
                self.note("A random 24-character password. Save it where you need it.");
                return;
            }
            _ => {}
        }
        match f.focus {
            NewFocus::Text => {
                if edit(&mut f.text, k) {
                    f.generated = false;
                }
            }
            NewFocus::Path => {
                if k.code == KeyCode::Enter {
                    let added = add_file(f);
                    match added {
                        Ok(()) => {}
                        Err(e) => self.error(e),
                    }
                } else {
                    edit(&mut f.path, k);
                }
            }
            NewFocus::Files => match k.code {
                KeyCode::Up => f.file_sel = f.file_sel.saturating_sub(1),
                KeyCode::Down => f.file_sel = (f.file_sel + 1).min(f.files.len().saturating_sub(1)),
                KeyCode::Delete | KeyCode::Backspace => {
                    if f.file_sel < f.files.len() {
                        f.files.remove(f.file_sel);
                        f.file_sel = f.file_sel.min(f.files.len().saturating_sub(1));
                        if f.files.is_empty() {
                            f.focus = NewFocus::Path;
                        }
                    }
                }
                _ => {}
            },
            NewFocus::Ttl => match k.code {
                KeyCode::Left => f.ttl = f.ttl.saturating_sub(1),
                KeyCode::Right => f.ttl = (f.ttl + 1).min(TTLS.len() - 1),
                _ => {}
            },
            NewFocus::UsePass => {
                if matches!(k.code, KeyCode::Char(' ') | KeyCode::Enter) {
                    f.use_pass = !f.use_pass;
                    if !f.use_pass {
                        f.pass.clear();
                    }
                }
            }
            NewFocus::Pass => {
                edit(&mut f.pass, k);
            }
            NewFocus::Create => {
                if k.code == KeyCode::Enter {
                    if f.text.text().is_empty() && f.files.is_empty() {
                        self.error("Enter a secret or add a file.");
                    } else if f.use_pass && f.pass.text().is_empty() {
                        self.error("Enter a passphrase or turn it off.");
                    } else {
                        self.pending = Some(Op::Create);
                        self.note("Encrypting and creating…");
                    }
                }
            }
        }
    }

    fn key_created(&mut self, k: KeyEvent) {
        let Screen::Created(v) = &mut self.screen else {
            return;
        };
        match k.code {
            KeyCode::Char('c') => {
                let link = v.recipient.clone();
                self.copy(&link, "The link", false);
            }
            KeyCode::Char('o') => v.show_owner = !v.show_owner,
            KeyCode::Char('y') if v.show_owner => {
                let link = v.owner.clone();
                self.copy(&link, "Your status link", false);
            }
            KeyCode::Char('n') => self.screen = Screen::New(Box::new(NewForm::new())),
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Home { selected: 0 },
            _ => {}
        }
    }

    /// Run the queued operation (network, disk). Errors keep the screen and its input.
    pub fn perform(&mut self, client: &mut Client) {
        let Some(op) = self.pending.take() else {
            return;
        };
        self.message = None;
        match op {
            Op::Create => {
                let Screen::New(f) = &mut self.screen else {
                    return;
                };
                match create(f, client) {
                    Ok(v) => self.screen = Screen::Created(v),
                    Err(e) => self.error(e.to_string()),
                }
            }
        }
    }

    pub fn render(&self, f: &mut Frame) {
        let [title, body, msg, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .areas(f.area());
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " payneteasy ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Secrets", Style::default().fg(MUTED)),
            ])),
            title,
        );
        let hints = match &self.screen {
            Screen::Home { .. } => "↑↓ choose · Enter open · q quit",
            Screen::New(_) => "Tab next · Shift+Tab back · Ctrl+G generate password · Esc back",
            Screen::Created(v) if v.show_owner => {
                "c copy link · y copy status link · o hide · n new · Esc home"
            }
            Screen::Created(_) => "c copy link · o show your status link · n new · Esc home",
            Screen::Todo(_) => "Esc back · Ctrl+C quit",
        };
        match &self.screen {
            Screen::Home { selected } => render_home(f, body, *selected),
            Screen::New(form) => render_new(f, body, form),
            Screen::Created(v) => render_created(f, body, v),
            Screen::Todo(name) => f.render_widget(
                Paragraph::new(format!("{name}: coming soon"))
                    .block(Block::default().borders(Borders::ALL).title(*name)),
                body,
            ),
        }
        if let Some((is_error, m)) = &self.message {
            let style = Style::default().fg(if *is_error { DANGER } else { MUTED });
            f.render_widget(
                Paragraph::new(m.as_str())
                    .style(style)
                    .wrap(Wrap { trim: true }),
                msg,
            );
        }
        f.render_widget(
            Paragraph::new(hints).style(Style::default().fg(MUTED)),
            footer,
        );
    }
}

impl Drop for App {
    /// Also on an error or a panic in the event loop: the clipboard is not left holding a secret.
    fn drop(&mut self) {
        self.on_quit();
    }
}

/// Common editing keys for a field; true if the text changed.
fn edit(i: &mut Input, k: KeyEvent) -> bool {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match k.code {
        KeyCode::Char(c) if !ctrl => {
            let mut b = [0u8; 4];
            i.insert(c.encode_utf8(&mut b));
            true
        }
        KeyCode::Enter if i.multiline => {
            i.insert("\n");
            true
        }
        KeyCode::Backspace => {
            i.backspace();
            true
        }
        KeyCode::Delete => {
            i.delete();
            true
        }
        KeyCode::Left => {
            i.left();
            false
        }
        KeyCode::Right => {
            i.right();
            false
        }
        KeyCode::Up => {
            i.up();
            false
        }
        KeyCode::Down => {
            i.down();
            false
        }
        KeyCode::Home => {
            i.home();
            false
        }
        KeyCode::End => {
            i.end();
            false
        }
        _ => false,
    }
}

/// Add the file from the path field: it must exist and be a regular file; at most 20.
fn add_file(f: &mut NewForm) -> Result<(), String> {
    let raw = f.path.text().trim();
    if raw.is_empty() {
        return Err("Type the path of a file, then Enter.".into());
    }
    if f.files.len() >= format::MAX_FILES {
        return Err(format!("Too many files: at most {}.", format::MAX_FILES));
    }
    let path = expand_home(raw);
    let meta = std::fs::metadata(&path).map_err(|_| "No such file.".to_string())?;
    if !meta.is_file() {
        return Err("Not a regular file.".into());
    }
    if meta.len() == 0 {
        return Err("The file is empty.".into());
    }
    let raw_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    f.files.push(PickedFile {
        name: format::sanitize_file_name(&raw_name),
        size: meta.len(),
        path,
    });
    f.file_sel = f.files.len() - 1;
    f.path.clear();
    Ok(())
}

fn expand_home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(p),
    }
}

/// Read the files, compose the one record (FORMAT.md 4), encrypt and create.
fn create(f: &mut NewForm, client: &mut Client) -> Result<CreatedView, CliError> {
    let files = f
        .files
        .iter()
        .map(|p| crate::commands::read_file_secret(&p.path))
        .collect::<Result<Vec<_>, _>>()?;
    let content = format::compose(
        f.text.text(),
        files.iter().map(|(n, d)| (n.as_str(), &d[..])).collect(),
    );
    format::encode_plaintext(&content, format::MAX_BUCKET)?;
    let passphrase = f.use_pass.then(|| f.pass.text());
    let created = client.create(&content, passphrase, TTLS[f.ttl].1)?;
    Ok(CreatedView {
        recipient: created.recipient,
        owner: created.owner,
        expires: created.expires,
        passphrase: passphrase.is_some(),
        show_owner: false,
    })
}

fn focused_block(title: &str, focused: bool) -> Block<'_> {
    let b = Block::default().borders(Borders::ALL).title(title);
    if focused {
        b.border_style(Style::default().fg(ACCENT))
    } else {
        b
    }
}

fn render_home(f: &mut Frame, area: Rect, selected: usize) {
    let items: Vec<ListItem> = HOME_ITEMS.iter().map(|s| ListItem::new(*s)).collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" One-time secrets, encrypted on this machine "),
        )
        .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
        .highlight_symbol("› ");
    let mut state = ListState::default().with_selected(Some(selected));
    f.render_stateful_widget(list, area, &mut state);
}

/// Field scrolled so that the cursor stays visible; the terminal cursor is placed on it when
/// focused.
fn render_input(f: &mut Frame, area: Rect, input: &Input, title: &str, focused: bool) {
    let (line, col) = input.line_col();
    let (w, h) = (
        area.width.saturating_sub(2) as usize,
        area.height.saturating_sub(2) as usize,
    );
    let dy = line.saturating_sub(h.saturating_sub(1));
    let dx = col.saturating_sub(w.saturating_sub(1));
    f.render_widget(
        Paragraph::new(input.text())
            .scroll((dy as u16, dx as u16))
            .block(focused_block(title, focused)),
        area,
    );
    if focused && w > 0 && h > 0 {
        f.set_cursor_position(Position {
            x: area.x + 1 + (col - dx) as u16,
            y: area.y + 1 + (line - dy) as u16,
        });
    }
}

fn render_new(f: &mut Frame, area: Rect, form: &NewForm) {
    let files_h = (form.files.len() as u16).min(6) + 2;
    let [text, path, files, ttl, pass, create] = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(3),
        Constraint::Length(if form.files.is_empty() { 0 } else { files_h }),
        Constraint::Length(1),
        Constraint::Length(if form.use_pass { 4 } else { 1 }),
        Constraint::Length(1),
    ])
    .areas(area);
    let title = if form.generated {
        " Secret (generated password) "
    } else {
        " Secret "
    };
    render_input(f, text, &form.text, title, form.focus == NewFocus::Text);
    let path_title = format!(
        " Add a file: path, then Enter ({}/{}) ",
        form.files.len(),
        format::MAX_FILES
    );
    render_input(
        f,
        path,
        &form.path,
        &path_title,
        form.focus == NewFocus::Path,
    );
    if !form.files.is_empty() {
        let total: u64 = form.files.iter().map(|p| p.size).sum();
        let items: Vec<ListItem> = form
            .files
            .iter()
            .map(|p| {
                ListItem::new(format!(
                    "{}  {}",
                    p.name,
                    crate::ops::human_size(p.size as usize)
                ))
            })
            .collect();
        let title = format!(
            " Files, {} · Del removes ",
            crate::ops::human_size(total as usize)
        );
        let list = List::new(items)
            .block(focused_block(&title, form.focus == NewFocus::Files))
            .highlight_symbol("› ");
        let mut state = ListState::default().with_selected(Some(form.file_sel));
        f.render_stateful_widget(list, files, &mut state);
    }
    let mut spans = vec![Span::raw(" If nobody opens it, delete after: ")];
    for (i, (label, _)) in TTLS.iter().enumerate() {
        let style = if i == form.ttl {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(MUTED)
        };
        spans.push(Span::styled(format!(" {label} "), style));
    }
    if form.focus == NewFocus::Ttl {
        spans.push(Span::styled("  ←/→", Style::default().fg(ACCENT)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), ttl);
    let [toggle, field] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(pass);
    let mark = if form.use_pass { "[x]" } else { "[ ]" };
    let style = if form.focus == NewFocus::UsePass {
        Style::default().fg(ACCENT)
    } else {
        Style::default()
    };
    f.render_widget(
        Paragraph::new(format!(" {mark} Protect with a passphrase (Space)")).style(style),
        toggle,
    );
    if form.use_pass {
        render_input(
            f,
            field,
            &form.pass,
            " Passphrase: send it through a different channel ",
            form.focus == NewFocus::Pass,
        );
    }
    let style = if form.focus == NewFocus::Create {
        Style::default()
            .fg(Color::White)
            .bg(ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(ACCENT)
    };
    f.render_widget(
        Paragraph::new(" Create one-time link (Enter) ").style(style),
        create,
    );
}

fn render_created(f: &mut Frame, area: Rect, v: &CreatedView) {
    let mut lines = vec![
        Line::styled(
            "Send this link to the recipient",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::styled(
            "It opens once, then the secret is destroyed. Anyone who opens it first can read it.",
            Style::default().fg(MUTED),
        ),
        Line::raw(""),
        Line::styled(v.recipient.as_str(), Style::default().fg(ACCENT)),
        Line::raw(""),
    ];
    if v.passphrase {
        lines.push(Line::styled(
            "Send the passphrase separately, through a different channel.",
            Style::default().fg(MUTED),
        ));
    }
    lines.push(Line::styled(
        format!(
            "Opens only once. If nobody opens it, it is deleted on {}.",
            v.expires
        ),
        Style::default().fg(MUTED),
    ));
    lines.push(Line::raw(""));
    if v.show_owner {
        lines.push(Line::styled(
            "Only for you: track or revoke. Do not send this one.",
            Style::default().fg(OK),
        ));
        lines.push(Line::raw(v.owner.as_str()));
    } else {
        lines.push(Line::styled(
            "Only for you: track or revoke (o to show)",
            Style::default().fg(MUTED),
        ));
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ready to share "),
        ),
        area,
    );
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::{Arc, Mutex};

    /// Clipboard in memory: what was copied and whether it is the system one.
    #[derive(Clone, Default)]
    pub struct MemClip {
        pub value: Arc<Mutex<Option<String>>>,
        pub terminal: bool,
        /// The clipboard is temporarily unavailable.
        pub down: Arc<Mutex<bool>>,
    }

    impl Clip for MemClip {
        fn copy(&mut self, text: &str) -> Result<Via, String> {
            *self.value.lock().unwrap() = Some(text.to_owned());
            Ok(if self.terminal {
                Via::Terminal
            } else {
                Via::System
            })
        }
        fn read(&mut self) -> Result<Option<Zeroizing<String>>, Unavailable> {
            if *self.down.lock().unwrap() {
                return Err(Unavailable);
            }
            Ok(self.value.lock().unwrap().clone().map(Zeroizing::new))
        }
        fn clear(&mut self) -> Result<(), Unavailable> {
            if *self.down.lock().unwrap() {
                return Err(Unavailable);
            }
            *self.value.lock().unwrap() = None;
            Ok(())
        }
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    pub fn screen_text(app: &App) -> String {
        let mut t = Terminal::new(TestBackend::new(100, 30)).unwrap();
        t.draw(|f| app.render(f)).unwrap();
        let buf = t.backend().buffer().clone();
        buf.content.iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn home_navigation_and_quit() {
        let mut app = App::new(Box::new(MemClip::default()));
        assert!(screen_text(&app).contains("New secret"));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Enter));
        assert!(matches!(app.screen, Screen::Todo("Check status")));
        app.key(key(KeyCode::Esc));
        app.key(key(KeyCode::Up));
        app.key(key(KeyCode::Enter));
        assert!(app.quit, "Up from the first item wraps to Quit");
        let mut app = App::new(Box::new(MemClip::default()));
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.quit);
    }

    #[test]
    fn copy_warns_once_then_copies_and_clears_secret_text_only() {
        let clip = MemClip::default();
        let mut app = App::new(Box::new(clip.clone()));
        let t0 = Instant::now();
        app.tick(t0);
        app.copy("link", "The link", false);
        assert_eq!(*clip.value.lock().unwrap(), None, "first press only warns");
        app.copy("link", "The link", false);
        assert_eq!(clip.value.lock().unwrap().as_deref(), Some("link"));
        app.tick(t0 + CLEAR_AFTER * 2);
        assert_eq!(
            clip.value.lock().unwrap().as_deref(),
            Some("link"),
            "links stay"
        );
        // A secret text is removed after 60 s, even after leaving the screen.
        app.copy("s3cret", "The secret", true);
        app.screen = Screen::Home { selected: 0 };
        app.tick(t0 + CLEAR_AFTER * 2 + Duration::from_secs(59));
        assert_eq!(clip.value.lock().unwrap().as_deref(), Some("s3cret"));
        app.tick(t0 + CLEAR_AFTER * 3 + Duration::from_secs(1));
        assert_eq!(*clip.value.lock().unwrap(), None);
        // Replaced by the user meanwhile: left alone.
        app.copy("s3cret", "The secret", true);
        *clip.value.lock().unwrap() = Some("user text".into());
        app.tick(t0 + CLEAR_AFTER * 10);
        assert_eq!(clip.value.lock().unwrap().as_deref(), Some("user text"));
        // Quitting before the timer removes it at once.
        app.copy("s3cret", "The secret", true);
        app.on_quit();
        assert_eq!(*clip.value.lock().unwrap(), None);
        // Unavailable at removal time: retried, not forgotten.
        let t1 = t0 + CLEAR_AFTER * 20;
        app.tick(t1);
        app.copy("s3cret", "The secret", true);
        *clip.down.lock().unwrap() = true;
        app.tick(t1 + CLEAR_AFTER);
        assert_eq!(clip.value.lock().unwrap().as_deref(), Some("s3cret"));
        *clip.down.lock().unwrap() = false;
        app.tick(t1 + CLEAR_AFTER + CLEAR_RETRY);
        assert_eq!(*clip.value.lock().unwrap(), None);
        // An error or a panic in the loop drops the app: the secret is removed then too.
        app.copy("s3cret", "The secret", true);
        drop(app);
        assert_eq!(*clip.value.lock().unwrap(), None);
    }

    #[test]
    fn long_fields_scroll_to_the_cursor() {
        let mut app = App::new(Box::new(MemClip::default()));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.focus = NewFocus::Path;
        let long = format!("/very/long/{}/END-OF-PATH", "x".repeat(150));
        app.paste(&long);
        assert!(
            screen_text(&app).contains("END-OF-PATH"),
            "the tail is visible"
        );
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.focus = NewFocus::Text;
        let lines: String = (0..40).map(|i| format!("line {i}\n")).collect();
        app.paste(&format!("{lines}LAST-LINE"));
        assert!(
            screen_text(&app).contains("LAST-LINE"),
            "the last line is visible"
        );
    }

    #[test]
    fn new_form_generate_files_and_validation() {
        let mut app = App::new(Box::new(MemClip::default()));
        app.key(key(KeyCode::Enter));
        assert!(matches!(app.screen, Screen::New(_)));
        // Create with nothing: a message, nothing queued.
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.focus = NewFocus::Create;
        app.key(key(KeyCode::Enter));
        assert!(app.pending.is_none());
        assert!(screen_text(&app).contains("Enter a secret or add a file."));
        app.key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        assert_eq!(f.text.text().chars().count(), crate::password::LENGTH);
        assert!(f.generated);
        // A missing file is refused; a real one is listed.
        f.focus = NewFocus::Path;
        app.paste("/nonexistent/x");
        app.key(key(KeyCode::Enter));
        assert!(screen_text(&app).contains("No such file."));
        let dir = std::env::temp_dir().join(format!("sdrop-tui-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("key.pem");
        std::fs::write(&file, b"KEY").unwrap();
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.path.clear();
        app.paste(file.to_str().unwrap());
        app.key(key(KeyCode::Enter));
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        assert_eq!(f.files.len(), 1);
        assert_eq!(f.files[0].name, "key.pem");
        // Passphrase on but empty: refused.
        f.use_pass = true;
        f.focus = NewFocus::Create;
        app.key(key(KeyCode::Enter));
        assert!(app.pending.is_none());
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.pass.set("pw");
        app.key(key(KeyCode::Enter));
        assert!(matches!(app.pending, Some(Op::Create)));
    }
}
