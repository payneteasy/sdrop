//! TUI state machine (README, "Interactive mode"): keys and pastes change the state; network and
//! disk work is queued as an operation and run between frames (`perform`), so tests drive the app
//! without a terminal (ratatui `TestBackend`) and with a local test server.

use super::clipboard::{Clip, Unavailable, Via};
use super::input::Input;
use crate::api::{CliError, OwnerLink, RecipientLink};
use crate::format::{self, FormatError, Secret};
use crate::ops::{Client, Revoked, Status, human_size};
use crate::save;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
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

/// A link was checked (no request yet): reveal on confirmation.
pub struct RevealView {
    pub link: RecipientLink,
    pub pass: Input,
}

/// The envelope is fetched (the server has deleted it) and needs a passphrase: it is kept only
/// here, retries are local.
pub struct UnlockView {
    pub link: RecipientLink,
    pub envelope: Zeroizing<Vec<u8>>,
    pub pass: Input,
}

pub struct RevealedView {
    pub id: String,
    pub secret: Secret,
    pub scroll: usize,
    /// Last page start as of the last frame, so that keys stop scrolling at the end.
    pub max_scroll: std::cell::Cell<usize>,
    /// Typing the directory to save into.
    pub saving: bool,
    pub dir: Input,
    pub saved: Option<String>,
}

impl RevealedView {
    pub fn text(&self) -> &str {
        match &self.secret {
            Secret::Text(t) => t,
            Secret::Bundle { text, .. } => text,
            Secret::File { .. } => "",
        }
    }

    /// Sender file names and sizes (names are only shown, never used as paths).
    fn files(&self) -> Vec<(&str, usize)> {
        match &self.secret {
            Secret::Text(_) => vec![],
            Secret::File { name, data } => vec![(name.as_str(), data.len())],
            Secret::Bundle { files, .. } => {
                files.iter().map(|(n, d)| (n.as_str(), d.len())).collect()
            }
        }
    }

    /// What `Save` writes: the text as `text` (if any), a single file as `data`, the files of a
    /// text with files as `file-N` (as the CLI does).
    fn entries(&self) -> Vec<(String, &[u8])> {
        let mut v: Vec<(String, &[u8])> = Vec::new();
        if !self.text().is_empty() {
            v.push(("text".into(), self.text().as_bytes()));
        }
        match &self.secret {
            Secret::File { data, .. } => v.push(("data".into(), &data[..])),
            Secret::Bundle { files, .. } => {
                for (i, (_, d)) in files.iter().enumerate() {
                    v.push((format!("file-{}", i + 1), &d[..]));
                }
            }
            Secret::Text(_) => {}
        }
        v
    }

    fn has_files(&self) -> bool {
        !matches!(self.secret, Secret::Text(_))
    }
}

pub struct StatusView {
    pub link: OwnerLink,
    pub status: Status,
    pub confirm_revoke: bool,
}

pub enum Screen {
    Home { selected: usize },
    New(Box<NewForm>),
    Created(CreatedView),
    Open(Input),
    Reveal(Box<RevealView>),
    Unlock(Box<UnlockView>),
    Revealed(Box<RevealedView>),
    StatusForm(Input),
    Status(Box<StatusView>),
}

impl Screen {
    /// A fetched secret exists only in this screen: leaving destroys it.
    fn holds_secret(&self) -> bool {
        match self {
            Screen::Unlock(_) => true,
            Screen::Revealed(v) => v.has_files() && v.saved.is_none(),
            _ => false,
        }
    }
}

/// Work queued by a key and run between frames.
pub enum Op {
    Create,
    OpenLink,
    Consume,
    Unlock,
    Save,
    LoadStatus,
    RefreshStatus,
    Revoke,
}

/// What a mouse click hits; recorded while drawing. A button is the same as pressing its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    Key(KeyEvent),
    Home(usize),
    Focus(NewFocus),
    Ttl(usize),
    PassToggle,
    File(usize),
}

type Hits = Vec<(Rect, Hit)>;

fn press(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// A row of buttons; the first may be primary (filled). Each records its click area.
fn render_buttons(f: &mut Frame, area: Rect, buttons: &[(String, Hit, bool)], hits: &mut Hits) {
    let mut x = area.x;
    for (label, hit, primary) in buttons {
        let text = format!(" {label} ");
        let w = (unicode_width::UnicodeWidthStr::width(text.as_str()) as u16)
            .min(area.right().saturating_sub(x));
        if w == 0 {
            break;
        }
        let r = Rect {
            x,
            y: area.y,
            width: w,
            height: 1,
        };
        let style = if *primary {
            Style::default()
                .fg(Color::White)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(ACCENT).add_modifier(Modifier::REVERSED)
        };
        f.render_widget(Paragraph::new(text).style(style), r);
        hits.push((r, *hit));
        x = x.saturating_add(w + 2);
    }
}

/// A copied secret text to remove from the clipboard later: when, and a hash to recognise it.
struct PendingClear {
    at: Instant,
    hash: [u8; 32],
}

pub struct App {
    pub screen: Screen,
    pub quit: bool,
    /// A secret would be destroyed by leaving: the next leave key confirms.
    leave_armed: bool,
    /// Error (true) or note shown above the footer until the next key.
    pub message: Option<(bool, String)>,
    pub pending: Option<Op>,
    /// Click areas of the last frame.
    hits: std::cell::RefCell<Hits>,
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
            leave_armed: false,
            message: None,
            pending: None,
            hits: std::cell::RefCell::new(Vec::new()),
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
                    let hash: [u8; 32] = Sha256::digest(text.as_bytes()).into();
                    // Also on its own thread: a blocking request in the event loop cannot delay it.
                    self.clip.schedule_clear(hash, CLEAR_AFTER);
                    self.clear = Some(PendingClear {
                        at: self.now + CLEAR_AFTER,
                        hash,
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

    /// Leaving a screen that holds a fetched secret needs the key twice.
    fn may_leave(&mut self) -> bool {
        if !self.screen.holds_secret() || self.leave_armed {
            return true;
        }
        self.leave_armed = true;
        self.error(
            "The secret exists only here now: leaving destroys it. Press the key again to leave.",
        );
        false
    }

    pub fn key(&mut self, k: KeyEvent) {
        self.message = None;
        let open = matches!(self.screen, Screen::Open(_));
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let typing_dir = matches!(&self.screen, Screen::Revealed(v) if v.saving);
        let leaving =
            (ctrl && k.code == KeyCode::Char('c')) || (k.code == KeyCode::Esc && !typing_dir);
        if !leaving {
            self.leave_armed = false;
        }
        if ctrl && k.code == KeyCode::Char('c') {
            if self.may_leave() {
                self.quit = true;
            }
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
                    1 => self.screen = Screen::Open(Input::new(false)),
                    2 => self.screen = Screen::StatusForm(Input::new(false)),
                    _ => self.quit = true,
                },
                _ => {}
            },
            Screen::New(_) => self.key_new(k),
            Screen::Created(_) => self.key_created(k),
            Screen::Open(link) | Screen::StatusForm(link) => match k.code {
                KeyCode::Esc => self.screen = Screen::Home { selected: 0 },
                KeyCode::Enter if link.text().trim().is_empty() => {
                    self.error("Paste the link first.");
                }
                KeyCode::Enter => {
                    self.pending = Some(if open { Op::OpenLink } else { Op::LoadStatus });
                }
                _ => {
                    edit(link, k);
                }
            },
            Screen::Reveal(v) => match k.code {
                KeyCode::Esc => self.screen = Screen::Home { selected: 0 },
                KeyCode::Enter if v.link.passphrase_hint && v.pass.text().is_empty() => {
                    self.error("Type the passphrase first.");
                }
                KeyCode::Enter => {
                    self.pending = Some(Op::Consume);
                    self.note("Fetching and decrypting…");
                }
                _ if v.link.passphrase_hint => {
                    edit(&mut v.pass, k);
                }
                _ => {}
            },
            Screen::Unlock(v) => match k.code {
                KeyCode::Esc => {
                    if self.may_leave() {
                        self.screen = Screen::Home { selected: 0 };
                    }
                }
                KeyCode::Enter if v.pass.text().is_empty() => {
                    self.error("Type the passphrase. The secret is kept only in memory now.");
                }
                KeyCode::Enter => {
                    self.pending = Some(Op::Unlock);
                    self.note("Decrypting…");
                }
                _ => {
                    edit(&mut v.pass, k);
                }
            },
            Screen::Revealed(_) => self.key_revealed(k),
            Screen::Status(v) => match k.code {
                KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Home { selected: 0 },
                KeyCode::Char('r') => {
                    v.confirm_revoke = false;
                    self.pending = Some(Op::RefreshStatus);
                }
                KeyCode::Char('x') if v.status.state == "stored" => {
                    if v.confirm_revoke {
                        v.confirm_revoke = false;
                        self.pending = Some(Op::Revoke);
                    } else {
                        v.confirm_revoke = true;
                        self.error(
                            "Revoke: the link stops working for good. Press x again to revoke.",
                        );
                    }
                }
                _ => v.confirm_revoke = false,
            },
        }
    }

    fn key_revealed(&mut self, k: KeyEvent) {
        let Screen::Revealed(v) = &mut self.screen else {
            return;
        };
        if v.saving {
            match k.code {
                KeyCode::Esc => v.saving = false,
                KeyCode::Enter => {
                    self.pending = Some(Op::Save);
                    self.note("Saving…");
                }
                _ => {
                    edit(&mut v.dir, k);
                }
            }
            return;
        }
        // The terminal may have grown since the scroll was set: clamp the state, not only the view.
        v.scroll = v.scroll.min(v.max_scroll.get());
        match k.code {
            KeyCode::Up => v.scroll = v.scroll.saturating_sub(1),
            KeyCode::Down => v.scroll = (v.scroll + 1).min(v.max_scroll.get()),
            KeyCode::PageUp => v.scroll = v.scroll.saturating_sub(10),
            KeyCode::PageDown => v.scroll = (v.scroll + 10).min(v.max_scroll.get()),
            KeyCode::Char('c') if !v.text().is_empty() => {
                let text = Zeroizing::new(v.text().to_owned());
                self.copy(&text, "The secret", true);
            }
            KeyCode::Char('s') => {
                v.saving = true;
                v.dir.clear();
            }
            KeyCode::Esc => {
                if self.may_leave() {
                    self.screen = Screen::Home { selected: 0 };
                }
            }
            _ => {}
        }
    }

    pub fn paste(&mut self, text: &str) {
        match &mut self.screen {
            Screen::New(f) => match f.focus {
                NewFocus::Text => {
                    f.text.insert(text);
                    f.generated = false;
                }
                NewFocus::Path => f.path.insert(text),
                NewFocus::Pass => f.pass.insert(text),
                _ => {}
            },
            Screen::Open(i) | Screen::StatusForm(i) => i.insert(text.trim()),
            Screen::Reveal(v) if v.link.passphrase_hint => v.pass.insert(text),
            Screen::Unlock(v) => v.pass.insert(text),
            Screen::Revealed(v) if v.saving => v.dir.insert(text.trim()),
            _ => {}
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
            // Create from any field: Ctrl+S everywhere; Shift/Cmd/Ctrl+Enter where the terminal
            // reports the modifier (keyboard enhancement).
            KeyCode::Char('s') if ctrl => return self.request_create(),
            KeyCode::Enter
                if k.modifiers.intersects(
                    KeyModifiers::SHIFT
                        | KeyModifiers::SUPER
                        | KeyModifiers::CONTROL
                        | KeyModifiers::META,
                ) =>
            {
                return self.request_create();
            }
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
                    self.request_create();
                }
            }
        }
    }

    fn request_create(&mut self) {
        let Screen::New(f) = &self.screen else {
            return;
        };
        if f.text.text().is_empty() && f.files.is_empty() {
            self.error("Enter a secret or add a file.");
        } else if f.use_pass && f.pass.text().is_empty() {
            self.error("Enter a passphrase or turn it off.");
        } else {
            self.pending = Some(Op::Create);
            self.note("Encrypting and creating…");
        }
    }

    /// A mouse event: clicks act like the key of what was hit; the wheel scrolls.
    pub fn mouse(&mut self, m: MouseEvent) {
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let hit = self
                    .hits
                    .borrow()
                    .iter()
                    .rev()
                    .find(|(r, _)| {
                        r.contains(ratatui::layout::Position {
                            x: m.column,
                            y: m.row,
                        })
                    })
                    .map(|(_, h)| *h);
                match hit {
                    Some(Hit::Key(k)) => self.key(k),
                    Some(Hit::Home(i)) => {
                        if let Screen::Home { selected } = &mut self.screen {
                            *selected = i;
                        }
                        self.key(press(KeyCode::Enter));
                    }
                    Some(Hit::Focus(to)) => {
                        if let Screen::New(f) = &mut self.screen {
                            f.focus = to;
                        }
                    }
                    Some(Hit::Ttl(i)) => {
                        if let Screen::New(f) = &mut self.screen {
                            f.ttl = i;
                            f.focus = NewFocus::Ttl;
                        }
                    }
                    Some(Hit::PassToggle) => {
                        if let Screen::New(f) = &mut self.screen {
                            f.focus = NewFocus::UsePass;
                        }
                        self.key(press(KeyCode::Char(' ')));
                    }
                    Some(Hit::File(i)) => {
                        if let Screen::New(f) = &mut self.screen {
                            f.file_sel = i;
                            f.focus = NewFocus::Files;
                        }
                    }
                    None => {}
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let code = if m.kind == MouseEventKind::ScrollDown {
                    KeyCode::Down
                } else {
                    KeyCode::Up
                };
                match &self.screen {
                    Screen::Revealed(v) if !v.saving => {
                        for _ in 0..3 {
                            self.key(press(code));
                        }
                    }
                    Screen::Home { .. } => self.key(press(code)),
                    _ => {}
                }
            }
            _ => {}
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
        match (op, &mut self.screen) {
            (Op::Create, Screen::New(f)) => match create(f, client) {
                Ok(v) => self.screen = Screen::Created(v),
                Err(e) => self.error(e.to_string()),
            },
            // The link is checked against the trusted origin: no request is sent.
            (Op::OpenLink, Screen::Open(i)) => match client.recipient_link(i.text().trim()) {
                Ok(link) => {
                    self.screen = Screen::Reveal(Box::new(RevealView {
                        link,
                        pass: Input::new(false),
                    }))
                }
                Err(e) => self.error(e.to_string()),
            },
            (Op::Consume, Screen::Reveal(v)) => {
                let envelope = match client.consume(&v.link) {
                    Ok(e) => e,
                    Err(e) => return self.error(e.to_string()),
                };
                let result = {
                    let pass = v.link.passphrase_hint.then(|| v.pass.text());
                    format::decrypt(&envelope, &v.link.key, pass)
                };
                let Screen::Reveal(v) =
                    std::mem::replace(&mut self.screen, Screen::Home { selected: 0 })
                else {
                    unreachable!()
                };
                self.after_decrypt(result, v.link, envelope);
            }
            (Op::Unlock, Screen::Unlock(v)) => {
                match format::decrypt(&v.envelope, &v.link.key, Some(v.pass.text())) {
                    Ok(secret) => {
                        let id = v.link.id.clone();
                        self.reveal(id, secret);
                    }
                    Err(FormatError::DecryptFailed) => {
                        v.pass.clear();
                        self.error(
                            "Wrong passphrase. The secret is already deleted from the server; try again.",
                        );
                    }
                    Err(e) => {
                        self.screen = Screen::Home { selected: 0 };
                        self.error(CliError::from(e).to_string());
                    }
                }
            }
            (Op::Save, Screen::Revealed(v)) => {
                let typed = v.dir.text().trim().to_owned();
                let result = {
                    let entries = v.entries();
                    let saved = if typed.is_empty() {
                        save::save_dir_default(&v.id, &entries)
                    } else {
                        let dir = expand_home(&typed);
                        save::write_dir(&dir, &entries).map(|_| dir)
                    };
                    saved.map(|dir| (dir, entries.len()))
                };
                match result {
                    Ok((dir, n)) => {
                        let shown = crate::api::printable(&dir.display().to_string());
                        v.saving = false;
                        v.saved = Some(shown.clone());
                        self.note(format!("Saved {n} file(s) to {shown}."));
                    }
                    Err(e) => {
                        let id8 = v.id[..8].to_owned();
                        self.error(format!(
                            "Cannot save there: {}. The secret is still here: type another new directory, or leave it empty for ./sdrop-{id8}.",
                            e.kind()
                        ));
                    }
                }
            }
            (Op::LoadStatus, Screen::StatusForm(i)) => {
                let result = client
                    .owner_link(i.text().trim())
                    .and_then(|link| client.status(&link).map(|s| (link, s)));
                match result {
                    Ok((link, status)) => {
                        self.screen = Screen::Status(Box::new(StatusView {
                            link,
                            status,
                            confirm_revoke: false,
                        }));
                        self.note("Checked just now.");
                    }
                    Err(e) => self.error(e.to_string()),
                }
            }
            (Op::RefreshStatus, Screen::Status(v)) => match client.status(&v.link) {
                Ok(s) => {
                    v.status = s;
                    self.note("Checked just now.");
                }
                Err(e) => self.error(e.to_string()),
            },
            (Op::Revoke, Screen::Status(v)) => match client.revoke(&v.link) {
                Ok(Revoked::Done) => {
                    match client.status(&v.link) {
                        Ok(s) => v.status = s,
                        Err(_) => v.status.state = "revoked".into(),
                    }
                    self.note("Revoked: the link no longer works.");
                }
                Ok(Revoked::AlreadyRead(s)) => {
                    v.status = s;
                    self.error("Already read, cannot revoke.");
                }
                Err(e) => self.error(e.to_string()),
            },
            _ => {}
        }
    }

    /// After consume: show it, or ask for the passphrase keeping the envelope (retries are local).
    fn after_decrypt(
        &mut self,
        result: Result<Secret, FormatError>,
        link: RecipientLink,
        envelope: Zeroizing<Vec<u8>>,
    ) {
        match result {
            Ok(secret) => self.reveal(link.id.clone(), secret),
            Err(e @ (FormatError::NeedPassphrase | FormatError::DecryptFailed)) => {
                let wrong = e == FormatError::DecryptFailed;
                self.screen = Screen::Unlock(Box::new(UnlockView {
                    link,
                    envelope,
                    pass: Input::new(false),
                }));
                self.error(if wrong {
                    "Wrong passphrase. The secret is already deleted from the server; try again."
                } else {
                    "This secret is protected with a passphrase. It is already deleted from the server; leaving now destroys it."
                });
            }
            Err(e) => {
                self.screen = Screen::Home { selected: 0 };
                self.error(CliError::from(e).to_string());
            }
        }
    }

    pub fn reveal(&mut self, id: String, secret: Secret) {
        let has_files = !matches!(secret, Secret::Text(_));
        self.screen = Screen::Revealed(Box::new(RevealedView {
            id,
            secret,
            scroll: 0,
            max_scroll: std::cell::Cell::new(0),
            saving: false,
            dir: Input::new(false),
            saved: None,
        }));
        self.note(if has_files {
            "The secret is deleted from the server. Save the files (s) before leaving."
        } else {
            "The secret is deleted from the server. Closing removes it for good."
        });
    }

    pub fn render(&self, f: &mut Frame) {
        let mut hits: Hits = Vec::new();
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
            Screen::New(_) => {
                "Tab next · Shift+Tab back · Ctrl+S create · Ctrl+G generate password · Esc back · mouse: click"
            }
            Screen::Created(v) if v.show_owner => {
                "c copy link · y copy status link · o hide · n new · Esc home"
            }
            Screen::Created(_) => "c copy link · o show your status link · n new · Esc home",
            Screen::Open(_) => "paste the recipient link · Enter check · Esc back",
            Screen::Reveal(_) => "Enter reveal (destroys it on the server) · Esc back",
            Screen::Unlock(_) => "type the passphrase · Enter decrypt",
            Screen::Revealed(v) if v.saving => {
                "new directory (empty: ./sdrop-<id>) · Enter save · Esc cancel"
            }
            Screen::Revealed(_) => "↑↓ scroll · c copy text · s save · Esc leave",
            Screen::StatusForm(_) => "paste your status link · Enter check · Esc back",
            Screen::Status(_) => "r check status · x revoke · Esc home",
        };
        let buttons = self.buttons();
        let [body, bar] = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(if buttons.is_empty() { 0 } else { 2 }),
        ])
        .areas(body);
        match &self.screen {
            Screen::Home { selected } => render_home(f, body, *selected, &mut hits),
            Screen::New(form) => render_new(f, body, form, &mut hits),
            Screen::Created(v) => render_created(f, body, v),
            Screen::Open(i) => render_link_form(f, body, i, " Recipient link "),
            Screen::StatusForm(i) => render_link_form(f, body, i, " Your status link "),
            Screen::Reveal(v) => render_reveal(f, body, v),
            Screen::Unlock(v) => render_unlock(f, body, v),
            Screen::Revealed(v) => render_revealed(f, body, v),
            Screen::Status(v) => render_status(f, body, v),
        }
        // A blank line, then the buttons.
        let bar = Rect {
            y: bar.y + 1,
            height: 1,
            ..bar
        };
        render_buttons(f, bar, &buttons, &mut hits);
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
        *self.hits.borrow_mut() = hits;
    }

    /// The buttons under the current screen: (label, what a click does, primary).
    fn buttons(&self) -> Vec<(String, Hit, bool)> {
        let b = |l: &str, k: KeyEvent, primary: bool| (l.to_string(), Hit::Key(k), primary);
        match &self.screen {
            Screen::Home { .. } => vec![],
            Screen::New(f) => vec![
                (
                    if f.focus == NewFocus::Create {
                        "▶ Create one-time link  Ctrl+S".to_string()
                    } else {
                        "Create one-time link  Ctrl+S".to_string()
                    },
                    Hit::Key(ctrl('s')),
                    true,
                ),
                b("Generate password  Ctrl+G", ctrl('g'), false),
                b("Back  Esc", press(KeyCode::Esc), false),
            ],
            Screen::Created(v) => {
                let mut v2 = vec![
                    b("Copy link  c", press(KeyCode::Char('c')), true),
                    b(
                        if v.show_owner {
                            "Hide status link  o"
                        } else {
                            "Show my status link  o"
                        },
                        press(KeyCode::Char('o')),
                        false,
                    ),
                ];
                if v.show_owner {
                    v2.push(b("Copy status link  y", press(KeyCode::Char('y')), false));
                }
                v2.push(b("New secret  n", press(KeyCode::Char('n')), false));
                v2.push(b("Home  Esc", press(KeyCode::Esc), false));
                v2
            }
            Screen::Open(_) | Screen::StatusForm(_) => vec![
                b("Check link  Enter", press(KeyCode::Enter), true),
                b("Back  Esc", press(KeyCode::Esc), false),
            ],
            Screen::Reveal(_) => vec![
                b("Reveal secret  Enter", press(KeyCode::Enter), true),
                b("Back  Esc", press(KeyCode::Esc), false),
            ],
            Screen::Unlock(_) => vec![b("Decrypt  Enter", press(KeyCode::Enter), true)],
            Screen::Revealed(v) if v.saving => vec![
                b("Save  Enter", press(KeyCode::Enter), true),
                b("Cancel  Esc", press(KeyCode::Esc), false),
            ],
            Screen::Revealed(v) => {
                let mut v2 = Vec::new();
                if !v.text().is_empty() {
                    v2.push(b("Copy text  c", press(KeyCode::Char('c')), true));
                }
                v2.push(b(
                    if v.has_files() {
                        "Save files  s"
                    } else {
                        "Save to a file  s"
                    },
                    press(KeyCode::Char('s')),
                    v.text().is_empty(),
                ));
                v2.push(b("Leave  Esc", press(KeyCode::Esc), false));
                v2
            }
            Screen::Status(v) => {
                let mut v2 = vec![b("Check status  r", press(KeyCode::Char('r')), true)];
                if v.status.state == "stored" {
                    v2.push(b("Revoke  x", press(KeyCode::Char('x')), false));
                }
                v2.push(b("Home  Esc", press(KeyCode::Esc), false));
                v2
            }
        }
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

fn render_home(f: &mut Frame, area: Rect, selected: usize, hits: &mut Hits) {
    for i in 0..HOME_ITEMS.len() {
        let y = area.y + 1 + i as u16;
        if y + 1 < area.bottom() {
            hits.push((
                Rect {
                    x: area.x + 1,
                    y,
                    width: area.width.saturating_sub(2),
                    height: 1,
                },
                Hit::Home(i),
            ));
        }
    }
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
    // Only the visible window is handed to ratatui (slices of the text, no copies): offsets of any
    // size work, unlike Paragraph::scroll with its u16 offsets.
    // The cells actually skipped on the cursor's line (a wide grapheme at the edge goes whole).
    let mut skipped = dx;
    let visible: Vec<Line> = input
        .text()
        .split('\n')
        .enumerate()
        .skip(dy)
        .take(h.max(1))
        .map(|(n, l)| {
            let (rest, cut) = skip_cols(l, dx);
            if n == line {
                skipped = cut;
            }
            Line::raw(rest)
        })
        .collect();
    f.render_widget(
        Paragraph::new(visible).block(focused_block(title, focused)),
        area,
    );
    if focused && w > 0 && h > 0 {
        f.set_cursor_position(Position {
            x: area.x + 1 + col.saturating_sub(skipped) as u16,
            y: area.y + 1 + (line - dy) as u16,
        });
    }
}

/// Screen lines of `text` at `width` cells: each line cut into pieces at grapheme boundaries
/// (slices of the text, no copies).
fn wrapped(text: &str, width: usize) -> impl Iterator<Item = &str> {
    text.split('\n').flat_map(move |line| {
        let mut pieces = Vec::new();
        let (mut start, mut cells) = (0, 0);
        for (i, g) in unicode_segmentation::UnicodeSegmentation::grapheme_indices(line, true) {
            let gw = super::input::cells(g);
            if cells + gw > width && i > start {
                pieces.push(&line[start..i]);
                start = i;
                cells = 0;
            }
            cells += gw;
        }
        pieces.push(&line[start..]);
        pieces
    })
}

/// The part of a line after its first `cols` terminal cells, cut at grapheme boundaries (a wide
/// grapheme straddling the edge is skipped whole), and the cells actually skipped.
fn skip_cols(line: &str, cols: usize) -> (&str, usize) {
    let mut seen = 0;
    for (i, g) in unicode_segmentation::UnicodeSegmentation::grapheme_indices(line, true) {
        if seen >= cols {
            return (&line[i..], seen);
        }
        seen += super::input::cells(g);
    }
    ("", seen)
}

fn render_new(f: &mut Frame, area: Rect, form: &NewForm, hits: &mut Hits) {
    let files_h = (form.files.len() as u16).min(6) + 2;
    let [text, path, files, ttl, pass] = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(3),
        Constraint::Length(if form.files.is_empty() { 0 } else { files_h }),
        Constraint::Length(1),
        Constraint::Length(if form.use_pass { 4 } else { 1 }),
    ])
    .areas(area);
    hits.push((text, Hit::Focus(NewFocus::Text)));
    hits.push((path, Hit::Focus(NewFocus::Path)));
    for i in 0..form.files.len().min(6) {
        let y = files.y + 1 + i as u16;
        hits.push((
            Rect {
                x: files.x + 1,
                y,
                width: files.width.saturating_sub(2),
                height: 1,
            },
            Hit::File(i),
        ));
    }
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
    let prefix = " If nobody opens it, delete after: ";
    let mut spans = vec![Span::raw(prefix)];
    let mut x = ttl.x + prefix.len() as u16;
    for (i, (label, _)) in TTLS.iter().enumerate() {
        let style = if i == form.ttl {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(MUTED)
        };
        let item = format!(" {label} ");
        let w = item.len() as u16;
        hits.push((
            Rect {
                x,
                y: ttl.y,
                width: w,
                height: 1,
            },
            Hit::Ttl(i),
        ));
        x += w;
        spans.push(Span::styled(item, style));
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
    hits.push((toggle, Hit::PassToggle));
    if form.use_pass {
        hits.push((field, Hit::Focus(NewFocus::Pass)));
    }
    if form.use_pass {
        render_input(
            f,
            field,
            &form.pass,
            " Passphrase: send it through a different channel ",
            form.focus == NewFocus::Pass,
        );
    }
}

/// A link field; nothing is sent from it before the next screen.
fn render_link_form(f: &mut Frame, area: Rect, i: &Input, title: &str) {
    let [field, hint] = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(area);
    render_input(f, field, i, title, true);
    f.render_widget(
        Paragraph::new("Nothing is sent until you confirm.").style(Style::default().fg(MUTED)),
        hint,
    );
}

fn render_reveal(f: &mut Frame, area: Rect, v: &RevealView) {
    let [warn, pass] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(if v.link.passphrase_hint { 3 } else { 0 }),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(vec![
            Line::styled(
                "Someone shared a secret with you",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "It will be destroyed on the server as soon as you reveal it. Make sure you can copy or save it now.",
                Style::default().fg(Color::Yellow),
            ),
            Line::styled(
                "Not expecting it? Don't open it, tell the sender.",
                Style::default().fg(MUTED),
            ),
        ])
        .wrap(Wrap { trim: true }),
        warn,
    );
    if v.link.passphrase_hint {
        render_input(f, pass, &v.pass, " Passphrase ", true);
    }
}

fn render_unlock(f: &mut Frame, area: Rect, v: &UnlockView) {
    let [warn, pass, _] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(vec![
            Line::styled(
                "Enter the passphrase",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "The secret has been fetched and deleted from the server. Leaving destroys it.",
                Style::default().fg(Color::Yellow),
            ),
        ])
        .wrap(Wrap { trim: true }),
        warn,
    );
    render_input(f, pass, &v.pass, " Passphrase ", true);
}

fn render_revealed(f: &mut Frame, area: Rect, v: &RevealedView) {
    let files = v.files();
    let files_h = if files.is_empty() {
        0
    } else {
        (files.len() as u16).min(8) + 2
    };
    let [text, list, dir] = Layout::vertical([
        Constraint::Min(if v.text().is_empty() { 0 } else { 3 }),
        Constraint::Length(files_h),
        Constraint::Length(if v.saving { 3 } else { 0 }),
    ])
    .areas(area);
    if !v.text().is_empty() {
        // Wrapped at the field width by graphemes (exact for tokens and keys) and scrolled by
        // screen lines; the scroll stops at the last page.
        let (w, h) = (
            text.width.saturating_sub(2).max(1) as usize,
            text.height.saturating_sub(2).max(1) as usize,
        );
        let total = wrapped(v.text(), w).count();
        let max = total.saturating_sub(h);
        v.max_scroll.set(max);
        let lines: Vec<Line> = wrapped(v.text(), w)
            .skip(v.scroll.min(max))
            .take(h)
            .map(Line::raw)
            .collect();
        f.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Your secret "),
            ),
            text,
        );
    }
    if !files.is_empty() {
        let items: Vec<ListItem> = files
            .iter()
            .map(|(n, size)| {
                ListItem::new(format!(
                    "{}  {}",
                    crate::api::printable(n),
                    human_size(*size)
                ))
            })
            .collect();
        let title = match &v.saved {
            Some(dir) => format!(" Files: saved to {dir} "),
            None => " Files (s saves them into a new private directory) ".to_string(),
        };
        f.render_widget(
            List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
            list,
        );
    }
    if v.saving {
        render_input(f, dir, &v.dir, " Save into a new directory ", true);
    }
}

fn render_status(f: &mut Frame, area: Rect, v: &StatusView) {
    let s = &v.status;
    let state = match s.state.as_str() {
        "stored" => "Waiting to be read",
        "consumed" => "Read",
        "revoked" => "Revoked",
        other => other,
    };
    let row = |k: &'static str, val: String| {
        Line::from(vec![
            Span::styled(k, Style::default().fg(MUTED)),
            Span::raw(val),
        ])
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled("State             ", Style::default().fg(MUTED)),
            Span::styled(state, Style::default().add_modifier(Modifier::BOLD)),
        ]),
        row("Created           ", s.created.clone()),
        row("Deleted if unread ", s.expires.clone()),
    ];
    if let Some(at) = &s.consumed_at {
        let by = s
            .consumed_by
            .as_deref()
            .map(|b| format!(" by {b}"))
            .unwrap_or_default();
        lines.push(row("Read              ", format!("{at}{by}")));
    }
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Secret status "),
        ),
        area,
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

    type Scheduled = Arc<Mutex<Vec<([u8; 32], Duration)>>>;

    /// Clipboard in memory: what was copied and whether it is the system one.
    #[derive(Clone, Default)]
    pub struct MemClip {
        pub value: Arc<Mutex<Option<String>>>,
        /// Background removals asked for: (hash, delay).
        pub scheduled: Scheduled,
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
        fn schedule_clear(&mut self, hash: [u8; 32], delay: Duration) {
            self.scheduled.lock().unwrap().push((hash, delay));
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
        assert!(matches!(app.screen, Screen::StatusForm(_)));
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
        assert!(
            clip.scheduled.lock().unwrap().is_empty(),
            "links are not removed"
        );
        app.tick(t0 + CLEAR_AFTER * 2);
        assert_eq!(
            clip.value.lock().unwrap().as_deref(),
            Some("link"),
            "links stay"
        );
        // A secret text is removed after 60 s, even after leaving the screen; the removal is also
        // scheduled on its own thread, so a blocking request cannot delay it.
        app.copy("s3cret", "The secret", true);
        assert_eq!(
            *clip.scheduled.lock().unwrap(),
            [(<[u8; 32]>::from(Sha256::digest(b"s3cret")), CLEAR_AFTER)]
        );
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
        // Beyond u16 offsets: a 70 KB single line still shows its end.
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.text.clear();
        app.paste(&format!("{}TAIL-OF-70K", "y".repeat(70_000)));
        assert!(screen_text(&app).contains("TAIL-OF-70K"));
        // Emoji ZWJ sequences: the window and the cursor agree, the tail stays visible.
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.text.clear();
        app.paste(&format!(
            "{}TAIL-EMOJI",
            "👨\u{200d}👩\u{200d}👧\u{200d}👦".repeat(100)
        ));
        assert!(screen_text(&app).contains("TAIL-EMOJI"));
    }

    /// Click at the centre of the first recorded area for `hit` in the last frame.
    fn click(app: &mut App, want: Hit) {
        screen_text(app);
        let r = app
            .hits
            .borrow()
            .iter()
            .find(|(_, h)| *h == want)
            .map(|(r, _)| *r)
            .unwrap_or_else(|| panic!("{want:?} not on screen"));
        app.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: r.x + r.width / 2,
            row: r.y,
            modifiers: KeyModifiers::NONE,
        });
    }

    #[test]
    fn mouse_clicks_and_create_shortcuts() {
        let mut app = App::new(Box::new(MemClip::default()));
        click(&mut app, Hit::Home(0));
        assert!(matches!(app.screen, Screen::New(_)));
        app.paste("by mouse");
        click(&mut app, Hit::Ttl(2));
        click(&mut app, Hit::PassToggle);
        let Screen::New(f) = &app.screen else {
            unreachable!()
        };
        assert_eq!((f.ttl, f.use_pass), (2, true));
        click(&mut app, Hit::Focus(NewFocus::Pass));
        app.paste("pw");
        click(&mut app, Hit::Focus(NewFocus::Text));
        let Screen::New(f) = &app.screen else {
            unreachable!()
        };
        assert_eq!(f.focus, NewFocus::Text);
        // The Create button is drawn and clickable whatever the focus.
        assert!(screen_text(&app).contains("Create one-time link  Ctrl+S"));
        click(&mut app, Hit::Key(ctrl('s')));
        assert!(matches!(app.pending, Some(Op::Create)));
        // Keyboard: Ctrl+S and Shift+Enter from the text field; a plain Enter is a new line.
        for k in [
            ctrl('s'),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::SUPER),
        ] {
            app.pending = None;
            app.key(k);
            assert!(matches!(app.pending, Some(Op::Create)), "{k:?}");
        }
        app.pending = None;
        app.key(press(KeyCode::Enter));
        assert!(app.pending.is_none());
        let Screen::New(f) = &app.screen else {
            unreachable!()
        };
        assert_eq!(f.text.text(), "by mouse\n");
    }

    #[test]
    fn mouse_wheel_scrolls_revealed_text() {
        let mut app = App::new(Box::new(MemClip::default()));
        let text: String = (0..200).map(|i| format!("row {i}\n")).collect();
        app.reveal("0".repeat(64), Secret::Text(Zeroizing::new(text)));
        screen_text(&app);
        for _ in 0..10 {
            app.mouse(MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 5,
                row: 5,
                modifiers: KeyModifiers::NONE,
            });
        }
        let Screen::Revealed(v) = &app.screen else {
            unreachable!()
        };
        assert_eq!(v.scroll, 30);
        // The bar offers the actions as buttons.
        let s = screen_text(&app);
        assert!(s.contains("Copy text  c") && s.contains("Save to a file  s"));
    }

    #[test]
    fn long_revealed_line_wraps_and_scrolls_to_the_end() {
        let mut app = App::new(Box::new(MemClip::default()));
        let token = format!("{}END-OF-TOKEN", "t".repeat(5000));
        app.reveal("0".repeat(64), Secret::Text(Zeroizing::new(token)));
        assert!(!screen_text(&app).contains("END-OF-TOKEN"));
        // Keys use the page size known from the last frame; scrolling past the end stops there.
        for _ in 0..10 {
            screen_text(&app);
            app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
        assert!(screen_text(&app).contains("END-OF-TOKEN"));
        app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert!(
            screen_text(&app).contains("tttt"),
            "one page up from the end is still text"
        );
        // Over-scrolled state (e.g. the terminal grew): the first Up moves the view at once.
        if let Screen::Revealed(v) = &mut app.screen {
            v.scroll = 10_000;
        }
        let before = screen_text(&app);
        app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_ne!(screen_text(&app), before);
    }

    #[test]
    fn halfwidth_marks_wrap_without_losing_text() {
        let mut app = App::new(Box::new(MemClip::default()));
        app.reveal(
            "0".repeat(64),
            Secret::Text(Zeroizing::new(format!("{}END", "ｶﾞ".repeat(98)))),
        );
        let mut seen = String::new();
        for _ in 0..5 {
            seen.push_str(&screen_text(&app));
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        let shown = seen.matches("ｶﾞ").count();
        assert!(shown >= 98, "{shown} of 98 shown");
        assert!(seen.contains("END"));
    }

    #[test]
    fn cursor_after_a_wide_grapheme_at_the_scroll_edge() {
        let mut app = App::new(Box::new(MemClip::default()));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let Screen::New(f) = &mut app.screen else {
            unreachable!()
        };
        f.focus = NewFocus::Path;
        app.paste(&format!("{}AB", "界".repeat(50)));
        app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
        t.draw(|f| app.render(f)).unwrap();
        let pos = t.get_cursor_position().unwrap();
        let buf = t.backend().buffer().clone();
        assert_eq!(
            buf[(pos.x, pos.y)].symbol(),
            "A",
            "the cursor is on A, where typing inserts"
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
