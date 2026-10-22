//! TUI state machine (README, "Interactive mode"): keys, clicks and pastes become actions that
//! change the state; network and disk work is queued as an operation and run between frames
//! (`perform`), so tests drive the app without a terminal and with a local test server. Drawing is
//! in `view.rs`.

use super::clipboard::{Clip, Unavailable, Via};
use super::input::Input;
use super::theme::Role;
use super::widgets::Button;
use crate::api::{CliError, OwnerLink, RecipientLink};
use crate::format::{self, FormatError, Secret};
use crate::ops::{Client, Revoked, Status};
use crate::save;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const HOME_ITEMS: [&str; 4] = ["New secret", "Open a link", "Check status", "Quit"];
pub const TTLS: [(&str, u32); 3] = [("1 hour", 3600), ("24 hours", 86400), ("7 days", 604800)];
/// How long a copied secret text stays in the system clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(60);
/// Retry interval when the clipboard is unavailable at removal time.
pub const CLEAR_RETRY: Duration = Duration::from_secs(5);

/// Everything a key, a button or a click can do: both paths call the same code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    // Home
    Open(usize),
    // New secret
    AddFile,
    RemoveFile(usize),
    SelectFile(usize),
    GeneratePassphrase,
    TogglePassphrase,
    SetTtl(usize),
    Create,
    // Link ready
    CopyRecipient,
    ToggleOwner,
    CopyOwner,
    NewSecret,
    // Open a link, Check status
    CheckLink,
    // Reveal, Unlock
    Reveal,
    Decrypt,
    // Revealed
    CopyText,
    StartSave,
    Save,
    CancelSave,
    // Status
    RefreshStatus,
    AskRevoke,
    // Any screen
    Back,
    Choose(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFocus {
    Text,
    Path,
    Add,
    Files,
    Ttl,
    UsePass,
    Pass,
    Generate,
    Create,
    Back,
}

/// A file to send; its path and name are part of the secret, kept in wiped buffers.
pub struct PickedFile {
    pub path: Zeroizing<String>,
    pub name: Zeroizing<String>,
    pub size: u64,
}

pub struct NewForm {
    pub text: Input,
    pub path: Input,
    pub files: Vec<PickedFile>,
    pub file_sel: usize,
    /// First file row drawn (kept by the view so the selected file stays visible).
    pub file_top: Cell<usize>,
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
            file_top: Cell::new(0),
            ttl: 1,
            use_pass: false,
            pass: Input::new(false),
            focus: NewFocus::Text,
            generated: false,
        }
    }

    /// Tab order: fields and buttons as they appear; hidden ones are skipped.
    pub fn order(&self) -> Vec<NewFocus> {
        let mut v = vec![NewFocus::Text, NewFocus::Path, NewFocus::Add];
        if !self.files.is_empty() {
            v.push(NewFocus::Files);
        }
        v.extend([NewFocus::Ttl, NewFocus::UsePass]);
        if self.use_pass {
            v.extend([NewFocus::Pass, NewFocus::Generate]);
        }
        v.extend([NewFocus::Create, NewFocus::Back]);
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
    pub focus: usize,
}

/// A link field of Open a link / Check status; focus 0 is the field.
pub struct LinkForm {
    pub input: Input,
    pub focus: usize,
}

/// A link was checked (no request yet): reveal on confirmation.
pub struct RevealView {
    pub link: RecipientLink,
    pub pass: Input,
    pub focus: usize,
}

/// The envelope is fetched (the server has deleted it) and needs a passphrase: it is kept only
/// here, retries are local.
pub struct UnlockView {
    pub link: RecipientLink,
    pub envelope: Zeroizing<Vec<u8>>,
    pub pass: Input,
    pub focus: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealedFocus {
    Text,
    Files,
    Dir,
    Button(usize),
}

pub struct RevealedView {
    pub id: String,
    pub secret: Secret,
    pub scroll: usize,
    /// Last page start as of the last frame, so that keys stop scrolling at the end.
    pub max_scroll: Cell<usize>,
    pub file_top: usize,
    pub max_file_top: Cell<usize>,
    /// Typing the directory to save into.
    pub saving: bool,
    pub dir: Input,
    pub saved: Option<String>,
    pub focus: RevealedFocus,
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
    pub fn files(&self) -> Vec<(&str, usize)> {
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

    pub fn has_files(&self) -> bool {
        !matches!(self.secret, Secret::Text(_))
    }

    /// Focus order: the text and the file list (when there), the save field, the buttons.
    pub fn order(&self) -> Vec<RevealedFocus> {
        let mut v = Vec::new();
        if self.saving {
            v.push(RevealedFocus::Dir);
        } else {
            if !self.text().is_empty() {
                v.push(RevealedFocus::Text);
            }
            if self.has_files() {
                v.push(RevealedFocus::Files);
            }
        }
        v.extend((0..revealed_buttons(self).len()).map(RevealedFocus::Button));
        v
    }
}

pub struct StatusView {
    pub link: OwnerLink,
    pub status: Status,
    pub focus: usize,
}

pub enum Screen {
    Home { selected: usize },
    New(Box<NewForm>),
    Created(CreatedView),
    Open(LinkForm),
    Reveal(Box<RevealView>),
    Unlock(Box<UnlockView>),
    Revealed(Box<RevealedView>),
    StatusForm(LinkForm),
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

/// Where a confirmed leave goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Home,
    Quit,
}

/// A confirmation over the screen; the background takes no clicks meanwhile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogKind {
    /// Leaving the received files unsaved.
    LeaveUnsaved(Intent),
    /// Leaving the passphrase screen: the fetched envelope is dropped.
    Discard(Intent),
    Revoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dialog {
    pub kind: DialogKind,
    /// Starts on the safe choice (index 0).
    pub focus: usize,
}

impl Dialog {
    pub fn title(&self) -> &'static str {
        match self.kind {
            DialogKind::LeaveUnsaved(_) => "Leave without saving?",
            DialogKind::Discard(_) => "Discard the downloaded secret?",
            DialogKind::Revoke => "Revoke this secret?",
        }
    }

    pub fn lines(&self, files: usize) -> Vec<String> {
        match self.kind {
            DialogKind::LeaveUnsaved(_) => vec![
                format!(
                    "{files} received file{} not saved.",
                    if files == 1 { " is" } else { "s are" }
                ),
                "The server copy is already deleted.".into(),
            ],
            DialogKind::Discard(_) => vec![
                "The server copy is already deleted.".into(),
                "You cannot download it again.".into(),
            ],
            DialogKind::Revoke => vec!["The recipient link will stop working.".into()],
        }
    }

    /// The choices; the first one is safe.
    pub fn buttons(&self) -> Vec<Button<Action>> {
        let b = |l: &str, i: usize, role: Role| Button::new(l, "", Action::Choose(i), role);
        match self.kind {
            DialogKind::LeaveUnsaved(_) => vec![
                b("Stay", 0, Role::Primary),
                b("Save files", 1, Role::Secondary),
                b("Leave without saving", 2, Role::Danger),
            ],
            DialogKind::Discard(_) => vec![
                b("Keep trying", 0, Role::Primary),
                b("Discard", 1, Role::Danger),
            ],
            DialogKind::Revoke => {
                vec![b("Cancel", 0, Role::Primary), b("Revoke", 1, Role::Danger)]
            }
        }
    }
}

/// Work queued by an action and run between frames.
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

/// What a mouse click hits; recorded while drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// A button or a clickable line: the action (and the focus moves to it).
    Act(Action, Option<usize>),
    Home(usize),
    Focus(NewFocus),
    /// The text field of a link, passphrase or directory screen.
    Field,
    RevealedText,
    RevealedFiles,
}

pub type Hits = Vec<(Rect, Hit)>;

/// A copied secret text to remove from the clipboard later: when, and a hash to recognise it.
struct PendingClear {
    at: Instant,
    hash: [u8; 32],
}

pub struct App {
    pub screen: Screen,
    pub dialog: Option<Dialog>,
    pub quit: bool,
    /// Error (true) or note shown above the footer until the next key.
    pub message: Option<(bool, String)>,
    pub pending: Option<Op>,
    /// The service limit, once known (shown next to the size of the secret).
    pub limit: Option<usize>,
    /// Ask the service for its limit (the event loop does it outside the state machine).
    pub wants_limit: bool,
    /// Click areas of the last frame.
    pub hits: RefCell<Hits>,
    /// The last frame was smaller than 80×24: only its message was drawn, input waits.
    pub too_small: Cell<bool>,
    clip: Box<dyn Clip>,
    clip_warned: bool,
    clear: Option<PendingClear>,
    now: Instant,
}

const CLIP_WARNING: &str =
    "Clipboard managers may keep a history of what you copy. Press again to copy.";

fn press(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

/// Buttons of a screen (other than New secret, Home and Revealed, which have their own).
pub fn link_form_buttons() -> Vec<Button<Action>> {
    vec![
        Button::new("Check link", "Enter", Action::CheckLink, Role::Primary),
        Button::new("Back", "Esc", Action::Back, Role::Secondary),
    ]
}

pub fn created_buttons(v: &CreatedView) -> Vec<Button<Action>> {
    let mut b = vec![
        Button::new(
            "Copy recipient link",
            "c",
            Action::CopyRecipient,
            Role::Primary,
        ),
        // Drawn as the `[+]` line that shows the private sender link.
        Button::new(
            "Only for you: track or revoke",
            "o",
            Action::ToggleOwner,
            Role::Secondary,
        ),
    ];
    if v.show_owner {
        b.push(Button::new(
            "Copy private sender link",
            "y",
            Action::CopyOwner,
            Role::Secondary,
        ));
    }
    b.push(Button::new(
        "New secret",
        "n",
        Action::NewSecret,
        Role::Secondary,
    ));
    b.push(Button::new("Home", "Esc", Action::Back, Role::Secondary));
    b
}

pub fn reveal_buttons() -> Vec<Button<Action>> {
    vec![
        Button::new("Reveal secret", "Enter", Action::Reveal, Role::Primary),
        Button::new("Back", "Esc", Action::Back, Role::Secondary),
    ]
}

pub fn unlock_buttons() -> Vec<Button<Action>> {
    vec![
        Button::new("Decrypt", "Enter", Action::Decrypt, Role::Primary),
        Button::new("Discard", "Esc", Action::Back, Role::Danger),
    ]
}

pub fn revealed_buttons(v: &RevealedView) -> Vec<Button<Action>> {
    if v.saving {
        return vec![
            Button::new("Save", "Enter", Action::Save, Role::Primary),
            Button::new("Cancel", "Esc", Action::CancelSave, Role::Secondary),
        ];
    }
    let mut b = Vec::new();
    if !v.text().is_empty() {
        b.push(Button::new(
            "Copy text",
            "c",
            Action::CopyText,
            Role::Primary,
        ));
    }
    b.push(Button::new(
        if v.has_files() {
            "Save files"
        } else {
            "Save to a file"
        },
        "s",
        Action::StartSave,
        if v.text().is_empty() {
            Role::Primary
        } else {
            Role::Secondary
        },
    ));
    b.push(Button::new("Leave", "Esc", Action::Back, Role::Secondary));
    b
}

pub fn status_buttons(v: &StatusView) -> Vec<Button<Action>> {
    vec![
        Button::new("Check status", "r", Action::RefreshStatus, Role::Primary),
        Button::new("Revoke", "x", Action::AskRevoke, Role::Danger)
            .enabled(v.status.state == "stored"),
        Button::new("Home", "Esc", Action::Back, Role::Secondary),
    ]
}

/// Focus list of the screens with a field and buttons: 0 is the field (when there).
fn field_and_buttons(has_field: bool, buttons: usize) -> usize {
    usize::from(has_field) + buttons
}

impl App {
    pub fn new(clip: Box<dyn Clip>) -> App {
        App {
            screen: Screen::Home { selected: 0 },
            dialog: None,
            quit: false,
            message: None,
            pending: None,
            limit: None,
            wants_limit: false,
            hits: RefCell::new(Vec::new()),
            too_small: Cell::new(false),
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
                    self.note(format!(
                        "{what} copied; it is removed from the clipboard in 60 seconds."
                    ));
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

    fn go(&mut self, screen: Screen) {
        let new = matches!(screen, Screen::New(_));
        self.screen = screen;
        self.dialog = None;
        if new && self.limit.is_none() {
            self.wants_limit = true;
        }
    }

    /// Leave the screen (Home) or the app; a screen that holds a fetched secret asks first.
    fn leave(&mut self, intent: Intent) {
        let kind = match &self.screen {
            Screen::Unlock(_) => DialogKind::Discard(intent),
            s if s.holds_secret() => DialogKind::LeaveUnsaved(intent),
            _ => return self.finish(intent),
        };
        self.dialog = Some(Dialog { kind, focus: 0 });
    }

    fn finish(&mut self, intent: Intent) {
        match intent {
            Intent::Home => self.go(Screen::Home { selected: 0 }),
            Intent::Quit => self.quit = true,
        }
    }

    pub fn render(&self, f: &mut ratatui::Frame) {
        super::view::render(self, f);
    }

    pub fn key(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if self.too_small.get() {
            // Nothing on the screen to act on; only quitting (asks first if a secret is held).
            if ctrl && k.code == KeyCode::Char('c') && self.dialog.is_none() {
                self.leave(Intent::Quit);
            }
            return;
        }
        self.message = None;
        if self.dialog.is_some() {
            return self.key_dialog(k);
        }
        if ctrl && k.code == KeyCode::Char('c') {
            return self.leave(Intent::Quit);
        }
        match &self.screen {
            Screen::Home { .. } => self.key_home(k),
            Screen::New(_) => self.key_new(k),
            Screen::Revealed(_) => self.key_revealed(k),
            _ => self.key_simple(k),
        }
    }

    fn key_dialog(&mut self, k: KeyEvent) {
        let Some(d) = &mut self.dialog else {
            return;
        };
        let n = d.buttons().len();
        match k.code {
            KeyCode::Tab | KeyCode::Right | KeyCode::Down => d.focus = (d.focus + 1) % n,
            KeyCode::BackTab | KeyCode::Left | KeyCode::Up => d.focus = (d.focus + n - 1) % n,
            KeyCode::Enter | KeyCode::Char(' ') => {
                let i = d.focus;
                self.act(Action::Choose(i));
            }
            // Esc (and Ctrl+C) cancel: nothing is left or revoked.
            KeyCode::Esc => self.dialog = None,
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => self.dialog = None,
            _ => {}
        }
    }

    fn key_home(&mut self, k: KeyEvent) {
        let Screen::Home { selected } = &mut self.screen else {
            return;
        };
        match k.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                *selected = (*selected + HOME_ITEMS.len() - 1) % HOME_ITEMS.len();
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                *selected = (*selected + 1) % HOME_ITEMS.len();
            }
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Enter => {
                let i = *selected;
                self.act(Action::Open(i));
            }
            _ => {}
        }
    }

    fn key_new(&mut self, k: KeyEvent) {
        let Screen::New(f) = &mut self.screen else {
            return;
        };
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Esc => return self.act(Action::Back),
            KeyCode::Tab => return f.step(false),
            KeyCode::BackTab => return f.step(true),
            // Create from any field: Ctrl+S everywhere; Shift/Cmd/Ctrl+Enter where the terminal
            // reports the modifier (keyboard enhancement).
            KeyCode::Char('s') if ctrl => return self.act(Action::Create),
            KeyCode::Enter
                if k.modifiers.intersects(
                    KeyModifiers::SHIFT
                        | KeyModifiers::SUPER
                        | KeyModifiers::CONTROL
                        | KeyModifiers::ALT
                        | KeyModifiers::META,
                ) =>
            {
                return self.act(Action::Create);
            }
            KeyCode::Char('g') if ctrl => return self.act(Action::GeneratePassphrase),
            _ => {}
        }
        let activate = matches!(k.code, KeyCode::Enter | KeyCode::Char(' '));
        match f.focus {
            NewFocus::Text => {
                edit(&mut f.text, k);
            }
            NewFocus::Path if k.code == KeyCode::Enter => self.act(Action::AddFile),
            NewFocus::Path => {
                edit(&mut f.path, k);
            }
            NewFocus::Files => match k.code {
                KeyCode::Up => f.file_sel = f.file_sel.saturating_sub(1),
                KeyCode::Down => f.file_sel = (f.file_sel + 1).min(f.files.len().saturating_sub(1)),
                KeyCode::Delete | KeyCode::Backspace => {
                    let i = f.file_sel;
                    self.act(Action::RemoveFile(i));
                }
                _ => {}
            },
            NewFocus::Ttl => match k.code {
                KeyCode::Left => f.ttl = f.ttl.saturating_sub(1),
                KeyCode::Right => f.ttl = (f.ttl + 1).min(TTLS.len() - 1),
                _ => {}
            },
            NewFocus::UsePass if activate => self.act(Action::TogglePassphrase),
            NewFocus::Pass => {
                if edit(&mut f.pass, k) {
                    f.generated = false;
                }
            }
            NewFocus::Add if activate => self.act(Action::AddFile),
            NewFocus::Generate if activate => self.act(Action::GeneratePassphrase),
            NewFocus::Create if activate => self.act(Action::Create),
            NewFocus::Back if activate => self.act(Action::Back),
            _ => {}
        }
    }

    /// Screens made of an optional field and a row of buttons: Link ready, Open a link, Check
    /// status, Reveal, Unlock, Status.
    fn key_simple(&mut self, k: KeyEvent) {
        let (has_field, buttons) = self.simple_parts();
        let n = field_and_buttons(has_field, buttons.len());
        let focus = self.simple_focus();
        let on_field = has_field && focus == 0;
        match k.code {
            KeyCode::Tab => return self.set_simple_focus((focus + 1) % n),
            KeyCode::BackTab => return self.set_simple_focus((focus + n - 1) % n),
            KeyCode::Esc => return self.act(Action::Back),
            KeyCode::Enter | KeyCode::Char(' ') if !on_field || k.code == KeyCode::Enter => {
                let action = if on_field {
                    // Enter in the field: the screen's main action.
                    buttons[0].action
                } else {
                    match buttons.get(focus - usize::from(has_field)) {
                        Some(b) if b.enabled => b.action,
                        _ => return,
                    }
                };
                return self.act(action);
            }
            _ => {}
        }
        if on_field {
            if let Some(i) = self.simple_field() {
                edit(i, k);
            }
            return;
        }
        // Shortcut letters of the buttons (shown in their parentheses).
        if let KeyCode::Char(c) = k.code
            && let Some(b) = buttons
                .iter()
                .find(|b| b.key.len() == 1 && b.key.starts_with(c) && b.enabled)
        {
            let action = b.action;
            self.act(action);
        }
    }

    fn simple_parts(&self) -> (bool, Vec<Button<Action>>) {
        match &self.screen {
            Screen::Created(v) => (false, created_buttons(v)),
            Screen::Open(_) | Screen::StatusForm(_) => (true, link_form_buttons()),
            Screen::Reveal(v) => (v.link.passphrase_hint, reveal_buttons()),
            Screen::Unlock(_) => (true, unlock_buttons()),
            Screen::Status(v) => (false, status_buttons(v)),
            _ => (false, Vec::new()),
        }
    }

    pub fn simple_focus(&self) -> usize {
        match &self.screen {
            Screen::Created(v) => v.focus,
            Screen::Open(f) | Screen::StatusForm(f) => f.focus,
            Screen::Reveal(v) => v.focus,
            Screen::Unlock(v) => v.focus,
            Screen::Status(v) => v.focus,
            _ => 0,
        }
    }

    fn set_simple_focus(&mut self, to: usize) {
        match &mut self.screen {
            Screen::Created(v) => v.focus = to,
            Screen::Open(f) | Screen::StatusForm(f) => f.focus = to,
            Screen::Reveal(v) => v.focus = to,
            Screen::Unlock(v) => v.focus = to,
            Screen::Status(v) => v.focus = to,
            _ => {}
        }
    }

    fn simple_field(&mut self) -> Option<&mut Input> {
        match &mut self.screen {
            Screen::Open(f) | Screen::StatusForm(f) => Some(&mut f.input),
            Screen::Reveal(v) if v.link.passphrase_hint => Some(&mut v.pass),
            Screen::Unlock(v) => Some(&mut v.pass),
            _ => None,
        }
    }

    fn key_revealed(&mut self, k: KeyEvent) {
        let Screen::Revealed(v) = &mut self.screen else {
            return;
        };
        let order = v.order();
        let at = order.iter().position(|f| *f == v.focus).unwrap_or(0);
        let buttons = revealed_buttons(v);
        match k.code {
            KeyCode::Tab => {
                v.focus = order[(at + 1) % order.len()];
                return;
            }
            KeyCode::BackTab => {
                v.focus = order[(at + order.len() - 1) % order.len()];
                return;
            }
            KeyCode::Esc => {
                let a = if v.saving {
                    Action::CancelSave
                } else {
                    Action::Back
                };
                return self.act(a);
            }
            _ => {}
        }
        // The terminal may have grown since the scroll was set: clamp the state, not only the view.
        v.scroll = v.scroll.min(v.max_scroll.get());
        v.file_top = v.file_top.min(v.max_file_top.get());
        match (v.focus, k.code) {
            (RevealedFocus::Dir, KeyCode::Enter) => self.act(Action::Save),
            (RevealedFocus::Dir, _) => {
                edit(&mut v.dir, k);
            }
            (RevealedFocus::Button(i), KeyCode::Enter | KeyCode::Char(' ')) => {
                if let Some(b) = buttons.get(i) {
                    let action = b.action;
                    self.act(action);
                }
            }
            (RevealedFocus::Files, KeyCode::Up) => v.file_top = v.file_top.saturating_sub(1),
            (RevealedFocus::Files, KeyCode::Down) => {
                v.file_top = (v.file_top + 1).min(v.max_file_top.get())
            }
            (_, KeyCode::Up) => v.scroll = v.scroll.saturating_sub(1),
            (_, KeyCode::Down) => v.scroll = (v.scroll + 1).min(v.max_scroll.get()),
            (_, KeyCode::PageUp) => v.scroll = v.scroll.saturating_sub(10),
            (_, KeyCode::PageDown) => v.scroll = (v.scroll + 10).min(v.max_scroll.get()),
            (_, KeyCode::Char(c)) => {
                if let Some(b) = buttons
                    .iter()
                    .find(|b| b.key.len() == 1 && b.key.starts_with(c))
                {
                    let action = b.action;
                    self.act(action);
                }
            }
            _ => {}
        }
    }

    pub fn paste(&mut self, text: &str) {
        if self.dialog.is_some() || self.too_small.get() {
            return;
        }
        match &mut self.screen {
            Screen::New(f) => match f.focus {
                NewFocus::Text => f.text.insert(text),
                NewFocus::Path => f.path.insert(text),
                NewFocus::Pass => {
                    f.pass.insert(text);
                    f.generated = false;
                }
                _ => {}
            },
            Screen::Open(f) | Screen::StatusForm(f) if f.focus == 0 => f.input.insert(text.trim()),
            Screen::Reveal(v) if v.link.passphrase_hint && v.focus == 0 => v.pass.insert(text),
            Screen::Unlock(v) if v.focus == 0 => v.pass.insert(text),
            Screen::Revealed(v) if v.focus == RevealedFocus::Dir => v.dir.insert(text.trim()),
            _ => {}
        }
    }

    /// Run an action: keys, buttons and clicks all end here.
    pub fn act(&mut self, a: Action) {
        if let Action::Choose(i) = a {
            return self.choose(i);
        }
        match &mut self.screen {
            Screen::Home { .. } => {
                if let Action::Open(i) = a {
                    match i {
                        0 => self.go(Screen::New(Box::new(NewForm::new()))),
                        1 => self.go(Screen::Open(LinkForm {
                            input: Input::new(false),
                            focus: 0,
                        })),
                        2 => self.go(Screen::StatusForm(LinkForm {
                            input: Input::new(false),
                            focus: 0,
                        })),
                        _ => self.quit = true,
                    }
                }
            }
            Screen::New(f) => match a {
                Action::AddFile => {
                    if let Err(e) = add_file(f) {
                        self.error(e);
                    }
                }
                Action::RemoveFile(i) if i < f.files.len() => {
                    f.files.remove(i);
                    f.file_sel = f.file_sel.min(f.files.len().saturating_sub(1));
                    if f.files.is_empty() && f.focus == NewFocus::Files {
                        f.focus = NewFocus::Path;
                    }
                }
                Action::SelectFile(i) if i < f.files.len() => {
                    f.file_sel = i;
                    f.focus = NewFocus::Files;
                }
                Action::SetTtl(i) if i < TTLS.len() => {
                    f.ttl = i;
                    f.focus = NewFocus::Ttl;
                }
                Action::TogglePassphrase => {
                    f.use_pass = !f.use_pass;
                    f.focus = NewFocus::UsePass;
                    if !f.use_pass {
                        f.pass.clear();
                        f.generated = false;
                    }
                }
                // A random passphrase, when the passphrase is on (the secret itself is the user's).
                Action::GeneratePassphrase => {
                    if f.use_pass {
                        f.pass.set(&crate::password::generate());
                        f.generated = true;
                        self.note("Send the passphrase through a separate channel.");
                    } else {
                        self.error("Turn on the passphrase first (Space).");
                    }
                }
                Action::Create => {
                    if f.text.text().is_empty() && f.files.is_empty() {
                        self.error("Enter a secret or add a file.");
                    } else if f.use_pass && f.pass.text().is_empty() {
                        self.error("Enter a passphrase or turn it off.");
                    } else {
                        self.pending = Some(Op::Create);
                        self.note("Encrypting and creating…");
                    }
                }
                Action::Back => self.go(Screen::Home { selected: 0 }),
                _ => {}
            },
            Screen::Created(v) => match a {
                Action::CopyRecipient => {
                    let link = v.recipient.clone();
                    self.copy(&link, "Recipient link", false);
                }
                // The buttons change: the focus stays on the same action, else on the toggle.
                Action::ToggleOwner => {
                    let before = created_buttons(v).get(v.focus).map(|b| b.action);
                    v.show_owner = !v.show_owner;
                    let after = created_buttons(v);
                    let at = |a| after.iter().position(|b| b.action == a);
                    v.focus = before
                        .and_then(at)
                        .or_else(|| at(Action::ToggleOwner))
                        .unwrap_or(0);
                }
                Action::CopyOwner if v.show_owner => {
                    let link = v.owner.clone();
                    self.copy(&link, "Private sender link", false);
                }
                Action::NewSecret => self.go(Screen::New(Box::new(NewForm::new()))),
                Action::Back => self.go(Screen::Home { selected: 0 }),
                _ => {}
            },
            Screen::Open(f) | Screen::StatusForm(f) => match a {
                Action::CheckLink if f.input.text().trim().is_empty() => {
                    self.error("Paste the link first.");
                }
                Action::CheckLink => {
                    let open = matches!(self.screen, Screen::Open(_));
                    self.pending = Some(if open { Op::OpenLink } else { Op::LoadStatus });
                }
                Action::Back => self.go(Screen::Home { selected: 0 }),
                _ => {}
            },
            Screen::Reveal(v) => match a {
                Action::Reveal if v.link.passphrase_hint && v.pass.text().is_empty() => {
                    v.focus = 0;
                    self.error("Type the passphrase first.");
                }
                Action::Reveal => {
                    self.pending = Some(Op::Consume);
                    self.note("Fetching and decrypting…");
                }
                Action::Back => self.go(Screen::Home { selected: 0 }),
                _ => {}
            },
            Screen::Unlock(v) => match a {
                Action::Decrypt if v.pass.text().is_empty() => {
                    v.focus = 0;
                    self.error("Type the passphrase. The secret is kept only in memory now.");
                }
                Action::Decrypt => {
                    self.pending = Some(Op::Unlock);
                    self.note("Decrypting…");
                }
                Action::Back => self.leave(Intent::Home),
                _ => {}
            },
            Screen::Revealed(v) => match a {
                Action::CopyText if !v.text().is_empty() => {
                    let text = Zeroizing::new(v.text().to_owned());
                    self.copy(&text, "The secret", true);
                }
                Action::StartSave => {
                    v.saving = true;
                    v.dir.clear();
                    v.focus = RevealedFocus::Dir;
                }
                Action::Save => {
                    self.pending = Some(Op::Save);
                    self.note("Saving…");
                }
                Action::CancelSave => {
                    v.saving = false;
                    v.focus = RevealedFocus::Button(0);
                }
                Action::Back => self.leave(Intent::Home),
                _ => {}
            },
            Screen::Status(v) => match a {
                Action::RefreshStatus => self.pending = Some(Op::RefreshStatus),
                Action::AskRevoke if v.status.state == "stored" => {
                    self.dialog = Some(Dialog {
                        kind: DialogKind::Revoke,
                        focus: 0,
                    });
                }
                Action::Back => self.go(Screen::Home { selected: 0 }),
                _ => {}
            },
        }
    }

    /// A dialog choice; index 0 is always the safe one (nothing changes).
    fn choose(&mut self, i: usize) {
        let Some(d) = self.dialog.take() else {
            return;
        };
        match (d.kind, i) {
            (DialogKind::LeaveUnsaved(_), 1) => self.act(Action::StartSave),
            (DialogKind::LeaveUnsaved(intent), 2) | (DialogKind::Discard(intent), 1) => {
                self.finish(intent)
            }
            (DialogKind::Revoke, 1) => self.pending = Some(Op::Revoke),
            _ => {}
        }
    }

    /// A mouse event: a click runs the action of what was hit; the wheel scrolls. While a dialog is
    /// open only its buttons take clicks.
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
                let Some(hit) = hit else {
                    return;
                };
                self.message = None;
                if self.dialog.is_some() {
                    if let Hit::Act(a @ Action::Choose(_), _) = hit {
                        self.act(a);
                    }
                    return;
                }
                match hit {
                    Hit::Act(a, focus) => {
                        if let Some(i) = focus {
                            self.focus_button(i);
                        }
                        self.act(a);
                    }
                    Hit::Home(i) => {
                        if let Screen::Home { selected } = &mut self.screen {
                            *selected = i;
                        }
                        self.act(Action::Open(i));
                    }
                    Hit::Focus(to) => {
                        if let Screen::New(f) = &mut self.screen {
                            f.focus = to;
                        }
                    }
                    Hit::Field => match &mut self.screen {
                        Screen::Revealed(v) => v.focus = RevealedFocus::Dir,
                        _ => self.set_simple_focus(0),
                    },
                    // Only what Tab can reach now: while saving, the field and its buttons.
                    Hit::RevealedText | Hit::RevealedFiles => {
                        if let Screen::Revealed(v) = &mut self.screen {
                            let to = if hit == Hit::RevealedText {
                                RevealedFocus::Text
                            } else {
                                RevealedFocus::Files
                            };
                            if v.order().contains(&to) {
                                v.focus = to;
                            }
                        }
                    }
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                if self.dialog.is_some() {
                    return;
                }
                let code = if m.kind == MouseEventKind::ScrollDown {
                    KeyCode::Down
                } else {
                    KeyCode::Up
                };
                match &mut self.screen {
                    Screen::Revealed(v) if !v.saving => {
                        // The wheel scrolls the list it is over, else the text.
                        let over_files = self.hits.borrow().iter().any(|(r, h)| {
                            *h == Hit::RevealedFiles
                                && r.contains(ratatui::layout::Position {
                                    x: m.column,
                                    y: m.row,
                                })
                        });
                        let focus = v.focus;
                        v.focus = if over_files {
                            RevealedFocus::Files
                        } else {
                            RevealedFocus::Text
                        };
                        for _ in 0..3 {
                            self.key(press(code));
                        }
                        if let Screen::Revealed(v) = &mut self.screen {
                            v.focus = focus;
                        }
                    }
                    Screen::New(f) if !f.files.is_empty() => {
                        f.file_sel = if code == KeyCode::Down {
                            (f.file_sel + 1).min(f.files.len() - 1)
                        } else {
                            f.file_sel.saturating_sub(1)
                        };
                    }
                    Screen::Home { .. } => self.key(press(code)),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Move the focus to the `i`-th focusable item of the screen (a clicked button).
    fn focus_button(&mut self, i: usize) {
        match &mut self.screen {
            Screen::New(f) => {
                if let Some(to) = f.order().get(i) {
                    f.focus = *to;
                }
            }
            Screen::Revealed(v) => {
                if let Some(to) = v.order().get(i) {
                    v.focus = *to;
                }
            }
            _ => self.set_simple_focus(i),
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
                Ok((v, limit)) => {
                    self.limit = Some(limit);
                    self.go(Screen::Created(v));
                }
                Err(e) => self.error(e.to_string()),
            },
            // The link is checked against the trusted origin: no request is sent.
            (Op::OpenLink, Screen::Open(f)) => match client.recipient_link(f.input.text().trim()) {
                // The focus starts on the passphrase field if there is one, else on Reveal.
                Ok(link) => self.go(Screen::Reveal(Box::new(RevealView {
                    link,
                    pass: Input::new(false),
                    focus: 0,
                }))),
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
                        v.focus = 0;
                        self.error(
                            "Wrong passphrase. Retry locally; the server copy is already deleted.",
                        );
                    }
                    Err(e) => {
                        self.go(Screen::Home { selected: 0 });
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
                        let dir = PathBuf::from(expand_home(&typed).as_str());
                        save::write_dir(&dir, &entries).map(|_| dir)
                    };
                    saved.map(|dir| (dir, entries.len()))
                };
                match result {
                    Ok((dir, n)) => {
                        let shown = crate::api::printable(&dir.display().to_string());
                        v.saving = false;
                        v.saved = Some(shown.clone());
                        v.focus = RevealedFocus::Button(0);
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
            (Op::LoadStatus, Screen::StatusForm(f)) => {
                let result = client
                    .owner_link(f.input.text().trim())
                    .and_then(|link| client.status(&link).map(|s| (link, s)));
                match result {
                    Ok((link, status)) => {
                        self.go(Screen::Status(Box::new(StatusView {
                            link,
                            status,
                            focus: 0,
                        })));
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
                    v.focus = 0;
                    self.note("Revoked: the recipient link no longer works.");
                }
                Ok(Revoked::AlreadyRead(s)) => {
                    v.status = s;
                    self.error("Already opened, cannot revoke.");
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
                self.go(Screen::Unlock(Box::new(UnlockView {
                    link,
                    envelope,
                    pass: Input::new(false),
                    focus: 0,
                })));
                self.error(if wrong {
                    "Wrong passphrase. Retry locally; the server copy is already deleted."
                } else {
                    "This secret has a passphrase. The server copy is already deleted; leaving now destroys it."
                });
            }
            Err(e) => {
                self.go(Screen::Home { selected: 0 });
                self.error(CliError::from(e).to_string());
            }
        }
    }

    pub fn reveal(&mut self, id: String, secret: Secret) {
        let has_files = !matches!(secret, Secret::Text(_));
        let mut v = RevealedView {
            id,
            secret,
            scroll: 0,
            max_scroll: Cell::new(0),
            file_top: 0,
            max_file_top: Cell::new(0),
            saving: false,
            dir: Input::new(false),
            saved: None,
            focus: RevealedFocus::Button(0),
        };
        v.focus = *v.order().first().unwrap_or(&RevealedFocus::Button(0));
        self.go(Screen::Revealed(Box::new(v)));
        self.note(if has_files {
            "Deleted from the server. Available in this session: save the files (s)."
        } else {
            "Deleted from the server. Available in this session."
        });
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
        return Err("Type the path of a file, then Add.".into());
    }
    if f.files.len() >= format::MAX_FILES {
        return Err(format!("Too many files: at most {}.", format::MAX_FILES));
    }
    let path = expand_home(raw);
    let meta = std::fs::metadata(path.as_str()).map_err(|_| "No such file.".to_string())?;
    if !meta.is_file() {
        return Err("Not a regular file.".into());
    }
    if meta.len() == 0 {
        return Err("The file is empty.".into());
    }
    // The path is UTF-8 (typed in the field): the name is borrowed from it, not copied.
    let name = std::path::Path::new(path.as_str())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    f.files.push(PickedFile {
        name: format::sanitize_file_name(name),
        size: meta.len(),
        path,
    });
    f.file_sel = f.files.len() - 1;
    f.path.clear();
    Ok(())
}

/// `~/` expanded to the home directory, in a wiped buffer reserved up front.
fn expand_home(p: &str) -> Zeroizing<String> {
    let home = std::env::var("HOME").ok();
    let (home, rest) = match (p.strip_prefix("~/"), home.as_deref()) {
        (Some(rest), Some(home)) => (home.trim_end_matches('/'), rest),
        _ => ("", p),
    };
    let mut out = Zeroizing::new(String::with_capacity(home.len() + 1 + rest.len()));
    if !home.is_empty() {
        out.push_str(home);
        out.push('/');
    }
    out.push_str(rest);
    out
}

/// Read the files, compose the one record (FORMAT.md 4), encrypt and create; also the limit the
/// service reported on the way.
fn create(f: &mut NewForm, client: &mut Client) -> Result<(CreatedView, usize), CliError> {
    let files = f
        .files
        .iter()
        .map(|p| crate::commands::read_file_secret(std::path::Path::new(p.path.as_str())))
        .collect::<Result<Vec<_>, _>>()?;
    let content = format::compose(
        f.text.text(),
        files.iter().map(|(n, d)| (n.as_str(), &d[..])).collect(),
    );
    format::encode_plaintext(&content, format::MAX_BUCKET)?;
    let passphrase = f.use_pass.then(|| f.pass.text());
    let limit = client.limit()?;
    let created = client.create(&content, passphrase, TTLS[f.ttl].1)?;
    Ok((
        CreatedView {
            recipient: created.recipient,
            owner: created.owner,
            expires: created.expires,
            passphrase: passphrase.is_some(),
            show_owner: false,
            focus: 0,
        },
        limit,
    ))
}

#[cfg(test)]
#[path = "app_tests.rs"]
pub mod tests;
