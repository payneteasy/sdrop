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

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// The screen at `w`×`h`, row by row.
pub fn screen_at(app: &App, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| app.render(f)).unwrap();
    let buf = t.backend().buffer().clone();
    buf.content
        .chunks(w as usize)
        .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn screen_text(app: &App) -> String {
    screen_at(app, 100, 30)
}

fn new_form(app: &mut App) -> &mut NewForm {
    match &mut app.screen {
        Screen::New(f) => f,
        _ => panic!("not on New secret"),
    }
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
    click_at(app, r.x + r.width / 2, r.y);
}

fn click_at(app: &mut App, column: u16, row: u16) {
    app.mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::NONE,
    });
}

/// Click the button whose action is `a`.
fn press_button(app: &mut App, a: Action) {
    screen_text(app);
    let hit = app
        .hits
        .borrow()
        .iter()
        .find(|(_, h)| matches!(h, Hit::Act(x, _) if *x == a))
        .map(|(_, h)| *h)
        .unwrap_or_else(|| panic!("{a:?} not on screen"));
    click(app, hit);
}

fn files_secret() -> Secret {
    Secret::Bundle {
        text: Zeroizing::new("note".into()),
        files: vec![
            (
                Zeroizing::new("a.pem".into()),
                Zeroizing::new(b"AAA".to_vec()),
            ),
            (
                Zeroizing::new("b.pem".into()),
                Zeroizing::new(b"BBB".to_vec()),
            ),
        ],
    }
}

#[test]
fn home_navigation_and_quit() {
    let mut app = App::new(Box::new(MemClip::default()));
    assert!(screen_text(&app).contains("> New secret"));
    app.key(key(KeyCode::Down));
    app.key(key(KeyCode::Down));
    app.key(key(KeyCode::Enter));
    assert!(matches!(app.screen, Screen::StatusForm(_)));
    app.key(key(KeyCode::Esc));
    app.key(key(KeyCode::Up));
    app.key(key(KeyCode::Enter));
    assert!(app.quit, "Up from the first item wraps to Quit");
    let mut app = App::new(Box::new(MemClip::default()));
    app.key(ctrl('c'));
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
    app.key(key(KeyCode::Enter));
    new_form(&mut app).focus = NewFocus::Path;
    let long = format!("/very/long/{}/END-OF-PATH", "x".repeat(150));
    app.paste(&long);
    assert!(
        screen_text(&app).contains("END-OF-PATH"),
        "the tail is visible"
    );
    new_form(&mut app).focus = NewFocus::Text;
    let lines: String = (0..40).map(|i| format!("line {i}\n")).collect();
    app.paste(&format!("{lines}LAST-LINE"));
    assert!(
        screen_text(&app).contains("LAST-LINE"),
        "the last line is visible"
    );
    // Beyond u16 offsets: a 70 KB single line still shows its end.
    new_form(&mut app).text.clear();
    app.paste(&format!("{}TAIL-OF-70K", "y".repeat(70_000)));
    assert!(screen_text(&app).contains("TAIL-OF-70K"));
    // Emoji ZWJ sequences: the window and the cursor agree, the tail stays visible.
    new_form(&mut app).text.clear();
    app.paste(&format!(
        "{}TAIL-EMOJI",
        "👨\u{200d}👩\u{200d}👧\u{200d}👦".repeat(100)
    ));
    assert!(screen_text(&app).contains("TAIL-EMOJI"));
}

#[test]
fn mouse_clicks_and_create_shortcuts() {
    let mut app = App::new(Box::new(MemClip::default()));
    click(&mut app, Hit::Home(0));
    assert!(matches!(app.screen, Screen::New(_)));
    app.paste("by mouse");
    click(&mut app, Hit::Act(Action::SetTtl(2), None));
    press_button(&mut app, Action::TogglePassphrase);
    let f = new_form(&mut app);
    assert_eq!((f.ttl, f.use_pass), (2, true));
    click(&mut app, Hit::Focus(NewFocus::Pass));
    app.paste("pw");
    click(&mut app, Hit::Focus(NewFocus::Text));
    assert_eq!(new_form(&mut app).focus, NewFocus::Text);
    // The Create button is drawn and clickable whatever the focus.
    assert!(screen_text(&app).contains("[ Create one-time link (Ctrl+S) ]"));
    press_button(&mut app, Action::Create);
    assert!(matches!(app.pending, Some(Op::Create)));
    assert_eq!(
        new_form(&mut app).focus,
        NewFocus::Create,
        "the click moves the focus"
    );
    new_form(&mut app).focus = NewFocus::Text;
    // Keyboard: Ctrl+S and Shift+Enter from the text field; a plain Enter is a new line.
    for k in [
        ctrl('s'),
        KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
        KeyEvent::new(KeyCode::Enter, KeyModifiers::SUPER),
        KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT),
    ] {
        app.pending = None;
        app.key(k);
        assert!(matches!(app.pending, Some(Op::Create)), "{k:?}");
    }
    app.pending = None;
    app.key(key(KeyCode::Enter));
    assert!(app.pending.is_none());
    assert_eq!(new_form(&mut app).text.text(), "by mouse\n");
}

#[test]
fn focus_is_marked_without_color_and_tab_skips_hidden_fields() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.key(key(KeyCode::Enter));
    let order = new_form(&mut app).order();
    assert_eq!(
        order,
        [
            NewFocus::Text,
            NewFocus::Path,
            NewFocus::Add,
            NewFocus::Ttl,
            NewFocus::UsePass,
            NewFocus::Create,
            NewFocus::Back
        ],
        "no file list and no passphrase field while they are hidden"
    );
    for _ in 0..5 {
        app.key(key(KeyCode::Tab));
    }
    assert!(screen_text(&app).contains("> Create one-time link (Ctrl+S) <"));
    app.key(key(KeyCode::BackTab));
    assert!(screen_text(&app).contains("> [ ] Protect with a passphrase (Space) <"));
    app.key(key(KeyCode::Char(' ')));
    assert!(new_form(&mut app).order().contains(&NewFocus::Generate));
    app.key(key(KeyCode::BackTab));
    app.key(key(KeyCode::Right));
    assert!(screen_text(&app).contains("> (*) 7 days <"));
}

#[test]
fn clicks_on_a_scrolled_file_list_pick_the_drawn_file() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.key(key(KeyCode::Enter));
    let f = new_form(&mut app);
    for i in 0..9 {
        f.files.push(PickedFile {
            path: Zeroizing::new(format!("/x/f{i}")),
            name: Zeroizing::new(format!("file-{i}")),
            size: 1,
        });
    }
    f.file_sel = 8;
    f.focus = NewFocus::Files;
    // Fewer rows than files with the last one selected: the list ends at it.
    let s = screen_text(&app);
    assert!(!s.contains("file-0 ") && s.contains("file-8 "));
    let first = app.hits.borrow().iter().find_map(|(_, h)| match h {
        Hit::Act(Action::SelectFile(i), _) => Some(*i),
        _ => None,
    });
    let first = first.unwrap();
    assert!(first > 0, "the top drawn row is not the first file");
    click(&mut app, Hit::Act(Action::SelectFile(first), None));
    assert_eq!(new_form(&mut app).file_sel, first);
    click(&mut app, Hit::Act(Action::RemoveFile(first), None));
    let f = new_form(&mut app);
    assert_eq!(f.files.len(), 8);
    assert!(
        f.files
            .iter()
            .all(|p| p.name.as_str() != format!("file-{first}"))
    );
}

#[test]
fn buttons_wrap_instead_of_being_cut_at_80_columns() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.screen = Screen::Created(CreatedView {
        recipient: Zeroizing::new(format!(
            "https://x/s/{}#{}~p",
            "1".repeat(64),
            "k".repeat(43)
        )),
        owner: Zeroizing::new(format!("https://x/o/{}#{}", "1".repeat(64), "t".repeat(43))),
        expires: "2026-10-23T02:19:00.177Z".into(),
        passphrase: true,
        show_owner: true,
        focus: 0,
    });
    let text = screen_at(&app, 80, 24);
    for label in [
        "> Copy recipient link (c) <",
        "[-] Only for you: track or revoke (o)",
        "[ Copy private sender link (y) ]",
        "[ New secret (n) ]",
        "[ Home (Esc) ]",
        "23 Oct 2026, 02:19 UTC",
    ] {
        assert!(text.contains(label), "{label} is drawn whole:\n{text}");
    }
}

#[test]
fn created_keys_and_owner_link_toggle() {
    let clip = MemClip::default();
    let mut app = App::new(Box::new(clip.clone()));
    app.screen = Screen::Created(CreatedView {
        recipient: Zeroizing::new("https://x/s/1#k".into()),
        owner: Zeroizing::new("https://x/o/1#t".into()),
        expires: "e".into(),
        passphrase: false,
        show_owner: false,
        focus: 0,
    });
    assert!(
        !screen_text(&app).contains("https://x/o/1#t"),
        "hidden at first"
    );
    app.key(key(KeyCode::Char('y')));
    assert_eq!(
        *clip.value.lock().unwrap(),
        None,
        "no copy of a hidden link"
    );
    app.key(key(KeyCode::Char('o')));
    assert!(screen_text(&app).contains("https://x/o/1#t"));
    app.key(key(KeyCode::Char('y')));
    app.key(key(KeyCode::Char('y')));
    assert_eq!(
        clip.value.lock().unwrap().as_deref(),
        Some("https://x/o/1#t")
    );
    // Enter on the focused button: Copy recipient link.
    app.key(key(KeyCode::Enter));
    assert_eq!(
        clip.value.lock().unwrap().as_deref(),
        Some("https://x/s/1#k")
    );
    // Hiding the private link while Home (after Copy private sender link) is focused: the focus
    // stays on Home, Enter goes home (no out-of-range button).
    app.key(key(KeyCode::BackTab));
    app.key(key(KeyCode::Char('o')));
    let Screen::Created(v) = &app.screen else {
        unreachable!()
    };
    assert_eq!(created_buttons(v)[v.focus].action, Action::Back);
    // Focus on the hidden button itself: it moves to the toggle.
    app.key(key(KeyCode::Char('o')));
    if let Screen::Created(v) = &mut app.screen {
        v.focus = 2;
    }
    app.key(key(KeyCode::Char('o')));
    let Screen::Created(v) = &app.screen else {
        unreachable!()
    };
    assert_eq!(created_buttons(v)[v.focus].action, Action::ToggleOwner);
    // The sequence from the review: show, focus Home, hide, Enter.
    app.key(key(KeyCode::Char('o')));
    app.key(key(KeyCode::BackTab));
    app.key(key(KeyCode::BackTab));
    app.key(key(KeyCode::Char('o')));
    app.key(key(KeyCode::Enter));
    assert!(matches!(app.screen, Screen::Home { .. }));
    app.screen = Screen::Created(CreatedView {
        recipient: Zeroizing::new("https://x/s/1#k".into()),
        owner: Zeroizing::new("https://x/o/1#t".into()),
        expires: "e".into(),
        passphrase: false,
        show_owner: false,
        focus: 0,
    });
    app.key(key(KeyCode::Char('n')));
    assert!(matches!(app.screen, Screen::New(_)));
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
            column: 20,
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
    assert!(s.contains("Copy text (c)") && s.contains("Save to a file (s)"));
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
        app.key(key(KeyCode::PageDown));
    }
    assert!(screen_text(&app).contains("END-OF-TOKEN"));
    app.key(key(KeyCode::PageUp));
    assert!(
        screen_text(&app).contains("tttt"),
        "one page up from the end is still text"
    );
    // Over-scrolled state (e.g. the terminal grew): the first Up moves the view at once.
    if let Screen::Revealed(v) = &mut app.screen {
        v.scroll = 10_000;
    }
    let before = screen_text(&app);
    app.key(key(KeyCode::Up));
    assert_ne!(screen_text(&app), before);
}

#[test]
fn many_received_files_scroll() {
    let mut app = App::new(Box::new(MemClip::default()));
    let files = (0..20)
        .map(|i| {
            (
                Zeroizing::new(format!("f-{i:02}.bin")),
                Zeroizing::new(vec![b'x'; 10]),
            )
        })
        .collect();
    app.reveal(
        "0".repeat(64),
        Secret::Bundle {
            text: Zeroizing::new("t".into()),
            files,
        },
    );
    let s = screen_at(&app, 80, 24);
    assert!(s.contains("20 files") && s.contains("Not saved"));
    assert!(!s.contains("f-19.bin"));
    if let Screen::Revealed(v) = &mut app.screen {
        v.focus = RevealedFocus::Files;
    }
    for _ in 0..20 {
        screen_at(&app, 80, 24);
        app.key(key(KeyCode::Down));
    }
    assert!(screen_at(&app, 80, 24).contains("f-19.bin"));
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
        app.key(key(KeyCode::Down));
    }
    let shown = seen.matches("ｶﾞ").count();
    assert!(shown >= 98, "{shown} of 98 shown");
    assert!(seen.contains("END"));
}

#[test]
fn cursor_after_a_wide_grapheme_at_the_scroll_edge() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.key(key(KeyCode::Enter));
    new_form(&mut app).focus = NewFocus::Path;
    app.paste(&format!("{}AB", "界".repeat(50)));
    app.key(key(KeyCode::Left));
    app.key(key(KeyCode::Left));
    let mut t = Terminal::new(TestBackend::new(100, 30)).unwrap();
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
    assert!(
        app.wants_limit,
        "the limit is asked for once the form opens"
    );
    // Create with nothing: a message, nothing queued.
    new_form(&mut app).focus = NewFocus::Create;
    app.key(key(KeyCode::Enter));
    assert!(app.pending.is_none());
    assert!(screen_text(&app).contains("Enter a secret or add a file."));
    // Ctrl+G is for the passphrase: without it, nothing is generated (the secret is the user's).
    app.key(ctrl('g'));
    let f = new_form(&mut app);
    assert_eq!(f.text.text(), "");
    assert_eq!(f.pass.text(), "");
    f.use_pass = true;
    app.key(ctrl('g'));
    let f = new_form(&mut app);
    assert_eq!(f.pass.text().chars().count(), crate::password::LENGTH);
    assert_eq!(f.text.text(), "");
    assert!(f.generated);
    let first = f.pass.text().to_owned();
    // The button beside the field does the same.
    press_button(&mut app, Action::GeneratePassphrase);
    assert_ne!(new_form(&mut app).pass.text(), first);
    assert!(screen_text(&app).contains("Generate (Ctrl+G)"));
    let f = new_form(&mut app);
    f.use_pass = false;
    f.pass.clear();
    f.generated = false;
    // A missing file is refused; a real one is listed.
    f.focus = NewFocus::Path;
    app.paste("/nonexistent/x");
    app.key(key(KeyCode::Enter));
    assert!(screen_text(&app).contains("No such file."));
    let dir = std::env::temp_dir().join(format!("sdrop-tui-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("key.pem");
    std::fs::write(&file, b"KEY").unwrap();
    new_form(&mut app).path.clear();
    app.paste(file.to_str().unwrap());
    press_button(&mut app, Action::AddFile);
    let f = new_form(&mut app);
    assert_eq!(f.files.len(), 1);
    assert_eq!(f.files[0].name.as_str(), "key.pem");
    // The size counts the record as it is encrypted; over the service limit it says so.
    app.limit = Some(1024);
    let s = screen_text(&app);
    assert!(
        s.contains("1 of 20 files · Size") && s.contains("of 1 KB"),
        "{s}"
    );
    new_form(&mut app).text.set(&"z".repeat(2000));
    assert!(screen_text(&app).contains("too large"));
    new_form(&mut app).text.clear();
    // Passphrase on but empty: refused.
    let f = new_form(&mut app);
    f.use_pass = true;
    f.focus = NewFocus::Create;
    app.key(key(KeyCode::Enter));
    assert!(app.pending.is_none());
    new_form(&mut app).pass.set("pw");
    app.key(key(KeyCode::Enter));
    assert!(matches!(app.pending, Some(Op::Create)));
}

/// What leaving a received secret does: Enter on a fresh dialog, Esc and a click outside it keep
/// the secret; only the explicit choice leaves.
#[test]
fn leaving_unsaved_files_asks_and_defaults_to_stay() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.reveal("0".repeat(64), files_secret());
    for open in [key(KeyCode::Esc), ctrl('c')] {
        app.key(open);
        let d = app.dialog.expect("asks first");
        assert_eq!(d.focus, 0, "Stay is focused");
        let s = screen_text(&app);
        assert!(
            s.contains("Leave without saving?") && s.contains("2 received files are not saved")
        );
        // A click on the background (the Leave button behind the dialog) does nothing.
        screen_text(&app);
        let behind = app
            .hits
            .borrow()
            .iter()
            .find(|(_, h)| matches!(h, Hit::Act(Action::Back, _)))
            .map(|(r, _)| *r)
            .unwrap();
        click_at(&mut app, behind.x, behind.y);
        click_at(&mut app, 0, 0);
        assert!(app.dialog.is_some() && matches!(app.screen, Screen::Revealed(_)));
        // Esc cancels; Enter on the fresh dialog stays.
        app.key(key(KeyCode::Esc));
        assert!(app.dialog.is_none() && !app.quit);
        app.key(open);
        app.key(key(KeyCode::Enter));
        assert!(app.dialog.is_none() && !app.quit);
        assert!(matches!(app.screen, Screen::Revealed(_)));
    }
    // "Save files" opens the directory field; leaving after saving does not ask.
    app.key(key(KeyCode::Esc));
    app.key(key(KeyCode::Tab));
    app.key(key(KeyCode::Enter));
    let Screen::Revealed(v) = &mut app.screen else {
        unreachable!()
    };
    assert!(v.saving && v.focus == RevealedFocus::Dir);
    v.saving = false;
    v.saved = Some("./x".into());
    app.key(key(KeyCode::Esc));
    assert!(app.dialog.is_none() && matches!(app.screen, Screen::Home { .. }));
    // The danger choice leaves (by mouse too).
    app.reveal("0".repeat(64), files_secret());
    app.key(key(KeyCode::Esc));
    click(&mut app, Hit::Act(Action::Choose(2), None));
    assert!(matches!(app.screen, Screen::Home { .. }));
    // Ctrl+C then "Leave without saving" quits.
    app.reveal("0".repeat(64), files_secret());
    app.key(ctrl('c'));
    app.key(key(KeyCode::Left));
    app.key(key(KeyCode::Enter));
    assert!(app.quit);
}

/// While saving, clicks on the text or the file list do not move the focus out of the Tab order.
#[test]
fn clicks_while_saving_keep_the_focus_in_the_tab_order() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.reveal("0".repeat(64), files_secret());
    click(&mut app, Hit::RevealedFiles);
    let Screen::Revealed(v) = &app.screen else {
        unreachable!()
    };
    assert_eq!(v.focus, RevealedFocus::Files);
    app.key(key(KeyCode::Char('s')));
    for hit in [Hit::RevealedText, Hit::RevealedFiles] {
        click(&mut app, hit);
        let Screen::Revealed(v) = &app.screen else {
            unreachable!()
        };
        assert!(v.order().contains(&v.focus), "{hit:?}: {:?}", v.focus);
        assert_eq!(v.focus, RevealedFocus::Dir);
    }
}

/// Received names are shown with control characters replaced, in full otherwise.
#[test]
fn received_names_are_shown_safely() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.reveal(
        "0".repeat(64),
        Secret::File {
            name: Zeroizing::new("evil\u{9b}31mname.txt".into()),
            data: Zeroizing::new(b"x".to_vec()),
        },
    );
    let s = screen_text(&app);
    assert!(
        s.contains("evil?31mname.txt") && !s.contains('\u{9b}'),
        "{s}"
    );
}

#[test]
fn text_only_secret_leaves_without_asking() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.reveal("0".repeat(64), Secret::Text(Zeroizing::new("t".into())));
    app.key(key(KeyCode::Esc));
    assert!(app.dialog.is_none() && matches!(app.screen, Screen::Home { .. }));
}

/// The terminal shrinks below 80×24 and grows again: everything typed or received is kept, and
/// input waits meanwhile.
#[test]
fn small_window_keeps_the_state() {
    let mut app = App::new(Box::new(MemClip::default()));
    app.key(key(KeyCode::Enter));
    app.paste("typed secret");
    new_form(&mut app).use_pass = true;
    screen_at(&app, 80, 24);
    let small = screen_at(&app, 79, 23);
    assert!(small.contains("Enlarge the window") && small.contains("now 79×23"));
    assert!(!small.contains("typed secret"));
    app.key(key(KeyCode::Esc));
    app.paste("more");
    click_at(&mut app, 10, 5);
    let big = screen_at(&app, 120, 35);
    assert!(big.contains("typed secret") && !big.contains("more"));
    assert!(new_form(&mut app).use_pass);

    app.reveal("0".repeat(64), files_secret());
    screen_at(&app, 79, 23);
    app.key(key(KeyCode::Esc));
    assert!(matches!(app.screen, Screen::Revealed(_)) && app.dialog.is_none());
    let big = screen_at(&app, 120, 35);
    assert!(big.contains("a.pem") && big.contains("note"));
}

#[test]
fn snapshots() {
    // SNAPSHOTS=1 cargo test snapshots -- --nocapture: the screens as text, for review.
    if std::env::var_os("SNAPSHOTS").is_none() {
        return;
    }
    let link = format!(
        "https://secrets.example.com/s/{}#{}~p",
        "3f9a1c7e".repeat(8),
        "Qm9yZWQgb2YgdGhlIHNhbWUgb2xkIGtleXM_c29ycnk"
    );
    let owner = format!(
        "https://secrets.example.com/o/{}#{}",
        "3f9a1c7e".repeat(8),
        "b3duZXJUb2tlbkZvclRoZVNlbmRlck9ubHlfeHl6MTIz"
    );
    let mut app = App::new(Box::new(MemClip::default()));
    app.key(key(KeyCode::Enter));
    app.limit = Some(1 << 20);
    app.paste("DB_PASSWORD=Xk29!fPq\nAPI_TOKEN=sk_live_example");
    let f = new_form(&mut app);
    f.files.push(PickedFile {
        path: Zeroizing::new("/x/prod.env".into()),
        name: Zeroizing::new("prod.env".into()),
        size: 2400,
    });
    f.use_pass = true;
    f.pass.set("tame-otter-lamp-91");
    f.generated = true;
    f.focus = NewFocus::Text;
    for (w, h) in [(80, 24), (120, 35)] {
        println!("--- New secret {w}x{h}\n{}", screen_at(&app, w, h));
    }
    app.screen = Screen::Created(CreatedView {
        recipient: Zeroizing::new(link),
        owner: Zeroizing::new(owner),
        expires: "2026-10-23T02:19:00.177Z".into(),
        passphrase: true,
        show_owner: false,
        focus: 0,
    });
    for (w, h) in [(80, 24), (120, 35)] {
        println!("--- Link ready {w}x{h}\n{}", screen_at(&app, w, h));
    }
    app.key(key(KeyCode::Char('o')));
    println!(
        "--- Link ready, private link 80x24\n{}",
        screen_at(&app, 80, 24)
    );
    app.reveal("3f9a1c7e".repeat(8), files_secret());
    println!("--- Revealed 80x24\n{}", screen_at(&app, 80, 24));
    app.key(key(KeyCode::Esc));
    println!("--- Leave dialog 80x24\n{}", screen_at(&app, 80, 24));
    app.screen = Screen::Status(Box::new(StatusView {
        link: crate::api::OwnerLink {
            id: "3f9a1c7e".repeat(8),
            token: Zeroizing::new("t".into()),
        },
        status: crate::ops::Status {
            state: "consumed".into(),
            created: "2026-10-22T02:19:00.177Z".into(),
            expires: "2026-10-23T02:19:00.177Z".into(),
            consumed_at: Some("2026-10-22T03:01:12.000Z".into()),
            consumed_by: None,
        },
        focus: 0,
    }));
    app.dialog = None;
    println!("--- Status 80x24\n{}", screen_at(&app, 80, 24));
    app.screen = Screen::Open(LinkForm {
        input: Input::new(false),
        focus: 0,
    });
    println!("--- Open 80x24\n{}", screen_at(&app, 80, 24));
}
