//! Terminal guard (README, "Interactive mode"): raw mode, the alternate screen and bracketed paste
//! for the session; on exit, error and panic the screen is cleared *before* leaving the alternate
//! screen, so a shown secret does not stay in the terminal or its scrollback.

use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{Stdout, stdout};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static HOOK: Once = Once::new();

pub type Tty = Terminal<CrosstermBackend<Stdout>>;

/// Clear, leave the alternate screen, restore input. Idempotent; best effort (used from the panic
/// hook too, where nothing may fail).
pub fn restore() {
    if !ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    let mut out = stdout();
    let _ = execute!(
        out,
        Clear(ClearType::All),
        cursor::MoveTo(0, 0),
        DisableBracketedPaste,
        LeaveAlternateScreen,
        cursor::Show
    );
    let _ = disable_raw_mode();
}

pub struct Guard {
    pub terminal: Tty,
}

impl Guard {
    pub fn enter() -> std::io::Result<Guard> {
        HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore();
                previous(info);
            }));
        });
        enable_raw_mode()?;
        ACTIVE.store(true, Ordering::SeqCst);
        let mut out = stdout();
        if let Err(e) = execute!(out, EnterAlternateScreen, EnableBracketedPaste) {
            restore();
            return Err(e);
        }
        match Terminal::new(CrosstermBackend::new(stdout())) {
            Ok(terminal) => Ok(Guard { terminal }),
            Err(e) => {
                restore();
                Err(e)
            }
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // After a panic the hook has already restored the terminal: drawing now would clear the
        // user's normal screen instead of the alternate one.
        if !ACTIVE.load(Ordering::SeqCst) {
            return;
        }
        // A blank frame overwrites the rendered cells (the secret) in ratatui's buffers too.
        let _ = self.terminal.draw(|f| {
            let area = f.area();
            f.render_widget(ratatui::widgets::Clear, area);
        });
        restore();
    }
}
