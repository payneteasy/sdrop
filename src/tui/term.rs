//! Terminal guard (README, "Interactive mode"): raw mode, the alternate screen and bracketed paste
//! for the session; on exit, error and panic the screen is cleared *before* leaving the alternate
//! screen, so a shown secret does not stay in the terminal or its scrollback.

use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
};
#[cfg(not(windows))]
use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
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
    // Step by step: a step that fails (an unsupported one) does not skip the rest.
    let mut out = stdout();
    let _ = execute!(out, Clear(ClearType::All), cursor::MoveTo(0, 0));
    #[cfg(not(windows))]
    let _ = execute!(out, PopKeyboardEnhancementFlags);
    let _ = execute!(out, DisableMouseCapture);
    let _ = execute!(out, DisableBracketedPaste);
    let _ = execute!(out, LeaveAlternateScreen, cursor::Show);
    let _ = disable_raw_mode();
}

pub struct Guard {
    pub terminal: Tty,
}

impl Guard {
    pub fn enter() -> std::io::Result<Guard> {
        HOOK.call_once(|| {
            // The default hook would print the panic message, which might carry text from the
            // screen; only the location is printed, after the terminal is restored.
            std::panic::set_hook(Box::new(|info| {
                restore();
                let place = info
                    .location()
                    .map(|l| format!(" at {}:{}", l.file(), l.line()))
                    .unwrap_or_default();
                eprintln!("sdrop: internal error{place}");
            }));
        });
        enable_raw_mode()?;
        ACTIVE.store(true, Ordering::SeqCst);
        let mut out = stdout();
        // Mouse clicks and the wheel; Shift/Cmd+Enter where the terminal supports the keyboard
        // protocol (others ignore the request).
        if let Err(e) = execute!(
            out,
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableMouseCapture
        ) {
            restore();
            return Err(e);
        }
        // Not on Windows: crossterm uses the console API there, which has no such protocol.
        #[cfg(not(windows))]
        let _ = execute!(
            out,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        );
        match Terminal::new(CrosstermBackend::new(stdout())) {
            Ok(terminal) => Ok(Guard { terminal }),
            Err(e) => {
                restore();
                Err(e)
            }
        }
    }
}

impl Guard {
    /// Overwrite both frame buffers in memory (the last frames may show the secret). Cells hold
    /// short symbols inline, so resetting a cell overwrites its bytes in place.
    fn wipe_buffers(&mut self) {
        self.terminal.current_buffer_mut().reset();
        self.terminal.swap_buffers();
        self.terminal.current_buffer_mut().reset();
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // After a panic the hook has already restored the terminal: nothing is drawn then (it would
        // clear the user's normal screen), only the memory is wiped.
        if ACTIVE.load(Ordering::SeqCst) {
            // A blank frame clears the alternate screen before it is left.
            let _ = self.terminal.draw(|f| {
                let area = f.area();
                f.render_widget(ratatui::widgets::Clear, area);
            });
            restore();
        }
        self.wipe_buffers();
    }
}
