//! Interactive mode: `sdrop tui`, or `sdrop` without arguments on a terminal (README).

pub mod app;
pub mod clipboard;
pub mod input;
pub mod term;

use crate::api::CliError;
use app::App;
use crossterm::event::{self, Event, KeyEventKind};
use std::time::Duration;
use zeroize::Zeroizing;

pub fn run() -> Result<(), CliError> {
    // The configured origin is checked (Client::new) before the terminal is taken over.
    let mut guard =
        term::Guard::enter().map_err(|_| CliError::Msg("cannot open the terminal".into()))?;
    let io = |_| CliError::Msg("terminal error".into());
    let mut client = crate::ops::Client::new(false)?;
    let mut app = App::new(Box::new(clipboard::SystemClip::new()));
    #[cfg(feature = "test-loopback")]
    if let Ok(m) = std::env::var("SDROP_TEST_TUI_MARKER") {
        app.message = Some((false, m));
    }
    loop {
        guard.terminal.draw(|f| app.render(f)).map_err(io)?;
        #[cfg(feature = "test-loopback")]
        test_exit(&app)?;
        if app.quit {
            app.on_quit();
            return Ok(());
        }
        if app.pending.is_some() {
            app.perform(&mut client);
            continue;
        }
        app.tick(std::time::Instant::now());
        if !event::poll(Duration::from_millis(500)).map_err(io)? {
            continue;
        }
        match event::read().map_err(io)? {
            Event::Key(k) if k.kind != KeyEventKind::Release => app.key(k),
            Event::Paste(s) => {
                let s = Zeroizing::new(s);
                app.paste(&s);
            }
            _ => {}
        }
    }
}

/// Test build only: after the first frame with a secret marker on screen, fail with an error or a
/// panic (SDROP_TEST_TUI_EXIT=error|panic), to check that the screen is cleared on both paths.
#[cfg(feature = "test-loopback")]
fn test_exit(app: &App) -> Result<(), CliError> {
    let _ = app;
    match std::env::var("SDROP_TEST_TUI_EXIT").as_deref() {
        Ok("error") => Err(CliError::Msg("test error".into())),
        // The panic message carries the marker: it must not be printed after the terminal is restored.
        Ok("panic") => panic!(
            "test panic {}",
            std::env::var("SDROP_TEST_TUI_MARKER").unwrap_or_default()
        ),
        _ => Ok(()),
    }
}
