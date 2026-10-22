//! Clipboard for the TUI (README, "Interactive mode"): the system clipboard (arboard) on this
//! machine; over SSH, or when the system clipboard is unavailable, the terminal's OSC 52, which
//! reaches the clipboard of the machine the terminal runs on.

use base64::Engine as _;
use std::io::Write;
use zeroize::Zeroizing;

/// Where a copy went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    System,
    Terminal,
}

/// The system clipboard cannot be used right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

pub trait Clip {
    fn copy(&mut self, text: &str) -> Result<Via, String>;
    /// Current system clipboard text: `Ok(None)` if it holds no text, `Err` if the clipboard is
    /// unavailable right now (then a pending removal is retried, not dropped).
    fn read(&mut self) -> Result<Option<Zeroizing<String>>, Unavailable>;
    fn clear(&mut self) -> Result<(), Unavailable>;
    /// Remove the text with this SHA-256 after `delay`, independently of the caller's thread.
    fn schedule_clear(&mut self, _hash: [u8; 32], _delay: std::time::Duration) {}
}

/// Outcome of one removal attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// Removed, or the clipboard holds something else now: nothing more to do.
    Done,
    /// The clipboard could not be used: try again later.
    Retry,
}

/// One attempt with the system clipboard: remove the text with this SHA-256 if it is still there.
fn attempt_clear(hash: [u8; 32]) -> Attempt {
    use sha2::{Digest, Sha256};
    let Ok(mut b) = arboard::Clipboard::new() else {
        return Attempt::Retry;
    };
    match b.get_text() {
        Ok(t) => {
            let t = Zeroizing::new(t);
            if <[u8; 32]>::from(Sha256::digest(t.as_bytes())) != hash || b.clear().is_ok() {
                Attempt::Done
            } else {
                Attempt::Retry
            }
        }
        Err(arboard::Error::ContentNotAvailable) => Attempt::Done,
        Err(_) => Attempt::Retry,
    }
}

/// The removal timer of generation `mine`: each attempt runs under the lock that `copy` takes, and
/// only while no newer copy happened, so a retry of an old timer never removes a newer copy.
pub fn run_clear(
    generation: &std::sync::Mutex<u64>,
    mine: u64,
    mut attempt: impl FnMut() -> Attempt,
    mut wait: impl FnMut(),
) {
    for _ in 0..60 {
        {
            let current = generation.lock().unwrap_or_else(|e| e.into_inner());
            if *current != mine || attempt() == Attempt::Done {
                return;
            }
        }
        wait();
    }
}

pub struct SystemClip {
    board: Option<arboard::Clipboard>,
    ssh: bool,
    /// Generation of the latest copy; taken by `copy` and by every removal attempt.
    generation: std::sync::Arc<std::sync::Mutex<u64>>,
}

impl SystemClip {
    pub fn new() -> SystemClip {
        let ssh =
            std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some();
        SystemClip {
            board: if ssh {
                None
            } else {
                arboard::Clipboard::new().ok()
            },
            ssh,
            generation: Default::default(),
        }
    }
}

impl Default for SystemClip {
    fn default() -> Self {
        SystemClip::new()
    }
}

/// OSC 52 "set clipboard" sequence for `text`.
pub fn osc52(text: &str) -> Zeroizing<String> {
    let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(text.as_bytes()));
    Zeroizing::new(format!("\x1b]52;c;{}\x07", b64.as_str()))
}

impl Clip for SystemClip {
    fn copy(&mut self, text: &str) -> Result<Via, String> {
        let mut generation = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        *generation += 1;
        if !self.ssh
            && let Some(b) = self.board.as_mut()
            && b.set_text(text).is_ok()
        {
            return Ok(Via::System);
        }
        let seq = osc52(text);
        let mut out = std::io::stdout();
        out.write_all(seq.as_bytes())
            .and_then(|_| out.flush())
            .map_err(|_| "cannot write to the terminal".to_string())?;
        Ok(Via::Terminal)
    }

    fn read(&mut self) -> Result<Option<Zeroizing<String>>, Unavailable> {
        let b = self.board.as_mut().ok_or(Unavailable)?;
        match b.get_text() {
            Ok(t) => Ok(Some(Zeroizing::new(t))),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(_) => Err(Unavailable),
        }
    }

    fn clear(&mut self) -> Result<(), Unavailable> {
        self.board
            .as_mut()
            .ok_or(Unavailable)?
            .clear()
            .map_err(|_| Unavailable)
    }

    fn schedule_clear(&mut self, hash: [u8; 32], delay: std::time::Duration) {
        if self.board.is_some() {
            let generation = self.generation.clone();
            let mine = *generation.lock().unwrap_or_else(|e| e.into_inner());
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                run_clear(
                    &generation,
                    mine,
                    || attempt_clear(hash),
                    || std::thread::sleep(std::time::Duration::from_secs(5)),
                );
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_old_timer_retry_never_removes_a_newer_copy() {
        use std::sync::Mutex;
        // The clipboard is unavailable at the first attempt; meanwhile the secret is copied again.
        let generation = Mutex::new(1);
        let mut attempts = 0;
        run_clear(
            &generation,
            1,
            || {
                attempts += 1;
                Attempt::Retry
            },
            || *generation.lock().unwrap() += 1,
        );
        assert_eq!(attempts, 1, "the retry saw the newer copy and stopped");
        // Still the latest copy: attempts go on until done.
        let generation = Mutex::new(5);
        let mut n = 0;
        run_clear(
            &generation,
            5,
            || {
                n += 1;
                if n < 3 { Attempt::Retry } else { Attempt::Done }
            },
            || {},
        );
        assert_eq!(n, 3);
    }

    #[test]
    fn osc52_sequence() {
        assert_eq!(osc52("hi").as_str(), "\x1b]52;c;aGk=\x07");
    }
}
