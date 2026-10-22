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

/// Remove the copied text if the clipboard still holds it; retried while the clipboard is
/// unavailable (bounded: about five minutes).
fn clear_if_same(hash: [u8; 32]) {
    use sha2::{Digest, Sha256};
    for _ in 0..60 {
        if let Ok(mut b) = arboard::Clipboard::new() {
            match b.get_text() {
                Ok(t) => {
                    let t = Zeroizing::new(t);
                    if <[u8; 32]>::from(Sha256::digest(t.as_bytes())) != hash || b.clear().is_ok() {
                        return;
                    }
                }
                Err(arboard::Error::ContentNotAvailable) => return,
                Err(_) => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

pub struct SystemClip {
    board: Option<arboard::Clipboard>,
    ssh: bool,
    /// Generation of the latest scheduled removal: an older timer leaves a newer copy alone.
    generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
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
            let mine = generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                if is_current(&generation, mine) {
                    clear_if_same(hash);
                }
            });
        }
    }
}

/// The timer of generation `mine` is still the latest one.
fn is_current(generation: &std::sync::atomic::AtomicU64, mine: u64) -> bool {
    generation.load(std::sync::atomic::Ordering::SeqCst) == mine
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_older_timer_is_not_current() {
        let g = std::sync::atomic::AtomicU64::new(0);
        let first = g.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        assert!(is_current(&g, first));
        let second = g.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        assert!(
            !is_current(&g, first),
            "copied again: the first timer leaves it alone"
        );
        assert!(is_current(&g, second));
    }

    #[test]
    fn osc52_sequence() {
        assert_eq!(osc52("hi").as_str(), "\x1b]52;c;aGk=\x07");
    }
}
