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

pub trait Clip {
    fn copy(&mut self, text: &str) -> Result<Via, String>;
    /// Current system clipboard text (None if unavailable or not text).
    fn read(&mut self) -> Option<Zeroizing<String>>;
    fn clear(&mut self);
}

pub struct SystemClip {
    board: Option<arboard::Clipboard>,
    ssh: bool,
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
            && b.set_text(text.to_owned()).is_ok()
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

    fn read(&mut self) -> Option<Zeroizing<String>> {
        self.board.as_mut()?.get_text().ok().map(Zeroizing::new)
    }

    fn clear(&mut self) {
        if let Some(b) = self.board.as_mut() {
            let _ = b.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_sequence() {
        assert_eq!(osc52("hi").as_str(), "\x1b]52;c;aGk=\x07");
    }
}
