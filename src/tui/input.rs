//! Text fields of the TUI: single-line (links, paths, passphrase) and multi-line (the secret).
//! The text lives in a wiped buffer; the cursor is a char index.

use zeroize::Zeroizing;

pub struct Input {
    text: Zeroizing<String>,
    /// Cursor position in chars.
    cursor: usize,
    pub multiline: bool,
}

impl Input {
    pub fn new(multiline: bool) -> Input {
        Input {
            text: Zeroizing::new(String::new()),
            cursor: 0,
            multiline,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Replace the whole text (generated password, paste into an empty field) and put the cursor
    /// at the end. The old text is wiped.
    pub fn set(&mut self, s: &str) {
        let mut t = Zeroizing::new(String::with_capacity(s.len()));
        t.push_str(s);
        self.text = t;
        self.cursor = self.text.chars().count();
    }

    pub fn clear(&mut self) {
        self.set("");
    }

    fn byte_at(&self, chars: usize) -> usize {
        self.text
            .char_indices()
            .nth(chars)
            .map_or(self.text.len(), |(i, _)| i)
    }

    /// Insert text at the cursor; in a single-line field line breaks become spaces (a pasted link
    /// with a trailing newline stays one line).
    pub fn insert(&mut self, s: &str) {
        let s: String = if self.multiline {
            s.replace("\r\n", "\n").replace('\r', "\n")
        } else {
            s.chars()
                .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                .collect()
        };
        let s = Zeroizing::new(s);
        // Grow into a fresh wiped buffer: a reallocation would leave an unwiped copy behind.
        let at = self.byte_at(self.cursor);
        let mut t = Zeroizing::new(String::with_capacity(self.text.len() + s.len()));
        t.push_str(&self.text[..at]);
        t.push_str(&s);
        t.push_str(&self.text[at..]);
        self.text = t;
        self.cursor += s.chars().count();
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let from = self.byte_at(self.cursor - 1);
        let to = self.byte_at(self.cursor);
        self.remove(from, to);
        self.cursor -= 1;
    }

    pub fn delete(&mut self) {
        let from = self.byte_at(self.cursor);
        let to = self.byte_at(self.cursor + 1);
        self.remove(from, to);
    }

    fn remove(&mut self, from: usize, to: usize) {
        let mut t = Zeroizing::new(String::with_capacity(self.text.len()));
        t.push_str(&self.text[..from]);
        t.push_str(&self.text[to..]);
        self.text = t;
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.text.chars().count());
    }

    /// Start and end (char indices) of the line with the cursor.
    fn line_bounds(&self) -> (usize, usize) {
        let chars: Vec<char> = self.text.chars().collect();
        let mut start = self.cursor;
        while start > 0 && chars[start - 1] != '\n' {
            start -= 1;
        }
        let mut end = self.cursor;
        while end < chars.len() && chars[end] != '\n' {
            end += 1;
        }
        (start, end)
    }

    pub fn home(&mut self) {
        self.cursor = self.line_bounds().0;
    }

    pub fn end(&mut self) {
        self.cursor = self.line_bounds().1;
    }

    /// Previous line, same column (or its end).
    pub fn up(&mut self) {
        let (start, _) = self.line_bounds();
        if start == 0 {
            return;
        }
        let col = self.cursor - start;
        self.cursor = start - 1;
        let (pstart, pend) = self.line_bounds();
        self.cursor = (pstart + col).min(pend);
    }

    /// Next line, same column (or its end).
    pub fn down(&mut self) {
        let (start, end) = self.line_bounds();
        if end >= self.text.chars().count() {
            return;
        }
        let col = self.cursor - start;
        self.cursor = end + 1;
        let (nstart, nend) = self.line_bounds();
        self.cursor = (nstart + col).min(nend);
    }

    /// Line and column of the cursor, for placing the terminal cursor.
    pub fn line_col(&self) -> (usize, usize) {
        let before: String = self.text.chars().take(self.cursor).collect();
        let line = before.matches('\n').count();
        let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count());
        (line, col)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_single_line() {
        let mut i = Input::new(false);
        i.insert("https://x/s/1#k\n");
        assert_eq!(i.text(), "https://x/s/1#k ");
        i.backspace();
        i.left();
        i.left();
        i.insert("Z");
        assert_eq!(i.text(), "https://x/s/1Z#k");
        i.home();
        i.delete();
        assert_eq!(i.text(), "ttps://x/s/1Z#k");
        i.end();
        assert_eq!(i.cursor(), 15);
    }

    #[test]
    fn edit_multi_line_and_unicode() {
        let mut i = Input::new(true);
        i.insert("ключ\r\nдва 🔐");
        assert_eq!(i.text(), "ключ\nдва 🔐");
        assert_eq!(i.line_col(), (1, 5));
        i.up();
        assert_eq!(i.line_col(), (0, 4));
        i.home();
        i.down();
        assert_eq!(i.line_col(), (1, 0));
        i.backspace();
        assert_eq!(i.text(), "ключдва 🔐");
        i.set("abc");
        assert_eq!((i.text(), i.cursor()), ("abc", 3));
        i.clear();
        assert_eq!(i.text(), "");
    }
}
