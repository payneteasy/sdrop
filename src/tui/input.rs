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
    /// with a trailing newline stays one line). Built directly in a wiped buffer of the final
    /// size: no intermediate copy and no reallocation leaves the secret behind.
    pub fn insert(&mut self, s: &str) {
        let at = self.byte_at(self.cursor);
        let mut t = Zeroizing::new(String::with_capacity(self.text.len() + s.len()));
        t.push_str(&self.text[..at]);
        let mut added = 0;
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            let c = match c {
                '\r' if chars.peek() == Some(&'\n') => continue,
                '\r' | '\n' if self.multiline => '\n',
                '\r' | '\n' => ' ',
                c => c,
            };
            t.push(c);
            added += 1;
        }
        t.push_str(&self.text[at..]);
        self.text = t;
        self.cursor += added;
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

    /// Start and end (char indices) of the line with the cursor, scanning the text in place.
    fn line_bounds(&self) -> (usize, usize) {
        let (mut start, mut end) = (0, None);
        for (i, c) in self.text.chars().enumerate() {
            if c != '\n' {
                continue;
            }
            if i < self.cursor {
                start = i + 1;
            } else {
                end = Some(i);
                break;
            }
        }
        (start, end.unwrap_or_else(|| self.text.chars().count()))
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

    /// Line and display column of the cursor (terminal cells: wide characters take two, combining
    /// marks none), for placing the terminal cursor. Computed in place, without copies.
    pub fn line_col(&self) -> (usize, usize) {
        let (mut line, mut col) = (0, 0);
        for c in self.text.chars().take(self.cursor) {
            if c == '\n' {
                line += 1;
                col = 0;
            } else {
                col += unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
            }
        }
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
        // "два 🔐": three letters, a space and a wide emoji = 6 cells.
        assert_eq!(i.line_col(), (1, 6));
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

    #[test]
    fn display_width_of_wide_and_combining() {
        let mut i = Input::new(false);
        i.insert("界a");
        assert_eq!(i.line_col(), (0, 3));
        i.set("e\u{301}x");
        assert_eq!(i.line_col(), (0, 2));
        let mut m = Input::new(true);
        m.insert("a\r\nb\rc\n");
        assert_eq!(m.text(), "a\nb\nc\n");
        assert_eq!(m.line_col(), (3, 0));
    }
}
