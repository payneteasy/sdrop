//! Building blocks of the TUI screens: buttons, single-line and boxed fields, the card, wrapping
//! by graphemes and dates. Layout functions return the rectangles they draw into, so the same
//! geometry serves drawing and mouse hits.

use super::input::{Input, cells};
use super::theme::{self, Role};
use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

/// A button: what it does (`A`), how it looks and whether it can be pressed now.
#[derive(Debug, Clone)]
pub struct Button<A> {
    pub label: String,
    /// The key shown in parentheses, e.g. "Ctrl+S".
    pub key: &'static str,
    pub action: A,
    pub role: Role,
    pub enabled: bool,
}

impl<A> Button<A> {
    pub fn new(label: impl Into<String>, key: &'static str, action: A, role: Role) -> Self {
        Button {
            label: label.into(),
            key,
            action,
            role,
            enabled: true,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// `[ Label (Key) ]`, or `> Label (Key) <` with focus: visible without color too.
    pub fn text(&self, focused: bool) -> String {
        let inner = if self.key.is_empty() {
            self.label.clone()
        } else {
            format!("{} ({})", self.label, self.key)
        };
        if focused {
            format!("> {inner} <")
        } else {
            format!("[ {inner} ]")
        }
    }

    pub fn width(&self) -> u16 {
        unicode_width::UnicodeWidthStr::width(self.text(false).as_str()) as u16
    }
}

/// Places buttons left to right with two spaces between them; one that does not fit moves to the
/// next row (never cut). Returns one rectangle per button (empty if no room).
pub fn layout_buttons<A>(area: Rect, buttons: &[Button<A>]) -> Vec<Rect> {
    let (mut x, mut y) = (area.x, area.y);
    buttons
        .iter()
        .map(|b| {
            let w = b.width().min(area.width);
            if x > area.x && x + w > area.right() {
                x = area.x;
                y += 1;
            }
            if y >= area.bottom() {
                return Rect::default();
            }
            let r = Rect {
                x,
                y,
                width: w,
                height: 1,
            };
            x = x.saturating_add(w + 2);
            r
        })
        .collect()
}

/// Rows the buttons need at this width.
pub fn button_rows<A>(width: u16, buttons: &[Button<A>]) -> u16 {
    let area = Rect {
        x: 0,
        y: 0,
        width,
        height: u16::MAX,
    };
    layout_buttons(area, buttons)
        .iter()
        .map(|r| r.y + 1)
        .max()
        .unwrap_or(0)
}

pub fn render_button<A>(f: &mut Frame, r: Rect, b: &Button<A>, focused: bool) {
    if r.width == 0 {
        return;
    }
    f.render_widget(
        Paragraph::new(b.text(focused)).style(theme::button(b.role, focused, b.enabled)),
        r,
    );
}

/// The part of a line after its first `cols` terminal cells, cut at grapheme boundaries (a wide
/// grapheme straddling the edge is skipped whole), and the cells actually skipped.
pub fn skip_cols(line: &str, cols: usize) -> (&str, usize) {
    let mut seen = 0;
    for (i, g) in unicode_segmentation::UnicodeSegmentation::grapheme_indices(line, true) {
        if seen >= cols {
            return (&line[i..], seen);
        }
        seen += cells(g);
    }
    ("", seen)
}

/// Screen lines of `text` at `width` cells: each line cut into pieces at grapheme boundaries
/// (slices of the text, no copies).
pub fn wrapped(text: &str, width: usize) -> impl Iterator<Item = &str> {
    text.split('\n').flat_map(move |line| {
        let mut pieces = Vec::new();
        let (mut start, mut used) = (0, 0);
        for (i, g) in unicode_segmentation::UnicodeSegmentation::grapheme_indices(line, true) {
            let gw = cells(g);
            if used + gw > width && i > start {
                pieces.push(&line[start..i]);
                start = i;
                used = 0;
            }
            used += gw;
        }
        pieces.push(&line[start..]);
        pieces
    })
}

/// Visible window of an input inside `inner` (cells), scrolled to keep the cursor in view; draws
/// the text and places the terminal cursor when focused.
fn draw_window(f: &mut Frame, inner: Rect, input: &Input, focused: bool) {
    let (line, col) = input.line_col();
    let (w, h) = (inner.width as usize, inner.height as usize);
    if w == 0 || h == 0 {
        return;
    }
    let dy = line.saturating_sub(h - 1);
    let dx = col.saturating_sub(w - 1);
    let mut skipped = dx;
    let visible: Vec<Line> = input
        .text()
        .split('\n')
        .enumerate()
        .skip(dy)
        .take(h)
        .map(|(n, l)| {
            let (rest, cut) = skip_cols(l, dx);
            if n == line {
                skipped = cut;
            }
            Line::raw(rest)
        })
        .collect();
    f.render_widget(Paragraph::new(visible), inner);
    if focused {
        f.set_cursor_position(Position {
            x: inner.x + col.saturating_sub(skipped).min(w - 1) as u16,
            y: inner.y + (line - dy) as u16,
        });
    }
}

/// A multi-line field in a box (the secret editor), the title in its top border.
pub fn render_box_input(f: &mut Frame, area: Rect, title: &str, input: &Input, focused: bool) {
    let block = boxed(title, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let inner = Rect {
        x: inner.x + 1,
        width: inner.width.saturating_sub(2),
        ..inner
    };
    draw_window(f, inner, input, focused);
}

/// A box with a title in its top border; the focused one is in the accent color and bold.
pub fn boxed(title: &str, focused: bool) -> Block<'_> {
    let (border, label) = if focused {
        (
            theme::focus_border(),
            theme::focus_border().add_modifier(ratatui::style::Modifier::BOLD),
        )
    } else {
        (theme::secondary(), theme::bold())
    };
    let b = Block::default().borders(Borders::ALL).border_style(border);
    if title.is_empty() {
        b
    } else {
        // The focus is visible without color too.
        let title = if focused {
            format!(" > {title} < ")
        } else {
            format!(" {title} ")
        };
        b.title(Span::styled(title, label))
    }
}

/// A single-line field `label [ text ]` in one row; returns the bracketed field area.
pub fn render_line_input(
    f: &mut Frame,
    area: Rect,
    label: &str,
    input: &Input,
    focused: bool,
) -> Rect {
    let lw = if label.is_empty() {
        0
    } else {
        unicode_width::UnicodeWidthStr::width(label) as u16 + 1
    };
    let field = Rect {
        x: area.x + lw,
        width: area.width.saturating_sub(lw),
        ..area
    };
    if lw > 0 {
        let style = if focused {
            theme::bold()
        } else {
            theme::text()
        };
        f.render_widget(Paragraph::new(Span::styled(label, style)), area);
    }
    let bracket = if focused {
        theme::focus_border().add_modifier(ratatui::style::Modifier::BOLD)
    } else {
        theme::secondary()
    };
    if field.width >= 5 {
        f.render_widget(Paragraph::new(Span::styled("[", bracket)), field);
        let right = Rect {
            x: field.right() - 1,
            width: 1,
            ..field
        };
        f.render_widget(Paragraph::new(Span::styled("]", bracket)), right);
        let inner = Rect {
            x: field.x + 2,
            width: field.width - 4,
            ..field
        };
        draw_window(f, inner, input, focused);
    }
    field
}

/// The card: centered, `width` cells wide at most (and at most the area less 2×margin), as tall as
/// its content allows.
pub fn card(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y,
        width: w,
        height: height.min(area.height),
    }
}

/// `2026-10-23T02:19:00.177Z` → `23 Oct 2026, 02:19 UTC`; anything else is shown as it is.
pub fn human_time(iso: &str) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parse = || -> Option<String> {
        let b = iso.as_bytes();
        if iso.len() < 17 || !iso.ends_with('Z') || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
            return None;
        }
        let num = |r: std::ops::Range<usize>| iso.get(r)?.parse::<u32>().ok();
        let (y, mo, d, h, mi) = (
            num(0..4)?,
            num(5..7)?,
            num(8..10)?,
            num(11..13)?,
            num(14..16)?,
        );
        let month = MONTHS.get(mo.checked_sub(1)? as usize)?;
        ((1..=31).contains(&d) && h < 24 && mi < 60)
            .then(|| format!("{d} {month} {y}, {h:02}:{mi:02} UTC"))
    };
    parse().unwrap_or_else(|| iso.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buttons_show_focus_without_color_and_wrap() {
        let b = Button::new("Create one-time link", "Ctrl+S", 1, Role::Primary);
        assert_eq!(b.text(false), "[ Create one-time link (Ctrl+S) ]");
        assert_eq!(b.text(true), "> Create one-time link (Ctrl+S) <");
        let bs = vec![b.clone(), Button::new("Back", "Esc", 2, Role::Secondary)];
        assert_eq!(button_rows(80, &bs), 1);
        assert_eq!(button_rows(40, &bs), 2);
        let rs = layout_buttons(
            Rect {
                x: 0,
                y: 0,
                width: 40,
                height: 5,
            },
            &bs,
        );
        assert_eq!((rs[1].x, rs[1].y), (0, 1));
    }

    #[test]
    fn dates() {
        assert_eq!(
            human_time("2026-10-23T02:19:00.177Z"),
            "23 Oct 2026, 02:19 UTC"
        );
        assert_eq!(human_time("2026-01-05T14:07:00Z"), "5 Jan 2026, 14:07 UTC");
        for bad in ["c", "2026-13-01T00:00:00Z", "2026-10-23 02:19", ""] {
            assert_eq!(human_time(bad), bad);
        }
    }
}
