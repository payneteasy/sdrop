//! Colors and styles of the TUI (README, "Interactive mode"). Text and background are the
//! terminal's own; accents are the brand colors: exact RGB with 24-bit color, else the nearest of
//! the 256-color palette (Apple Terminal draws RGB colors as the default gray), none with NO_COLOR.
//! Meaning never rests on color alone: focus is `> … <`, the chosen option `(*)`.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    TrueColor,
    Palette256,
    NoColor,
}

pub fn mode() -> Mode {
    static MODE: std::sync::OnceLock<Mode> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        detect(
            std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
            &std::env::var("COLORTERM").unwrap_or_default(),
            &std::env::var("TERM_PROGRAM").unwrap_or_default(),
        )
    })
}

/// NO_COLOR (no-color.org) wins; 24-bit only when the terminal says so and is not Apple Terminal.
pub fn detect(no_color: bool, colorterm: &str, term_program: &str) -> Mode {
    if no_color {
        Mode::NoColor
    } else if term_program != "Apple_Terminal" && (colorterm == "truecolor" || colorterm == "24bit")
    {
        Mode::TrueColor
    } else {
        Mode::Palette256
    }
}

fn pick(rgb: (u8, u8, u8), indexed: u8) -> Option<Color> {
    match mode() {
        Mode::TrueColor => Some(Color::Rgb(rgb.0, rgb.1, rgb.2)),
        Mode::Palette256 => Some(Color::Indexed(indexed)),
        Mode::NoColor => None,
    }
}

/// Dodger Blue #348BFF; 256 colors: 33.
pub fn accent() -> Option<Color> {
    pick((52, 139, 255), 33)
}

/// Nevada #69747A; 256 colors: 244.
pub fn muted() -> Option<Color> {
    pick((105, 116, 122), 244)
}

/// Danger #EC493D; 256 colors: 203.
pub fn danger() -> Option<Color> {
    pick((236, 73, 61), 203)
}

/// Success #00A475; 256 colors: 36.
pub fn ok() -> Option<Color> {
    pick((0, 164, 117), 36)
}

fn fg(c: Option<Color>) -> Style {
    match c {
        Some(c) => Style::default().fg(c),
        None => Style::default(),
    }
}

pub fn text() -> Style {
    Style::default()
}

pub fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// Secondary text; without color it is dimmed.
pub fn secondary() -> Style {
    match muted() {
        Some(c) => Style::default().fg(c),
        None => Style::default().add_modifier(Modifier::DIM),
    }
}

pub fn accent_text() -> Style {
    fg(accent())
}

pub fn danger_text() -> Style {
    fg(danger()).add_modifier(Modifier::BOLD)
}

pub fn ok_text() -> Style {
    fg(ok())
}

/// Border of the focused field or of the link box.
pub fn focus_border() -> Style {
    match accent() {
        Some(c) => Style::default().fg(c),
        None => Style::default().add_modifier(Modifier::BOLD),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Secondary,
    Danger,
}

/// Button: the focused one is filled (and carries `> … <`); otherwise primary is accent text,
/// secondary plain, danger red; a disabled one is dimmed.
pub fn button(role: Role, focused: bool, enabled: bool) -> Style {
    if !enabled {
        return Style::default().add_modifier(Modifier::DIM);
    }
    if focused {
        let base = match (role, accent(), danger()) {
            (Role::Danger, _, Some(d)) => Style::default().bg(d).fg(Color::White),
            (_, Some(a), _) => Style::default().bg(a).fg(Color::White),
            _ => Style::default().add_modifier(Modifier::REVERSED),
        };
        return base.add_modifier(Modifier::BOLD);
    }
    match role {
        Role::Primary => accent_text().add_modifier(Modifier::BOLD),
        Role::Secondary => text(),
        Role::Danger => fg(danger()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_mode_detection() {
        assert_eq!(detect(true, "truecolor", ""), Mode::NoColor);
        assert_eq!(detect(false, "truecolor", "iTerm.app"), Mode::TrueColor);
        assert_eq!(detect(false, "24bit", ""), Mode::TrueColor);
        assert_eq!(
            detect(false, "truecolor", "Apple_Terminal"),
            Mode::Palette256
        );
        assert_eq!(detect(false, "", ""), Mode::Palette256);
    }
}
