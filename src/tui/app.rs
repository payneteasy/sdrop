//! TUI state machine (README, "Interactive mode"): keys and pastes change the state; network and
//! disk work is queued as an operation and run between frames, so tests drive the app without a
//! terminal (ratatui `TestBackend`).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

pub const ACCENT: Color = Color::Rgb(52, 139, 255);
pub const MUTED: Color = Color::Rgb(105, 116, 122);
pub const DANGER: Color = Color::Rgb(236, 73, 61);

pub const HOME_ITEMS: [&str; 4] = ["New secret", "Open a link", "Check status", "Quit"];

pub enum Screen {
    Home {
        selected: usize,
    },
    /// Not implemented yet (steps 25-26).
    Todo(&'static str),
}

pub struct App {
    pub screen: Screen,
    pub quit: bool,
    /// Error or note shown above the footer until the next key.
    pub message: Option<(bool, String)>,
}

impl Default for App {
    fn default() -> Self {
        App::new()
    }
}

impl App {
    pub fn new() -> App {
        App {
            screen: Screen::Home { selected: 0 },
            quit: false,
            message: None,
        }
    }

    pub fn key(&mut self, k: KeyEvent) {
        self.message = None;
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match &mut self.screen {
            Screen::Home { selected } => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    *selected = (*selected + HOME_ITEMS.len() - 1) % HOME_ITEMS.len();
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    *selected = (*selected + 1) % HOME_ITEMS.len();
                }
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                KeyCode::Enter => match *selected {
                    0 => self.screen = Screen::Todo("New secret"),
                    1 => self.screen = Screen::Todo("Open a link"),
                    2 => self.screen = Screen::Todo("Check status"),
                    _ => self.quit = true,
                },
                _ => {}
            },
            Screen::Todo(_) => {
                if k.code == KeyCode::Esc {
                    self.screen = Screen::Home { selected: 0 };
                }
            }
        }
    }

    pub fn paste(&mut self, _text: &str) {}

    pub fn render(&self, f: &mut Frame) {
        let [title, body, msg, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(f.area());
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " payneteasy ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Secrets", Style::default().fg(MUTED)),
            ])),
            title,
        );
        let hints = match &self.screen {
            Screen::Home { .. } => "↑↓ choose · Enter open · q quit",
            Screen::Todo(_) => "Esc back · Ctrl+C quit",
        };
        match &self.screen {
            Screen::Home { selected } => render_home(f, body, *selected),
            Screen::Todo(name) => f.render_widget(
                Paragraph::new(format!("{name}: coming soon"))
                    .block(Block::default().borders(Borders::ALL).title(*name)),
                body,
            ),
        }
        if let Some((is_error, m)) = &self.message {
            let style = Style::default().fg(if *is_error { DANGER } else { MUTED });
            f.render_widget(
                Paragraph::new(m.as_str())
                    .style(style)
                    .wrap(Wrap { trim: true }),
                msg,
            );
        }
        f.render_widget(
            Paragraph::new(hints).style(Style::default().fg(MUTED)),
            footer,
        );
    }
}

fn render_home(f: &mut Frame, area: Rect, selected: usize) {
    let items: Vec<ListItem> = HOME_ITEMS.iter().map(|s| ListItem::new(*s)).collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" One-time secrets, encrypted on this machine "),
        )
        .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
        .highlight_symbol("› ");
    let mut state = ListState::default().with_selected(Some(selected));
    f.render_stateful_widget(list, area, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn screen_text(app: &App) -> String {
        let mut t = Terminal::new(TestBackend::new(80, 20)).unwrap();
        t.draw(|f| app.render(f)).unwrap();
        let buf = t.backend().buffer().clone();
        buf.content.iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn home_navigation_and_quit() {
        let mut app = App::new();
        assert!(screen_text(&app).contains("New secret"));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Enter));
        assert!(matches!(app.screen, Screen::Todo("Check status")));
        app.key(key(KeyCode::Esc));
        assert!(matches!(app.screen, Screen::Home { .. }));
        app.key(key(KeyCode::Up));
        app.key(key(KeyCode::Enter));
        assert!(app.quit, "Up from the first item wraps to Quit");
        let mut app = App::new();
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.quit);
    }
}
