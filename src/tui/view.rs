//! Drawing of the TUI screens (README, "Interactive mode"): the header, the card in the middle,
//! the message and the key hints at the bottom, and a dialog over the card. Click areas are
//! recorded while drawing, from the same rectangles.

use super::app::{
    Action, App, CreatedView, Dialog, HOME_ITEMS, Hit, Hits, LinkForm, NewFocus, NewForm,
    RevealView, RevealedFocus, RevealedView, Screen, StatusView, TTLS, UnlockView, created_buttons,
    link_form_buttons, reveal_buttons, revealed_buttons, status_buttons, unlock_buttons,
};
use super::theme::{self, Role};
use super::widgets::{
    Button, boxed, button_rows, human_time, layout_buttons, render_box_input, render_button,
    render_line_input, wrapped,
};
use crate::format;
use crate::ops::human_size;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;
use zeroize::Zeroizing;

/// Smaller than this, only "enlarge the window" is shown; the state is kept.
pub const MIN_W: u16 = 80;
pub const MIN_H: u16 = 24;
/// The card: 72 cells at 80 columns, at most 96.
const CARD_MAX: u16 = 96;

/// A column filled top to bottom.
struct Col {
    area: Rect,
    y: u16,
}

impl Col {
    fn new(area: Rect) -> Col {
        Col { area, y: area.y }
    }

    fn take(&mut self, h: u16) -> Rect {
        let h = h.min(self.area.bottom().saturating_sub(self.y));
        let r = Rect {
            x: self.area.x,
            y: self.y,
            width: self.area.width,
            height: h,
        };
        self.y += h;
        r
    }

    fn line(&mut self, f: &mut Frame, line: Line) -> Rect {
        let r = self.take(1);
        f.render_widget(Paragraph::new(line), r);
        r
    }

    /// Wrapped text, as many rows as it needs.
    fn text(&mut self, f: &mut Frame, text: &str, style: Style) -> Rect {
        let rows = wrapped(text, self.area.width.max(1) as usize).count() as u16;
        let r = self.take(rows);
        f.render_widget(
            Paragraph::new(text).style(style).wrap(Wrap { trim: true }),
            r,
        );
        r
    }
}

/// Blank lines between groups, dropped first when the window is short: `wanted` spacers out of the
/// rows left after the content.
fn spacers(room: u16, wanted: u16) -> Vec<bool> {
    (0..wanted).map(|i| i < room).collect()
}

/// Buttons in a row (wrapping), the `focus`-th focused; `first` is the focus index of the first.
fn buttons_row(
    f: &mut Frame,
    area: Rect,
    buttons: &[Button<Action>],
    focus: Option<usize>,
    first: usize,
    hits: &mut Hits,
) {
    for (i, (r, b)) in layout_buttons(area, buttons)
        .into_iter()
        .zip(buttons)
        .enumerate()
    {
        render_button(f, r, b, focus == Some(first + i));
        if b.enabled && r.width > 0 {
            hits.push((r, Hit::Act(b.action, Some(first + i))));
        }
    }
}

/// One button at `(x, y)`.
fn button_at(
    f: &mut Frame,
    x: u16,
    y: u16,
    b: &Button<Action>,
    focused: bool,
    focus_index: Option<usize>,
    hits: &mut Hits,
) -> Rect {
    let r = Rect {
        x,
        y,
        width: b.width(),
        height: 1,
    };
    render_button(f, r, b, focused);
    if b.enabled {
        hits.push((r, Hit::Act(b.action, focus_index)));
    }
    r
}

fn screen_title(app: &App) -> &'static str {
    match &app.screen {
        Screen::Home { .. } => "",
        Screen::New(_) => "New secret",
        Screen::Created(_) => "Link ready",
        Screen::Open(_) => "Open a link",
        Screen::Reveal(_) => "Reveal",
        Screen::Unlock(_) => "Passphrase",
        Screen::Revealed(_) => "Your secret",
        Screen::StatusForm(_) => "Check status",
        Screen::Status(_) => "Status",
    }
}

fn hints(app: &App) -> &'static str {
    if app.dialog.is_some() {
        return "←/→ choose · Enter confirm · Esc cancel";
    }
    match &app.screen {
        Screen::Home { .. } => "↑/↓ choose · Enter open · q quit",
        Screen::New(_) => "Tab next · Shift+Tab back · Ctrl+S create · Esc back",
        Screen::Created(_) => "Tab next · c copy link · o private link · n new secret · Esc home",
        Screen::Open(_) | Screen::StatusForm(_) => "Enter check · Esc back",
        Screen::Reveal(_) => "Enter reveal · Esc back",
        Screen::Unlock(_) => "Enter decrypt · Esc discard",
        Screen::Revealed(v) if v.saving => "Enter save · Esc cancel",
        Screen::Revealed(_) => "↑/↓ scroll · Tab next · c copy · s save · Esc leave",
        Screen::Status(_) => "Tab next · r check · x revoke · Esc home",
    }
}

pub fn render(app: &App, f: &mut Frame) {
    let mut hits: Hits = Vec::new();
    let area = f.area();
    if area.width < MIN_W || area.height < MIN_H {
        app.too_small.set(true);
        render_small(app, f, area);
        *app.hits.borrow_mut() = hits;
        return;
    }
    app.too_small.set(false);
    let w = area.width.saturating_sub(8).min(CARD_MAX);
    let x = area.x + (area.width - w) / 2;
    let row = |y: u16, height: u16| Rect {
        x,
        y,
        width: w,
        height,
    };
    let header = row(area.y, 1);
    let body = row(area.y + 2, area.height - 5);
    let message = row(area.bottom() - 3, 2);
    let footer = row(area.bottom() - 1, 1);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("payneteasy", theme::bold()),
            Span::styled(" · Secrets", theme::secondary()),
        ])),
        header,
    );
    let title = screen_title(app);
    f.render_widget(
        Paragraph::new(Span::styled(title, theme::bold()))
            .alignment(ratatui::layout::Alignment::Right),
        header,
    );

    match &app.screen {
        Screen::Home { selected } => render_home(f, body, *selected, &mut hits),
        Screen::New(form) => render_new(f, body, form, app.limit, &mut hits),
        Screen::Created(v) => render_created(f, body, v, &mut hits),
        Screen::Open(form) => render_link_form(
            f,
            body,
            form,
            "Paste the recipient link you received (…/s/…).",
            "Checking the link sends nothing; the secret opens only when you reveal it.",
            &mut hits,
        ),
        Screen::StatusForm(form) => render_link_form(
            f,
            body,
            form,
            "Paste your private sender link (…/o/…).",
            "Checking the status does not open the secret.",
            &mut hits,
        ),
        Screen::Reveal(v) => render_reveal(f, body, v, &mut hits),
        Screen::Unlock(v) => render_unlock(f, body, v, &mut hits),
        Screen::Revealed(v) => render_revealed(f, body, v, &mut hits),
        Screen::Status(v) => render_status(f, body, v, &mut hits),
    }
    if let Some((is_error, m)) = &app.message {
        let style = if *is_error {
            theme::danger_text()
        } else {
            theme::secondary()
        };
        f.render_widget(
            Paragraph::new(m.as_str())
                .style(style)
                .wrap(Wrap { trim: true }),
            message,
        );
    }
    f.render_widget(Paragraph::new(hints(app)).style(theme::secondary()), footer);
    if let Some(d) = &app.dialog {
        let files = match &app.screen {
            Screen::Revealed(v) => v.files().len(),
            _ => 0,
        };
        render_dialog(f, body, d, files, &mut hits);
    }
    *app.hits.borrow_mut() = hits;
}

/// The window is too small: say so; the screen behind keeps its state.
fn render_small(app: &App, f: &mut Frame, area: Rect) {
    let mut lines = vec![
        Line::styled("Enlarge the window", theme::bold()),
        Line::raw(format!(
            "to at least {MIN_W}×{MIN_H} (now {}×{}).",
            area.width, area.height
        )),
        Line::styled("Your input is kept.", theme::secondary()),
    ];
    if let Some(d) = &app.dialog {
        lines.push(Line::styled(d.title(), theme::danger_text()));
    }
    let h = lines.len() as u16;
    let r = Rect {
        y: area.y + area.height.saturating_sub(h) / 2,
        height: h.min(area.height),
        ..area
    };
    f.render_widget(
        Paragraph::new(lines)
            .alignment(ratatui::layout::Alignment::Center)
            .wrap(Wrap { trim: true }),
        r,
    );
}

fn render_home(f: &mut Frame, area: Rect, selected: usize, hits: &mut Hits) {
    const NOTES: [&str; 4] = [
        "encrypt text or files, get a one-time link",
        "reveal a secret someone sent you",
        "see whether your secret was opened, or revoke it",
        "",
    ];
    let mut col = Col::new(area);
    col.line(
        f,
        Line::styled(
            "One-time secrets, encrypted on this machine.",
            theme::secondary(),
        ),
    );
    col.take(1);
    for (i, item) in HOME_ITEMS.iter().enumerate() {
        let on = i == selected;
        let (mark, style) = if on {
            (
                "> ",
                theme::accent_text().add_modifier(ratatui::style::Modifier::BOLD),
            )
        } else {
            ("  ", theme::text())
        };
        let r = col.line(
            f,
            Line::from(vec![
                Span::styled(format!("{mark}{item:<14}"), style),
                Span::styled(NOTES[i], theme::secondary()),
            ]),
        );
        hits.push((r, Hit::Home(i)));
    }
}

fn render_new(f: &mut Frame, area: Rect, form: &NewForm, limit: Option<usize>, hits: &mut Hits) {
    let order = form.order();
    let idx = |x: NewFocus| order.iter().position(|o| *o == x);
    let on = |x: NewFocus| form.focus == x;
    let buttons = [
        Button::new(
            "Create one-time link",
            "Ctrl+S",
            Action::Create,
            Role::Primary,
        ),
        Button::new("Back", "Esc", Action::Back, Role::Secondary),
    ];
    let brows = button_rows(area.width, &buttons);
    let nfiles = form.files.len() as u16;
    // Rows: the add row, the summary, the lifetime, the switch, the passphrase and its hint, the
    // buttons; the editor (at least 3 lines) and at least one file row; then what is left goes to
    // blank lines, more file rows and a taller editor.
    let fixed = 4 + if form.use_pass { 2 } else { 0 } + brows;
    let mut room = area.height.saturating_sub(fixed + 5 + nfiles.min(1));
    let near = room.min(2);
    room -= near;
    let extra_files = (nfiles.min(6).saturating_sub(1)).min(room);
    room -= extra_files;
    let far = room.min(2);
    room -= far;
    // A taller window gets a taller editor (not one that grows while typing).
    let extra_editor = room.min(7);
    let near = spacers(near, 2);
    let far = spacers(far, 2);

    let mut col = Col::new(area);
    let editor = col.take(5 + extra_editor);
    render_box_input(f, editor, "Secret", &form.text, on(NewFocus::Text));
    if form.text.text().is_empty() && !on(NewFocus::Text) {
        let inner = boxed("", false).inner(editor);
        f.render_widget(
            Paragraph::new(Span::styled(
                "Type or paste the secret: a password, a token, a note…",
                theme::secondary(),
            )),
            inner,
        );
    }
    hits.push((editor, Hit::Focus(NewFocus::Text)));
    if near[0] {
        col.take(1);
    }

    // Add a file [ path ] [ Add (Enter) ]
    let row = col.take(1);
    let add = Button::new("Add", "Enter", Action::AddFile, Role::Secondary);
    let field = render_line_input(
        f,
        Rect {
            width: row.width.saturating_sub(add.width() + 1),
            ..row
        },
        "Add a file",
        &form.path,
        on(NewFocus::Path),
    );
    hits.push((field, Hit::Focus(NewFocus::Path)));
    button_at(
        f,
        row.right().saturating_sub(add.width()),
        row.y,
        &add,
        on(NewFocus::Add),
        idx(NewFocus::Add),
        hits,
    );

    // The files: the selected one stays visible.
    let visible = (nfiles.min(1) + extra_files) as usize;
    if visible > 0 {
        let n = form.files.len();
        let mut top = form.file_top.get().min(n - visible);
        if form.file_sel < top {
            top = form.file_sel;
        } else if form.file_sel >= top + visible {
            top = form.file_sel + 1 - visible;
        }
        form.file_top.set(top);
        for (i, file) in form.files.iter().enumerate().skip(top).take(visible) {
            let r = col.take(1);
            let sel = on(NewFocus::Files) && i == form.file_sel;
            let remove = Button::new(
                "Remove",
                if sel { "Del" } else { "" },
                Action::RemoveFile(i),
                Role::Danger,
            );
            let size = human_size(file.size as usize);
            // "> name  size [ Remove ]": the mark, the name, two spaces, the size in 8 cells.
            let name_w = (r.width as usize).saturating_sub(remove.width() as usize + 13);
            let name = wrapped(&file.name, name_w.max(1)).next().unwrap_or("");
            let (mark, style) = if sel {
                ("> ", theme::bold())
            } else {
                ("  ", theme::text())
            };
            let line = Line::from(vec![
                Span::styled(mark, style),
                Span::styled(name, style),
                Span::raw(" ".repeat(name_w.saturating_sub(name.width()))),
                Span::styled(format!("  {size:>8}"), theme::secondary()),
            ]);
            f.render_widget(Paragraph::new(line), r);
            hits.push((
                Rect {
                    width: r.width.saturating_sub(remove.width() + 1),
                    ..r
                },
                Hit::Act(Action::SelectFile(i), None),
            ));
            button_at(
                f,
                r.right().saturating_sub(remove.width()),
                r.y,
                &remove,
                sel,
                None,
                hits,
            );
        }
    }

    // 2 of 20 files · Size 14 KB of 1 MB
    let sizes: Vec<(&str, usize)> = form
        .files
        .iter()
        .map(|p| (p.name.as_str(), p.size as usize))
        .collect();
    let size = format::plaintext_len(form.text.text(), &sizes);
    let mut spans = vec![Span::styled(
        format!(
            "{} of {} files · Size {}",
            form.files.len(),
            format::MAX_FILES,
            human_size(size)
        ),
        theme::secondary(),
    )];
    match limit {
        Some(l) if size > l => spans.push(Span::styled(
            format!(" of {}: too large", human_size(l)),
            theme::danger_text(),
        )),
        Some(l) => spans.push(Span::styled(
            format!(" of {}", human_size(l)),
            theme::secondary(),
        )),
        None => {}
    }
    if form.files.len() > visible {
        spans.push(Span::styled(" · ↑/↓ scroll the files", theme::secondary()));
    }
    col.line(f, Line::from(spans));
    if far[0] {
        col.take(1);
    }

    // Delete if unopened:  ( ) 1 hour  (*) 24 hours  ( ) 7 days
    let r = col.take(1);
    let label = "  Delete if unopened:";
    let label_style = if on(NewFocus::Ttl) {
        theme::bold()
    } else {
        theme::text()
    };
    let gutter = if on(NewFocus::Ttl) { "> " } else { "  " };
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("{gutter}{}", &label[2..]),
            label_style,
        )),
        r,
    );
    let mut x = r.x + label.width() as u16 + 1;
    for (i, (name, _)) in TTLS.iter().enumerate() {
        let chosen = i == form.ttl;
        let mark = if chosen { "(*)" } else { "( )" };
        let focused = chosen && on(NewFocus::Ttl);
        let text = if focused {
            format!("> {mark} {name} <")
        } else {
            format!("  {mark} {name}  ")
        };
        let style = if focused {
            theme::button(Role::Primary, true, true)
        } else if chosen {
            theme::accent_text()
        } else {
            theme::text()
        };
        let o = Rect {
            x,
            y: r.y,
            width: text.width() as u16,
            height: 1,
        };
        f.render_widget(Paragraph::new(Span::styled(text, style)), o);
        hits.push((o, Hit::Act(Action::SetTtl(i), None)));
        x += o.width;
    }
    if far[1] {
        col.take(1);
    }

    // [x] Protect with a passphrase
    let r = col.take(1);
    let check = Button::new(
        format!(
            "{} Protect with a passphrase",
            if form.use_pass { "[x]" } else { "[ ]" }
        ),
        "Space",
        Action::TogglePassphrase,
        Role::Secondary,
    );
    let focused = on(NewFocus::UsePass);
    let text = format!(
        "{} {} ({}){}",
        if focused { ">" } else { " " },
        check.label,
        check.key,
        if focused { " <" } else { "" }
    );
    let cr = Rect {
        width: (text.width() as u16).min(r.width),
        ..r
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            text,
            if focused {
                theme::button(Role::Secondary, true, true)
            } else {
                theme::text()
            },
        )),
        cr,
    );
    hits.push((
        cr,
        Hit::Act(Action::TogglePassphrase, idx(NewFocus::UsePass)),
    ));

    if form.use_pass {
        let row = col.take(1);
        let generate = Button::new(
            "Generate",
            "Ctrl+G",
            Action::GeneratePassphrase,
            Role::Secondary,
        );
        let field = render_line_input(
            f,
            Rect {
                x: row.x + 4,
                width: row.width.saturating_sub(generate.width() + 5),
                ..row
            },
            "Passphrase",
            &form.pass,
            on(NewFocus::Pass),
        );
        hits.push((field, Hit::Focus(NewFocus::Pass)));
        button_at(
            f,
            row.right().saturating_sub(generate.width()),
            row.y,
            &generate,
            on(NewFocus::Generate),
            idx(NewFocus::Generate),
            hits,
        );
        let r = col.take(1);
        f.render_widget(
            Paragraph::new(Span::styled(
                if form.generated {
                    "    Generated. Send it separately, through a different channel."
                } else {
                    "    Send it separately, through a different channel."
                },
                theme::secondary(),
            )),
            r,
        );
    }
    if near[1] {
        col.take(1);
    }
    let first = idx(NewFocus::Create).unwrap_or(0);
    let focus = idx(form.focus);
    buttons_row(f, col.take(brows), &buttons, focus, first, hits);
}

/// A link in a box, wrapped by characters; returns its rows.
fn link_box(f: &mut Frame, col: &mut Col, title: &str, link: &str, style: Style) {
    let inner_w = col.area.width.saturating_sub(4).max(1) as usize;
    let rows: Vec<Line> = wrapped(link, inner_w)
        // Spans borrow the link: no unwiped copies of the key or the token.
        .map(|l| Line::from(vec![Span::raw(" "), Span::styled(l, style)]))
        .collect();
    let r = col.take(rows.len() as u16 + 2);
    f.render_widget(Paragraph::new(rows).block(boxed(title, false)), r);
}

fn link_box_rows(width: u16, link: &str) -> u16 {
    wrapped(link, width.saturating_sub(4).max(1) as usize).count() as u16 + 2
}

fn render_created(f: &mut Frame, area: Rect, v: &CreatedView, hits: &mut Hits) {
    let buttons = created_buttons(v);
    let at = |a: Action| buttons.iter().position(|b| b.action == a);
    let focus = |a: Action| at(a) == Some(v.focus);
    let info = 2 + u16::from(v.passphrase);
    let mut need = 1 + link_box_rows(area.width, &v.recipient) + 1 + info + 1 + 1;
    if v.show_owner {
        need += link_box_rows(area.width, &v.owner) + 1;
    }
    let sp = spacers(area.height.saturating_sub(need), 3);

    let mut col = Col::new(area);
    col.line(f, Line::styled("Recipient link — send this", theme::bold()));
    link_box(f, &mut col, "", &v.recipient, theme::accent_text());
    let r = col.take(1);
    let copy = &buttons[at(Action::CopyRecipient).unwrap_or(0)];
    button_at(f, r.x, r.y, copy, focus(copy.action), at(copy.action), hits);
    if sp[0] {
        col.take(1);
    }
    col.line(
        f,
        Line::styled(
            "Opens once, then it is destroyed. Whoever opens it first can read it.",
            theme::secondary(),
        ),
    );
    col.line(
        f,
        Line::from(vec![
            Span::styled("Deleted if unopened: ", theme::secondary()),
            Span::raw(human_time(&v.expires)),
        ]),
    );
    if v.passphrase {
        col.line(
            f,
            Line::styled(
                "Send the passphrase separately, through a different channel.",
                theme::secondary(),
            ),
        );
    }
    if sp[1] {
        col.take(1);
    }
    // [+] Only for you: track or revoke (o)
    let r = col.take(1);
    let i = at(Action::ToggleOwner);
    let focused = i == Some(v.focus);
    let text = format!(
        "{}{} Only for you: track or revoke (o){}",
        if focused { "> " } else { "" },
        if v.show_owner { "[-]" } else { "[+]" },
        if focused { " <" } else { "" }
    );
    let tr = Rect {
        width: (text.width() as u16).min(r.width),
        ..r
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            text,
            if focused {
                theme::button(Role::Secondary, true, true)
            } else {
                theme::text()
            },
        )),
        tr,
    );
    hits.push((tr, Hit::Act(Action::ToggleOwner, i)));
    if v.show_owner {
        link_box(
            f,
            &mut col,
            "Private sender link — do not send",
            &v.owner,
            theme::text(),
        );
        let r = col.take(1);
        if let Some(i) = at(Action::CopyOwner) {
            button_at(f, r.x, r.y, &buttons[i], v.focus == i, Some(i), hits);
        }
    }
    if sp[2] {
        col.take(1);
    }
    let first = at(Action::NewSecret).unwrap_or(0);
    buttons_row(
        f,
        col.take(1),
        &buttons[first..],
        Some(v.focus),
        first,
        hits,
    );
}

fn render_link_form(
    f: &mut Frame,
    area: Rect,
    form: &LinkForm,
    prompt: &str,
    note: &str,
    hits: &mut Hits,
) {
    let mut col = Col::new(area);
    col.text(f, prompt, theme::bold());
    col.take(1);
    let field = render_line_input(f, col.take(1), "Link", &form.input, form.focus == 0);
    hits.push((field, Hit::Field));
    col.text(f, note, theme::secondary());
    col.take(1);
    buttons_row(
        f,
        col.take(2),
        &link_form_buttons(),
        Some(form.focus),
        1,
        hits,
    );
}

fn render_reveal(f: &mut Frame, area: Rect, v: &RevealView, hits: &mut Hits) {
    let mut col = Col::new(area);
    col.text(f, "Someone shared a secret with you", theme::bold());
    col.text(
        f,
        "Revealing deletes it from the server: it opens only once. Be ready to copy or save it.",
        theme::danger_text(),
    );
    col.text(
        f,
        "Not expecting it? Do not open it; tell the sender.",
        theme::secondary(),
    );
    col.take(1);
    let has_field = v.link.passphrase_hint;
    if has_field {
        let field = render_line_input(f, col.take(1), "Passphrase", &v.pass, v.focus == 0);
        hits.push((field, Hit::Field));
        col.text(
            f,
            "The link says this secret has a passphrase; the sender sends it separately.",
            theme::secondary(),
        );
        col.take(1);
    }
    buttons_row(
        f,
        col.take(2),
        &reveal_buttons(),
        Some(v.focus),
        usize::from(has_field),
        hits,
    );
}

fn render_unlock(f: &mut Frame, area: Rect, v: &UnlockView, hits: &mut Hits) {
    let mut col = Col::new(area);
    col.text(f, "Enter the passphrase", theme::bold());
    col.text(
        f,
        "The secret is downloaded and deleted from the server. It exists only here now; discarding destroys it.",
        theme::danger_text(),
    );
    col.take(1);
    let field = render_line_input(f, col.take(1), "Passphrase", &v.pass, v.focus == 0);
    hits.push((field, Hit::Field));
    col.take(1);
    buttons_row(f, col.take(2), &unlock_buttons(), Some(v.focus), 1, hits);
}

fn render_revealed(f: &mut Frame, area: Rect, v: &RevealedView, hits: &mut Hits) {
    let order = v.order();
    let focus_at = order.iter().position(|o| *o == v.focus);
    let buttons = revealed_buttons(v);
    let first = order
        .iter()
        .position(|o| *o == RevealedFocus::Button(0))
        .unwrap_or(0);
    let brows = button_rows(area.width, &buttons);
    let save_rows = if v.saving { 2 } else { 0 };
    let files = v.files();
    let has_text = !v.text().is_empty();
    let room = area.height.saturating_sub(brows + 1 + save_rows);
    let files_h = if files.is_empty() {
        0
    } else if has_text {
        (files.len() as u16 + 2)
            .min(8)
            .min(room.saturating_sub(5))
            .max(3)
    } else {
        room
    };
    let text_h = room.saturating_sub(files_h);

    let mut col = Col::new(area);
    if has_text {
        let r = col.take(text_h);
        let (w, h) = (
            r.width.saturating_sub(4).max(1) as usize,
            r.height.saturating_sub(2).max(1) as usize,
        );
        let total = wrapped(v.text(), w).count();
        let max = total.saturating_sub(h);
        v.max_scroll.set(max);
        let top = v.scroll.min(max);
        let title = if total > h {
            format!(
                "Secret · lines {}–{} of {total}",
                top + 1,
                (top + h).min(total)
            )
        } else {
            "Secret".into()
        };
        let lines: Vec<Line> = wrapped(v.text(), w)
            .skip(top)
            .take(h)
            // Borrowed from the secret: no unwiped copies.
            .map(|l| Line::from(vec![Span::raw(" "), Span::raw(l)]))
            .collect();
        f.render_widget(
            Paragraph::new(lines).block(boxed(&title, v.focus == RevealedFocus::Text)),
            r,
        );
        hits.push((r, Hit::RevealedText));
    }
    if !files.is_empty() {
        let r = col.take(files_h);
        let h = r.height.saturating_sub(2) as usize;
        let max = files.len().saturating_sub(h);
        v.max_file_top.set(max);
        let top = v.file_top.min(max);
        let total: usize = files.iter().map(|(_, s)| s).sum();
        let saved = match &v.saved {
            Some(dir) => format!("Saved to {dir}"),
            None => "Not saved".into(),
        };
        let mut title = format!(
            "{} file{} · {} · {saved}",
            files.len(),
            if files.len() == 1 { "" } else { "s" },
            human_size(total)
        );
        if files.len() > h {
            title.push_str(&format!(" · {}–{}", top + 1, (top + h).min(files.len())));
        }
        let name_w = r.width.saturating_sub(16) as usize;
        // File names are part of the secret: the printable copies are wiped, the spans borrow them.
        let shown: Vec<(Zeroizing<String>, usize)> = files
            .iter()
            .skip(top)
            .take(h)
            .map(|(n, s)| (shown_name(n), *s))
            .collect();
        let lines: Vec<Line> = shown
            .iter()
            .map(|(n, s)| {
                let name = wrapped(n, name_w.max(1)).next().unwrap_or("");
                Line::from(vec![
                    Span::raw(" "),
                    Span::raw(name),
                    Span::raw(" ".repeat(name_w.saturating_sub(name.width()))),
                    Span::styled(format!(" {:>10}", human_size(*s)), theme::secondary()),
                ])
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines).block(boxed(&title, v.focus == RevealedFocus::Files)),
            r,
        );
        hits.push((r, Hit::RevealedFiles));
    }
    if v.saving {
        let field = render_line_input(
            f,
            col.take(1),
            "Save into a new directory",
            &v.dir,
            v.focus == RevealedFocus::Dir,
        );
        hits.push((field, Hit::Field));
        col.line(
            f,
            Line::styled(
                format!("Leave it empty for ./sdrop-{}", &v.id[..8.min(v.id.len())]),
                theme::secondary(),
            ),
        );
    }
    col.take(1);
    buttons_row(f, col.take(brows), &buttons, focus_at, first, hits);
}

/// A received file name for the screen: control characters as `?`, in a buffer reserved up front
/// (a replacement is never longer than the character), so no reallocation leaves copies.
fn shown_name(name: &str) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(name.len()));
    for c in name.chars() {
        s.push(if c.is_control() { '?' } else { c });
    }
    s
}

fn render_status(f: &mut Frame, area: Rect, v: &StatusView, hits: &mut Hits) {
    let s = &v.status;
    let (state, style) = match s.state.as_str() {
        "stored" => ("Waiting to be opened", theme::accent_text()),
        "consumed" => ("Opened", theme::ok_text()),
        "revoked" => ("Revoked", theme::danger_text()),
        other => (other, theme::text()),
    };
    let row = |k: &str, val: Span<'static>| {
        Line::from(vec![
            Span::styled(format!("{k:<22}"), theme::secondary()),
            val,
        ])
    };
    let mut col = Col::new(area);
    col.line(
        f,
        row(
            "State",
            Span::styled(
                state.to_string(),
                style.add_modifier(ratatui::style::Modifier::BOLD),
            ),
        ),
    );
    col.line(f, row("Created", Span::raw(human_time(&s.created))));
    if s.state == "stored" {
        col.line(
            f,
            row("Deleted if unopened", Span::raw(human_time(&s.expires))),
        );
    }
    if let Some(at) = &s.consumed_at {
        let by = s
            .consumed_by
            .as_deref()
            .map(|b| format!(" by {b}"))
            .unwrap_or_default();
        col.line(
            f,
            row("Opened", Span::raw(format!("{}{by}", human_time(at)))),
        );
    }
    col.take(1);
    buttons_row(f, col.take(2), &status_buttons(v), Some(v.focus), 0, hits);
}

/// A dialog over the card; only its buttons take clicks.
fn render_dialog(f: &mut Frame, body: Rect, d: &Dialog, files: usize, hits: &mut Hits) {
    let buttons = d.buttons();
    let w = 60.min(body.width);
    let lines = d.lines(files);
    let inner_w = w - 4;
    let brows = button_rows(inner_w, &buttons);
    let h = lines.len() as u16 + brows + 3;
    let r = Rect {
        x: body.x + (body.width - w) / 2,
        y: body.y + body.height.saturating_sub(h) / 3,
        width: w,
        height: h.min(body.height),
    };
    f.render_widget(Clear, r);
    let block = boxed(d.title(), true);
    let inner = block.inner(r);
    f.render_widget(block, r);
    let inner = Rect {
        x: inner.x + 1,
        width: inner.width.saturating_sub(2),
        ..inner
    };
    let mut col = Col::new(inner);
    for l in &lines {
        col.line(f, Line::raw(l.clone()));
    }
    col.take(1);
    let area = col.take(brows);
    for (i, (br, b)) in layout_buttons(area, &buttons)
        .into_iter()
        .zip(&buttons)
        .enumerate()
    {
        render_button(f, br, b, i == d.focus);
        hits.push((br, Hit::Act(b.action, None)));
    }
}
