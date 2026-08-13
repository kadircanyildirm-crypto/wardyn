// SPDX-License-Identifier: AGPL-3.0-or-later
//! Live ratatui terminal UI: a scrolling event feed coloured by policy verdict
//! (allow = grey, warn = yellow, block = red/bold, excepted = cyan, notice =
//! blue) with a counter header — plus approve-once exceptions: under
//! `--enforce`, `a` offers to allow the last kernel denial, the confirm prompt
//! states the TRUE blast radius (the kernel matches bare names/addresses, so an
//! exception can't be narrower), and `y` updates the kernel maps and the
//! userspace mirror together, so the feed never claims a denial the kernel
//! stopped making.
//!
//! The terminal is restored by a guard, not by the happy path: every `?` in here
//! used to return before the restore sequence, leaving the operator in raw mode
//! inside the alternate screen with no prompt.
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{
    event::{self, Event as CtEvent, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};
use tokio::io::unix::AsyncFd;
use tokio::process::Child;
use wardyn_common::kind;
use wardyn_policy::policy::{Action, DenialKey, Exceptions};

use crate::{drain, notice_row, prune_watched, wait_for, Desc, RunCtx, StatSnapshot};

const MAX_ROWS: usize = 4096;

struct App {
    target: String,
    enforce: bool,
    rows: VecDeque<Desc>,
    exec: u64,
    open: u64,
    connect: u64,
    warn: u64,
    block: u64,
    denied: u64,
    granted: u64,
    stats: StatSnapshot,
    /// The most recent kernel denial (key + the rule that produced it) — what
    /// `a` offers to except.
    last_denial: Option<(DenialKey, String)>,
    /// A pending approve-once confirmation, waiting for y/n.
    confirm: Option<DenialKey>,
    /// Whether that confirmation has actually been drawn. A pre-typed `a`+`y`
    /// arriving in one batch must not grant an exception whose blast-radius
    /// prompt the operator never saw.
    confirm_shown: bool,
}

impl App {
    fn new(target: String, enforce: bool) -> Self {
        Self {
            target,
            enforce,
            rows: VecDeque::new(),
            exec: 0,
            open: 0,
            connect: 0,
            warn: 0,
            block: 0,
            denied: 0,
            granted: 0,
            stats: StatSnapshot::default(),
            last_denial: None,
            confirm: None,
            confirm_shown: false,
        }
    }

    fn push(&mut self, d: Desc) {
        if !d.notice {
            match d.kind {
                kind::EXEC | kind::DENY_EXEC => self.exec += 1,
                kind::OPEN | kind::DENY_FILE => self.open += 1,
                kind::CONNECT | kind::DENY_NET => self.connect += 1,
                _ => {}
            }
            match d.action {
                Action::Warn => self.warn += 1,
                Action::Block => self.block += 1,
                Action::Allow => {}
            }
            if d.denied(self.enforce) {
                self.denied += 1;
                if let Some(key) = &d.denial_key {
                    self.last_denial = Some((key.clone(), d.rule.clone()));
                }
            }
        }
        self.rows.push_back(d);
        while self.rows.len() > MAX_ROWS {
            self.rows.pop_front();
        }
    }

    fn draw(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(f.area());

        let mut spans = vec![
            Span::styled(
                " 🐕 wardyn ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {}    ", self.target)),
            Span::styled(
                format!("exec {}", self.exec),
                Style::default().fg(Color::Gray),
            ),
            Span::raw("  "),
            Span::styled(
                format!("open {}", self.open),
                Style::default().fg(Color::Gray),
            ),
            Span::raw("  "),
            Span::styled(
                format!("connect {}", self.connect),
                Style::default().fg(Color::Gray),
            ),
            Span::raw("    "),
            Span::styled(
                format!("⚠ warn {}", self.warn),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("⛔ block {}", self.block),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("denied {}", self.denied),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ];
        if self.enforce {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("✔ excep {}", self.granted),
                Style::default().fg(Color::Cyan),
            ));
        }
        // Losses are not decoration: a dropped event has no feed row, no audit
        // record and no receipt line, and a full watch set means whole child
        // processes ran unobserved. Both belong next to the counters they
        // invalidate.
        if self.stats.ring_drops > 0 {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("‼ DROPPED {}", self.stats.ring_drops),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        if self.stats.watch_full > 0 {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("‼ WATCH-SET FULL {}", self.stats.watch_full),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        let header = Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).title(" Wardyn "));
        f.render_widget(header, chunks[0]);

        let visible = chunks[1].height.saturating_sub(2) as usize;
        let start = self.rows.len().saturating_sub(visible);
        let enforce = self.enforce;
        let rows = self.rows.iter().skip(start).map(|d| {
            // Bold red = actually denied; plain red = block-class but not
            // enforced; cyan = allowed under an operator exception; blue = a
            // wardyn notice rather than an observed action.
            let (fg, modifier) = if d.notice {
                (Color::Blue, Modifier::empty())
            } else if d.excepted {
                (Color::Cyan, Modifier::empty())
            } else {
                match d.action {
                    Action::Block if d.denied(enforce) => (Color::Red, Modifier::BOLD),
                    Action::Block => (Color::Red, Modifier::empty()),
                    Action::Warn => (Color::Yellow, Modifier::empty()),
                    Action::Allow => (Color::Gray, Modifier::empty()),
                }
            };
            Row::new(vec![
                Cell::from(if d.notice {
                    String::new()
                } else {
                    d.pid.to_string()
                }),
                Cell::from(d.comm_display()),
                Cell::from(d.label),
                Cell::from(d.act(enforce)),
                Cell::from(d.shown()),
            ])
            .style(Style::default().fg(fg).add_modifier(modifier))
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(7),
                Constraint::Length(15),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(vec!["PID", "COMM", "EVENT", "ACT", "DETAIL"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(table, chunks[1]);

        // Footer: a pending confirmation replaces the key hints, and states the
        // honest blast radius — never "allow this file", which the kernel's
        // bare-name matching couldn't deliver.
        let footer = if let Some(key) = &self.confirm {
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " ⚠ ALLOW ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    " {} — for the rest of this run?  ",
                    key.blast_radius()
                )),
                Span::styled(" y ", Style::default().fg(Color::Black).bg(Color::Green)),
                Span::raw(" confirm  "),
                Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" cancel"),
            ]))
        } else {
            let mut spans = vec![
                Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" quit (stops the agent)"),
            ];
            if self.enforce {
                spans.push(Span::raw("   "));
                spans.push(Span::styled(
                    " a ",
                    Style::default().fg(Color::Black).bg(Color::Gray),
                ));
                let hint = match &self.last_denial {
                    Some((key, _)) => format!(" allow last denial ({key})"),
                    None => " allow last denial".to_string(),
                };
                spans.push(Span::raw(hint));
            }
            Paragraph::new(Line::from(spans))
        };
        f.render_widget(footer, chunks[2]);
    }
}

/// Apply an approved exception everywhere it must land at once: the kernel
/// map (stop denying), the userspace mirror (stop claiming denials), the
/// audit log (the override is part of the security record), and the agent's
/// receipt (it may retry now). A row in the feed shows what was granted.
fn grant(app: &mut App, ctx: &mut RunCtx<'_>, exceptions: &mut Exceptions, key: DenialKey) {
    match ctx.maps.apply_exception(&key) {
        Ok(()) => {
            exceptions.grant(key.clone());
            ctx.audit
                .record_exception(&key.to_string(), &key.blast_radius());
            if let Some(r) = ctx.receipt.as_deref_mut() {
                let _ = r.record_exception(&key.to_string(), &key.blast_radius());
            }
            app.granted += 1;
            app.last_denial = None;
            app.push(exception_row(&key));
        }
        // A failure here is an internal error, not a policy verdict: it must not
        // inflate the warn counter the operator is reading.
        Err(e) => app.push(notice_row(&format!(
            "FAILED to apply exception {key}: {e:#} — the kernel is still denying it"
        ))),
    }
}

/// Synthetic feed row announcing an exception grant.
fn exception_row(key: &DenialKey) -> Desc {
    Desc {
        pid: 0,
        comm: "operator".into(),
        kind: u32::MAX - 1,
        label: "except",
        detail: format!("now allowed: {}", key.blast_radius()),
        action: Action::Allow,
        rule: key.to_string(),
        enforceable: false,
        denial_key: None,
        excepted: true,
        kernel: false,
        notice: false,
    }
}

/// Restores the terminal on every exit path, including `?` and panics.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<TerminalGuard> {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            prev(info);
        }));
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(TerminalGuard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    let _ = execute!(io::stdout(), ratatui::crossterm::cursor::Show);
}

pub async fn run(
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    child: &mut Option<Child>,
    target: String,
    ctx: &mut RunCtx<'_>,
    notices: Vec<String>,
) -> Result<()> {
    let _guard = TerminalGuard::enter()?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let mut app = App::new(target, ctx.enforce);
    // Startup diagnostics as the first rows: printing them to stderr moments
    // before switching to the alternate screen meant nobody ever read them.
    for n in &notices {
        app.push(notice_row(n));
    }
    let mut exceptions = Exceptions::default();
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    // Prune WATCHED against /proc and refresh the kernel counters every ~2s
    // (20 × 100ms ticks).
    let mut sweeps: u32 = 0;
    let mut quit = false;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    while !quit {
        term.draw(|f| app.draw(f))?;
        if app.confirm.is_some() {
            app.confirm_shown = true;
        }
        tokio::select! {
            _ = sigterm.recv() => quit = true,
            _ = sighup.recv() => quit = true,
            _ = ticker.tick() => {
                sweeps += 1;
                if sweeps >= 20 {
                    sweeps = 0;
                    if let Some(m) = ctx.watched.as_mut() {
                        prune_watched(m);
                    }
                    if let Some(s) = ctx.stats.as_ref() {
                        app.stats = s.snapshot();
                    }
                }
                while event::poll(Duration::ZERO)? {
                    let CtEvent::Key(k) = event::read()? else { continue };
                    // crossterm reports press *and* release on some terminals;
                    // acting on both would double every keystroke.
                    if k.kind == KeyEventKind::Release {
                        continue;
                    }
                    let ctrl_c = k.code == KeyCode::Char('c')
                        && k.modifiers.contains(KeyModifiers::CONTROL);
                    if ctrl_c {
                        quit = true;
                    } else if let Some(key) = app.confirm.clone() {
                        // A confirmation is pending: only y / n / Esc count, and
                        // `y` only once the prompt has actually been rendered.
                        match k.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') if app.confirm_shown => {
                                app.confirm = None;
                                app.confirm_shown = false;
                                grant(&mut app, ctx, &mut exceptions, key);
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                                app.confirm = None;
                                app.confirm_shown = false;
                            }
                            _ => {}
                        }
                    } else {
                        match k.code {
                            KeyCode::Char('q') | KeyCode::Esc => quit = true,
                            KeyCode::Char('a') | KeyCode::Char('A') if ctx.enforce => {
                                if let Some((key, _)) = app.last_denial.clone() {
                                    if !exceptions.contains(&key) {
                                        app.confirm = Some(key);
                                        app.confirm_shown = false;
                                        // Stop draining this batch: anything
                                        // already buffered was typed before the
                                        // prompt existed and must not answer it.
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                drain(guard.get_inner_mut(), ctx, &exceptions, |d| app.push(d));
                guard.clear_ready();
            }
            _ = wait_for(child), if child.is_some() => quit = true,
        }
    }

    // Final sweep before tearing the terminal down: the child-exit branch can
    // win the select with events (a last secret read, a denied connect) still
    // queued in the ring. Drain + one last render so they are shown and audited.
    drain(async_fd.get_mut(), ctx, &exceptions, |d| app.push(d));
    if let Some(s) = ctx.stats.as_ref() {
        app.stats = s.snapshot();
    }
    term.draw(|f| app.draw(f))?;
    Ok(())
}
