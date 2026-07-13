// SPDX-License-Identifier: MIT OR Apache-2.0
//! Live ratatui terminal UI: a scrolling event feed coloured by policy verdict
//! (allow = grey, warn = yellow, block = red/bold) with a counter header.
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use leash_common::kind;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{
    event::{self, Event as CtEvent, KeyCode, KeyModifiers},
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

use crate::audit::Audit;
use crate::policy::{Action, Policy};
use crate::{describe, parse_event, wait_for, Desc};

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
        }
    }

    fn push(&mut self, d: Desc) {
        match d.kind {
            kind::EXEC => self.exec += 1,
            kind::OPEN => self.open += 1,
            kind::CONNECT => self.connect += 1,
            _ => {}
        }
        match d.action {
            Action::Warn => self.warn += 1,
            Action::Block => self.block += 1,
            Action::Allow => {}
        }
        if d.denied(self.enforce) {
            self.denied += 1;
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

        let header = Paragraph::new(Line::from(vec![
            Span::styled(
                " 🐕 leash ",
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
        ]))
        .block(Block::default().borders(Borders::ALL).title(" Leash "));
        f.render_widget(header, chunks[0]);

        let visible = chunks[1].height.saturating_sub(2) as usize;
        let start = self.rows.len().saturating_sub(visible);
        let enforce = self.enforce;
        let rows = self.rows.iter().skip(start).map(|d| {
            // Bold red = actually denied; plain red = block-class but not enforced.
            let (fg, modifier) = match d.action {
                Action::Block if d.denied(enforce) => (Color::Red, Modifier::BOLD),
                Action::Block => (Color::Red, Modifier::empty()),
                Action::Warn => (Color::Yellow, Modifier::empty()),
                Action::Allow => (Color::Gray, Modifier::empty()),
            };
            Row::new(vec![
                Cell::from(d.pid.to_string()),
                Cell::from(d.comm.clone()),
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

        let footer = Paragraph::new(Line::from(vec![
            Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
            Span::raw(" quit"),
        ]));
        f.render_widget(footer, chunks[2]);
    }
}

/// Restore the terminal even if we panic mid-draw.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        prev(info);
    }));
}

pub async fn run(
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    mut child: Option<Child>,
    target: String,
    policy: &Policy,
    audit: &mut Audit,
    enforce: bool,
) -> Result<()> {
    install_panic_hook();
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;

    let mut app = App::new(target, enforce);
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    let mut quit = false;

    while !quit {
        term.draw(|f| app.draw(f))?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => quit = true,
            _ = ticker.tick() => {
                while event::poll(Duration::ZERO)? {
                    if let CtEvent::Key(k) = event::read()? {
                        let ctrl_c = k.code == KeyCode::Char('c')
                            && k.modifiers.contains(KeyModifiers::CONTROL);
                        if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                            quit = true;
                        }
                    }
                }
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    if let Some(d) = parse_event(&item).as_ref().and_then(|ev| describe(ev, policy)) {
                        if d.action != Action::Allow {
                            let _ = audit.record(
                                d.pid, &d.comm, d.label, &d.detail, d.action, &d.rule, d.denied(enforce),
                            );
                        }
                        app.push(d);
                    }
                }
                guard.clear_ready();
            }
            _ = wait_for(&mut child), if child.is_some() => quit = true,
        }
    }

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}
