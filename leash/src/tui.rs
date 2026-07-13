//! Live ratatui terminal UI: a scrolling event feed with per-type colours and a
//! counter header. Used when stdout is a real terminal.
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

use crate::{describe, parse_event, wait_for, Desc};

const MAX_ROWS: usize = 4096;

struct App {
    target: String,
    rows: VecDeque<Desc>,
    exec: u64,
    open: u64,
    connect: u64,
}

impl App {
    fn new(target: String) -> Self {
        Self {
            target,
            rows: VecDeque::new(),
            exec: 0,
            open: 0,
            connect: 0,
        }
    }

    fn push(&mut self, d: Desc) {
        match d.kind {
            kind::EXEC => self.exec += 1,
            kind::OPEN => self.open += 1,
            kind::CONNECT => self.connect += 1,
            _ => {}
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

        // header with counters
        let header = Paragraph::new(Line::from(vec![
            Span::styled(
                " 🐕 leash ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {}    ", self.target)),
            Span::styled(format!("exec {}", self.exec), Style::default().fg(Color::Cyan)),
            Span::raw("   "),
            Span::styled(format!("open {}", self.open), Style::default().fg(Color::Yellow)),
            Span::raw("   "),
            Span::styled(
                format!("connect {}", self.connect),
                Style::default().fg(Color::Magenta),
            ),
        ]))
        .block(Block::default().borders(Borders::ALL).title(" Leash "));
        f.render_widget(header, chunks[0]);

        // event table — show the last rows that fit
        let visible = chunks[1].height.saturating_sub(2) as usize; // borders + header row
        let start = self.rows.len().saturating_sub(visible);
        let rows = self.rows.iter().skip(start).map(|d| {
            let color = match d.kind {
                kind::EXEC => Color::Cyan,
                kind::OPEN => Color::Yellow,
                kind::CONNECT => Color::Magenta,
                _ => Color::White,
            };
            Row::new(vec![
                Cell::from(d.pid.to_string()),
                Cell::from(d.comm.clone()),
                Cell::from(Span::styled(
                    d.label,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(d.detail.clone()),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(16),
                Constraint::Length(9),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(vec!["PID", "COMM", "EVENT", "DETAIL"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(table, chunks[1]);

        // footer
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
            Span::raw(" quit"),
        ]));
        f.render_widget(footer, chunks[2]);
    }
}

/// Restore the terminal from the alternate screen even if we panic mid-draw, so
/// a crash never leaves the user's shell in raw mode.
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
) -> Result<()> {
    install_panic_hook();
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;

    let mut app = App::new(target);
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
                    if let Some(d) = parse_event(&item).as_ref().and_then(describe) {
                        app.push(d);
                    }
                }
                guard.clear_ready();
            }
            _ = wait_for(&mut child), if child.is_some() => {
                // target finished — draw the final frame, then exit.
                quit = true;
            }
        }
    }

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}
