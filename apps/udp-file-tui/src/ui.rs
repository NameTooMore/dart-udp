use std::{
    collections::BTreeMap,
    io::{self, Stdout},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use crate::{config::UiConfigFile, error::AppError};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap},
};
use tokio::sync::mpsc;
use transfer_client::{
    ResumeSession, ResumeTicket, TransferEvent, TransferHandle, TransferRole, TransferSummary,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeAction {
    Send,
    Receive,
    Resume,
    Quit,
}

#[derive(Debug, Clone)]
pub struct ResumeItem {
    pub session: ResumeSession,
    pub ticket: Option<ResumeTicket>,
    pub ticket_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeAction {
    Back,
    Resume(usize),
    Clean(usize),
}

pub fn home_screen(config: &UiConfigFile) -> Result<HomeAction, AppError> {
    let mut terminal = TerminalSession::new()?;
    let tick = refresh_duration(config.refresh_hz);
    loop {
        terminal.terminal.draw(|frame| {
            let area = frame.area();
            let accent = accent_style(config.color);
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(6),
                    Constraint::Length(3),
                ])
                .split(area);
            frame.render_widget(
                Paragraph::new("UDP File Transfer")
                    .style(accent)
                    .block(Block::default().borders(Borders::ALL).title("UDP 文件传输")),
                layout[0],
            );
            let items = [
                ListItem::new("[s] 创建配对并发送文件"),
                ListItem::new("[r] 输入配对码并接收文件"),
                ListItem::new("[u] 查看未完成传输状态"),
                ListItem::new("[q] 退出"),
            ];
            frame.render_widget(
                List::new(items).block(Block::default().borders(Borders::ALL).title("主页")),
                layout[1],
            );
            frame.render_widget(
                Paragraph::new("配对码只显示在终端，不会写入配置文件或日志。")
                    .wrap(Wrap { trim: true })
                    .block(Block::default().borders(Borders::ALL).title("安全提示")),
                layout[2],
            );
        })?;
        if event::poll(tick)?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('s') | KeyCode::Char('S') => return Ok(HomeAction::Send),
                KeyCode::Char('r') | KeyCode::Char('R') => return Ok(HomeAction::Receive),
                KeyCode::Char('u') | KeyCode::Char('U') => return Ok(HomeAction::Resume),
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                    return Ok(HomeAction::Quit);
                }
                _ => {}
            }
        }
    }
}

pub fn resume_screen(
    config: &UiConfigFile,
    items: &[ResumeItem],
) -> Result<ResumeAction, AppError> {
    let mut terminal = TerminalSession::new()?;
    let tick = refresh_duration(config.refresh_hz);
    let mut selected = 0_usize;
    let mut message = if items.is_empty() {
        "没有发现未完成的传输状态。按 Esc 返回主页。".to_owned()
    } else {
        "Enter 恢复，d 清理，Esc 返回".to_owned()
    };
    loop {
        terminal.terminal.draw(|frame| {
            let area = frame.area();
            let accent = accent_style(config.color);
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(6),
                    Constraint::Length(3),
                ])
                .split(area);
            frame.render_widget(
                Paragraph::new("选择要继续的传输")
                    .style(accent)
                    .block(Block::default().borders(Borders::ALL).title("断点恢复")),
                layout[0],
            );

            let list = items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let marker = if index == selected { ">" } else { " " };
                    let role = item
                        .ticket
                        .as_ref()
                        .map(|ticket| match ticket.role() {
                            TransferRole::Offerer => "发送",
                            TransferRole::Accepter => "接收",
                        })
                        .unwrap_or("未知");
                    let status = match (&item.ticket, &item.ticket_error) {
                        (Some(ticket), _) if ticket.is_expired() => "ticket 已过期",
                        (Some(_), _) => "可恢复",
                        (None, Some(error)) => error.as_str(),
                        (None, None) => "ticket 不可用",
                    };
                    let line = format!(
                        "{marker} {}  {role}  checkpoint={}  临时数据={}  {status}",
                        item.session.transfer_id,
                        item.session.state_files,
                        format_bytes(item.session.partial_bytes),
                    );
                    let style = if index == selected {
                        accent
                    } else {
                        Style::default()
                    };
                    ListItem::new(line).style(style)
                })
                .collect::<Vec<_>>();
            frame.render_widget(
                List::new(list).block(Block::default().borders(Borders::ALL).title("未完成传输")),
                layout[1],
            );
            frame.render_widget(
                Paragraph::new(message.as_str())
                    .wrap(Wrap { trim: true })
                    .block(Block::default().borders(Borders::ALL)),
                layout[2],
            );
        })?;

        if event::poll(tick)?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if !items.is_empty() {
                        selected = selected.saturating_sub(1);
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !items.is_empty() {
                        selected = (selected + 1).min(items.len() - 1);
                    }
                }
                KeyCode::Enter => {
                    if let Some(item) = items.get(selected) {
                        if item
                            .ticket
                            .as_ref()
                            .is_some_and(|ticket| !ticket.is_expired())
                        {
                            return Ok(ResumeAction::Resume(selected));
                        }
                        message = "当前条目没有可用的未过期 ticket。".to_owned();
                    }
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    if !items.is_empty() {
                        return Ok(ResumeAction::Clean(selected));
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                    return Ok(ResumeAction::Back);
                }
                _ => {}
            }
        }
    }
}

pub async fn run_transfer(
    handle: TransferHandle,
    title: String,
    known_total: Option<u64>,
    config: UiConfigFile,
    non_interactive: bool,
    json_output: bool,
    resume_root: std::path::PathBuf,
) -> Result<TransferSummary, AppError> {
    let ticket_handle = handle.clone();
    let sync_ticket_handle = handle.clone();
    let sync_resume_root = resume_root.clone();
    let ticket_saver = tokio::spawn(async move {
        if let Err(error) = ticket_handle.save_resume_ticket(resume_root).await {
            tracing::warn!(error = %error, "保存恢复 ticket 失败");
        }
    });
    let result = if non_interactive {
        run_text_transfer(handle, title, known_total, json_output).await
    } else {
        run_tui_transfer(handle, title, known_total, config).await
    };
    save_available_ticket(&sync_ticket_handle, &sync_resume_root);
    ticket_saver.abort();
    result
}

fn save_available_ticket(handle: &TransferHandle, root: &std::path::Path) {
    if let Some(ticket) = handle.try_resume_ticket()
        && let Err(error) = ticket.save_to(root)
    {
        tracing::warn!(error = %error, "保存恢复 ticket 失败");
    }
}

async fn run_text_transfer(
    handle: TransferHandle,
    title: String,
    known_total: Option<u64>,
    json_output: bool,
) -> Result<TransferSummary, AppError> {
    println!("{title}");
    if let Some(total) = known_total {
        println!("总大小：{}", format_bytes(total));
    }
    let mut events = handle.subscribe();
    let wait_handle = handle.clone();
    let wait = wait_handle.wait();
    tokio::pin!(wait);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut interrupted = false;
    loop {
        tokio::select! {
            result = &mut wait => {
                let summary = result?;
                if json_output {
                    print_json_summary(&summary);
                } else {
                    println!("传输完成：{} 个文件，{}，路径={:?}，relay={}", summary.completed_files, format_bytes(summary.total_size), summary.path_kind, summary.relay_used);
                }
                return Ok(summary);
            }
            event = events.recv() => {
                if let Ok(event) = event {
                    print_transfer_event(&event);
                }
            }
            _ = &mut ctrl_c, if !interrupted => {
                interrupted = true;
                println!("收到 Ctrl-C，正在取消传输……");
                let _ = handle.cancel().await;
            }
        }
    }
}

fn print_json_summary(summary: &TransferSummary) {
    println!(
        "{{\"transfer_id\":\"{}\",\"path_kind\":\"{:?}\",\"relay_used\":{},\"path_id\":null,\"bytes\":{},\"integrity\":\"ok\"}}",
        summary.transfer_id, summary.path_kind, summary.relay_used, summary.total_size
    );
}

async fn run_tui_transfer(
    handle: TransferHandle,
    title: String,
    known_total: Option<u64>,
    config: UiConfigFile,
) -> Result<TransferSummary, AppError> {
    let mut terminal = TerminalSession::new()?;
    let mut keys = KeyReader::spawn();
    let mut state = TransferView::new(title, known_total);
    let mut events = handle.subscribe();
    let wait_handle = handle.clone();
    let wait = wait_handle.wait();
    tokio::pin!(wait);
    let tick = refresh_duration(config.refresh_hz);
    let mut cancelled = false;
    let result = loop {
        terminal
            .terminal
            .draw(|frame| state.render(frame, config.color))?;
        tokio::select! {
            result = &mut wait => break result.map_err(AppError::from),
            event = events.recv() => {
                if let Ok(event) = event {
                    state.apply(event);
                }
            }
            key = keys.receiver.recv() => {
                if let Some(key) = key
                    && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q') | KeyCode::Esc)
                    && !cancelled
                {
                    cancelled = true;
                    state.message = "正在取消……".to_owned();
                    let _ = handle.cancel().await;
                }
            }
            _ = tokio::time::sleep(tick) => {}
        }
    };
    result.inspect(|summary| {
        state.message = format!(
            "完成：{} 个文件，{}，路径={:?}",
            summary.completed_files,
            format_bytes(summary.total_size),
            summary.path_kind
        );
    })
}

struct KeyReader {
    receiver: mpsc::UnboundedReceiver<KeyEvent>,
    stop: Arc<AtomicBool>,
    reader: Option<thread::JoinHandle<()>>,
}

impl KeyReader {
    fn spawn() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let reader = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                if !event::poll(Duration::from_millis(100)).unwrap_or(false) {
                    continue;
                }
                let Ok(Event::Key(key)) = event::read() else {
                    continue;
                };
                if key.kind == KeyEventKind::Press && sender.send(key).is_err() {
                    break;
                }
            }
        });
        Self {
            receiver,
            stop,
            reader: Some(reader),
        }
    }
}

impl Drop for KeyReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    fn new() -> Result<Self, io::Error> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        let _ = self.terminal.show_cursor();
    }
}

struct TransferView {
    title: String,
    known_total: Option<u64>,
    bytes: BTreeMap<String, u64>,
    path: String,
    state: String,
    message: String,
    logs: Vec<String>,
}

impl TransferView {
    fn new(title: String, known_total: Option<u64>) -> Self {
        Self {
            title,
            known_total,
            bytes: BTreeMap::new(),
            path: "等待路径选择".to_owned(),
            state: "启动中".to_owned(),
            message: "按 c 或 q 取消".to_owned(),
            logs: Vec::new(),
        }
    }

    fn apply(&mut self, event: TransferEvent) {
        match &event {
            TransferEvent::StateChanged { to, .. } => {
                self.state = to.name().to_owned();
            }
            TransferEvent::FileProgress {
                file_id,
                durable_offset,
                total_size,
            } => {
                self.bytes.insert(file_id.to_string(), *durable_offset);
                if *total_size > 0 {
                    self.known_total = Some(*total_size);
                }
            }
            TransferEvent::PathSelected { kind } => {
                self.path = format!("{kind:?}");
            }
            TransferEvent::PathFallback => {
                self.path = "路径回退到 relay".to_owned();
            }
            TransferEvent::Completed(summary) => {
                self.known_total = Some(summary.total_size);
                self.message = "传输完成".to_owned();
            }
            TransferEvent::Failed(message) => {
                self.message = format!("失败：{message}");
            }
        }
        self.logs.push(format_event(&event));
        if self.logs.len() > 6 {
            self.logs.remove(0);
        }
    }

    fn render(&self, frame: &mut ratatui::Frame<'_>, color: bool) {
        let accent = accent_style(color);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(5),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .split(frame.area());
        frame.render_widget(
            Paragraph::new(self.title.as_str())
                .style(accent)
                .block(Block::default().borders(Borders::ALL).title("传输")),
            chunks[0],
        );
        let total = self.bytes.values().copied().sum::<u64>();
        let ratio = self
            .known_total
            .filter(|total_size| *total_size > 0)
            .map(|total_size| (total as f64 / total_size as f64).min(1.0))
            .unwrap_or(0.0);
        frame.render_widget(
            Gauge::default()
                .block(Block::default().borders(Borders::ALL).title("durable 进度"))
                .gauge_style(accent)
                .ratio(ratio)
                .label(format!(
                    "{} / {}",
                    format_bytes(total),
                    self.known_total
                        .map(format_bytes)
                        .unwrap_or_else(|| "未知".to_owned())
                )),
            chunks[1],
        );
        let info = vec![
            Line::from(format!("状态：{}", self.state)),
            Line::from(format!("路径：{}", self.path)),
            Line::from(format!("文件数：{}", self.bytes.len())),
        ];
        frame.render_widget(
            Paragraph::new(info).block(Block::default().borders(Borders::ALL).title("状态")),
            chunks[2],
        );
        let logs = self
            .logs
            .iter()
            .map(|line| ListItem::new(line.as_str()))
            .collect::<Vec<_>>();
        frame.render_widget(
            List::new(logs).block(Block::default().borders(Borders::ALL).title("事件")),
            chunks[3],
        );
        frame.render_widget(
            Paragraph::new(self.message.as_str())
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL)),
            chunks[4],
        );
    }
}

fn print_transfer_event(event: &TransferEvent) {
    println!("事件：{}", format_event(event));
}

fn format_event(event: &TransferEvent) -> String {
    match event {
        TransferEvent::StateChanged { to, .. } => format!("状态 -> {}", to.name()),
        TransferEvent::FileProgress {
            file_id,
            durable_offset,
            total_size,
        } => format!("文件 {file_id} durable={durable_offset}/{total_size}"),
        TransferEvent::PathSelected { kind } => format!("路径 -> {kind:?}"),
        TransferEvent::PathFallback => "路径回退 -> relay".to_owned(),
        TransferEvent::Completed(summary) => format!("完成 -> {} 个文件", summary.completed_files),
        TransferEvent::Failed(message) => format!("失败 -> {message}"),
    }
}

fn accent_style(color: bool) -> Style {
    if color {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    }
}

fn refresh_duration(refresh_hz: u16) -> Duration {
    Duration::from_millis((1_000_u64 / u64::from(refresh_hz.max(1))).max(1))
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", value as u64, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
