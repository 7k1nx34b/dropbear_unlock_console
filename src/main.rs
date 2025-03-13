use crossterm::{
    event::{self, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use ssh2::Session;
use std::{env, io::{self, Read, Write}, net::TcpStream, path::Path, sync::{Arc, atomic::{AtomicBool, Ordering}}, thread, time::Duration};
use dotenv;

struct AppState {
    logs: Vec<String>,
    password_input: String,
    password_submitted: bool,
    unlocked: bool,
    show_password: bool,
}

impl AppState {
    fn new() -> Self {
        Self {
            logs: vec![],
            password_input: String::new(),
            password_submitted: false,
            unlocked: false,
            show_password: false,
        }
    }

    fn log<S: Into<String>>(&mut self, msg: S) {
        self.logs.push(msg.into());
    }

    fn reset_password(&mut self) {
        self.password_input.clear();
        self.password_submitted = false;
    }
}

fn rendering(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &AppState,
) -> Result<(), Box<dyn std::error::Error>> {
    terminal.draw(|f| {
        let size = f.size();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .split(size);

        let input_text = if app.show_password {
            app.password_input.clone()
        } else {
            "*".repeat(app.password_input.len())
        };

        let input_box = Paragraph::new(input_text)
            .block(Block::default().borders(Borders::ALL).title("Password"))
            .style(Style::default().fg(Color::White));

        let toggle_text = format!(
            "[{}] Show password [CTRL+v]",
            if app.show_password { "x" } else { " " }
        );

        let toggle = Paragraph::new(toggle_text)
            .style(Style::default().fg(Color::DarkGray));

        let info = Paragraph::new("[Enter] to unlock | [CTRL+q] to quit")
            .style(Style::default().fg(Color::DarkGray));

        let log_items = app.logs.iter().rev().take(10).map(|log| {
            ListItem::new(Line::from(Span::styled(
                log,
                Style::default().fg(Color::Gray),
            )))
        }).collect::<Vec<_>>();

        let log_widget = List::new(log_items)
            .block(Block::default().borders(Borders::ALL).title("Log"));

        f.render_widget(input_box, chunks[0]);
        f.render_widget(info, chunks[1]);
        f.render_widget(toggle, chunks[2]);
        f.render_widget(log_widget, chunks[3]);

        if app.unlocked {
            let popup_area = centered_rect(40, 10, size);
            let popup = Paragraph::new("Disks unlocked!")
                .style(
                    Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(Modifier::BOLD),
                )
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title("Success"));

            f.render_widget(popup, popup_area);
        }
    })?;

    Ok(())
}


fn try_unlock_with_dropbear(app: &mut AppState, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, running: &Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    rendering(terminal, app)?;

    match TcpStream::connect(
        format!(
            "{}:{}",
            env::var("DROPBEAR_SSH_HOST").unwrap().as_str(),
            env::var("DROPBEAR_SSH_PORT").unwrap().as_str()
        )
    ) {
        Ok(mut tcp) => {
            tcp.set_nonblocking(true)?;
            let mut sess = Session::new()?;
            sess.set_tcp_stream(tcp);
            sess.handshake()?;
            sess.userauth_pubkey_file("root", None, Path::new(
                env::var("DROPBEAR_SSH_PRV_RSA").unwrap().as_str()
            ), None)?;

            if !sess.authenticated() {
                app.log("Dropbear SSH pubkey failed.");
                rendering(terminal, app)?;
                return Ok(());
            }

            app.log("Dropbear SSH pubkey correct!");
            rendering(terminal, app)?;

            let mut channel = sess.channel_session()?;
            channel.request_pty("tty", None, None)?;
            channel.shell()?;

            thread::sleep(Duration::from_secs(1));
            channel.write_all(b"cryptroot-unlock\n")?;
            channel.flush()?;

            let mut buf = [0u8; 1024];
            let pass = app.password_input.clone();
            let mut in_unlock_await_step = false;
            let mut conut = 1;



            while running.load(Ordering::Relaxed) {
                if event::poll(Duration::from_millis(1))? {
                    if let CEvent::Key(key) = event::read()? {
                        if let KeyCode::Char('q') = key.code {
                            return Ok(());
                        }
                    }
                }

                match channel.read(&mut buf) {
                    Ok(0) => continue,
                    Ok(len) => {
                        let response = String::from_utf8_lossy(&buf[..len]);

                        if in_unlock_await_step {
                            if response.contains("bad") || response.contains("maximum") {
                                app.log("Incorrect LUKS password. re-init Dropbear session...");
                                rendering(terminal, app)?;
                                app.reset_password();
                                return Ok(());
                            } else {
                                app.log(format!("{} Disk unlocked!", conut));
                                rendering(terminal, app)?;
                                conut += 1;

                            }

                        }

                        if response.contains("Please unlock") {
                            channel.write_all(pass.trim_end().as_bytes())?;
                            channel.write_all(b"\n")?;
                            in_unlock_await_step = true;
                            channel.read(&mut buf).unwrap();
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => {
                        if conut > 1 {
                            app.unlocked = true;
                            rendering(terminal, app)?;
                        }
                        break;
                    },
                }
            }
        }
        Err(_) => {
            app.log("Retrying...");
            rendering(terminal, app)?;
            thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;

    dotenv::from_filename(".env").ok();

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new();
    let running = Arc::new(AtomicBool::new(true));

    loop {
        rendering(&mut terminal, &app)?;

        if app.password_submitted && !app.unlocked {
            if let Err(e) = try_unlock_with_dropbear(&mut app, &mut terminal, &running) {
                app.log(format!("Error: {e}"));
            }
        }

        if event::poll(Duration::from_millis(10))? {
            if let CEvent::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                    KeyCode::Char('v') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                        app.show_password = !app.show_password
                    }

                    KeyCode::Char(c) => {
                        if !app.password_submitted {
                            app.password_input.push(c);
                        }
                    }
                    KeyCode::Backspace => {
                        if !app.password_submitted {
                            app.password_input.pop();
                        }
                    }
                    KeyCode::Enter => {
                        if !app.password_input.is_empty() && !app.password_submitted {
                            app.password_submitted = true;
                            app.log("Try unlocking...");
                            rendering(&mut terminal, &app)?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    fn centered_constraints(percent: u16) -> [Constraint; 3] {
        let margin = (100 - percent) / 2;
        [Constraint::Percentage(margin), Constraint::Percentage(percent), Constraint::Percentage(margin)]
    }

    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(centered_constraints(percent_y))
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(centered_constraints(percent_x))
        .split(vertical_chunks[1])[1]
}
