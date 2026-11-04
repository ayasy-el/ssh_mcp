pub mod app;
pub mod ui;

use crate::config::Config;
use crate::mcp::{HitlDecision, HitlRequest, LiveLogEntry, McpServer};
use crate::ssh::{AuthMethod, HostKeyStatus, SshClient};
use crate::tui::app::{App, ConnectField, MitmState, Screen, TofuState};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub async fn run_tui(
    config: Config,
    mcp_server: McpServer,
    hitl_rx: mpsc::Receiver<HitlRequest>,
    live_log_rx: mpsc::Receiver<LiveLogEntry>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(config, hitl_rx, live_log_rx);

    let res = run_loop(&mut terminal, &mut app, &mcp_server).await;

    // Restore terminal on exit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

async fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    mcp_server: &McpServer,
) -> Result<()> {
    loop {
        // Poll async events from MCP server
        app.poll_channels();

        terminal.draw(|f| ui::render_ui(f, app))?;

        if app.should_quit {
            break;
        }

        // Poll keyboard events with timeout to allow UI updates
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                // Global Ctrl+C handler
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    app.should_quit = true;
                    break;
                }

                // 1. Handle Pending HITL Modal
                if app.pending_hitl.is_some() {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            app.resolve_pending_hitl(HitlDecision::ApproveOnce);
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.resolve_pending_hitl(HitlDecision::Deny);
                        }
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            app.resolve_pending_hitl(HitlDecision::ApproveSession);
                        }
                        _ => {}
                    }
                    continue;
                }

                // 2. Handle Pending TOFU Modal
                if let Some(tofu) = app.tofu_dialog.take() {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            // Trust and save host key
                            if let Err(e) = SshClient::save_known_host(
                                &tofu.session,
                                &tofu.host,
                                tofu.port,
                                &tofu.raw_key,
                                tofu.key_type,
                            ) {
                                app.status_message = Some((format!("Failed saving host key: {}", e), true));
                            } else {
                                // Proceed to authenticate with saved key
                                complete_authentication(app, tofu.session, mcp_server).await;
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.status_message = Some(("Host rejected by operator".to_string(), true));
                        }
                        _ => {
                            // Put back if not answered
                            app.tofu_dialog = Some(tofu);
                        }
                    }
                    continue;
                }

                // 3. Handle MITM Modal
                if app.mitm_dialog.is_some() {
                    if let KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc = key.code {
                        app.mitm_dialog = None;
                        app.status_message = Some(("Connection aborted due to host key mismatch".to_string(), true));
                    }
                    continue;
                }

                // 4. Handle Normal Screen Inputs
                match app.screen {
                    Screen::Connect => handle_connect_input(app, key.code, key.modifiers, mcp_server).await,
                    Screen::Dashboard => handle_dashboard_input(app, key.code, mcp_server).await,
                }
            }
        }
    }

    Ok(())
}

async fn handle_connect_input(
    app: &mut App,
    code: KeyCode,
    _modifiers: KeyModifiers,
    mcp_server: &McpServer,
) {
    match code {
        KeyCode::Tab | KeyCode::Down => {
            app.focused_field = app.focused_field.next(&app.auth_method);
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.focused_field = app.focused_field.prev(&app.auth_method);
        }
        KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Enter => match app.focused_field {
            ConnectField::History => {
                if !app.history.is_empty() {
                    app.focused_field = ConnectField::Password;
                }
            }
            _ => {
                initiate_connection(app, mcp_server).await;
            }
        },
        KeyCode::Left => match app.focused_field {
            ConnectField::History => app.cycle_history_prev(),
            ConnectField::Preset => app.cycle_preset(),
            ConnectField::AuthMethod => app.cycle_auth_method(),
            _ => {}
        },
        KeyCode::Right => match app.focused_field {
            ConnectField::History => app.cycle_history_next(),
            ConnectField::Preset => app.cycle_preset(),
            ConnectField::AuthMethod => app.cycle_auth_method(),
            _ => {}
        },
        KeyCode::Char(' ') => match app.focused_field {
            ConnectField::History => app.cycle_history_next(),
            ConnectField::Preset => app.cycle_preset(),
            ConnectField::AuthMethod => app.cycle_auth_method(),
            ConnectField::ConnectButton => initiate_connection(app, mcp_server).await,
            _ => append_char(app, ' '),
        },
        KeyCode::Char(c) => {
            if c == 'q' && app.focused_field != ConnectField::Host && app.focused_field != ConnectField::Username && app.focused_field != ConnectField::Password && app.focused_field != ConnectField::KeyPath {
                app.should_quit = true;
                return;
            }
            append_char(app, c);
        }
        KeyCode::Backspace => {
            backspace(app);
        }
        _ => {}
    }
}

fn append_char(app: &mut App, c: char) {
    match app.focused_field {
        ConnectField::Host => app.host.push(c),
        ConnectField::Port => {
            if c.is_ascii_digit() {
                app.port.push(c);
            }
        }
        ConnectField::Username => app.username.push(c),
        ConnectField::KeyPath => app.key_path.push(c),
        ConnectField::Password => {
            let mut s = (*app.password).clone();
            s.push(c);
            app.password = Zeroizing::new(s);
        }
        _ => {}
    }
}

fn backspace(app: &mut App) {
    match app.focused_field {
        ConnectField::Host => {
            app.host.pop();
        }
        ConnectField::Port => {
            app.port.pop();
        }
        ConnectField::Username => {
            app.username.pop();
        }
        ConnectField::KeyPath => {
            app.key_path.pop();
        }
        ConnectField::Password => {
            let mut s = (*app.password).clone();
            s.pop();
            app.password = Zeroizing::new(s);
        }
        _ => {}
    }
}

async fn initiate_connection(app: &mut App, mcp_server: &McpServer) {
    app.is_connecting = true;
    app.status_message = Some(("Connecting to SSH host...".to_string(), false));

    let host = app.host.trim().to_string();
    let port: u16 = app.port.trim().parse().unwrap_or(22);

    match SshClient::connect_and_check_host_key(&host, port) {
        Ok((session, HostKeyStatus::Trusted)) => {
            complete_authentication(app, session, mcp_server).await;
        }
        Ok((session, HostKeyStatus::NewHost { host, port, fingerprint_sha256, raw_key, key_type })) => {
            app.is_connecting = false;
            app.tofu_dialog = Some(TofuState {
                host,
                port,
                fingerprint: fingerprint_sha256,
                raw_key,
                key_type,
                session,
            });
        }
        Ok((_, HostKeyStatus::Mismatch { host, port, fingerprint_sha256 })) => {
            app.is_connecting = false;
            app.mitm_dialog = Some(MitmState {
                host,
                port,
                fingerprint: fingerprint_sha256,
            });
        }
        Err(e) => {
            app.is_connecting = false;
            app.status_message = Some((format!("Connection error: {}", e), true));
        }
    }
}

async fn complete_authentication(
    app: &mut App,
    session: ssh2::Session,
    mcp_server: &McpServer,
) {
    let host = app.host.trim().to_string();
    let port: u16 = app.port.trim().parse().unwrap_or(22);
    let username = app.username.trim().to_string();
    let auth_method = app.auth_method.clone();

    let password = if !app.password.is_empty() {
        Some(app.password.clone())
    } else {
        None
    };

    let key_path = if !app.key_path.trim().is_empty() {
        Some(app.key_path.trim())
    } else {
        None
    };

    let auth_res = SshClient::authenticate(
        session,
        &host,
        port,
        &username,
        &auth_method,
        password,
        key_path,
        None,
    );

    match auth_res {
        Ok(client) => {
            let client_arc = Arc::new(client);
            mcp_server.set_client(Arc::clone(&client_arc));
            app.client = Some(Arc::clone(&client_arc));

            // Record into session history (credentials/passwords are NEVER stored)
            let auth_method_str = match auth_method {
                AuthMethod::Password => "password",
                AuthMethod::KeyFile => "key",
                AuthMethod::Agent => "agent",
            };
            crate::history::SessionHistoryEntry::record(
                &host,
                port,
                &username,
                auth_method_str,
                key_path,
            );
            app.history = crate::history::SessionHistoryEntry::load_history();

            // Fetch initial sysinfo
            if let Ok(info) = client_arc.system_info() {
                app.remote_info = Some(info);
            }

            app.is_connecting = false;
            app.screen = Screen::Dashboard;
            app.status_message = None;
        }
        Err(e) => {
            app.is_connecting = false;
            app.status_message = Some((format!("Auth failed: {}", e), true));
        }
    }
}

async fn handle_dashboard_input(app: &mut App, code: KeyCode, mcp_server: &McpServer) {
    // 1. If help dialog is open, dismiss it
    if app.show_help_dialog {
        if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Char('q')) {
            app.show_help_dialog = false;
        }
        return;
    }

    // 2. If filtering modal is open, handle typing into filter
    if app.is_filtering {
        match code {
            KeyCode::Enter => {
                app.is_filtering = false;
            }
            KeyCode::Esc => {
                app.log_filter.clear();
                app.is_filtering = false;
                app.selected_log_index = 0;
            }
            KeyCode::Backspace => {
                app.log_filter.pop();
                app.selected_log_index = 0;
            }
            KeyCode::Char(c) => {
                app.log_filter.push(c);
                app.selected_log_index = 0;
            }
            _ => {}
        }
        return;
    }

    // 3. If log detail modal is open, any dismiss key closes it
    if app.log_detail_dialog.is_some() {
        if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('d')) {
            app.log_detail_dialog = None;
        }
        return;
    }

    // 4. Normal Dashboard Controls
    match code {
        KeyCode::Char('?') | KeyCode::Char('h') => {
            app.show_help_dialog = true;
            app.export_notification = None;
        }
        KeyCode::Char('/') | KeyCode::Char('f') => {
            app.is_filtering = true;
            app.export_notification = None;
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            match app.export_logs() {
                Ok(msg) => app.export_notification = Some((msg, false)),
                Err(err) => app.export_notification = Some((err, true)),
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.selected_log_index = app.selected_log_index.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max_idx = app.filtered_logs().len().min(50).saturating_sub(1);
            if app.selected_log_index < max_idx {
                app.selected_log_index += 1;
            }
        }
        KeyCode::Enter | KeyCode::Char('d') => {
            let filtered = app.filtered_logs();
            let reversed_logs: Vec<&&LiveLogEntry> = filtered.iter().rev().take(50).collect();
            if let Some(entry) = reversed_logs.get(app.selected_log_index) {
                app.log_detail_dialog = Some((**entry).clone());
            }
        }
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Char('p') => {
            let new_mode = app.cycle_policy_mode();
            mcp_server.update_policy_mode(new_mode);
        }
        KeyCode::Char('r') => {
            if let Some(client) = &app.client {
                if let Ok(info) = client.system_info() {
                    app.remote_info = Some(info);
                }
            }
        }
        KeyCode::Char('c') => {
            if !app.log_filter.is_empty() {
                app.log_filter.clear();
                app.selected_log_index = 0;
            } else {
                app.live_logs.clear();
                app.selected_log_index = 0;
            }
            app.export_notification = None;
        }
        _ => {}
    }
}
