use crate::security::RiskTier;
use crate::ssh::AuthMethod;
use crate::tui::app::{App, ConnectField, Screen};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

/// Tokyo Night Palette
pub mod tokyo_night {
    use ratatui::style::Color;
    pub const BG: Color = Color::Rgb(26, 27, 38);        // #1a1b26
    pub const FG: Color = Color::Rgb(192, 202, 245);     // #c0caf5
    pub const BLUE: Color = Color::Rgb(122, 162, 247);    // #7aa2f7
    pub const CYAN: Color = Color::Rgb(125, 207, 255);    // #7dcfff
    pub const TEAL: Color = Color::Rgb(115, 218, 202);    // #73daca
    pub const GREEN: Color = Color::Rgb(158, 206, 106);   // #9ece6a
    pub const YELLOW: Color = Color::Rgb(224, 175, 104);  // #e0af68
    #[allow(dead_code)]
    pub const ORANGE: Color = Color::Rgb(255, 158, 100);  // #ff9e64
    pub const RED: Color = Color::Rgb(247, 118, 142);     // #f7768e
    pub const PURPLE: Color = Color::Rgb(187, 154, 247);  // #bb9af7
    pub const COMMENT: Color = Color::Rgb(86, 95, 137);   // #565f89
    #[allow(dead_code)]
    pub const SEL_BG: Color = Color::Rgb(40, 52, 87);     // #283457
    #[allow(dead_code)]
    pub const DARK_RED_BG: Color = Color::Rgb(68, 30, 45);
}

pub fn render_ui(f: &mut Frame, app: &App) {
    match app.screen {
        Screen::Connect => render_connect_screen(f, app),
        Screen::Dashboard => render_dashboard_screen(f, app),
    }

    // Modal overlays
    if let Some(tofu) = &app.tofu_dialog {
        render_tofu_modal(f, tofu);
    } else if let Some(mitm) = &app.mitm_dialog {
        render_mitm_modal(f, mitm);
    } else if let Some(hitl) = &app.pending_hitl {
        render_hitl_modal(f, hitl);
    } else if let Some(log_detail) = &app.log_detail_dialog {
        render_log_detail_modal(f, log_detail);
    } else if app.is_filtering {
        render_filter_modal(f, app);
    } else if app.show_help_dialog {
        render_help_modal(f);
    }
}

fn render_connect_screen(f: &mut Frame, app: &App) {
    let size = f.area();

    // Outer background
    let bg_block = Block::default()
        .borders(Borders::ALL)
        .title(" SSH MCP SERVER - Interactive Terminal ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::BLUE));
    f.render_widget(bg_block, size);

    // Centered Form Dialog
    let area = centered_rect(68, 88, size);
    f.render_widget(Clear, area);

    let form_block = Block::default()
        .borders(Borders::ALL)
        .title(" Remote SSH Connection & Auth ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD));
    f.render_widget(form_block.clone(), area);

    let inner = form_block.inner(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Recent Sessions (History)
            Constraint::Length(3), // Preset
            Constraint::Length(3), // Host
            Constraint::Length(3), // Port
            Constraint::Length(3), // Username
            Constraint::Length(3), // Auth Method
            Constraint::Length(3), // Key Path or Password
            Constraint::Length(3), // Password (if Key with passphrase)
            Constraint::Length(3), // Connect Button
            Constraint::Length(2), // Status
            Constraint::Min(1),    // Help Footer
        ])
        .split(inner);

    // 0. Recent Session History
    let history_label = if let Some(idx) = app.selected_history {
        if let Some(entry) = app.history.get(idx) {
            format!(
                "< {} > [{}/{}] (Space / ← / → to cycle, Enter to jump to password)",
                entry.display_label(),
                idx + 1,
                app.history.len()
            )
        } else {
            "None".to_string()
        }
    } else if app.history.is_empty() {
        "No previous sessions saved yet (auto-saved upon connecting)".to_string()
    } else {
        format!(
            "None (Press Space to select from {} saved sessions)",
            app.history.len()
        )
    };

    let history_style = field_style(app.focused_field == ConnectField::History);
    let history_p = Paragraph::new(history_label).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 🕒 Session History ")
            .style(history_style),
    );
    f.render_widget(history_p, chunks[0]);

    // 1. Preset Selector
    let preset_label = if let Some(idx) = app.selected_preset {
        if let Some((name, _)) = app.presets.get(idx) {
            format!("< {} > (Press Space to cycle)", name)
        } else {
            "None (Custom)".to_string()
        }
    } else if app.presets.is_empty() {
        "No presets in config.toml".to_string()
    } else {
        "None (Custom - Press Space to select preset)".to_string()
    };

    let preset_style = field_style(app.focused_field == ConnectField::Preset);
    let preset_p = Paragraph::new(preset_label).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Server Preset (config.toml) ")
            .style(preset_style),
    );
    f.render_widget(preset_p, chunks[1]);

    // 2. Host
    let host_style = field_style(app.focused_field == ConnectField::Host);
    let host_p = Paragraph::new(app.host.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Host (IP or Domain) ")
            .style(host_style),
    );
    f.render_widget(host_p, chunks[2]);

    // 3. Port
    let port_style = field_style(app.focused_field == ConnectField::Port);
    let port_p = Paragraph::new(app.port.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" SSH Port ")
            .style(port_style),
    );
    f.render_widget(port_p, chunks[3]);

    // 4. Username
    let user_style = field_style(app.focused_field == ConnectField::Username);
    let user_p = Paragraph::new(app.username.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Remote Username ")
            .style(user_style),
    );
    f.render_widget(user_p, chunks[4]);

    // 5. Auth Method
    let auth_style = field_style(app.focused_field == ConnectField::AuthMethod);
    let auth_str = match app.auth_method {
        AuthMethod::Password => "[ Password ]  Key File   SSH Agent   (Space to cycle)",
        AuthMethod::KeyFile => "  Password  [ Key File ] SSH Agent   (Space to cycle)",
        AuthMethod::Agent => "  Password   Key File  [ SSH Agent ] (Space to cycle)",
    };
    let auth_p = Paragraph::new(auth_str).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Authentication Method ")
            .style(auth_style),
    );
    f.render_widget(auth_p, chunks[5]);

    // 6 & 7. Key Path or Password Field
    match app.auth_method {
        AuthMethod::Password => {
            let pass_style = field_style(app.focused_field == ConnectField::Password);
            let masked: String = "•".repeat(app.password.len());
            let pass_p = Paragraph::new(masked).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Password (enter manually) ")
                    .style(pass_style),
            );
            f.render_widget(pass_p, chunks[6]);
        }
        AuthMethod::KeyFile => {
            let key_style = field_style(app.focused_field == ConnectField::KeyPath);
            let key_p = Paragraph::new(app.key_path.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Private Key Path ")
                    .style(key_style),
            );
            f.render_widget(key_p, chunks[6]);

            // Passphrase in chunk 7
            let pass_style = field_style(app.focused_field == ConnectField::Password);
            let masked: String = "•".repeat(app.password.len());
            let pass_p = Paragraph::new(masked).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Key Passphrase (optional) ")
                    .style(pass_style),
            );
            f.render_widget(pass_p, chunks[7]);
        }
        AuthMethod::Agent => {
            let agent_p = Paragraph::new("Using $SSH_AUTH_SOCK for authentication").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" SSH Agent ")
                    .style(Style::default().fg(tokyo_night::COMMENT)),
            );
            f.render_widget(agent_p, chunks[6]);
        }
    }

    // 8. Connect Button
    let btn_style = if app.focused_field == ConnectField::ConnectButton {
        Style::default()
            .bg(tokyo_night::GREEN)
            .fg(tokyo_night::BG)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(tokyo_night::GREEN)
    };
    let btn_text = if app.is_connecting {
        "⏳ Connecting to remote server..."
    } else {
        "▶ [ Press Enter to Connect ]"
    };
    let btn_p = Paragraph::new(btn_text)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).style(btn_style));
    f.render_widget(btn_p, chunks[8]);

    // 9. Status Message
    if let Some((msg, is_err)) = &app.status_message {
        let color = if *is_err { tokyo_night::RED } else { tokyo_night::GREEN };
        let status_p = Paragraph::new(msg.as_str())
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center);
        f.render_widget(status_p, chunks[9]);
    }

    // 10. Footer
    let footer_text = "[Tab / ↑ / ↓] Navigate   [Space / ← / →] Select History   [Enter] Connect   [Esc] Quit";
    let footer_p = Paragraph::new(footer_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::COMMENT));
    f.render_widget(footer_p, chunks[10]);
}

fn render_dashboard_screen(f: &mut Frame, app: &App) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top Bar
            Constraint::Length(9), // MCP Info & Remote Sysinfo
            Constraint::Min(8),    // Live Activity Table
            Constraint::Length(2), // Footer
        ])
        .split(size);

    // 1. Top Header Bar
    let client_info = if let Some(c) = &app.client {
        format!("🟢 CONNECTED: {}@{}:{}", c.username(), c.host(), c.port())
    } else {
        "🔴 DISCONNECTED".to_string()
    };

    let policy_str = format!("Policy: {} [p]", app.config.security.hitl_mode.display_label());

    let header_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(40),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    let title_p = Paragraph::new(Span::styled(
        concat!(" SSH-MCP SERVER v", env!("CARGO_PKG_VERSION"), " "),
        Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD),
    ))
    .block(Block::default().borders(Borders::ALL).style(Style::default().fg(tokyo_night::BLUE)));
    f.render_widget(title_p, header_layout[0]);

    let conn_p = Paragraph::new(Span::styled(
        client_info,
        Style::default().fg(tokyo_night::GREEN).add_modifier(Modifier::BOLD),
    ))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).style(Style::default().fg(tokyo_night::BLUE)));
    f.render_widget(conn_p, header_layout[1]);

    let policy_p = Paragraph::new(Span::styled(
        policy_str,
        Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD),
    ))
    .alignment(Alignment::Right)
    .block(Block::default().borders(Borders::ALL).style(Style::default().fg(tokyo_night::BLUE)));
    f.render_widget(policy_p, header_layout[2]);

    // 2. Middle Row: MCP Info (Left) & Sysinfo (Right)
    let mid_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    // Left: MCP Server & Agent Setup
    let mcp_url = format!("http://{}:{}/mcp", app.config.general.mcp_bind, app.config.general.mcp_port);
    let mcp_text = vec![
        Line::from(vec![
            Span::styled("MCP Endpoint: ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(&mcp_url, Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Pi Agent Add: ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(
                format!("pi mcp add -l ssh --url {}", mcp_url),
                Style::default().fg(tokyo_night::GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total Calls:  ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(format!("{}", app.total_calls), Style::default().fg(tokyo_night::YELLOW)),
        ]),
        Line::from(vec![
            Span::styled("Max Output:   ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(
                format!("{} KB / {} lines", app.config.security.max_output_bytes / 1024, app.config.security.max_output_lines),
                Style::default().fg(tokyo_night::FG),
            ),
        ]),
    ];
    let mcp_p = Paragraph::new(mcp_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" MCP Server & Agent Integration ")
            .style(Style::default().fg(tokyo_night::BLUE)),
    );
    f.render_widget(mcp_p, mid_chunks[0]);

    // Right: Remote System Info
    let sys_text = if let Some(info) = &app.remote_info {
        vec![
            Line::from(vec![
                Span::styled("OS:     ", Style::default().fg(tokyo_night::COMMENT)),
                Span::styled(&info.os_release, Style::default().fg(tokyo_night::FG)),
                Span::styled(" (", Style::default().fg(tokyo_night::COMMENT)),
                Span::styled(&info.kernel, Style::default().fg(tokyo_night::COMMENT)),
                Span::styled(")", Style::default().fg(tokyo_night::COMMENT)),
            ]),
            Line::from(vec![
                Span::styled("CPU:    ", Style::default().fg(tokyo_night::COMMENT)),
                Span::styled(format!("{} Cores", info.cpu_cores), Style::default().fg(tokyo_night::FG)),
                Span::styled(" | Uptime: ", Style::default().fg(tokyo_night::COMMENT)),
                Span::styled(&info.uptime, Style::default().fg(tokyo_night::FG)),
            ]),
            Line::from(vec![
                Span::styled("Memory: ", Style::default().fg(tokyo_night::COMMENT)),
                Span::styled(
                    format!("{} MB free / {} MB total", info.memory_free_mb, info.memory_total_mb),
                    Style::default().fg(tokyo_night::YELLOW),
                ),
            ]),
            Line::from(vec![
                Span::styled("Disk /: ", Style::default().fg(tokyo_night::COMMENT)),
                Span::styled(
                    format!("{} used / {} avail ({})", info.disk_root_used, info.disk_root_avail, info.disk_root_pct),
                    Style::default().fg(tokyo_night::TEAL),
                ),
            ]),
        ]
    } else {
        vec![Line::from("Gathering remote system metrics... [r to refresh]")]
    };
    let sys_p = Paragraph::new(sys_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Remote Server Health ")
            .style(Style::default().fg(tokyo_night::BLUE)),
    );
    f.render_widget(sys_p, mid_chunks[1]);

    // 3. Live Agent Activity & Audit Trail Table
    let header_cells = ["  Time", "Tool", "Risk", "Target / Command", "Status", "Duration"]
        .iter()
        .map(|h| Span::styled(*h, Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let filtered = app.filtered_logs();

    let rows: Vec<Row> = if filtered.is_empty() {
        let empty_msg = if !app.log_filter.is_empty() {
            format!("No logs matching filter \"{}\" (press 'c' to clear filter)", app.log_filter)
        } else {
            "Agent tool calls and commands will stream here in real time.".to_string()
        };

        vec![Row::new(vec![
            Span::styled("  --:--:--", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled("No activity", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled("-", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(empty_msg, Style::default().fg(tokyo_night::COMMENT)),
            Span::styled("-", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled("-", Style::default().fg(tokyo_night::COMMENT)),
        ])]
    } else {
        filtered
            .iter()
            .rev()
            .take(50)
            .enumerate()
            .map(|(idx, log)| {
                let is_selected = idx == app.selected_log_index;
                let (risk_color, risk_badge) = match log.risk {
                    RiskTier::Safe => (tokyo_night::GREEN, "[SAFE]"),
                    RiskTier::Mutating => (tokyo_night::CYAN, "[MUTATE]"),
                    RiskTier::HighRisk => (tokyo_night::RED, "[HIGH RISK]"),
                    RiskTier::Forbidden => (tokyo_night::PURPLE, "[FORBIDDEN]"),
                };

                let status_color = match log.status.as_str() {
                    "OK" => tokyo_night::GREEN,
                    "DENIED" | "DENIED_READONLY" | "DENIED_HEADLESS" => tokyo_night::RED,
                    "FORBIDDEN" => tokyo_night::PURPLE,
                    _ => tokyo_night::YELLOW,
                };

                let pointer = if is_selected { "▶ " } else { "  " };

                let cells = vec![
                    Span::styled(format!("{}{}", pointer, log.timestamp), if is_selected { Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD) } else { Style::default().fg(tokyo_night::COMMENT) }),
                    Span::styled(log.tool.clone(), Style::default().fg(tokyo_night::FG)),
                    Span::styled(risk_badge, Style::default().fg(risk_color).add_modifier(Modifier::BOLD)),
                    Span::styled(log.detail.clone(), Style::default().fg(tokyo_night::FG)),
                    Span::styled(log.status.clone(), Style::default().fg(status_color)),
                    Span::styled(format!("{}ms", log.duration_ms), Style::default().fg(tokyo_night::COMMENT)),
                ];

                let row = Row::new(cells);
                if is_selected {
                    row.style(Style::default().add_modifier(Modifier::BOLD))
                } else {
                    row
                }
            })
            .collect()
    };

    let filter_tag = if !app.log_filter.is_empty() {
        format!(" [Filter: \"{}\" - {} matches] ", app.log_filter, filtered.len())
    } else {
        String::new()
    };

    let table_title = format!(
        " Live Activity & Audit Trail ({} calls){} [↑/↓ Select, Enter Inspect, / Filter, ? Help] ",
        app.total_calls, filter_tag
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Min(30),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(table_title)
            .style(Style::default().fg(tokyo_night::BLUE)),
    );
    f.render_widget(table, chunks[2]);

    // 4. Footer Bar
    if let Some((msg, is_err)) = &app.export_notification {
        let color = if *is_err { tokyo_night::RED } else { tokyo_night::GREEN };
        let footer_p = Paragraph::new(Span::styled(
            format!("  ✔ {}", msg),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
        f.render_widget(footer_p, chunks[3]);
    } else {
        let footer_text = " [↑/↓] Select  [Enter] Detail  [/] Filter  [e] Export  [p] Policy  [r] Refresh  [?] Help  [q] Quit";
        let footer_p = Paragraph::new(footer_text)
            .alignment(Alignment::Center)
            .style(Style::default().fg(tokyo_night::COMMENT));
        f.render_widget(footer_p, chunks[3]);
    }
}

fn render_hitl_modal(f: &mut Frame, hitl: &crate::mcp::HitlRequest) {
    let area = centered_rect(65, 42, f.area());
    f.render_widget(Clear, area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .title(" ⚠️ HUMAN APPROVAL REQUIRED (HITL) ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::RED).add_modifier(Modifier::BOLD));
    f.render_widget(modal_block.clone(), area);

    let inner = modal_block.inner(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(2),
        ])
        .split(inner);

    let intro = Paragraph::new("An AI Agent is requesting to execute a HIGH-RISK action:")
        .style(Style::default().fg(tokyo_night::YELLOW));
    f.render_widget(intro, chunks[0]);

    let cmd_p = Paragraph::new(format!("> {}", hitl.command_or_target))
        .style(
            Style::default()
                .fg(tokyo_night::RED)
                .add_modifier(Modifier::BOLD),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(cmd_p, chunks[1]);

    let reason_p = Paragraph::new(format!(
        "Tool: {} | Risk: {} ({})",
        hitl.tool_name,
        hitl.risk_tier.badge(),
        hitl.reason
    ))
    .style(Style::default().fg(tokyo_night::RED));
    f.render_widget(reason_p, chunks[2]);

    let actions = Paragraph::new(
        "\n [Y] Approve Once     [N] Deny Action     [A] Always Allow (This Session)",
    )
    .alignment(Alignment::Center)
    .style(
        Style::default()
            .fg(tokyo_night::FG)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(actions, chunks[3]);
}

fn render_log_detail_modal(f: &mut Frame, log: &crate::mcp::LiveLogEntry) {
    let area = centered_rect(72, 65, f.area());
    f.render_widget(Clear, area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .title(" 📋 AUDIT LOG ENTRY DETAILS ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD));
    f.render_widget(modal_block.clone(), area);

    let inner = modal_block.inner(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(5), // Metadata rows
            Constraint::Min(6),    // Command / target content
            Constraint::Length(2), // Close hint
        ])
        .split(inner);

    let (risk_color, risk_badge) = match log.risk {
        RiskTier::Safe => (tokyo_night::GREEN, "[SAFE]"),
        RiskTier::Mutating => (tokyo_night::CYAN, "[MUTATE]"),
        RiskTier::HighRisk => (tokyo_night::RED, "[HIGH RISK]"),
        RiskTier::Forbidden => (tokyo_night::PURPLE, "[FORBIDDEN]"),
    };

    let status_color = match log.status.as_str() {
        "OK" => tokyo_night::GREEN,
        "DENIED" | "DENIED_READONLY" | "DENIED_HEADLESS" => tokyo_night::RED,
        "FORBIDDEN" => tokyo_night::PURPLE,
        _ => tokyo_night::YELLOW,
    };

    let exit_str = log.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "N/A".to_string());

    let meta_lines = vec![
        Line::from(vec![
            Span::styled("Timestamp:     ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(&log.timestamp, Style::default().fg(tokyo_night::FG)),
            Span::styled("    Duration:   ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(format!("{} ms", log.duration_ms), Style::default().fg(tokyo_night::YELLOW)),
        ]),
        Line::from(vec![
            Span::styled("Tool Invoked:  ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(&log.tool, Style::default().fg(tokyo_night::FG).add_modifier(Modifier::BOLD)),
            Span::styled("    Risk Tier:  ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(risk_badge, Style::default().fg(risk_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Status:        ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(&log.status, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
            Span::styled("    Exit Code:  ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(exit_str, Style::default().fg(tokyo_night::FG)),
            Span::styled("    Payload: ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(format!("{} bytes", log.output_bytes), Style::default().fg(tokyo_night::FG)),
        ]),
    ];
    let meta_p = Paragraph::new(meta_lines);
    f.render_widget(meta_p, chunks[0]);

    let cmd_block = Block::default()
        .borders(Borders::ALL)
        .title(" Full Command / Target Argument ")
        .style(Style::default().fg(tokyo_night::BLUE));
    let cmd_p = Paragraph::new(log.detail.as_str())
        .block(cmd_block)
        .style(Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD))
        .wrap(Wrap { trim: false });
    f.render_widget(cmd_p, chunks[1]);

    let close_hint = Paragraph::new("[Press Esc or Enter to close]")
        .alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::COMMENT));
    f.render_widget(close_hint, chunks[2]);
}

fn render_tofu_modal(f: &mut Frame, tofu: &crate::tui::app::TofuState) {
    let area = centered_rect(65, 38, f.area());
    f.render_widget(Clear, area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .title(" ⚠️ UNVERIFIED HOST KEY (Trust On First Use) ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD));
    f.render_widget(modal_block.clone(), area);

    let inner = modal_block.inner(area);
    let text = vec![
        Line::from(vec![
            Span::styled("Target Host:   ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(format!("{}:{}", tofu.host, tofu.port), Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Key Algorithm: ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(tofu.key_type_name.as_str(), Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Fingerprint:   ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(tofu.fingerprint.as_str(), Style::default().fg(tokyo_night::GREEN).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from("This host is not yet recorded in ~/.ssh/known_hosts."),
        Line::from("Do you want to trust this server fingerprint and save it to known_hosts?"),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [Y] Trust & Save ", Style::default().fg(tokyo_night::BG).bg(tokyo_night::GREEN).add_modifier(Modifier::BOLD)),
            Span::raw("     "),
            Span::styled(" [N] Reject & Abort (Esc) ", Style::default().fg(tokyo_night::BG).bg(tokyo_night::RED).add_modifier(Modifier::BOLD)),
        ]),
    ];

    let p = Paragraph::new(text).wrap(Wrap { trim: true });
    f.render_widget(p, inner);
}

fn render_mitm_modal(f: &mut Frame, mitm: &crate::tui::app::MitmState) {
    let area = centered_rect(76, 48, f.area());
    f.render_widget(Clear, area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .title(" 🚨 SECURITY ALERT: HOST KEY MISMATCH 🚨 ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::RED).add_modifier(Modifier::BOLD));
    f.render_widget(modal_block.clone(), area);

    let inner = modal_block.inner(area);
    let text = vec![
        Line::from(Span::styled(
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
            Style::default().fg(tokyo_night::RED).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Target Host:   ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(format!("{}:{}", mitm.host, mitm.port), Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Key Algorithm: ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(mitm.key_type_name.as_str(), Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Fingerprint:   ", Style::default().fg(tokyo_night::COMMENT)),
            Span::styled(mitm.fingerprint.as_str(), Style::default().fg(tokyo_night::GREEN).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "The key presented by the remote server differs from the entry in ~/.ssh/known_hosts.",
            Style::default().fg(tokyo_night::FG),
        )),
        Line::from(Span::styled(
            "This can happen if the server was reinstalled, IP rotated, or an attacker is intercepting traffic.",
            Style::default().fg(tokyo_night::COMMENT),
        )),
        Line::from(""),
        Line::from(Span::styled("Select an action:", Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [Y] Accept & Update ", Style::default().fg(tokyo_night::BG).bg(tokyo_night::GREEN).add_modifier(Modifier::BOLD)),
            Span::raw("  Overwrite ~/.ssh/known_hosts with this key"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [O] Connect Once    ", Style::default().fg(tokyo_night::BG).bg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD)),
            Span::raw("  Proceed for this session without saving"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [N] Abort (Esc)     ", Style::default().fg(tokyo_night::BG).bg(tokyo_night::RED).add_modifier(Modifier::BOLD)),
            Span::raw("  Disconnect immediately (RECOMMENDED if unexpected)"),
        ]),
    ];

    let p = Paragraph::new(text).wrap(Wrap { trim: true });
    f.render_widget(p, inner);
}

fn render_filter_modal(f: &mut Frame, app: &App) {
    let area = centered_rect(65, 30, f.area());
    f.render_widget(Clear, area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .title(" 🔍 FILTER ACTIVITY LOGS ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::CYAN).add_modifier(Modifier::BOLD));
    f.render_widget(modal_block.clone(), area);

    let inner = modal_block.inner(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Input query box
            Constraint::Length(2), // Match statistics
            Constraint::Length(1), // Hint
        ])
        .split(inner);

    let input_query = format!("{}█", app.log_filter);
    let query_box = Paragraph::new(input_query).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Search Query (tool, command, status, risk) ")
            .style(Style::default().fg(tokyo_night::YELLOW)),
    );
    f.render_widget(query_box, chunks[0]);

    let matched_count = app.filtered_logs().len();
    let stats_text = format!(
        "Matching: {} of {} total log entries",
        matched_count,
        app.live_logs.len()
    );
    let stats_p = Paragraph::new(stats_text)
        .style(Style::default().fg(tokyo_night::GREEN).add_modifier(Modifier::BOLD));
    f.render_widget(stats_p, chunks[1]);

    let hint_p = Paragraph::new("[Enter] Apply filter   [Esc] Clear filter and close")
        .alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::COMMENT));
    f.render_widget(hint_p, chunks[2]);
}

fn render_help_modal(f: &mut Frame) {
    let area = centered_rect(72, 72, f.area());
    f.render_widget(Clear, area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .title(" 💡 KEYBOARD SHORTCUTS & HELP ")
        .title_alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::PURPLE).add_modifier(Modifier::BOLD));
    f.render_widget(modal_block.clone(), area);

    let inner = modal_block.inner(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2), // Intro
            Constraint::Min(12),   // Shortcuts table/list
            Constraint::Length(2), // Close hint
        ])
        .split(inner);

    let intro = Paragraph::new("Quick reference for TUI navigation and controls:")
        .style(Style::default().fg(tokyo_night::FG));
    f.render_widget(intro, chunks[0]);

    let help_items = vec![
        ("↑ / k", "Navigate up through activity logs"),
        ("↓ / j", "Navigate down through activity logs"),
        ("Enter / d", "Inspect full details of selected log"),
        ("/ or f", "Filter / search logs in real time by command, tool, or status"),
        ("e", "Export all live logs to timestamped JSON file"),
        ("p", "Cycle Security Policy: Autonomous -> High-Risk -> Strict -> Read-Only"),
        ("r", "Refresh remote server system metrics (CPU, RAM, Disk)"),
        ("c", "Clear current log activity stream or active filter"),
        ("y / n / a", "Approve Once / Deny / Allow for Session (on HITL modals)"),
        ("?", "Toggle this Help & Keyboard Shortcuts dialog"),
        ("q / Esc", "Disconnect from SSH session and quit gracefully"),
    ];

    let rows: Vec<Row> = help_items
        .into_iter()
        .map(|(key, desc)| {
            Row::new(vec![
                Span::styled(format!("  [{}]", key), Style::default().fg(tokyo_night::YELLOW).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" : {}", desc), Style::default().fg(tokyo_night::FG)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Length(16), Constraint::Min(40)],
    );
    f.render_widget(table, chunks[1]);

    let close_hint = Paragraph::new("[Press Esc, Enter, or ? to close]")
        .alignment(Alignment::Center)
        .style(Style::default().fg(tokyo_night::COMMENT));
    f.render_widget(close_hint, chunks[2]);
}

fn field_style(is_focused: bool) -> Style {
    if is_focused {
        Style::default()
            .fg(tokyo_night::YELLOW)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(tokyo_night::FG)
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
