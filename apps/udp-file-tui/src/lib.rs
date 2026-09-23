mod cli;
mod config;
mod error;
mod ui;

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use cli::{Command, OverwriteArg, ReceiveArgs, ResumeCommand, SendArgs};
use transfer_client::{
    OverwritePolicy, PairingCode, PairingOptions, ReceiveOptions, ResumeSession, ResumeTicket,
    TransferClient, TransferRole, cleanup_resume_session, list_resume_sessions,
};
use transfer_protocol::TransferId;

pub use cli::Cli;
pub use config::{
    AppConfig, ClientConfigFile, NetworkConfigFile, ServerConfigFile, StorageConfigFile,
    TransferConfigFile, UiConfigFile,
};
pub use error::{AppError, ConfigError};

pub async fn run(cli: Cli) -> Result<(), AppError> {
    let non_interactive = cli.non_interactive;
    let json_output = cli.json;
    let log_level = cli.log_level.clone();
    let mut config = AppConfig::load_unvalidated(cli.config.as_deref())?;
    config.apply_cli(&cli)?;
    init_logging(&log_level)?;

    match cli.command {
        Some(Command::Send(args)) => run_send(config, args, non_interactive, json_output).await,
        Some(Command::Receive(args)) => {
            run_receive(config, args, non_interactive, json_output).await
        }
        Some(Command::Doctor) => run_doctor(&config),
        Some(Command::Probe) => run_probe(config).await,
        Some(Command::Resume { command }) => run_resume(&config, command),
        None if non_interactive => Err(AppError::Invalid(
            "--non-interactive 必须配合 send、receive、doctor、probe 或 resume 使用".to_owned(),
        )),
        None => run_home(config).await,
    }
}

async fn run_home(config: AppConfig) -> Result<(), AppError> {
    loop {
        match ui::home_screen(&config.ui)? {
            ui::HomeAction::Send => {
                let sources = prompt_sources()?;
                run_send(
                    config.clone(),
                    SendArgs {
                        sources,
                        pairing_ttl_seconds: None,
                    },
                    false,
                    false,
                )
                .await?;
            }
            ui::HomeAction::Receive => {
                let code = prompt("配对码：")?;
                run_receive(
                    config.clone(),
                    ReceiveArgs {
                        code: Some(code),
                        output: None,
                        overwrite: None,
                        accept: false,
                    },
                    false,
                    false,
                )
                .await?;
            }
            ui::HomeAction::Resume => {
                run_resume_interactive(&config).await?;
            }
            ui::HomeAction::Quit => return Ok(()),
        }
    }
}

async fn run_send(
    config: AppConfig,
    args: SendArgs,
    non_interactive: bool,
    json_output: bool,
) -> Result<(), AppError> {
    if args.sources.is_empty() {
        return Err(AppError::Invalid("至少需要一个发送源路径".to_owned()));
    }
    let client = connect_client(&config).await?;
    let ttl = args
        .pairing_ttl_seconds
        .unwrap_or(config.server.pairing_ttl_seconds);
    let offer = client
        .create_pairing(PairingOptions {
            requested_ttl_seconds: ttl,
        })
        .await?;
    println!("配对码：{}", offer.code());
    println!("配对有效期截止：{}（Unix 毫秒）", offer.expires_at_millis());
    println!("请将配对码交给接收方；配对码不会写入配置或日志。");
    let handle = offer.offer_files(args.sources).await?;
    ui::run_transfer(
        handle,
        "发送文件".to_owned(),
        None,
        config.ui,
        non_interactive,
        json_output,
        config.storage.download_root,
    )
    .await?;
    Ok(())
}

async fn run_receive(
    config: AppConfig,
    args: ReceiveArgs,
    non_interactive: bool,
    json_output: bool,
) -> Result<(), AppError> {
    let code = match args.code {
        Some(code) => code,
        None if non_interactive => {
            return Err(AppError::Invalid(
                "无交互模式必须通过 --code 提供配对码".to_owned(),
            ));
        }
        None => prompt("配对码：")?,
    };
    let code = PairingCode::from_str(&code)
        .map_err(|error| AppError::Invalid(format!("配对码无效：{error}")))?;
    let client = connect_client(&config).await?;
    println!("正在等待发送方的 offer……");
    let incoming = client.join_pairing(code).await?;
    println!(
        "收到 offer：发送方={}，文件数={}，大小={}",
        incoming.sender_display_name(),
        incoming.file_count(),
        format_bytes(incoming.total_size())
    );
    let output_supplied = args.output.is_some();
    let root = args
        .output
        .unwrap_or_else(|| config.storage.download_root.clone());
    let root = if non_interactive || output_supplied {
        root
    } else {
        prompt_default("下载目录", &root.display().to_string())?.into()
    };
    if !args.accept && !non_interactive && !confirm("接受此 offer？[y/N] ")? {
        incoming
            .reject_offer(transfer_client::RejectReason::User)
            .await?;
        println!("已拒绝 offer。");
        return Ok(());
    }
    let overwrite = match args.overwrite {
        Some(value) => overwrite_from_arg(value),
        None => config.overwrite_policy()?,
    };
    let mut options = ReceiveOptions::new(root.clone());
    options.overwrite_policy = overwrite;
    options.sync_data = config.storage.sync_data;
    options.sync_all = config.storage.sync_all;
    let total_size = incoming.total_size();
    let handle = incoming.accept_offer(options).await?;
    println!("目标目录：{}", root.display());
    ui::run_transfer(
        handle,
        "接收文件".to_owned(),
        Some(total_size),
        config.ui,
        non_interactive,
        json_output,
        root,
    )
    .await?;
    Ok(())
}

async fn run_resume_interactive(config: &AppConfig) -> Result<(), AppError> {
    loop {
        let root = config.storage.download_root.clone();
        let items = load_resume_items(&root)?;
        match ui::resume_screen(&config.ui, &items)? {
            ui::ResumeAction::Back => return Ok(()),
            ui::ResumeAction::Clean(index) => {
                let item = items
                    .get(index)
                    .ok_or_else(|| AppError::Invalid("选中的断点状态不存在".to_owned()))?;
                if confirm(&format!(
                    "清理 transfer {} 的临时状态？[y/N] ",
                    item.session.transfer_id
                ))? {
                    cleanup_resume_session(&root, &item.session.transfer_id)?;
                    println!("已清理 transfer {} 的临时状态。", item.session.transfer_id);
                }
            }
            ui::ResumeAction::Resume(index) => {
                let item = items
                    .get(index)
                    .ok_or_else(|| AppError::Invalid("选中的断点状态不存在".to_owned()))?;
                let ticket = item.ticket.clone().ok_or_else(|| {
                    AppError::Invalid("选中的断点状态没有可用的 resume ticket".to_owned())
                })?;
                run_resume_transfer(config.clone(), ticket).await?;
                return Ok(());
            }
        }
    }
}

fn load_resume_items(root: &Path) -> Result<Vec<ui::ResumeItem>, AppError> {
    list_resume_sessions(root)?
        .into_iter()
        .map(|session| {
            let transfer_id = parse_transfer_id(&session.transfer_id)?;
            match ResumeTicket::load_from(root, transfer_id) {
                Ok(ticket) => Ok(ui::ResumeItem {
                    session,
                    ticket: Some(ticket),
                    ticket_error: None,
                }),
                Err(error) => Ok(ui::ResumeItem {
                    session,
                    ticket: None,
                    ticket_error: Some(format!("ticket 不可用：{error}")),
                }),
            }
        })
        .collect()
}

fn parse_transfer_id(value: &str) -> Result<TransferId, AppError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Invalid(format!(
            "断点状态包含无效 transfer ID：{value}"
        )));
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = value.as_bytes()[index * 2];
        let low = value.as_bytes()[index * 2 + 1];
        *byte = (hex_digit(high)? << 4) | hex_digit(low)?;
    }
    Ok(TransferId::from_bytes(bytes))
}

fn hex_digit(value: u8) -> Result<u8, AppError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AppError::Invalid(
            "transfer ID 必须是十六进制字符串".to_owned(),
        )),
    }
}

async fn run_resume_transfer(config: AppConfig, ticket: ResumeTicket) -> Result<(), AppError> {
    let root = config.storage.download_root.clone();
    let known_total = ticket.manifest().map(|manifest| manifest.total_size());
    let client = connect_client(&config).await?;
    let (handle, title) = match ticket.role() {
        TransferRole::Offerer => {
            let sources = prompt_sources()?;
            (
                client.resume_send(ticket, sources).await?,
                "恢复发送文件".to_owned(),
            )
        }
        TransferRole::Accepter => {
            println!("恢复接收目录：{}", root.display());
            let mut options = ReceiveOptions::new(root.clone());
            options.overwrite_policy = config.overwrite_policy()?;
            options.sync_data = config.storage.sync_data;
            options.sync_all = config.storage.sync_all;
            (
                client.resume_receive(ticket, options).await?,
                "恢复接收文件".to_owned(),
            )
        }
    };
    ui::run_transfer(handle, title, known_total, config.ui, false, false, root).await?;
    Ok(())
}

fn run_doctor(config: &AppConfig) -> Result<(), AppError> {
    config.client_config()?;
    println!("配置有效");
    println!("服务端：{}", config.server.endpoint);
    println!("本地绑定：{}", config.client.bind);
    println!(
        "direct：{}（direct_only={}）",
        config.network.enable_direct, config.network.direct_only
    );
    println!(
        "relay 保活：{}（当前客户端始终保留 relay fallback）",
        config.network.keep_relay_warm
    );
    println!("下载目录：{}", config.storage.download_root.display());
    println!("配对 TTL：{} 秒", config.server.pairing_ttl_seconds);
    println!("连接超时配置：{} 毫秒", config.server.connect_timeout_ms);
    println!("敏感 token、私钥和配对码不会写入 TOML。");
    Ok(())
}

async fn connect_client(config: &AppConfig) -> Result<TransferClient, AppError> {
    let client_config = config.client_config()?;
    tokio::time::timeout(
        Duration::from_millis(config.server.connect_timeout_ms),
        TransferClient::connect(client_config),
    )
    .await
    .map_err(|_| AppError::Invalid("连接服务端超时".to_owned()))?
    .map_err(AppError::from)
}

async fn run_probe(config: AppConfig) -> Result<(), AppError> {
    let client = connect_client(&config).await?;
    let snapshot = client.network_snapshot()?;
    let candidates = client.local_candidates().unwrap_or_default();
    println!("服务端连接：{}", config.server.endpoint);
    println!(
        "网络接口：{}，路由：{}",
        snapshot.interfaces().len(),
        snapshot.routes().len()
    );
    println!("本地候选地址：{}", candidates.len());
    for candidate in candidates {
        println!(
            "  kind={:?} priority={} address={}",
            candidate.kind,
            candidate.priority,
            candidate
                .address
                .map_or_else(|| "无地址".to_owned(), |address| address.to_string())
        );
    }
    Ok(())
}

fn run_resume(config: &AppConfig, command: ResumeCommand) -> Result<(), AppError> {
    match command {
        ResumeCommand::List { root } => {
            let root = root.unwrap_or_else(|| config.storage.download_root.clone());
            let sessions = list_resume_sessions(&root)?;
            if sessions.is_empty() {
                println!("没有发现未完成的传输状态。");
            } else {
                for session in sessions {
                    print_resume_session(&session);
                }
            }
        }
        ResumeCommand::Clean { root, transfer_id } => {
            let root = root.unwrap_or_else(|| config.storage.download_root.clone());
            cleanup_resume_session(&root, &transfer_id)?;
            println!("已清理 transfer {} 的临时状态。", transfer_id);
        }
    }
    Ok(())
}

fn print_resume_session(session: &ResumeSession) {
    println!(
        "transfer={}，checkpoint={} 个，临时数据={}",
        session.transfer_id,
        session.state_files,
        format_bytes(session.partial_bytes)
    );
}

fn init_logging(level: &str) -> Result<(), AppError> {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .map_err(|error| AppError::Invalid(format!("日志级别无效：{error}")))?;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .try_init();
    Ok(())
}

fn prompt_sources() -> Result<Vec<PathBuf>, AppError> {
    Ok(vec![PathBuf::from(prompt(
        "发送路径（多个文件或目录请使用 send 子命令）：",
    )?)])
}

fn prompt(message: &str) -> Result<String, AppError> {
    print!("{message}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_owned();
    if input.is_empty() {
        return Err(AppError::Invalid("输入不能为空".to_owned()));
    }
    Ok(input)
}

fn confirm(message: &str) -> Result<bool, AppError> {
    let answer = prompt(message)?;
    Ok(matches!(
        answer.to_ascii_lowercase().as_str(),
        "y" | "yes" | "是"
    ))
}

fn prompt_default(message: &str, default: &str) -> Result<String, AppError> {
    print!("{message} [{default}]：");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    Ok(if input.is_empty() {
        default.to_owned()
    } else {
        input.to_owned()
    })
}

fn overwrite_from_arg(value: OverwriteArg) -> OverwritePolicy {
    match value {
        OverwriteArg::Ask => OverwritePolicy::Ask,
        OverwriteArg::NoReplace => OverwritePolicy::NoReplace,
        OverwriteArg::Replace => OverwritePolicy::ReplaceAfterConfirm,
        OverwriteArg::Rename => OverwritePolicy::RenameWithSuffix,
    }
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

#[cfg(test)]
mod tests {
    use super::parse_transfer_id;

    #[test]
    fn parses_transfer_id_hex() {
        let transfer_id = parse_transfer_id("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(transfer_id.to_string(), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn rejects_invalid_transfer_id() {
        assert!(parse_transfer_id("not-a-transfer-id").is_err());
        assert!(parse_transfer_id("00112233445566778899aabbccddeefg").is_err());
    }
}
