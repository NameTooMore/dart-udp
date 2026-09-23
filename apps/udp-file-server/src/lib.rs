mod cli;
mod config;
mod error;

use std::io;

use cli::Command;
use tracing_subscriber::EnvFilter;
use transfer_server::TransferServer;

pub use cli::Cli;
pub use config::{AppConfig, RelayConfigFile, ServerConfigFile};
pub use error::{AppError, ConfigError};

pub async fn run(cli: Cli) -> Result<(), AppError> {
    let log_level = cli.log_level.clone();
    let mut config = AppConfig::load_unvalidated(cli.config.as_deref())?;
    config.apply_cli(&cli)?;
    init_logging(&log_level)?;

    match cli.command {
        Some(Command::Doctor) => run_doctor(&config),
        None => run_server(config).await,
    }
}

async fn run_server(config: AppConfig) -> Result<(), AppError> {
    let bind_addr = config.server.bind;
    let server = TransferServer::bind(config.server_config()?).await?;
    let local_addr = server.local_addr();
    println!("udp-file-server 已启动，监听 {local_addr}");
    tracing::info!(%local_addr, configured_bind = %bind_addr, "文件传输服务端已启动");

    let signal_result = shutdown_signal().await;
    let snapshot = server.metrics().await.snapshot();
    tracing::info!(
        active_pairings = snapshot.active_pairings,
        created_pairings = snapshot.created_pairings,
        joined_pairings = snapshot.joined_pairings,
        expired_pairings = snapshot.expired_pairings,
        rejected_joins = snapshot.rejected_joins,
        relay_bytes = snapshot.relay_bytes,
        relay_failures = snapshot.relay_failures,
        "服务端正在关闭"
    );
    let shutdown_result = server.shutdown().await;

    signal_result?;
    shutdown_result?;
    println!("udp-file-server 已停止");
    Ok(())
}

fn run_doctor(config: &AppConfig) -> Result<(), AppError> {
    let server = config.server_config()?;
    println!("配置有效");
    println!("监听地址：{}", server.endpoint.bind_addr);
    println!("配对 TTL：{} 秒", config.server.pairing_ttl_seconds);
    println!("最大配对数：{}", config.server.max_pairings);
    println!("每个配对最大加入尝试：{}", config.server.max_join_attempts);
    println!(
        "每个配对待处理控制消息：{}",
        config.server.max_pending_messages
    );
    println!(
        "中继：每会话 {} 字节，总计 {} 字节（0 表示不限制总计）",
        format_bytes(config.relay.max_bytes_per_session),
        format_bytes(config.relay.max_bytes_total)
    );
    println!(
        "中继流数：{}，缓冲区：{}",
        config.relay.max_streams_per_session,
        format_bytes(config.relay.buffer_size as u64)
    );
    Ok(())
}

fn init_logging(level: &str) -> Result<(), AppError> {
    let filter = EnvFilter::try_new(level)
        .map_err(|error| AppError::Invalid(format!("日志级别无效：{error}")))?;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .try_init();
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", value as u64, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
