use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "udp-file-server",
    version,
    about = "基于可靠 UDP 的文件传输服务端",
    long_about = "启动文件传输的配对、信令和中继服务；服务端不负责本地文件读写。"
)]
pub struct Cli {
    /// TOML 配置文件路径。
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// 覆盖服务端 UDP 监听地址；端口为 0 时由系统分配。
    #[arg(long, alias = "endpoint", global = true, value_name = "HOST:PORT")]
    pub bind: Option<SocketAddr>,

    /// 覆盖默认配对有效期，单位为秒。
    #[arg(long, global = true, value_name = "SECONDS")]
    pub pairing_ttl_seconds: Option<u64>,

    /// 覆盖同时保存的配对会话数。
    #[arg(long, global = true, value_name = "COUNT")]
    pub max_pairings: Option<usize>,

    /// 覆盖单个配对会话允许的加入尝试次数。
    #[arg(long, global = true, value_name = "COUNT")]
    pub max_join_attempts: Option<usize>,

    /// 覆盖单个配对会话等待转发的控制消息数。
    #[arg(long, global = true, value_name = "COUNT")]
    pub max_pending_messages: Option<usize>,

    /// 覆盖单个配对会话的中继累计字节上限；0 表示不允许中继。
    #[arg(long, global = true, value_name = "BYTES")]
    pub relay_max_bytes_per_session: Option<u64>,

    /// 覆盖服务端生命周期内的中继累计字节上限；0 表示不限制。
    #[arg(long, global = true, value_name = "BYTES")]
    pub relay_max_bytes_total: Option<u64>,

    /// 覆盖单个配对会话同时中继的数据流数。
    #[arg(long, global = true, value_name = "COUNT")]
    pub relay_max_streams_per_session: Option<usize>,

    /// 覆盖中继复制缓冲区大小。
    #[arg(long, global = true, value_name = "BYTES")]
    pub relay_buffer_size: Option<usize>,

    /// 日志级别，例如 error、warn、info、debug、trace。
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 检查配置，不绑定 UDP 端口。
    Doctor,
}
