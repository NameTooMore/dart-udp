use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "udp-file",
    version,
    about = "基于可靠 UDP 的文件传输客户端",
    long_about = "基于配对码的文件传输客户端；不指定子命令时进入交互式 TUI。"
)]
pub struct Cli {
    /// TOML 配置文件路径。
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// 覆盖配置中的服务端地址。
    #[arg(long, global = true, value_name = "HOST:PORT")]
    pub server: Option<SocketAddr>,

    /// 覆盖配置中的本地 UDP 绑定地址。
    #[arg(long, global = true, value_name = "HOST:PORT")]
    pub bind: Option<SocketAddr>,

    /// 覆盖配置中的客户端显示名称。
    #[arg(long, global = true)]
    pub display_name: Option<String>,

    /// 覆盖单个数据块大小。
    #[arg(long, global = true, value_name = "BYTES")]
    pub chunk_size: Option<usize>,

    /// 覆盖同时处理的文件数。
    #[arg(long, global = true, value_name = "COUNT")]
    pub max_parallel_files: Option<usize>,

    /// 覆盖断点状态的字节间隔。
    #[arg(long, global = true, value_name = "BYTES")]
    pub checkpoint_interval_bytes: Option<u64>,

    /// 覆盖下载根目录。
    #[arg(long, global = true, value_name = "DIR")]
    pub download_root: Option<PathBuf>,

    /// 强制使用中继，不发送 direct candidate。
    #[arg(long, global = true)]
    pub direct_only: bool,

    /// 禁用 direct candidate 探测。
    #[arg(long, global = true)]
    pub no_direct: bool,

    /// 禁用终端颜色。
    #[arg(long, global = true)]
    pub no_color: bool,

    /// UI 刷新频率，单位为 Hz。
    #[arg(long, global = true, value_name = "HZ")]
    pub refresh_hz: Option<u16>,

    /// 使用纯文本输出并响应 Ctrl-C，适合 Compose 和 CI。
    #[arg(long, global = true)]
    pub non_interactive: bool,

    /// 在传输完成时额外输出一条机器可读的 JSON 结果记录。
    #[arg(long, global = true)]
    pub json: bool,

    /// 日志级别，例如 error、warn、info、debug、trace。
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 创建配对并发送文件或目录。
    #[command(alias = "create")]
    Send(SendArgs),
    /// 使用配对码接收文件。
    #[command(alias = "join")]
    Receive(ReceiveArgs),
    /// 检查配置，不连接服务端。
    Doctor,
    /// 连接服务端并输出本机候选地址。
    Probe,
    /// 查看或清理本地断点状态。
    Resume {
        #[command(subcommand)]
        command: ResumeCommand,
    },
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// 要发送的文件或目录，可以重复指定。
    #[arg(value_name = "SOURCE", required = true)]
    pub sources: Vec<PathBuf>,

    /// 本次配对有效期，0 表示使用服务端默认值。
    #[arg(long, value_name = "SECONDS")]
    pub pairing_ttl_seconds: Option<u32>,
}

#[derive(Debug, Args)]
pub struct ReceiveArgs {
    /// 配对码；交互模式省略时会在终端中询问。
    #[arg(long, short = 'c', value_name = "CODE")]
    pub code: Option<String>,

    /// 下载根目录。
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// 已存在文件的处理策略。
    #[arg(long, value_enum)]
    pub overwrite: Option<OverwriteArg>,

    /// 交互模式下直接接受 offer。
    #[arg(long)]
    pub accept: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OverwriteArg {
    Ask,
    NoReplace,
    Replace,
    Rename,
}

#[derive(Debug, Subcommand)]
pub enum ResumeCommand {
    /// 列出下载目录中的未完成 session。
    List {
        #[arg(long, short = 'r', value_name = "DIR")]
        root: Option<PathBuf>,
    },
    /// 删除指定 transfer 的临时状态。
    Clean {
        #[arg(long, short = 'r', value_name = "DIR")]
        root: Option<PathBuf>,
        #[arg(long, value_name = "TRANSFER_ID")]
        transfer_id: String,
    },
}
