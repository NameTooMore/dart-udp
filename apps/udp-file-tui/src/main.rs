use clap::Parser;

use udp_file_tui::{Cli, run};

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("错误：{error}");
        std::process::exit(1);
    }
}
