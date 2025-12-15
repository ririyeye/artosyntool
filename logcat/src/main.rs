//! logcat - 日志抓取工具
//!
//! 两种模式:
//! 1. 本地模式: 本地执行 ar_logcat 命令抓取日志
//! 2. 远程模式: 通过 SSH 连接到远程机器执行 ar_logcat
//!
//! 使用 rslog 存储日志到第一个二进制通道

mod export;
mod local;
mod osd_meta;
mod remote;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

const DEFAULT_OUTPUT: &str = "/factory/rslog.dat";
const DEFAULT_MAX_SIZE: u64 = 3_145_728; // 3 MB
const REMOTE_DEFAULT_OUTPUT: &str = "rslog_remote.dat";
const REMOTE_DEFAULT_MAX_SIZE: u64 = 64 * 1024 * 1024; // 64 MB

#[derive(Parser)]
#[command(name = "logcat")]
#[command(about = "Log capture tool - local or remote ar_logcat to rslog storage")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 输出文件路径
    #[arg(short, long)]
    output: Option<String>,

    /// 最大存储大小（字节）
    #[arg(short, long)]
    max_size: Option<u64>,

    /// 详细输出
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// 本地模式: 本地执行 ar_logcat
    Local {
        /// ar_logcat 命令路径
        #[arg(short, long, default_value = "ar_logcat")]
        cmd: String,
    },

    /// 远程模式: 通过 SSH 远程执行 ar_logcat
    Remote {
        /// SSH 主机地址
        #[arg(short = 'H', long)]
        host: String,

        /// SSH 端口
        #[arg(short, long, default_value_t = 22)]
        port: u16,

        /// SSH 用户名
        #[arg(short, long, default_value = "root")]
        user: String,

        /// SSH 密码
        #[arg(short = 'P', long)]
        password: Option<String>,

        /// SSH 私钥路径
        #[arg(short, long)]
        key: Option<String>,

        /// ar_logcat 命令路径
        #[arg(short, long, default_value = "ar_logcat")]
        cmd: String,

        /// ar_dbg 服务端口
        #[arg(short = 'd', long, default_value_t = 1234)]
        dbg_port: u16,
    },

    /// 导出已录制的 rslog 数据
    Export {
        /// 输入 rslog 文件路径
        #[arg(short = 'i', long, default_value = "/factory/rslog.dat")]
        input: String,

        /// 导出目录（会自动创建）
        #[arg(short = 'D', long = "out-dir", default_value = "logcat_export")]
        out_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 设置日志
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("logcat: Starting...");

    match cli.command {
        None | Some(Commands::Local { .. }) => {
            let cmd = match &cli.command {
                Some(Commands::Local { cmd }) => cmd.clone(),
                _ => "ar_logcat".to_string(),
            };
            let output = cli
                .output
                .clone()
                .unwrap_or_else(|| DEFAULT_OUTPUT.to_string());
            let max_size = cli.max_size.unwrap_or(DEFAULT_MAX_SIZE);
            info!("logcat: Local mode, command: {}", cmd);
            info!("logcat: Output file: {}", output);
            info!("logcat: Max size: {} bytes", max_size);
            local::run_local(&output, &cmd, max_size).await?;
        }
        Some(Commands::Remote {
            host,
            port,
            user,
            password,
            key,
            cmd,
            dbg_port,
        }) => {
            let output = cli
                .output
                .clone()
                .unwrap_or_else(|| REMOTE_DEFAULT_OUTPUT.to_string());
            let max_size = cli.max_size.unwrap_or(REMOTE_DEFAULT_MAX_SIZE);
            info!("logcat: Remote mode, host: {}:{}", host, port);
            info!("logcat: Output file: {}", output);
            info!("logcat: Max size: {} bytes", max_size);
            remote::run_remote(
                &output, max_size, &host, port, &user, password, key, &cmd, dbg_port,
            )
            .await?;
        }
        Some(Commands::Export { input, out_dir }) => {
            info!("logcat: Export mode, input: {}", input);
            info!("logcat: Export dir: {}", out_dir);
            export::run_export(export::ExportOptions {
                input: &input,
                output_dir: &out_dir,
            })?;
        }
    }

    Ok(())
}
