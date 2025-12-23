//! logcat - 日志抓取工具
//!
//! 两种模式:
//! 1. 本地模式: 本地执行 ar_logcat 命令抓取日志
//! 2. 远程模式: 通过 SSH 连接到远程机器执行 ar_logcat，同时抓取寄存器数据
//!
//! 使用 rslog 存储：
//! - 通道0: logcat 文本
//! - 通道1: 寄存器跟踪数据（二进制格式）

#[cfg(feature = "remote")]
mod export;
mod local;
#[cfg(feature = "remote")]
mod reg_meta;
#[cfg(feature = "remote")]
mod remote;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

const DEFAULT_OUTPUT: &str = "/factory/rslog.dat";
const DEFAULT_MAX_SIZE: u64 = 3_145_728; // 3 MB
#[cfg(feature = "remote")]
const REMOTE_DEFAULT_OUTPUT: &str = "rslog_remote.dat";
#[cfg(feature = "remote")]
const REMOTE_DEFAULT_MAX_SIZE: u64 = 64 * 1024 * 1024; // 64 MB
#[cfg(feature = "remote")]
const DEFAULT_REG_PORT: u16 = 12345;

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

    #[cfg(feature = "remote")]
    /// 远程模式: 通过 SSH 远程执行 ar_logcat，同时抓取寄存器数据
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

        /// 寄存器跟踪服务端口
        #[arg(short = 'r', long, default_value_t = DEFAULT_REG_PORT)]
        reg_port: u16,

        /// 寄存器配置 JSON 文件路径（指定要抓取的寄存器）
        #[arg(short = 'C', long)]
        config: Option<String>,
    },

    #[cfg(feature = "remote")]
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
        #[cfg(feature = "remote")]
        Some(Commands::Remote {
            host,
            port,
            user,
            password,
            key,
            cmd,
            reg_port,
            config,
        }) => {
            let output = cli
                .output
                .clone()
                .unwrap_or_else(|| REMOTE_DEFAULT_OUTPUT.to_string());
            let max_size = cli.max_size.unwrap_or(REMOTE_DEFAULT_MAX_SIZE);
            info!("logcat: Remote mode, host: {}:{}", host, port);
            info!("logcat: Output file: {}", output);
            info!("logcat: Max size: {} bytes", max_size);

            // 加载寄存器配置
            let reg_config = if let Some(config_path) = &config {
                info!("logcat: Loading register config from {}", config_path);
                Some(reg_meta::RegTraceConfig::from_file(config_path)?)
            } else {
                info!(
                    "logcat: Using default register config ({} items)",
                    reg_meta::RegTraceConfig::default().items.len()
                );
                Some(reg_meta::RegTraceConfig::default())
            };

            remote::run_remote(remote::RemoteOptions {
                output: &output,
                max_size,
                host: &host,
                ssh_port: port,
                user: &user,
                password: password.as_deref(),
                key: key.as_deref(),
                cmd: &cmd,
                reg_port,
                reg_config,
            })
            .await?;
        }
        #[cfg(feature = "remote")]
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
