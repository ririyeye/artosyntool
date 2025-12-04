//! Artosyn Debug Service OSD Web Client
//!
//! 带 Web 界面的 OSD 客户端，可在浏览器中实时查看 OSD 数据曲线。
//!
//! 使用方法:
//!   ar_dbg_web --host 192.168.1.100 --port 1234 --web-port 8080
//!   ar_dbg_web --role ap    # 强制使用 AP 角色
//!   ar_dbg_web --role dev   # 强制使用 DEV 角色

use ar_dbg_client::osd::{set_device_role, DeviceRole};
use ar_dbg_client::web::WebState;
use ar_dbg_client::{ArDbgClient, ClientConfig, OsdPlot};
use clap::Parser;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Artosyn Debug Service OSD Web Client
#[derive(Parser, Debug)]
#[command(name = "ar_dbg_web")]
#[command(about = "Connect to Artosyn Debug Service and display OSD data in web browser")]
struct Args {
    /// Target host IP address
    #[arg(short = 'H', long, default_value = "192.168.1.100")]
    host: String,

    /// Target port
    #[arg(short, long, default_value_t = 1234)]
    port: u16,

    /// Web server port
    #[arg(short, long, default_value_t = 8080)]
    web_port: u16,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Debug mode
    #[arg(short, long)]
    debug: bool,

    /// Force device role (ap|dev), auto-detect if not specified
    #[arg(long)]
    role: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // 设置日志
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let config = ClientConfig {
        host: args.host.clone(),
        port: args.port,
    };

    // 设置调试模式
    ar_dbg_client::osd::set_debug_mode(args.debug);

    // 解析并设置设备角色
    let force_role = args.role.as_ref().map(|r| match r.to_lowercase().as_str() {
        "ap" => DeviceRole::Ap,
        "dev" | "device" => DeviceRole::Dev,
        _ => {
            eprintln!("Invalid role '{}', must be 'ap' or 'dev'", r);
            std::process::exit(1);
        }
    });

    info!("Starting OSD Web Client...");
    info!("Target device: {}:{}", args.host, args.port);
    info!("Web server: http://0.0.0.0:{}", args.web_port);

    if let Some(role) = &force_role {
        info!("Forced device role: {:?}", role);
        set_device_role(*role);
    } else {
        info!("Auto-detecting device role...");
    }

    // 创建 Web 状态
    let web_state = Arc::new(WebState::new());
    let web_state_clone = web_state.clone();

    // 启动 Web 服务器
    let web_port = args.web_port;
    tokio::spawn(async move {
        if let Err(e) = ar_dbg_client::web::start_web_server(web_state_clone, web_port).await {
            error!("Web server error: {}", e);
        }
    });

    // 等待 Web 服务器启动
    tokio::time::sleep(Duration::from_millis(100)).await;

    println!("\n========================================");
    println!("  📡 Artosyn OSD 实时监控");
    println!("========================================");
    println!("  设备地址: {}:{}", args.host, args.port);
    println!("  Web 界面: http://localhost:{}", args.web_port);
    println!("========================================\n");

    let client = ArDbgClient::new(config);

    // 统计计数器
    let osd_count = Arc::new(AtomicU64::new(0));
    let osd_count_clone = osd_count.clone();
    let web_state_for_callback = web_state.clone();

    let callback = move |osd: &OsdPlot| {
        let count = osd_count_clone.fetch_add(1, Ordering::SeqCst) + 1;

        // 广播到 Web 客户端
        web_state_for_callback.broadcast(osd);

        // 每 100 包打印一次统计
        if count % 100 == 0 {
            info!(
                "Received {} OSD packets, SNR: {:.1} dB, Locked: {}",
                count,
                osd.snr_db(),
                osd.is_locked()
            );
        }
    };

    // 启动 OSD 流
    loop {
        let result = if force_role.is_some() {
            client.start_osd_stream(callback.clone()).await
        } else {
            client.start_osd_stream_auto_role(callback.clone()).await
        };

        match result {
            Ok(_) => {
                info!("OSD stream ended normally");
                break;
            }
            Err(e) => {
                error!("OSD stream error: {}", e);
                info!("Reconnecting in 3 seconds...");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }

    let total = osd_count.load(Ordering::SeqCst);
    info!("Total OSD packets received: {}", total);
}
