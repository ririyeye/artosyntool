//! Artosyn Debug Service OSD Client
//!
//! 连接到 Artosyn 调试服务，启动 OSD 功能并接收显示 OSD 数据。
//!
//! 使用方法:
//!   ar_dbg_client --host 192.168.1.100 --port 1234
//!   ar_dbg_client --role ap    # 强制使用 AP 角色
//!   ar_dbg_client --role dev   # 强制使用 DEV 角色
//!   ar_dbg_client              # 自动检测角色

use ar_dbg_client::osd::{set_device_role, DeviceRole};
use ar_dbg_client::{ArDbgClient, ClientConfig, OsdPlot};
use clap::Parser;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Artosyn Debug Service OSD Client
#[derive(Parser, Debug)]
#[command(name = "ar_dbg_client")]
#[command(about = "Connect to Artosyn Debug Service and receive OSD data")]
struct Args {
    /// Target host IP address
    #[arg(short = 'H', long, default_value = "192.168.1.100")]
    host: String,

    /// Target port
    #[arg(short, long, default_value_t = 1234)]
    port: u16,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Print raw data in hex
    #[arg(short, long)]
    raw: bool,

    /// Only show summary every N seconds (0 = show all)
    #[arg(short, long, default_value_t = 0)]
    summary_interval: u64,

    /// Debug mode: show raw hex dump and field parsing details
    #[arg(short, long)]
    debug: bool,

    /// Force device role (ap|dev), auto-detect if not specified
    #[arg(long)]
    role: Option<String>,
}

fn print_osd_summary(osd: &OsdPlot, raw: bool) {
    use ar_dbg_client::osd::DeviceRole;

    if raw {
        match osd.role {
            DeviceRole::Dev => {
                // DEV 模式原始数据
                println!(
                    "RAW[DEV]: BR_LOCK={} BR_LDPC={} BR_SNR={} BR_AGC=[{},{},{},{}] BR_CH={} SLOT_TX={} SLOT_RX={} SLOT_OPT={} MAIN_PWR={} OPT_PWR={} MCS={}",
                    osd.br_lock,
                    osd.br_ldpc_error,
                    osd.br_snr_value,
                    osd.br_agc_value[0],
                    osd.br_agc_value[1],
                    osd.br_agc_value[2],
                    osd.br_agc_value[3],
                    osd.br_channel,
                    osd.slot_tx_channel,
                    osd.slot_rx_channel,
                    osd.slot_rx_opt_channel,
                    osd.main_avr_pwr,
                    osd.opt_avr_pwr,
                    osd.mcs_value
                );
            }
            DeviceRole::Ap => {
                // AP 模式原始数据
                println!(
                    "RAW[AP]: FCH_LOCK={} SLOT_LOCK={} SLOT_LDPC={} SLOT_SNR={} AFTER_ERR={} SLOT_AGC=[{},{},{},{}] SLOT_OPT={} MAIN_PWR={} OPT_PWR={} MCS={}",
                    osd.fch_lock,
                    osd.slot_lock,
                    osd.slot_ldpc_error,
                    osd.slot_snr_value,
                    osd.slot_ldpc_after_error,
                    osd.slot_agc_value[0],
                    osd.slot_agc_value[1],
                    osd.slot_agc_value[2],
                    osd.slot_agc_value[3],
                    osd.slot_rx_opt_channel,
                    osd.main_avr_pwr,
                    osd.opt_avr_pwr,
                    osd.mcs_value
                );
            }
        }
    } else {
        println!("{}", osd);
    }
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

    info!("Starting OSD client...");
    info!("Target: {}:{}", args.host, args.port);
    if args.debug {
        info!("Debug mode enabled - showing raw hex dump");
    }
    if let Some(role) = &force_role {
        info!("Forced device role: {:?}", role);
        set_device_role(*role);
    } else {
        info!("Auto-detecting device role...");
    }

    let client = ArDbgClient::new(config);

    // 统计计数器
    let osd_count = Arc::new(AtomicU64::new(0));
    let osd_count_clone = osd_count.clone();

    let raw = args.raw;
    let summary_interval = args.summary_interval;
    let last_print = Arc::new(std::sync::Mutex::new(Instant::now()));
    let last_osd = Arc::new(std::sync::Mutex::new(None::<OsdPlot>));

    let callback = move |osd: &OsdPlot| {
        osd_count_clone.fetch_add(1, Ordering::SeqCst);

        if summary_interval == 0 {
            // 实时打印每个 OSD
            print_osd_summary(osd, raw);
        } else {
            // 按间隔打印摘要
            *last_osd.lock().unwrap() = Some(osd.clone());

            let mut last = last_print.lock().unwrap();
            if last.elapsed() >= Duration::from_secs(summary_interval) {
                if let Some(ref osd) = *last_osd.lock().unwrap() {
                    let count = osd_count_clone.load(Ordering::SeqCst);
                    println!("\n--- OSD Summary (received {} packets) ---", count);
                    print_osd_summary(osd, raw);
                }
                *last = Instant::now();
            }
        }
    };

    // 启动 OSD 流
    loop {
        let result = if force_role.is_some() {
            // 强制角色模式：使用原始的 start_osd_stream
            client.start_osd_stream(callback.clone()).await
        } else {
            // 自动检测角色模式：使用 start_osd_stream_auto_role
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
