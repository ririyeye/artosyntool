//! 简单的 OSD 接收示例
//!
//! 演示如何使用 ar_dbg_client 库接收 OSD 数据

use ar_dbg_client::{client::create_osd_receiver, ArDbgClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 配置客户端
    let config = ClientConfig {
        host: "192.168.1.100".to_string(),
        port: 1234,
    };

    println!("Starting OSD stream with callback...");

    // 使用 channel 方式接收
    let (callback, mut rx) = create_osd_receiver();

    // 在后台启动 OSD 流 (自动检测设备角色)
    let client = ArDbgClient::new(config);

    tokio::spawn(async move {
        if let Err(e) = client.start_osd_stream_auto_role(callback).await {
            eprintln!("OSD stream error: {}", e);
        }
    });

    // 接收并处理 OSD 数据
    let mut count = 0;
    while let Some(osd) = rx.recv().await {
        count += 1;
        println!("\n=== OSD #{} (Role: {:?}) ===", count, osd.role);
        println!(
            "锁定状态: {}",
            if osd.is_locked() {
                "已锁定"
            } else {
                "未锁定"
            }
        );
        println!("MCS: {}", osd.mcs_value);
        println!("SNR: {:.1} dB", osd.snr_db());
        println!("LDPC ERR: {}", osd.ldpc_error());
        println!("AGC: {:?}", osd.agc_values());
        println!("Power: MAIN={} OPT={}", osd.main_avr_pwr, osd.opt_avr_pwr);

        // 只接收10个包作为演示
        if count >= 10 {
            println!("\nReceived 10 OSD packets, stopping...");
            break;
        }
    }

    Ok(())
}
