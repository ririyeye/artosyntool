//! 简单的寄存器跟踪示例
//!
//! 运行: cargo run --example simple_trace -- -H 192.168.1.100

use ar_dbg_client::{ClientConfig, ConfigRequest, RegTraceClient, RegTraceItem};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 配置客户端
    let config = ClientConfig {
        host: std::env::args()
            .skip_while(|a| a != "-H")
            .nth(1)
            .unwrap_or_else(|| "192.168.1.100".to_string()),
        port: 12345,
        timeout_secs: 5,
    };

    println!("Connecting to {}:{}", config.host, config.port);

    let client = RegTraceClient::new(config);
    let mut stream = client.connect().await?;

    // Ping 测试
    let ping_resp = client.ping(&mut stream).await?;
    println!("Server uptime: {} seconds", ping_resp.uptime_sec);

    // 配置采集项（第一页的前几个寄存器）
    let trace_config = ConfigRequest {
        items: vec![
            RegTraceItem::new(0, 0x00, 4), // 页0，偏移0，4字节
            RegTraceItem::new(0, 0x04, 4), // 页0，偏移4，4字节
            RegTraceItem::new(0, 0x08, 4), // 页0，偏移8，4字节
            RegTraceItem::new(0, 0x0C, 4), // 页0，偏移12，4字节
        ],
        sample_div: 1,
        buffer_depth: 100,
    };

    println!("Configuring trace with {} items", trace_config.items.len());
    let config_resp = client.config(&mut stream, &trace_config).await?;
    println!(
        "Config response: result={}, items={}",
        config_resp.result, config_resp.actual_items
    );

    // 启动采集
    println!("Starting trace...");
    let start_resp = client.start(&mut stream, true).await?;
    println!("Start response: {}", start_resp.result);

    // 等待一段时间让数据采集
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // 查询状态
    let status = client.status(&mut stream).await?;
    println!(
        "Status: running={}, records={}/{}",
        status.is_running, status.record_count, status.buffer_depth
    );

    // 拉取数据
    let fetch_resp = client.fetch(&mut stream, 10, true).await?;
    println!(
        "Fetched {} records ({} remaining)",
        fetch_resp.record_count, fetch_resp.remaining_count
    );

    for record in &fetch_resp.records {
        println!("  {}", record);
    }

    // 停止采集
    println!("Stopping trace...");
    let stop_resp = client.stop(&mut stream).await?;
    println!("Stop response: {}", stop_resp.result);

    Ok(())
}
