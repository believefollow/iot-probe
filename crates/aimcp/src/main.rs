//! iotprobe-mcp — iot-probe ai-gate 的 MCP server 入口。
//!
//! 用法:
//! - `iotprobe-mcp`            启动 MCP server(stdio 传输;stdout 只走 MCP 协议,诊断走 stderr)
//! - `iotprobe-mcp ai-setup <zcode|trae|cursor|claude>`  打印对应客户端的 MCP 配置 JSON 片段
//! - `iotprobe-mcp help`       用法说明
//!
//! 工具全是只读(设计文档 §3 权限分级):list_devices / read_frames / query_events / export_context。

mod aisetup;
mod collect;
mod config;
mod session;
mod tools;

use rmcp::ServiceExt;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        None => {
            let code = mcp_main();
            std::process::exit(code);
        }
        Some("ai-setup") => {
            std::process::exit(aisetup::run(args.get(2).map(|s| s.as_str())));
        }
        Some("-h" | "--help" | "help") => {
            print_help();
        }
        Some(other) => {
            eprintln!("未知子命令: {other}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("iotprobe-mcp — iot-probe ai-gate:MCP server(第一版只读)");
    println!();
    println!("用法:");
    println!("  iotprobe-mcp                                   启动 MCP server(stdio)");
    println!("  iotprobe-mcp ai-setup <zcode|trae|cursor|claude>  打印客户端 MCP 配置 JSON");
    println!("  iotprobe-mcp help                              本说明");
    println!();
    println!("{}", aisetup::capabilities_line());
    println!("提示词:prompt serbox-expert(内置 {} 行,源文件 crates/aimcp/prompts/serbox-expert.md)", aisetup::prompt_lines());
    println!("配置:iot-probe 同目录 ai-gate.json( devices:[{{name,tcp}}] );stdout 仅承载 MCP 协议。");
}

/// MCP server 主循环:stdio 传输,进程退出即断开(客户端 stdio 生命周期语义)
fn mcp_main() -> i32 {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tokio runtime 创建失败: {e}");
            return 1;
        }
    };
    rt.block_on(async move {
        let server = tools::AimcpServer::new();
        let running = match server.serve(rmcp::transport::stdio()).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("MCP server 启动失败: {e}");
                return 1;
            }
        };
        eprintln!("iotprobe-mcp:ai-gate MCP server 已就绪(stdio;工具 list_devices/read_frames/query_events/export_context + prompt serbox-expert)");
        // waiting():stdio 关闭(客户端退出)后自然返回
        if let Err(e) = running.waiting().await {
            eprintln!("MCP server 异常退出: {e}");
            return 1;
        }
        0
    })
}
