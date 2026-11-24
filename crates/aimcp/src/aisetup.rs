//! `ai-setup <client>`:打印各 AI 客户端的 MCP 配置 JSON 片段(stdio 形式,粘贴即用)。
//!
//! 设计原则(与 Magpie/ai-gate 文档一致):**打印即粘贴,零文档查阅**。
//! stdout 只输出 JSON(机器可定向);说明文字走 stderr,不污染粘贴内容。
//! command 用当前可执行文件的绝对路径 —— 客户端启动 MCP server 不依赖 PATH。

use crate::collect;
use crate::tools::SERBOX_EXPERT_PROMPT;

/// 支持的客户端清单
pub const CLIENTS: &[&str] = &["zcode", "trae", "cursor", "claude"];

/// 生成某客户端的配置片段(纯 JSON 文本,可直接粘进对应配置文件)
pub fn snippet(client: &str) -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("无法定位 iotprobe-mcp 可执行文件: {e}"))?;
    let cmd = exe.to_string_lossy().replace('\\', "\\\\");
    let body = |extra: &str| -> String {
        format!(
            "{{\n  \"mcpServers\": {{\n    \"iot-probe\": {{\n      \"command\": \"{cmd}\",\n      \"args\": []{extra}\n    }}\n  }}\n}}"
        )
    };
    match client {
        // ZCode:mcpServers 段(全局或工作区 MCP 配置)
        "zcode" => Ok(body(",\n      \"env\": {}")),
        // Trae:手动添加 MCP 时粘贴的 JSON(mcpServers 形态)
        "trae" => Ok(body(",\n      \"env\": {}")),
        // Cursor:~/.cursor/mcp.json(项目级 .cursor/mcp.json 同构)
        "cursor" => Ok(body("")),
        // Claude Code:项目 .mcp.json / claude mcp add-json 均为 mcpServers 形态
        "claude" => Ok(body("")),
        other => Err(format!(
            "未知客户端 {other:?};支持:{}",
            CLIENTS.join(" | ")
        )),
    }
}

/// 每个客户端的粘贴位置说明(stderr)
fn where_to_paste(client: &str) -> &'static str {
    match client {
        "zcode" => "粘贴到 ZCode 的 MCP 配置(mcpServers 段):全局 ~/.zcode/cli/mcp.json 或工作区 .zcode/mcp.json,重启客户端生效。",
        "trae" => "粘贴到 Trae 的「MCP 手动添加」输入框(或 trae 配置的 mcpServers 段),保存后确认服务器已连接。",
        "cursor" => "粘贴到 ~/.cursor/mcp.json(全局)或项目 .cursor/mcp.json,重启 Cursor 后在 MCP 设置里确认已连接。",
        "claude" => "粘贴到项目根 .mcp.json,或执行:claude mcp add-json iot-probe '<以上JSON的iot-probe对象>'。",
        _ => "",
    }
}

/// 子命令入口:`iotprobe-mcp ai-setup <client>`
pub fn run(client: Option<&str>) -> i32 {
    let Some(client) = client else {
        eprintln!("用法: iotprobe-mcp ai-setup <{}>", CLIENTS.join("|"));
        eprintln!("  stdout 输出该客户端的 MCP 配置 JSON 片段(stdio 形式),说明走 stderr。");
        return 2;
    };
    if client == "list" {
        println!("{}", CLIENTS.join("\n"));
        return 0;
    }
    match snippet(client) {
        Ok(json) => {
            println!("{json}");
            eprintln!("# iot-probe ai-gate (iotprobe-mcp) — 只读工具: list_devices/read_frames/query_events/export_context + prompt serbox-expert");
            eprintln!("# {}", where_to_paste(client));
            eprintln!("# 提示词包已内置,客户端里调用 prompt serbox-expert 即可注入总线专家打法;");
            eprintln!("# 也可直接阅读随仓库分发的 crates/aimcp/prompts/serbox-expert.md(本二进制内嵌同一份)。");
            eprintln!("# 排故工作流提示:read_frames 会话会被 query_events/export_context 复用;导出包默认落在 ai-gate-export/。");
            eprintln!("# (ai-gate v1;写类工具 send_frame/config_channel 待 serbox 控制面就绪后解锁)");
            0
        }
        Err(e) => {
            eprintln!("ai-setup 失败: {e}");
            1
        }
    }
}

/// 给 --help 用的能力清单文本(引用 collect 常量,保持文案与实现一致)
pub fn capabilities_line() -> String {
    format!(
        "读类工具: list_devices / read_frames(默认 {} 帧,空闲 {}s 自动收口) / query_events / export_context",
        collect::DEFAULT_MAX_FRAMES,
        collect::IDLE_TIMEOUT.as_secs()
    )
}

/// 提示词包行数(供 help 展示,确认二进制确实内嵌了提示词)
pub fn prompt_lines() -> usize {
    SERBOX_EXPERT_PROMPT.lines().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippets_are_valid_json() {
        for c in CLIENTS {
            let s = snippet(c).unwrap();
            let v: serde_json::Value = serde_json::from_str(&s).unwrap();
            let server = &v["mcpServers"]["iot-probe"];
            assert!(server["command"].as_str().unwrap().len() > 0, "command 必须存在: {s}");
            assert_eq!(server["args"], serde_json::json!([]));
        }
    }

    #[test]
    fn unknown_client_errors() {
        assert!(snippet("windsurf").is_err());
    }
}
