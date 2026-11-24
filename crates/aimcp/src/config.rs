//! ai-gate 配置(`ai-gate.json`):设备清单,name → TCP 地址映射。
//!
//! 文件放在 iot-probe 同目录(工作区根/可执行文件旁):
//! ```json
//! {"devices":[{"name":"serbox-1","tcp":"192.168.1.50:3333"}]}
//! ```
//! 查找顺序:当前工作目录 → 可执行文件目录 → 可执行文件上级目录
//! (覆盖「cargo run 从 target/debug 起但配置在仓库根」的场景)。

use serde::Deserialize;

/// 单台 serbox 设备
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceEntry {
    /// 设备名(人类可读,read_frames 用它寻址)
    pub name: String,
    /// NDJSON 帧流地址(TCP 3333),如 192.168.1.50:3333
    pub tcp: String,
}

/// ai-gate.json 的结构(手写小 schema,不引入额外依赖)
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AiGateConfig {
    #[serde(default)]
    pub devices: Vec<DeviceEntry>,
}

/// 常量文件名
pub const CONFIG_FILE: &str = "ai-gate.json";

/// 依次探测候选路径,返回第一个存在的配置文件路径
pub fn find_config_path() -> Option<std::path::PathBuf> {
    let mut candidates: Vec<std::path::PathBuf> = vec![
        std::env::current_dir().ok()?.join(CONFIG_FILE),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(CONFIG_FILE));
            // cargo run 场景:target/debug/iotprobe-mcp.exe → 仓库根
            if let Some(parent) = dir.parent() {
                candidates.push(parent.join(CONFIG_FILE));
            }
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// 读取并解析配置;文件不存在返回 Ok(None);存在但解析失败返回 Err(内容/语法错误要让 AI 看见)
pub fn load() -> Result<Option<(std::path::PathBuf, AiGateConfig)>, String> {
    let Some(path) = find_config_path() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let cfg: AiGateConfig = serde_json::from_str(&text)
        .map_err(|e| format!("解析 {} 失败(期望 {{\"devices\":[{{\"name\":\"...\",\"tcp\":\"host:port\"}}]}}): {e}", path.display()))?;
    Ok(Some((path, cfg)))
}

/// 按名字查设备
pub fn find_device<'a>(cfg: &'a AiGateConfig, name: &str) -> Option<&'a DeviceEntry> {
    cfg.devices.iter().find(|d| d.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let cfg: AiGateConfig =
            serde_json::from_str(r#"{"devices":[{"name":"serbox-1","tcp":"192.168.1.50:3333"}]}"#).unwrap();
        assert_eq!(cfg.devices.len(), 1);
        assert_eq!(cfg.devices[0].name, "serbox-1");
        assert_eq!(cfg.devices[0].tcp, "192.168.1.50:3333");
        // 空对象也合法(设备清单可以为空)
        let empty: AiGateConfig = serde_json::from_str("{}").unwrap();
        assert!(empty.devices.is_empty());
    }

    #[test]
    fn bad_config_is_error() {
        let r: Result<AiGateConfig, _> = serde_json::from_str(r#"{"devices":"oops"}"#);
        assert!(r.is_err());
    }
}
