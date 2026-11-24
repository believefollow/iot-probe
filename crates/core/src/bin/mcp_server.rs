//! MCP server(FR-7.1):stdio JSON-RPC,五工具对接 AI 客户端(Claude Desktop / Cursor)。
//! 数据源:契约导出目录(`*.frames.jsonl` + `*.events.jsonl` + `*.signals.jsonl`,
//! 由 IoTProbe「导出CSV」或 dbg_analyze 产出)。
//! 用法:mcp_server.exe <sessions_root>
//! 注册(Claude Desktop / Cursor MCP 配置):
//!   { "mcpServers": { "iotprobe": { "command": "<路径>/mcp_server.exe",
//!                                    "args": ["<sessions_root>"] } } }
//!
//! 协议处理是纯函数(handle_request),便于测试;main 只做 stdio 泵。

use iotprobe_core::export::{build_evidence_bundle, EvidenceMeta};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "iotprobe";
const SERVER_VERSION: &str = "0.1.0";

pub struct SessionStore {
    pub root: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct SessionInfo {
    pub name: String,
    pub frames: usize,
    pub events: usize,
    pub signals: usize,
    pub t_range_s: Option<(f64, f64)>,
}

impl SessionStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        SessionStore { root: root.into() }
    }

    fn paths(&self, session: &str) -> (PathBuf, PathBuf, PathBuf) {
        (
            self.root.join(format!("{session}.frames.jsonl")),
            self.root.join(format!("{session}.events.jsonl")),
            self.root.join(format!("{session}.signals.jsonl")),
        )
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        let mut out = vec![];
        if let Ok(rd) = std::fs::read_dir(&self.root) {
            for e in rd.filter_map(|e| e.ok()) {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(stem) = name.strip_suffix(".frames.jsonl") {
                    let (fp, ep, sp) = self.paths(stem);
                    let frames = load_jsonl(&fp);
                    let events = load_jsonl(&ep);
                    let signals = load_jsonl(&sp);
                    let t = frames
                        .iter()
                        .filter_map(|f| f.get("ts_ns").and_then(|t| t.as_u64()))
                        .reduce(|a, b| if b > a { b } else { a });
                    let t_min = frames
                        .iter()
                        .filter_map(|f| f.get("ts_ns").and_then(|t| t.as_u64()))
                        .reduce(|a, b| if b < a { b } else { a });
                    out.push(SessionInfo {
                        name: stem.to_string(),
                        frames: frames.len(),
                        events: events.len(),
                        signals: signals.len(),
                        t_range_s: t_min.zip(t).map(|(a, b)| (a as f64 / 1e9, b as f64 / 1e9)),
                    });
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn load(&self, session: &str) -> Result<(Vec<Value>, Vec<Value>, Vec<Value>), String> {
        let (fp, ep, sp) = self.paths(session);
        if !fp.exists() {
            return Err(format!("会话不存在: {session}"));
        }
        Ok((load_jsonl(&fp), load_jsonl(&ep), load_jsonl(&sp)))
    }
}

pub fn load_jsonl(path: &PathBuf) -> Vec<Value> {
    std::fs::read_to_string(path)
        .map(|t| t.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
        .unwrap_or_default()
}

// ================= 五个工具 =================

fn ts_ns(v: &Value) -> u64 {
    v.get("ts_ns").and_then(|t| t.as_u64()).unwrap_or(0)
}

fn t_in(v: &Value, from: Option<f64>, to: Option<f64>) -> bool {
    let t = ts_ns(v) as f64 / 1e9;
    from.map(|f| t >= f).unwrap_or(true) && to.map(|t2| t <= t2).unwrap_or(true)
}

fn tool_list_sessions(store: &SessionStore, _args: &Value) -> Result<Value, String> {
    let sessions = store.list();
    Ok(json!({
        "sessions": sessions.iter().map(|s| json!({
            "name": s.name,
            "frames": s.frames,
            "events": s.events,
            "signal_points": s.signals,
            "t_range_s": s.t_range_s,
        })).collect::<Vec<_>>(),
        "hint": "query_events/query_frames 用 name 作为 session 参数",
    }))
}

fn tool_query_events(store: &SessionStore, args: &Value) -> Result<Value, String> {
    let session = args.get("session").and_then(|s| s.as_str()).ok_or("缺少 session")?;
    let ( _, events, _) = store.load(session)?;
    let from = args.get("t_from_s").and_then(|v| v.as_f64());
    let to = args.get("t_to_s").and_then(|v| v.as_f64());
    let level = args.get("level").and_then(|v| v.as_str());
    let code = args.get("code_contains").and_then(|v| v.as_str()).map(|s| s.to_lowercase());
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100).min(1000) as usize;
    let mut out: Vec<&Value> = events
        .iter()
        .filter(|e| t_in(e, from, to))
        .filter(|e| level.map(|l| e.get("level").and_then(|x| x.as_str()) == Some(l)).unwrap_or(true))
        .filter(|e| {
            code.as_ref()
                .map(|c| e.get("code").and_then(|x| x.as_str()).map(|s| s.to_lowercase().contains(c)).unwrap_or(false))
                .unwrap_or(true)
        })
        .collect();
    out.sort_by_key(|e| ts_ns(e));
    let total = out.len();
    let picked: Vec<Value> = out.into_iter().take(limit).cloned().collect();
    Ok(json!({ "session": session, "total": total, "returned": picked.len(), "events": picked }))
}

fn tool_query_frames(store: &SessionStore, args: &Value) -> Result<Value, String> {
    let session = args.get("session").and_then(|s| s.as_str()).ok_or("缺少 session")?;
    let (frames, _, _) = store.load(session)?;
    let from = args.get("t_from_s").and_then(|v| v.as_f64());
    let to = args.get("t_to_s").and_then(|v| v.as_f64());
    let id = args.get("id").and_then(|v| v.as_u64());
    let id_type = args.get("id_type").and_then(|v| v.as_str());
    let proto = args.get("bus_type").and_then(|v| v.as_str());
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200).min(2000) as usize;
    let mut out: Vec<&Value> = frames
        .iter()
        .filter(|f| t_in(f, from, to))
        .filter(|f| id.map(|i| f.get("id").and_then(|x| x.as_u64()) == Some(i)).unwrap_or(true))
        .filter(|f| {
            id_type
                .map(|it| f.get("id_type").and_then(|x| x.as_str()) == Some(it))
                .unwrap_or(true)
        })
        .filter(|f| {
            proto
                .map(|p| f.get("bus").and_then(|b| b.get("type")).and_then(|x| x.as_str()) == Some(p))
                .unwrap_or(true)
        })
        .collect();
    out.sort_by_key(|f| ts_ns(f));
    let total = out.len();
    let picked: Vec<Value> = out.into_iter().take(limit).cloned().collect();
    Ok(json!({ "session": session, "total": total, "returned": picked.len(), "frames": picked }))
}

fn tool_get_signal_series(store: &SessionStore, args: &Value) -> Result<Value, String> {
    let session = args.get("session").and_then(|s| s.as_str()).ok_or("缺少 session")?;
    let name_contains = args
        .get("name_contains")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .ok_or("缺少 name_contains")?;
    let from = args.get("t_from_s").and_then(|v| v.as_f64());
    let to = args.get("t_to_s").and_then(|v| v.as_f64());
    let cap = args.get("downsample").and_then(|v| v.as_u64()).unwrap_or(2000).max(10) as usize;
    let (_, _, signals) = store.load(session)?;
    // 按信号名分组
    let mut groups: BTreeMap<String, Vec<(u64, f64, &str, u64)>> = BTreeMap::new();
    for s in &signals {
        let name = s.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        if !name.to_lowercase().contains(&name_contains) {
            continue;
        }
        let t = s.get("t_ns").and_then(|t| t.as_u64()).unwrap_or(0);
        if !t_in(s, from, to) {
            continue;
        }
        let v = s.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let unit = s.get("unit").and_then(|u| u.as_str()).unwrap_or("");
        let fi = s.get("frame_idx").and_then(|f| f.as_u64()).unwrap_or(0);
        groups.entry(name).or_default().push((t, v, unit, fi));
    }
    let mut series = vec![];
    for (name, mut pts) in groups {
        pts.sort_by_key(|p| p.0);
        let total = pts.len();
        // 均匀抽稀到 cap
        let step = if total > cap { total as f64 / cap as f64 } else { 1.0 };
        let picked: Vec<Value> = (0..total)
            .step_by(step.ceil() as usize)
            .map(|k| {
                let (t, v, u, fi) = pts[k];
                json!({ "t_s": t as f64 / 1e9, "value": v, "unit": u, "frame_idx": fi })
            })
            .collect();
        let unit = pts.last().map(|(_, _, u, _)| u.to_string()).unwrap_or_default();
        series.push(json!({ "name": name, "unit": unit, "total_points": total, "points": picked }));
    }
    Ok(json!({ "session": session, "series": series }))
}

fn tool_export_session(store: &SessionStore, args: &Value) -> Result<Value, String> {
    let session = args.get("session").and_then(|s| s.as_str()).ok_or("缺少 session")?;
    let (frames, events, signals) = store.load(session)?;
    // 窗口:焦点事件 ±10s(S3 场景)或给定范围,缺省全会话
    let (from, to, focus) = if let Some(fid) = args.get("event_id").and_then(|v| v.as_str()) {
        let ev = events
            .iter()
            .find(|e| e.get("id").and_then(|i| i.as_str()) == Some(fid))
            .ok_or_else(|| format!("事件不存在: {fid}"))?;
        let t = ts_ns(ev) as f64 / 1e9;
        (t - 10.0, t + 10.0, Some(fid.to_string()))
    } else {
        (
            args.get("t_from_s").and_then(|v| v.as_f64()).unwrap_or(0.0),
            args.get("t_to_s")
                .and_then(|v| v.as_f64())
                .unwrap_or(f64::MAX / 2.0),
            None,
        )
    };
    let packs: Vec<(String, String)> = {
        let mut m = BTreeMap::new();
        for e in &events {
            if let Some(r) = e.get("evidence").and_then(|ev| ev.get("rule_ref")) {
                if let (Some(p), Some(f)) = (r.get("pack").and_then(|x| x.as_str()), r.get("file").and_then(|x| x.as_str())) {
                    m.insert(p.to_string(), f.to_string());
                }
            }
        }
        m.into_iter().collect()
    };
    let meta = EvidenceMeta {
        session: session.to_string(),
        t_from_s: from.max(0.0),
        t_to_s: to,
        focus_event: focus,
        packs,
    };
    let out_path = store.root.join(format!("{session}_evidence.json"));
    let (evs, fr, sg, truncated) = build_evidence_bundle(&frames, &events, &signals, &meta, &out_path)?;
    let summary: Vec<String> = out_path
        .exists()
        .then(|| {
            serde_json::from_str::<Value>(&std::fs::read_to_string(&out_path).unwrap_or_default())
                .ok()
                .and_then(|d| d.get("summary").cloned())
                .and_then(|s| serde_json::from_value::<Vec<String>>(s).ok())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    Ok(json!({
        "written": out_path.display().to_string(),
        "stats": { "events": evs, "frames": fr, "signal_points": sg, "truncated": truncated },
        "summary": summary,
        "hint": "把该 JSON 文件交给 AI 阅读即可;含事件+信号+原始帧+规则出处",
    }))
}

// ================= MCP 协议处理(纯函数) =================

pub fn tools_definition() -> Value {
    json!([
        {
            "name": "list_sessions",
            "description": "列出可查询的报文会话(帧数/事件数/时间范围)",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "query_events",
            "description": "查询语义/诊断事件。按时间窗、level(info/warn/fault)、code 子串过滤",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "t_from_s": { "type": "number" },
                    "t_to_s": { "type": "number" },
                    "level": { "type": "string", "enum": ["info", "warn", "fault"] },
                    "code_contains": { "type": "string" },
                    "limit": { "type": "integer" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "query_frames",
            "description": "查询原始报文帧(含十六进制字节),按时间窗/id/总线类型过滤",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "t_from_s": { "type": "number" },
                    "t_to_s": { "type": "number" },
                    "id": { "type": "integer", "description": "CAN 11/29bit id" },
                    "id_type": { "type": "string", "enum": ["std", "ext", "none"] },
                    "bus_type": { "type": "string", "enum": ["can", "canfd", "uart", "ecat"] },
                    "limit": { "type": "integer" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "get_signal_series",
            "description": "获取解码信号的时间序列(如 TempSensor/Speed/压差),自动抽稀",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "name_contains": { "type": "string" },
                    "t_from_s": { "type": "number" },
                    "t_to_s": { "type": "number" },
                    "downsample": { "type": "integer" }
                },
                "required": ["session", "name_contains"]
            }
        },
        {
            "name": "export_session",
            "description": "导出证据包(事件+信号+原始帧+规则出处,单文件≤10MB)。event_id 给定时取该事件前后 10 秒",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "event_id": { "type": "string" },
                    "t_from_s": { "type": "number" },
                    "t_to_s": { "type": "number" }
                },
                "required": ["session"]
            }
        }
    ])
}

/// 处理一条 JSON-RPC 请求;通知(无 id)返回 None
pub fn handle_request(store: &SessionStore, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let reply = |result: Result<Value, String>| -> Option<Value> {
        let rid = id?;
        Some(match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": rid, "result": r }),
            Err(e) => json!({ "jsonrpc": "2.0", "id": rid, "error": { "code": -32000, "message": e } }),
        })
    };
    match method.as_str() {
        "initialize" => reply(Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
        }))),
        "notifications/initialized" | "initialized" => None,
        "ping" => reply(Ok(json!({}))),
        "tools/list" => reply(Ok(json!({ "tools": tools_definition() }))),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let result = match name.as_str() {
                "list_sessions" => tool_list_sessions(store, &args),
                "query_events" => tool_query_events(store, &args),
                "query_frames" => tool_query_frames(store, &args),
                "get_signal_series" => tool_get_signal_series(store, &args),
                "export_session" => tool_export_session(store, &args),
                other => Err(format!("未知工具: {other}")),
            };
            match result {
                Ok(v) => reply(Ok(json!({
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }],
                    "isError": false
                }))),
                Err(e) => reply(Ok(json!({
                    "content": [{ "type": "text", "text": e }],
                    "isError": true
                }))),
            }
        }
        other if other.starts_with("notifications/") => None,
        other => {
            let _ = other;
            reply(Err("method not found".into()))
        }
    }
}

fn main() {
    let root = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("IOTPROBE_SESSIONS").ok())
        .unwrap_or_else(|| ".".into());
    let store = SessionStore::new(root);
    use std::io::BufRead;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(resp) = handle_request(&store, &msg) {
            println!("{}", serde_json::to_string(&resp).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn seed_store(dir: &PathBuf) -> SessionStore {
        fs::create_dir_all(dir).unwrap();
        let base = 1767225600_000_000_000u64;
        let mut frames = String::new();
        let mut events = String::new();
        let mut signals = String::new();
        for i in 0..20u64 {
            let t = base + i * 100_000_000;
            frames.push_str(&json!({
                "ts_ns": t, "ts_src": "sw",
                "bus": { "type": "can", "ch": 0, "alias": "BMS-CAN" },
                "dir": "rx", "id": 0x1A0, "id_type": "std", "dlc": 8,
                "data": [i as u8, 0, 0, 0, 0, 0, 0, 0], "meta": { "seq": i + 1 }
            }).to_string());
            frames.push('\n');
            signals.push_str(&json!({ "name": "CAN 0x1A0·Speed", "unit": "kph", "t_ns": t, "value": i as f64, "frame_idx": i }).to_string());
            signals.push('\n');
        }
        events.push_str(&json!({
            "id": "demo:0", "ts_ns": base + 500_000_000, "level": "fault", "code": "OVER_TEMP",
            "source": { "bus_type": "can", "ch": 0, "alias": "BMS-CAN" },
            "message": "温度越限 47.5 °C",
            "evidence": { "signals": [{ "name": "Temp", "value": 47.5 }], "frames_ref": ["0:0:1"], "rule_ref": { "pack": "generic-bms", "file": "rules.yaml", "rule_id": "OVER_TEMP" } }
        }).to_string());
        events.push('\n');
        fs::write(dir.join("demo.frames.jsonl"), frames).unwrap();
        fs::write(dir.join("demo.events.jsonl"), events).unwrap();
        fs::write(dir.join("demo.signals.jsonl"), signals).unwrap();
        SessionStore::new(dir.clone())
    }

    fn call(store: &SessionStore, id: u64, method: &str, params: Value) -> Option<Value> {
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        handle_request(store, &msg)
    }

    #[test]
    fn protocol_handshake_and_tools_list() {
        let store = SessionStore::new("/tmp");
        let r = call(&store, 1, "initialize", json!({})).unwrap();
        assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(r["result"]["serverInfo"]["name"], SERVER_NAME);
        // 通知无响应
        assert!(handle_request(&store, &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).is_none());
        let r = call(&store, 2, "tools/list", json!({})).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5, "五工具");
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"export_session") && names.contains(&"get_signal_series"));
        // 未知方法
        let r = call(&store, 3, "resources/list", json!({})).unwrap();
        assert!(r.get("error").is_some());
    }

    #[test]
    fn tools_query_and_series() {
        let dir = std::env::temp_dir().join("iotprobe_mcp_test");
        let _ = fs::remove_dir_all(&dir);
        let store = seed_store(&dir);
        let r = call(&store, 1, "tools/call", json!({ "name": "list_sessions", "arguments": {} })).unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("demo") && text.contains("frames"), "{text}");
        let r = call(&store, 2, "tools/call", json!({ "name": "query_events", "arguments": { "session": "demo", "level": "fault" } })).unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("OVER_TEMP"), "{text}");
        let r = call(&store, 3, "tools/call", json!({ "name": "query_frames", "arguments": { "session": "demo", "id": 416, "limit": 5 } })).unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("demo"), "{text}");
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["total"], 20);
        assert_eq!(v["returned"], 5);
        let r = call(&store, 4, "tools/call", json!({ "name": "get_signal_series", "arguments": { "session": "demo", "name_contains": "Speed" } })).unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("CAN 0x1A0·Speed"), "{text}");
        // 未知工具 → isError
        let r = call(&store, 5, "tools/call", json!({ "name": "nope", "arguments": {} })).unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn export_session_evidence_bundle() {
        let dir = std::env::temp_dir().join("iotprobe_mcp_test2");
        let _ = fs::remove_dir_all(&dir);
        let store = seed_store(&dir);
        let r = call(&store, 1, "tools/call", json!({ "name": "export_session", "arguments": { "session": "demo", "event_id": "demo:0" } })).unwrap();
        assert_eq!(r["result"]["isError"], false);
        let written = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(written.contains("_evidence.json"), "{written}");
        let doc: Value = serde_json::from_str(&fs::read_to_string(dir.join("demo_evidence.json")).unwrap()).unwrap();
        assert_eq!(doc["type"], "iotprobe-evidence");
        assert!(doc["summary"].as_array().unwrap().iter().any(|s| s.as_str().unwrap().contains("fault")));
        // 契约帧在证据包内
        assert!(doc["frames"].as_array().unwrap().len() >= 10);
        assert!(doc["events"].as_array().unwrap().iter().any(|e| e["code"] == "OVER_TEMP"));
        // 规则出处
        assert!(doc["rule_packs"].as_array().unwrap().iter().any(|p| p["pack"] == "generic-bms"));
    }
}
