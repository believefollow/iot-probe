//! ai-gate MCP 集成测试:起本地 mock TCP 源推 NDJSON 样例,把 iotprobe-mcp 当真实
//! 二进制拉起,直接走 JSON-RPC over stdio(MCP stdio 传输就是行分隔 JSON-RPC),
//! 验证 initialize / tools/list / tools/call / prompts/get 全链路。
//!
//! 不引入 rmcp client 依赖:stdio 线格式是冻结契约(与 GUI/脚本直连一致)。

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// 与 core live 集成测试同一份样例(8 条有效帧 + 1 条坏行)
const MOCK: &str = include_str!("../../core/tests/data/mock_live.ndjson");

const REQ_TIMEOUT: Duration = Duration::from_secs(30);

/// 一个跑起来的 MCP server 子进程(带 stdout 行读取线程)
struct McpProc {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<(Value, Value)>, // (id, 完整响应)
    next_id: u64,
}

impl McpProc {
    /// 拉起二进制;cwd 指定时 list_devices/export_context 以该目录为基准
    fn spawn(cwd: Option<&std::path::Path>) -> McpProc {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_iotprobe-mcp"));
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("启动 iotprobe-mcp");
        // stderr 异步排空(诊断信息,不阻塞)
        if let Some(err) = child.stderr.take() {
            std::thread::spawn(move || {
                let r = BufReader::new(err);
                for line in r.lines().flatten() {
                    eprintln!("[iotprobe-mcp] {line}");
                }
            });
        }
        let stdout = child.stdout.take().expect("stdout");
        let stdin = child.stdin.take().expect("stdin");
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let r = BufReader::new(stdout);
            for line in r.lines().flatten() {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    eprintln!("[iotprobe-mcp 非JSON行] {line}");
                    continue;
                };
                let Some(id) = v.get("id").cloned() else {
                    continue; // 通知/日志,忽略
                };
                if tx.send((id, v)).is_err() {
                    break;
                }
            }
        });
        McpProc { child, stdin, rx, next_id: 1 }
    }

    fn send_raw(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").expect("写入 stdin");
        self.stdin.flush().expect("flush stdin");
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send_raw(&json!({"jsonrpc": "2.0", "method": method, "params": params}).to_string());
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send_raw(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
        );
        let deadline = Instant::now() + REQ_TIMEOUT;
        loop {
            let now = Instant::now();
            if now >= deadline {
                panic!("等待 {method} 响应超时");
            }
            match self.rx.recv_timeout(deadline - now) {
                Ok((rid, v)) if rid == json!(id) => {
                    if let Some(err) = v.get("error") {
                        panic!("{method} 返回 JSON-RPC 错误: {err}");
                    }
                    return v["result"].clone();
                }
                Ok(_) => continue, // 别的 id(理论上不会乱序,容错跳过)
                Err(RecvTimeoutError::Timeout) => panic!("等待 {method} 响应超时"),
                Err(RecvTimeoutError::Disconnected) => panic!("iotprobe-mcp stdout 关闭({method})"),
            }
        }
    }

    /// 完成握手(initialize → initialized)
    fn handshake(&mut self) -> Value {
        let init = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "aimcp-it", "version": "0.0.1"},
            }),
        );
        self.notify("notifications/initialized", json!({}));
        init
    }

    fn call_tool(&mut self, name: &str, args: Value) -> Value {
        let result = self.request("tools/call", json!({"name": name, "arguments": args}));
        let is_error = result["isError"].as_bool().unwrap_or(false);
        assert!(!is_error, "工具 {name} 返回 isError: {result}");
        let text = result["content"][0]["text"].as_str().unwrap_or_else(|| panic!("工具 {name} 无文本内容: {result}"));
        serde_json::from_str(text).unwrap_or_else(|e| panic!("工具 {name} 文本不是合法 JSON: {e}; {text}"))
    }

    fn shutdown(&mut self) {
        // stdio 关闭 → 服务端 waiting() 返回
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

impl Drop for McpProc {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// mock serbox:监听后把样例 NDJSON 全量推给第一个连入者,然后关闭(触发 EOF)
fn spawn_mock_serbox() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(MOCK.as_bytes()).unwrap();
        s.flush().unwrap();
        std::thread::sleep(Duration::from_millis(50)); // 给读取留一点时间
        s.shutdown(std::net::Shutdown::Both).ok();
    });
    (addr, h)
}

#[test]
fn full_flow_over_stdio() {
    let (addr, mock) = spawn_mock_serbox();
    let cwd = std::env::temp_dir().join(format!("iotprobe_aimcp_it_{}", std::process::id()));
    std::fs::create_dir_all(&cwd).unwrap();
    let mut mcp = McpProc::spawn(Some(&cwd));

    // ---- initialize:服务端信息/capabilities/instructions ----
    let init = mcp.handshake();
    assert_eq!(init["serverInfo"]["name"], "iotprobe-ai-gate", "init={init}");
    assert_eq!(init["capabilities"]["tools"].as_object().unwrap().len() >= 0, true);
    assert!(init["capabilities"]["prompts"].is_object(), "prompts capability={}", init["capabilities"]);
    assert!(init["instructions"].as_str().unwrap().contains("只读"), "instructions={init}");

    // ---- tools/list:四个读类工具,描述非空,全部只读标记 ----
    let tools = mcp.request("tools/list", json!({}));
    let names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for want in ["list_devices", "read_frames", "query_events", "export_context"] {
        assert!(names.contains(&want), "缺工具 {want}; names={names:?}");
    }
    for t in tools["tools"].as_array().unwrap() {
        assert!(t["description"].as_str().map(|d| d.len() > 30).unwrap_or(false), "工具 {} 描述缺失", t["name"]);
        assert_eq!(t["annotations"]["readOnlyHint"], json!(true), "只读标注: {}", t["name"]);
        assert!(t["inputSchema"].is_object(), "inputSchema: {}", t["name"]);
    }

    // ---- read_frames:直连 mock TCP,断言帧解析 ----
    let rf = mcp.call_tool(
        "read_frames",
        json!({"tcp": addr.to_string(), "max_frames": 50, "seconds": 5}),
    );
    assert_eq!(rf["collected"], 8, "8 条有效帧 rf={rf}");
    assert_eq!(rf["bad_lines"], 1, "1 条坏行进 warnings");
    assert_eq!(rf["gaps_detected"], 1, "seq 2→5 丢帧检出");
    assert_eq!(rf["frames_returned"], 8);
    let frames = rf["frames"].as_array().unwrap();
    // 帧 0:Modbus RTU 请求(uart ch0,alias 电表-485,tx)
    assert_eq!(frames[0]["frame_no"], 0);
    assert!(frames[0]["channel"].as_str().unwrap().contains("电表-485"), "帧内 alias 优先, rf={rf}");
    assert_eq!(frames[0]["dir"], "TX");
    assert_eq!(frames[0]["proto"], "Modbus RTU", "请求/响应配对识别, rf={rf}");
    assert_eq!(frames[0]["hex"], "01 03 00 00 00 02 C4 0B");
    assert!(frames[0]["summary"].as_str().unwrap().contains("读保持寄存器"), "summary={}", frames[0]["summary"]);
    // 第二帧响应含读到的寄存器
    assert_eq!(frames[1]["dir"], "RX");
    assert_eq!(frames[1]["proto"], "Modbus RTU");
    // CAN 帧:ext id 显示 + 通道合并
    let can = frames.iter().find(|f| f["proto"] == "CAN").expect("CAN 通道");
    assert!(can["channel"].as_str().unwrap().contains("BMS-CAN"));
    // 丢帧标注(gap_n)在 seq=5 的帧上
    let gapped: Vec<&Value> = frames.iter().filter(|f| f["gap_n"].as_u64().unwrap_or(0) > 0).collect();
    assert_eq!(gapped.len(), 1, "gap_n 标注 rf={rf}");
    assert_eq!(gapped[0]["gap_n"], 2);
    // 墙钟时间:样例首帧 ts=1767225600000000000(2026-01-01)
    assert_eq!(frames[0]["t_wall"], "2026-01-01 00:00:00.000", "wall time(UTC)={}", frames[0]["t_wall"]);

    // ---- query_events:当前会话(RT 配对)→ Timeout + StreamDrop,证据帧号 ----
    let qe = mcp.call_tool("query_events", json!({}));
    let events = qe["events"].as_array().unwrap();
    let kinds: Vec<&str> = events.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"请求无响应"), "第三条请求无响应 → Timeout; kinds={kinds:?}");
    assert!(kinds.contains(&"流丢段"), "seq 丢帧 → StreamDrop; kinds={kinds:?}");
    let timeout_ev = events.iter().find(|e| e["kind"] == "请求无响应").unwrap();
    assert!(timeout_ev["frame"].is_u64(), "Timeout 事件带证据帧号: {timeout_ev}");
    // 日志收尾的 Timeout core 不带 frame → aimcp 按时间就近推断出请求帧 frame_no=2
    assert_eq!(timeout_ev["frame"], json!(2), "推断证据帧: {timeout_ev}");
    assert_eq!(timeout_ev["frame_source"], "inferred");
    assert!(timeout_ev["detail"].as_str().unwrap().contains("无响应"));
    // 流丢段事件同样就近推断到 seq=5 的帧(frame_no=6)
    let drop_ev = events.iter().find(|e| e["kind"] == "流丢段").unwrap();
    assert_eq!(drop_ev["frame"], json!(6), "流丢段推断证据帧: {drop_ev}");
    // kind 过滤
    let qe2 = mcp.call_tool("query_events", json!({"kind": "丢"}));
    let k2: Vec<&str> = qe2["events"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert!(k2.iter().all(|k| k.contains("丢")), "kind 过滤: {k2:?}");
    assert_eq!(qe2["total_matched"], qe2["returned"], "无抽稀");

    // ---- export_context:默认写到 cwd/ai-gate-export,文件内容自洽 ----
    let ec = mcp.call_tool("export_context", json!({}));
    let path = ec["path"].as_str().unwrap().to_string();
    assert!(path.contains("ai-gate-export"), "导出路径: {path}");
    assert!(std::path::Path::new(&path).is_file(), "文件已写出: {path}");
    let pack: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(pack["schema"], "iot-probe ai-gate context pack v1");
    assert_eq!(pack["frames"].as_array().unwrap().len(), 8);
    assert!(pack["events"].as_array().unwrap().len() >= 2);
    assert_eq!(pack["meta"]["frames_total"], 8);
    assert_eq!(pack["source"], format!("tcp:{}", addr));

    // ---- list_devices:cwd 无配置 → 空列表 + hint ----
    let ld = mcp.call_tool("list_devices", json!({}));
    assert_eq!(ld["count"], 0);
    assert!(ld["hint"].as_str().unwrap().contains("ai-gate.json"), "hint={}", ld["hint"]);

    // ---- prompts/get serbox-expert:提示词包内置可达 ----
    let pr = mcp.request("prompts/get", json!({"name": "serbox-expert", "arguments": {}}));
    let msg_text = pr["messages"][0]["content"]["text"].as_str().expect("prompt 文本");
    assert!(msg_text.contains("bus.ch"), "提示词含通道约定");
    assert!(msg_text.contains("帧号"), "提示词含输出格式约定");

    mock.join().unwrap();
    mcp.shutdown();
}

#[test]
fn list_devices_reads_config_and_read_frames_by_device() {
    let cwd = std::env::temp_dir().join(format!("iotprobe_aimcp_cfg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cwd);
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(
        cwd.join("ai-gate.json"),
        r#"{"devices":[{"name":"serbox-it","tcp":"127.0.0.1:1"}]}"#,
    )
    .unwrap();
    let mut mcp = McpProc::spawn(Some(&cwd));
    mcp.handshake();

    let ld = mcp.call_tool("list_devices", json!({}));
    assert_eq!(ld["count"], 1, "ld={ld}");
    assert_eq!(ld["devices"][0]["name"], "serbox-it");
    assert_eq!(ld["devices"][0]["tcp"], "127.0.0.1:1");
    assert!(ld["config_path"].as_str().unwrap().contains("ai-gate.json"));

    // device 寻址:配置里有但端口没人听 → 工具返回 is_error 且文本可读(不是 crash)
    let result = mcp.request("tools/call", json!({"name": "read_frames", "arguments": {"device": "serbox-it", "seconds": 2}}));
    assert_eq!(result["isError"], json!(true), "连接失败应报 is_error: {result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("连接") || text.contains("127.0.0.1:1"), "错误文本: {text}");

    // 未知设备名 → 明确报错并列出现有设备
    let result2 = mcp.request("tools/call", json!({"name": "read_frames", "arguments": {"device": "nope"}}));
    assert_eq!(result2["isError"], json!(true));
    let text2 = result2["content"][0]["text"].as_str().unwrap();
    assert!(text2.contains("serbox-it"), "错误应列出现有设备: {text2}");

    mcp.shutdown();
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn file_source_and_session_reuse() {
    let cwd = std::env::temp_dir().join(format!("iotprobe_aimcp_file_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cwd);
    std::fs::create_dir_all(&cwd).unwrap();
    let ndjson = cwd.join("replay.ndjson");
    std::fs::write(&ndjson, MOCK).unwrap();
    let mut mcp = McpProc::spawn(Some(&cwd));
    mcp.handshake();

    // 文件源收集(query_events 直接带 file 参数:收集+分析一条龙)
    let qe = mcp.call_tool("query_events", json!({"file": ndjson.to_string_lossy()}));
    assert!(qe["events"].as_array().unwrap().len() >= 2, "qe={qe}");
    // read_frames 不带数据源 → 复用刚收集的会话
    let rf = mcp.call_tool("read_frames", json!({}));
    assert_eq!(rf["collected"], 8, "会话复用: rf={rf}");
    assert!(rf["source"].as_str().unwrap().starts_with("file:"));
    // export_context 指定路径
    let out = cwd.join("my-pack.json");
    let ec = mcp.call_tool("export_context", json!({"path": out.to_string_lossy()}));
    assert_eq!(ec["path"], out.to_string_lossy().as_ref());
    assert!(out.is_file());

    mcp.shutdown();
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn ai_setup_prints_client_json() {
    for client in ["zcode", "trae", "cursor", "claude"] {
        let out = Command::new(env!("CARGO_BIN_EXE_iotprobe-mcp"))
            .args(["ai-setup", client])
            .output()
            .expect("ai-setup 运行");
        assert!(out.status.success(), "ai-setup {client} 退出码 {:?}", out.status.code());
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("ai-setup {client} stdout 不是纯 JSON: {e}; {stdout}"));
        let server = &v["mcpServers"]["iot-probe"];
        assert!(server["command"].as_str().unwrap().contains("iotprobe-mcp"), "{stdout}");
        assert_eq!(server["args"], json!([]));
        // stderr 有粘贴位置说明但不污染 stdout
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("prompt serbox-expert"), "stderr 说明: {stderr}");
    }
    // 未知客户端 → 非零退出
    let bad = Command::new(env!("CARGO_BIN_EXE_iotprobe-mcp"))
        .args(["ai-setup", "windsurf"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
