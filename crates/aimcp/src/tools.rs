//! MCP server 本体:四个读类工具 + serbox-expert 提示词,rmcp stdio 传输。
//!
//! 权限模型(设计文档 §3):第一版全部只读 ✅;写类工具(send_frame/config_channel)等
//! serbox 控制面(3334)就绪后在控制面任务里解锁,这里不放桩。

use crate::collect::{self, CollectResult};
use crate::config::{self, AiGateConfig};
use crate::session::{self, SharedSession};
use iotprobe_core::model::Dataset;
use rmcp::handler::server::router::prompt::PromptRouter;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResponse, CallToolResult, ContentBlock, GetPromptResult, Implementation,
    InitializeResult, PromptMessage, Role, ServerCapabilities, ServerConfig,
};
use rmcp::{prompt, prompt_handler, prompt_router, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

/// 提示词包(编译期打进二进制;MCP prompts/get 与 ai-setup 都用它)
pub const SERBOX_EXPERT_PROMPT: &str = include_str!("../prompts/serbox-expert.md");

/// 服务器 instructions(MCP initialize 时给客户端的用法提示)
pub const SERVER_INSTRUCTIONS: &str = "iot-probe ai-gate:串口/CAN 总线数据接入与排故(第一版全部只读)。\
开场先 list_devices;排查故障按 query_events → read_frames → 假设 → 建议验证 的顺序;\
结论必须带帧号(frame_no)引用。调用 prompt serbox-expert 可获取完整总线专家打法。\
会话语义:read_frames 的收集结果会成为 query_events/export_context 的当前会话(整体替换)。";

/// 成功结果:JSON 文本作为唯一 text content
fn text_response(json_text: String) -> Result<CallToolResponse, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(json_text)]).into())
}

/// 工具级错误(MCP 规范:执行失败 → isError=true + 可读文本,不要用协议错误吞掉消息)
fn error_response(msg: impl Into<String>) -> Result<CallToolResponse, McpError> {
    Ok(CallToolResult::error(vec![ContentBlock::text(msg.into())]).into())
}

// ---------- 工具入参 schema(schemars 生成;serde 文档注释进 schema 描述) ----------

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ListDevicesParams {}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ReadFramesParams {
    /// 设备名:ai-gate.json 里 devices[].name,自动解析出 TCP 地址;与 tcp/file 三选一
    #[serde(default)]
    pub device: Option<String>,
    /// 直连地址 host:port(serbox NDJSON 帧流,固定 TCP 3333);与 device/file 三选一
    #[serde(default)]
    pub tcp: Option<String>,
    /// 回放文件路径(.ndjson/.jsonl 录制文件,与实时同一解析器);与 device/tcp 三选一
    #[serde(default)]
    pub file: Option<String>,
    /// 最多收集帧数(默认 200,上限 100000;达到即断开/截断)
    #[serde(default)]
    pub max_frames: Option<usize>,
    /// 最长收集秒数(TCP 默认 10s;连续 3s 无新数据也会提前返回;文件源忽略此参数)
    #[serde(default)]
    pub seconds: Option<f64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct QueryEventsParams {
    /// 数据源:设备名(等价 read_frames 的 device);不给则分析当前会话已收集的帧
    #[serde(default)]
    pub device: Option<String>,
    /// 数据源:直连地址 host:port
    #[serde(default)]
    pub tcp: Option<String>,
    /// 数据源:回放文件路径(.ndjson/.jsonl)
    #[serde(default)]
    pub file: Option<String>,
    /// 事件类型过滤(子串匹配,中英文皆可):如 "Timeout"/"校验"/"丢帧"/"CRC";不过滤给全部
    #[serde(default)]
    pub kind: Option<String>,
    /// 最多返回事件数(默认 200)
    #[serde(default)]
    pub max_events: Option<usize>,
    /// 配合数据源收集时的帧数上限(默认 200)
    #[serde(default)]
    pub max_frames: Option<usize>,
    /// 配合数据源收集时的时长上限(TCP 默认 10s)
    #[serde(default)]
    pub seconds: Option<f64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ExportContextParams {
    /// 输出文件路径(绝对路径);缺省写到 ai-gate.json 所在目录(没有则当前目录)的 ai-gate-export/context-<时间戳>.json
    #[serde(default)]
    pub path: Option<String>,
}

// ---------- MCP Server ----------

/// ai-gate MCP 服务。所有状态 = 一个共享会话槽;工具都是读操作 + 本地文件写(仅 export_context)。
pub struct AimcpServer {
    session: SharedSession,
    tool_router: ToolRouter<Self>,
    prompt_router: PromptRouter<Self>,
}

/// 数据源寻址(工具共用):file > tcp > device
enum Source {
    File(String),
    Tcp(String),
    Device(String),
}

impl Source {
    fn from_parts(device: Option<&str>, tcp: Option<&str>, file: Option<&str>) -> Option<Source> {
        if let Some(f) = file {
            return Some(Source::File(f.to_string()));
        }
        if let Some(t) = tcp {
            return Some(Source::Tcp(t.to_string()));
        }
        device.map(|d| Source::Device(d.to_string()))
    }
}

impl AimcpServer {
    pub fn new() -> Self {
        Self {
            session: SharedSession::default(),
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
        }
    }

    /// 收集并写入共享会话(整体替换)。调用方保证 src 存在。
    fn collect_into_session(
        &self,
        src: Source,
        max_frames: Option<usize>,
        seconds: Option<f64>,
    ) -> Result<(CollectResult, String), String> {
        let (r, desc) = match &src {
            Source::File(path) => {
                let r = collect::collect_file(std::path::Path::new(path), max_frames, None)?;
                (r, format!("file:{path}"))
            }
            Source::Tcp(addr) => {
                let r = collect::collect_tcp(addr, max_frames, seconds, None)?;
                (r, format!("tcp:{addr}"))
            }
            Source::Device(name) => {
                let cfg = match config::load()? {
                    Some((_, c)) => c,
                    None => return Err(format!(
                        "未找到 ai-gate.json,无法按设备名 {name:?} 寻址。可让用户在 iot-probe 同目录创建配置,或改用 tcp 参数直连"
                    )),
                };
                let dev = config::find_device(&cfg, name)
                    .ok_or_else(|| format!("ai-gate.json 里没有设备 {name:?};现有:{}", list_names(&cfg)))?;
                let r = collect::collect_tcp(&dev.tcp, max_frames, seconds, Some(name))?;
                (r, format!("device:{name} (tcp:{})", dev.tcp))
            }
        };
        self.session.set(session::Session::from_collect(r.clone(), desc.clone()));
        Ok((r, desc))
    }

    // ---- 工具内部实现(阻塞收集 + 一次 analyze,输出 JSON Value) ----

    fn do_list_devices() -> Result<Value, String> {
        match config::load()? {
            Some((path, cfg)) => Ok(json!({
                "count": cfg.devices.len(),
                "config_path": path.display().to_string(),
                "devices": cfg.devices.iter().map(|d| json!({
                    "name": d.name,
                    "tcp": d.tcp,
                })).collect::<Vec<_>>(),
            })),
            None => Ok(json!({
                "count": 0,
                "config_path": null,
                "devices": [],
                "hint": "未找到 ai-gate.json。可在 iot-probe 同目录(或当前工作目录/可执行文件目录)创建:{\"devices\":[{\"name\":\"serbox-1\",\"tcp\":\"192.168.1.50:3333\"}]};之后 read_frames(device=\"serbox-1\") 即可寻址。没有配置也可以直接用 read_frames 的 tcp 参数直连 host:3333。",
            })),
        }
    }

    /// 读帧:有数据源参数先收集;都缺时沿用当前会话(便于复查),会话为空才报错
    fn do_read_frames(&self, p: ReadFramesParams) -> Result<Value, String> {
        let (collected, parsed_ok, bad_lines, gaps, epoch, warns, desc, stop_label, stop_text) =
            match Source::from_parts(p.device.as_deref(), p.tcp.as_deref(), p.file.as_deref()) {
                Some(src) => {
                    let (r, desc) = self.collect_into_session(src, p.max_frames, p.seconds)?;
                    (
                        r.records.len(),
                        r.stats.ok,
                        r.stats.bad,
                        r.stats.gaps,
                        r.epoch_ns,
                        r.warnings_capped(20),
                        desc,
                        r.stop.label(),
                        r.stop.text(),
                    )
                }
                None if self.session.has_data() => {
                    let s = self.session.snapshot_meta();
                    (s.records, s.ok, s.bad, s.gaps, s.epoch_ns, s.warnings, s.source_desc, s.stop_label, s.stop_text)
                }
                None => return Err("没有指定数据源(device/tcp/file),且当前会话为空;请给出数据源参数".into()),
            };
        self.session
            .with_analyze(|_s, ds: &Dataset| {
                let (frames, sampled) = session::frames_json(ds);
                json!({
                    "source": desc,
                    "collected": collected,
                    "parsed_ok": parsed_ok,
                    "bad_lines": bad_lines,
                    "gaps_detected": gaps,
                    "stop_reason": stop_label,
                    "stop_detail": stop_text,
                    "epoch_ns": epoch,
                    "channels": session::channels_json(ds),
                    "warnings": warns,
                    "frames_returned": frames.len(),
                    "frames_sampled": sampled,
                    "frames": frames,
                    "session_note": "这批帧已成为当前会话:query_events/export_context 默认使用它(read_frames 会整体替换会话)",
                })
            })
            .ok_or_else(|| "内部错误:会话读不到".to_string())
    }

    fn do_query_events(&self, p: QueryEventsParams) -> Result<Value, String> {
        // 带数据源参数 → 先收集(替换会话);否则直接分析当前会话
        if let Some(src) = Source::from_parts(p.device.as_deref(), p.tcp.as_deref(), p.file.as_deref()) {
            self.collect_into_session(src, p.max_frames, p.seconds)?;
        } else if !self.session.has_data() {
            return Err("当前会话为空:先用 read_frames 收集帧,或在本次调用里给 device/tcp/file 参数".into());
        }
        let max_out = p
            .max_events
            .unwrap_or(session::RENDER_MAX_EVENTS)
            .clamp(1, session::RENDER_MAX_EVENTS);
        let kind = p.kind.clone();
        let desc = self.session.source_desc().unwrap_or_default();
        self.session
            .with_analyze(|_s, ds: &Dataset| {
                let (events, total, sampled) = session::events_json(ds, kind.as_deref(), max_out);
                let mut by_kind = std::collections::BTreeMap::<String, usize>::new();
                for e in &ds.events {
                    *by_kind.entry(e.kind.label().to_string()).or_default() += 1;
                }
                json!({
                    "source": desc,
                    "kind_filter": kind,
                    "total_matched": total,
                    "returned": events.len(),
                    "sampled": sampled,
                    "by_kind": by_kind,
                    "events": events,
                    "evidence_note": "events[].frame 是证据帧号 = read_frames 返回的 frames[] 下标(frame_no),可直接引用回跳",
                })
            })
            .ok_or_else(|| "内部错误:会话读不到".to_string())
    }

    fn do_export_context(&self, p: ExportContextParams) -> Result<Value, String> {
        if !self.session.has_data() {
            return Err("当前会话为空:先用 read_frames 收集帧再导出".into());
        }
        // 输出路径:参数 > ai-gate.json 所在目录 > 当前目录;文件名带毫秒时间戳防覆盖
        let out_path = match &p.path {
            Some(x) => std::path::PathBuf::from(x),
            None => {
                let base = config::find_config_path()
                    .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                    .or_else(|| std::env::current_dir().ok())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                base.join("ai-gate-export")
                    .join(format!("context-{}.json", unix_ms()))
            }
        };
        if let Some(dir) = out_path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("创建目录 {} 失败: {e}", dir.display()))?;
        }
        let (text, frames_written, events_written, sampled) = self
            .session
            .with_analyze(|s, ds: &Dataset| {
                let (mut frames, sampled_frames) = session::frames_json(ds);
                let (events, _total, _s) = session::events_json(ds, None, usize::MAX);
                let mut value = build_context_value(s, ds, &frames, &events, sampled_frames);
                let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
                // 单文件 ≤10MB(与 core 证据包一致);超限对帧均匀抽稀后重写
                const MAX_BYTES: usize = 10 * 1024 * 1024;
                let mut by_size = false;
                if text.len() > MAX_BYTES {
                    let n = ds.frames.len().min(session::RENDER_MAX_FRAMES);
                    let step = ds.frames.len() as f64 / n as f64;
                    let idx: Vec<usize> = (0..n)
                        .map(|k| ((k as f64 * step) as usize).min(ds.frames.len() - 1))
                        .collect();
                    frames = idx.iter().map(|&i| session::frame_json(ds, i)).collect();
                    value = build_context_value(s, ds, &frames, &events, true);
                    text = serde_json::to_string_pretty(&value).unwrap_or_default();
                    by_size = true;
                }
                (text, frames.len(), events.len(), by_size)
            })
            .ok_or_else(|| "内部错误:会话读不到".to_string())?;
        std::fs::write(&out_path, &text).map_err(|e| format!("写出 {} 失败: {e}", out_path.display()))?;
        Ok(json!({
            "path": out_path.display().to_string(),
            "bytes": text.len(),
            "frames": frames_written,
            "events": events_written,
            "frames_sampled": sampled,
            "note": "单文件 JSON 上下文包:schema/generated_at/source/meta/frames/events;供人工复核或塞给任何 AI 上下文",
        }))
    }
}

/// 组装上下文包 JSON(帧/事件 + 摘要 meta;不含推断性结论,与 core 证据包原则一致)
fn build_context_value(
    s: &session::Session,
    ds: &Dataset,
    frames: &[Value],
    events: &[Value],
    frames_sampled: bool,
) -> Value {
    json!({
        "schema": "iot-probe ai-gate context pack v1",
        "generated_at": unix_ms(),
        "source": s.source_desc,
        "epoch_ns": s.epoch_ns,
        "meta": {
            "frames_total": ds.frames.len(),
            "frames_in_pack": frames.len(),
            "frames_sampled": frames_sampled,
            "events_total": ds.events.len(),
            "records": ds.records.len(),
            "channels": session::channels_json(ds),
            "warnings": s.warnings.iter().take(50).collect::<Vec<_>>(),
        },
        "frames": frames,
        "events": events,
    })
}

/// 当前 Unix 毫秒(文件名/生成时间)
fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// 设备名清单(错误信息用)
fn list_names(cfg: &AiGateConfig) -> String {
    if cfg.devices.is_empty() {
        "(空)".into()
    } else {
        cfg.devices.iter().map(|d| d.name.as_str()).collect::<Vec<_>>().join(", ")
    }
}

// ---------- rmcp 宏接线 ----------

#[tool_router(router = tool_router)]
impl AimcpServer {
    /// 列出 ai-gate 配置(ai-gate.json)里的 serbox 设备。
    #[tool(
        name = "list_devices",
        description = "列出 ai-gate 配置(ai-gate.json)里的 serbox 设备清单:devices[{name, tcp}] 与配置文件路径。无配置文件时返回空列表 + hint(如何创建配置,或改用 read_frames 的 tcp 参数直连)。开场第一步,确认现场有哪些设备/通道。",
        annotations(read_only_hint = true)
    )]
    fn list_devices(&self, Parameters(_p): Parameters<ListDevicesParams>) -> Result<CallToolResponse, McpError> {
        match Self::do_list_devices() {
            Ok(v) => text_response(v.to_string()),
            Err(e) => error_response(e),
        }
    }

    /// 收集帧并返回结构化帧列表(ts/通道/方向/hex/解析摘要);结果写入当前会话。
    #[tool(
        name = "read_frames",
        description = "收集总线帧并返回结构化列表:每帧含 frame_no/t_rel/t_wall/channel/dir/proto/hex/summary(协议解析摘要)。数据源三选一:device=ai-gate.json 设备名;tcp=直连地址 host:port(serbox NDJSON 帧流 3333);file=.ndjson 回放文件路径。可选 max_frames(默认 200,上限 100000)、seconds(TCP 最长收集秒数,默认 10s;连续 3s 无新数据提前返回)。不带数据源参数时复用当前会话的帧(便于复查)。收集结果成为当前会话(read_frames 会整体替换会话);排故时用 query_events 先看事件。",
        annotations(read_only_hint = true)
    )]
    fn read_frames(&self, Parameters(p): Parameters<ReadFramesParams>) -> Result<CallToolResponse, McpError> {
        match self.do_read_frames(p) {
            Ok(v) => text_response(v.to_string()),
            Err(e) => error_response(e),
        }
    }

    /// 对帧跑完整分析管线,返回异常事件列表(类型/时间/证据帧号)。
    #[tool(
        name = "query_events",
        description = "对收集到的帧跑 iot-probe 分析管线(协议识别/CRC/请求响应配对/丢帧/间隔),返回事件列表:kind(如 校验错误/请求无响应/流丢段/间隔异常)、time、channel、detail、frame(证据帧号 = read_frames 的 frames 下标 frame_no)。可选 kind 子串过滤(如 \"Timeout\"/\"校验\")、max_events(默认 200)。不带数据源参数时分析当前会话;带 device/tcp/file 参数则先收集再分析(会替换会话)。排故第二步:先看事件再翻帧。",
        annotations(read_only_hint = true)
    )]
    fn query_events(&self, Parameters(p): Parameters<QueryEventsParams>) -> Result<CallToolResponse, McpError> {
        match self.do_query_events(p) {
            Ok(v) => text_response(v.to_string()),
            Err(e) => error_response(e),
        }
    }

    /// 把当前会话(帧+事件)写成单文件 JSON 上下文包,返回路径。
    #[tool(
        name = "export_context",
        description = "把当前收集的帧+事件导出为单文件 JSON 上下文包(schema/generated_at/source/meta/frames/events),返回文件绝对路径。可选 path 指定输出位置(缺省写到 ai-gate.json 所在目录的 ai-gate-export/context-<时间戳>.json)。单文件 ≤10MB,超限自动抽稀帧并标注。供人工复核、跨会话留证或直接塞进其他 AI 上下文。",
        annotations(read_only_hint = true)
    )]
    fn export_context(&self, Parameters(p): Parameters<ExportContextParams>) -> Result<CallToolResponse, McpError> {
        match self.do_export_context(p) {
            Ok(v) => text_response(v.to_string()),
            Err(e) => error_response(e),
        }
    }
}

#[prompt_router]
impl AimcpServer {
    /// serbox-expert:总线专家系统提示词(通道约定/frame.schema/排故打法/输出格式)。
    #[prompt(
        name = "serbox-expert",
        description = "总线专家系统提示词:bus.ch 通道约定(0=485/1=232/2=TTL)、frame.schema 字段含义、排故打法(query_events→read_frames→假设→建议验证)、输出格式约定(结论必须带帧号引用)。调用后按它扮演 serbox 总线专家。"
    )]
    fn serbox_expert(&self) -> GetPromptResult {
        GetPromptResult::new(vec![PromptMessage::new_text(Role::User, SERBOX_EXPERT_PROMPT)])
            .with_description("serbox 总线专家系统提示词(ai-gate 提示词包 v1)")
    }
}

// 工具 + 提示词双路由;get_info 手写(同时声明两个 capability,并带 instructions)
#[tool_handler(router = self.tool_router)]
#[prompt_handler(router = self.prompt_router)]
impl ServerHandler for AimcpServer {
    fn get_info(&self) -> ServerConfig {
        let mut info = InitializeResult::new(
            ServerCapabilities::builder().enable_tools().enable_prompts().build(),
        );
        info.server_info = Implementation::new("iotprobe-ai-gate", env!("CARGO_PKG_VERSION"))
            .with_title("iot-probe ai-gate")
            .with_description("serbox/iot-probe 总线能力的 MCP 代理层(第一版只读)");
        info.instructions = Some(SERVER_INSTRUCTIONS.to_string());
        info
    }
}
