//! 工具间共享的「当前收集会话」:read_frames 收集 → query_events 分析 → export_context 导出。
//!
//! 会话语义:每次带数据源的收集(直连/文件)整体替换当前会话(单设备单通道流是主场景,
//! 替换比追加更不容易让 AI 拿到混合来源的困惑数据;文档在工具描述里写清)。
//! 分析侧复用 core 的 dissect::analyze 全管线(协议识别/事件/RTT),零拷贝共享字节(Arc<[u8]>)。

use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use iotprobe_core::ingest::SourceData;
use iotprobe_core::model::{Dataset, Dir, EventKind};
use iotprobe_core::timeutil;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

/// 一次会话(一批同源帧)
pub struct Session {
    pub records: Vec<iotprobe_core::model::Record>,
    pub labels: HashMap<u16, String>,
    pub warnings: Vec<String>,
    pub epoch_ns: Option<u64>,
    /// 收集统计(有效帧/坏行/丢帧)
    pub stats: crate::collect::LiveStats,
    /// 收集停止原因
    pub stop: crate::collect::StopReason,
    /// 数据源描述(设备名/地址/文件路径),写进导出包与工具返回
    pub source_desc: String,
}

impl Session {
    pub fn from_collect(c: crate::collect::CollectResult, source_desc: String) -> Self {
        Session {
            records: c.records,
            labels: c.labels,
            warnings: c.warnings,
            epoch_ns: c.epoch_ns,
            stats: c.stats,
            stop: c.stop,
            source_desc,
        }
    }

    /// 跑完整分析管线(协议识别 → 帧 → 事件)。记录字节是 Arc 共享,克隆廉价。
    pub fn analyze(&self) -> Dataset {
        let src = SourceData {
            name: self.source_desc.clone(),
            records: self.records.clone(),
            epoch_ns: self.epoch_ns,
            warnings: self.warnings.clone(),
            chan_labels: self.labels.clone(),
        };
        analyze(vec![src], &AnalyzeCfg::default())
    }
}

/// 全局会话槽(None = 还没收集过)
#[derive(Default)]
pub struct SharedSession(Mutex<Option<Session>>);

impl SharedSession {
    pub fn set(&self, s: Session) {
        *self.0.lock().expect("session 锁中毒") = Some(s);
    }

    /// 对当前会话跑分析;没有会话返回 None
    pub fn with_analyze<R>(&self, f: impl FnOnce(&Session, &Dataset) -> R) -> Option<R> {
        let guard = self.0.lock().expect("session 锁中毒");
        let s = guard.as_ref()?;
        let ds = s.analyze();
        Some(f(s, &ds))
    }

    pub fn has_data(&self) -> bool {
        self.0.lock().expect("session 锁中毒").is_some()
    }

    pub fn source_desc(&self) -> Option<String> {
        self.0.lock().expect("session 锁中毒").as_ref().map(|s| s.source_desc.clone())
    }

    /// 会话元信息快照(复用会话时给工具返回用;不含记录本体)
    pub fn snapshot_meta(&self) -> SessionMeta {
        let guard = self.0.lock().expect("session 锁中毒");
        match guard.as_ref() {
            Some(s) => SessionMeta {
                records: s.records.len(),
                ok: s.stats.ok,
                bad: s.stats.bad,
                gaps: s.stats.gaps,
                epoch_ns: s.epoch_ns,
                warnings: s.warnings.iter().take(20).cloned().collect(),
                source_desc: s.source_desc.clone(),
                stop_label: s.stop.label(),
                stop_text: s.stop.text(),
            },
            None => SessionMeta::default(),
        }
    }
}

/// 会话元信息(工具返回的统计字段)
#[derive(Debug, Clone, Default)]
pub struct SessionMeta {
    pub records: usize,
    pub ok: u64,
    pub bad: u64,
    pub gaps: u64,
    pub epoch_ns: Option<u64>,
    pub warnings: Vec<String>,
    pub source_desc: String,
    pub stop_label: &'static str,
    pub stop_text: &'static str,
}

// ---------- 渲染:Dataset → MCP 返回的 JSON ----------

/// 返回帧列表上限(保护 AI 上下文窗口;超出抽稀并标注)
pub const RENDER_MAX_FRAMES: usize = 2000;
/// 返回事件列表上限
pub const RENDER_MAX_EVENTS: usize = 200;

/// 事件时间:有墙钟锚点用墙钟,否则相对秒
fn fmt_time(epoch_ns: Option<u64>, t_ns: u64) -> String {
    match epoch_ns {
        Some(e) => timeutil::fmt_wall_ns(e.saturating_add(t_ns)),
        None => timeutil::fmt_rel_ns(t_ns),
    }
}

/// 帧 → JSON(ts/通道/方向/hex/解析摘要;frame_no 是全局下标,与 query_events 的证据帧号一致)
pub fn frame_json(ds: &Dataset, i: usize) -> Value {
    let f = &ds.frames[i];
    let rec = &ds.records[f.record as usize];
    let start = (f.off as usize).min(rec.data.len());
    let end = ((f.off + f.len) as usize).min(rec.data.len());
    let hex = rec.data[start..end]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    json!({
        "frame_no": i,
        "t_rel": timeutil::fmt_rel_ns(f.t_ns),
        "t_wall": ds.epoch_ns.map(|e| timeutil::fmt_wall_ns(e.saturating_add(f.t_ns))),
        "channel": ds.channel_label(f.source, f.channel),
        "dir": f.dir.label(),
        "proto": f.proto.label(),
        "bytes": f.len,
        "ts_src": f.ts_src.label(),
        "gap_n": f.gap_n,
        "seq": f.seq,
        "hex": hex,
        "summary": f.summary,
    })
}

/// 帧列表(最多 RENDER_MAX_FRAMES 条;返回 抽稀后的列表 + 是否抽稀)
pub fn frames_json(ds: &Dataset) -> (Vec<Value>, bool) {
    let total = ds.frames.len();
    let sampled = total > RENDER_MAX_FRAMES;
    let mut out = Vec::with_capacity(total.min(RENDER_MAX_FRAMES));
    if sampled {
        // 均匀抽稀:保首尾,步进采样
        let step = total as f64 / RENDER_MAX_FRAMES as f64;
        for k in 0..RENDER_MAX_FRAMES {
            out.push(frame_json(ds, ((k as f64 * step) as usize).min(total - 1)));
        }
    } else {
        for i in 0..total {
            out.push(frame_json(ds, i));
        }
    }
    (out, sampled)
}

/// 事件列表(kind 子串过滤可选;返回 (列表, 过滤后总数, 是否抽稀))
pub fn events_json(ds: &Dataset, kind_filter: Option<&str>, max_out: usize) -> (Vec<Value>, usize, bool) {
    let matched: Vec<(usize, &iotprobe_core::model::Event)> = ds
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| match kind_filter {
            Some(k) if !k.is_empty() => {
                // 类型中英文都可过滤:kind 中文标签 / 契约码 / detail 都参与匹配
                e.kind.label().contains(k) || e.kind.diag_code().contains(k) || e.detail.contains(k)
            }
            _ => true,
        })
        .collect();
    let total = matched.len();
    let sampled = total > max_out;
    let mut out = Vec::new();
    for &(i, e) in matched.iter().take(max_out) {
        // 证据帧:core 事件自带引用优先;日志收尾 Timeout / 流丢段不带 frame(core 行为),
        // 这里按时间就近推断(frame_source=inferred),AI 结论可回跳验证。
        let (frame, frame_source) = match e.frame {
            Some(f) => (Some(f), "event"),
            None => {
                let fb = match e.kind {
                    EventKind::Timeout => ds.frames.iter().rposition(|f| {
                        f.source == e.source && f.channel == e.channel && f.dir == Dir::Tx && f.t_ns <= e.t_ns
                    }),
                    EventKind::StreamDrop => ds.frames.iter().position(|f| {
                        f.source == e.source && f.channel == e.channel && f.t_ns >= e.t_ns
                    }),
                    _ => None,
                };
                (fb.map(|x| x as u32), if fb.is_some() { "inferred" } else { "none" })
            }
        };
        out.push(json!({
            "no": i,
            "kind": e.kind.label(),
            "kind_code": e.kind.diag_code(),
            "level": e.kind.diag_level(),
            "rule": e.rule.as_ref().map(|r| json!({"pack": r.pack, "rule_id": r.rule_id, "level": r.level})),
            "time": fmt_time(ds.epoch_ns, e.t_ns),
            "t_rel": timeutil::fmt_rel_ns(e.t_ns),
            "channel": ds.channel_label(e.source, e.channel),
            "detail": e.detail,
            "frame": frame,
            "frame_source": frame_source,
            "evidence": frame.map(|fi| format!("read_frames 结果的 frames[{fi}](frame_no={fi},{frame_source})")),
        }));
    }
    (out, total, sampled)
}

/// 通道概览
pub fn channels_json(ds: &Dataset) -> Vec<Value> {
    ds.channels
        .iter()
        .map(|c| {
            let n = ds.frames.iter().filter(|f| f.source == c.source && f.channel == c.id).count();
            json!({
                "label": c.label,
                "proto": c.proto.label(),
                "ts_src": c.ts_src.label(),
                "ts_level": c.ts_src.level(),
                "frames": n,
            })
        })
        .collect()
}
