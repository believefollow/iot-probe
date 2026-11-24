//! CSV 导出。


fn esc(s: &str) -> String {
    let s = s.replace('"', "\"\"");
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{s}\"")
    } else {
        s
    }
}

pub fn frames_csv(ds: &Dataset, path: &std::path::Path) -> Result<(), String> {
    let mut out = String::from("idx,t_rel_s,wall,dir,source,channel,proto,len,summary\n");
    for (i, f) in ds.frames.iter().enumerate() {
        let wall = ds
            .epoch_ns
            .map(|e| crate::timeutil::fmt_wall_ns(e + f.t_ns))
            .unwrap_or_default();
        out.push_str(&format!(
            "{},{:.6},{},{},{},{},{},{},{}\n",
            i,
            f.t_ns as f64 / 1e9,
            wall,
            f.dir.label(),
            ds.channels.iter().find(|c| c.source == f.source).map(|c| c.label.clone()).unwrap_or_default(),
            f.channel,
            f.proto.label(),
            f.len,
            esc(&f.summary)
        ));
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

pub fn signals_csv(ds: &Dataset, path: &std::path::Path) -> Result<(), String> {
    let mut out = String::from("signal,unit,t_rel_s,value,frame_idx\n");
    for s in &ds.signals {
        for (t, v, fi) in &s.pts {
            out.push_str(&format!(
                "{},{},{:.6},{},{}\n",
                esc(&s.key),
                esc(&s.unit),
                *t as f64 / 1e9,
                v,
                fi
            ));
        }
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

pub fn events_csv(ds: &Dataset, path: &std::path::Path) -> Result<(), String> {
    let mut out = String::from("t_rel_s,kind,detail,frame_idx\n");
    for e in &ds.events {
        out.push_str(&format!(
            "{:.6},{},{},{}\n",
            e.t_ns as f64 / 1e9,
            e.kind.label(),
            esc(&e.detail),
            e.frame.map(|f| f.to_string()).unwrap_or_default()
        ));
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

// ================= 契约导出(ADR-0007:冻结 schema + 映射约定) =================

use crate::model::{Dataset, Dir, Frame, Proto};

fn bus_type(p: Proto) -> &'static str {
    match p {
        Proto::Can => "can",
        Proto::CanFd => "canfd",
        Proto::EtherCat => "ecat",
        _ => "uart", // ADR-0007:非 CAN/EtherCAT 字节流一律 uart,真实载体进 meta.transport
    }
}

fn transport(p: Proto) -> &'static str {
    match p {
        Proto::Tcp | Proto::ModbusTcp | Proto::Mqtt | Proto::Iec104 | Proto::Http => "tcp",
        Proto::Udp => "udp",
        _ => "serial-log",
    }
}

fn dir_str(d: Dir) -> (&'static str, bool) {
    match d {
        Dir::Rx => ("rx", false),
        Dir::Tx => ("tx", false),
        // ADR-0007:无方向标记 → rx + meta.assumed_dir 如实标注
        Dir::Unknown => ("rx", true),
    }
}

fn alias_of(ds: &Dataset, f: &Frame) -> String {
    let full = ds.channel_label(f.source, f.channel);
    // 去掉 "[文件名] " 前缀,保留用户可读别名
    let a = full
        .find("] ")
        .map(|k| full[k + 2..].to_string())
        .unwrap_or(full);
    a.chars().take(64).collect()
}

/// 导出为 frame.schema.json 形态的 JSONL(data.maxItems 按 ADR-0007 放宽到 512)
pub fn frames_jsonl(ds: &Dataset, path: &std::path::Path) -> Result<usize, String> {
    use serde_json::json;
    let mut out = String::new();
    let mut n = 0usize;
    for f in &ds.frames {
        let rec = &ds.records[f.record as usize];
        let (id_bits, ext) = rec.id_split();
        let (dir, assumed) = dir_str(f.dir);
        let is_can = matches!(f.proto, Proto::Can | Proto::CanFd);
        let id = if is_can { id_bits } else { 0 };
        let id_type = if is_can {
            if ext { "ext" } else { "std" }
        } else {
            "none"
        };
        let data = &rec.data[f.off as usize..(f.off + f.len) as usize];
        // ADR-0007:uart 字节流上限 512;超出分段,frag 记录分片序号
        let chunks: Vec<&[u8]> = if data.len() <= 512 {
            vec![data]
        } else {
            data.chunks(512).collect()
        };
        for (k, chunk) in chunks.iter().enumerate() {
            let mut meta = json!({ "seq": f.seq });
            if f.gap_n > 0 {
                meta["gap"] = json!(f.gap_n);
            }
            meta["transport"] = json!(transport(f.proto));
            if assumed {
                meta["assumed_dir"] = json!(true);
            }
            if chunks.len() > 1 {
                meta["frag"] = json!(k);
                meta["frag_total"] = json!(chunks.len());
            }
            let obj = json!({
                "ts_ns": f.t_ns,
                "ts_src": f.ts_src.label(),
                "bus": {
                    "type": bus_type(f.proto),
                    "ch": f.channel,
                    "alias": alias_of(ds, f),
                },
                "dir": dir,
                "id": id,
                "id_type": id_type,
                "dlc": chunk.len(),
                "data": chunk.iter().map(|b| json!(b)).collect::<Vec<_>>(),
                "meta": meta,
            });
            out.push_str(&serde_json::to_string(&obj).map_err(|e| e.to_string())?);
            out.push('\n');
            n += 1;
        }
    }
    std::fs::write(path, out).map_err(|e| e.to_string())?;
    Ok(n)
}

/// 导出为 event.schema.json 形态的 JSONL。
/// 注意:这些是解析层诊断事件,rule_ref.pack="builtin-diag"(ADR-0007);
/// 厂商语义事件待 rules 引擎(T-2.1)产出后走正规路径。
pub fn events_jsonl(ds: &Dataset, path: &std::path::Path) -> Result<usize, String> {
    use serde_json::json;
    let mut out = String::new();
    let session_id: String = ds.name.chars().take(48).collect();
    for (i, e) in ds.events.iter().enumerate() {
        let cm = ds.channels.iter().find(|c| c.source == e.source && c.id == e.channel);
        let bus_type = cm.map(|c| bus_type(c.proto)).unwrap_or("system");
        let ch = cm.map(|c| c.id as i64).unwrap_or(0);
        let alias = cm.map(|c| {
            let full = &c.label;
            let a = full.find("] ").map(|k| full[k + 2..].to_string()).unwrap_or(full.clone());
            a.chars().take(64).collect::<String>()
        }).unwrap_or_default();
        let frame_key = e.frame.map(|fi| {
            let f = &ds.frames[fi as usize];
            format!("{}:{}:{}", f.source, f.channel, f.seq)
        });
        // 规则事件(ADR-6)与诊断事件(builtin-diag)统一映射到 event.schema
        let (code, level, rule_ref, sigs) = match &e.rule {
            Some(r) => (
                json!(r.rule_id),
                json!(r.level),
                json!({ "pack": r.pack, "file": r.file, "rule_id": r.rule_id }),
                r.signals
                    .iter()
                    .map(|(n, v, u)| {
                        let mut o = json!({ "name": n, "value": v });
                        if !u.is_empty() {
                            o["unit"] = json!(u);
                        }
                        o
                    })
                    .collect::<Vec<_>>(),
            ),
            None => (
                json!(e.kind.diag_code()),
                json!(e.kind.diag_level()),
                json!({ "pack": "builtin-diag", "file": "crates/core/src/dissect", "rule_id": format!("{:?}", e.kind) }),
                vec![],
            ),
        };
        let (signal_name, signal_value) = match e.frame {
            Some(fi) => (format!("frame#{}", fi), json!(ds.frames[fi as usize].summary)),
            None => (format!("t_s"), json!(e.t_ns as f64 / 1e9)),
        };
        // 契约要求 signals ≥1:规则无信号证据时回退帧摘要
        let signals = if sigs.is_empty() {
            json!([{ "name": signal_name, "value": signal_value }])
        } else {
            json!(sigs)
        };
        let obj = json!({
            "id": format!("{}:{}", session_id, i),
            "ts_ns": e.t_ns,
            "level": level,
            "code": code,
            "source": { "bus_type": bus_type, "ch": ch, "alias": alias },
            "message": e.detail.chars().take(500).collect::<String>(),
            "evidence": {
                "signals": signals,
                "frames_ref": frame_key.map(|k| vec![k]).unwrap_or_else(|| vec![format!("{}:{}", e.source, e.channel)]),
                "rule_ref": rule_ref,
            },
        });
        out.push_str(&serde_json::to_string(&obj).map_err(|e| e.to_string())?);
        out.push('\n');
    }
    std::fs::write(path, out).map_err(|e| e.to_string())?;
    Ok(ds.events.len())
}

/// 信号契约导出(过渡格式:signal.schema.json 尚未冻结,T-0.3)
pub fn signals_jsonl(ds: &Dataset, path: &std::path::Path) -> Result<usize, String> {
    use serde_json::json;
    let mut out = String::new();
    let mut n = 0usize;
    for s in &ds.signals {
        for (t, v, fi) in &s.pts {
            let o = json!({
                "name": s.key,
                "unit": s.unit,
                "t_ns": t,
                "value": v,
                "frame_idx": fi,
            });
            out.push_str(&serde_json::to_string(&o).map_err(|e| e.to_string())?);
            out.push('\n');
            n += 1;
        }
    }
    std::fs::write(path, out).map_err(|e| e.to_string())?;
    Ok(n)
}

// ================= 证据包(FR-7.2/7.3) =================

pub struct EvidenceMeta {
    pub session: String,
    /// 窗口(相对秒)
    pub t_from_s: f64,
    pub t_to_s: f64,
    /// 焦点事件 id(session:seq)
    pub focus_event: Option<String>,
    /// 规则包出处 (pack, file)
    pub packs: Vec<(String, String)>,
}

const EVIDENCE_MAX_BYTES: usize = 10 * 1024 * 1024;
const EVIDENCE_MAX_FRAMES: usize = 20_000;
const EVIDENCE_MAX_SIGNAL_PTS: usize = 50_000;

fn in_window(ts_ns: u64, from_s: f64, to_s: f64) -> bool {
    let t = ts_ns as f64 / 1e9;
    t >= from_s && t <= to_s
}

fn sample<T: Copy>(v: &[T], cap: usize) -> Vec<T> {
    if v.len() <= cap {
        return v.to_vec();
    }
    let step = v.len() as f64 / cap as f64;
    (0..cap).map(|k| v[(k as f64 * step) as usize]).collect()
}

/// 组装证据包:契约帧/事件/信号 + 人类可读摘要 + 规则包出处,单文件 ≤10MB(超限自动抽稀并标注)
pub fn build_evidence_bundle(
    frames: &[serde_json::Value],
    events: &[serde_json::Value],
    signals: &[serde_json::Value],
    meta: &EvidenceMeta,
    path: &std::path::Path,
) -> Result<(usize, usize, usize, bool), String> {
    use serde_json::json;
    let in_w = |ts_ns: u64| in_window(ts_ns, meta.t_from_s, meta.t_to_s);
    // 全会话导出时 t_to_s 是 f64::MAX/2 哨兵:摘要展示收敛到数据实际末尾,别把 1.8e308 写进人读的窗口行
    let t_to_display = if meta.t_to_s.is_finite() && meta.t_to_s < 1e12 {
        meta.t_to_s
    } else {
        frames
            .iter()
            .filter_map(|f| f.get("ts_ns").and_then(|t| t.as_u64()))
            .max()
            .map(|t| t as f64 / 1e9)
            .unwrap_or(meta.t_from_s)
    };

    // 事件(窗口内)
    let mut evs: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e.get("ts_ns").and_then(|t| t.as_u64()).map(in_w).unwrap_or(false))
        .collect();
    // 焦点事件置顶
    if let Some(fid) = &meta.focus_event {
        evs.sort_by_key(|e| !(e.get("id").and_then(|i| i.as_str()).map(|s| s == fid.as_str()).unwrap_or(false)) as u8);
    }

    // 帧(窗口内,抽稀)
    let frames_w: Vec<&serde_json::Value> = frames
        .iter()
        .filter(|f| f.get("ts_ns").and_then(|t| t.as_u64()).map(in_w).unwrap_or(false))
        .collect();

    // 信号点(窗口内,抽稀)
    let sigs_w: Vec<&serde_json::Value> = signals
        .iter()
        .filter(|s| s.get("t_ns").and_then(|t| t.as_u64()).map(in_w).unwrap_or(false))
        .collect();

    // 摘要(人类可读,不含推断性结论)
    let mut fault_by_code: std::collections::BTreeMap<String, usize> = Default::default();
    for e in &evs {
        if e.get("level").and_then(|l| l.as_str()) == Some("fault") {
            let code = e.get("code").and_then(|c| c.as_str()).unwrap_or("?").to_string();
            *fault_by_code.entry(code).or_default() += 1;
        }
    }
    let mut summary = vec![];
    if let Some(fid) = &meta.focus_event {
        summary.push(format!("焦点事件: {fid}"));
    }
    summary.push(format!(
        "窗口 {:.3}s ~ {:.3}s({:.3}s);帧 {} 条(抽稀后 {}),事件 {} 条,信号点 {} 条",
        meta.t_from_s,
        t_to_display,
        t_to_display - meta.t_from_s,
        frames_w.len(),
        frames_w.len().min(EVIDENCE_MAX_FRAMES),
        evs.len(),
        sigs_w.len().min(EVIDENCE_MAX_SIGNAL_PTS)
    ));
    if !fault_by_code.is_empty() {
        let line = fault_by_code.iter().map(|(c, n)| format!("{c}×{n}")).collect::<Vec<_>>().join(", ");
        summary.push(format!("fault 事件: {line}"));
    } else {
        summary.push("窗口内无 fault 级事件".into());
    }

    let packs: Vec<_> = meta
        .packs
        .iter()
        .map(|(p, f)| json!({ "pack": p, "file": f }))
        .collect();

    let mk = |fr: &[&serde_json::Value], sg: &[&serde_json::Value]| {
        json!({
            "type": "iotprobe-evidence",
            "version": 1,
            "session": meta.session,
            "window": { "t_from_s": meta.t_from_s, "t_to_s": meta.t_to_s, "focus_event": meta.focus_event },
            "summary": summary,
            "stats": { "frames": frames_w.len(), "events": evs.len(), "signal_points": sg.len() },
            "rule_packs": packs,
            "events": evs,
            "frames": fr,
            "signals": sg,
        })
    };

    // 尺寸守护:超 10MB 逐级抽稀
    let mut fr_cap = EVIDENCE_MAX_FRAMES;
    let mut sg_cap = EVIDENCE_MAX_SIGNAL_PTS;
    let mut truncated = false;
    let fr_owned = sample(&frames_w, fr_cap);
    let sg_owned = sample(&sigs_w, sg_cap);
    let mut doc = mk(&fr_owned, &sg_owned);
    loop {
        let bytes = serde_json::to_string(&doc).map_err(|e| e.to_string())?.len();
        if bytes <= EVIDENCE_MAX_BYTES || (fr_cap < 100 && sg_cap < 100) {
            if bytes > EVIDENCE_MAX_BYTES {
                truncated = true;
            }
            break;
        }
        truncated = true;
        fr_cap /= 2;
        sg_cap /= 2;
        let fr2 = sample(&frames_w, fr_cap.max(50));
        let sg2 = sample(&sigs_w, sg_cap.max(50));
        doc = mk(&fr2, &sg2);
    }
    // truncated 标注
    if truncated {
        doc["summary"].as_array_mut().unwrap().push(json!("⚠ 超出 10MB,帧/信号已抽稀"));
    }
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())?;
    Ok((evs.len(), fr_owned.len(), sg_owned.len(), truncated))
}

// ==================== MVP HTML 报告(体检卡/批量回归共用) ====================

fn hesc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn fmt_span(t_ns_max: u64, t_ns_min: u64) -> String {
    format!("{:.3}s", (t_ns_max.saturating_sub(t_ns_min)) as f64 / 1e9)
}

/// 体检统计(MVP):结构化数据(终端/批量用),HTML 片段由此渲染
pub struct Checkup {
    pub name: String,
    pub frames: usize,
    pub records: usize,
    pub span_s: f64,
    pub channels: usize,
    pub faults: u32,
    pub warns: u32,
    pub infos: u32,
    /// DBC 覆盖:(命中帧, CAN 帧总)
    pub dbc: Option<(u32, u32)>,
    /// 帧间隔异常/流丢段(链路质量类事件)
    pub gap_events: u32,
}

impl Checkup {
    /// 结论:fault>0 = FAIL;warn>0 或 gap>0 = WARN;否则 PASS(声明式阈值,透明可复核)
    pub fn verdict(&self) -> (&'static str, &'static str) {
        if self.faults > 0 {
            ("FAIL", "检出 fault 级事件")
        } else if self.warns > 0 || self.gap_events > 0 {
            ("WARN", "检出 warn/链路质量类事件")
        } else {
            ("PASS", "未检出异常事件")
        }
    }

    pub fn from_dataset(ds: &Dataset) -> Self {
        let (mut faults, mut warns, mut infos, mut gap) = (0u32, 0u32, 0u32, 0u32);
        for e in &ds.events {
            match e.kind {
                crate::model::EventKind::Info => infos += 1,
                crate::model::EventKind::Rule => {
                    match e.rule.as_ref().map(|r| r.level.as_str()).unwrap_or("warn") {
                        "fault" => faults += 1,
                        "warn" => warns += 1,
                        _ => infos += 1,
                    }
                }
                crate::model::EventKind::Gap | crate::model::EventKind::StreamDrop => {
                    gap += 1;
                    infos += 1;
                }
                _ => warns += 1,
            }
        }
        let span = ds
            .frames
            .last()
            .map(|f| f.t_ns)
            .unwrap_or(0)
            .saturating_sub(ds.frames.first().map(|f| f.t_ns).unwrap_or(0)) as f64
            / 1e9;
        Checkup {
            name: ds.name.clone(),
            frames: ds.frames.len(),
            records: ds.records.len(),
            span_s: span,
            channels: ds.channels.len(),
            faults,
            warns,
            infos,
            dbc: ds.channels.iter().fold(None, |acc, c| match (acc, c.dbc_hit) {
                (None, Some(x)) => Some(x),
                (Some((h, t)), Some((h2, t2))) => Some((h + h2, t + t2)),
                (a, _) => a,
            }),
            gap_events: gap,
        }
    }
}

/// 体检卡 HTML 片段(单文件报告与批量汇总共用;无脚本依赖)
pub fn checkup_html_frag(ds: &Dataset, name: &str) -> String {
    let c = Checkup::from_dataset(ds);
    let (verdict, why) = c.verdict();
    let vcolor = match verdict {
        "PASS" => "#2e9e5b",
        "WARN" => "#d98c1f",
        _ => "#d43f3f",
    };
    let mut h = format!(
        "<h2>体检结论:{}<small style=\"color:{vcolor}\"> {verdict} — {why}</small></h2>\
<table class=kv><tr><th>文件</th><td>{}</td></tr>\
<tr><th>帧数</th><td>{}(记录 {})</td></tr>\
<tr><th>时间跨度</th><td>{:.3}s</td></tr>\
<tr><th>通道</th><td>{}</td></tr>\
<tr><th>事件</th><td><span class=fault>fault {}</span> · <span class=warn>warn {}</span> · info {} · 链路质量 {}</td></tr>",
        hesc(name),
        hesc(&c.name),
        c.frames,
        c.records,
        c.span_s,
        c.channels,
        c.faults,
        c.warns,
        c.infos,
        c.gap_events,
    );
    if let Some((hit, total)) = c.dbc {
        let pct = if total > 0 { hit as f64 * 100.0 / total as f64 } else { 0.0 };
        let note = if total > hit { " ← 未命中帧可挂协议库补解" } else { "" };
        h.push_str(&format!("<tr><th>DBC 覆盖</th><td>{hit}/{total} 帧({pct:.0}%){note}</td></tr>"));
    }
    h.push_str("</table>");

    // 通道表
    h.push_str("<h3>通道</h3><table><tr><th>通道</th><th>协议</th><th>帧数</th><th>跨度</th><th>时基</th><th>DBC 覆盖</th></tr>");
    for ch in &ds.channels {
        let idxs: Vec<_> = ds.frames.iter().filter(|f| f.source == ch.source && f.channel == ch.id).collect();
        let span = idxs
            .last()
            .map(|l| fmt_span(l.t_ns, idxs[0].t_ns))
            .unwrap_or_else(|| "-".into());
        let dbc = ch
            .dbc_hit
            .map(|(a, b)| format!("{}%({}/{})", if b > 0 { a * 100 / b } else { 0 }, a, b))
            .unwrap_or_else(|| "-".into());
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{span}</td><td>{}</td><td>{dbc}</td></tr>",
            hesc(&ch.label),
            ch.proto.label(),
            idxs.len(),
            ch.ts_src.label(),
        ));
    }
    h.push_str("</table>");

    // 事件明细(top 100)
    let evs: Vec<_> = ds.events.iter().take(100).collect();
    if !evs.is_empty() {
        h.push_str(&format!("<h3>事件(前 {} / 共 {})</h3><table><tr><th>时刻</th><th>类别</th><th>详情</th><th>帧</th></tr>", evs.len(), ds.events.len()));
        for e in evs {
            let cls = match e.kind {
                crate::model::EventKind::Info => "info",
                crate::model::EventKind::Rule => {
                    if e.rule.as_ref().map(|r| r.level.as_str()) == Some("fault") { "fault" } else { "warn" }
                }
                _ => "warn",
            };
            h.push_str(&format!(
                "<tr><td>{:.3}s</td><td class={cls}>{}</td><td>{}</td><td>{}</td></tr>",
                e.t_ns as f64 / 1e9,
                e.kind.label(),
                hesc(&e.detail),
                e.frame.map(|f| format!("#{f}")).unwrap_or_else(|| "-".into()),
            ));
        }
        h.push_str("</table>");
    }

    // 信号统计(top 30,按点数)
    let mut sigs: Vec<_> = ds.signals.iter().collect();
    sigs.sort_by(|a, b| b.pts.len().cmp(&a.pts.len()));
    sigs.truncate(30);
    if !sigs.is_empty() {
        h.push_str("<h3>信号(top 30,按采样点数)</h3><table><tr><th>信号</th><th>单位</th><th>点数</th><th>min</th><th>max</th><th>最后</th></tr>");
        for s in sigs {
            let (mut mn, mut mx) = (f64::INFINITY, f64::NEG_INFINITY);
            for p in &s.pts {
                mn = mn.min(p.1);
                mx = mx.max(p.1);
            }
            let last = s.pts.last().map(|p| p.1).unwrap_or(0.0);
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{mn:.3}</td><td>{mx:.3}</td><td>{last:.3}</td></tr>",
                hesc(&s.key),
                hesc(&s.unit),
                s.pts.len(),
            ));
        }
        h.push_str("</table>");
    }
    h
}

const REPORT_CSS: &str = "\
body{font-family:'Segoe UI',system-ui,sans-serif;margin:24px;max-width:960px;color:#222}\
h2{border-bottom:2px solid #2b6cb0;padding-bottom:4px}h3{margin-top:18px}\
table{border-collapse:collapse;width:100%;margin:8px 0}\
th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:13px}\
th{background:#eef}\
table.kv th{width:110px;background:#f7f7f7}\
.fault{color:#d43f3f;font-weight:600}.warn{color:#d98c1f}.info{color:#2e9e5b}\
footer{margin-top:24px;color:#888;font-size:12px}";

/// 生成时刻(UTC 民用时间;无 TZ 依赖,报告页脚如实标 UTC)
pub fn utc_now_str() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, mo, day) = {
        // 民用日历(Howard Hinnant 算法)
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let dd = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let mm = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        ((y + if mm <= 2 { 1 } else { 0 }) as i32, mm, dd)
    };
    format!("{y:04}-{mo:02}-{day:02} {:02}:{:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// 自包含 HTML 报告(体检+通道+事件+信号统计;内联 CSS 可打印,零外部依赖)。
/// 返回文件字节数。
pub fn html_report(ds: &Dataset, name: &str, path: &std::path::Path) -> Result<usize, String> {
    let frag = checkup_html_frag(ds, name);
    let doc = format!(
        "<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"utf-8\"><title>{} 体检报告</title>\
<style>{REPORT_CSS}</style></head><body>\
<h1>IoTProbe 体检报告 — {}</h1>{frag}\
<footer>IoTProbe v{} · 生成于 {}</footer></body></html>",
        hesc(name),
        hesc(name),
        env!("CARGO_PKG_VERSION"),
        utc_now_str(),
    );
    std::fs::write(path, doc.as_bytes()).map_err(|e| format!("写报告失败: {e}"))?;
    Ok(doc.len())
}
