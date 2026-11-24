//! 批量回归("日志的 CI"):
//! 目录/多文件扫描 → 逐文件 解析+规则评估 → PASS/FAIL/WARN 判定 → 汇总 HTML 报告 + 终端摘要。
//! 判定口径(声明式、透明,随报告落盘):fault>0 = FAIL;warn 或链路质量事件>0 = WARN;否则 PASS。
//!
//! 用法:
//!   batch_runner [--dir <日志目录>](可多) [--rules <规则包目录>](可多) [--dbc x.dbc]
//!                [--map map.json] [--map104 points.yaml] [--out report.html]
//!                [--ext asc,log,pcap](默认常用格式集)
//! 无网络、无硬件依赖——适合 CI 定时任务/交付前回归。

use iotprobe_core::dissect::{analyze, AnalyzeCfg, Map104, ModbusMap};
use iotprobe_core::dbc;
use iotprobe_core::export::{self, Checkup};
use iotprobe_core::ingest;

const DEFAULT_EXTS: &[&str] = &["asc", "log", "pcap", "pcapng", "cap", "blf", "ndjson", "jsonl", "txt"];

struct Args {
    dirs: Vec<String>,
    rules: Vec<String>,
    dbc: Vec<String>,
    map: Option<String>,
    map104: Option<String>,
    out: String,
    exts: Vec<String>,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut a = Args {
        dirs: vec![],
        rules: vec![],
        dbc: Vec::new(),
        map: None,
        map104: None,
        out: "batch_report.html".into(),
        exts: DEFAULT_EXTS.iter().map(|s| s.to_string()).collect(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" | "--rules" => {
                let key = args[i].clone();
                i += 1;
                match key.as_str() {
                    "--dir" => a.dirs.push(args[i].clone()),
                    _ => a.rules.push(args[i].clone()),
                }
            }
            "--dbc" => {
                i += 1;
                a.dbc.push(args[i].clone());
            }
            "--map" => {
                i += 1;
                a.map = Some(args[i].clone());
            }
            "--map104" => {
                i += 1;
                a.map104 = Some(args[i].clone());
            }
            "--out" => {
                i += 1;
                a.out = args[i].clone();
            }
            "--ext" => {
                i += 1;
                a.exts = args[i].split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect();
            }
            other => {
                eprintln!("未知参数 {other}(支持 --dir --rules --dbc --map --map104 --out --ext)");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    if a.dirs.is_empty() {
        eprintln!("用法: batch_runner --dir <日志目录>(可多) [--rules <规则包>] [--dbc x.dbc] [--out report.html] [--ext asc,log,...]");
        std::process::exit(2);
    }
    a
}

fn build_cfg(args: &Args) -> AnalyzeCfg {
    let mut cfg = AnalyzeCfg::default();
    for p in &args.dbc {
        let (text, enc) = iotprobe_core::textio::read_text(std::path::Path::new(p)).expect("读 dbc");
        if enc != "UTF-8" {
            eprintln!("提示: DBC 非 UTF-8(按 {enc} 解码)");
        }
        let parsed = dbc::parse(&text);
        // 协议库多选:多 DBC 合并(与 GUI 同语义)
        cfg.dbc = Some(match cfg.dbc.take() {
            Some(mut acc) => {
                acc.merge(parsed);
                acc
            }
            None => parsed,
        });
    }
    if let Some(p) = &args.map {
        let text = iotprobe_core::textio::read_text_simple(std::path::Path::new(p)).expect("读 map");
        cfg.map = Some(serde_json::from_str::<ModbusMap>(&text).expect("map"));
    }
    if let Some(p) = &args.map104 {
        let text = iotprobe_core::textio::read_text_simple(std::path::Path::new(p)).expect("读 map104");
        cfg.map104 = Some(Map104::parse(&text).expect("104 点表"));
    }
    for p in &args.rules {
        let pack = iotprobe_core::rules::load_pack_dir(std::path::Path::new(p)).expect("规则包加载失败");
        cfg.rule_packs.push(pack);
    }
    cfg
}

fn main() {
    let args = parse_args();
    let cfg = build_cfg(&args);
    // 收集文件(递归一层;按扩展名过滤;排序保证输出稳定)
    let mut files: Vec<std::path::PathBuf> = vec![];
    for d in &args.dirs {
        let rd = match std::fs::read_dir(d) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("读目录 {d} 失败: {e}");
                continue;
            }
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                let ext = p.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                if args.exts.iter().any(|x| x == &ext) {
                    files.push(p);
                }
            } else if p.is_dir() {
                // 一层子目录(日志归档常见按日期分目录)
                if let Ok(sub) = std::fs::read_dir(&p) {
                    for e2 in sub.flatten() {
                        let p2 = e2.path();
                        let ext = p2.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                        if p2.is_file() && args.exts.iter().any(|x| x == &ext) {
                            files.push(p2);
                        }
                    }
                }
            }
        }
    }
    files.sort();
    if files.is_empty() {
        eprintln!("未收集到日志文件(扩展名: {})", args.exts.join(","));
        std::process::exit(1);
    }

    struct Row {
        name: String,
        frames: usize,
        span_s: f64,
        faults: u32,
        warns: u32,
        infos: u32,
        gap: u32,
        verdict: &'static str,
        top_event: String,
    }
    let mut rows: Vec<Row> = vec![];
    let mut fails = 0usize;
    let mut warns_n = 0usize;
    for (i, f) in files.iter().enumerate() {
        let name = f.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let src = match ingest::read_file(f) {
            Ok(s) => s,
            Err(e) => {
                rows.push(Row {
                    name: name.clone(),
                    frames: 0,
                    span_s: 0.0,
                    faults: 0,
                    warns: 0,
                    infos: 0,
                    gap: 0,
                    verdict: "FAIL",
                    top_event: e,
                });
                fails += 1;
                continue;
            }
        };
        let mut ds = analyze(vec![src], &cfg);
        iotprobe_core::rules::reload_rules(&cfg.rule_packs, &mut ds);
        let ck = Checkup::from_dataset(&ds);
        let (verdict, _why) = ck.verdict();
        let top = ds
            .events
            .iter()
            .find(|e| e.kind != iotprobe_core::model::EventKind::Info)
            .map(|e| e.detail.chars().take(80).collect())
            .unwrap_or_else(|| "-".into());
        if verdict == "FAIL" {
            fails += 1;
        } else if verdict == "WARN" {
            warns_n += 1;
        }
        rows.push(Row {
            frames: ck.frames,
            span_s: ck.span_s,
            faults: ck.faults,
            warns: ck.warns,
            infos: ck.infos,
            gap: ck.gap_events,
            name,
            verdict,
            top_event: top,
        });
        // 进度(长任务反馈)
        if (i + 1) % 10 == 0 || i + 1 == files.len() {
            eprintln!("[{}/{}] 已分析", i + 1, files.len());
        }
    }

    // 终端摘要
    println!();
    println!("=== 批量回归汇总: {} 文件 | FAIL {} | WARN {} | PASS {} ===", files.len(), fails, warns_n, files.len() - fails - warns_n);
    for r in &rows {
        let mark = match r.verdict {
            "FAIL" => "🔴",
            "WARN" => "🟠",
            _ => "🟢",
        };
        println!("{mark} {:<36} {}帧 {:.1}s fault{} warn{} gap{} — {}", r.name, r.frames, r.span_s, r.faults, r.warns, r.gap, r.top_event);
    }

    // HTML 汇总(与单文件报告同一 CSS;表格含判定列;失败文件行高亮)
    let mut h = format!(
        "<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"utf-8\"><title>批量回归汇总</title><style>{}</style></head><body>\
<h1>批量回归汇总</h1>\
<p>目录 {} 个 · 文件 {} · FAIL {} · WARN {} · PASS {} · 判定口径: fault&gt;0=FAIL,warn/链路质量&gt;0=WARN</p>\
<table><tr><th>判定</th><th>文件</th><th>帧数</th><th>跨度</th><th>fault</th><th>warn</th><th>info</th><th>链路</th><th>代表性事件</th></tr>",
        crate_css(),
        args.dirs.len(),
        files.len(),
        fails,
        warns_n,
        files.len() - fails - warns_n,
    );
    for r in &rows {
        let cls = match r.verdict {
            "FAIL" => "fault",
            "WARN" => "warn",
            _ => "info",
        };
        h.push_str(&format!(
            "<tr class={cls}><td class={cls}>{}</td><td>{}</td><td>{}</td><td>{:.1}s</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            r.verdict,
            html::esc(&r.name),
            r.frames,
            r.span_s,
            r.faults,
            r.warns,
            r.infos,
            r.gap,
            html::esc(&r.top_event),
        ));
    }
    h.push_str("</table>");
    if !cfg.rule_packs.is_empty() {
        h.push_str(&format!("<p>规则包: {}</p>", html::esc(&args.rules.join("、"))));
    }
    h.push_str(&format!("<footer>IoTProbe v{} · 生成于 {}</footer></body></html>", env!("CARGO_PKG_VERSION"), export::utc_now_str()));
    std::fs::write(&args.out, h.as_bytes()).map_err(|e| format!("写汇总报告失败: {e}")).unwrap();
    println!("\n汇总报告 → {}", args.out);
    if fails > 0 {
        std::process::exit(1); // CI 语义:有 FAIL 即非零退出
    }
}

/// batch 内联 html 工具(esc/内联 CSS 与 export 同源)
mod html {
    pub fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }
}

fn crate_css() -> &'static str {
    "body{font-family:'Segoe UI',system-ui,sans-serif;margin:24px;color:#222}\
h1{border-bottom:2px solid #2b6cb0;padding-bottom:4px}\
table{border-collapse:collapse;width:100%;margin:8px 0}\
th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:13px}th{background:#eef}\
tr.fault td{background:#fdecec}tr.warn td{background:#fdf3e0}\
td.fault{color:#d43f3f;font-weight:600}td.warn{color:#d98c1f}td.info{color:#2e9e5b}\
footer{margin-top:24px;color:#888;font-size:12px}"
}
