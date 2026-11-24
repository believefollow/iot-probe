//! CLI 解析验证工具:无 GUI 快速检查一个/多个日志的解析结果。
//! 用法:dbg_analyze [--custom spec.json]... [--dbc x.dbc] [--map map.json]
//!                [--map104 points.yaml|json] [--rules <规则包目录>] [--probe]
//!                [--report out.html(体检 HTML 报告)] [--export <目录>(契约 JSONL)]
//!                [--frame "602#4017100000000000"(单帧秒解,可多)] 文件...

use iotprobe_core::dissect::{analyze, unknown, AnalyzeCfg, CustomSpec, Map104, ModbusMap};
use iotprobe_core::dbc;
use iotprobe_core::export;
use iotprobe_core::ingest;
use iotprobe_core::model::Proto;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = AnalyzeCfg::default();
    let mut files = vec![];
    let mut do_probe = false;
    let mut export_dir: Option<std::path::PathBuf> = None;
    let mut frames: Vec<String> = vec![];
    let mut report_path: Option<std::path::PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--custom" => {
                i += 1;
                let text = iotprobe_core::textio::read_text_simple(std::path::Path::new(&args[i])).expect("读 custom");
                let spec: CustomSpec = serde_json::from_str(&text).expect("spec");
                cfg.custom.push(spec);
            }
            "--dbc" => {
                // 多 DBC 合并(重复 --dbc 即多选;与 GUI 协议库/batch_runner 同语义)
                i += 1;
                let (text, enc) = iotprobe_core::textio::read_text(std::path::Path::new(&args[i])).expect("读 dbc");
                if enc != "UTF-8" {
                    eprintln!("提示: DBC 非 UTF-8(按 {enc} 解码): {}", args[i]);
                }
                let parsed = dbc::parse(&text);
                cfg.dbc = Some(match cfg.dbc.take() {
                    Some(mut acc) => {
                        acc.merge(parsed);
                        acc
                    }
                    None => parsed,
                });
            }
            "--map" => {
                i += 1;
                let text = iotprobe_core::textio::read_text_simple(std::path::Path::new(&args[i])).expect("读 map");
                cfg.map = Some(serde_json::from_str::<ModbusMap>(&text).expect("map"));
            }
            "--map104" => {
                i += 1;
                let text = iotprobe_core::textio::read_text_simple(std::path::Path::new(&args[i])).expect("读 map104");
                cfg.map104 = Some(Map104::parse(&text).expect("104 点表"));
            }
            "--rules" => {
                i += 1;
                let pack = iotprobe_core::rules::load_pack_dir(std::path::Path::new(&args[i]))
                    .expect("规则包加载失败");
                cfg.rule_packs.push(pack);
            }
            "--probe" => do_probe = true,
            "--frame" => {
                i += 1;
                frames.push(args[i].clone());
            }
            "--report" => {
                i += 1;
                report_path = Some(std::path::PathBuf::from(&args[i]));
            }
            // --export <目录>:输出 <数据集名>.frames/events/signals.jsonl(MCP server 数据源,S3 场景)
            "--export" => {
                i += 1;
                export_dir = Some(std::path::PathBuf::from(&args[i]));
            }
            f => files.push(f.to_string()),
        }
        i += 1;
    }
    // 单帧秒解(--frame):同一 analyze 管线,语义层(DBC/CANopen/自定义/Modbus)全可用
    if !frames.is_empty() {
        use iotprobe_core::ingest::live::{BusKind, LiveFrame};
        use iotprobe_core::model::{Dir, TsSrc};
        // 全部帧进同一通道(顺序保持):SDO 请求/响应配对、事务时序才有意义
        let mut records: Vec<iotprobe_core::model::Record> = vec![];
        for (k, fr) in frames.iter().enumerate() {
            let (id_s, data_s) = fr.split_once('#').unwrap_or((fr.as_str(), ""));
            let id = u32::from_str_radix(id_s.trim_start_matches("0x"), 16).unwrap_or(0);
            let ext = id > 0x7FF;
            let data: Vec<u8> = (0..data_s.len() / 2).filter_map(|x| u8::from_str_radix(&data_s[x * 2..x * 2 + 2], 16).ok()).collect();
            let f = LiveFrame {
                ts_ns: k as u64,
                ts_src: TsSrc::Wall,
                bus_type: BusKind::Can,
                ch: 0,
                alias: Some("单帧解码".into()),
                dir: Dir::Rx,
                id: id & 0x1FFF_FFFF,
                id_ext: ext,
                dlc: data.len(),
                data,
                seq: None,
                meta_gap: None,
            };
            // core bin 内联 NDJSON(frame.schema 合规;live_frame_to_jsonl 在 app 层)
            let line = serde_json::json!({
                "ts_ns": f.ts_ns, "ts_src": "wall",
                "bus": {"type": "can", "ch": 0, "alias": "单帧解码"},
                "dir": "rx", "id": f.id, "id_type": if f.id_ext { "ext" } else { "std" },
                "dlc": f.data.len(), "data": f.data,
            })
            .to_string();
            let mut sess = iotprobe_core::ingest::live::LiveSession::new(None);
            if let Some(r) = sess.map_line(&line) {
                records.push(r);
            }
            let _ = k;
        }
        let sess2 = iotprobe_core::ingest::live::LiveSession::new(None);
        // 重灌:同一 LiveSession 逐行 map 保证通道/序号连续(时序/配对语义正确)
        let ds = analyze(vec![sess2.into_source("单帧解码", records)], &cfg);
        println!("=== 单帧解码 ===");
        for f in &ds.frames {
            println!("  {}", f.summary);
        }
        for e in &ds.events {
            println!("  [{:?}] {}", e.kind, e.detail);
        }
        if let Some(rp) = &report_path {
            match export::html_report(&ds, "单帧解码", rp) {
                Ok(n) => println!("HTML 报告 → {}({n} 字节)", rp.display()),
                Err(e) => eprintln!("报告导出失败: {e}"),
            }
        }
        return;
    }
    let mut sources = vec![];
    for f in &files {
        match ingest::read_file(std::path::Path::new(f)) {
            Ok(s) => sources.push(s),
            Err(e) => eprintln!("读取 {f} 失败: {e}"),
        }
    }
    if sources.is_empty() {
        eprintln!("没有可解析的文件");
        std::process::exit(1);
    }
    let ds = analyze(sources, &cfg);
    if let Some(dir) = &export_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("创建导出目录失败: {e}")).unwrap();
        // 数据集名取文件 stem(join(" + ") 含路径分隔符,MCP 会话名会乱)
        let stem = files
            .first()
            .and_then(|f| std::path::Path::new(f).file_stem().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "session".into());
        let mk = |suffix: &str| dir.join(format!("{stem}.{suffix}.jsonl"));
        let nf = export::frames_jsonl(&ds, &mk("frames")).expect("frames 导出");
        let ne = export::events_jsonl(&ds, &mk("events")).expect("events 导出");
        let ns = export::signals_jsonl(&ds, &mk("signals")).expect("signals 导出");
        println!(
            "-- 导出契约 JSONL → {} ({stem}: {} 帧 / {} 事件 / {} 信号点) --",
            dir.display(),
            nf,
            ne,
            ns
        );
    }
    if let Some(rp) = &report_path {
        match export::html_report(&ds, &ds.name, rp) {
            Ok(n) => println!("HTML 报告 → {}({n} 字节)", rp.display()),
            Err(e) => eprintln!("报告导出失败: {e}"),
        }
    }
    if do_probe {
        println!("=== 未知协议试探 ===");
        for c in &ds.channels {
            if c.proto != Proto::Raw {
                continue;
            }
            let recs: Vec<&iotprobe_core::model::Record> = ds
                .records
                .iter()
                .filter(|r| r.source == c.source && r.channel == c.id)
                .collect();
            if recs.is_empty() {
                continue;
            }
            let rep = unknown::probe(&c.label, &recs);
            println!("\n[{}] 判定 {:?} 置信度 {:.0}%", c.label, rep.verdict, rep.confidence * 100.0);
            for n in &rep.notes {
                println!("  · {n}");
            }
            if let Some(s) = &rep.sync {
                println!("  同步头 {s}");
            }
            if let Some((p, w, le, bias)) = rep.length {
                println!("  长度域 @{p} 宽{w} {} bias={bias}", if le { "LE" } else { "BE" });
            }
            if let Some((a, cs, el)) = &rep.checksum {
                println!("  校验 {a} cover从{cs} 尾部{el}B");
            }
            for h in &rep.hints {
                println!("  字段猜测: {} @{} ({})", h.kind, h.pos, h.detail);
            }
            if let Some(d) = &rep.draft {
                println!("  ---- CustomSpec 草案 ----");
                println!("{}", serde_json::to_string_pretty(d).unwrap());
            }
        }
        return;
    }
    println!("=== 数据集: {} ===", ds.name);
    println!("records={} frames={} signals={} events={}", ds.records.len(), ds.frames.len(), ds.signals.len(), ds.events.len());
    println!("\n-- 通道 --");
    for c in &ds.channels {
        println!("  {} -> {}", c.label, c.proto.label());
    }
    println!("\n-- 信号 --");
    for s in &ds.signals {
        println!("  {} [{}] {}点 最新={}", s.key, s.unit, s.pts.len(), s.pts.last().map(|p| p.1).unwrap_or(0.0));
    }
    println!("\n-- 事件(前 20) --");
    for e in ds.events.iter().take(20) {
        println!("  {:?} t={:.3}s {}", e.kind, e.t_ns as f64 / 1e9, e.detail);
    }
    println!("\n-- 帧样例(前 8) --");
    for f in ds.frames.iter().take(8) {
        println!("  {:.3}s {} {} {}", f.t_ns as f64 / 1e9, f.dir.label(), f.proto.label(), f.summary);
    }
    if !ds.warnings.is_empty() {
        println!("\n-- 警告 --");
        for w in &ds.warnings {
            println!("  {w}");
        }
    }
}
