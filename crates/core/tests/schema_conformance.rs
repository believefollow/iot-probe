//! 契约符合性测试:导出的 Frame/Event JSONL 必须通过冻结 schema 校验。
//! 校验器:真实 jsonschema 实现;校验所用 schema = 冻结契约 + ADR-0007 补丁
//! (仅 data.maxItems 64→512 一处数值变更,其余映射均不触碰冻结枚举)。

use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use serde_json::{json, Value};

const FRAME_SCHEMA: &str = include_str!("../../../contracts/frame.schema.json");
const EVENT_SCHEMA: &str = include_str!("../../../contracts/event.schema.json");

/// ADR-0007 补丁:对冻结 schema 仅放宽 data.maxItems(uart 字节流最长 512B)
fn patch_frame_schema(v: &mut Value) {
    v["properties"]["data"]["maxItems"] = json!(512);
}

fn validator(schema: &Value) -> impl Fn(&Value) -> Result<(), String> + '_ {
    let v = jsonschema::validator_for(schema).expect("schema 编译失败");
    move |inst: &Value| {
        let errs: Vec<String> = v
            .iter_errors(inst)
            .map(|e| format!("{} (at {})", e, e.instance_path()))
            .collect();
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

fn build_dataset() -> iotprobe_core::model::Dataset {
    // 造一份覆盖多协议的日志:Modbus RTU(含墙钟时间戳、含坏帧)+ CAN + 无方向
    let text = "\
RX 2026-01-05 10:00:00.000  01 03 00 00 00 02 C4 0B
TX 2026-01-05 10:00:00.008  01 03 04 00 FA 01 F4 DA 15
RX 2026-01-05 10:00:00.100  01 03 00 00 00 02 C4 0B
TX 2026-01-05 10:00:00.108  01 03 04 01 4C 01 F4 DA 04
RX 2026-01-05 10:00:00.200  01 03 00 00 00 02 C4 0B
TX 2026-01-05 10:00:00.208  FF EE 12 34 56 78 90 AB CD EF
";
    let mut records = vec![];
    let mut labels = std::collections::HashMap::new();
    let mut epoch = None;
    let mut warns = vec![];
    iotprobe_core::ingest::hexlog::parse(text, &mut records, &mut labels, &mut epoch, &mut warns);
    let src = iotprobe_core::ingest::SourceData {
        name: "conformance.log".into(),
        records,
        epoch_ns: epoch,
        warnings: warns,
        chan_labels: labels,
    };
    analyze(vec![src], &AnalyzeCfg::default())
}

#[test]
fn frames_jsonl_passes_frozen_schema() {
    let ds = build_dataset();
    assert!(ds.frames.len() >= 4, "应有解析出的 Modbus 帧");
    let dir = std::env::temp_dir().join("iotprobe_schema_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("frames.jsonl");
    let n = iotprobe_core::export::frames_jsonl(&ds, &path).unwrap();
    assert!(n >= 4);

    let mut schema: Value = serde_json::from_str(FRAME_SCHEMA).unwrap();
    patch_frame_schema(&mut schema);
    let check = validator(&schema);

    for (i, line) in std::fs::read_to_string(&path).unwrap().lines().enumerate() {
        let inst: Value = serde_json::from_str(line).unwrap();
        if let Err(e) = check(&inst) {
            panic!("第 {} 行未通过 frame.schema: {e}\n{line}", i + 1);
        }
    }
}

#[test]
fn can_frame_passes_unpatched_strict_schema() {
    // 纯 CAN 帧(≤64B)不打任何补丁也必须过 —— 冻结契约的严格符合性
    let schema: Value = serde_json::from_str(FRAME_SCHEMA).unwrap();
    let check = validator(&schema);
    let inst = json!({
        "ts_ns": 1767225600_000_000_000u64,
        "ts_src": "hw",
        "bus": { "type": "canfd", "ch": 0, "alias": "BMS-CAN" },
        "dir": "rx",
        "id": 0x1A0,
        "id_type": "std",
        "dlc": 8,
        "data": [1,2,3,4,5,6,7,8],
        "meta": { "seq": 1 }
    });
    check(&inst).expect("CAN 帧必须严格符合冻结 schema");
    // 非法值必须被拒
    let mut bad = inst.clone();
    bad["ts_src"] = json!("unknown");
    assert!(check(&bad).is_err(), "非法 ts_src 必须被拒");
    let mut bad2 = inst.clone();
    bad2["data"] = json!(vec![0u8; 65]);
    assert!(check(&bad2).is_err(), "65B 数据在冻结 schema 下必须被拒");
}

#[test]
fn events_jsonl_passes_frozen_schema() {
    // 用含异常的日志(坏帧 → DIAG_MALFORMED_FRAME;间隔 → DIAG_TIMING_GAP;覆盖请求 → DIAG_RESP_TIMEOUT)
    let req_hex = "01 03 00 00 00 02 C4 0B";
    let mut lines = vec![];
    let base = iotprobe_core::timeutil::wall_to_epoch_ns(2026, 1, 5, 10, 0, 0, 0);
    let stamp = |off_ms: u64| -> String {
        let ns = base + off_ms * 1_000_000;
        let (y, mo, d, h, mi, s, frac) = iotprobe_core::timeutil::epoch_ns_to_wall(ns);
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}.{:03}", frac / 1_000_000)
    };
    for i in 0..10u64 {
        let t = i * 100;
        lines.push(format!("TX {} {}", stamp(t), req_hex));
        let temp = (i * 7 % 256) as u8;
        let mut resp = vec![0x01u8, 0x03, 0x04, temp, 0x01, 0x00, 0xF4];
        let c = iotprobe_core::crc::crc16_modbus(&resp);
        resp.push(c as u8);
        resp.push((c >> 8) as u8);
        let mut hexs = String::new();
        for b in &resp {
            hexs.push_str(&format!("{b:02X} "));
        }
        if i == 5 {
            hexs = "AA BB CC DD EE FF 11 22 33".into(); // 垃圾数据:CRC 必败
        }
        lines.push(format!("RX {} {}", stamp(t + 8), hexs.trim_end()));
    }
    // 2 秒断流后一对(触发 Gap)
    let t = 10 * 100 + 2000;
    lines.push(format!("TX {} {}", stamp(t), req_hex));
    lines.push(format!("RX {} {}", stamp(t + 8), req_hex));
    let text = lines.join("\n");
    let mut records = vec![];
    let mut labels = std::collections::HashMap::new();
    let mut epoch = None;
    let mut warns = vec![];
    iotprobe_core::ingest::hexlog::parse(&text, &mut records, &mut labels, &mut epoch, &mut warns);
    let src = iotprobe_core::ingest::SourceData {
        name: "evt.log".into(),
        records,
        epoch_ns: epoch,
        warnings: warns,
        chan_labels: labels,
    };
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    assert!(!ds.events.is_empty(), "应产生诊断事件");

    let dir = std::env::temp_dir().join("iotprobe_schema_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let n = iotprobe_core::export::events_jsonl(&ds, &path).unwrap();
    assert_eq!(n, ds.events.len());

    let schema: Value = serde_json::from_str(EVENT_SCHEMA).unwrap();
    let check = validator(&schema);
    for (i, line) in std::fs::read_to_string(&path).unwrap().lines().enumerate() {
        let inst: Value = serde_json::from_str(line).unwrap();
        if let Err(e) = check(&inst) {
            panic!("第 {} 行未通过 event.schema: {e}\n{line}", i + 1);
        }
    }
}

#[test]
fn ts_src_labels_are_honest() {
    // FR-2.2:墙钟日志必须标 wall(无精度保证),不得冒充 sw/hw
    let ds = build_dataset();
    assert!(
        ds.frames.iter().all(|f| f.ts_src == iotprobe_core::model::TsSrc::Wall),
        "hexlog 墙钟时间戳必须标 wall"
    );
    assert!(
        ds.channels.iter().all(|c| c.ts_src == iotprobe_core::model::TsSrc::Wall),
        "通道时基取最差等级"
    );
}
