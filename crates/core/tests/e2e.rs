//! 端到端集成测试:摄入 → 协议识别 → 解码 → 时序/事件。
//! 运行前先执行:cargo run -p iotprobe-core --bin gen_samples -- crates/core/tests/data
//! (测试会用相对路径自动生成一次)

use iotprobe_core::dissect::{analyze, AnalyzeCfg, CustomSpec, Map104};
use iotprobe_core::model::Record;
use iotprobe_core::ingest;
use iotprobe_core::model::*;

fn ensure_samples() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from("tests/data");
    if !dir.join("modbus_rtu.log").exists() {
        // 复用 gen_samples 的生成逻辑:直接调用其内部函数不可行,改为运行 bin
        let out = std::process::Command::new(std::env::current_exe().unwrap().parent().unwrap().join("gen_samples.exe"))
            .arg(dir.to_str().unwrap())
            .output();
        if out.is_err() {
            panic!("请先运行: cargo run -p iotprobe-core --bin gen_samples -- tests/data");
        }
    }
    dir
}

#[test]
fn modbus_rtu_e2e() {
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("modbus_rtu.log")).expect("读取失败");
    assert!(src.records.len() > 1000);
    // 加载寄存器映射(信号命名/换算)
    let map_json = std::fs::read_to_string(dir.join("configs/modbus_map.json")).unwrap();
    let cfg = AnalyzeCfg { map: Some(serde_json::from_str(&map_json).unwrap()), ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    // 协议应识别为 Modbus RTU
    assert!(ds.channels.iter().any(|c| c.proto == Proto::ModbusRtu), "channels: {:?}", ds.channels.iter().map(|c| c.proto.label()).collect::<Vec<_>>());
    // 帧数量:约 600 对 ×2 + 1 异常 = 1201
    assert!(ds.frames.len() > 1100, "frames={}", ds.frames.len());
    // 信号:TempSensor / SetPoint / Energy(32bit CDAB)/ RunState(枚举)
    assert!(ds.signals.iter().any(|s| s.key.contains("TempSensor")), "signals: {:?}", ds.signals.iter().map(|s| &s.key).collect::<Vec<_>>());
    assert!(ds.signals.iter().any(|s| s.key.contains("SetPoint")));
    assert!(ds.signals.iter().any(|s| s.key.contains("Energy")), "32bit CDAB 应成信号");
    assert!(ds.signals.iter().any(|s| s.key.contains("RunState")), "枚举寄存器应成信号");
    // 事件:坏 CRC 帧无法定界(Malformed)+ 异常码 + 间隔
    assert!(ds.events.iter().any(|e| e.kind == EventKind::Malformed), "events: {:?}", ds.events.iter().map(|e| e.kind).collect::<Vec<_>>());
    assert!(ds.events.iter().any(|e| e.kind == EventKind::Exception));
    assert!(ds.events.iter().any(|e| e.kind == EventKind::Gap));
    // 自动 Gap 阈值不应误报:Gap 事件应很少(仅断流处)
    let gaps = ds.events.iter().filter(|e| e.kind == EventKind::Gap).count();
    assert!(gaps <= 3, "Gap 误报过多: {gaps}");
    // 轮询事务分析:RTT 信号 + 坏CRC导致的无响应事务
    assert!(ds.signals.iter().any(|s| s.key.starts_with("RTT·")), "应有 RTT 信号");
    assert!(ds.events.iter().any(|e| e.kind == EventKind::Timeout), "坏CRC响应应产生无响应事件");
    // 按需解码与存储解码一致(小数据集全存储)
    let d1 = ds.decoded[10].clone().expect("应已存储");
    let d2 = iotprobe_core::dissect::decode_one(&ds, 10).expect("按需解码应成功");
    assert_eq!(d1.proto, d2.proto);
    assert_eq!(d1.root.len(), d2.root.len(), "按需解码字段数应一致");
}

#[test]
fn custom_protocol_e2e() {
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("custom_485.log")).expect("读取失败");
    let spec_json = std::fs::read_to_string(dir.join("configs/custom_example.json")).unwrap();
    let spec: CustomSpec = serde_json::from_str(&spec_json).unwrap();
    let cfg = AnalyzeCfg { custom: vec![spec], ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Custom), "应为 Custom");
    // 信号:temp 与 rpm
    assert!(ds.signals.iter().any(|s| s.key.contains("temp")));
    assert!(ds.signals.iter().any(|s| s.key.contains("rpm")));
    // fault 位抖动产生 bool 信号
    assert!(ds.signals.iter().any(|s| s.key.contains("fault")));
    // 坏同步/坏校验 → Malformed 事件
    assert!(ds.events.iter().any(|e| e.kind == EventKind::Malformed), "events: {:?}", ds.events.iter().map(|e| e.kind).collect::<Vec<_>>());
}

#[test]
fn can_dbc_e2e() {
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("candump.log")).expect("读取失败");
    let dbc_text = std::fs::read_to_string(dir.join("motor.dbc")).unwrap();
    let cfg = AnalyzeCfg { dbc: Some(iotprobe_core::dbc::parse(&dbc_text)), ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Can));
    // DBC 信号曲线
    assert!(ds.signals.iter().any(|s| s.key.contains("Speed")));
    assert!(ds.signals.iter().any(|s| s.key.contains("Torque")));
    // 断流 → Gap 事件
    assert!(ds.events.iter().any(|e| e.kind == EventKind::Gap));
    // 有 Δt 伪信号
    assert!(ds.signals.iter().any(|s| s.key.starts_with("Δt")));
}

#[test]
fn pcap_multi_proto_e2e() {
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("net.pcap")).expect("读取失败");
    let cfg = AnalyzeCfg::default();
    let ds = analyze(vec![src], &cfg);
    let protos: Vec<Proto> = ds.channels.iter().map(|c| c.proto).collect();
    // Modbus TCP / MQTT / EtherCAT 三种协议同时识别
    assert!(protos.contains(&Proto::ModbusTcp), "protos={protos:?}");
    assert!(protos.contains(&Proto::Mqtt), "protos={protos:?}");
    assert!(protos.contains(&Proto::EtherCat), "protos={protos:?}");
    // EtherCAT wkc=0 事件
    assert!(ds.events.iter().any(|e| e.kind == EventKind::WkcError));
    // MQTT CONNECT 摘要
    assert!(ds.frames.iter().any(|f| f.summary.contains("sensor-01")), "MQTT CONNECT 应含 client id");
    // Modbus TCP 寄存器信号
    assert!(ds.signals.iter().any(|s| s.key.contains("HR0")));
    // EtherCAT wkc 曲线
    assert!(ds.signals.iter().any(|s| s.key.contains("EtherCAT·wkc")));
}

#[test]
fn unknown_probe_closed_loop_e2e() {
    // 无配置加载 → Raw 通道 → 试探 → 草案 → 采纳 → 识别为 Custom 且出信号
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("unknown_protocol.log")).expect("读取失败");
    assert!(src.records.len() >= 400);
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    let chan = ds.channels.iter().find(|c| c.proto == Proto::Raw).expect("应为未识别通道");
    let recs: Vec<&Record> = ds.records.iter().filter(|r| r.source == chan.source && r.channel == chan.id).collect();
    let rep = iotprobe_core::dissect::unknown::probe(&chan.label, &recs);
    assert_eq!(rep.verdict, iotprobe_core::dissect::unknown::Verdict::Framed, "notes={:?}", rep.notes);
    assert_eq!(rep.sync.as_deref(), Some("5AA5"), "notes={:?}", rep.notes);
    assert_eq!(rep.length, Some((3, 1, true, 5)));
    assert!(rep.confidence > 0.85);
    // 闭环:采纳草案重新解析
    let spec = rep.draft.expect("应有草案");
    let src2 = ingest::read_file(&dir.join("unknown_protocol.log")).unwrap();
    let cfg = AnalyzeCfg { custom: vec![spec], ..Default::default() };
    let ds2 = analyze(vec![src2], &cfg);
    assert!(ds2.channels.iter().any(|c| c.proto == Proto::Custom), "采纳后应为 Custom");
    assert!(ds2.signals.iter().any(|s| s.key.contains("cnt")), "计数器应成信号");
}

#[test]
fn vector_asc_e2e() {
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("vector.asc")).expect("读取失败");
    assert!(src.records.len() >= 300, "records={}", src.records.len());
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Can));
    // 扩展帧位
    assert!(ds.records.iter().any(|r| r.can_id.map(|id| id & 0x8000_0000 != 0).unwrap_or(false)));
    // 帧摘要带扩展 x 标记
    assert!(ds.frames.iter().any(|f| f.summary.contains("x") && f.summary.starts_with("0x")));
}

#[test]
fn socketcan_pcap_e2e() {
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("can_socketcan.pcap")).expect("读取失败");
    assert!(src.records.len() >= 60, "records={}", src.records.len());
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    let n_classic = ds.frames.iter().filter(|f| f.proto == Proto::Can).count();
    let n_fd = ds.frames.iter().filter(|f| f.proto == Proto::CanFd).count();
    assert!(n_classic >= 60, "classic={n_classic}");
    assert!(n_fd >= 5, "fd={n_fd}");
    assert!(ds.records.iter().any(|r| r.can_id == Some(0x123 | 0x8000_0000)));
}

// ================= socket 私有协议 / HTTP / Modbus ASCII =================

use iotprobe_core::model::Dir;

fn mkrec(proto_: Proto, ch: u16, dir_: Dir, data: Vec<u8>) -> Record {
    Record { t_ns: 0, ts_src: iotprobe_core::model::TsSrc::Sw, dir: dir_, source: 0, channel: ch, proto: proto_, gap_n: 0, can_id: None, data: data.into() }
}

/// TCP 私有协议:字节流 + DSL(同步头/长度域/CRC)→ Custom 通道 + 信号
#[test]
fn tcp_private_dsl_e2e() {
    let spec: CustomSpec = serde_json::from_str(
        r#"{"name":"priv-tcp","sync":"A55A","min_len":6,
            "length":{"at":2,"size":1,"bias":4},
            "checksum":{"algo":"sum8","cover":[0,"end-1"]},
            "fields":[{"name":"press","at":3,"ty":"u16","endian":"big","plot":true}]}"#,
    ).unwrap();
    let mkframe = |press: u16| -> Vec<u8> {
        let mut f = vec![0xA5u8, 0x5A, 0x02];
        f.extend_from_slice(&press.to_be_bytes());
        f.push(iotprobe_core::crc::sum8(&f));
        f
    };
    // 两个 chunk,各含 1 个前导噪声字节 + 1 帧
    let f1 = mkframe(1000);
    let f2 = mkframe(2000);
    let mut c1 = vec![0x00u8];
    c1.extend_from_slice(&f1);
    let mut c2 = vec![0x11u8];
    c2.extend_from_slice(&f2);
    let recs = vec![
        mkrec(Proto::Tcp, 0, Dir::Rx, c1),
        mkrec(Proto::Tcp, 0, Dir::Rx, c2),
    ];
    let src = iotprobe_core::ingest::SourceData { name: "tcp.log".into(), records: recs, epoch_ns: None, warnings: vec![], chan_labels: std::collections::HashMap::new() };
    let cfg = AnalyzeCfg { custom: vec![spec], ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Custom), "TCP 私有协议应识别为 Custom: {:?}", ds.channels.iter().map(|c| c.proto.label()).collect::<Vec<_>>());
    assert!(ds.signals.iter().any(|s| s.key.contains("press")), "TCP DSL 信号应成列: {:?}", ds.signals.iter().map(|s| &s.key).collect::<Vec<_>>());
}

/// UDP 私有协议:数据报即帧,无同步头直接按字段解码
#[test]
fn udp_private_datagram_e2e() {
    let spec: CustomSpec = serde_json::from_str(
        r#"{"name":"priv-udp","min_len":3,
            "fields":[{"name":"flow","at":0,"ty":"i16","scale":0.1,"plot":true},
                      {"name":"temp","at":2,"ty":"i8","plot":true}]}"#,
    ).unwrap();
    let mut recs = vec![];
    for i in 0..5i16 {
        let mut d = (i * 100).to_be_bytes().to_vec(); // flow = i*100 → 0.1 缩放
        d.push((20 + i) as u8);                       // temp
        d.push(0x55);                                  // status(未映射)
        recs.push(mkrec(Proto::Udp, 0, Dir::Rx, d));
    }
    let src = iotprobe_core::ingest::SourceData { name: "udp.log".into(), records: recs, epoch_ns: None, warnings: vec![], chan_labels: std::collections::HashMap::new() };
    let cfg = AnalyzeCfg { custom: vec![spec], ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Custom), "UDP 私有协议应识别为 Custom: {:?}", ds.channels.iter().map(|c| c.proto.label()).collect::<Vec<_>>());
    assert!(ds.signals.iter().any(|s| s.key.contains("flow")), "UDP DSL 信号应成列");
    // 未加载 DSL 时:可打印判定/裸字节(不 panic 即可)
    let src2 = iotprobe_core::ingest::SourceData {
        name: "udp2.log".into(),
        records: (0..5u16).map(|i| mkrec(Proto::Udp, 0, Dir::Rx, vec![i as u8, 0x41, 0x42])).collect(),
        epoch_ns: None, warnings: vec![], chan_labels: std::collections::HashMap::new(),
    };
    let ds2 = analyze(vec![src2], &AnalyzeCfg::default());
    assert!(!ds2.frames.is_empty());
}

/// HTTP 简析:请求/状态行 + Content-Length
#[test]
fn http_lite_e2e() {
    let req = b"POST /api/v1/telemetry HTTP/1.1\r\nHost: dev1\r\nContent-Length: 5\r\n\r\n".to_vec();
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec();
    let recs = vec![mkrec(Proto::Tcp, 0, Dir::Tx, req), mkrec(Proto::Tcp, 0, Dir::Rx, resp)];
    let src = iotprobe_core::ingest::SourceData { name: "http.log".into(), records: recs, epoch_ns: None, warnings: vec![], chan_labels: std::collections::HashMap::new() };
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Http), "HTTP 应识别: {:?}", ds.channels.iter().map(|c| c.proto.label()).collect::<Vec<_>>());
    assert!(ds.frames.iter().any(|f| f.summary.contains("POST /api/v1/telemetry")));
    assert!(ds.frames.iter().any(|f| f.summary.contains("200 OK")));
    // 按需解码一致
    if let Some(Some(d1)) = ds.decoded.get(0) {
        if ds.decoded[0].is_some() {
            let d2 = iotprobe_core::dissect::decode_one(&ds, 0).expect("HTTP 按需解码");
            assert_eq!(d1.root.len(), d2.root.len());
        }
    }
}

/// Modbus ASCII(LRC)
#[test]
fn modbus_ascii_e2e() {
    let req: Vec<u8> = {
        let mut d = vec![0x01u8, 0x03, 0x00, 0x00, 0x00, 0x02];
        d.push(iotprobe_core::crc::lrc8(&d));
        d
    };
    let resp: Vec<u8> = {
        let mut d = vec![0x01u8, 0x03, 0x04, 0x01, 0x00, 0x01, 0xF4];
        d.push(iotprobe_core::crc::lrc8(&d));
        d
    };
    let mut lines = vec![];
    let base = iotprobe_core::timeutil::wall_to_epoch_ns(2026, 1, 5, 10, 0, 0, 0);
    for i in 0..6u64 {
        let stamp = |ns: u64| -> String {
            let (y, mo, dd, h, mi, s, frac) = iotprobe_core::timeutil::epoch_ns_to_wall(ns);
            format!("{y:04}-{mo:02}-{dd:02} {h:02}:{mi:02}:{s:02}.{:03}", frac / 1_000_000)
        };
        let t = base + i * 100_000_000;
        let hexs = |d: &[u8]| d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
        lines.push(format!("TX {} {}", stamp(t), hexs(&req)));
        lines.push(format!("RX {} {}", stamp(t + 8_000_000), hexs(&resp)));
    }
    let text = lines.join("\n");
    let mut records = vec![];
    let mut labels = std::collections::HashMap::new();
    let mut epoch = None;
    let mut warns = vec![];
    iotprobe_core::ingest::hexlog::parse(&text, &mut records, &mut labels, &mut epoch, &mut warns);
    let src = iotprobe_core::ingest::SourceData { name: "ascii.log".into(), records, epoch_ns: epoch, warnings: warns, chan_labels: labels };
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    assert!(ds.channels.iter().any(|c| c.proto == Proto::ModbusAscii), "Modbus ASCII 应识别: {:?}", ds.channels.iter().map(|c| c.proto.label()).collect::<Vec<_>>());
    assert!(ds.signals.iter().any(|s| s.key.contains("HR")), "ASCII 寄存器值应成列");
}

// ================= 规则包(ADR-6) =================

#[test]
fn rules_pack_e2e() {
    // 内置 BMS 规则包 + modbus 样例 → 三级语义事件(fault/warn/info)
    let dir = ensure_samples();
    let pack = iotprobe_core::rules::load_pack_dir(&dir.join("rules-pack/generic-bms")).expect("规则包加载");
    assert_eq!(pack.pack, "generic-bms");
    let src = ingest::read_file(&dir.join("modbus_rtu.log")).unwrap();
    let map_json = std::fs::read_to_string(dir.join("configs/modbus_map.json")).unwrap();
    let cfg = AnalyzeCfg {
        map: Some(serde_json::from_str(&map_json).unwrap()),
        rule_packs: vec![pack],
        ..Default::default()
    };
    let ds = analyze(vec![src], &cfg);
    let rules: Vec<&iotprobe_core::model::Event> = ds.events.iter().filter(|e| e.kind == EventKind::Rule).collect();
    assert!(!rules.is_empty(), "应有规则事件");
    let codes: std::collections::HashSet<&str> = rules
        .iter()
        .filter_map(|e| e.rule.as_ref().map(|r| r.rule_id.as_str()))
        .collect();
    assert!(codes.contains("TEMP_OVER_LIMIT"), "codes={codes:?}");
    assert!(codes.contains("TEMP_HIGH"), "codes={codes:?}");
    assert!(codes.contains("MOTOR_IDLE"), "codes={codes:?}");
    // 契约:rule_ref + 信号证据 + 三级 level
    let r = rules[0].rule.as_ref().unwrap();
    assert_eq!(r.pack, "generic-bms");
    assert!(!r.signals.is_empty());
    assert!(rules.iter().any(|e| e.rule.as_ref().unwrap().level == "fault"));
    assert!(rules.iter().any(|e| e.rule.as_ref().unwrap().level == "warn"));
    // events_jsonl 仍过 event.schema,code 来自规则 id
    let path = std::env::temp_dir().join("iotprobe_rules_events.jsonl");
    iotprobe_core::export::events_jsonl(&ds, &path).unwrap();
    for line in std::fs::read_to_string(&path).unwrap().lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v["code"].is_string() && v["evidence"]["rule_ref"]["pack"].is_string());
        if v["code"] == "TEMP_OVER_LIMIT" {
            assert_eq!(v["level"], "fault");
            assert!(v["evidence"]["signals"].as_array().unwrap().len() >= 1);
        }
    }
}

/// 超时规则:candump 断流(100ms)触发 BUS_SILENCE(80ms)
#[test]
fn rules_timeout_e2e() {
    let dir = ensure_samples();
    let pack = iotprobe_core::rules::load_pack_dir(&dir.join("rules-pack/generic-heartbeat")).unwrap();
    let src = ingest::read_file(&dir.join("candump.log")).unwrap();
    let cfg = AnalyzeCfg { rule_packs: vec![pack], ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    let silences: Vec<&iotprobe_core::model::Event> = ds
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Rule && e.detail.contains("静默"))
        .collect();
    assert!(!silences.is_empty(), "断流处应触发静默规则");
}

#[test]
fn iec104_e2e() {
    // IEC 60870-5-104 抓包(Wireshark 样本):此前被通道识别误判为 MQTT,
    // 修复后应优先按 APCI 结构判定(P0-A 回归用例)
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("iec104.pcap")).expect("读取失败");
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Iec104),
        "protos={:?}", ds.channels.iter().map(|c| c.proto.label()).collect::<Vec<_>>());
    assert!(!ds.channels.iter().any(|c| c.proto == Proto::Mqtt), "104 不应再被误判为 MQTT");
    // ASDU 解码:遥信/遥测/遥控/设定值都应成信号
    assert!(ds.signals.len() > 30, "signals={}", ds.signals.len());
    assert!(ds.signals.iter().any(|s| s.key.contains("M_DP")), "双点遥信应成信号");
    assert!(ds.signals.iter().any(|s| s.key.contains("C_SE") || s.key.contains("C_SC")), "遥控/设定值应成信号");
    // 帧摘要应带 ASDU 类型名(U/S/I 帧都能解)
    assert!(ds.frames.iter().any(|f| f.summary.contains("M_ME_NC") || f.summary.contains("M_ME_N")));
    assert!(ds.frames.iter().any(|f| f.summary.starts_with("TX U ")));
}

#[test]
fn gb27930_tp_e2e() {
    // GB/T 27930 充电会话节选:J1939 TP.BAM 多帧重组(FR-3.4)
    // BRM 49B(7 包)与 BCP 13B(2 包)应重组后按 DBC 解码出信号
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("gb27930_tp.log")).expect("读取失败");
    let dbc_text = std::fs::read_to_string(dir.join("gb27930_tp.dbc")).unwrap();
    let cfg = AnalyzeCfg { dbc: Some(iotprobe_core::dbc::parse(&dbc_text)), ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Can), "应识别为 CAN 通道");
    // 重组完成事件(BRM + BCP 两路)
    let dones: Vec<_> = ds.events.iter().filter(|e| e.kind == EventKind::Info && e.detail.contains("重组完成")).collect();
    assert!(dones.len() >= 2, "events={:?}", ds.events.iter().map(|e| &e.detail).collect::<Vec<_>>());
    assert!(dones.iter().any(|e| e.detail.contains("49B")), "BRM 49B 应重组");
    assert!(dones.iter().any(|e| e.detail.contains("13B")), "BCP 13B 应重组");
    // BRM 重组信号:rated_capacity_ah = 62.5(生成器写入的额定容量)
    let cap = ds.signals.iter().find(|s| s.key.contains("rated_capacity_ah")).expect("BRM 重组应产出额定容量");
    assert_eq!(cap.pts[0].1, 62.5);
    // BCP 重组信号:soc = 22.0%
    let soc = ds.signals.iter().find(|s| s.key.contains("soc") && s.key.contains("180656")).expect("BCP 重组应产出 SOC");
    assert_eq!(soc.pts[0].1, 22.0);
    // 单帧消息不受影响:BHM 最大电压 355.2V
    let bhm = ds.signals.iter().find(|s| s.key.contains("max_battery_voltage_v")).expect("BHM 单帧信号");
    assert!((bhm.pts[0].1 - 355.2).abs() < 0.01, "BHM={}", bhm.pts[0].1);
}

#[test]
fn map104_e2e() {
    // 104 点表(MVP ②):IOA→工程名/变比/单位,命中时信号改名且值换算
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("iec104.pcap")).expect("读取失败");
    let pt_text = std::fs::read_to_string(dir.join("configs/points_104_demo.yaml")).unwrap();
    let cfg = AnalyzeCfg { map104: Some(Map104::parse(&pt_text).unwrap()), ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    // 改名 + 单位
    let p = ds.signals.iter().find(|s| s.key == "104 有功功率P").expect("点表改名应生效");
    assert_eq!(p.unit, "kW");
    assert!(ds.signals.iter().any(|s| s.key == "104 断路器1位置"), "双点遥信应按点表改名");
    // 变比:标度化遥测 IOA512 ×0.1
    let v = ds.signals.iter().find(|s| s.key == "104 直流电压").expect("标度化遥测应按点表换算");
    assert_eq!(v.unit, "V");
    // 未在点表中的信号保持默认键名
    assert!(ds.signals.iter().any(|s| s.key.contains("M_DP_NA_1·IOA256")), "未配置点表信号应保留默认键名");
    // 原默认键名不再出现(点表命中的 IOA 已改名)
    assert!(!ds.signals.iter().any(|s| s.key.contains("M_ME_NC_1·IOA256")), "命中点表后旧键名应消失");
}

// ================= 拓扑视图(MVP ③)离线回测 =================

use iotprobe_core::topology::{Health, Topology, evaluate};

#[test]
fn topology_modbus_e2e() {
    // 拓扑 YAML 绑定信号 → 设备卡片:绑定命中/越限告警/事件归属/覆盖度
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("modbus_rtu.log")).expect("读取失败");
    let map_json = std::fs::read_to_string(dir.join("configs/modbus_map.json")).unwrap();
    let cfg = AnalyzeCfg { map: Some(serde_json::from_str(&map_json).unwrap()), ..Default::default() };
    let ds = analyze(vec![src], &cfg);

    // 手写拓扑:unit1 绑温度/设定值/状态(温度曲线 17..33°C 会越限 30);
    // 空设备绑定不存在的信号 → NoData
    let topo = Topology::parse(
        r#"name: demo站
devices:
  - id: unit1
    kind: meter
    binds:
      - {signal: TempSensor, label: 温度, warn: '$ > 30', fault: '$ > 45'}
      - {signal: SetPoint}
      - {signal: RunState}
  - id: 空设备
    kind: other
    binds:
      - {signal: 不存在的信号}
"#,
    )
    .unwrap();
    let st = evaluate(&ds, &topo);
    assert_eq!(st.devices.len(), 2);

    // 设备1:绑定信号全部捕获(点表命名的带单位;枚举寄存器也在)
    let d1 = &st.devices[0];
    let temp = d1.sigs.iter().find(|s| s.bind_label == "温度").expect("温度绑定应命中");
    assert_eq!(temp.unit, "°C");
    assert!(temp.frame.is_some(), "应带帧号供点击跳转");
    assert!(d1.sigs.iter().any(|s| s.series_key == "unit1·SetPoint"));
    assert!(d1.sigs.iter().any(|s| s.series_key.ends_with("·RunState")));
    // 健康级:温度越限 30(非 45)→ Warn,不到 Fault
    assert_eq!(d1.health, Health::Warn, "越限告警应置 Warn");
    // 事件归属:unit1 的 CRC 失败/异常码事件 detail 含 unit1 → 归到设备1
    assert!(d1.event_n >= 1, "诊断事件应归到设备1");

    // 设备2:无命中 → NoData 且无信号
    assert_eq!(st.devices[1].health, Health::NoData);
    assert!(st.devices[1].sigs.is_empty());
    // 覆盖度:RTT 等信号未被任何设备绑定 → unbound > 0
    assert!(st.unbound > 0, "unbound 应统计未绑定信号数");
}

#[test]
fn topology_104_e2e() {
    // 104 站拓扑:点表命名的工程信号绑定到 PCS/电池簇卡片
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("iec104.pcap")).expect("读取失败");
    let pt_text = std::fs::read_to_string(dir.join("configs/points_104_demo.yaml")).unwrap();
    let cfg = AnalyzeCfg { map104: Some(Map104::parse(&pt_text).unwrap()), ..Default::default() };
    let ds = analyze(vec![src], &cfg);
    let topo = Topology::parse(
        r#"name: 104储能站
devices:
  - id: PCS-1
    kind: pcs
    binds:
      - {signal: 104 有功功率P, label: 有功, warn: '$ > 1e9'}
  - id: 簇1
    kind: cluster
    binds:
      - {signal: 104 直流电压}
      - {signal: 104 断路器1位置}
"#,
    )
    .unwrap();
    let st = evaluate(&ds, &topo);
    assert_eq!(st.devices.len(), 2);
    // PCS:点表改名 + 单位跟随;warn 阈值 1e9 不可能命中 → 正常
    // (104 点表信号键无 · 分隔,绑定用全等;Modbus/DBC 类用 ·后缀匹配)
    let pcs = &st.devices[0];
    let p = pcs.sigs.iter().find(|s| s.series_key == "104 有功功率P").expect("PCS 有功绑定应命中");
    assert_eq!(p.unit, "kW");
    assert_eq!(pcs.health, Health::Ok);
    // 簇1:直流电压(变比后)与遥信都在
    let c1 = &st.devices[1];
    assert!(c1.sigs.iter().any(|s| s.series_key == "104 直流电压" && s.unit == "V"));
    assert!(c1.sigs.iter().any(|s| s.series_key == "104 断路器1位置"));
}

#[test]
fn rules_hot_reload_e2e() {
    // FR-3.7 规则热加载:真实 modbus 样例上改阈值重跑,不动报文解码
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("modbus_rtu.log")).expect("读取失败");
    let map_json = std::fs::read_to_string(dir.join("configs/modbus_map.json")).unwrap();
    let cfg = AnalyzeCfg { map: Some(serde_json::from_str(&map_json).unwrap()), ..Default::default() };
    let ds = analyze(vec![src], &cfg); // 帧数与诊断事件已固定
    let n_frames = ds.frames.len();
    let n_diag = ds.events.iter().filter(|e| e.kind != EventKind::Rule).count();

    // v1:温度 > 45 → 触发若干 fault
    let pack_v1 = iotprobe_core::rules::load_pack_dir(&dir.join("rules-pack/generic-bms")).unwrap();
    let mut ds2 = ds.clone();
    iotprobe_core::rules::run_rules(std::slice::from_ref(&pack_v1), &mut ds2);
    let v1: Vec<_> = ds2.events.iter().filter(|e| e.kind == EventKind::Rule).collect();
    assert!(!v1.is_empty(), "v1 应有规则事件");

    // v2:同一包三条规则阈值全改为不可能命中 → 旧事件被替换为 0 条,帧数/诊断事件原样
    let pack_v2_yaml = std::fs::read_to_string(dir.join("rules-pack/generic-bms/rules.yaml"))
        .unwrap()
        .replace("$ > 32.0", "$ > 900.0")
        .replace("$ > 30.0 && $ <= 32.0", "$ > 900.0")
        .replace("$ == 2", "$ == 999");
    let pack_v2 = iotprobe_core::rules::parse_pack_yaml(&pack_v2_yaml, "v2").unwrap();
    iotprobe_core::rules::reload_rules(std::slice::from_ref(&pack_v2), &mut ds2);
    assert_eq!(ds2.frames.len(), n_frames, "热加载不动帧");
    assert_eq!(ds2.events.iter().filter(|e| e.kind != EventKind::Rule).count(), n_diag, "诊断事件保留");
    assert_eq!(ds2.events.iter().filter(|e| e.kind == EventKind::Rule).count(), 0, "改阈值后旧规则事件应清零");
    for w in ds2.events.windows(2) {
        assert!(w[0].t_ns <= w[1].t_ns, "事件保持时间有序");
    }
}

#[test]
fn rules_rate_e2e() {
    // on_rate 变化率规则(真实样例):modbus_rtu 温度信号(生成器相位参数为毫秒级 →
    // 采样混叠跳变,实测 1s 时间窗最大变化率 108°C/s)。窗口 1s、阈值 |rate|>8 命中跳变沿;
    // 阈值 150(超过数据实际峰值)不应误报 —— 回测防误报边界。
    let dir = ensure_samples();
    let src = ingest::read_file(&dir.join("modbus_rtu.log")).expect("读取失败");
    let map_json = std::fs::read_to_string(dir.join("configs/modbus_map.json")).unwrap();
    let pack = iotprobe_core::rules::parse_pack_yaml(
        "pack: rate-demo\nrules:\n  - id: TEMP_RAMP\n    level: warn\n    on: rate\n    signal: TempSensor\n    window: 1s\n    rate: \"rate > 8 || rate < -8\"\n    message: \"温度变化过快 {rate}°C/s\"\n",
        "inline",
    )
    .unwrap();
    let cfg = AnalyzeCfg {
        map: Some(serde_json::from_str(&map_json).unwrap()),
        rule_packs: vec![pack],
        ..Default::default()
    };
    let ds = analyze(vec![src], &cfg);
    let ramps: Vec<&Event> = ds.events.iter().filter(|e| e.kind == EventKind::Rule && e.rule.as_ref().unwrap().rule_id == "TEMP_RAMP").collect();
    assert!(!ramps.is_empty(), "跳变沿应触发变化率事件: events={:?}", ds.events.iter().map(|e| &e.detail).collect::<Vec<_>>());
    // 证据带变化率
    let r0 = &ramps[0].rule.as_ref().unwrap().signals;
    assert!(r0.iter().any(|s| s.0.ends_with("·rate")), "证据应含 rate: {:?}", r0);
    // 阈值 150(超过数据实际峰值 108)不应误报
    let pack_hi = iotprobe_core::rules::parse_pack_yaml(
        "pack: rate-hi\nrules:\n  - id: TEMP_RAMP_HI\n    level: warn\n    on: rate\n    signal: TempSensor\n    window: 1s\n    rate: \"rate > 150 || rate < -150\"\n",
        "inline",
    )
    .unwrap();
    let ds2 = analyze(vec![ingest::read_file(&dir.join("modbus_rtu.log")).unwrap()], &AnalyzeCfg {
        map: Some(serde_json::from_str(&map_json).unwrap()),
        rule_packs: vec![pack_hi],
        ..Default::default()
    });
    assert_eq!(ds2.events.iter().filter(|e| e.kind == EventKind::Rule).count(), 0, "阈值超过数据实际峰值不应误报");
}
