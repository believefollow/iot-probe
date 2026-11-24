//! CANopen 验收(任务卡 F1):合成 candump 抓包 → NMT/心跳/SDO 读写配对/EMCY/abort 全链路。
//! 验收口径:SDO 读写配对事件(带 RTT+帧号)、EMCY 错误码可读、PDO 标注、abort/无响应事件。

use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use iotprobe_core::ingest::read_file;
use std::path::PathBuf;

fn run(log_text: &str) -> iotprobe_core::model::Dataset {
    let dir = std::env::temp_dir().join(format!("iotprobe_canopen_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p: PathBuf = dir.join("co.log");
    std::fs::write(&p, log_text).unwrap();
    let sd = read_file(&p).unwrap_or_else(|e| panic!("candump 读取失败: {e}"));
    let ds = analyze(vec![sd], &AnalyzeCfg::default());
    let _ = std::fs::remove_dir_all(&dir);
    ds
}

#[test]
fn canopen_sdo_emcy_nmt_heartbeat() {
    let log = "\
(000.000000) can0 000#0100
(000.010000) can0 705#05
(000.020000) can0 602#4017100000000000
(000.025000) can0 582#4B171000F4010000
(000.030000) can0 083#0022480000000000
(000.040000) can0 181#0102030405060708
(000.050000) can0 602#2B17100201000000
(000.060000) can0 582#8017100201000508
";
    let ds = run(log);
    // 通道应判为 CANopen(11 位 ID + 多类语义帧)
    assert!(ds.frames.iter().any(|f| f.summary.contains("CANopen·NMT")), "NMT 帧: {:?}", ds.frames.iter().map(|f| &f.summary).take(4).collect::<Vec<_>>());
    // SDO 读配对事件(OD 1017:00 = 0x1F4(500),RTT≈5ms,帧号引用)
    let sdo = ds.events.iter().find(|e| e.detail.contains("SDO 读") && e.detail.contains("1017:00")).expect("SDO 读配对事件");
    assert!(sdo.detail.contains("0x1f4"), "值应含 0x1f4: {}", sdo.detail);
    assert!(sdo.detail.contains("RTT"), "应带 RTT: {}", sdo.detail);
    assert!(sdo.frame.is_some(), "证据帧号");
    // SDO abort(Timeout 级,带中止码)
    let abort = ds.events.iter().find(|e| e.detail.contains("被中止")).expect("SDO abort 事件");
    assert!(abort.detail.contains("0x08050001"), "中止码: {}", abort.detail);
    // EMCY 可读(电压异常)
    let emcy = ds.events.iter().find(|e| e.detail.contains("EMCY")).expect("EMCY 事件");
    assert!(emcy.detail.contains("电压异常"), "EMCY 分段名: {}", emcy.detail);
    // 心跳字段
    assert!(ds.frames.iter().any(|f| f.summary.contains("心跳 node5 Operational")), "心跳帧");
    // TPDO 标注
    assert!(ds.frames.iter().any(|f| f.summary.contains("TPDO1(node1)")), "TPDO 标注帧");
}
