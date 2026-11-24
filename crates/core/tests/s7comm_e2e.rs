//! S7comm 验收:真实抓包(Wireshark wiki s7comm_reading_plc_status.pcap)→ 通道判定/事务配对/COTP 全链路。

use iotprobe_core::ingest::read_file;
use iotprobe_core::model::Proto;
use iotprobe_core::dissect::{analyze, AnalyzeCfg};

#[test]
fn s7comm_real_capture() {
    let src = read_file(std::path::Path::new("tests/data/s7comm_reading_plc_status.pcap")).expect("读取失败");
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    // 通道判定:S7comm(且不再误判 MQTT/RAW)
    assert!(ds.channels.iter().any(|c| c.proto == Proto::S7), "应识别 S7comm 通道");
    // COTP 连接请求/确认帧
    assert!(ds.frames.iter().any(|f| f.summary.contains("COTP 连接请求")));
    assert!(ds.frames.iter().any(|f| f.summary.contains("COTP 连接确认")));
    // Setup Communication 事务(请求帧 #3 → 响应帧 #148,RTT>0)
    let e = ds.events.iter().find(|e| e.detail.contains("Setup Communication 完成")).expect("事务配对事件");
    assert!(e.detail.contains("RTT") && e.detail.contains("请求帧 #3"), "{}", e.detail);
    // Userdata 帧存在(该样本主体是 Userdata 读写系统状态表)
    assert!(ds.frames.iter().any(|f| f.summary.contains("Userdata")));
    // 全帧无一误判 MQTT
    assert!(!ds.frames.iter().any(|f| f.summary.contains("MQTT")));
}
