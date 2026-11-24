//! PROFINET 验收:真实抓包(Wireshark wiki PROFINET/DCP ChangeIPUsingDCP.pcap)→
//! EtherType 0x8892 通道判定 + DCP Get/Set 流程 + **Set 改配置事件**(运维排障核心)。

use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use iotprobe_core::ingest::read_file;
use iotprobe_core::model::Proto;

#[test]
fn profinet_dcp_real_capture() {
    let src = read_file(std::path::Path::new("tests/data/ChangeIPUsingDCP.pcap")).expect("读取失败");
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    // 通道判定:EtherType 0x8892 → PROFINET
    assert!(ds.channels.iter().any(|c| c.proto == Proto::Pn), "应识别 PROFINET 通道");
    // DCP 流程:Get 请求 → Set 改配置
    assert!(ds.frames.iter().any(|f| f.summary.contains("DCP Get请求")), "DCP Get 帧");
    assert!(ds.frames.iter().any(|f| f.summary.contains("DCP Get响应")), "DCP Get 响应帧");
    assert!(ds.frames.iter().any(|f| f.summary.contains("DCP Set请求")), "DCP Set 帧");
    // Set 事件:改设备名/改 IP 被捕获(fault 级可见)
    let set_e = ds.events.iter().find(|e| e.detail.contains("DCP Set")).expect("DCP Set 事件");
    assert!(set_e.detail.contains("设备名") || set_e.detail.contains("IP"), "{}", set_e.detail);
}
