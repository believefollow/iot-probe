//! 摄入层:文件 → Record 列表。
//! 支持自定义串口十六进制日志(hexlog)、candump 日志、pcap/pcapng(自动做 TCP 重组)。

pub mod hexlog;
pub mod candump;
pub mod asc;
pub mod blf;
pub mod inflate;
pub mod pcap;
pub mod pcapng;
pub mod stream;
pub mod live;

use crate::model::{Dir, Proto, Record, TsSrc};
use std::collections::HashMap;
use std::sync::Arc;

pub struct SourceData {
    pub name: String,
    pub records: Vec<Record>,
    pub epoch_ns: Option<u64>,
    pub warnings: Vec<String>,
    pub chan_labels: HashMap<u16, String>,
}

/// 按扩展名/内容嗅探读取一个文件
pub fn read_file(path: &std::path::Path) -> Result<SourceData, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {}", name, e))?;
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let lower = name.to_lowercase();
    if ext == "pcap" || ext == "cap" || lower.ends_with(".pcapng") {
        let (pkts, mut warns) = pcap::read_any(&bytes)?;
        let mut recs = Vec::new();
        let mut labels = HashMap::new();
        stream::build_streams(&pkts, &mut recs, &mut labels, &mut warns);
        let epoch_ns = pkts.first().map(|p| p.t_ns).filter(|t| *t > 1_000_000_000_000);
        return Ok(SourceData { name, records: recs, epoch_ns, warnings: warns, chan_labels: labels });
    }
    if ext == "dbc" {
        return Err("DBC 文件请用「加载DBC」入口".into());
    }
    // BLF 二进制(Vector Binary Logging):按扩展名或 LOGG 魔法数分流,不进文本嗅探
    if ext == "blf" || bytes.starts_with(b"LOGG") {
        let (records, labels, epoch_ns, warns) = blf::read(&bytes, &name)?;
        return Ok(SourceData { name, records, epoch_ns, warnings: warns, chan_labels: labels });
    }
    // 实时会话录制/回放的 NDJSON 帧流文件(frame.schema.json),与实时接入同一解析器
    if ext == "ndjson" || ext == "jsonl" {
        return live::load_ndjson_file(path);
    }
    // 文本日志:嗅探 candump / Vector ASC / 通用 hexlog
    let text = String::from_utf8_lossy(&bytes).to_string();
    let mut epoch_ns = None;
    let mut records = Vec::new();
    let mut labels = HashMap::new();
    let mut warns = Vec::new();
    if asc::looks_like_asc(&text) {
        asc::parse(&text, &mut records, &mut labels, &mut warns);
    } else if candump::looks_like_candump(&text) {
        candump::parse(&text, &mut records, &mut labels, &mut epoch_ns, &mut warns);
    } else {
        hexlog::parse(&text, &mut records, &mut labels, &mut epoch_ns, &mut warns);
    }
    Ok(SourceData { name, records, epoch_ns, warnings: warns, chan_labels: labels })
}

pub fn rec(t_ns: u64, dir: Dir, proto: Proto, data: Vec<u8>) -> Record {
    Record { t_ns, ts_src: TsSrc::Sw, dir, source: 0, channel: 0, proto, gap_n: 0, can_id: None, data: Arc::from(data) }
}
