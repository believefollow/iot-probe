//! 解析编排:协议自动识别 → 帧定界 → 字段解码 → 信号时序 + 异常事件。

pub mod custom;
pub mod modbus;
pub mod mqtt;
pub mod iec104;
pub mod map104;
pub mod ethercat;
pub mod dnp3;
pub mod canopen;
pub mod s7comm;
pub mod profinet;
pub mod dl645;
pub mod unknown;

pub use custom::CustomSpec;
pub use modbus::ModbusMap;
pub use map104::Map104;

use crate::dbc::{self, Dbc};
use crate::ingest::SourceData;
use crate::model::*;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct AnalyzeCfg {
    /// 帧间隔告警阈值(ms)。0 = 自动(中位间隔 × 8)
    pub gap_threshold_ms: f64,
    pub custom: Vec<CustomSpec>,
    pub dbc: Option<Dbc>,
    pub map: Option<ModbusMap>,
    /// IEC 104 信息体点表(MVP ②:IOA→工程名/变比/单位)
    pub map104: Option<Map104>,
    /// 规则包(ADR-6;加载即评估,产出契约语义事件)
    pub rule_packs: Vec<crate::rules::RulePack>,
}

// ---------- 信号累积器 ----------

#[derive(Default)]
pub struct SigAcc {
    series: Vec<Series>,
    map: HashMap<String, usize>,
}

/// 测试辅助:构造空的解码上下文(仅单元测试用;泄漏借用以满足 'static)
pub fn dec_for_test() -> Dec<'static> {
    let strings: &'static mut Strings = Box::leak(Box::new(Strings::default()));
    let sigs: &'static mut SigAcc = Box::leak(Box::new(SigAcc::default()));
    let events: &'static mut Vec<Event> = Box::leak(Box::new(Vec::new()));
    Dec {
        strings,
        sigs,
        events,
        map: None,
        map104: None,
        frame: 0,
        t_ns: 0,
        source: 0,
        channel: 0,
        chan_label: String::new(),
        fields: vec![],
    }
}

impl SigAcc {
    pub fn push(&mut self, key: &str, unit: &str, t: u64, v: f64, frame: u32) {
        if let Some(&i) = self.map.get(key) {
            self.series[i].pts.push((t, v, frame));
            if self.series[i].unit.is_empty() && !unit.is_empty() {
                self.series[i].unit = unit.to_string();
            }
        } else {
            self.map.insert(key.to_string(), self.series.len());
            self.series.push(Series { key: key.to_string(), unit: unit.to_string(), pts: vec![(t, v, frame)] });
        }
    }
    pub fn into_series(mut self) -> Vec<Series> {
        for s in &mut self.series {
            s.pts.sort_by_key(|p| p.0);
        }
        self.series.sort_by(|a, b| a.key.cmp(&b.key));
        self.series
    }
}

// ---------- 解码上下文 ----------

pub struct Dec<'a> {
    pub strings: &'a mut Strings,
    pub sigs: &'a mut SigAcc,
    pub events: &'a mut Vec<Event>,
    pub map: Option<&'a modbus::ModbusMap>,
    /// IEC 104 点表(热路径用 ioa 索引)
    pub map104: Option<&'a Map104>,
    pub frame: u32,
    pub t_ns: u64,
    pub source: u16,
    pub channel: u16,
    /// 通道完整标签(用于 RTT 等派生信号命名)
    pub chan_label: String,
    pub fields: Vec<Field>,
}

impl<'a> Dec<'a> {
    pub fn f(&mut self, name: &str, val: Value, start: usize, len: u16, plot: bool, unit: &str) -> Field {
        Field {
            name: self.strings.intern(name),
            val,
            start: start as u16,
            len,
            plot,
            unit: if unit.is_empty() { None } else { Some(self.strings.intern(unit)) },
            children: vec![],
        }
    }
    pub fn f_named(&mut self, name: &str, val: Value, start: usize, len: u16, plot: bool, unit: &str, children: Vec<Field>) -> Field {
        Field {
            name: self.strings.intern(name),
            val,
            start: start as u16,
            len,
            plot,
            unit: if unit.is_empty() { None } else { Some(self.strings.intern(unit)) },
            children,
        }
    }
    pub fn take_fields(&mut self, v: Vec<Field>) {
        self.fields = v;
    }
    pub fn ev(&mut self, kind: EventKind, detail: String, frame: Option<u32>) {
        self.events.push(Event { t_ns: self.t_ns, frame, kind, detail, source: self.source, channel: self.channel, rule: None });
    }
    pub fn sig(&mut self, key: &str, unit: &str, v: f64) {
        let (t, f) = (self.t_ns, self.frame);
        self.sigs.push(key, unit, t, v, f);
    }
}

// ---------- 编排 ----------

#[derive(Clone, Debug)]
enum Mode {
    ModbusRtu,
    ModbusAscii,
    ModbusTcp,
    Mqtt,
    Iec104,
    S7,
    Dl645,
    Dnp3,
    Http,
    EtherCat,
    Pn,
    Can(bool), // fd
    Arp,
    Custom(usize),
    /// UDP 数据报即帧(私有 UDP 协议最常见形态):每报文直接按 spec 字段解码
    CustomDgram(usize),
    RawText,
    RawHex,
}

impl Mode {
    fn proto(&self) -> Proto {
        match self {
            Mode::ModbusRtu => Proto::ModbusRtu,
            Mode::ModbusAscii => Proto::ModbusAscii,
            Mode::ModbusTcp => Proto::ModbusTcp,
            Mode::Mqtt => Proto::Mqtt,
            Mode::Iec104 => Proto::Iec104,
            Mode::S7 => Proto::S7,
            Mode::Dl645 => Proto::Dl645,
            Mode::Dnp3 => Proto::Dnp3,
            Mode::Http => Proto::Http,
            Mode::EtherCat => Proto::EtherCat,
            Mode::Pn => Proto::Pn,
            Mode::Can(false) => Proto::Can,
            Mode::Can(true) => Proto::CanFd,
            Mode::Arp => Proto::Arp,
            Mode::Custom(_) | Mode::CustomDgram(_) => Proto::Custom,
            Mode::RawText | Mode::RawHex => Proto::Raw,
        }
    }
}

/// 轻量 HTTP 探测:方法开头或响应头出现
fn http_probe(d: &[u8]) -> bool {
    let n = d.len().min(4096);
    let head = String::from_utf8_lossy(&d[..n]);
    if ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/1."].iter().any(|m| head.starts_with(m)) {
        return true;
    }
    head.contains("HTTP/1.")
}

/// TPKT(RFC 1006)探测:S7comm/COTP 走 102 端口的载波,每个 PDU 以 `03 00 xx xx` 开头。
/// 命中说明是 TPKT 承载的工业协议(S7 等),解析器未实现,先按 RAW 透传,别被宽松的
/// MQTT 启发式误吞(真实 S7 抓包回归发现)。
/// S7comm 探测:TPKT 头(03 00)+ 内层 COTP 后紧跟 0x32(S7 魔数);≥2 帧命中即判。
/// 强特征(0x32 + COTP 长度自洽),几乎无误命中可能。
fn s7_probe(recs: &[&Record]) -> bool {
    let mut hits = 0usize;
    let mut n = 0usize;
    for r in recs {
        if s7comm::scan(&r.data).0.len() >= 1 {
            hits += 1;
        }
        n += 1;
    }
    n > 0 && hits * 2 > n
}

fn tpkt_probe(recs: &[&Record]) -> bool {
    let mut hits = 0usize;
    let mut n = 0usize;
    for r in recs {
        if r.data.len() >= 4 && r.data[0] == 0x03 && r.data[1] == 0x00 {
            let len = u16::from_be_bytes([r.data[2], r.data[3]]) as usize;
            if len >= 4 && len <= r.data.len() + 4 {
                hits += 1;
            }
        }
        n += 1;
    }
    n > 0 && hits * 2 > n
}

/// DNP3 探测:链路帧 `05 64 LEN CTRL DST SRC` + 首块 CRC-16/DNP 校验通过。
/// CRC 是强校验(单帧误命中概率 ~2⁻¹⁶);TCP 流经重组后一条单向流常只有 1 条记录,
/// 其中可能夹杂零填充/坏帧,不能要求"过半记录命中"(真实抓包回归发现)。
/// 判据:全零/极短(<4B)记录不计入分母;有效记录 ≤1 时单命中即接受,否则要求过半命中。
fn dnp3_probe(recs: &[&Record]) -> bool {
    let mut hits = 0usize;
    let mut n_eff = 0usize;
    for r in recs {
        if r.data.iter().all(|&b| b == 0) || r.data.len() < 10 {
            continue; // 零填充 / keepalive 碎字节,不参与判定
        }
        n_eff += 1;
        // 帧可能不在记录开头(TCP 重组流里前面带零填充/其它字节),窗口扫描;
        // CRC 只对首块(8B)做:LEN<5 的残帧(模糊测试语料)也算命中,定界阶段仍按 LEN≥5 收,
        // 命中的残帧走 Malformed 事件
        let mut hit = false;
        for w in r.data.windows(10).take(8192) {
            if w[0] == 0x05 && w[1] == 0x64 && dnp3::crc_dnp(&w[..8]) == u16::from_le_bytes([w[8], w[9]]) {
                hit = true;
                break;
            }
        }
        if hit {
            hits += 1;
        }
    }
    hits > 0 && (n_eff <= 2 || hits * 2 > n_eff)
}

/// 自定义 spec 在字节流(串口行/TCP 流)上的打分:定界覆盖
fn custom_stream_best(recs: &[&Record], specs: &[custom::CustomSpec]) -> Option<usize> {
    let mut best: Option<(usize, f64)> = None;
    for (i, spec) in specs.iter().enumerate() {
        let mut total = 0usize;
        let mut framed = 0usize;
        let mut n = 0;
        for r in recs {
            total += r.data.len();
            let (fs, _sk) = custom::deframe(&r.data, spec);
            framed += fs.iter().map(|(_, l)| l).sum::<usize>();
            n += fs.len();
        }
        if n >= 2 {
            let score = framed as f64 / total.max(1) as f64;
            if score > 0.3 && best.map(|b| score > b.1).unwrap_or(true) {
                best = Some((i, score));
            }
        }
    }
    best.map(|(i, _)| i)
}

/// 自定义 spec 在 UDP 数据报上的打分:每报文即一帧,按 spec 解码出 ≥1 字段
fn custom_datagram_best(recs: &[&Record], specs: &[custom::CustomSpec]) -> Option<usize> {
    if recs.len() < 2 {
        return None;
    }
    for (i, spec) in specs.iter().enumerate() {
        let mut ok = 0usize;
        let mut n = 0usize;
        let mut st = Strings::default();
        for r in recs {
            if r.data.len() < 4 || r.data.len() > 1500 {
                continue;
            }
            n += 1;
            let fields = custom::decode(&r.data, spec, &mut st);
            if !fields.is_empty() {
                ok += 1;
            }
        }
        if n >= 2 && ok as f64 > n as f64 * 0.6 {
            return Some(i);
        }
    }
    None
}

fn printable_ratio(d: &[u8]) -> f64 {
    if d.is_empty() {
        return 0.0;
    }
    let ok = d.iter().filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7F).contains(&b) || b >= 0x80).count();
    ok as f64 / d.len() as f64
}

pub fn analyze(sources: Vec<SourceData>, cfg: &AnalyzeCfg) -> Dataset {
    let mut records: Vec<Record> = vec![];
    let mut src_names: Vec<String> = vec![];
    let mut warnings = vec![];
    let mut epoch: Option<u64> = None;
    let mut chan_labels: HashMap<(u16, u16), String> = HashMap::new();
    for (si, s) in sources.into_iter().enumerate() {
        let si = si as u16;
        src_names.push(s.name.clone());
        if epoch.is_none() {
            epoch = s.epoch_ns;
        }
        for w in &s.warnings {
            warnings.push(format!("[{}] {}", s.name, w));
        }
        for (cid, lab) in s.chan_labels {
            chan_labels.insert((si, cid), lab);
        }
        for mut r in s.records {
            r.source = si;
            records.push(r);
        }
    }

    // 时间基准归零
    let t0 = records.iter().map(|r| r.t_ns).min().unwrap_or(0);
    for r in &mut records {
        r.t_ns -= t0;
    }

    // 通道分组(保持出现顺序)
    let mut order: Vec<(u16, u16)> = vec![];
    let mut groups: HashMap<(u16, u16), Vec<u32>> = HashMap::new();
    for (i, r) in records.iter().enumerate() {
        let k = (r.source, r.channel);
        if !groups.contains_key(&k) {
            order.push(k);
        }
        groups.entry(k).or_default().push(i as u32);
    }

    let mut strings = Strings::default();
    let mut sigs = SigAcc::default();
    let mut events: Vec<Event> = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut decoded: Vec<Option<Arc<Decoded>>> = Vec::new();
    let mut channels: Vec<ChannelMeta> = Vec::new();
    // 大文件护栏:字段树是内存大头,超过预算的通道不再存储(详情页按需解码)
    let mut tree_budget: usize = LAZY_TREE_LIMIT;
    let mut lazy_channels = 0usize;

    for (src, ch) in order {
        let ridxs = groups[&(src, ch)].clone();
        let hint = records[ridxs[0] as usize].proto;
        let base_label = chan_labels.get(&(src, ch)).cloned().unwrap_or_else(|| format!("ch{ch}"));

        // ---- 协议求解 ----
        let mode: Mode = match hint {
            Proto::Tcp => {
                // 已知协议 → 私有 DSL(同步头/长度域,字节流形态)→ HTTP → 裸字节
                // IEC 104 在 MQTT 之前判定:APCI 结构严格(0x68+长度收尾+域合法),
                // 且要求 ≥2 个 APDU、覆盖率过半;MQTT 扫描宽松(起始 nibble + varint),
                // 若先判会把 104 流量误吞。
                let mut mb = 0;
                let mut mq = 0;
                let mut hp = 0;
                let mut i104_n = 0usize;
                let mut i104_framed = 0usize;
                let mut total_b = 0usize;
                let recs: Vec<&Record> = ridxs.iter().map(|&ri| &records[ri as usize]).collect();
                for r in &recs {
                    mb += modbus::parse_tcp(&r.data).len();
                    mq += mqtt::scan(&r.data).0.len();
                    let (apdus, _) = iec104::scan(&r.data);
                    i104_n += apdus.len();
                    i104_framed += apdus.iter().map(|(_, l, _)| *l).sum::<usize>();
                    total_b += r.data.len();
                    if http_probe(&r.data) {
                        hp += 1;
                    }
                }
                if mb > 0 {
                    Mode::ModbusTcp
                } else if i104_n >= 2 && i104_framed > total_b / 2 {
                    Mode::Iec104
                } else if s7_probe(&recs) {
                    Mode::S7
                } else if tpkt_probe(&recs) {
                    // 其余 TPKT 载波(未实现协议):保持 RAW 不被 MQTT 吞
                    Mode::RawHex
                } else if dnp3_probe(&recs) {
                    Mode::Dnp3
                } else if mq > 0 {
                    Mode::Mqtt
                } else if let Some(i) = custom_stream_best(&recs, &cfg.custom) {
                    Mode::Custom(i)
                } else if hp > 0 {
                    Mode::Http
                } else {
                    Mode::RawHex
                }
            }
            Proto::EtherCat => Mode::EtherCat,
            Proto::Pn => Mode::Pn,
            Proto::Can => Mode::Can(false),
            Proto::CanFd => Mode::Can(true),
            Proto::Udp => {
                // 数据报即帧:私有 UDP 协议(设备直报)→ 文本 → hex
                let recs: Vec<&Record> = ridxs.iter().map(|&ri| &records[ri as usize]).collect();
                if let Some(i) = custom_datagram_best(&recs, &cfg.custom) {
                    Mode::CustomDgram(i)
                } else {
                    let mut pr = 0f64;
                    for r in &recs {
                        pr += printable_ratio(&r.data);
                    }
                    if pr / recs.len().max(1) as f64 > 0.8 {
                        Mode::RawText
                    } else {
                        Mode::RawHex
                    }
                }
            }
            Proto::Arp => Mode::Arp,
            _ => {
                // 串口/未知:自定义 spec → Modbus RTU → 文本 → 十六进制
                let mut best: Option<(usize, f64)> = None;
                for (i, spec) in cfg.custom.iter().enumerate() {
                    let mut total = 0usize;
                    let mut framed = 0usize;
                    let mut n = 0;
                    for &ri in &ridxs {
                        let d = &records[ri as usize].data;
                        total += d.len();
                        let (fs, _sk) = custom::deframe(d, spec);
                        framed += fs.iter().map(|(_, l)| l).sum::<usize>();
                        n += fs.len();
                    }
                    if n >= 2 {
                        let score = framed as f64 / total.max(1) as f64;
                        if score > 0.3 && best.map(|b| score > b.1).unwrap_or(true) {
                            best = Some((i, score));
                        }
                    }
                }
                if let Some((i, _)) = best {
                    Mode::Custom(i)
                } else {
                    let mut cov_total = 0usize;
                    let mut cov_ok = 0usize;
                    for &ri in &ridxs {
                        let d = &records[ri as usize].data;
                        cov_total += d.len();
                        for (_, l) in modbus::scan(d, records[ri as usize].dir) {
                            cov_ok += l;
                        }
                    }
                    // DL/T 645-2007 探测:68..68..16 + CS 校验通过(强特征,先于 Modbus 判定)
                    let mut d645_ok = 0usize;
                    let mut d645_n = 0usize;
                    for &ri in &ridxs {
                        let d = &records[ri as usize].data;
                        if d.len() < 12 {
                            continue;
                        }
                        d645_n += 1;
                        let (fs645, _) = dl645::scan(d);
                        if !fs645.is_empty() {
                            d645_ok += 1;
                        }
                    }
                    if d645_n >= 2 && d645_ok as f64 > d645_n as f64 * 0.6 {
                        Mode::Dl645
                    } else if cov_ok as f64 > cov_total as f64 * 0.5 && cov_ok > 0 {
                        Mode::ModbusRtu
                    } else {
                        // Modbus ASCII:整行 LRC 校验命中(FR-3.2 可选)
                        let mut ascii_ok = 0usize;
                        let mut ascii_n = 0usize;
                        for &ri in &ridxs {
                            let d = &records[ri as usize].data;
                            if d.is_empty() {
                                continue;
                            }
                            ascii_n += 1;
                            if modbus::lrc_frame_ok(d) && d.len() >= 4 && matches!(d[1], 1..=6 | 15 | 16) {
                                ascii_ok += 1;
                            }
                        }
                        if ascii_n >= 2 && ascii_ok as f64 > ascii_n as f64 * 0.6 {
                            Mode::ModbusAscii
                        } else {
                            let mut pr = 0f64;
                            let mut n = 0;
                            for &ri in &ridxs {
                                pr += printable_ratio(&records[ri as usize].data);
                                n += 1;
                            }
                            if n > 0 && pr / n as f64 > 0.8 {
                                Mode::RawText
                            } else {
                                Mode::RawHex
                            }
                        }
                    }
                }
            }
        };

        // ---- 帧定界 ----
        // 每项: (record 索引, off, len)
        let mut ch_frames: Vec<(u32, usize, usize)> = Vec::new();
        match mode {
            Mode::Dl645 => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    ch_frames.push((ri, 0, rec.data.len()));
                }
            }
            Mode::ModbusRtu => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    let found = modbus::scan(&rec.data, rec.dir);
                    if found.is_empty() && !rec.data.is_empty() {
                        events.push(Event {
                            t_ns: rec.t_ns,
                            frame: None,
                            kind: EventKind::Malformed,
                            detail: format!("[{}] {}B 数据无法按 Modbus RTU 定界", base_label, rec.data.len()),
                            source: src,
                            channel: ch,
                        rule: None,
                        });
                    }
                    for (o, l) in found {
                        ch_frames.push((ri, o, l));
                    }
                }
            }
            Mode::Custom(si) => {
                let spec = &cfg.custom[si];
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    let (fs, skipped) = custom::deframe(&rec.data, spec);
                    if skipped > 0 {
                        events.push(Event {
                            t_ns: rec.t_ns,
                            frame: None,
                            kind: EventKind::Malformed,
                            detail: format!("[{}] {}B 无法按 {} 定界(同步/校验失败)", base_label, skipped, spec.name),
                            source: src,
                            channel: ch,
                        rule: None,
                        });
                    }
                    for (o, l) in fs {
                        ch_frames.push((ri, o, l));
                    }
                }
            }
            Mode::CustomDgram(si) => {
                // UDP 数据报即帧:每报文整段按 spec 解码
                let _ = si;
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    ch_frames.push((ri, 0, rec.data.len()));
                }
            }
            Mode::ModbusTcp => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    for f in modbus::parse_tcp(&rec.data) {
                        ch_frames.push((ri, f.off, f.len));
                    }
                }
            }
            Mode::Mqtt => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    let (fs, junk) = mqtt::scan(&rec.data);
                    if junk > 0 {
                        events.push(Event {
                            t_ns: rec.t_ns,
                            frame: None,
                            kind: EventKind::Malformed,
                            detail: format!("[{}] MQTT 流中 {}B 无法解析", base_label, junk),
                            source: src,
                            channel: ch,
                        rule: None,
                        });
                    }
                    for (o, l, _) in fs {
                        ch_frames.push((ri, o, l));
                    }
                }
            }
            Mode::Iec104 => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    let (fs, junk) = iec104::scan(&rec.data);
                    if junk > 0 {
                        events.push(Event {
                            t_ns: rec.t_ns,
                            frame: None,
                            kind: EventKind::Malformed,
                            detail: format!("[{}] IEC 104 流中 {}B 无法按 APCI 定界", base_label, junk),
                            source: src,
                            channel: ch,
                        rule: None,
                        });
                    }
                    for (o, l, _) in fs {
                        ch_frames.push((ri, o, l));
                    }
                }
            }
            Mode::S7 => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    let (fs, junk) = s7comm::scan(&rec.data);
                    if junk > 0 {
                        events.push(Event {
                            t_ns: rec.t_ns,
                            frame: None,
                            kind: EventKind::Malformed,
                            detail: format!("[{}] S7comm 流中 {}B 无法按 TPKT/COTP 定界", base_label, junk),
                            source: src,
                            channel: ch,
                            rule: None,
                        });
                    }
                    for (o, l) in fs {
                        ch_frames.push((ri, o, l));
                    }
                }
            }
            Mode::Dnp3 => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    let (fs, junk) = dnp3::scan(&rec.data);
                    if junk > 0 {
                        events.push(Event {
                            t_ns: rec.t_ns,
                            frame: None,
                            kind: EventKind::Malformed,
                            detail: format!("[{}] DNP3 流中 {}B 无法按链路帧定界(CRC 不符)", base_label, junk),
                            source: src,
                            channel: ch,
                        rule: None,
                        });
                    }
                    for (o, l) in fs {
                        ch_frames.push((ri, o, l));
                    }
                }
            }
            _ => {
                for &ri in &ridxs {
                    let rec = &records[ri as usize];
                    ch_frames.push((ri, 0, rec.data.len()));
                }
            }
        }

        // ---- 解码 ----
        let mut can_total = 0u32; // 体检卡:CAN 帧总数(MVP C2)
        let mut can_dbc_hit = 0u32; // 体检卡:DBC 解出信号的 CAN 帧数
        let mut mqtt_v5 = false; // 会话级:CONNECT level≥5 时置位(属性段跳过)
        let mut pending_rtu: HashMap<u8, (u8, u16, u16, u64)> = HashMap::new(); // unit → (func, start, qty, 请求时间)
        let mut pending_tcp: HashMap<u16, (u8, u16, u16, u64)> = HashMap::new(); // tid → (func, start, qty, 请求时间)
        let mut sdo_pairers: HashMap<(u16, u16), canopen::SdoPairer> = HashMap::new(); // (src,ch) → SDO 请求/响应配对(F1)
        let mut s7_pairers: HashMap<(u16, u16), s7comm::S7Pairer> = HashMap::new(); // (src,ch) → S7 事务配对
        // FR-3.4: J1939 TP.BAM 多帧重组会话(按源地址 SA 一路一会话)+ 总线上出现过的源地址集
        let mut tp_bam: HashMap<u8, TpBamSess> = HashMap::new();
        let mut ext_srcs: Vec<u8> = Vec::new();

        for &(ri, off, len) in &ch_frames {
            let rec = &records[ri as usize];
            let mut proto = mode.proto();
            let fi = frames.len() as u32;
            let d = &rec.data[off.min(rec.data.len())..(off + len).min(rec.data.len())];
            let chan_label_full = format!(
                "[{}] {}",
                src_names.get(src as usize).map(|s| s.as_str()).unwrap_or("?"),
                base_label
            );
            let mut dec = Dec {
                strings: &mut strings,
                sigs: &mut sigs,
                events: &mut events,
                map: cfg.map.as_ref(),
                map104: cfg.map104.as_ref(),
                frame: fi,
                t_ns: rec.t_ns,
                source: src,
                channel: ch,
                chan_label: chan_label_full.clone(),
                fields: vec![],
            };
            let summary;
            let mut root = Vec::new();
            let mut ok = true;
            match mode {
                Mode::Dl645 => {
                    summary = format!("{} {}", rec.dir.label(), dl645::decode(&mut dec, d));
                    root = std::mem::take(&mut dec.fields);
                }
                Mode::ModbusRtu => {
                    if d.len() >= 4 {
                        let unit = d[0];
                        let f = d[1];
                        let pdu = &d[1..d.len() - 2];
                        let crc_valid = modbus::crc_ok(d);
                        if !crc_valid {
                            dec.ev(EventKind::CrcError, format!("unit{unit} CRC16 校验失败"), Some(fi));
                            ok = false;
                        }
                        // 响应先查配对的请求;请求解码后登记
                        let req_t = if rec.dir == Dir::Rx { pending_rtu.get(&unit).map(|(_, _, _, t)| *t) } else { None };
                        let hint = if rec.dir == Dir::Rx { pending_rtu.get(&unit).map(|(_, s, q, _)| (*s, *q)) } else { None };
                        let out = modbus::decode_pdu(&mut dec, rec.dir, unit, pdu, 1, hint);
                        if crc_valid && rec.dir == Dir::Tx {
                            if let Some((s, q)) = out.req {
                                // 旧请求未等到响应就被覆盖 = 该轮请求丢失响应(重试场景的关键事件)
                                if let Some((of, os, oq, ot)) = pending_rtu.get(&unit) {
                                    let oend = os + oq.saturating_sub(1);
                                    let dt_s = rec.t_ns.saturating_sub(*ot) as f64 / 1e9;
                                    dec.ev(
                                        EventKind::Timeout,
                                        format!(
                                            "[{base_label}] unit{unit} {} [{os}..{oend}] 无响应(请求被 {dt_s:.3}s 后的后续请求覆盖)",
                                            modbus::func_name(of & 0x7F)
                                        ),
                                        Some(fi),
                                    );
                                }
                                pending_rtu.insert(unit, (f, s, q, rec.t_ns));
                            }
                        }
                        if rec.dir == Dir::Rx {
                            if let Some(rt) = req_t {
                                let rtt = rec.t_ns.saturating_sub(rt) as f64 / 1e6;
                                dec.sig(&format!("RTT·{}", dec.chan_label), "ms", rtt);
                            }
                            // 收到响应(含异常响应)= 事务完成
                            pending_rtu.remove(&unit);
                        }
                        summary = format!("{} {}", rec.dir.label(), out.summary);
                        root = out.root;
                    } else {
                        summary = format!("{} 短帧 {}B", rec.dir.label(), d.len());
                    }
                }
                Mode::ModbusAscii => {
                    // ASCII 帧:addr,func,...,lrc(单字节校验);pdu 与 RTU 同构
                    if d.len() >= 4 {
                        let unit = d[0];
                        let f = d[1];
                        let pdu = &d[1..d.len() - 1];
                        let lrc_ok = modbus::lrc_frame_ok(d);
                        if !lrc_ok {
                            dec.ev(EventKind::CrcError, format!("unit{unit} LRC 校验失败"), Some(fi));
                            ok = false;
                        }
                        let req_t = if rec.dir == Dir::Rx { pending_rtu.get(&unit).map(|(_, _, _, t)| *t) } else { None };
                        let hint = if rec.dir == Dir::Rx { pending_rtu.get(&unit).map(|(_, s, q, _)| (*s, *q)) } else { None };
                        let out = modbus::decode_pdu(&mut dec, rec.dir, unit, pdu, 1, hint);
                        if lrc_ok && rec.dir == Dir::Tx {
                            if let Some((s, q)) = out.req {
                                if let Some((of, os, oq, ot)) = pending_rtu.get(&unit) {
                                    let oend = os + oq.saturating_sub(1);
                                    let dt_s = rec.t_ns.saturating_sub(*ot) as f64 / 1e9;
                                    dec.ev(
                                        EventKind::Timeout,
                                        format!(
                                            "[{base_label}] unit{unit} {} [{os}..{oend}] 无响应(请求被 {dt_s:.3}s 后的后续请求覆盖)",
                                            modbus::func_name(of & 0x7F)
                                        ),
                                        Some(fi),
                                    );
                                }
                                pending_rtu.insert(unit, (f, s, q, rec.t_ns));
                            }
                        }
                        if rec.dir == Dir::Rx {
                            if let Some(rt) = req_t {
                                let rtt = rec.t_ns.saturating_sub(rt) as f64 / 1e6;
                                dec.sig(&format!("RTT·{}", dec.chan_label), "ms", rtt);
                            }
                            pending_rtu.remove(&unit);
                        }
                        summary = format!("{} {}", rec.dir.label(), out.summary);
                        root = out.root;
                    } else {
                        summary = format!("{} 短帧 {}B", rec.dir.label(), d.len());
                    }
                }
                Mode::ModbusTcp => {
                    if d.len() >= 8 {
                        let tid = u16::from_be_bytes([d[0], d[1]]);
                        let uid = d[6];
                        let pdu = &d[7..];
                        let f = pdu.first().copied().unwrap_or(0);
                        let mut req_t: Option<u64> = None;
                        let mut hint: Option<(u16, u16)> = None;
                        if rec.dir == Dir::Tx && f & 0x80 == 0 && pdu.len() >= 5 && matches!(f, 1..=4 | 6 | 16) {
                            let start = u16::from_be_bytes([pdu[1], pdu[2]]);
                            let qty = if f == 6 { 1 } else { u16::from_be_bytes([pdu[3], pdu[4]]) };
                            // 未应答的旧请求被覆盖 → 该轮丢失响应
                            if let Some((of, os, oq, ot)) = pending_tcp.get(&tid) {
                                let oend = os + oq.saturating_sub(1);
                                let dt_s = rec.t_ns.saturating_sub(*ot) as f64 / 1e9;
                                dec.ev(
                                    EventKind::Timeout,
                                    format!(
                                        "[{base_label}] tid={tid} {} [{os}..{oend}] 无响应(请求被 {dt_s:.3}s 后的后续请求覆盖)",
                                        modbus::func_name(of & 0x7F)
                                    ),
                                    Some(fi),
                                );
                            }
                            pending_tcp.insert(tid, (f, start, qty, rec.t_ns));
                        } else if rec.dir == Dir::Rx {
                            req_t = pending_tcp.get(&tid).map(|(_, _, _, t)| *t);
                            hint = pending_tcp.get(&tid).map(|(_, s, q, _)| (*s, *q));
                        }
                        let out = modbus::decode_pdu(&mut dec, rec.dir, uid, pdu, 7, hint);
                        if rec.dir == Dir::Rx {
                            if let Some(rt) = req_t {
                                let rtt = rec.t_ns.saturating_sub(rt) as f64 / 1e6;
                                dec.sig(&format!("RTT·{}", dec.chan_label), "ms", rtt);
                            }
                            pending_tcp.remove(&tid);
                        }
                        summary = format!("{} tid={tid} {}", rec.dir.label(), out.summary);
                        root = out.root;
                    } else {
                        summary = format!("{} 短帧 {}B", rec.dir.label(), d.len());
                    }
                }
                Mode::Mqtt => {
                    let (fs, _junk) = mqtt::scan(&rec.data);
                    let ptype = fs.iter().find(|(o, _, _)| *o == off).map(|(_, _, t)| *t).unwrap_or(0);
                    if ptype == 1 {
                        if let Some(lv) = mqtt::connect_level(&rec.data, off, len) {
                            if lv >= 5 {
                                mqtt_v5 = true;
                            }
                        }
                    }
                    if ptype > 0 {
                        summary = format!("{} {}", rec.dir.label(), mqtt::decode(&mut dec, &rec.data, off, len, ptype, mqtt_v5));
                        root = std::mem::take(&mut dec.fields);
                    } else {
                        summary = format!("{} MQTT {}B", rec.dir.label(), len);
                    }
                }
                Mode::EtherCat => {
                    summary = ethercat::decode(&mut dec, &rec.data);
                    root = std::mem::take(&mut dec.fields);
                }
                Mode::Pn => {
                    summary = profinet::decode(&mut dec, &rec.data);
                    root = std::mem::take(&mut dec.fields);
                }
                Mode::Iec104 => {
                    summary = format!("{} {}", rec.dir.label(), iec104::decode(&mut dec, &rec.data, off, len));
                    root = std::mem::take(&mut dec.fields);
                }
                Mode::S7 => {
                    let pairer = s7_pairers.entry((src, ch)).or_default();
                    let t_ns = rec.t_ns;
                    match s7comm::decode(&mut dec, &rec.data, off, len, pairer, fi, t_ns) {
                        Some((fld, text)) => {
                            root = std::mem::take(&mut dec.fields);
                            root.push(fld);
                            summary = format!("{} {}", rec.dir.label(), text);
                        }
                        None => {
                            summary = format!("{} {}B", rec.dir.label(), d.len());
                            root.push(dec.f("数据", Value::Hex(d.to_vec()), 0, d.len() as u16, false, ""));
                        }
                    }
                }
                Mode::Dnp3 => {
                    summary = format!("{} {}", rec.dir.label(), dnp3::decode(&mut dec, &rec.data, off, len));
                    root = std::mem::take(&mut dec.fields);
                }
                Mode::Can(_) => {
                    if rec.proto == Proto::CanFd {
                        proto = Proto::CanFd;
                    }
                    let fd = rec.proto == Proto::CanFd;
                    let raw_id = rec.can_id.unwrap_or(0);
                    let ext = raw_id & 0x8000_0000 != 0;
                    let id = raw_id & 0x1FFF_FFFF;
                    let id_str = if ext { format!("0x{id:X}x") } else { format!("0x{id:X}") };
                    can_total += 1;
                    let mut kids = vec![dec.f("数据", Value::Hex(d.to_vec()), 0, d.len() as u16, false, "")];
                    if let Some(dbc) = &cfg.dbc {
                        let key = crate::dbc::msg_key(id, ext);
                        for (sig, v, label) in dbc::decode_message(dbc, key, d) {
                            let disp = match &label {
                                Some(l) => format!("{} = {} ({l})", sig.name, Value::F(v).display()),
                                None => format!("{} = {}", sig.name, Value::F(v).display()),
                            };
                            let sk = format!("CAN {id_str}·{}", sig.name);
                            dec.sig(&sk, &sig.unit, v);
                            kids.push(dec.f(&disp, Value::F(v), 0, 0, true, &sig.unit));
                        }
                    }
                    if kids.len() > 1 {
                        can_dbc_hit += 1;
                    }
                    // F1:DBC 未命中且 11 位 ID → 尝试 CANopen 语义层(NMT/EMCY/心跳/SDO/PDO;
                    // 严格帧结构校验,非 CANopen 总线不误标;PDO 信号命名等真实 EDS 样本)
                    if !ext && kids.len() == 1 {
                        if let Some(fld) = canopen::decode(&mut dec, id, d) {
                            kids.push(fld);
                            let fc = id >> 7;
                            if (fc == 11 || fc == 12) && d.len() == 8 {
                                sdo_pairers.entry((src, ch)).or_default().feed(&mut dec, fi, rec.t_ns, id, d);
                            }
                        }
                    }
                    // FR-3.4:J1939 TP.BAM 多帧重组(GB/T 27930 BRM/BCP/BCS 等 >8B 报文)
                    if ext && d.len() >= 8 {
                        let sa = (id & 0xFF) as u8;
                        let pf = ((id >> 16) & 0xFF) as u8;
                        if !ext_srcs.contains(&sa) {
                            ext_srcs.push(sa);
                        }
                        if pf == 0xEC && d[0] == 32 {
                            // BAM 宣告:总长 / 总包数 / PGN(3B LE)
                            let total = (d[1] as usize | (d[2] as usize) << 8).min(1785);
                            let pkts = (d[3] as usize).clamp(1, 255);
                            let pgn = d[5] as u32 | (d[6] as u32) << 8 | (d[7] as u32) << 16;
                            if let Some(old) = tp_bam.insert(sa, TpBamSess { total, pkts, pgn, buf: vec![0xFF; total], rcv: vec![false; pkts], frags: vec![] }) {
                                if old.frags.len() < old.pkts {
                                    dec.ev(EventKind::StreamDrop, format!(
                                        "[{base_label}] TP.BAM PGN {:#06X} 重组未完成(收 {}/{} 包)即被新会话替换",
                                        old.pgn, old.frags.len(), old.pkts), Some(fi));
                                }
                            }
                        } else if pf == 0xEB {
                            let seq = d[0] as usize;
                            let mut done: Option<(u32, usize, usize, Vec<u8>)> = None;
                            if let Some(s) = tp_bam.get_mut(&sa) {
                                if seq >= 1 && seq <= s.pkts {
                                    let o = (seq - 1) * 7;
                                    let end = (o + 7).min(s.buf.len());
                                    if o < end {
                                        s.buf[o..end].copy_from_slice(&d[1..1 + (end - o)]);
                                    }
                                    s.rcv[seq - 1] = true;
                                    s.frags.push(fi);
                                    if s.rcv.iter().all(|&b| b) {
                                        done = Some((s.pgn, s.total, s.frags.len(), std::mem::take(&mut s.buf)));
                                    }
                                }
                            }
                            if let Some((pgn, total, nfrag, payload)) = done {
                                tp_bam.remove(&sa);
                                let pf2 = (pgn >> 8) as u8;
                                let mut n_sig = 0usize;
                                if let Some(dbc) = &cfg.dbc {
                                    // 候选目的地址:对端 SA(点对点)/ 0x00 / 0xFF(广播);
                                    // 掩码匹配 DBC 键(容忍任意优先级),命中一组即止
                                    let mut ps_cands: Vec<u8> = ext_srcs.iter().copied().filter(|&s| s != sa).collect();
                                    for ps in [0x00u8, 0xFF] {
                                        if !ps_cands.contains(&ps) {
                                            ps_cands.push(ps);
                                        }
                                    }
                                    for ps in ps_cands {
                                        let want = ((pf2 as u32) << 16) | ((ps as u32) << 8);
                                        // 掩码 0x01FF_FF00 = DP+PF+PS(bit 8..=24),剔除优先级与保留位
                                        let key = dbc.msgs.keys().find(|k| (*k & 0x01FF_FF00) == want && (*k & 0xFF) == sa as u32).copied();
                                        let Some(key) = key else { continue };
                                        for (sig, v, label) in dbc::decode_message(dbc, key, &payload) {
                                            let disp = match &label {
                                                Some(l) => format!("{} = {} ({l})", sig.name, Value::F(v).display()),
                                                None => format!("{} = {}", sig.name, Value::F(v).display()),
                                            };
                                            let sk = format!("CAN 0x{:X}x·{}", key & 0x1FFF_FFFF, sig.name);
                                            dec.sig(&sk, &sig.unit, v);
                                            kids.push(dec.f(&disp, Value::F(v), 0, 0, true, &sig.unit));
                                            n_sig += 1;
                                        }
                                        break;
                                    }
                                }
                                dec.ev(EventKind::Info, format!(
                                    "[{base_label}] TP.BAM 重组完成 PGN {:#06X}:{total}B → {n_sig} 信号({nfrag} 包碎片)",
                                    pgn), Some(fi));
                            }
                        }
                    }
                    let sig_txt = kids.iter().skip(1).map(|f| dec.strings.get(f.name).to_string()).collect::<Vec<_>>().join(" ");
                    summary = format!("{id_str} {}B{} {}", d.len(), if fd { "+" } else { "" }, sig_txt);
                    root.push(dec.f_named(&format!("ID {id_str}"), Value::U(id as u64), 0, 0, false, "", kids));
                }
                Mode::Arp => {
                    summary = format!("{} {}B", mode.proto().label(), d.len());
                    root.push(dec.f("数据", Value::Hex(d.to_vec()), 0, d.len() as u16, false, ""));
                }
                Mode::Custom(si) => {
                    let spec = cfg.custom[si].clone();
                    root = custom::decode(d, &spec, &mut *dec.strings);
                    // 递归收集 plot 字段(含 bits 子位)
                    let mut pts: Vec<(String, String, f64)> = Vec::new();
                    collect_custom_signals(&root, &*dec.strings, &spec.name, &mut pts);
                    for (k, u, v) in pts {
                        dec.sig(&k, &u, v);
                    }
                    summary = format!("{} {} {}", spec.name, d.iter().take(8).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "), if d.len() > 8 { "…" } else { "" });
                }
                Mode::CustomDgram(si) => {
                    // UDP 数据报即帧:整报文按 spec 解码
                    let spec = cfg.custom[si].clone();
                    root = custom::decode(d, &spec, &mut *dec.strings);
                    let mut pts: Vec<(String, String, f64)> = Vec::new();
                    collect_custom_signals(&root, &*dec.strings, &spec.name, &mut pts);
                    for (k, u, v) in pts {
                        dec.sig(&k, &u, v);
                    }
                    summary = format!("{} {}B {}", spec.name, d.len(), d.iter().take(6).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "));
                }
                Mode::Http => {
                    // 轻量 HTTP 简析:请求/状态行 + Content-Length
                    let text = String::from_utf8_lossy(d);
                    let first = text.lines().next().unwrap_or("").to_string();
                    let mut content_len: Option<u64> = None;
                    for l in text.lines() {
                        let ll = l.to_ascii_lowercase();
                        if let Some(v) = ll.strip_prefix("content-length:") {
                            content_len = v.trim().parse().ok();
                        }
                        if l.trim().is_empty() {
                            break;
                        }
                    }
                    let mut kids = vec![dec.f("首行", Value::S(first.clone()), 0, first.len() as u16, false, "")];
                    if let Some(cl) = content_len {
                        kids.push(dec.f("Content-Length", Value::U(cl), 0, 0, false, "B"));
                    }
                    summary = truncate_str(&first, 70);
                    root.push(dec.f_named("HTTP", Value::None, 0, 0, false, "", kids));
                }
                Mode::RawText => {
                    let s = String::from_utf8_lossy(d).trim_end().to_string();
                    summary = truncate_str(&s, 70);
                    root.push(dec.f("文本", Value::S(s), 0, d.len() as u16, false, ""));
                }
                Mode::RawHex => {
                    let hexs = d.iter().take(8).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                    summary = format!("{}B {}{}", d.len(), hexs, if d.len() > 8 { "…" } else { "" });
                    root.push(dec.f("数据", Value::Hex(d.to_vec()), 0, d.len() as u16, false, ""));
                }
            }
            frames.push(Frame {
                record: ri,
                off: off as u32,
                len: len as u32,
                t_ns: rec.t_ns,
                ts_src: rec.ts_src,
                dir: rec.dir,
                source: src,
                channel: ch,
                proto,
                seq: 0,
                gap_n: rec.gap_n,
                summary,
            });
            shift_fields(&mut root, off as i32);
            if tree_budget > 0 {
                tree_budget -= 1;
                decoded.push(Some(Arc::new(Decoded { proto, ok, root })));
            } else {
                decoded.push(None);
            }
        }

        // 事务超时:直到通道结束仍未等到响应的请求(轮询/重试场景的核心指标)
        if matches!(mode, Mode::ModbusRtu) {
            let mut pend: Vec<(u8, (u8, u16, u16, u64))> = pending_rtu.drain().collect();
            pend.sort_by_key(|(u, (_, _, _, t))| (*t, *u));
            for (unit, (f, s, q, t)) in pend {
                events.push(Event {
                    t_ns: t,
                    frame: None,
                    kind: EventKind::Timeout,
                    detail: format!(
                        "[{base_label}] unit{unit} {} [{}..{}] 无响应(日志结束仍未响应)",
                        modbus::func_name(f & 0x7F),
                        s,
                        s + q.saturating_sub(1)
                    ),
                    source: src,
                    channel: ch,
                rule: None,
                });
            }
        }
        if matches!(mode, Mode::ModbusTcp) {
            let mut pend: Vec<(u16, (u8, u16, u16, u64))> = pending_tcp.drain().collect();
            pend.sort_by_key(|(t_, (_, _, _, t))| (*t, *t_));
            for (tid, (f, s, q, t)) in pend {
                events.push(Event {
                    t_ns: t,
                    frame: None,
                    kind: EventKind::Timeout,
                    detail: format!(
                        "[{base_label}] tid={tid} {} [{}..{}] 无响应(日志结束仍未响应)",
                        modbus::func_name(f & 0x7F),
                        s,
                        s + q.saturating_sub(1)
                    ),
                    source: src,
                    channel: ch,
                rule: None,
                });
            }
        }
        if tree_budget == 0 {
            lazy_channels += 1;
        }
        // 流丢段事件
        for &ri in &ridxs {
            let rec = &records[ri as usize];
            if rec.gap_n > 0 {
                events.push(Event {
                    t_ns: rec.t_ns,
                    frame: None,
                    kind: EventKind::StreamDrop,
                    detail: format!("[{}] 抓包缺段:此处有字节未被捕获", base_label),
                    source: src,
                    channel: ch,
                rule: None,
                });
            }
        }

        let decoder = match &mode {
            Mode::ModbusRtu => Decoder::ModbusRtu,
            Mode::Dl645 => Decoder::Dl645,
            Mode::ModbusAscii => Decoder::ModbusAscii,
            Mode::ModbusTcp => Decoder::ModbusTcp,
            Mode::Mqtt => Decoder::Mqtt,
            Mode::Iec104 => Decoder::Iec104,
            Mode::S7 => Decoder::S7,
            Mode::Dnp3 => Decoder::Dnp3,
            Mode::Http => Decoder::Http,
            Mode::EtherCat => Decoder::EtherCat,
            Mode::Pn => Decoder::Pn,
            Mode::Can(_) => Decoder::Can,
            Mode::Custom(_) | Mode::CustomDgram(_) => Decoder::Custom,
            Mode::RawText => Decoder::RawText,
            Mode::RawHex | Mode::Arp => Decoder::RawHex,
        };
        // 通道时基 = 通道内最差等级(FR-2.2 如实标注)
        let chan_ts_rank = ridxs
            .iter()
            .map(|&ri| records[ri as usize].ts_src.rank())
            .min()
            .unwrap_or(1);
        channels.push(ChannelMeta {
            source: src,
            id: ch,
            label: format!("[{}] {}", src_names.get(src as usize).map(|s| s.as_str()).unwrap_or("?"), base_label),
            proto: mode.proto(),
            ts_src: TsSrc::from_rank(chan_ts_rank),
            decoder,
            spec_idx: match &mode { Mode::Custom(i) => Some(*i), _ => None },
            dbc_hit: if can_total > 0 { Some((can_dbc_hit, can_total)) } else { None },
        });
    }

    // ---- 全局按时间排序 ----
    let mut ord: Vec<usize> = (0..frames.len()).collect();
    ord.sort_by_key(|&i| (frames[i].t_ns, i));
    let mut sorted_frames: Vec<Frame> = ord.iter().map(|&i| frames[i].clone()).collect();
    let sorted_decoded: Vec<Option<Arc<Decoded>>> = ord.iter().map(|&i| decoded[i].clone()).collect();
    // 同通道内递增序号(meta.seq),从 1 开始
    {
        let mut counters: HashMap<(u16, u16), u32> = HashMap::new();
        for f in &mut sorted_frames {
            let c = counters.entry((f.source, f.channel)).or_insert(0);
            *c += 1;
            f.seq = *c;
        }
    }

    // ---- Δt 信号 + 间隔事件 ----
    let mut chan_pos: HashMap<(u16, u16), Vec<usize>> = HashMap::new();
    for (i, f) in sorted_frames.iter().enumerate() {
        chan_pos.entry((f.source, f.channel)).or_default().push(i);
    }
    for ((src, ch), idxs) in &chan_pos {
        let label = channels
            .iter()
            .find(|c| c.source == *src && c.id == *ch)
            .map(|c| c.label.clone())
            .unwrap_or_default();
        let mut dts: Vec<f64> = Vec::new();
        let mut prev: Option<u64> = None;
        for &i in idxs {
            let t = sorted_frames[i].t_ns;
            if let Some(p) = prev {
                let dt = t.saturating_sub(p) as f64 / 1e6;
                if dt > 0.0 {
                    dts.push(dt);
                }
                sigs.push(&format!("Δt·{label}"), "ms", t, dt, i as u32);
            }
            prev = Some(t);
        }
        if dts.is_empty() {
            continue;
        }
        dts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = dts[dts.len() / 2];
        // 自动阈值:P95 × 2(对"请求-响应"双峰间隔鲁棒,中位数会被短间隔拉低导致误报)
        let p95 = dts[((dts.len() as f64) * 0.95) as usize % dts.len()];
        let threshold = if cfg.gap_threshold_ms > 0.0 {
            cfg.gap_threshold_ms
        } else {
            (p95 * 2.0).max(1.0)
        };
        let mut prev = None;
        for &i in idxs {
            let t = sorted_frames[i].t_ns;
            if let Some(p) = prev {
                let dt_ms = t.saturating_sub(p) as f64 / 1e6;
                if dt_ms > threshold && t.saturating_sub(p) > 0 {
                    events.push(Event {
                        t_ns: t,
                        frame: Some(i as u32),
                        kind: EventKind::Gap,
                        detail: format!("[{label}] 间隔 {:.0}ms(中位 {:.1}ms)", dt_ms, median),
                        source: *src,
                        channel: *ch,
                    rule: None,
                    });
                }
            }
            prev = Some(t);
        }
    }

    events.sort_by_key(|e| e.t_ns);

    let name = src_names.join(" + ");
    let mut warnings = warnings;
    if lazy_channels > 0 {
        warnings.push(format!(
            "帧数超过 {} 的字段树预算,{} 个通道已启用按需解码(点击帧时才解码详情)",
            LAZY_TREE_LIMIT, lazy_channels
        ));
    }
    let mut ds = Dataset {
        name,
        epoch_ns: epoch,
        records,
        frames: sorted_frames,
        decoded: sorted_decoded,
        signals: sigs.into_series(),
        events,
        channels,
        strings,
        warnings,
        decode_ctx: DecodeCtx { custom: cfg.custom.clone(), map: cfg.map.clone(), map104: cfg.map104.clone(), dbc: cfg.dbc.clone() },
    };
    // 规则引擎(ADR-6):信号/超时/帧三类触发,产出契约语义事件
    if !cfg.rule_packs.is_empty() {
        crate::rules::run_rules(&cfg.rule_packs, &mut ds);
        ds.events.sort_by_key(|e| e.t_ns);
    }
    ds
}

/// 字段树存储预算:超过此帧数的通道不再保留解码树(内存大头),详情页按需解码
pub const LAZY_TREE_LIMIT: usize = 300_000;

/// FR-3.4:J1939 TP.BAM 重组会话(每个源地址同时最多一路广播传输)
struct TpBamSess {
    total: usize,
    pkts: usize,
    pgn: u32,
    buf: Vec<u8>,
    rcv: Vec<bool>,
    /// 参与重组的帧索引(证据链)
    frags: Vec<u32>,
}

/// Modbus 请求 PDU → (起始地址, 数量)。pdu 从功能码字节开始。
fn mb_req_hint(pdu: &[u8]) -> Option<(u16, u16)> {
    let f = *pdu.first()?;
    match f {
        1..=4 if pdu.len() >= 5 => Some((u16::from_be_bytes([pdu[1], pdu[2]]), u16::from_be_bytes([pdu[3], pdu[4]]))),
        5 | 6 => Some((u16::from_be_bytes([pdu[1], pdu[2]]), 1)),
        15 | 16 if pdu.len() >= 5 => Some((u16::from_be_bytes([pdu[1], pdu[2]]), u16::from_be_bytes([pdu[3], pdu[4]]))),
        _ => None,
    }
}

/// 按需解码单帧(大文件懒解码模式):从数据集自带的解码上下文重建字段树。
/// 不产生信号/事件(那些在整体分析时已生成)。
pub fn decode_one(ds: &Dataset, fi: usize) -> Option<Decoded> {
    let f = ds.frames.get(fi)?;
    let cm = ds.channels.iter().find(|c| c.source == f.source && c.id == f.channel)?;
    let rec = ds.records.get(f.record as usize)?;
    if f.off as usize + f.len as usize > rec.data.len() {
        return None;
    }
    let d = &rec.data[f.off as usize..(f.off + f.len) as usize];
    let ctx = &ds.decode_ctx;
    let mut strings = ds.strings.clone();
    let mut sigs = SigAcc::default();
    let mut ev: Vec<Event> = Vec::new();
    let mut dec = Dec {
        strings: &mut strings,
        sigs: &mut sigs,
        events: &mut ev,
        map: ctx.map.as_ref(),
        map104: ctx.map104.as_ref(),
        frame: fi as u32,
        t_ns: f.t_ns,
        source: f.source,
        channel: f.channel,
        chan_label: ds.channel_label(f.source, f.channel),
        fields: vec![],
    };
    let mut root = Vec::new();
    let mut ok = true;
    let proto = cm.proto;
    match cm.decoder {
        Decoder::ModbusRtu => {
            if d.len() >= 4 {
                let unit = d[0];
                let pdu = &d[1..d.len() - 2];
                ok = modbus::crc_ok(d);
                // 向后扫描同通道最近请求,恢复寄存器命名
                let mut hint = None;
                for j in (0..fi).rev().take(256) {
                    let pj = &ds.frames[j];
                    if pj.channel != f.channel || pj.source != f.source || pj.dir != Dir::Tx || pj.proto != Proto::ModbusRtu {
                        continue;
                    }
                    if let Some(rj) = ds.records.get(pj.record as usize) {
                        let dj = &rj.data[pj.off as usize..(pj.off + pj.len) as usize];
                        if dj.len() >= 4 && dj[0] == unit && modbus::crc_ok(dj) {
                            hint = mb_req_hint(&dj[1..dj.len() - 2]);
                            break;
                        }
                    }
                }
                let out = modbus::decode_pdu(&mut dec, f.dir, unit, pdu, 1, hint);
                root = out.root;
            }
        }
        Decoder::ModbusTcp => {
            if d.len() >= 8 {
                let tid = u16::from_be_bytes([d[0], d[1]]);
                let uid = d[6];
                let pdu = &d[7..];
                let mut hint = None;
                for j in (0..fi).rev().take(512) {
                    let pj = &ds.frames[j];
                    if pj.channel != f.channel || pj.source != f.source || pj.dir != Dir::Tx || pj.proto != Proto::ModbusTcp {
                        continue;
                    }
                    if let Some(rj) = ds.records.get(pj.record as usize) {
                        if pj.off as usize + pj.len as usize > rj.data.len() {
                            continue;
                        }
                        let dj = &rj.data[pj.off as usize..(pj.off + pj.len) as usize];
                        if dj.len() >= 12 && u16::from_be_bytes([dj[0], dj[1]]) == tid {
                            hint = mb_req_hint(&dj[7..]);
                            break;
                        }
                    }
                }
                let out = modbus::decode_pdu(&mut dec, f.dir, uid, pdu, 7, hint);
                root = out.root;
            }
        }
        Decoder::Dl645 => {
            dl645::decode(&mut dec, &rec.data);
            root = std::mem::take(&mut dec.fields);
        }
        Decoder::ModbusAscii => {
            if d.len() >= 4 {
                let unit = d[0];
                let pdu = &d[1..d.len() - 1];
                let mut hint = None;
                for j in (0..fi).rev().take(256) {
                    let pj = &ds.frames[j];
                    if pj.channel != f.channel || pj.source != f.source || pj.dir != Dir::Tx || pj.proto != Proto::ModbusAscii {
                        continue;
                    }
                    if let Some(rj) = ds.records.get(pj.record as usize) {
                        let dj = &rj.data[pj.off as usize..(pj.off + pj.len) as usize];
                        if dj.len() >= 4 && dj[0] == unit && modbus::lrc_frame_ok(dj) {
                            hint = mb_req_hint(&dj[1..dj.len() - 1]);
                            break;
                        }
                    }
                }
                let out = modbus::decode_pdu(&mut dec, f.dir, unit, pdu, 1, hint);
                root = out.root;
            }
        }
        Decoder::Http => {
            let text = String::from_utf8_lossy(d);
            let first = text.lines().next().unwrap_or("").to_string();
            let mut kids = vec![dec.f("首行", Value::S(first.clone()), 0, first.len() as u16, false, "")];
            for l in text.lines() {
                let ll = l.to_ascii_lowercase();
                if let Some(v) = ll.strip_prefix("content-length:") {
                    if let Ok(cl) = v.trim().parse::<u64>() {
                        kids.push(dec.f("Content-Length", Value::U(cl), 0, 0, false, "B"));
                    }
                }
                if l.trim().is_empty() {
                    break;
                }
            }
            root.push(dec.f_named("HTTP", Value::None, 0, 0, false, "", kids));
        }
        Decoder::Mqtt => {
            let (fs, _junk) = mqtt::scan(&rec.data);
            if let Some(&(_, _, ptype)) = fs.iter().find(|(o, _, _)| *o == f.off as usize) {
                mqtt::decode(&mut dec, &rec.data, f.off as usize, f.len as usize, ptype, false);
                root = std::mem::take(&mut dec.fields);
            }
        }
        Decoder::S7 => {
            // 懒解码(按需字段树):不产出配对事件(事件属主分析路径),仅还原字段
            let mut p = s7comm::S7Pairer::new();
            if let Some((fld, _text)) = s7comm::decode(&mut dec, &rec.data, f.off as usize, f.len as usize, &mut p, fi as u32, rec.t_ns) {
                root = std::mem::take(&mut dec.fields);
                root.push(fld);
            } else {
                root.push(dec.f("数据", Value::Hex(d.to_vec()), 0, d.len() as u16, false, ""));
            }
        }
        Decoder::Iec104 => {
            iec104::decode(&mut dec, &rec.data, f.off as usize, f.len as usize);
            root = std::mem::take(&mut dec.fields);
        }
        Decoder::Dnp3 => {
            dnp3::decode(&mut dec, &rec.data, f.off as usize, f.len as usize);
            root = std::mem::take(&mut dec.fields);
        }
        Decoder::EtherCat => {
            ethercat::decode(&mut dec, &rec.data);
            root = std::mem::take(&mut dec.fields);
        }
        Decoder::Pn => {
            profinet::decode(&mut dec, &rec.data);
            root = std::mem::take(&mut dec.fields);
        }
        Decoder::Can => {
            let raw_id = rec.can_id.unwrap_or(0);
            let ext = raw_id & 0x8000_0000 != 0;
            let id = raw_id & 0x1FFF_FFFF;
            let id_str = if ext { format!("0x{id:X}x") } else { format!("0x{id:X}") };
            let mut kids = vec![dec.f("数据", Value::Hex(d.to_vec()), 0, d.len() as u16, false, "")];
            if let Some(dbc) = &ctx.dbc {
                let key = crate::dbc::msg_key(id, ext);
                for (sig, v, label) in dbc::decode_message(dbc, key, d) {
                    let disp = match &label {
                        Some(l) => format!("{} = {} ({l})", sig.name, Value::F(v).display()),
                        None => format!("{} = {}", sig.name, Value::F(v).display()),
                    };
                    kids.push(dec.f(&disp, Value::F(v), 0, 0, true, &sig.unit));
                }
            }
            root.push(dec.f_named(&format!("ID {id_str}"), Value::U(id as u64), 0, 0, false, "", kids));
        }
        Decoder::Custom => {
            if let Some(i) = cm.spec_idx {
                if let Some(spec) = ctx.custom.get(i) {
                    root = custom::decode(d, spec, &mut strings);
                }
            }
        }
        Decoder::RawText => {
            let txt = String::from_utf8_lossy(d).trim_end().to_string();
            root.push(dec.f("文本", Value::S(txt), 0, d.len() as u16, false, ""));
        }
        Decoder::RawHex => {
            root.push(dec.f("数据", Value::Hex(d.to_vec()), 0, d.len() as u16, false, ""));
        }
    }
    shift_fields(&mut root, f.off as i32);
    Some(Decoded { proto, ok, root })
}

/// 递归收集自定义 DSL 的 plot 字段(含 bits 子位)为信号点
fn collect_custom_signals(fields: &[Field], st: &Strings, base: &str, out: &mut Vec<(String, String, f64)>) {
    for f in fields {
        let name = st.get(f.name).to_string();
        if f.plot {
            if let Some(v) = f.val.to_f64() {
                let unit = f.unit.map(|u| st.get(u).to_string()).unwrap_or_default();
                out.push((format!("{base}·{name}"), unit, v));
            }
        }
        if !f.children.is_empty() {
            collect_custom_signals(&f.children, st, base, out);
        }
    }
}

/// 把字段树的字节区间统一归一化为帧相对(摄入/解码时可能用记录相对偏移)
fn shift_fields(fields: &mut Vec<Field>, delta: i32) {
    if delta == 0 {
        return;
    }
    for f in fields {
        if f.len > 0 {
            f.start = (f.start as i32 - delta).max(0) as u16;
        }
        shift_fields(&mut f.children, delta);
    }
}

fn truncate_str(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}
