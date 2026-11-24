//! 实时接入(FR-S1):serbox 的 NDJSON 帧流(frame.schema.json,冻结契约)→ Record。
//!
//! 设计要点:
//! - 手写小型 JSON 字段提取器,只认 schema 定义的字段;坏行不 panic,计数进 warnings。
//!   (core 不为此引入任何新第三方依赖)
//! - 时间戳相对化:首个绝对墙钟级 ts(≥ TS_ABS_MIN_NS)作为会话基准,后续 t_ns = ts_ns − 基准,
//!   与 ingest 的 epoch 逻辑一致;设备上电单调 ts(小值)直接使用。相对化保证增量重建时
//!   analyze() 的全局最小值不变,旧帧时间轴稳定。
//! - 通道映射:bus.type=uart → Proto::Raw(走现有自定义/Modbus/文本启发式链);
//!   can/canfd → Proto::Can / Proto::CanFd(can_id 带 ext 位,bus 型号帧);
//!   ecat → Proto::EtherCat。can 与 canfd 属同一物理总线,合并为一个通道;
//!   通道 id 按 (总线族, ch) 首次出现顺序分配,避免 uart ch0 与 can ch0 撞号。
//! - 丢帧检测:meta.seq 同通道递增,跳号 → Record.gap(下游生成「流丢段」事件);meta.gap 同理。
//! - 三个数据源:TCP 客户端 / TCP 服务端 / 回放 .ndjson 文件;串口(COM)源在 app crate
//!   (serialport 依赖不进 core),复用本模块的 Pipeline/pump。

use super::SourceData;
use crate::model::{Dir, Proto, Record, TsSrc};
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// 单行字节上限(正常帧远小于此,防垃圾流撑爆内存)
pub const MAX_LINE_BYTES: usize = 8192;
/// ts 视为"绝对墙钟 epoch ns"的下限(与 pcap 判据一致:1e12 ns ≈ 1970-01-01 00:16:40)
pub const TS_ABS_MIN_NS: u64 = 1_000_000_000_000;
/// pump 单批回调的记录数
pub const BATCH: usize = 256;
/// warnings 上限(防刷屏,超出部分只计数)
const MAX_WARNS: usize = 200;

// ---------- 帧字段(与 frame.schema.json 逐字段对应) ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusKind {
    Uart,
    Can,
    CanFd,
    Ecat,
    /// TCP 字节流,一行一应用帧(IEC 104 等;ADR-0017)
    Tcp,
}

/// 一行 NDJSON 解析出的 BusFrame(schema 固定,手写提取)
#[derive(Debug, Clone)]
pub struct LiveFrame {
    pub ts_ns: u64,
    /// 时间戳来源等级(复用 model::TsSrc,与 ADR-5 时基标注一致)
    pub ts_src: TsSrc,
    pub bus_type: BusKind,
    pub ch: u32,
    pub alias: Option<String>,
    pub dir: Dir,
    pub id: u32,
    /// id_type == "ext"
    pub id_ext: bool,
    pub dlc: usize,
    pub data: Vec<u8>,
    pub seq: Option<u64>,
    pub meta_gap: Option<u64>,
}

impl Default for LiveFrame {
    fn default() -> Self {
        Self {
            ts_ns: 0,
            ts_src: TsSrc::Sw,
            bus_type: BusKind::Uart,
            ch: 0,
            alias: None,
            dir: Dir::Rx,
            id: 0,
            id_ext: false,
            dlc: 0,
            data: vec![],
            seq: None,
            meta_gap: None,
        }
    }
}

// ---------- 极小 JSON 提取器 ----------

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
        *i += 1;
    }
}

fn expect(b: &[u8], i: &mut usize, c: u8) -> Result<(), String> {
    skip_ws(b, i);
    if *i < b.len() && b[*i] == c {
        *i += 1;
        Ok(())
    } else {
        Err(format!("JSON 语法错误 @{}: 期望 '{}'", *i, c as char))
    }
}

/// 解析非负整数(所有 schema 数值字段均 ≥ 0;负数/溢出即坏行)
fn parse_u64(b: &[u8], i: &mut usize) -> Result<u64, String> {
    skip_ws(b, i);
    if *i < b.len() && b[*i] == b'-' {
        return Err("不支持负数".into());
    }
    let start = *i;
    let mut v: u64 = 0;
    while *i < b.len() && b[*i].is_ascii_digit() {
        v = v
            .checked_mul(10)
            .and_then(|x| x.checked_add((b[*i] - b'0') as u64))
            .ok_or_else(|| format!("数字溢出 @{}", *i))?;
        *i += 1;
    }
    if *i == start {
        return Err(format!("期望数字 @{}", *i));
    }
    Ok(v)
}

/// 解析字符串(支持常见转义与 \uXXXX 含代理对;多字节 UTF-8 以字节收集后宽松解码)
fn parse_string(b: &[u8], i: &mut usize) -> Result<String, String> {
    skip_ws(b, i);
    if *i >= b.len() || b[*i] != b'"' {
        return Err(format!("期望字符串 @{}", *i));
    }
    *i += 1;
    let mut out: Vec<u8> = vec![];
    while *i < b.len() {
        let c = b[*i];
        *i += 1;
        match c {
            b'"' => return Ok(String::from_utf8_lossy(&out).into_owned()),
            b'\\' => {
                if *i >= b.len() {
                    break;
                }
                let e = b[*i];
                *i += 1;
                match e {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'u' => {
                        let hi = parse_hex4(b, i)?;
                        let ch = if (0xD800..=0xDBFF).contains(&hi) {
                            // 高位代理:尝试配对低位
                            if *i + 2 <= b.len() && b[*i] == b'\\' && b[*i + 1] == b'u' {
                                let save = *i;
                                *i += 2;
                                match parse_hex4(b, i) {
                                    Ok(lo) if (0xDC00..=0xDFFF).contains(&lo) => {
                                        let c = 0x10000u32 + ((hi - 0xD800) as u32) * 0x400 + (lo - 0xDC00) as u32;
                                        char::from_u32(c).unwrap_or('\u{FFFD}')
                                    }
                                    _ => {
                                        *i = save;
                                        '\u{FFFD}'
                                    }
                                }
                            } else {
                                '\u{FFFD}'
                            }
                        } else {
                            char::from_u32(hi as u32).unwrap_or('\u{FFFD}')
                        };
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                    _ => return Err(format!("非法转义 \\{}", e as char)),
                }
            }
            _ => out.push(c),
        }
    }
    Err("字符串未闭合".into())
}

fn parse_hex4(b: &[u8], i: &mut usize) -> Result<u16, String> {
    if *i + 4 > b.len() {
        return Err("\\u 转义截断".into());
    }
    let mut v: u16 = 0;
    for k in 0..4 {
        let c = b[*i + k];
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return Err(format!("\\u 转义含非十六进制字符 @{}", *i + k)),
        };
        v = v * 16 + d as u16;
    }
    *i += 4;
    Ok(v)
}

/// 跳过一个任意 JSON 值(未知字段容错)
fn skip_value(b: &[u8], i: &mut usize) -> Result<(), String> {
    skip_ws(b, i);
    if *i >= b.len() {
        return Err("JSON 截断".into());
    }
    match b[*i] {
        b'"' => {
            parse_string(b, i)?;
        }
        b'{' | b'[' => {
            let mut depth = 0usize;
            while *i < b.len() {
                match b[*i] {
                    b'"' => {
                        parse_string(b, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            *i += 1;
                            return Ok(());
                        }
                    }
                    _ => {}
                }
                *i += 1;
            }
            return Err("JSON 截断".into());
        }
        b't' => expect_word(b, i, "true")?,
        b'f' => expect_word(b, i, "false")?,
        b'n' => expect_word(b, i, "null")?,
        _ => {
            // 数字(宽松吞掉,含负号/小数/指数)
            let start = *i;
            while *i < b.len()
                && (b[*i].is_ascii_digit() || matches!(b[*i], b'-' | b'+' | b'.' | b'e' | b'E'))
            {
                *i += 1;
            }
            if *i == start {
                return Err(format!("无法识别的值 @{}", *i));
            }
        }
    }
    Ok(())
}

fn expect_word(b: &[u8], i: &mut usize, w: &str) -> Result<(), String> {
    if b[*i..].starts_with(w.as_bytes()) {
        *i += w.len();
        Ok(())
    } else {
        Err(format!("JSON 语法错误 @{}: 期望 {w}", *i))
    }
}

/// 迭代 JSON 对象成员:返回下一个 key;None = 对象结束
fn next_key(b: &[u8], i: &mut usize, first: &mut bool) -> Result<Option<String>, String> {
    skip_ws(b, i);
    if *i >= b.len() {
        return Err("JSON 截断".into());
    }
    if b[*i] == b'}' {
        *i += 1;
        return Ok(None);
    }
    if !*first {
        if b[*i] != b',' {
            return Err(format!("JSON 语法错误 @{}: 期望 ','", *i));
        }
        *i += 1;
        skip_ws(b, i);
        if *i < b.len() && b[*i] == b'}' {
            *i += 1;
            return Ok(None); // 容忍尾逗号
        }
    }
    let key = parse_string(b, i)?;
    expect(b, i, b':')?;
    *first = false;
    Ok(Some(key))
}

/// data 数组:schema maxItems 64,字节 0..=255
fn parse_data(b: &[u8], i: &mut usize) -> Result<Vec<u8>, String> {
    expect(b, i, b'[')?;
    let mut out = vec![];
    skip_ws(b, i);
    if *i < b.len() && b[*i] == b']' {
        *i += 1;
        return Ok(out);
    }
    loop {
        let v = parse_u64(b, i)?;
        if v > 255 {
            return Err(format!("data 字节越界: {v}"));
        }
        out.push(v as u8);
        if out.len() > 4096 {
            return Err("data 数组过长".into());
        }
        skip_ws(b, i);
        if *i >= b.len() {
            return Err("JSON 截断".into());
        }
        match b[*i] {
            b',' => *i += 1,
            b']' => {
                *i += 1;
                // ADR-0007:运行时口径 512(冻结契约 64 由导出校验侧 patch;Modbus RTU ADU 最长 256,uart 字节流可更长)
                if out.len() > 512 {
                    return Err(format!("data 超过运行时上限 512 字节(实际 {})", out.len()));
                }
                return Ok(out);
            }
            _ => return Err(format!("JSON 语法错误 @{}: data 数组期望 ',' 或 ']'", *i)),
        }
    }
}

/// 解析一行 NDJSON BusFrame。任何不符合 schema 之处返回 Err(不 panic)。
pub fn parse_line(line: &str) -> Result<LiveFrame, String> {
    let s = line.trim();
    if s.is_empty() {
        return Err("空行".into());
    }
    let b = s.as_bytes();
    if b.len() > MAX_LINE_BYTES {
        return Err(format!("行超过 {MAX_LINE_BYTES} 字节上限"));
    }
    let mut i = 0usize;
    expect(b, &mut i, b'{')?;
    let mut f = LiveFrame::default();
    let mut h = HaveFields::default();
    let mut first = true;
    while let Some(key) = next_key(b, &mut i, &mut first)? {
        skip_ws(b, &mut i);
        match key.as_str() {
            "ts_ns" => {
                f.ts_ns = parse_u64(b, &mut i)?;
                h.ts = true;
            }
            "ts_src" => {
                let s = parse_string(b, &mut i)?;
                f.ts_src = match s.as_str() {
                    "sw" => TsSrc::Sw,
                    "hw" => TsSrc::Hw,
                    "mcu" => TsSrc::Mcu,
                    "wall" => TsSrc::Wall,
                    _ => return Err(format!("ts_src 非法: {s}")),
                };
                h.ts_src = true;
            }
            "bus" => {
                parse_bus(b, &mut i, &mut f, &mut h)?;
            }
            "dir" => {
                let s = parse_string(b, &mut i)?;
                f.dir = match s.as_str() {
                    "rx" => Dir::Rx,
                    "tx" => Dir::Tx,
                    _ => return Err(format!("dir 非法: {s}")),
                };
                h.dir = true;
            }
            "id" => {
                let v = parse_u64(b, &mut i)?;
                if v > 0x1FFF_FFFF {
                    return Err(format!("id 超出 29 位上限: {v}"));
                }
                f.id = v as u32;
                h.id = true;
            }
            "id_type" => {
                let s = parse_string(b, &mut i)?;
                f.id_ext = match s.as_str() {
                    "std" | "none" => false,
                    "ext" => true,
                    _ => return Err(format!("id_type 非法: {s}")),
                };
                h.id_type = true;
            }
            "dlc" => {
                let v = parse_u64(b, &mut i)?;
                // 同上:运行时 512 口径
                if v > 512 {
                    return Err(format!("dlc 超出运行时上限 512: {v}"));
                }
                f.dlc = v as usize;
                h.dlc = true;
            }
            "data" => {
                f.data = parse_data(b, &mut i)?;
                h.data = true;
            }
            "meta" => {
                parse_meta(b, &mut i, &mut f)?;
            }
            _ => skip_value(b, &mut i)?,
        }
    }
    let missing: Vec<&str> = [
        ("ts_ns", h.ts),
        ("ts_src", h.ts_src),
        ("bus.type", h.bus_type),
        ("bus.ch", h.ch),
        ("dir", h.dir),
        ("id", h.id),
        ("id_type", h.id_type),
        ("dlc", h.dlc),
        ("data", h.data),
    ]
    .iter()
    .filter(|(_, ok)| !ok)
    .map(|(k, _)| *k)
    .collect();
    if !missing.is_empty() {
        return Err(format!("缺少必填字段: {}", missing.join(", ")));
    }
    Ok(f)
}

fn parse_bus(b: &[u8], i: &mut usize, f: &mut LiveFrame, h: &mut HaveFields) -> Result<(), String> {
    expect(b, i, b'{')?;
    let mut first = true;
    while let Some(key) = next_key(b, i, &mut first)? {
        skip_ws(b, i);
        match key.as_str() {
            "type" => {
                let s = parse_string(b, i)?;
                f.bus_type = match s.as_str() {
                    "uart" => BusKind::Uart,
                    "can" => BusKind::Can,
                    "canfd" => BusKind::CanFd,
                    "ecat" => BusKind::Ecat,
                    "tcp" => BusKind::Tcp,
                    _ => return Err(format!("bus.type 非法: {s}")),
                };
                h.bus_type = true;
            }
            "ch" => {
                f.ch = parse_u64(b, i)? as u32;
                h.ch = true;
            }
            "alias" => {
                f.alias = Some(parse_string(b, i)?);
            }
            _ => skip_value(b, i)?,
        }
    }
    Ok(())
}

fn parse_meta(b: &[u8], i: &mut usize, f: &mut LiveFrame) -> Result<(), String> {
    expect(b, i, b'{')?;
    let mut first = true;
    while let Some(key) = next_key(b, i, &mut first)? {
        skip_ws(b, i);
        match key.as_str() {
            "seq" => f.seq = Some(parse_u64(b, i)?),
            "gap" => f.meta_gap = Some(parse_u64(b, i)?),
            _ => skip_value(b, i)?, // bitrate/err_flags 等:不承载业务语义,跳过
        }
    }
    Ok(())
}

#[derive(Default)]
struct HaveFields {
    ts: bool,
    ts_src: bool,
    bus_type: bool,
    ch: bool,
    dir: bool,
    id: bool,
    id_type: bool,
    dlc: bool,
    data: bool,
}

// ---------- 会话映射:LiveFrame → Record ----------

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LiveStats {
    pub ok: u64,
    pub bad: u64,
    pub gaps: u64,
}

/// 一次实时/回放会话的映射状态(时间基准、通道分配、丢帧检测)。
/// 通道 id 按 (总线族, ch) 首次出现顺序分配;can/canfd 同族合并。
pub struct LiveSession {
    base: Option<u64>,
    epoch: Option<u64>,
    alias_prefix: Option<String>,
    ch_map: HashMap<(u8, u32), u16>,
    labels: HashMap<u16, String>,
    last_seq: HashMap<u16, u64>,
    ok: u64,
    bad: u64,
    gaps: u64,
    warnings: Vec<String>,
    /// 坏行按原因去重计数(刷屏抑制)
    bad_keys: HashMap<String, u64>,
}

impl LiveSession {
    pub fn new(alias_prefix: Option<&str>) -> Self {
        Self {
            base: None,
            epoch: None,
            alias_prefix: alias_prefix
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            ch_map: HashMap::new(),
            labels: HashMap::new(),
            last_seq: HashMap::new(),
            ok: 0,
            bad: 0,
            gaps: 0,
            warnings: vec![],
            bad_keys: HashMap::new(),
        }
    }

    pub fn warn(&mut self, msg: String) {
        if self.warnings.len() < MAX_WARNS {
            self.warnings.push(msg);
        }
    }

    /// 同类坏行去重告警:首个样例保留,后续只累计条数(连续大量同因坏行不刷屏)
    pub fn warn_dedup(&mut self, key: &str, msg: String) {
        let n = {
            let e = self.bad_keys.entry(key.to_string()).or_insert(0u64);
            *e += 1;
            *e
        };
        if n == 1 {
            self.warn(msg);
        } else if n == 10 {
            self.warn(format!("{key}:同类坏行已累计 {n} 条(仅首次展示样例)"));
        }
    }

    /// 映射一帧。data 长度为准;dlc 不一致仅告警。
    pub fn map(&mut self, f: &LiveFrame) -> Record {
        self.ok += 1;
        // 1) 时间相对化:首个绝对墙钟 ts 作基准(记入 epoch);上电单调 ts 直接用
        let t_ns = match self.base {
            Some(b) => f.ts_ns.saturating_sub(b),
            None => {
                if f.ts_ns >= TS_ABS_MIN_NS {
                    // 绝对墙钟:以首帧为基准相对化,epoch 记录锚点
                    self.epoch = Some(f.ts_ns);
                    self.base = Some(f.ts_ns);
                    0
                } else {
                    // 上电单调 ts:原值即相对时间(相对设备上电),不设墙钟锚点
                    self.base = Some(0);
                    f.ts_ns
                }
            }
        };
        // 2) 通道:can/canfd 同族合并;其余各自成族;按出现顺序分配通道号
        let class = match f.bus_type {
            BusKind::Uart => 0u8,
            BusKind::Can | BusKind::CanFd => 1,
            BusKind::Ecat => 2,
            BusKind::Tcp => 3,
        };
        let key = (class, f.ch);
        let ch_id = if let Some(&c) = self.ch_map.get(&key) {
            c
        } else {
            let id = self.ch_map.len() as u16;
            self.ch_map.insert(key, id);
            let default = match f.bus_type {
                BusKind::Uart => format!("UART{}", f.ch),
                BusKind::Can | BusKind::CanFd => format!("CAN{}", f.ch),
                BusKind::Ecat => format!("ECAT{}", f.ch),
                BusKind::Tcp => format!("TCP{}", f.ch),
            };
            let label = match (&f.alias, &self.alias_prefix) {
                (Some(a), _) => a.clone(),
                (None, Some(p)) => format!("{p}·{default}"),
                (None, None) => default,
            };
            self.labels.insert(id, label);
            id
        };
        // 3) 协议 / 方向 / CAN id(扩展帧置 bit31,与 candump/asc 摄入一致)
        let proto = match f.bus_type {
            BusKind::Uart => Proto::Raw,
            BusKind::Can => Proto::Can,
            BusKind::CanFd => Proto::CanFd,
            BusKind::Ecat => Proto::EtherCat,
            BusKind::Tcp => Proto::Tcp,
        };
        let can_id = match f.bus_type {
            BusKind::Can | BusKind::CanFd => Some(f.id | ((f.id_ext as u32) << 31)),
            _ => None,
        };
        // 4) 丢帧检测:meta.seq 同通道递增;meta.gap 显式标注。缺失帧数记入 gap_n
        let mut gap_n: u32 = 0;
        if let Some(seq) = f.seq {
            if let Some(&last) = self.last_seq.get(&ch_id) {
                if seq > last + 1 {
                    gap_n = (seq - last - 1).min(u32::MAX as u64) as u32;
                    self.gaps += 1;
                    let label = self.labels.get(&ch_id).map(|s| s.as_str()).unwrap_or("?");
                    self.warn(format!("丢帧:通道[{label}] seq {last}→{seq}(约缺 {} 帧)", seq - last - 1));
                }
            }
            // 只单调前进,乱序/重传不回退
            self.last_seq.entry(ch_id).and_modify(|l| if seq > *l { *l = seq }).or_insert(seq);
        }
        if let Some(g) = f.meta_gap {
            if g > 0 && gap_n == 0 {
                gap_n = g.min(u32::MAX as u64) as u32;
                self.gaps += 1;
                let label = self.labels.get(&ch_id).map(|s| s.as_str()).unwrap_or("?");
                self.warn(format!("丢帧:通道[{label}] meta.gap={g}"));
            }
        }
        // 5) dlc 与 data 长度不一致 → 告警,data 为准
        if f.dlc != f.data.len() {
            self.warn(format!("dlc={} 与 data 长度 {} 不一致(以 data 为准)", f.dlc, f.data.len()));
        }
        Record {
            t_ns,
            ts_src: f.ts_src,
            dir: f.dir,
            source: 0,
            channel: ch_id,
            proto,
            gap_n,
            can_id,
            data: Arc::from(f.data.clone()),
        }
    }

    /// 解析并映射一行;坏行返回 None 并计数+告警
    pub fn map_line(&mut self, line: &str) -> Option<Record> {
        let t = line.trim();
        if t.is_empty() {
            return None;
        }
        match parse_line(t) {
            Ok(f) => Some(self.map(&f)),
            Err(e) => {
                self.bad += 1;
                let snippet: String = t.chars().take(48).collect();
                let key = e.split('(').next().unwrap_or(&e).to_string();
                self.warn_dedup(&key, format!("NDJSON 坏行({e}): {snippet}"));
                None
            }
        }
    }

    pub fn labels(&self) -> HashMap<u16, String> {
        self.labels.clone()
    }
    pub fn epoch_ns(&self) -> Option<u64> {
        self.epoch
    }
    pub fn stats(&self) -> LiveStats {
        LiveStats { ok: self.ok, bad: self.bad, gaps: self.gaps }
    }
    /// 取走自上次以来的新增告警(流式场景按批取走)
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    /// 一次性收口为 SourceData(离线打开录制文件用)
    pub fn into_source(self, name: &str, records: Vec<Record>) -> SourceData {
        let LiveSession { epoch, labels, ok, bad, mut warnings, .. } = self;
        if ok == 0 {
            warnings.insert(0, format!("NDJSON:未解析到有效帧(坏行 {bad})"));
        }
        SourceData { name: name.to_string(), records, epoch_ns: epoch, warnings, chan_labels: labels }
    }
}

// ---------- 行缓冲:字节流 → 完整行 ----------

/// 增量行拆分器(处理跨 chunk 的行、CRLF、超长垃圾行)
pub struct LineSplitter {
    buf: Vec<u8>,
    max_line: usize,
    skipping: bool,
}

impl Default for LineSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl LineSplitter {
    pub fn new() -> Self {
        Self { buf: vec![], max_line: MAX_LINE_BYTES, skipping: false }
    }

    /// 喂入字节,输出完整行(不含行尾);返回因超长被丢弃的行数
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<String>) -> u64 {
        let mut dropped = 0u64;
        for &c in chunk {
            if self.skipping {
                if c == b'\n' {
                    self.skipping = false;
                    self.buf.clear();
                }
                continue;
            }
            if c == b'\n' {
                let mut line = std::mem::take(&mut self.buf);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.len() > self.max_line {
                    dropped += 1;
                } else {
                    out.push(String::from_utf8_lossy(&line).into_owned());
                }
            } else {
                self.buf.push(c);
                if self.buf.len() > self.max_line {
                    // 无行尾的超长垃圾:丢弃到下一个换行为止
                    self.buf.clear();
                    self.skipping = true;
                    dropped += 1;
                }
            }
        }
        dropped
    }

    /// 流结束时取出残留(无换行结尾的最后一行)
    pub fn finish(&mut self, out: &mut Vec<String>) {
        if self.skipping {
            self.skipping = false;
            self.buf.clear();
            return;
        }
        let line = std::mem::take(&mut self.buf);
        if !line.is_empty() && line.len() <= self.max_line {
            out.push(String::from_utf8_lossy(&line).into_owned());
        }
    }
}

// ---------- 会话录制(FR-S2):原始 NDJSON 行追加落盘 ----------

pub struct Recorder {
    w: std::io::BufWriter<std::fs::File>,
    path: std::path::PathBuf,
    err: Option<String>,
    pub lines: u64,
}

impl Recorder {
    /// 追加模式打开(同一文件可多次会话续录)
    pub fn create(path: &std::path::Path) -> Result<Self, String> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("打开录制文件 {} 失败: {e}", path.display()))?;
        Ok(Self { w: std::io::BufWriter::new(f), path: path.into(), err: None, lines: 0 })
    }

    /// 记录一行原始 NDJSON(自动补行尾);写失败只记首次错误,不影响接收
    pub fn write_line(&mut self, line: &str) {
        self.lines += 1;
        if let Err(e) = std::io::Write::write_all(&mut self.w, line.as_bytes()) {
            if self.err.is_none() {
                self.err = Some(format!("{}: {e}", self.path.display()));
            }
        }
        if let Err(e) = std::io::Write::write_all(&mut self.w, b"\n") {
            if self.err.is_none() {
                self.err = Some(format!("{}: {e}", self.path.display()));
            }
        }
    }

    pub fn flush(&mut self) {
        let _ = std::io::Write::flush(&mut self.w);
    }
    pub fn err(&self) -> Option<&String> {
        self.err.as_ref()
    }
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

// ---------- 处理管线:原始行 → (录制) → 解析 → Record ----------

/// 实时/回放共用的行处理管线。串口源(app crate)与 TCP/文件源(core)共用。
pub struct Pipeline {
    pub sess: LiveSession,
    lines: LineSplitter,
    recorder: Option<Recorder>,
    /// 帧流转发 tee(可选):契约行同步推给外部消费方(TCP 转发器/脚本)。
    /// Arc+Mutex 槽位:App 可在运行中热插拔转发器,无需重连
    pub tee_slot: Option<Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>>,
}

impl Pipeline {
    pub fn set_tee_slot(&mut self, slot: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>) {
        self.tee_slot = Some(slot);
    }

    pub fn new(recorder: Option<Recorder>, alias_prefix: Option<&str>) -> Self {
        Self { sess: LiveSession::new(alias_prefix), lines: LineSplitter::new(), recorder, tee_slot: None }
    }

    /// 喂入一段字节(网络/串口/文件块)
    pub fn feed_bytes(&mut self, chunk: &[u8], out: &mut Vec<Record>) {
        let mut lines = vec![];
        let dropped = self.lines.feed(chunk, &mut lines);
        if dropped > 0 {
            self.sess.warn(format!("丢弃 {dropped} 条超长行(> {MAX_LINE_BYTES} 字节)"));
        }
        for l in lines {
            self.feed_line(&l, out);
        }
    }

    /// 处理一行:先录制原始行(保真,含坏行),再解析映射
    pub fn feed_line(&mut self, line: &str, out: &mut Vec<Record>) {
        let t = line.trim();
        if t.is_empty() {
            return;
        }
        if let Some(r) = &mut self.recorder {
            r.write_line(t);
        }
        // 帧流转发 tee:原始契约行推给消费方(慢/断开由消费方自弃,不阻塞采集)
        if let Some(slot) = &self.tee_slot {
            if let Ok(g) = slot.lock() {
                if let Some(sender) = g.as_ref() {
                    let _ = sender.send(t.to_string());
                }
            }
        }
        if let Some(rec) = self.sess.map_line(t) {
            out.push(rec);
        }
    }

    /// 流结束:取出残留行并冲刷录制文件
    pub fn flush_eof(&mut self, out: &mut Vec<Record>) {
        let mut lines = vec![];
        self.lines.finish(&mut lines);
        for l in lines {
            self.feed_line(&l, out);
        }
        if let Some(r) = &mut self.recorder {
            r.flush();
        }
    }

    pub fn recorder_error(&self) -> Option<String> {
        self.recorder.as_ref().and_then(|r| r.err().cloned())
    }
}

// ---------- 数据源读取 ----------

/// 通用读取泵:阻塞源(串口超时/文件)与非阻塞 TCP 均适用。
/// 每 BATCH 条记录或流结束时回调;stop 置位后尽快返回。
pub fn pump<R: std::io::Read + ?Sized>(
    rd: &mut R,
    stop: &AtomicBool,
    pipe: &mut Pipeline,
    mut on_batch: impl FnMut(Vec<Record>, &mut LiveSession),
) -> Result<(), String> {
    let mut buf = [0u8; 8192];
    let mut batch: Vec<Record> = Vec::new();
    let res = loop {
        if stop.load(Ordering::Relaxed) {
            break Ok(());
        }
        match rd.read(&mut buf) {
            Ok(0) => break Ok(()), // 对端关闭/文件读完
            Ok(n) => {
                pipe.feed_bytes(&buf[..n], &mut batch);
                if batch.len() >= BATCH {
                    on_batch(std::mem::take(&mut batch), &mut pipe.sess);
                }
                if let Some(e) = pipe.recorder_error() {
                    break Err(format!("录制写入失败: {e}"));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => break Err(format!("读取失败: {e}")),
        }
    };
    pipe.flush_eof(&mut batch);
    if !batch.is_empty() {
        on_batch(batch, &mut pipe.sess);
    }
    res
}

/// TCP 客户端:主动连接 serbox。connect 放短命线程执行,保证「断开」随时可取消。
pub fn open_tcp_client(addr: &str, stop: &AtomicBool) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| format!("地址 {addr} 无法解析: {e}"))?
        .next()
        .ok_or_else(|| format!("地址 {addr} 无法解析"))?;
    let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<TcpStream>>();
    std::thread::spawn(move || {
        let r = TcpStream::connect(sa).map(|s| {
            let _ = s.set_nonblocking(true); // 泵内轮询,保证 stop 响应
            s
        });
        let _ = tx.send(r);
    });
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err("连接已取消".into());
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => return Err(format!("连接 {addr} 失败: {e}")),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err("连接线程异常退出".into()),
        }
    }
}

/// TCP 服务端:监听等板子连入(取第一个连入的连接)。
pub fn open_tcp_server(addr: &str, stop: &AtomicBool) -> Result<TcpStream, String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("监听 {addr} 失败: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("设置非阻塞失败: {e}"))?;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err("等待连接已取消".into());
        }
        match listener.accept() {
            Ok((s, _peer)) => {
                let _ = s.set_nonblocking(true);
                return Ok(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("accept 失败: {e}")),
        }
    }
}

/// 回放 .ndjson 录制文件(与实时同一解析器);快速流式读取。
pub fn replay_file(
    path: &std::path::Path,
    stop: &AtomicBool,
    pipe: &mut Pipeline,
    on_batch: impl FnMut(Vec<Record>, &mut LiveSession),
) -> Result<(), String> {
    let f = std::fs::File::open(path).map_err(|e| format!("打开回放文件 {} 失败: {e}", path.display()))?;
    let mut rd = std::io::BufReader::with_capacity(64 * 1024, f);
    pump(&mut rd, stop, pipe, on_batch)
}

/// 回放 Vector .asc 抓包文件:ASC 行 → Record,按时间序分批喂给实时管线。
/// 与 .ndjson 回放同一 on_batch 通道,后续 DBC 解码/信号分组/录制完全复用。
pub fn replay_asc_file(
    path: &std::path::Path,
    stop: &AtomicBool,
    pipe: &mut Pipeline,
    mut on_batch: impl FnMut(Vec<Record>, &mut LiveSession),
) -> Result<(), String> {
    let (text, enc) = crate::textio::read_text(path)
        .map_err(|e| format!("打开回放文件 {} 失败: {e}", path.display()))?;
    if enc != "UTF-8" {
        pipe.sess.warn(format!("ASC 非 UTF-8(按 {enc} 解码)"));
    }
    let mut recs = vec![];
    let mut labels = std::collections::HashMap::new();
    let mut warns = vec![];
    super::asc::parse(&text, &mut recs, &mut labels, &mut warns);
    for (ch, l) in &labels {
        pipe.sess.labels.entry(*ch).or_insert_with(|| l.clone());
    }
    for w in warns {
        pipe.sess.warn(w);
    }
    if recs.is_empty() {
        pipe.sess.warn("ASC:未解析到有效帧".into());
    }
    let mut batch: Vec<Record> = Vec::new();
    for r in recs {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        batch.push(r);
        if batch.len() >= BATCH {
            on_batch(std::mem::take(&mut batch), &mut pipe.sess);
        }
    }
    if !batch.is_empty() {
        on_batch(batch, &mut pipe.sess);
    }
    Ok(())
}

/// 回放并入运行中的实时会话(模拟现场):把录制/抓包文件重映射到目标设备通道,
/// t_ns 重定基到并入点(t_offset)并按 speed 节流推送 —— 与既有实时数据同屏混流。
/// speed:1.0=原速(按录制节奏);>1 加速;0=极速(不等待,保留原始相对间隔)。
pub fn replay_into(
    path: &std::path::Path,
    target_ch: u16,
    speed: f64,
    t_offset_ns: u64,
    stop: &AtomicBool,
    pipe: &mut Pipeline,
    mut on_batch: impl FnMut(Vec<Record>, &mut LiveSession),
) -> Result<(), String> {
    let is_asc = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("asc"))
        .unwrap_or(false);
    // 1) 按时间序取回全部记录(ASC 走文本解析;NDJSON 逐行过同一解析器,坏行计数照常)
    let mut recs: Vec<Record> = vec![];
    if is_asc {
        let (text, enc) = crate::textio::read_text(path)
            .map_err(|e| format!("打开回放文件 {} 失败: {e}", path.display()))?;
        if enc != "UTF-8" {
            pipe.sess.warn(format!("ASC 非 UTF-8(按 {enc} 解码)"));
        }
        let mut labels = std::collections::HashMap::new();
        let mut warns = vec![];
        super::asc::parse(&text, &mut recs, &mut labels, &mut warns);
        for w in warns {
            pipe.sess.warn(w);
        }
        if recs.is_empty() {
            pipe.sess.warn("ASC:未解析到有效帧".into());
        }
    } else {
        let f = std::fs::File::open(path).map_err(|e| format!("打开回放文件 {} 失败: {e}", path.display()))?;
        let mut rd = std::io::BufReader::with_capacity(64 * 1024, f);
        let mut line = String::new();
        loop {
            line.clear();
            let n = std::io::BufRead::read_line(&mut rd, &mut line)
                .map_err(|e| format!("读取回放文件失败: {e}"))?;
            if n == 0 {
                break;
            }
            if let Some(r) = pipe.sess.map_line(&line) {
                recs.push(r);
            }
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
        }
    }
    if recs.is_empty() {
        return Ok(());
    }
    // 2) 重映射通道 + 重定基时间轴;原速/加速按调度点收割推送(兼容粗粒度 sleep)
    let t0 = recs[0].t_ns;
    let start = std::time::Instant::now();
    let paced = speed > 0.0;
    let sched_of = |t: u64| -> u64 {
        let rel = t.saturating_sub(t0);
        if paced { (rel as f64 / speed) as u64 } else { rel }
    };
    let mut batch: Vec<Record> = Vec::new();
    let mut i = 0usize;
    while i < recs.len() {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let now = start.elapsed().as_nanos() as u64;
        while i < recs.len() && (!paced || sched_of(recs[i].t_ns) <= now) {
            let mut r = recs[i].clone();
            r.t_ns = t_offset_ns + sched_of(recs[i].t_ns);
            r.channel = target_ch;
            batch.push(r);
            i += 1;
            if batch.len() >= BATCH {
                on_batch(std::mem::take(&mut batch), &mut pipe.sess);
            }
        }
        if paced && i < recs.len() {
            let next = sched_of(recs[i].t_ns);
            let remain = next.saturating_sub(start.elapsed().as_nanos() as u64);
            std::thread::sleep(Duration::from_nanos(remain.min(100_000_000)));
        }
    }
    if !batch.is_empty() {
        on_batch(batch, &mut pipe.sess);
    }
    Ok(())
}

/// 离线一次性打开 .ndjson 录制文件(供 read_file 按 .ndjson/.jsonl 扩展名路由)
pub fn load_ndjson_file(
    path: &std::path::Path,
) -> Result<SourceData, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "ndjson".into());
    let bytes = std::fs::read(path).map_err(|e| format!("{name}: {e}"))?;
    let mut pipe = Pipeline::new(None, None);
    let mut recs = vec![];
    pipe.feed_bytes(&bytes, &mut recs);
    pipe.flush_eof(&mut recs);
    let st = pipe.sess.stats();
    if st.ok == 0 && st.bad == 0 {
        pipe.sess.warn("文件中没有 NDJSON 行".into());
    }
    Ok(pipe.sess.into_source(&name, recs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_frame() {
        let f = parse_line(
            r#"{"ts_ns":1767225600000000000,"ts_src":"mcu","bus":{"type":"uart","ch":2,"alias":"电\"表"},"dir":"rx","id":0,"id_type":"none","dlc":3,"data":[1,2,3],"meta":{"seq":7},"extra":{"x":[1,2,{"y":"z"}],"bitrate":921600}}"#,
        )
        .unwrap();
        assert_eq!(f.ts_ns, 1767225600000000000);
        assert_eq!(f.ts_src, TsSrc::Mcu);
        assert_eq!(f.bus_type, BusKind::Uart);
        assert_eq!(f.ch, 2);
        assert_eq!(f.alias.as_deref(), Some("电\"表"));
        assert_eq!(f.dir, Dir::Rx);
        assert_eq!(f.dlc, 3);
        assert_eq!(f.data, vec![1, 2, 3]);
        assert_eq!(f.seq, Some(7));
    }

    #[test]
    fn parse_can_ext_and_fd() {
        let f = parse_line(
            r#"{"ts_ns":10,"ts_src":"hw","bus":{"type":"canfd","ch":0},"dir":"tx","id":536870911,"id_type":"ext","dlc":0,"data":[]}"#,
        )
        .unwrap();
        assert_eq!(f.bus_type, BusKind::CanFd);
        assert_eq!(f.ts_src, TsSrc::Hw);
        assert!(f.id_ext);
        assert_eq!(f.id, 0x1FFF_FFFF);
        assert!(f.data.is_empty());
    }

    #[test]
    fn bad_lines() {
        for line in [
            r#"{"ts_ns":1}"#,                                        // 缺必填
            r#"{"ts_src":"mcu","bus":{"type":"can","ch":0},"dir":"rx","id":1,"id_type":"std","dlc":0,"data":[]}"#, // 缺 ts_ns
            r#"{"ts_ns":1,"ts_src":"bad","bus":{"type":"can","ch":0},"dir":"rx","id":1,"id_type":"std","dlc":0,"data":[]}"#, // 枚举非法
            r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"can","ch":0},"dir":"maybe","id":1,"id_type":"std","dlc":0,"data":[]}"#,
            r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"wifi","ch":0},"dir":"rx","id":1,"id_type":"std","dlc":0,"data":[]}"#,
            r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"can","ch":0},"dir":"rx","id":536870912,"id_type":"std","dlc":0,"data":[]}"#, // id 超 29bit
            r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"can","ch":0},"dir":"rx","id":1,"id_type":"std","dlc":0,"data":[256]}"#, // 字节越界
            r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"can","ch":-1},"dir":"rx","id":1,"id_type":"std","dlc":0,"data":[]}"#,   // 负数
            r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"can","ch":0},"dir":"rx","id":1,"id_type":"std","dlc":0,"data":["#, // 截断
            r#"not json"#,
            r#"{"ts_ns":1,"ts_src":"mcu""#, // 截断
        ] {
            assert!(parse_line(line).is_err(), "应判坏行: {line}");
        }
    }

    #[test]
    fn relativize_and_gap() {
        let mut s = LiveSession::new(None);
        let l1 = r#"{"ts_ns":500,"ts_src":"mcu","bus":{"type":"can","ch":0},"dir":"rx","id":1,"id_type":"std","dlc":1,"data":[1],"meta":{"seq":1}}"#;
        let l2 = r#"{"ts_ns":900,"ts_src":"mcu","bus":{"type":"canfd","ch":0},"dir":"rx","id":2,"id_type":"std","dlc":1,"data":[2],"meta":{"seq":3}}"#;
        let r1 = s.map_line(l1).unwrap();
        let r2 = s.map_line(l2).unwrap();
        // 上电单调 ts(< 1e12):不设墙钟 epoch,原值即相对时间
        assert_eq!(s.epoch_ns(), None);
        assert_eq!(r1.t_ns, 500);
        assert_eq!(r2.t_ns, 900);
        assert_eq!(r1.ts_src, TsSrc::Mcu);
        // can/canfd 同 ch 合并通道;seq 1→3 → 丢帧
        assert_eq!(r1.channel, r2.channel);
        assert_eq!(r1.proto, Proto::Can);
        assert_eq!(r2.proto, Proto::CanFd);
        assert_eq!(r1.gap_n, 0);
        assert_eq!(r2.gap_n, 1);
        assert_eq!(s.stats().gaps, 1);
        // 墙钟 ts:以首帧为基准相对化 + epoch
        let mut s2 = LiveSession::new(None);
        let a = s2
            .map_line(r#"{"ts_ns":1767225600000000000,"ts_src":"wall","bus":{"type":"uart","ch":0},"dir":"rx","id":0,"id_type":"none","dlc":1,"data":[9]}"#)
            .unwrap();
        let b = s2
            .map_line(r#"{"ts_ns":1767225600500000000,"ts_src":"wall","bus":{"type":"uart","ch":0},"dir":"rx","id":0,"id_type":"none","dlc":1,"data":[9]}"#)
            .unwrap();
        assert_eq!(a.t_ns, 0);
        assert_eq!(b.t_ns, 500_000_000);
        assert_eq!(s2.epoch_ns(), Some(1767225600000000000));
    }

    #[test]
    fn meta_gap_and_dlc_mismatch() {
        let mut s = LiveSession::new(None);
        let r = s
            .map_line(r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"uart","ch":0},"dir":"rx","id":0,"id_type":"none","dlc":5,"data":[1,2],"meta":{"gap":2}}"#)
            .unwrap();
        assert_eq!(r.gap_n, 2, "meta.gap>0 应标注 gap_n");
        assert_eq!(r.data.len(), 2, "data 长度为准");
        assert!(s.warnings.iter().any(|w| w.contains("dlc")), "warnings={:?}", s.warnings);
        assert_eq!(s.stats().gaps, 1);
    }

    #[test]
    fn alias_prefix_used_when_frame_has_none() {
        let mut s = LiveSession::new(Some("serbox"));
        s.map_line(r#"{"ts_ns":1,"ts_src":"mcu","bus":{"type":"uart","ch":0,"alias":"485"},"dir":"rx","id":0,"id_type":"none","dlc":1,"data":[1]}"#).unwrap();
        s.map_line(r#"{"ts_ns":2,"ts_src":"mcu","bus":{"type":"uart","ch":1},"dir":"rx","id":0,"id_type":"none","dlc":1,"data":[1]}"#).unwrap();
        let labels = s.labels();
        assert_eq!(labels.get(&0).unwrap(), "485", "帧内 alias 优先");
        assert_eq!(labels.get(&1).unwrap(), "serbox·UART1", "无 alias 用前缀·默认名");
    }

    #[test]
    fn line_splitter_chunks() {
        let mut sp = LineSplitter::new();
        let mut out = vec![];
        let b = b"AA\r\nBB\nCC"; // CC 无行尾 → finish 取出
        let mut dropped = 0;
        dropped += sp.feed(&b[..2], &mut out);
        dropped += sp.feed(&b[2..5], &mut out);
        dropped += sp.feed(&b[5..], &mut out);
        sp.finish(&mut out);
        assert_eq!(dropped, 0);
        assert_eq!(out, vec!["AA".to_string(), "BB".to_string(), "CC".to_string()]);
        // 超长行丢弃,不影响后续行
        let mut sp2 = LineSplitter::new();
        let mut out2 = vec![];
        let big = "x".repeat(MAX_LINE_BYTES + 10);
        let d = sp2.feed(format!("{big}\nOK\n").as_bytes(), &mut out2);
        assert_eq!(d, 1);
        assert_eq!(out2, vec!["OK".to_string()]);
    }

    #[test]
    fn recorder_roundtrip() {
        let dir = std::env::temp_dir().join("iotprobe_recorder_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.ndjson");
        let _ = std::fs::remove_file(&path);
        {
            let mut r = Recorder::create(&path).unwrap();
            r.write_line("{\"a\":1}");
            r.write_line("bad line");
            r.flush();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'), "自动补行尾");
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod replay_asc_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn replay_asc_feeds_pipeline() {
        let dir = std::env::temp_dir().join("iotprobe_replay_asc");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.asc");
        std::fs::write(&p, "\
date Mon Nov 16 17:51:00 2026
base hex  timestamps absolute
Begin Triggerblock
 0.000000 2  18F520EFx       Rx   d 8 04 00 01 00 00 00 00 00
 0.007153 2  18FF2DF3x       Rx   d 8 01 00 00 F8 00 4A B2 00
 0.027472 2  18FF8283x       Rx   d 8 04 00 00 00 00 00 00 00
End Triggerblock
").unwrap();
        let stop = AtomicBool::new(false);
        let mut pipe = Pipeline::new(None, None);
        let mut batches = 0usize;
        let mut total = 0usize;
        replay_asc_file(&p, &stop, &mut pipe, |b, _sess| {
            batches += 1;
            total += b.len();
        })
        .unwrap();
        assert_eq!(total, 3, "3 条 CAN 帧");
        assert!(batches >= 1);
        let st = pipe.sess.stats();
        assert_eq!(st.ok, 0, "ASC 回放直接喂 Record,不走 NDJSON 计数");
    }

    #[test]
    fn replay_into_rewrites_channel_and_rebases() {
        // 并入语义:通道重写为目标;t_ns 重定基到并入点;极速保留原始相对间隔
        let dir = std::env::temp_dir().join("iotprobe_replay_into");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.ndjson");
        let base: u64 = 1_700_000_000_000_000_000;
        let mut text = String::new();
        for i in 0..3u64 {
            text.push_str(&format!(
                "{{\"ts_ns\":{},\"ts_src\":\"sw\",\"bus\":{{\"type\":\"uart\",\"ch\":1}},\"dir\":\"rx\",\"id\":0,\"id_type\":\"none\",\"dlc\":2,\"data\":[1,{}]}}\n",
                base + i * 100_000_000,
                i
            ));
        }
        std::fs::write(&p, text).unwrap();
        let stop = AtomicBool::new(false);
        let mut pipe = Pipeline::new(None, None);
        let mut out: Vec<Record> = vec![];
        replay_into(&p, 7, 0.0, 5_000, &stop, &mut pipe, |b, _s| out.extend(b)).unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|r| r.channel == 7), "通道应重写为目标 7");
        assert_eq!(out[0].t_ns, 5_000, "首帧钉在并入点");
        assert_eq!(out[1].t_ns - out[0].t_ns, 100_000_000, "极速保留原始间隔");
        assert_eq!(out[2].t_ns - out[0].t_ns, 200_000_000);
    }

    #[test]
    fn replay_into_asc_uses_same_remap() {
        // ASC 抓包同样支持并入:通道重写 + 保留相对时序
        let dir = std::env::temp_dir().join("iotprobe_replay_into_asc");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.asc");
        std::fs::write(&p, "date Mon Nov 16 17:51:00 2026\nbase hex  timestamps absolute\nBegin Triggerblock\n 0.000000 2  18F520EFx       Rx   d 8 04 00 01 00 00 00 00 00\n 0.007153 2  18FF2DF3x       Rx   d 8 01 00 00 F8 00 4A B2 00\n 0.027472 2  18FF8283x       Rx   d 8 04 00 00 00 00 00 00 00\nEnd Triggerblock\n").unwrap();
        let stop = AtomicBool::new(false);
        let mut pipe = Pipeline::new(None, None);
        let mut out: Vec<Record> = vec![];
        replay_into(&p, 3, 0.0, 0, &stop, &mut pipe, |b, _s| out.extend(b)).unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|r| r.channel == 3), "ASC 通道应重写为目标 3");
        assert!(out[1].t_ns > out[0].t_ns, "保留相对时序");
    }
}

#[cfg(test)]
mod uart_cap_tests {
    use super::*;

    #[test]
    fn uart_data_up_to_512_accepted_65_plus_rejected_above() {
        // 回归:模拟器 PCS-2号 33 寄存器读响应 = 71B,曾被冻结契约 64 卡死(ADR-0007 运行时口径 512)
        // frame.schema.json 行(app 侧 live_frame_to_jsonl 的产物形态)手写等价:core 不依赖 app
        let mk = |dlc: usize| -> String {
            let data = vec![0u8; dlc];
            let hexs = data.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
            format!(
                r#"{{"ts_ns":1,"ts_src":"sw","bus":{{"type":"uart","ch":2}},"dir":"rx","id":0,"id_type":"none","dlc":{dlc},"data":[{hexs}]}}"#
            )
        };
        assert!(parse_line(&mk(71)).is_ok(), "71B uart 帧必须可解析");
        assert!(parse_line(&mk(512)).is_ok(), "512 边界放行");
        assert!(parse_line(&mk(513)).is_err(), "513 拒绝");
        // 坏行去重:连续同因坏行只出 1 条样例告警 + 第 10 条汇总
        let mut sess = LiveSession::new(None);
        for _ in 0..12 {
            sess.map_line("{\"data\":[");
        }
        let dedup_warnings: Vec<&String> = sess.warnings.iter().filter(|w| w.contains("同类坏行")).collect();
        assert!(sess.warnings.iter().any(|w| w.contains("NDJSON 坏行")), "首条样例必须有");
        assert_eq!(dedup_warnings.len(), 1, "第 10 条汇总只出现一次");
    }
}
