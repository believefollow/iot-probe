//! Modbus RTU / TCP 解析。
//! RTU 定界:函数码推断长度 + CRC16 验证 + 方向信息;未定界的字节会被统计并产生事件。
//! TCP:MBAP 头逐帧解析;请求/响应按事务 ID 配对,寄存器值自动进入时序曲线。

use super::Dec;
use crate::crc::crc16_modbus;
use crate::model::{Dir, EventKind, Field, Value};

// ---------- 寄存器映射 ----------

#[derive(Clone, Debug, serde::Deserialize)]
pub struct RegMeta {
    pub addr: u16,
    pub name: String,
    #[serde(default = "one")]
    pub scale: f64,
    #[serde(default)]
    pub offset: f64,
    #[serde(default)]
    pub unit: String,
    /// 占用寄存器数:1=16bit, 2=32bit(FR-3.2)
    #[serde(default = "d1")]
    pub width: u8,
    /// 字节序:16bit=AB/BA;32bit=ABCD/BADC/CDAB/DCBA。缺省 AB/ABCD(Modbus 标准大端)
    #[serde(default)]
    pub byte_order: String,
    /// 有符号解释
    #[serde(default)]
    pub signed: bool,
    /// 枚举表:raw 整数值 → 显示名(FR-3.3)
    #[serde(default)]
    pub enums: std::collections::BTreeMap<String, String>,
}
fn one() -> f64 {
    1.0
}
fn d1() -> u8 {
    1
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct ModbusMap {
    pub regs: Vec<RegMeta>,
}

impl ModbusMap {
    fn meta(&self, addr: u16) -> Option<&RegMeta> {
        self.regs.iter().find(|r| r.addr == addr)
    }
}

fn reg_label(map: Option<&ModbusMap>, addr: u16, func: u8) -> String {
    if let Some(m) = map {
        if let Some(r) = m.meta(addr) {
            return r.name.clone();
        }
    }
    match func {
        1 | 5 | 15 => format!("CO{addr}"),
        2 => format!("DI{addr}"),
        3 | 6 | 16 => format!("HR{addr}"),
        4 => format!("IR{addr}"),
        _ => format!("@{addr}"),
    }
}

pub fn func_name(f: u8) -> &'static str {
    match f {
        1 => "读线圈",
        2 => "读离散输入",
        3 => "读保持寄存器",
        4 => "读输入寄存器",
        5 => "写单线圈",
        6 => "写单寄存器",
        7 => "读异常状态",
        11 => "读通讯事件计数",
        15 => "写多线圈",
        16 => "写多寄存器",
        17 => "报告从机ID",
        _ => "未知",
    }
}

pub fn exc_name(c: u8) -> &'static str {
    match c {
        1 => "非法功能",
        2 => "非法数据地址",
        3 => "非法数据值",
        4 => "从机设备故障",
        5 => "确认",
        6 => "从机忙",
        8 => "存储奇偶错误",
        10 => "网关不可达",
        11 => "网关无响应",
        _ => "未知",
    }
}

// ---------- RTU ----------

pub fn crc_ok(frame: &[u8]) -> bool {
    if frame.len() < 4 {
        return false;
    }
    let n = frame.len();
    crc16_modbus(&frame[..n - 2]) == u16::from_le_bytes([frame[n - 2], frame[n - 1]])
}

fn candidate_lens(data: &[u8], i: usize, f: u8, dir: Dir) -> Vec<usize> {
    if f & 0x80 != 0 {
        if (f & 0x7F) <= 0x11 {
            return vec![5];
        }
        return vec![];
    }
    match f {
        1..=4 => {
            let resp = if i + 3 <= data.len() { 3 + data[i + 2] as usize + 2 } else { usize::MAX };
            match dir {
                Dir::Rx => vec![resp],
                Dir::Tx => vec![8],
                _ => vec![resp, 8],
            }
        }
        5 | 6 => vec![8],
        15 | 16 => {
            let req = if i + 7 <= data.len() { 9 + data[i + 6] as usize } else { usize::MAX };
            match dir {
                Dir::Tx => vec![req],
                Dir::Rx => vec![8],
                _ => vec![8, req],
            }
        }
        11 => match dir {
            Dir::Tx => vec![4],
            _ => vec![8, 4],
        },
        17 => match dir {
            Dir::Tx => vec![4],
            _ => vec![8, 4],
        },
        _ => vec![],
    }
}

/// 在一段字节流中扫描 RTU 帧,返回 (偏移, 长度)
pub fn scan(data: &[u8], dir: Dir) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let addr = data[i];
        if addr > 247 {
            i += 1;
            continue;
        }
        let f = data[i + 1];
        let mut matched = false;
        for l in candidate_lens(data, i, f, dir) {
            if i + l <= data.len() && crc_ok(&data[i..i + l]) {
                out.push((i, l));
                i += l;
                matched = true;
                break;
            }
        }
        if !matched {
            i += 1;
        }
    }
    out
}

// ---------- TCP ----------

pub struct TcpFrm {
    pub off: usize,
    pub len: usize,
    pub tid: u16,
    pub uid: u8,
    pub func: u8,
}

/// 解析一段 TCP 流数据中的完整 Modbus TCP 报文
pub fn parse_tcp(data: &[u8]) -> Vec<TcpFrm> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let tid = u16::from_be_bytes([data[i], data[i + 1]]);
        let pid = u16::from_be_bytes([data[i + 2], data[i + 3]]);
        let len = u16::from_be_bytes([data[i + 4], data[i + 5]]) as usize;
        if pid != 0 || len < 2 || len > 254 {
            break; // 失步
        }
        let total = 6 + len;
        if i + total > data.len() {
            break; // 半包
        }
        out.push(TcpFrm { off: i, len: total, tid, uid: data[i + 6], func: data[i + 7] });
        i += total;
    }
    out
}

// ---------- PDU 解码 ----------

pub struct PduOut {
    pub root: Vec<Field>,
    pub summary: String,
    /// 请求信息 (start, qty),用于配对
    pub req: Option<(u16, u16)>,
    pub exception: Option<u8>,
}

/// 解码 Modbus PDU(不含地址/MBAP)。base: func 字节在 record 数据中的偏移。
/// hint: 配对到的 (起始地址, 数量)。
pub fn decode_pdu(
    dec: &mut Dec,
    dir: Dir,
    unit: u8,
    pdu: &[u8],
    base: usize,
    hint: Option<(u16, u16)>,
) -> PduOut {
    let mut root = Vec::new();
    if pdu.is_empty() {
        return PduOut { root, summary: "空PDU".into(), req: None, exception: None };
    }
    let f = pdu[0];
    let is_exc = f & 0x80 != 0;
    root.push(dec.f("功能码", Value::U(f as u64), base, 1, false, ""));
    let mut req = None;
    let mut exception = None;
    let is_req = matches!(dir, Dir::Tx);

    macro_rules! u16be {
        ($p:expr, $k:expr) => {
            u16::from_be_bytes([$p[$k], $p[$k + 1]])
        };
    }

    let summary;
    if is_exc {
        let code = if pdu.len() > 1 { pdu[1] } else { 0 };
        exception = Some(code);
        root.push(dec.f("异常码", Value::U(code as u64), base + 1, 1, false, ""));
        root.push(dec.f("含义", Value::S(exc_name(code).into()), 0, 0, false, ""));
        summary = format!("EXC {} ({})", code, exc_name(code));
        let det = format!("unit{unit} {} 异常码{} ({})", func_name(f & 0x7F), code, exc_name(code));
        dec.ev(EventKind::Exception, det, Some(dec.frame));
        return PduOut { root, summary, req, exception };
    }

    match f {
        1..=4 => {
            if is_req {
                let start = if pdu.len() >= 3 { u16be!(pdu, 1) } else { 0 };
                let qty = if pdu.len() >= 5 { u16be!(pdu, 3) } else { 0 };
                req = Some((start, qty));
                root.push(dec.f("起始地址", Value::U(start as u64), base + 1, 2, false, ""));
                root.push(dec.f("数量", Value::U(qty as u64), base + 3, 2, false, ""));
                summary = format!("{} {}[{}..{}] unit{}", func_name(f), abbr(f), start, start + qty.saturating_sub(1), unit);
            } else {
                let bc = if pdu.len() > 1 { pdu[1] as usize } else { 0 };
                root.push(dec.f("字节数", Value::U(bc as u64), base + 1, 1, false, ""));
                let hint_start = hint.map(|h| h.0).unwrap_or(0);
                if f <= 2 {
                    // 位量:逐字节展开
                    for k in 0..bc {
                        if 2 + k >= pdu.len() {
                            break;
                        }
                        let byte = pdu[2 + k];
                        let at = base + 2 + k;
                        for bit in 0..8 {
                            let addr = hint_start + (k * 8 + bit) as u16;
                            let v = (byte >> bit) & 1 == 1;
                            root.push(dec.f(&format!("{}={}", reg_label(dec.map, addr, f), if v { "ON" } else { "OFF" }), Value::B(v), at, 1, false, ""));
                        }
                    }
                } else {
                    // 寄存器:按映射分组解码(16bit AB/BA、32bit ABCD/BADC/CDAB/DCBA、枚举)
                    let n = bc / 2;
                    let mut regs: Vec<u16> = Vec::with_capacity(n);
                    for k in 0..n {
                        if 2 + k * 2 + 1 < pdu.len() {
                            regs.push(u16be!(pdu, 2 + k * 2));
                        }
                    }
                    let map_ref = dec.map;
                    let mut k = 0usize;
                    while k < regs.len() {
                        let addr = hint_start + k as u16;
                        let at = base + 2 + k * 2;
                        if let Some(m) = map_ref.and_then(|m| m.meta(addr)) {
                            if let Some((w, name, phys, unit_s, label, _raw)) = decode_reg_group(m, &regs[k..]) {
                                let disp = match &label {
                                    Some(l) => format!("{name} = {} [{l}]", crate::model::Value::F(phys).display()),
                                    None => format!("{name} = {}", crate::model::Value::F(phys).display()),
                                };
                                root.push(dec.f(&disp, Value::F(phys), at, (w * 2) as u16, true, &unit_s));
                                dec.sig(&format!("unit{unit}·{name}"), &unit_s, phys);
                                k += w;
                                continue;
                            }
                        }
                        // 未命中映射:通用单寄存器
                        let raw = regs[k];
                        let (val, _scaled) = scale_reg(dec.map, addr, f, raw);
                        let (name, unit_s) = reg_meta(dec.map, addr, f);
                        root.push(dec.f(&format!("{} = {}", name, crate::model::Value::F(val).display()), Value::F(val), at, 2, true, &unit_s));
                        dec.sig(&format!("unit{unit}·{name}"), &unit_s, val);
                        k += 1;
                    }
                }
                summary = format!("RESP {} {}B unit{}", func_name(f), bc, unit);
            }
        }
        5 | 6 => {
            let addr = if pdu.len() >= 3 { u16be!(pdu, 1) } else { 0 };
            let val = if pdu.len() >= 5 { u16be!(pdu, 3) } else { 0 };
            req = Some((addr, 1));
            root.push(dec.f("地址", Value::U(addr as u64), base + 1, 2, false, ""));
            let (name, unit_s) = reg_meta(dec.map, addr, f);
            let (v, _) = scale_reg(dec.map, addr, f, val);
            root.push(dec.f(&format!("{}= {}", name, crate::model::Value::F(v).display()), Value::F(v), base + 3, 2, true, &unit_s));
            if is_req {
                dec.sig(&format!("unit{}·{}(写)", unit, name), &unit_s, v);
            }
            summary = format!("{} {}={} unit{}", func_name(f), name, val, unit);
        }
        15 | 16 => {
            if is_req {
                let addr = if pdu.len() >= 3 { u16be!(pdu, 1) } else { 0 };
                let qty = if pdu.len() >= 5 { u16be!(pdu, 3) } else { 0 };
                let bc = if pdu.len() > 5 { pdu[5] as usize } else { 0 };
                req = Some((addr, qty));
                root.push(dec.f("起始地址", Value::U(addr as u64), base + 1, 2, false, ""));
                root.push(dec.f("数量", Value::U(qty as u64), base + 3, 2, false, ""));
                root.push(dec.f("字节数", Value::U(bc as u64), base + 5, 1, false, ""));
                if bc > 0 && pdu.len() > 6 {
                    root.push(dec.f("数据", Value::Hex(pdu[6..(6 + bc).min(pdu.len())].to_vec()), base + 6, bc as u16, false, ""));
                }
                if f == 16 {
                    // 写寄存器:按映射分组入时序
                    let n = (qty as usize).min(bc / 2);
                    let mut regs: Vec<u16> = Vec::with_capacity(n);
                    for k in 0..n {
                        if 6 + k * 2 + 1 < pdu.len() {
                            regs.push(u16be!(pdu, 6 + k * 2));
                        }
                    }
                    let map_ref = dec.map;
                    let mut k = 0usize;
                    while k < regs.len() {
                        let a = addr + k as u16;
                        if let Some(m) = map_ref.and_then(|m| m.meta(a)) {
                            if let Some((w, name, phys, unit_s, _label, _raw)) = decode_reg_group(m, &regs[k..]) {
                                dec.sig(&format!("unit{unit}·{name}(写)"), &unit_s, phys);
                                k += w;
                                continue;
                            }
                        }
                        let raw = regs[k];
                        let (v, _) = scale_reg(dec.map, a, f, raw);
                        let (name, unit_s) = reg_meta(dec.map, a, f);
                        dec.sig(&format!("unit{unit}·{name}(写)"), &unit_s, v);
                        k += 1;
                    }
                }
                summary = format!("{} {}[{}..{}] x{} unit{}", func_name(f), abbr(f), addr, addr + qty.saturating_sub(1), qty, unit);
            } else {
                let addr = if pdu.len() >= 3 { u16be!(pdu, 1) } else { 0 };
                let qty = if pdu.len() >= 5 { u16be!(pdu, 3) } else { 0 };
                root.push(dec.f("起始地址", Value::U(addr as u64), base + 1, 2, false, ""));
                root.push(dec.f("数量", Value::U(qty as u64), base + 3, 2, false, ""));
                summary = format!("RESP 写确认 {}[{}] unit{}", abbr(f), addr, unit);
            }
        }
        11 | 17 => {
            root.push(dec.f("数据", Value::Hex(pdu[1..].to_vec()), base + 1, pdu.len().saturating_sub(1) as u16, false, ""));
            summary = format!("{} unit{}", func_name(f), unit);
        }
        _ => {
            root.push(dec.f("数据", Value::Hex(pdu[1..].to_vec()), base + 1, pdu.len().saturating_sub(1) as u16, false, ""));
            summary = format!("FUNC 0x{:02X} unit{}", f, unit);
        }
    }
    PduOut { root, summary, req, exception }
}

fn abbr(f: u8) -> &'static str {
    match f {
        1 | 5 | 15 => "CO",
        2 => "DI",
        3 | 6 | 16 => "HR",
        4 => "IR",
        _ => "?",
    }
}

fn scale_reg(map: Option<&ModbusMap>, addr: u16, _f: u8, raw: u16) -> (f64, f64) {
    if let Some(m) = map {
        if let Some(r) = m.meta(addr) {
            let v = raw as f64 * r.scale + r.offset;
            return (v, v);
        }
    }
    let v = raw as f64;
    (v, v)
}

/// 字节序 → 线缆字节(wire = 各寄存器大端展开 hi,lo)的取用顺序
fn word_order(bo: &str, width_regs: usize) -> Vec<usize> {
    let s = bo.trim().to_ascii_uppercase();
    match (width_regs, s.as_str()) {
        (1, "BA") => vec![1, 0],
        (2, "DCBA") => vec![3, 2, 1, 0],
        (2, "BADC") => vec![1, 0, 3, 2],
        (2, "CDAB") => vec![2, 3, 0, 1],
        _ => (0..width_regs * 2).collect(), // AB / ABCD
    }
}

/// 解码映射命中的寄存器组:返回 (消耗寄存器数, 名称, 物理值, 单位, 枚举标签, 原始整数值)
pub fn decode_reg_group(m: &RegMeta, regs: &[u16]) -> Option<(usize, String, f64, String, Option<String>, f64)> {
    let w = m.width.clamp(1, 2) as usize;
    if regs.len() < w {
        return None;
    }
    let (raw, phys_raw) = if w == 1 {
        let wire = [(regs[0] >> 8) as u8, (regs[0] & 0xFF) as u8];
        let o = word_order(&m.byte_order, 1);
        let raw = ((wire[o[0]] as u16) << 8) | wire[o[1]] as u16;
        let v = if m.signed { (raw as i16) as f64 } else { raw as f64 };
        (raw as f64, v)
    } else {
        let wire = [(regs[0] >> 8) as u8, (regs[0] & 0xFF) as u8, (regs[1] >> 8) as u8, (regs[1] & 0xFF) as u8];
        let o = word_order(&m.byte_order, 2);
        let raw = ((wire[o[0]] as u32) << 24)
            | ((wire[o[1]] as u32) << 16)
            | ((wire[o[2]] as u32) << 8)
            | (wire[o[3]] as u32);
        let v = if m.signed { (raw as i32) as f64 } else { raw as f64 };
        (raw as f64, v)
    };
    let phys = phys_raw * m.scale + m.offset;
    let label = m.enums.get(&format!("{}", raw as u64)).cloned();
    Some((w, m.name.clone(), phys, m.unit.clone(), label, raw))
}

fn reg_meta(map: Option<&ModbusMap>, addr: u16, f: u8) -> (String, String) {
    if let Some(m) = map {
        if let Some(r) = m.meta(addr) {
            return (r.name.clone(), r.unit.clone());
        }
    }
    (reg_label(map, addr, f), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Strings;

    fn f3_resp() -> Vec<u8> {
        // 01 03 04 41 20 00 00 + crc
        let mut f = vec![0x01, 0x03, 0x04, 0x41, 0x20, 0x00, 0x00];
        let c = crc16_modbus(&f);
        f.push(c as u8);
        f.push((c >> 8) as u8);
        f
    }

    #[test]
    fn scan_finds_frame() {
        let frame = f3_resp();
        let mut data = vec![0xAB, 0xCD]; // 噪声
        data.extend_from_slice(&frame);
        data.push(0x11);
        let out = scan(&data, Dir::Rx);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], (2, 9));
        assert!(crc_ok(&data[2..11]));
    }

    #[test]
    fn decode_resp_with_scale() {
        let mut strings = Strings::default();
        let mut sigs = super::super::SigAcc::default();
        let mut events = vec![];
        let map = ModbusMap {
            regs: vec![RegMeta {
                addr: 0,
                name: "TempSensor".into(),
                scale: 0.1,
                offset: 0.0,
                unit: "°C".into(),
                width: 1,
                byte_order: String::new(),
                signed: false,
                enums: Default::default(),
            }],
        };
        let mut dec = Dec {
            strings: &mut strings,
            sigs: &mut sigs,
            events: &mut events,
            map: Some(&map),
            map104: None,
            frame: 0,
            t_ns: 0,
            source: 0,
            channel: 0,
            chan_label: "test".into(),
            fields: vec![],
        };
        let frame = f3_resp();
        let pdu = &frame[1..frame.len() - 2];
        let out = decode_pdu(&mut dec, Dir::Rx, 1, pdu, 1, Some((0, 2)));
        assert!(out.exception.is_none());
        // 0x4120 = 16672 → 1667.2 °C(测试数据如此)
        let series = sigs.into_series();
        let s = series.iter().find(|s| s.key == "unit1·TempSensor").expect("应有 TempSensor 信号");
        assert!((s.pts[0].1 - 1667.2).abs() < 1e-9);
    }

    #[test]
    fn exception_decode() {
        let mut f = vec![0x01, 0x83, 0x02];
        let c = crc16_modbus(&f);
        f.push(c as u8);
        f.push((c >> 8) as u8);
        let out = scan(&f, Dir::Rx);
        assert_eq!(out, vec![(0, 5)]);
        let mut strings = Strings::default();
        let mut sigs = super::super::SigAcc::default();
        let mut events = vec![];
        let mut dec = Dec { strings: &mut strings, sigs: &mut sigs, events: &mut events, map: None, map104: None, frame: 0, t_ns: 0, source: 0, channel: 0, chan_label: "test".into(), fields: vec![] };
        let pdu = &f[1..3];
        let out = decode_pdu(&mut dec, Dir::Rx, 1, pdu, 1, None);
        assert_eq!(out.exception, Some(2));
        assert_eq!(events.len(), 1);
    }
}

#[cfg(test)]
mod byte_order_tests {
    use super::*;

    fn meta(addr: u16, name: &str, width: u8, bo: &str, signed: bool, scale: f64) -> RegMeta {
        RegMeta {
            addr,
            name: name.into(),
            scale,
            offset: 0.0,
            unit: String::new(),
            width,
            byte_order: bo.into(),
            signed,
            enums: Default::default(),
        }
    }

    /// FR-3.2 六种字节序:语义 = 值字节 A-D 在线缆上的排列顺序。
    /// 同一值 0x12345678(A=12,B=34,C=56,D=78)按各字节序放到寄存器,解码必须还原同一值。
    #[test]
    fn byte_orders_32bit() {
        // (byte_order, 承载 0x12345678 的寄存器组)
        let cases: [(&str, u16, u16); 4] = [
            ("ABCD", 0x1234, 0x5678), // 线缆 12 34 56 78
            ("DCBA", 0x7856, 0x3412), // 线缆 78 56 34 12
            ("BADC", 0x3412, 0x7856), // 线缆 34 12 78 56
            ("CDAB", 0x5678, 0x1234), // 线缆 56 78 12 34
        ];
        for (bo, r0, r1) in cases {
            let m = meta(0, "e", 2, bo, false, 1.0);
            let (w, _, v, _, _, raw) = decode_reg_group(&m, &[r0, r1]).unwrap();
            assert_eq!(w, 2);
            assert_eq!(raw as u32, 0x1234_5678u32, "byte_order {bo}");
            assert!((v - 0x1234_5678 as f64).abs() < 1e-9, "byte_order {bo}: {v}");
        }
    }

    #[test]
    fn byte_order_16bit_and_default() {
        let regs = [0x1234u16];
        let ab = meta(0, "x", 1, "", false, 1.0); // 缺省 = AB
        assert_eq!(decode_reg_group(&ab, &regs).unwrap().5 as u16, 0x1234u16);
        let ba = meta(0, "x", 1, "BA", false, 1.0);
        assert_eq!(decode_reg_group(&ba, &regs).unwrap().5 as u16, 0x3412u16);
    }

    #[test]
    fn signed_and_scale() {
        let m = meta(0, "t", 1, "AB", true, 0.1);
        let regs = [0xFF9Cu16]; // -100
        let (_, _, v, _, _, _) = decode_reg_group(&m, &regs).unwrap();
        assert!((v - (-10.0)).abs() < 1e-9);
    }

    /// FR-3.3 枚举表:raw 值映射显示名
    #[test]
    fn enum_labels() {
        let mut m = meta(0, "state", 1, "AB", false, 1.0);
        m.enums.insert("1".into(), "Run".into());
        m.enums.insert("2".into(), "Idle".into());
        let (_, _, _, _, label, raw) = decode_reg_group(&m, &[2u16]).unwrap();
        assert_eq!(raw, 2.0);
        assert_eq!(label.as_deref(), Some("Idle"));
        let (_, _, _, _, label, _) = decode_reg_group(&m, &[9u16]).unwrap();
        assert!(label.is_none());
    }
}

/// Modbus ASCII(LRC)整帧校验:末字节 = 前 N-1 字节的 LRC(两进制补码和)。
/// 输入为 hexlog 已解码的二进制帧(addr,func,...,lrc)。
pub fn lrc_frame_ok(d: &[u8]) -> bool {
    d.len() >= 4 && crate::crc::lrc8(&d[..d.len() - 1]) == d[d.len() - 1]
}

#[cfg(test)]
mod ascii_tests {
    use super::*;

    #[test]
    fn lrc_frame() {
        // 请求 01 03 00 00 00 02 → LRC = 0xFA
        let d = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x02, 0xFA];
        assert!(lrc_frame_ok(&d));
        let bad = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00];
        assert!(!lrc_frame_ok(&bad));
        // ASCII 文本形态(":010300000002FA\r\n" 已被 hexlog 解码为上式)
        let text = b":010300000002FA\r\n";
        let hexs: String = text[1..].iter().map(|b| *b as char).filter(|c| c.is_ascii_hexdigit()).collect();
        let mut bin = vec![];
        for k in (0..hexs.len()).step_by(2) {
            bin.push(u8::from_str_radix(&hexs[k..k + 2], 16).unwrap());
        }
        assert!(lrc_frame_ok(&bin));
    }
}
