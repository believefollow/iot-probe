//! MQTT 3.1.x/5.0 基础解析(基于 TCP 重组后的字节流)。

use super::Dec;
use crate::model::{Field, Value};

pub fn type_name(t: u8) -> &'static str {
    match t {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        _ => "RESV",
    }
}

fn read_varint(d: &[u8], at: usize) -> Option<(u32, usize)> {
    let mut v = 0u32;
    let mut mul = 1u32;
    let mut k = at;
    loop {
        if k >= d.len() || k - at >= 4 {
            return None;
        }
        let b = d[k];
        v += ((b & 0x7F) as u32) * mul;
        mul *= 128;
        k += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    Some((v, k - at))
}

/// CONNECT 报文的协议版本(level)。MQTT 5.0 = 5(有属性段)。
pub fn connect_level(data: &[u8], off: usize, len: usize) -> Option<u8> {
    let d = &data[off..off + len];
    if d.len() < 4 {
        return None;
    }
    let (_, vn) = read_varint(d, 1)?;
    let p = 1 + vn;
    let name_len = u16::from_be_bytes([*d.get(p)?, *d.get(p + 1)?]) as usize;
    d.get(p + 2 + name_len).copied()
}

/// 跳过 MQTT 5.0 属性段(变长前缀)。返回新位置。
fn skip_props_v5(d: &[u8], at: usize) -> usize {
    if let Some((plen, n)) = read_varint(d, at) {
        let end = at + n + plen as usize;
        if end <= d.len() {
            return end;
        }
    }
    at
}

fn read_u16(d: &[u8], at: usize) -> Option<u16> {
    if at + 2 <= d.len() {
        Some(u16::from_be_bytes([d[at], d[at + 1]]))
    } else {
        None
    }
}

fn read_str(d: &[u8], at: usize) -> Option<(String, usize)> {
    let n = read_u16(d, at)? as usize;
    if at + 2 + n > d.len() {
        return None;
    }
    Some((String::from_utf8_lossy(&d[at + 2..at + 2 + n]).to_string(), 2 + n))
}

/// 扫描字节流中的完整 MQTT 包,返回 (off, len, type)。第二个返回值 = 跳过的垃圾字节数。
pub fn scan(data: &[u8]) -> (Vec<(usize, usize, u8)>, usize) {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut junk = 0usize;
    while i < data.len() {
        let b0 = data[i];
        let t = b0 >> 4;
        if !(1..=14).contains(&t) {
            i += 1;
            junk += 1;
            continue;
        }
        // remaining length varint
        let mut rem: u32 = 0;
        let mut mul: u32 = 1;
        let mut k = i + 1;
        let mut bad = false;
        loop {
            if k >= data.len() {
                bad = true;
                break;
            }
            let b = data[k];
            rem += ((b & 0x7F) as u32) * mul;
            mul *= 128;
            k += 1;
            if b & 0x80 == 0 {
                break;
            }
            if k - i > 4 {
                bad = true;
                break;
            }
        }
        if bad {
            i += 1;
            junk += 1;
            continue;
        }
        let total = 1 + (k - i - 1) + rem as usize;
        if i + total > data.len() {
            break; // 半包
        }
        out.push((i, total, t));
        i += total;
    }
    (out, junk)
}

/// 解码一个包:构建字段树,返回 summary。base: 包在 record 数据中的起始偏移。
/// v5 = 会话中 CONNECT 协议版本 ≥5(属性段需要跳过)。
pub fn decode(dec: &mut Dec, data: &[u8], off: usize, len: usize, ptype: u8, v5: bool) -> String {
    let d = &data[off..off + len];
    let b0 = d[0];
    let mut root: Vec<Field> = vec![dec.f("类型", Value::S(type_name(ptype).into()), off, 1, false, "")];
    let mut summary = type_name(ptype).to_string();
    let qos = (b0 >> 1) & 3;
    match ptype {
        1 => {
            // CONNECT
            let mut p = 2;
            if let Some((name, n)) = read_str(d, p) {
                root.push(dec.f("协议名", Value::S(name.clone()), off + p, n as u16, false, ""));
                p += n;
            }
            if d.len() > p + 4 {
                let level = d[p];
                let flags = d[p + 1];
                let ka = u16::from_be_bytes([d[p + 2], d[p + 3]]);
                root.push(dec.f("协议版本", Value::U(level as u64), off + p, 1, false, ""));
                root.push(dec.f("连接标志", Value::U(flags as u64), off + p + 1, 1, false, ""));
                root.push(dec.f("KeepAlive", Value::U(ka as u64), off + p + 2, 2, false, "s"));
                p += 4;
                if level >= 5 {
                    p = skip_props_v5(d, p); // MQTT 5.0 属性段
                }
                if let Some((cid, n)) = read_str(d, p) {
                    root.push(dec.f("ClientID", Value::S(cid.clone()), off + p, n as u16, false, ""));
                    summary = format!("CONNECT client=\"{cid}\" keepalive={ka}s");
                } else {
                    summary = format!("CONNECT keepalive={ka}s");
                }
            }
        }
        2 => {
            if d.len() >= 4 {
                let rc = d[3];
                let txt = match rc {
                    0 => "连接接受",
                    1 => "协议版本错误",
                    2 => "ClientID被拒",
                    3 => "服务不可用",
                    4 => "用户名密码错误",
                    5 => "未授权",
                    _ => "见码",
                };
                root.push(dec.f("返回码", Value::U(rc as u64), off + 3, 1, false, ""));
                root.push(dec.f("含义", Value::S(txt.into()), 0, 0, false, ""));
                summary = format!("CONNACK rc={rc} {txt}");
            }
        }
        3 => {
            // PUBLISH
            root.push(dec.f("QoS", Value::U(qos as u64), off, 1, false, ""));
            let retain = b0 & 1 != 0;
            root.push(dec.f("Retain", Value::B(retain), off, 1, false, ""));
            let mut p = 2;
            if let Some((topic, n)) = read_str(d, p) {
                root.push(dec.f("主题", Value::S(topic.clone()), off + p, n as u16, false, ""));
                p += n;
                summary = format!("PUBLISH \"{topic}\" qos{qos}{} {}B", if retain { " R" } else { "" }, len - p);
                if qos > 0 {
                    if let Some(pid) = read_u16(d, p) {
                        root.push(dec.f("报文ID", Value::U(pid as u64), off + p, 2, false, ""));
                        p += 2;
                    }
                }
                if v5 {
                    p = skip_props_v5(d, p); // MQTT 5.0 属性段
                }
                if p < d.len() {
                    let payload = &d[p..];
                    let s = String::from_utf8_lossy(payload);
                    let printable = s.chars().all(|c| !c.is_control() || c == '\n');
                    if printable && payload.len() <= 512 {
                        root.push(dec.f("载荷", Value::S(s.to_string()), off + p, payload.len() as u16, false, ""));
                    } else {
                        root.push(dec.f("载荷", Value::Hex(payload.to_vec()), off + p, payload.len().min(u16::MAX as usize) as u16, false, ""));
                    }
                }
            } else {
                summary = format!("PUBLISH {}B", len);
            }
        }
        4 | 5 | 6 | 7 => {
            if d.len() >= 4 {
                let pid = read_u16(d, 2).unwrap_or(0);
                root.push(dec.f("报文ID", Value::U(pid as u64), off + 2, 2, false, ""));
                if v5 {
                    skip_props_v5(d, 4); // 属性段(不计入 summary)
                }
                summary = format!("{} pid={pid}", type_name(ptype));
            }
        }
        8 => {
            let mut p = 2;
            let pid = read_u16(d, 2).unwrap_or(0);
            root.push(dec.f("报文ID", Value::U(pid as u64), off + 2, 2, false, ""));
            p += 2;
            if v5 {
                p = skip_props_v5(d, p);
            }
            let mut filters = vec![];
            while p + 3 <= d.len() {
                if let Some((f, n)) = read_str(d, p) {
                    filters.push(f);
                    p += n + 1; // + opts byte
                } else {
                    break;
                }
            }
            root.push(dec.f("过滤器", Value::S(filters.join(", ")), off + 4, 0, false, ""));
            summary = format!("SUBSCRIBE pid={pid} [{}]", filters.join(", "));
        }
        9 => {
            let pid = read_u16(d, 2).unwrap_or(0);
            // SUBACK 载荷可能只有 2B(pid,授予 0 个)+ v5 属性,4.. 越界会 panic
            let rcs: Vec<String> = if d.len() > 4 {
                d[4..].iter().map(|r| r.to_string()).collect()
            } else {
                vec![]
            };
            root.push(dec.f("报文ID", Value::U(pid as u64), off + 2, 2, false, ""));
            root.push(dec.f("授予QoS", Value::S(rcs.join(",")), off + 4, 0, false, ""));
            summary = format!("SUBACK pid={pid} qos={}", rcs.join(","));
        }
        10 => {
            let pid = read_u16(d, 2).unwrap_or(0);
            root.push(dec.f("报文ID", Value::U(pid as u64), off + 2, 2, false, ""));
            summary = format!("UNSUBSCRIBE pid={pid}");
        }
        12 | 13 => {}
        14 => {
            summary = "DISCONNECT".into();
        }
        _ => {}
    }
    dec.take_fields(root);
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Strings;

    fn mqtt_str(s: &[u8]) -> Vec<u8> {
        let mut v = (s.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(s);
        v
    }

    fn mqtt_pkt(b0: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![b0];
        let mut r = body.len();
        loop {
            let mut x = (r % 128) as u8;
            r /= 128;
            if r > 0 {
                x |= 0x80;
            }
            p.push(x);
            if r == 0 {
                break;
            }
        }
        p.extend_from_slice(body);
        p
    }

    fn connect_pkt() -> Vec<u8> {
        let mut p = vec![0x10];
        let body = {
            let mut b = vec![];
            let name = b"MQTT";
            b.push(0);
            b.push(4);
            b.extend_from_slice(name);
            b.push(4); // level
            b.push(0x02); // clean session
            b.extend_from_slice(&60u16.to_be_bytes());
            let cid = b"sensor-01";
            b.extend_from_slice(&(cid.len() as u16).to_be_bytes());
            b.extend_from_slice(cid);
            b
        };
        let rem = body.len();
        // varint
        let mut v = vec![];
        let mut r = rem;
        loop {
            let mut x = (r % 128) as u8;
            r /= 128;
            if r > 0 {
                x |= 0x80;
            }
            v.push(x);
            if r == 0 {
                break;
            }
        }
        p.extend_from_slice(&v);
        p.extend_from_slice(&body);
        p
    }

    #[test]
    fn v5_connect_client_id_and_level() {
        // MQTT 5.0 CONNECT:keepalive 后有属性段,ClientID 在属性之后
        let mut body = vec![];
        body.extend_from_slice(&mqtt_str(b"MQTT"));
        body.push(5); // level 5
        body.push(0x02);
        body.extend_from_slice(&60u16.to_be_bytes());
        body.push(0x05); // 属性段长度 5
        body.extend_from_slice(&[0x21, 0x00, 0x00, 0x27, 0x10]); // 会话过期间隔属性
        body.extend_from_slice(&mqtt_str(b"v5-device"));
        let pkt = mqtt_pkt(0x10, &body);
        assert_eq!(connect_level(&pkt, 0, pkt.len()), Some(5));
        let mut strings = Strings::default();
        let mut sigs = super::super::SigAcc::default();
        let mut events = vec![];
        let mut dec = Dec { strings: &mut strings, sigs: &mut sigs, events: &mut events, map: None, map104: None, frame: 0, t_ns: 0, source: 0, channel: 0, chan_label: "t".into(), fields: vec![] };
        let summary = decode(&mut dec, &pkt, 0, pkt.len(), 1, true);
        assert!(summary.contains("v5-device"), "v5 属性跳过后应读到 ClientID: {summary}");
    }

    #[test]
    fn scan_connect() {
        let pkt = connect_pkt();
        let (out, junk) = scan(&pkt);
        assert_eq!(junk, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 0);
        assert_eq!(out[0].2, 1);
        let mut strings = Strings::default();
        let mut sigs = super::super::SigAcc::default();
        let mut events = vec![];
        let mut dec = Dec { strings: &mut strings, sigs: &mut sigs, events: &mut events, map: None, map104: None, frame: 0, t_ns: 0, source: 0, channel: 0, chan_label: "test".into(), fields: vec![] };
        let summary = decode(&mut dec, &pkt, 0, out[0].1, 1, false);
        assert!(summary.contains("sensor-01"));
    }
}
