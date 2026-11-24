//! candump 日志(SocketCAN 格式)解析:
//!   (1767225600.123456) can0  1A0#DEADBEEF
//!   can0  1A0   [8]  DE AD BE EF 00 11 22 33
//!   can0  1A0##1DEADBEEF              (CAN FD)

use super::rec;
use crate::model::{Dir, Proto, Record};
use std::collections::HashMap;

#[derive(Debug)]
pub struct CandLine {
    pub t: Option<f64>,
    pub ifname: String,
    pub id: u32,
    pub ext: bool,
    pub fd: bool,
    pub rtr: bool,
    pub data: Vec<u8>,
}

fn parse_data_hex(s: &str, out: &mut Vec<u8>) {
    for k in (0..s.len()).step_by(2) {
        if k + 2 <= s.len() {
            if let Ok(v) = u8::from_str_radix(&s[k..k + 2], 16) {
                out.push(v);
            }
        }
    }
}

pub fn parse_line(line: &str) -> Option<CandLine> {
    let mut s = line.trim().to_string();
    let mut t = None;
    if s.starts_with('(') {
        let end = s.find(')')?;
        let ts: f64 = s[1..end].parse().ok()?;
        t = Some(ts);
        s = s[end + 1..].trim().to_string();
    }
    let mut parts = s.split_whitespace();
    let ifname = parts.next()?.to_string();
    // 接口名不能是时间戳类浮点(防把 Vector ASC 等其它格式的首列吞掉)
    if ifname.contains('.') || ifname.parse::<f64>().is_ok() {
        return None;
    }
    let rest = parts.next()?.to_string();
    if let Some(hash2) = rest.find("##") {
        // FD
        let idpart = &rest[..hash2];
        let id: u32 = u32::from_str_radix(idpart, 16).ok()?;
        let ext = idpart.len() > 3;
        let after = &rest[hash2 + 2..];
        let flags = after.chars().next()?.to_digit(16)? as u8;
        let mut data = vec![flags];
        parse_data_hex(&after[1..], &mut data);
        return Some(CandLine { t, ifname, id, ext, fd: true, rtr: false, data });
    }
    if let Some(hash) = rest.find('#') {
        let idpart = &rest[..hash];
        let id: u32 = u32::from_str_radix(idpart, 16).ok()?;
        let ext = idpart.len() > 3;
        let after = &rest[hash + 1..];
        if after == "R" || after.starts_with('R') {
            return Some(CandLine { t, ifname, id, ext, fd: false, rtr: true, data: vec![] });
        }
        let mut data = Vec::new();
        parse_data_hex(after, &mut data);
        return Some(CandLine { t, ifname, id, ext, fd: false, rtr: false, data });
    }
    // 带空格形式: id [dlc] bytes
    let id: u32 = u32::from_str_radix(&rest, 16).ok()?;
    let ext = rest.len() > 3;
    let mut data = Vec::new();
    let mut toks = parts.peekable();
    if let Some(n) = toks.peek() {
        if n.starts_with('[') {
            toks.next();
        }
    }
    for tok in toks {
        if tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(v) = u8::from_str_radix(tok, 16) {
                data.push(v);
            }
        } else if tok.bytes().all(|b| b.is_ascii_hexdigit()) && tok.len() % 2 == 0 {
            parse_data_hex(tok, &mut data);
        }
    }
    Some(CandLine { t, ifname, id, ext, fd: false, rtr: false, data })
}

pub fn looks_like_candump(text: &str) -> bool {
    let mut hits = 0;
    let mut tries = 0;
    for line in text.lines().take(20) {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        tries += 1;
        if parse_line(l).is_some() {
            hits += 1;
        }
    }
    tries > 0 && hits * 2 > tries
}

pub fn parse(
    text: &str,
    out: &mut Vec<Record>,
    labels: &mut HashMap<u16, String>,
    epoch_base: &mut Option<u64>,
    warns: &mut Vec<String>,
) {
    let mut ch_map: HashMap<String, u16> = HashMap::new();
    let mut first_epoch: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(c) = parse_line(line) else { continue };
        let next_id = ch_map.len() as u16;
        let ch = *ch_map.entry(c.ifname.clone()).or_insert(next_id);
        let mut data = c.data;
        if c.rtr {
            data.clear();
        }
        let t_ns = match c.t {
            Some(t) => {
                let ns = (t * 1e9) as u64;
                if first_epoch.is_none() && ns > 1_000_000_000_000 {
                    first_epoch = Some(ns);
                }
                ns
            }
            None => 0,
        };
        let mut r = rec(
            t_ns,
            Dir::Unknown,
            if c.fd { Proto::CanFd } else { Proto::Can },
            data,
        );
        r.channel = ch;
        r.can_id = Some((c.id & 0x1FFF_FFFF) | ((c.ext as u32) << 31));
        out.push(r);
    }
    for (name, &id) in &ch_map {
        labels.insert(id, name.clone());
    }
    if first_epoch.is_some() {
        *epoch_base = first_epoch;
    }
    if out.is_empty() {
        warns.push("candump 日志中未解析到任何帧".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as HM;
    #[test]
    fn both_formats() {
        let text = "\
(1767225600.123456) can0  1A0#DEADBEEF00112233
  can0  1A0   [8]  DE AD BE EF 00 11 22 33
  can1  123##1DEADBEEF
  vcan0  456#R
";
        let mut out = vec![];
        let mut labels = HM::new();
        let mut eb = None;
        let mut w = vec![];
        parse(text, &mut out, &mut labels, &mut eb, &mut w);
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].data.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]);
        assert_eq!(out[0].channel, 0);
        assert_eq!(out[2].proto, Proto::CanFd);
        assert_eq!(out[3].data.len(), 0);
        assert!(eb.is_some());
        assert_eq!(labels.get(&0).unwrap(), "can0");
    }
}
