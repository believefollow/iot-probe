//! Vector ASC(CANoe / CANalyzer / ZCANPro 导出格式)摄入。
//! 经典 CAN 行:
//!   0.000000 1  1A0            Rx   d 8 01 02 03 04 05 06 07 08
//!   1.200000 2  18FF0102x      Tx   d 8 AA BB ...
//!   0.005000 1  100r           Rx   r 8
//! CAN FD 行(CANoe v8.5+ / python-can ASCWriter):
//!   30.506898 CANFD 4 Rx 4EE 0 1 f 64 A1 02 ...   (brs esi dlc(hex) 数据长度(十进制) 数据)
//!   31.506898 CANFD 4 Rx 1C4D80A7x 符号名 1 0 f 64 ...
//! 时间戳为相对记录起始的秒;扩展帧 ID 带 x 后缀。

use super::rec;
use crate::model::{Dir, Proto, Record};

fn is_hexs(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 解析一行;返回 None 表示不是 CAN 数据行(ASC 里还有大量事件行)
pub fn parse_line(line: &str) -> Option<(f64, u16, u32, bool, bool, bool, Vec<u8>)> {
    // (ts, channel, id, ext, remote, fd, data)
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < 6 {
        return None;
    }
    let ts: f64 = toks[0].parse().ok()?;
    let ch: u16 = toks[1].parse().ok()?;
    // id token:hex + 可选 x/r
    let idtok = toks[2];
    let (hexpart, suffix) = if let Some(h) = idtok.strip_suffix('x') {
        (h, "x")
    } else if let Some(h) = idtok.strip_suffix('r') {
        (h, "r")
    } else {
        (idtok, "")
    };
    if !is_hexs(hexpart) {
        return None;
    }
    let id = u32::from_str_radix(hexpart, 16).ok()?;
    let ext = suffix == "x";
    let dir = match toks[3] {
        "Rx" | "rx" => Dir::Rx,
        "Tx" | "tx" => Dir::Tx,
        _ => Dir::Unknown,
    };
    let typ = toks[4];
    let _ = dir;
    if typ == "d" {
        let _dlc: usize = toks[5].parse().ok()?;
        let mut data = Vec::new();
        for t in toks.iter().skip(6) {
            if t.len() == 2 && is_hexs(t) {
                if let Ok(v) = u8::from_str_radix(t, 16) {
                    data.push(v);
                }
            } else if is_hexs(t) && t.len() % 2 == 0 {
                for k in (0..t.len()).step_by(2) {
                    if let Ok(v) = u8::from_str_radix(&t[k..k + 2], 16) {
                        data.push(v);
                    }
                }
            }
        }
        return Some((ts, ch, id, ext, false, false, data));
    }
    if typ == "r" {
        return Some((ts, ch, id, ext, true, false, vec![]));
    }
    None
}

/// CANFD 行形状判断(嗅探用):ts CANFD ch dir id … 至少 9 个 token 才可能完整
fn is_canfd_line(line: &str) -> bool {
    let toks: Vec<&str> = line.split_whitespace().collect();
    toks.len() >= 9 && toks[1] == "CANFD" && toks[0].parse::<f64>().is_ok()
}

/// 解析一行 CANFD;返回 (ts, ch, id, ext, 数据长度, data)。
/// 数据长度为 0 即远程帧(data 为空);行尾附加数字字段(时长/标志/CRC/位时序)忽略。
pub fn parse_fd_line(line: &str) -> Option<(f64, u16, u32, bool, usize, Vec<u8>)> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < 9 || toks[1] != "CANFD" {
        return None;
    }
    let ts: f64 = toks[0].parse().ok()?;
    let ch: u16 = toks[2].parse().ok()?;
    let idtok = toks[4];
    let (hexpart, suffix) = if let Some(h) = idtok.strip_suffix('x') {
        (h, "x")
    } else if let Some(h) = idtok.strip_suffix('r') {
        (h, "r")
    } else {
        (idtok, "")
    };
    if !is_hexs(hexpart) {
        return None;
    }
    let id = u32::from_str_radix(hexpart, 16).ok()?;
    let ext = suffix == "x";
    let mut i = 5usize;
    // 可选符号名:纯数字 token 才是 brs,否则是符号名
    if toks.get(i).map(|t| !t.bytes().all(|b| b.is_ascii_digit())) == Some(true) {
        i += 1;
    }
    // brs esi dlc(hex) 数据长度(十进制)
    let dlc = usize::from_str_radix(toks.get(i + 2)?, 16).ok()?;
    let dlen: usize = toks.get(i + 3)?.parse().ok()?;
    let _ = dlc; // DLC 码与字节数换算仅在展示层需要,长度以数据长度域为准
    let mut data = Vec::new();
    for t in toks.iter().skip(i + 4) {
        if data.len() >= dlen.min(64) {
            break;
        }
        if t.len() == 2 && is_hexs(t) {
            data.push(u8::from_str_radix(t, 16).ok()?);
        } else {
            break;
        }
    }
    Some((ts, ch, id, ext, dlen, data))
}

pub fn looks_like_asc(text: &str) -> bool {
    let mut hits = 0;
    let mut tries = 0;
    for line in text.lines().take(40) {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        tries += 1;
        // Vector ASC 结构行:单条数据行的短日志(如仅 1 条远程帧)也靠它们定性
        let structural = l.contains("TriggerBlock")
            || l.contains("Triggerblock")
            || l.contains("Start of measurement")
            || l.contains("timestamps absolute")
            || l.starts_with("date ")
            || l.starts_with("// version ");
        if parse_line(l).is_some() || is_canfd_line(l) || structural {
            hits += 1;
        }
    }
    tries > 2 && hits >= 2
}

#[allow(clippy::type_complexity)]
pub fn parse(
    text: &str,
    out: &mut Vec<Record>,
    labels: &mut std::collections::HashMap<u16, String>,
    warns: &mut Vec<String>,
) {
    let mut fd_skipped = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 旧式 CAN FD 行("Type: 2/3",CANoe 早期格式)仍不支持
        if line.contains("Type: 2") || line.contains("Type: 3") {
            fd_skipped += 1;
            continue;
        }
        if let Some((ts, ch, id, ext, _dlen, data)) = parse_fd_line(line) {
            labels.entry(ch).or_insert_with(|| format!("ASC ch{ch}"));
            let mut r = rec((ts * 1e9) as u64, Dir::Unknown, Proto::CanFd, data);
            r.channel = ch;
            r.can_id = Some((id & 0x1FFF_FFFF) | ((ext as u32) << 31));
            out.push(r);
            continue;
        }
        let Some((ts, ch, id, ext, _remote, _fd, data)) = parse_line(line) else { continue };
        labels.entry(ch).or_insert_with(|| format!("ASC ch{ch}"));
        let mut r = rec((ts * 1e9) as u64, Dir::Unknown, Proto::Can, data);
        r.channel = ch;
        r.can_id = Some((id & 0x1FFF_FFFF) | ((ext as u32) << 31));
        out.push(r);
    }
    if fd_skipped > 0 {
        warns.push(format!("ASC 中 {fd_skipped} 条旧式 CAN FD 行(Type: 2/3)未解析"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_asc_lines() {
        let text = "\
date Sun Jan 05 10:00:00 2026
base hex timestamps absolute
internal events logged
Begin Triggerblock Sun Jan 05 10:00:00 2026
   0.000000 1  1A0             Rx   d 8 01 02 03 04 05 06 07 08
   0.010000 1  18FF0102x        Tx   d 8 AA BB CC DD EE FF 11 22
   0.020000 2  100r             Rx   r 8
   Status: running
End TriggerBlock
";
        assert!(looks_like_asc(text));
        let mut out = vec![];
        let mut labels = std::collections::HashMap::new();
        let mut w = vec![];
        parse(text, &mut out, &mut labels, &mut w);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].data.as_ref(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(out[1].can_id.unwrap() & 0x1FFF_FFFF, 0x18FF0102);
        assert!(out[1].can_id.unwrap() & 0x8000_0000 != 0, "扩展帧应打位31");
        assert_eq!(out[2].data.len(), 0);
        assert!(labels.contains_key(&1));
    }

    #[test]
    fn parse_asc_canfd_lines() {
        // 数据帧(无符号名)/ 带符号名的扩展帧 / 远程帧 —— 尾部数字字段应被忽略
        let text = "\
date Sam Sep 30 15:06:13.191 2017
base hex  timestamps absolute
Begin Triggerblock Sam Sep 30 15:06:13.191 2017
   0.000000 Start of measurement
  30.506898 CANFD   4 Rx        4EE                                   0 1 8 8 A1 02 03 04 00 00 00 00 64 1331984 11 0
  31.506898 CANFD   4 Rx        1C4D80A7x    AlphaNumericName_2       1 0 f 64 b1 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 64 1331984 11 0
  30.300981 CANFD   3 Tx     50005x                                0 1 5 0 140000 73 200050
End TriggerBlock
";
        assert!(looks_like_asc(text));
        let mut out = vec![];
        let mut labels = std::collections::HashMap::new();
        let mut w = vec![];
        parse(text, &mut out, &mut labels, &mut w);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].proto, Proto::CanFd);
        assert_eq!(out[0].can_id.unwrap() & 0x1FFF_FFFF, 0x4EE);
        assert_eq!(out[0].data.as_ref(), &[0xA1, 0x02, 0x03, 0x04, 0, 0, 0, 0]);
        assert!(out[1].can_id.unwrap() & 0x8000_0000 != 0, "扩展帧打位31");
        assert_eq!(out[1].data.len(), 64);
        assert_eq!(out[2].can_id.unwrap() & 0x1FFF_FFFF, 0x50005);
        assert!(out[2].data.is_empty(), "远程帧无数据");
    }
}
