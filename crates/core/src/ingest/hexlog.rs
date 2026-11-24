//! 通用串口十六进制日志解析。
//! 兼容常见格式(SSCOM 风格等):
//!   RX 2026-01-05 10:00:00.123  01 03 00 00 00 02 C4 0B
//!   [2026-01-05 10:00:00.123] Tx: 01 03 04 ...
//!   01 03 00 00 00 02 C4 0B            (无时间戳)
//!   2026-01-05 10:00:00.123,rx,"01 03"  (CSV-ish)

use super::rec;
use crate::model::{Dir, Proto, Record, TsSrc};

fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b.to_ascii_lowercase())
}

/// 在行中找时间戳 `YYYY-MM-DD HH:MM:SS(.frac)`,返回 (epoch_ns, 结束位置)
fn find_ts(line: &str) -> Option<(u64, usize)> {
    let b = line.as_bytes();
    let mut i = 0;
    while i + 19 <= b.len() {
        if b[i].is_ascii_digit()
            && b[i + 4] == b'-'
            && b[i + 7] == b'-'
            && b[i + 10] == b' '
            && b[i + 13] == b':'
            && b[i + 16] == b':'
            && b[i + 1].is_ascii_digit()
            && b[i + 2].is_ascii_digit()
            && b[i + 3].is_ascii_digit()
        {
            let y: i64 = line[i..i + 4].parse().ok()?;
            let mo: u32 = line[i + 5..i + 7].parse().ok()?;
            let d: u32 = line[i + 8..i + 10].parse().ok()?;
            let h: u32 = line[i + 11..i + 13].parse().ok()?;
            let mi: u32 = line[i + 14..i + 16].parse().ok()?;
            let s: u32 = line[i + 17..i + 19].parse().ok()?;
            if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
                i += 1;
                continue;
            }
            let mut end = i + 19;
            let mut frac_ns = 0u32;
            if end < b.len() && (b[end] == b'.' || b[end] == b',') {
                let start = end + 1;
                let mut j = start;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j > start {
                    let digits = &line[start..j];
                    let mut v: u64 = digits.parse().unwrap_or(0);
                    // 不足/超过 9 位归一化
                    let digits_n = digits.len().min(9);
                    v %= 10u64.pow(digits_n as u32);
                    frac_ns = (v * 10u64.pow(9 - digits_n as u32)) as u32;
                    end = j;
                }
            }
            let ns = crate::timeutil::wall_to_epoch_ns(y, mo, d, h, mi, s, frac_ns);
            return Some((ns, end));
        }
        i += 1;
    }
    None
}

const DIR_TOKENS: &[(&str, Dir)] = &[
    ("接收", Dir::Rx),
    ("发送", Dir::Tx),
    ("RX", Dir::Rx),
    ("TX", Dir::Tx),
    ("Rx", Dir::Rx),
    ("Tx", Dir::Tx),
    ("rx", Dir::Rx),
    ("tx", Dir::Tx),
    ("Recv", Dir::Rx),
    ("Send", Dir::Tx),
    ("Rcv", Dir::Rx),
    ("←", Dir::Rx),
    ("→", Dir::Tx),
];

/// 提取一行中的方向标记与十六进制字节。
/// hex_from:十六进制收集的起始位置(时间戳之前的数字不算字节);方向标记允许出现在任何字节之前。
fn parse_body(line: &str, hex_from: usize) -> (Dir, Vec<u8>) {
    let mut dir = Dir::Unknown;
    let mut bytes: Vec<u8> = Vec::new();
    let mut chars = line.char_indices().peekable();
    let mut byte_started = false;
    while let Some((i, c)) = chars.next() {
        if c.is_whitespace() || c == ',' || c == ':' || c == '[' || c == ']' || c == '"' || c == '-' {
            continue;
        }
        if !byte_started {
            let rest = &line[i..];
            let mut matched = false;
            for (tok, d) in DIR_TOKENS {
                if rest.starts_with(tok) {
                    let after = rest[tok.len()..].chars().next();
                    if after.map(|x| x.is_whitespace() || x == ':' || x == ']' || x == ',').unwrap_or(true) {
                        dir = *d;
                        matched = true;
                        break;
                    }
                }
            }
            if matched {
                continue;
            }
        }
        if i < hex_from {
            continue; // 时间戳区域,不当字节
        }
        if (c as u32) < 128 && is_hex(c as u8) {
            // 收集一个十六进制 token
            let start = i;
            let mut end = i + c.len_utf8();
            while let Some(&(j, ch)) = chars.peek() {
                if is_hex(ch as u8) {
                    chars.next();
                    end = j + ch.len_utf8();
                } else {
                    break;
                }
            }
            let tok = &line[start..end];
            if tok.len() >= 2 && tok.len() % 2 == 0 && tok.bytes().all(is_hex) {
                byte_started = true;
                for k in (0..tok.len()).step_by(2) {
                    if let Ok(v) = u8::from_str_radix(&tok[k..k + 2], 16) {
                        bytes.push(v);
                    }
                }
            } else if tok.len() == 1 {
                // 单字符(可能是方向 token 一部分),忽略
            } else {
                // 奇数长度或非法 token:跳过该 token
            }
        }
    }
    (dir, bytes)
}

pub fn parse(
    text: &str,
    out: &mut Vec<Record>,
    labels: &mut std::collections::HashMap<u16, String>,
    epoch_base: &mut Option<u64>,
    warns: &mut Vec<String>,
) {
    let mut saw_ts = false;
    labels.entry(0).or_insert_with(|| "串口".into());
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let (ts, ts_end) = match find_ts(line) {
            Some((t, e)) => (Some(t), e),
            None => (None, 0),
        };
        if ts.is_some() {
            saw_ts = true;
        }
        let body = if ts_end == 0 { line } else { &line[ts_end.min(line.len())..] };
        let (dir, bytes) = parse_body(line, line.len() - body.len());
        if bytes.is_empty() {
            continue;
        }
        let t = ts.unwrap_or(0);
        if epoch_base.is_none() && ts.is_some() {
            *epoch_base = ts;
        }
        out.push(rec(t, dir, Proto::Raw, bytes));
    }
    if !saw_ts && out.len() > 1 {
        warns.push("日志无时间戳:时间轴不可用,时序分析受限".into());
    }
    // 墙钟时间戳无精度保证(ADR-5:wall = 最低等级,如实标注)
    if saw_ts {
        for r in out.iter_mut() {
            r.ts_src = TsSrc::Wall;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_mixed() {
        let text = "\
# comment
RX 2026-01-05 10:00:00.000  01 03 00 00 00 02 C4 0B
[2026-01-05 10:00:00.005] Tx: 01 03 04 41 20 00 00 B8 39
DE AD BE EF
2026-01-05 10:00:00.010,rx,AA 55
发送 2026-01-05 10:00:00.020 00 11
";
        let mut out = vec![];
        let mut labels = std::collections::HashMap::new();
        let mut eb = None;
        let mut w = vec![];
        parse(text, &mut out, &mut labels, &mut eb, &mut w);
        assert_eq!(out.len(), 5);
        assert_eq!(out[0].dir, Dir::Rx);
        assert_eq!(out[0].data.len(), 8);
        assert_eq!(out[0].data[0], 0x01);
        assert_eq!(out[1].dir, Dir::Tx);
        assert_eq!(out[2].data.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(out[4].data.as_ref() == &[0x00, 0x11]);
        assert!(eb.is_some());
        // 时间递增
        assert!(out[1].t_ns > out[0].t_ns);
    }
}
