//! DNP3(IEEE 1815)链路层定界 + 传输层/应用层简析。
//! 帧结构:START(05 64) + LEN + CTRL + DST(2B) + SRC(2B) + 用户数据;CRC-16/DNP
//! (多项式 0x3D65 反射 0xA6BC,init 0,xorout 0xFFFF,低字节在前)按块附加:
//! 首块 = 起始 8 字节(START..SRC,地址域各 2 字节),其后每 ≤16B 用户数据块跟一个 CRC。
//! LEN 计 CTRL..用户数据(不含 CRC);最小 5。用户数据 = TH(1B) + 应用控制(1B) + 功能码(1B) + 对象。
//! 应用功能码:0x01 读 / 0x02 写 / 0x03 选择 / 0x04 操作 / 0x81 应答 / 0x82 无请求应答。
//! v1 只做报文级解码(链路功能 + 应用功能/对象组),不解析对象内部结构;坏帧 → CRC 错误/无法解析事件。

use super::Dec;
use crate::model::{EventKind, Value};

/// CRC-16/DNP(按块):poly 反射 0xA6BC,init 0,结果异或 0xFFFF
pub fn crc_dnp(data: &[u8]) -> u16 {
    let mut c: u16 = 0;
    for &b in data {
        c ^= b as u16;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xA6BC } else { c >> 1 };
        }
    }
    c ^ 0xFFFF
}

/// 链路控制域功能码(低 6 位)
fn ctrl_name(c: u8) -> String {
    let dir = if c & 0x80 != 0 { "从→主" } else { "主→从" };
    let prm = if c & 0x40 != 0 { "主" } else { "从" };
    let f = match c & 0x3F {
        0x00 => "ACK",
        0x01 => "NACK",
        0x02 => "链路状态",
        0x03 => "不支持的链路功能",
        0x04 => "用户数据",
        0x08 => "复位链路",
        0x09 => "请求链路状态",
        0x0B => "复位用户进程",
        0x11 => "请求链路状态",
        _ => "链路功能",
    };
    format!("{f}({dir}/{prm})")
}

/// 应用功能码(IEEE 1815 表 2-4)
fn app_func_name(f: u8) -> &'static str {
    match f {
        0x00 => "确认",
        0x01 => "读",
        0x02 => "写",
        0x03 => "选择",
        0x04 => "操作",
        0x05 => "直接操作",
        0x06 => "直接操作(无应答)",
        0x07 => "立即冻结",
        0x08 => "立即冻结(无应答)",
        0x09 => "冻结清除",
        0x0A => "冻结清除(无应答)",
        0x0B => "定时冻结",
        0x0C => "定时冻结(无应答)",
        0x0D => "冷重启",
        0x0E => "热重启",
        0x10 => "启动应用",
        0x11 => "停止应用",
        0x13 => "允许无请求",
        0x14 => "禁止无请求",
        0x15 => "指定类",
        0x16 => "延时测量",
        0x17 => "记录当前时间",
        0x18 => "打开文件",
        0x19 => "关闭文件",
        0x81 => "应答",
        0x82 => "无请求应答",
        0x83 => "应用确认",
        _ => "应用功能",
    }
}

/// 一条已定界的 DNP3 链路帧
#[derive(Debug)]
pub struct DnpFrame {
    /// 帧总长(含全部 CRC)
    pub len: usize,
    pub ctrl: u8,
    /// 目的/源站地址(2 字节小端)
    pub dst: u16,
    pub src: u16,
    /// 用户数据(TH + 应用层;不含 CRC)
    pub user: Vec<u8>,
    /// 链路层 CRC 是否全部通过
    pub crc_ok: bool,
}

/// 从字节流定界 DNP3 帧 CRC-验证版本。返回 (帧列表 (off, len), 未定界字节数)。
/// 帧总数 = 8 + (LEN-5>0 时: LEN-5 用户块 + 其 CRC)。
pub fn scan(data: &[u8]) -> (Vec<(usize, usize)>, usize) {
    let mut out = Vec::new();
    let mut junk = 0usize;
    let mut i = 0usize;
    while i + 10 <= data.len() {
        if data[i] != 0x05 || data[i + 1] != 0x64 {
            i += 1;
            junk += 1;
            continue;
        }
        let ln = data[i + 2] as usize;
        // LEN ≥ 2 的帧 CRC1 仍可验证(fuzz 语料里 LEN=2 的残帧按坏帧计);定界只认 5..=253
        if !(5..=253).contains(&ln) {
            i += 1;
            junk += 1;
            continue;
        }
        if crc_dnp(&data[i..i + 8]) != u16::from_le_bytes([data[i + 8], data[i + 9]]) {
            i += 1;
            junk += 1;
            continue;
        }
        let nuser = ln - 5;
        let mut pos = i + 10;
        let mut remaining = nuser;
        let mut ok = true;
        while remaining > 0 {
            let blk = remaining.min(16);
            if pos + blk + 2 > data.len()
                || crc_dnp(&data[pos..pos + blk]) != u16::from_le_bytes([data[pos + blk], data[pos + blk + 1]])
            {
                ok = false;
                break;
            }
            pos += blk + 2;
            remaining -= blk;
        }
        if !ok {
            i += 1;
            junk += 1;
            continue;
        }
        out.push((i, pos - i));
        i = pos;
    }
    if i < data.len() && data.len() - i > 300 {
        junk += data.len() - i;
    }
    (out, junk)
}

/// 解析一条定界好的帧(提取 ctrl/dst/src/用户数据)。
/// 地址域为 2 字节小端(CRC1 恰好覆盖 8 字节头块,语料全部为 16 位地址)。
pub fn parse_frame(data: &[u8], off: usize, len: usize) -> Option<DnpFrame> {
    let f = data.get(off..off + len)?;
    if f.len() < 10 || f[0] != 0x05 || f[1] != 0x64 {
        return None;
    }
    let ln = f[2] as usize;
    if !(5..=253).contains(&ln) {
        return None;
    }
    let nuser = ln - 5;
    let mut user = Vec::with_capacity(nuser);
    let mut pos = 10;
    let mut remaining = nuser;
    let mut crc_ok = true;
    while remaining > 0 {
        let blk = remaining.min(16);
        if pos + blk + 2 > f.len()
            || crc_dnp(&f[pos..pos + blk]) != u16::from_le_bytes([f[pos + blk], f[pos + blk + 1]])
        {
            crc_ok = false;
            break;
        }
        user.extend_from_slice(&f[pos..pos + blk]);
        pos += blk + 2;
        remaining -= blk;
    }
    Some(DnpFrame {
        len,
        ctrl: f[3],
        dst: u16::from_le_bytes([f[4], f[5]]),
        src: u16::from_le_bytes([f[6], f[7]]),
        user,
        crc_ok,
    })
}

/// 解码单帧(已在 scan 中定界),摘要 + 字段树写入 dec。
pub fn decode(dec: &mut Dec, data: &[u8], off: usize, len: usize) -> String {
    let Some(fr) = parse_frame(data, off, len) else {
        return format!("DNP3 短帧 {len}B");
    };
    let mut kids = vec![
        dec.f("CTRL", Value::U(fr.ctrl as u64), 3, 1, false, ""),
        dec.f("DST", Value::U(fr.dst as u64), 4, 2, false, ""),
        dec.f("SRC", Value::U(fr.src as u64), 6, 2, false, ""),
        dec.f("CTRL含义", Value::S(ctrl_name(fr.ctrl)), 0, 0, false, ""),
    ];
    let mut head = format!("{} dst={} src={}", ctrl_name(fr.ctrl), fr.dst, fr.src);
    if fr.ctrl & 0x3F == 0x04 && fr.user.len() >= 3 {
        // 用户数据:TH(1B) + 应用控制(1B,低 6 位为应用序号) + 功能码(1B) + [IIN(2B)] + 对象
        let (th, ac, func) = (fr.user[0], fr.user[1], fr.user[2]);
        kids.push(dec.f("TH", Value::U(th as u64), 0, 1, false, ""));
        kids.push(dec.f("应用序号", Value::U((ac & 0x3F) as u64), 0, 0, false, ""));
        kids.push(dec.f("应用功能", Value::S(app_func_name(func).into()), 0, 0, false, ""));
        head.push_str(&format!(" TH={th:#04x} APP {}(seq={})", app_func_name(func), ac & 0x3F));
        // 应答/无请求应答在对象前带 2 字节内部指示字 IIN(低字节在前)
        let objs = if matches!(func, 0x81 | 0x82) && fr.user.len() >= 5 {
            let iin = u16::from_le_bytes([fr.user[3], fr.user[4]]);
            kids.push(dec.f("IIN", Value::Hex(vec![fr.user[3], fr.user[4]]), 0, 0, false, ""));
            head.push_str(&format!(" IIN={iin:#06x}"));
            &fr.user[5..]
        } else {
            &fr.user[3..]
        };
        // 对象组/变体/限定词(读/写/选择/操作/应答/指定类才带对象)
        if objs.len() >= 3 && matches!(func, 0x01 | 0x02 | 0x03 | 0x04 | 0x15 | 0x81 | 0x82) {
            let (g, v, q) = (objs[0], objs[1], objs[2]);
            kids.push(dec.f("对象组", Value::U(g as u64), 0, 0, false, ""));
            kids.push(dec.f("变体", Value::U(v as u64), 0, 0, false, ""));
            kids.push(dec.f("限定词", Value::S(format!("{q:#04x}")), 0, 0, false, ""));
            head.push_str(&format!(" g{g}v{v} q={q:#04x}"));
        }
    } else if fr.ctrl & 0x3F == 0x04 {
        head.push_str(&format!(" TH={:#04x} 应用层未识别", fr.user.first().copied().unwrap_or(0)));
    }
    if !fr.crc_ok {
        dec.ev(EventKind::CrcError, "DNP3 链路层 CRC 校验失败".into(), Some(dec.frame));
    }
    dec.take_fields(kids);
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 从真实抓包提取的完整链路帧(Wireshark wiki / ICS-pcap 样本)
    const SELECT: &[u8] = &[
        0x05, 0x64, 0x1a, 0xc4, 0x03, 0x00, 0x04, 0x00, 0xc9, 0xb7, // 头 + CRC1
        0xc1, 0xc1, 0x03, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x01, 0x00, 0x03, 0x01, // 用户块1
        0x64, 0x00, 0x00, 0x00, 0x7b, 0x5e, // 用户块2 + CRC
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, // 用户块3 + CRC
    ];
    /// 无请求应答帧(ICS-pcap part1 实抓):user = TH e6 + AC f7(seq=0x37) + 功能 0x82 + IIN 0x0010(设备重启位)
    const UNSOLICITED: &[u8] = &[0x05, 0x64, 0x0a, 0x44, 0x03, 0x00, 0x04, 0x00, 0x7c, 0xae, 0xe6, 0xf7, 0x82, 0x10, 0x00, 0x4f, 0xbd];
    /// 链路状态请求(无用户数据,LEN=5)
    const LINK_REQ: &[u8] = &[0x05, 0x64, 0x05, 0xc9, 0x03, 0x00, 0x04, 0x00, 0xbd, 0x71];

    #[test]
    fn crc_dnp_known_vectors() {
        // 头块 056405c903000400 的 CRC = bd 71(小端存储)
        assert_eq!(crc_dnp(&[0x05, 0x64, 0x05, 0xc9, 0x03, 0x00, 0x04, 0x00]), 0x71bd);
        // SELECT 帧同头块
        assert_eq!(crc_dnp(&SELECT[..8]), u16::from_le_bytes([SELECT[8], SELECT[9]]));
    }

    #[test]
    fn scan_select_operate_two_frames() {
        let mut data = SELECT.to_vec();
        data.extend_from_slice(OPERATE);
        let (frames, junk) = scan(&data);
        assert_eq!(frames.len(), 2, "应定界出 2 帧");
        assert_eq!(junk, 0);
        assert_eq!(frames[0].1, SELECT.len());
    }

    // OPERATE 帧完整字节(与 SELECT 同头,CRC 不同)
    const OPERATE: &[u8] = &[
        0x05, 0x64, 0x1a, 0xc4, 0x03, 0x00, 0x04, 0x00, 0xc9, 0xb7,
        0xc1, 0xc2, 0x04, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x01, 0x00, 0x03, 0x01,
        0x64, 0x00, 0x00, 0x00, 0x83, 0x54,
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b,
    ];

    #[test]
    fn decode_select_shows_objects() {
        let mut dec = crate::dissect::dec_for_test();
        let head = decode(&mut dec, SELECT, 0, SELECT.len());
        assert!(head.contains("选择"), "head={head}");
        assert!(head.contains("g12v1"), "head={head}");
        assert!(head.contains("seq=1"), "head={head}");
        assert!(head.contains("dst=3"), "head={head}");
    }

    #[test]
    fn decode_unsolicited_shows_iin() {
        let mut dec = crate::dissect::dec_for_test();
        let head = decode(&mut dec, UNSOLICITED, 0, UNSOLICITED.len());
        assert!(head.contains("无请求应答"), "head={head}");
        assert!(head.contains("IIN=0x0010"), "head={head}");
    }

    #[test]
    fn link_request_no_user_data() {
        let mut dec = crate::dissect::dec_for_test();
        let head = decode(&mut dec, LINK_REQ, 0, LINK_REQ.len());
        assert!(head.contains("请求链路状态"), "head={head}");
        let fr = parse_frame(LINK_REQ, 0, LINK_REQ.len()).unwrap();
        assert!(fr.user.is_empty());
        assert!(fr.crc_ok);
    }

    #[test]
    fn scan_rejects_crc_corruption() {
        let mut data = SELECT.to_vec();
        data[8] ^= 0xff; // CRC1 头块破坏
        let (frames, junk) = scan(&data);
        assert!(frames.is_empty() && junk > 0, "坏 CRC 应计为 junk");
    }

    #[test]
    fn len_out_of_range_is_junk() {
        let mut data = SELECT.to_vec();
        data[2] = 1; // LEN=1 < 5
        let (frames, junk) = scan(&data);
        assert!(frames.is_empty() && junk > 0);
    }
}
