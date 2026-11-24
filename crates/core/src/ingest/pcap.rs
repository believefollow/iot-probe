//! 经典 pcap 读取(自研,零依赖)。支持大小端与 µs/ns 两种时间精度。

use super::stream::Pkt;

fn rd_u32(b: &[u8], off: usize, le: bool) -> u32 {
    if le {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    } else {
        u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }
}

/// 嗅探并读取 pcap / pcapng
pub fn read_any(data: &[u8]) -> Result<(Vec<Pkt>, Vec<String>), String> {
    if data.len() >= 4 && rd_u32(data, 0, true) == 0x0A0D0D0A {
        return super::pcapng::read(data).map(|p| (p, vec![]));
    }
    read(data)
}

/// 严格走一条记录;失败返回 None(不吞异常)
fn walk_record(data: &[u8], off: usize, le: bool, ns: bool, link: u16, out: &mut Vec<Pkt>) -> Option<()> {
    let ts_sec = rd_u32(data, off, le) as u64;
    let ts_frac = rd_u32(data, off + 4, le) as u64;
    let incl = rd_u32(data, off + 8, le) as usize;
    let off = off + 16;
    if incl > 262144 || off + incl > data.len() {
        return None;
    }
    let t_ns = if ns { ts_sec * 1_000_000_000 + ts_frac } else { ts_sec * 1_000_000_000 + ts_frac * 1000 };
    out.push(Pkt { t_ns, link, data: data[off..off + incl].to_vec() });
    Some(())
}

/// 读取 pcap;严格路径失败时按"宽松重同步"修复(走完全文件才接受)。
/// 已知病灶:某些写盘器在 16B 记录头后又垫 8B 零(载荷实际 incl+8),
/// mqtt_redhat_tcpdump.pcap 即此类 —— 严格走 rec1 即炸。
pub fn read(data: &[u8]) -> Result<(Vec<Pkt>, Vec<String>), String> {
    if data.len() < 24 {
        return Err("pcap 文件过短".into());
    }
    // Vector XCP 封装(嗅探器导出等工具的私有格式):魔法数 XCP\0 + 版本文本 002.001。
    // 明确拒识并给出转换指引,不进 pcap 解析路径。
    if data.len() >= 10 && &data[..4] == b"XCP\0" {
        return Err("Vector XCP 私有封装格式(.cap 魔法数 XCP\\0),非 libpcap;请先用 Wireshark 另存为 pcap 后加载".into());
    }
    let magic = rd_u32(data, 0, true);
    let (le, ns) = match magic {
        0xa1b2c3d4 => (true, false),
        0xd4c3b2a1 => (false, false),
        0xa1b23c4d => (true, true),
        0x4d3cb2a1 => (false, true),
        _ => return Err("不是 pcap 文件(魔法数不符)".into()),
    };
    let link = rd_u32(data, 20, le) as u16;
    let mut out = Vec::new();
    let mut off = 24usize;
    let mut strict_ok = true;
    while off + 16 <= data.len() {
        if walk_record(data, off, le, ns, link, &mut out).is_none() {
            strict_ok = false;
            break;
        }
        off += 16 + out.last().map(|p| p.data.len()).unwrap_or(0);
    }
    if strict_ok && off + 16 > data.len() {
        return Ok((out, vec![]));
    }
    // 宽松重同步:严格走挂了 —— 依次尝试记录载荷前垫 0B(常规)与 8B(损坏写盘器:
    // 16B 记录头后再垫 8 字节零,载荷实际读 incl 字节)。整条流必须恰好走完文件才算修复成功,
    // 否则放弃并维持原"损坏"报错(不猜测输出半截数据)。
    for pad in [0usize, 8] {
        out.clear();
        if walk_resync(data, le, ns, link, pad, &mut out) {
            let warn = if pad == 0 {
                "pcap 严格解析失败,已按宽松重同步(允许空记录/略过垃圾头)重读".to_string()
            } else {
                "pcap 严格解析失败:每条记录在 16B 头后多出 8B 垫字节(写盘器缺陷),已按 incl+8 跳过并重读".to_string()
            };
            return Ok((out, vec![warn]));
        }
    }
    Err("pcap 包长度异常,文件可能损坏(重同步修复亦失败)".into())
}

/// 以固定记录步长(16+pad+incl)重走全文件;全部记录合法且恰好走完返回 true。
fn walk_resync(data: &[u8], le: bool, ns: bool, link: u16, pad: usize, out: &mut Vec<Pkt>) -> bool {
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let ts_sec = rd_u32(data, off, le) as u64;
        let ts_frac = rd_u32(data, off + 4, le) as u64;
        let incl = rd_u32(data, off + 8, le) as usize;
        let payload = off + 16 + pad;
        if incl == 0 || incl > 262144 || payload + incl > data.len() {
            return false;
        }
        let t_ns = if ns { ts_sec * 1_000_000_000 + ts_frac } else { ts_sec * 1_000_000_000 + ts_frac * 1000 };
        out.push(Pkt { t_ns, link, data: data[payload..payload + incl].to_vec() });
        off = payload + incl;
    }
    // 必须恰好消费完整个文件(尾部不足一条头则允许)
    off + 16 > data.len()
}
