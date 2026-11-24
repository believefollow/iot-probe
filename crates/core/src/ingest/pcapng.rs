//! pcapng 读取(自研,支持 SHB/IDB/EPB,多接口、if_tsresol 任意时间分辨率)。

fn rd_u16(b: &[u8], off: usize, le: bool) -> u16 {
    if le {
        u16::from_le_bytes([b[off], b[off + 1]])
    } else {
        u16::from_be_bytes([b[off], b[off + 1]])
    }
}
fn rd_u32(b: &[u8], off: usize, le: bool) -> u32 {
    if le {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    } else {
        u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }
}

pub fn read(data: &[u8]) -> Result<Vec<Pkt>, String> {
    if data.len() < 28 {
        return Err("pcapng 文件过短".into());
    }
    if rd_u32(data, 0, true) != 0x0A0D0D0A {
        return Err("不是 pcapng 文件".into());
    }
    let mut out = Vec::new();
    let mut le = true;
    let mut ifaces: Vec<u16> = Vec::new(); // linktype
    let mut if_res: Vec<u64> = Vec::new(); // ns per ts unit
    let mut off = 0usize;
    while off + 12 <= data.len() {
        let btype = rd_u32(data, off, le);
        let blen = rd_u32(data, off + 4, le) as usize;
        if blen < 12 || off + blen > data.len() {
            break;
        }
        match btype {
            0x0A0D0D0A => {
                // SHB:重新确定本 section 字节序,清空接口表
                let bom = rd_u32(data, off + 8, le);
                match bom {
                    0x1A2B3C4D => le = true,
                    0x4D3C2B1A => le = false,
                    _ => {}
                }
                ifaces.clear();
                if_res.clear();
            }
            _ => {
                let body = &data[off + 8..off + blen - 4];
                match btype {
                    0x00000001 => {
                        // IDB: linktype u16 + reserved u16 + snaplen u32 + options...
                        if body.len() >= 8 {
                            ifaces.push(rd_u16(body, 0, le));
                            if_res.push(parse_tsresol(&body[8..], le));
                        }
                    }
                    0x00000006 => {
                        // EPB
                        if body.len() >= 20 {
                            let ifid = rd_u32(body, 0, le) as usize;
                            let ts = ((rd_u32(body, 4, le) as u64) << 32) | rd_u32(body, 8, le) as u64;
                            let caplen = rd_u32(body, 12, le) as usize;
                            if 20 + caplen <= body.len() {
                                let link = ifaces.get(ifid).copied().unwrap_or(1);
                                let res = if_res.get(ifid).copied().unwrap_or(1000);
                                out.push(Pkt {
                                    t_ns: ts.saturating_mul(res),
                                    link,
                                    data: body[20..20 + caplen].to_vec(),
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        off += blen;
    }
    Ok(out)
}

/// 解析 options 中 code=9 (if_tsresol),返回每个时间戳单位对应的纳秒数
fn parse_tsresol(opts: &[u8], le: bool) -> u64 {
    let mut o = 0usize;
    while o + 4 <= opts.len() {
        let code = rd_u16(opts, o, le);
        let vlen = rd_u16(opts, o + 2, le) as usize;
        o += 4;
        if o + vlen > opts.len() {
            break;
        }
        if code == 9 && vlen >= 1 {
            let b = opts[o];
            let exp = (b & 0x7F) as u32;
            let denom: u128 = if b & 0x80 != 0 {
                1u128 << exp.min(63)
            } else {
                10u128.pow(exp.min(18))
            };
            // ns_per_unit = 1e9 / denom,精度用 128 位算
            let ns = (1_000_000_000u128 * (1u128 << 32)) / denom;
            return (ns >> 32).max(1) as u64;
        }
        o += vlen + ((4 - (vlen % 4)) % 4);
    }
    1000 // 默认微秒分辨率
}

use super::stream::Pkt;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn minimal_epb() {
        // 手工构造一个最小 pcapng:SHB + IDB(以太网) + 1 EPB
        let mut b = Vec::new();
        let push32 = |v: u32, b: &mut Vec<u8>| b.extend_from_slice(&v.to_le_bytes());
        let push16 = |v: u16, b: &mut Vec<u8>| b.extend_from_slice(&v.to_le_bytes());
        // SHB(28B: type+len+bom+版本x2+snaplen+结尾len)
        push32(0x0A0D0D0A, &mut b);
        push32(28, &mut b);
        push32(0x1A2B3C4D, &mut b);
        push32(1, &mut b);     // 版本主
        push32(4, &mut b);     // 版本次
        push32(0xFFFF, &mut b); // snaplen
        push32(0x0A0D0D0A, &mut b);
        // IDB
        push32(0x00000001, &mut b);
        push32(20, &mut b);
        push16(1, &mut b); // linktype = ethernet
        push16(0, &mut b); // reserved
        push32(65535, &mut b); // snaplen
        push32(0x00000001, &mut b);
        // EPB
        let pkt = [0u8; 14]; // dummy eth frame
        push32(0x00000006, &mut b);
        push32(8 + 20 + 16 + 4, &mut b); // type+len + body(20) + 数据(14→16 pad) + 结尾len
        push32(0, &mut b); // ifid
        push32(0, &mut b); // ts_hi
        push32(123456, &mut b); // ts_lo (µs)
        push32(14, &mut b);
        push32(14, &mut b);
        b.extend_from_slice(&pkt);
        b.extend_from_slice(&[0, 0]); // pad to 16
        push32(0x00000006, &mut b); // block end marker == type
        let pkts = read(&b).unwrap();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].t_ns, 123456 * 1000);
        assert_eq!(pkts[0].link, 1);
    }
}
