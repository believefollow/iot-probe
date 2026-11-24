//! 最小 zlib / DEFLATE 解压器(RFC 1950 / 1951,自研零依赖)。
//! 服务 BLF 压缩容器(ZLIB_DEFLATE=2):支持存储块、定长 Huffman、动态 Huffman
//! 三种块型;带输出上限与畸形流防护(超界即报错,不编造输出)。

const MAX_BITS: usize = 15;
/// 解压输出上限(单容器),防压缩炸弹
const MAX_OUTPUT: usize = 16 * 1024 * 1024;

/// 长度码基值 / 附加位数(RFC 1951 3.2.5)
const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// 距离码基值 / 附加位数
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// 最低有效位在前的比特读取器
struct BitIn<'a> {
    data: &'a [u8],
    pos: usize,
    bitbuf: u32,
    bitcnt: u32,
}

impl<'a> BitIn<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitIn { data, pos: 0, bitbuf: 0, bitcnt: 0 }
    }

    fn bits(&mut self, need: u32) -> Option<u32> {
        while self.bitcnt < need {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            self.bitbuf |= (b as u32) << self.bitcnt;
            self.bitcnt += 8;
        }
        let val = self.bitbuf & ((1u32 << need) - 1);
        self.bitbuf >>= need;
        self.bitcnt -= need;
        Some(val)
    }

    /// 丢弃半个字节的余量,把未消费的整字节退回数据流(存储块按字节读)
    fn align(&mut self) {
        let drop = self.bitcnt % 8;
        self.bitbuf >>= drop;
        self.bitcnt -= drop;
        self.pos -= (self.bitcnt / 8) as usize;
        self.bitbuf = 0;
        self.bitcnt = 0;
    }
}

/// 规范哈夫曼解码表:每码长计数 + 按码长排序的符号(puff 风格)
struct Huff {
    count: [u16; MAX_BITS + 1],
    symbol: Vec<u16>,
}

impl Huff {
    /// 由码长表构建;超订阅/不完整码表返回 None(损坏流宁可拒绝)
    fn build(lengths: &[u8]) -> Option<Huff> {
        if lengths.is_empty() {
            return None;
        }
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lengths {
            if l as usize > MAX_BITS {
                return None;
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left <<= 1;
            left -= count[len] as i32;
            if left < 0 {
                return None;
            }
        }
        let mut offs = [0u16; MAX_BITS + 1];
        for len in 1..MAX_BITS {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Some(Huff { count, symbol })
    }

    fn decode(&self, br: &mut BitIn) -> Option<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_BITS {
            code |= br.bits(1)? as i32;
            let cnt = self.count[len] as i32;
            if code - first < cnt {
                return self.symbol.get((index + code - first) as usize).copied();
            }
            index += cnt;
            first += cnt;
            first <<= 1;
            code <<= 1;
        }
        None
    }
}

/// 定长 Huffman 表(RFC 1951 3.2.6)
fn fixed_tables() -> (Huff, Huff) {
    let mut lens = [0u8; 288];
    for (i, l) in lens.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let lit = Huff::build(&lens).expect("定长字面表合法");
    let dist = Huff::build(&[5u8; 30]).expect("定长距离表合法");
    (lit, dist)
}

/// 动态 Huffman 表头(RFC 1951 3.2.7)
fn dynamic_tables(br: &mut BitIn) -> Result<(Huff, Huff), String> {
    let nlen = 257 + br.bits(5).ok_or("deflate 流提前结束")? as usize;
    let ndist = 1 + br.bits(5).ok_or("deflate 流提前结束")? as usize;
    let ncode = 4 + br.bits(4).ok_or("deflate 流提前结束")? as usize;
    if nlen > 286 || ndist > 30 {
        return Err("动态表码数超界".into());
    }
    const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let mut clens = [0u8; 19];
    for i in 0..ncode {
        clens[ORDER[i]] = br.bits(3).ok_or("deflate 流提前结束")? as u8;
    }
    let clh = Huff::build(&clens).ok_or("码长表构建失败")?;
    let mut lens = vec![0u8; nlen + ndist];
    let mut i = 0usize;
    while i < lens.len() {
        let sym = clh.decode(br).ok_or("码长解码失败")? as usize;
        match sym {
            0..=15 => {
                lens[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err("重复码无处复制".into());
                }
                let prev = lens[i - 1];
                let rep = 3 + br.bits(2).ok_or("deflate 流提前结束")? as usize;
                for _ in 0..rep {
                    if i >= lens.len() {
                        return Err("码长重复越界".into());
                    }
                    lens[i] = prev;
                    i += 1;
                }
            }
            17 | 18 => {
                let (base, nb) = if sym == 17 { (3, 2) } else { (11, 7) };
                let rep = base + br.bits(nb).ok_or("deflate 流提前结束")? as usize;
                for _ in 0..rep {
                    if i >= lens.len() {
                        return Err("零重复越界".into());
                    }
                    lens[i] = 0;
                    i += 1;
                }
            }
            _ => return Err("非法码长符号".into()),
        }
    }
    let lit = Huff::build(&lens[..nlen]).ok_or("字面表构建失败")?;
    let dist = Huff::build(&lens[nlen..]).ok_or("距离表构建失败")?;
    Ok((lit, dist))
}

/// 解码一个数据块主体(字面/长度+距离回拷)
fn data_block(br: &mut BitIn, lit: &Huff, dist: &Huff, out: &mut Vec<u8>) -> Result<(), String> {
    loop {
        let sym = lit.decode(br).ok_or("字面码解码失败")?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            _ => {
                let i = (sym - 257) as usize;
                if i >= LBASE.len() {
                    return Err("长度码越界".into());
                }
                let len =
                    LBASE[i] as usize + br.bits(LEXTRA[i] as u32).ok_or("deflate 流提前结束")? as usize;
                let ds = dist.decode(br).ok_or("距离码解码失败")? as usize;
                if ds >= DBASE.len() {
                    return Err("距离码越界".into());
                }
                let d =
                    DBASE[ds] as usize + br.bits(DEXTRA[ds] as u32).ok_or("deflate 流提前结束")? as usize;
                if d > out.len() {
                    return Err("回拷距离越界".into());
                }
                if out.len() + len > MAX_OUTPUT {
                    return Err("解压输出超限".into());
                }
                let start = out.len() - d;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
        }
    }
}

/// 裸 DEFLATE 流解压(RFC 1951)
pub fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut br = BitIn::new(data);
    loop {
        let last = br.bits(1).ok_or("deflate 流提前结束")?;
        match br.bits(2).ok_or("deflate 流提前结束")? {
            0 => {
                br.align();
                if br.pos + 4 > br.data.len() {
                    return Err("存储块头越界".into());
                }
                let len = u16::from_le_bytes([br.data[br.pos], br.data[br.pos + 1]]) as usize;
                let nlen = u16::from_le_bytes([br.data[br.pos + 2], br.data[br.pos + 3]]) as usize;
                br.pos += 4;
                if len ^ 0xFFFF != nlen {
                    return Err("存储块 LEN/NLEN 校验失败".into());
                }
                if br.pos + len > br.data.len() {
                    return Err("存储块数据越界".into());
                }
                out.extend_from_slice(&br.data[br.pos..br.pos + len]);
                br.pos += len;
            }
            1 => {
                let (lit, dist) = fixed_tables();
                data_block(&mut br, &lit, &dist, &mut out)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut br)?;
                data_block(&mut br, &lit, &dist, &mut out)?;
            }
            _ => return Err("非法块型 3".into()),
        }
        if last == 1 {
            break;
        }
        if out.len() > MAX_OUTPUT {
            return Err("解压输出超限".into());
        }
    }
    Ok(out)
}

/// zlib 封装解压(RFC 1950:CMF/FLG 头 + deflate + Adler-32)
pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 6 {
        return Err("zlib 数据过短".into());
    }
    let cmf = data[0] as u16;
    let flg = data[1] as u16;
    if cmf & 0x0F != 8 {
        return Err(format!("zlib 压缩方法非 deflate: {:#x}", cmf & 0x0F));
    }
    if (cmf << 8 | flg) % 31 != 0 {
        return Err("zlib 头校验失败".into());
    }
    if flg & 0x20 != 0 {
        return Err("不支持 zlib 预置字典(FDICT)".into());
    }
    let out = inflate(&data[2..data.len() - 4])?;
    // Adler-32 校验:能对上就说明解压结果与源一致
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in &out {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    // Adler-32 按大端存储(RFC 1950)
    let stored = u32::from_be_bytes([data[data.len() - 4], data[data.len() - 3], data[data.len() - 2], data[data.len() - 1]]);
    if (b << 16) | a != stored {
        return Err(format!("Adler-32 校验失败(算得 {:#010x},存 {:#010x})", (b << 16) | a, stored));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// stdlib zlib(level=0)生成的存储块流
    const Z_STORED: &[u8] = &[
        0x78, 0x01, 0x01, 0x1c, 0x00, 0xe3, 0xff, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x44, 0x2d, 0x42,
        0x4c, 0x4f, 0x43, 0x4b, 0x2d, 0x54, 0x45, 0x53, 0x54, 0x2d, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x6e, 0x28, 0x07, 0x11,
    ];
    /// stdlib zlib(strategy=Z_FIXED)生成的定长 Huffman 流
    const Z_FIXED: &[u8] = &[
        0x78, 0x01, 0x4b, 0xcb, 0xac, 0x48, 0x4d, 0x51, 0xc8, 0x28, 0x4d, 0x4b, 0xcb, 0x4d, 0xcc,
        0x53, 0x48, 0xca, 0xc9, 0x4f, 0xce, 0xd6, 0x51, 0x28, 0x4a, 0x2d, 0x48, 0x4d, 0x2c, 0x49,
        0x4d, 0xb1, 0x52, 0x48, 0x4c, 0x4a, 0x86, 0x23, 0x00, 0x5d, 0x91, 0x0f, 0xc9,
    ];
    /// stdlib zlib(level=9)生成的动态 Huffman 流
    const Z_DYN: &[u8] = &[
        0x78, 0xda, 0x4b, 0xa9, 0xcc, 0x4b, 0xcc, 0xcd, 0x4c, 0x56, 0xc8, 0x28, 0x4d, 0x4b, 0xcb,
        0x4d, 0xcc, 0x53, 0x48, 0xa1, 0x90, 0xef, 0xea, 0xe7, 0x02, 0x00, 0x2e, 0xe4, 0x1f, 0x0a,
    ];

    #[test]
    fn stored_fixed_dynamic_roundtrip() {
        assert_eq!(zlib_decompress(Z_STORED).unwrap(), b"STORED-BLOCK-TEST-1234567890");
        assert_eq!(
            zlib_decompress(Z_FIXED).unwrap(),
            b"fixed huffman block, repeated: abcabcabcabc"
        );
        assert_eq!(
            zlib_decompress(Z_DYN).unwrap(),
            b"dynamic huffman dynamic huffman dynamic huffman dynamic huffman dynamic huffman END"
        );
    }

    #[test]
    fn rejects_corruption() {
        let mut bad = Z_STORED.to_vec();
        bad[10] ^= 0xff;
        assert!(zlib_decompress(&bad).is_err(), "载荷被改应 Adler 失败");
        assert!(zlib_decompress(&[0x78, 0x01, 0x00]).is_err(), "截断应报错");
        // 头校验位坏
        assert!(zlib_decompress(&[0x78, 0x02, 0x01, 0x05, 0x00, 0xfa, 0xff, 0x41, 0x41, 0x00, 0x00, 0x00, 0x01]).is_err());
    }
}
