//! 最小 RFC6455 WebSocket 服务端(std-only):握手(SHA1+Base64)、帧读写、ping/pong。
//! 只服务文本帧;浏览器控制消息(set_filter)均为单帧小 payload,不做分片续帧。

use std::io::{Read, Write};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn accept_key(client_key: &str) -> String {
    b64(&sha1(format!("{client_key}{WS_GUID}").as_bytes()))
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// 读一帧(浏览器客户端帧均为 masked;不接受分片续帧)
pub fn read_frame(r: &mut impl Read) -> Result<(u8, Vec<u8>), String> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).map_err(|e| e.to_string())?;
    let opcode = h[0] & 0x0F;
    let masked = h[1] & 0x80 != 0;
    let len7 = (h[1] & 0x7F) as usize;
    let len = match len7 {
        126 => {
            let mut b = [0u8; 2];
            r.read_exact(&mut b).map_err(|e| e.to_string())?;
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b).map_err(|e| e.to_string())?;
            u64::from_be_bytes(b) as usize
        }
        _ => len7,
    };
    if len > (1 << 20) {
        return Err("帧过大".into());
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).map_err(|e| e.to_string())?;
        Some(m)
    } else {
        None
    };
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).map_err(|e| e.to_string())?;
    if let Some(m) = mask {
        for i in 0..data.len() {
            data[i] ^= m[i % 4];
        }
    }
    Ok((opcode, data))
}

pub fn write_frame(w: &mut impl Write, opcode: u8, data: &[u8]) -> Result<(), String> {
    let mut head = vec![0x80u8 | opcode];
    if data.len() < 126 {
        head.push(data.len() as u8);
    } else if data.len() < 65536 {
        head.push(126);
        head.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        head.push(127);
        head.extend_from_slice(&(data.len() as u64).to_be_bytes());
    }
    w.write_all(&head).map_err(|e| e.to_string())?;
    w.write_all(data).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

pub fn write_text(w: &mut impl Write, msg: &str) -> Result<(), String> {
    write_frame(w, 0x1, msg.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_accept_vector() {
        // RFC 6455 §1.3 示例
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn b64_vectors() {
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64(b"foob"), "Zm9vYg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"f"), "Zg==");
    }
}
