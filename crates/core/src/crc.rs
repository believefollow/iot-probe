//! 校验算法集合(自研,零依赖)。

pub fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn crc16_msb(data: &[u8], init: u16) -> u16 {
    let mut crc = init;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// CRC-16/XMODEM (poly 0x1021, init 0x0000)
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    crc16_msb(data, 0x0000)
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF)
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    crc16_msb(data, 0xFFFF)
}

pub fn sum8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &b| a.wrapping_add(b))
}

pub fn xor8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &b| a ^ b)
}

/// LRC: 二进制补码(校验和的负数)
pub fn lrc8(data: &[u8]) -> u8 {
    (!sum8(data)).wrapping_add(1)
}

/// 按 DSL 中的算法名计算校验,返回应出现在报文中的字节序(LE for crc16_modbus, BE for ccitt/xmodem)。
pub fn calc(algo: &str, data: &[u8]) -> Option<Vec<u8>> {
    match algo {
        "crc16_modbus" => Some(crc16_modbus(data).to_le_bytes().to_vec()),
        "crc16_xmodem" => Some(crc16_xmodem(data).to_be_bytes().to_vec()),
        "crc16_ccitt" => Some(crc16_ccitt(data).to_be_bytes().to_vec()),
        "sum8" => Some(vec![sum8(data)]),
        "xor8" => Some(vec![xor8(data)]),
        "lrc" => Some(vec![lrc8(data)]),
        "none" => Some(vec![]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_vectors() {
        assert_eq!(crc16_modbus(b"123456789"), 0x4B37);
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }
    #[test]
    fn modbus_frame_crc() {
        // 经典示例帧 01 03 00 00 00 02 C4 0B
        let f = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x02];
        let c = crc16_modbus(&f).to_le_bytes();
        assert_eq!(c, [0xC4, 0x0B]);
    }
}
