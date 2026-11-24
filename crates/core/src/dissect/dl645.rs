//! DL/T 645-2007 读表协议解析(任务卡 J1;储能/微电网电表链路补环):
//! - 帧结构:`68 A0..A5 68 C L DATA CS 16`,CS = 从第一个 68 起全部字节模 256 和
//! - 地址 6 字节 BCD **低位在前**;`AAAAAAAAAAAA` 通配、`999999999999` 广播
//! - **已知坑(按任务卡要求)**:厂家普遍不守 L 字段(响应常写 0x0C 却实带 DI 回显)——
//!   解析按 **DI 长度自纠**,不能硬信 L;失步后逐字节重扫 `68` 重新对齐
//! - 前置 `FE` 唢醒字节:吃掉不下传(连续 1-4 个 FE 属正常)
//! - 范围:**只读**(0x11 读数据/0x12 读后续);0x08 广播校时仅观测;写/费控/ESAM 不做
//! - DI 常用项解码:电量(00000000/0001xxxx)、电压电流(0201/0202)、功率功率因数(0203)、
//!   日期时间(040001/04000402)、表号(04000003? 实为读通信地址 0x11 无 DI)
//! - 串口默认 2400/Even/8/1(红外 1200)——由接线方配置,本模块不管串口

use super::Dec;
use crate::model::{EventKind, Value};

/// 帧定界扫描:输入为一段字节流(串口原始字节/TCP 透传),输出 (偏移, 总长) 列表 + 无法定界字节数。
/// 长度自纠策略:以 C 控制码与 DI 结构推断数据区真实长度,不硬信 L(厂家不守)。
pub fn scan(data: &[u8]) -> (Vec<(usize, usize)>, usize) {
    let mut out = vec![];
    let mut junk = 0usize;
    let mut i = 0usize;
    while i + 12 <= data.len() {
        // 吃唤醒前导 FE(连续 1..4 个,后随 68 才跳过;否则逐字节计垃圾)
        if data[i] == 0xFE {
            let mut fe = 0usize;
            while i + fe < data.len() && data[i + fe] == 0xFE && fe < 4 {
                fe += 1;
            }
            if i + fe < data.len() && data[i + fe] == 0x68 {
                i += fe;
                continue;
            }
        }
        if data[i] != 0x68 {
            i += 1;
            junk += 1;
            continue;
        }
        // 第二个 68 必须在 +7
        if i + 8 > data.len() || data[i + 7] != 0x68 {
            i += 1;
            junk += 1;
            continue;
        }
        let ctrl = data[i + 8];
        let l_field = data[i + 9] as usize;
        // 判断是否响应帧(ctrl bit7=1),结合控制码低 5 位功能推断 DATA 真实长度
        let is_resp = ctrl & 0x80 != 0;
        let func = ctrl & 0x3F;
        // 常用读响应(0x91/0x92 读成功):DATA = DI(4) + N×8B 电量 或 DI+4..12 其他
        // 长度自纠:从 L 起尝试,CS/16 验证通过即接受;不过则按 DI 结构重推
        let mut data_len = l_field;
        let mut frame_ok = false;
        // 尝试 1:硬信 L
 // 68(1)+A(6)+68(1)+C(1)+L(1)+DATA+CS(1)+16(1) = 12+L? 精确:10 前导 + L + CS + 16
        if l_field <= 200 && i + 10 + data_len + 2 <= data.len() {
            let body = &data[i..i + 10 + data_len + 2];
            let cs_pos = 10 + data_len;
            let cs_calc = body[..cs_pos].iter().fold(0u8, |a, b| a.wrapping_add(*b));
            if body[cs_pos] == cs_calc && body[cs_pos + 1] == 0x16 {
                frame_ok = true;
            }
        }
        if !frame_ok && is_resp && matches!(func, 0x11 | 0x12) {
            // 长度自纠:按读成功响应结构 DI(4)+数据 推断,扫描 CS 验证
            // 常见长度:电压电流等 6B(DI4+2),电量 12B(DI4+8),其他 8/16/20
            for try_len in [6usize, 12, 8, 16, 20, 4, l_field, l_field + 4, l_field.wrapping_sub(4)] {
                let tl = 10 + try_len + 2;
                if try_len > 200 || i + tl > data.len() {
                    continue;
                }
                let body = &data[i..i + tl];
                let cs_pos = 10 + try_len;
                let cs_calc = body[..cs_pos].iter().fold(0u8, |a, b| a.wrapping_add(*b));
                if body[cs_pos] == cs_calc && body[cs_pos + 1] == 0x16 {
                    data_len = try_len;
                    frame_ok = true;
                    break;
                }
            }
        }
        if !frame_ok {
            i += 1;
            junk += 1;
            continue;
        }
        out.push((i, 10 + data_len + 2));
        i += 10 + data_len + 2;
    }
    // 尾部残渣(不足一帧或定界失败的残余)计入垃圾
    if i < data.len() {
        junk += data.len() - i;
    }
    (out, junk)
}

/// 地址 6 字节 BCD 低位在前 → 显示串(高位在前)
pub fn addr_to_string(a: &[u8; 6]) -> String {
    a.iter().rev().map(|b| format!("{:02X}", b)).collect()
}

/// 读出帧(data 区)解码:DI(4B BCD 低位在前) + 值
/// 返回 (DI 显示串, DI 数值, 值解码文本, 是否电量类)
pub fn decode_read_data(data_area: &[u8]) -> Option<(String, String, bool)> {
    if data_area.len() < 4 {
        return None;
    }
    let di = data_area[0] as u32
        | ((data_area[1] as u32) << 8)
        | ((data_area[2] as u32) << 16)
        | ((data_area[3] as u32) << 24);
    let di_s = format!("{:08X}", ((di & 0xFF) << 24) | ((di >> 8 & 0xFF) << 16) | ((di >> 16 & 0xFF) << 8) | (di >> 24));
    let vals = &data_area[4..];
    let (name, unit, scale, is_energy) = di_name(di);
    // BCD 优先(电量/电压电流类多为 BCD 压缩);解析失败回退二进制
    if vals.iter().all(|b| (b & 0x0F) <= 9 && (b >> 4) <= 9) && !vals.is_empty() {
        // BCD 解:每字节两 nibble;645 的数据是低位字节在前
        let digits: Vec<u8> = vals.iter().rev().flat_map(|b| vec![b >> 4, b & 0x0F]).collect();
        let total: f64 = digits.iter().fold(0.0, |a, d| a * 10.0 + *d as f64);
        let scaled = total * scale;
        Some((di_s, format!("{name} {:.4} {}", scaled, unit), is_energy))
    } else {
        let raw: i32 = match vals.len() {
            2 => i16::from_le_bytes([vals[0], vals[1]]) as i32,
            4 => i32::from_le_bytes([vals[0], vals[1], vals[2], vals[3]]),
            _ => 0,
        };
        Some((di_s, format!("{name} {} ({:#x})", raw, raw), is_energy))
    }
}

/// DI 常用项:名称/单位/倍率/是否电量
fn di_name(di: u32) -> (&'static str, &'static str, f64, bool) {
    // DI 结构:高字节=组(00 电量/02 电测),次高=类,低 2 字节=项
    match di {
        0x00000000 => ("有功总电量", "kWh", 0.01, true),
        _ if di >> 24 == 0x00 && di >> 16 & 0xFF <= 0x08 => ("有功费率电量", "kWh", 0.01, true),
        0x02010000 | 0x02010100 => ("A相电压", "V", 0.1, false),
        0x02010200 => ("B相电压", "V", 0.1, false),
        0x02010300 => ("C相电压", "V", 0.1, false),
        0x02020000 | 0x02020100 => ("A相电流", "A", 0.001, false),
        0x02020200 => ("B相电流", "A", 0.001, false),
        0x02020300 => ("C相电流", "A", 0.001, false),
        0x02030000 => ("瞬时有功功率", "kW", 0.0001, false),
        0x02030100 => ("瞬时有功功率A相", "kW", 0.0001, false),
        0x02040000 => ("瞬时无功功率", "kvar", 0.0001, false),
        0x02050000 => ("功率因数", "", 0.001, false),
        0x04000101 => ("日期", "—", 1.0, false),
        0x04000102 => ("时间", "—", 1.0, false),
        0x04000401 => ("日期时间", "—", 1.0, false),
        _ => ("DI 未细分", "", 1.0, false),
    }
}

/// 解码一帧 645(扫描定位后的帧);返回摘要文本(事件经 dec.ev 直写)。
/// data = 整帧字节(68..16);pairer/addr_state 由调用方跨帧维护(暂无状态需求,预留)。
pub fn decode(dec: &mut Dec, frame: &[u8]) -> String {
    if frame.len() < 12 || frame[0] != 0x68 || frame[7] != 0x68 || frame[frame.len() - 1] != 0x16 {
        return "645 帧结构异常".into();
    }
    let addr: [u8; 6] = frame[1..7].try_into().unwrap();
    let addr_s = if addr == [0xAA; 6] {
        "通配地址".into()
    } else if addr == [0x99; 6] {
        "广播地址".into()
    } else {
        format!("表号 {}", addr_to_string(&addr))
    };
    let ctrl = frame[8];
    let l_field = frame[9] as usize;
    let is_resp = ctrl & 0x80 != 0;
    let func = ctrl & 0x3F;
    let err = ctrl & 0x40 != 0;
    let data_area = &frame[10..frame.len() - 2];

    let dir_s = if is_resp { "从站响应" } else { "主站请求" };
    let mut kids = vec![];
    let mut summary = format!("645 {dir_s} {addr_s} fn={:#04x}", ctrl);

    match (is_resp, func, err) {
        (_, 0x11, true) | (_, 0x12, true) => {
            // 出错响应:DATA = DI + ERR
            if data_area.len() >= 5 {
                let Some((di_s, _txt, _is_e)) = decode_read_data(&data_area[..4]) else { return summary };
                let err_code = data_area[4];
                dec.ev(
                    EventKind::Rule,
                    format!("[645] {} 读 {} 出错: ERR={:#04x}", addr_s, di_s, err_code),
                    None,
                );
                summary = format!("645 读出错 ERR={:#04x}", err_code);
            }
        }
        (true, 0x11 | 0x12, false) => {
            // 读成功响应:DI + 值
            if let Some((di_s, txt, _is_e)) = decode_read_data(data_area) {
                summary = format!("645 读回 {} = {}", di_s, txt);
                kids.push(dec.f_named(&format!("DI {}", di_s), Value::S(txt.clone()), 0, 0, true, "", vec![]));
            }
        }
        (false, 0x11, false) => {
            // 读请求:DI
            if data_area.len() >= 4 {
                let Some((di_s, _txt, _is_e)) = decode_read_data(data_area) else { return summary };
                summary = format!("645 {addr_s} 读请求 {}", di_s);
                kids.push(dec.f_named(&format!("读请求 DI {}", di_s), Value::Hex(data_area.to_vec()), 0, 0, false, "", vec![]));
            }
        }
        (false, 0x08, false) => {
            // 广播校时(仅观测)
            summary = "645 广播校时".into();
            kids.push(dec.f_named("广播校时(仅观测)", Value::Hex(data_area.to_vec()), 0, 0, false, "", vec![]));
        }
        _ => {
            summary = format!("645 fn={:#04x}{} {}B", ctrl, if err { " ERR" } else { "" }, data_area.len());
        }
    }
    // L 字段差异提示(长度自纠生效时)
    if l_field != data_area.len() {
        dec.ev(
            EventKind::Info,
            format!(
                "[645] L 字段={} 实际 DATA {}B(厂家不守 L,已按 DI 结构自纠)",
                l_field,
                data_area.len()
            ),
            None,
        );
    }
    let _ = &mut kids;
    let _ = &mut summary;
    summary
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::dec_for_test;

    /// 构造 645 帧(标准):68 + A[6] + 68 + C + L + DATA + CS + 16
    fn build_frame(addr: [u8; 6], ctrl: u8, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x68u8];
        f.extend_from_slice(&addr);
        f.push(0x68);
        f.push(ctrl);
        f.push(data.len() as u8);
        f.extend_from_slice(data);
        let cs = f.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        f.push(cs);
        f.push(0x16);
        f
    }

    /// 主站读请求(fn 0x11,DI 4B)
    fn read_req(addr: [u8; 6], di: u32) -> Vec<u8> {
        let di_bytes = di.to_le_bytes();
        build_frame(addr, 0x11, &di_bytes)
    }

    /// 从站读响应(fn 0x91,DI + 值)
    fn read_resp(addr: [u8; 6], di: u32, vals: &[u8]) -> Vec<u8> {
        let di_bytes = di.to_le_bytes();
        let mut data = di_bytes.to_vec();
        data.extend_from_slice(vals);
        build_frame(addr, 0x91, &data)
    }

    /// 从站出错响应(fn | 0xC0 = 0xD1,DI + ERR)
    fn err_resp(addr: [u8; 6], di: u32, err: u8) -> Vec<u8> {
        let di_bytes = di.to_le_bytes();
        let mut data = di_bytes.to_vec();
        data.push(err);
        build_frame(addr, 0x91 | 0x40, &data) // 异常标志 bit6
    }

    const ADDR: [u8; 6] = [0x34, 0x12, 0x00, 0x00, 0x00, 0x00]; // 表号 000000001234
    const DI_UA: u32 = 0x02010100; // A相电压(DI 显示串 02010100;wire 低字节在前)
    const DI_ENERGY: u32 = 0x00000000; // 有功总电量

    #[test]
    fn scan_and_length_self_heal() {
        // 长度自纠:L 字段故意写错(0x0C,厂家常见错误),实际 DI4+值2=6B → 真长 18B
        // 读响应:DI(02010100 低位在前→02 01 01 02? 注意 di.to_le_bytes 是数值 LE)
        // 用电压:DI=0x02010100,值 BCD 2201(220.1V)→ 字节 21 02
        let mut data = Vec::new();
        // DI BCD 低位在前:02010100 → 字节序 = 00 01 01 02(BCD 各 nibble)... 简化:直接用数值 LE
        data.extend_from_slice(&DI_UA.to_le_bytes());
        data.extend_from_slice(&[0x01, 0x22]); // BCD 2201 ×0.1 = 220.1V
        let wrong_l = 0x0C; // 厂家错误:L=12 实为 6
        let mut f = vec![0x68u8];
        f.extend_from_slice(&ADDR);
        f.push(0x68);
        f.push(0x91);
        f.push(wrong_l);
        f.extend_from_slice(&data);
        let cs = f.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        f.push(cs);
        f.push(0x16);
        // 加唤醒前导 FE FE
        let mut wire = vec![0xFE, 0xFE];
        wire.extend_from_slice(&f);
        // 加垃圾尾
        wire.extend_from_slice(&[0x00, 0x11]);
        let (fs, junk) = scan(&wire);
        assert_eq!(junk, 2, "垃圾尾字节");
        assert_eq!(fs.len(), 1, "长度自纠应命中");
        let (o, l) = fs[0];
        assert_eq!(&wire[o..o + l], &f, "帧内容应完整复原");
        // FE 唤醒不在帧内
        assert_eq!(wire[o], 0x68);
    }

    #[test]
    fn decode_read_response_di_voltage() {
        let resp = read_resp(ADDR, DI_UA, &[0x21, 0x02]);
        let mut dec = dec_for_test();
        let s = decode(&mut dec, &resp);
        assert!(s.contains("读回"), "{s}");
        assert!(s.contains("A相电压"), "{s}");
        assert!(dec.events.is_empty(), "正常读无事件");
    }

    #[test]
    fn decode_read_request_and_error() {
        let mut dec = dec_for_test();
        let req = read_req(ADDR, DI_ENERGY);
        let s = decode(&mut dec, &req);
        assert!(s.contains("读请求"), "{s}");
        // 出错响应
        let mut dec2 = dec_for_test();
        let err = err_resp(ADDR, DI_ENERGY, 0x02);
        let s2 = decode(&mut dec2, &err);
        assert!(s2.contains("出错"), "{s2}");
        assert!(dec2.events.iter().any(|e| e.detail.contains("出错")), "出错应产出事件");
    }

    #[test]
    fn broadcast_and_wildcard_addr() {
        let mut dec = dec_for_test();
        let req = read_req([0x99; 6], DI_ENERGY);
        let s = decode(&mut dec, &req);
        assert!(s.contains("广播地址"), "{s}");
        let mut dec2 = dec_for_test();
        let req2 = read_req([0xAA; 6], DI_ENERGY);
        let s2 = decode(&mut dec2, &req2);
        assert!(s2.contains("通配地址"), "{s2}");
    }

    #[test]
    fn resync_after_garbage() {
        // 垃圾字节 + 两帧连续:失步重扫应分别定位两帧
        let f1 = read_req(ADDR, DI_ENERGY);
        let f2 = read_resp(ADDR, DI_UA, &[0x21, 0x02]);
        let mut wire = vec![0x55, 0x66];
        wire.extend_from_slice(&f1);
        wire.extend_from_slice(&[0x77]);
        wire.extend_from_slice(&f2);
        let (fs, junk) = scan(&wire);
        assert_eq!(fs.len(), 2, "两帧都应定位: {fs:?}");
        assert_eq!(junk, 3, "垃圾字节 55 66 77");
    }
}
