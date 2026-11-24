//! S7comm 解析(西门子 S7 以太网协议;真实样本:s7comm_reading_plc_status.pcap,Wireshark wiki):
//! TPKT(0x03 00 + 长度) → COTP(DT 数据 / CR·CC 连接) → S7 PDU(0x32 魔数)。
//! - ROSCTR:Job(1) / Ack(2) / Ack_Data(3) / Userdata(7)
//! - Read/Write Var(fn 0x04/0x05):S7ANY 变量项解码——存储区(I/Q/M/DB/P/DI/T/C)+DB 号+字节地址+数量
//! - Ack_Data 返回码:0x0A=成功,其余分级事件(fault);**Job/Ack_Data 按 pdu_ref 配对**(读/写事务+RTT,帧号引用)
//! - v1 不解:Userdata 组内结构、Upload/Download 数据体、大端 SzL 条目外的引用——按摘要层展示

use super::Dec;
use crate::model::{EventKind, Field, Value};

/// ROSCTR 名
fn rosctr_name(r: u8) -> &'static str {
    match r {
        1 => "Job(请求)",
        2 => "Ack(确认)",
        3 => "Ack_Data(响应)",
        7 => "Userdata",
        _ => "?",
    }
}

/// S7 功能码名(param[0])
fn fn_name(f: u8) -> &'static str {
    match f {
        0x04 => "Read Var",
        0x05 => "Write Var",
        0x1A => "Upload",
        0x1B => "Download",
        0x1D => "Request Download",
        0x1E => "Download Ended",
        0x1F => "Upload Ended",
        0x28 => "Insert Block",
        0x29 => "Delete Block",
        0xF0 => "Setup Communication",
        _ => "",
    }
}

/// 存储区名(S7ANY area 字节)
fn area_name(a: u8) -> &'static str {
    match a {
        0x81 => "I(输入)",
        0x82 => "Q(输出)",
        0x83 => "M(位存储)",
        0x84 => "DB",
        0x85 => "DI(全局DB)",
        0x86 => "P(外设)",
        0x1C => "T(定时器)",
        0x1D => "C(计数器)",
        0x00 => "P(外设)",
        _ => "?",
    }
}

/// Ack_Data 返回码
fn ret_code_name(c: u8) -> &'static str {
    match c {
        0x00 => "保留",
        0x03 => "保留(非法)",
        0x05 => "地址非法",
        0x06 => "数据类型不支持",
        0x07 => "访问对象不存在",
        0x08 => "访问值非法",
        0x09 => "读取非法",
        0x0A => "成功",
        0x0B => "写非法",
        0x0D => "诊断/服务失败",
        _ => "未知",
    }
}

/// TPKT 帧扫描:返回 (偏移, 总长) 列表 + 无法定界字节数。
/// 接受条件:TPKT 头(0x03 00 + 合理长度)且内层 COTP 长度字节自洽。
pub fn scan(data: &[u8]) -> (Vec<(usize, usize)>, usize) {
    let mut out = vec![];
    let mut junk = 0usize;
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i] != 0x03 || data[i + 1] != 0x00 {
            i += 1;
            junk += 1;
            continue;
        }
        let total = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        if total < 7 || i + total > data.len() {
            i += 1;
            junk += 1;
            continue;
        }
        // COTP 自洽:长度字节 + 类型 ∈ 已知集
        let co = i + 4;
        let cl = data[co] as usize;
        if cl < 2 || co + 1 + cl > i + total {
            i += 1;
            junk += 1;
            continue;
        }
        let cotp_t = data[co + 1];
        if !matches!(cotp_t, 0xF0 | 0xE0 | 0xD0 | 0xC0 | 0x81 | 0x02) {
            i += 1;
            junk += 1;
            continue;
        }
        out.push((i, total));
        i += total;
    }
    (out, junk)
}


/// 解码一个 TPKT 帧(TPKT+COTP+S7);返回 (顶层字段, 摘要文本)。None = 非 S7 帧。
pub fn decode(dec: &mut Dec, data: &[u8], off: usize, len: usize, pairer: &mut S7Pairer, fi: u32, t_ns: u64) -> Option<(Field, String)> {
    if off + len > data.len() || len < 12 {
        return None;
    }
    let body = &data[off..off + len];
    let co = 4usize;
    let cl = body[co] as usize;
    let cotp_t = body[co + 1];
    let s7 = co + 1 + cl;
    // COTP 连接类帧(CC/CR)无 S7 载荷且可能恰好占满 TPKT:先于 S7 边界检查分支
    match cotp_t {
        0xE0 => return Some((dec.f("S7comm·COTP 连接请求", Value::None, 0, 0, false, ""), "COTP 连接请求".into())),
        0xD0 => return Some((dec.f("S7comm·COTP 连接确认", Value::None, 0, 0, false, ""), "COTP 连接确认".into())),
        0xF0 => {}
        _ => return None,
    }
    if s7 + 10 > len || body[s7] != 0x32 {
        return None; // DT 帧但无 0x32:Keep-alive/异常
    }
    let rosctr = body[s7 + 1];
    let pdu_ref = u16::from_be_bytes([body[s7 + 4], body[s7 + 5]]);
    let param_len = u16::from_be_bytes([body[s7 + 6], body[s7 + 7]]) as usize;
    let data_len = u16::from_be_bytes([body[s7 + 8], body[s7 + 9]]) as usize;
    let param = body.get(s7 + 10..s7 + 10 + param_len).unwrap_or(&[]);
    let sdata = body.get(s7 + 10 + param_len..s7 + 10 + param_len + data_len).unwrap_or(&[]);

    match cotp_t {
        _ => {
            let (fname, detail) = decode_s7(rosctr, pdu_ref, param, sdata);
            let top = dec.f_named(
                &format!("S7comm·{} pdu_ref={} {}", rosctr_name(rosctr), pdu_ref, detail),
                Value::Hex(body[s7..].to_vec()),
                0,
                0,
                false,
                "",
                vec![],
            );
            pairer.feed(dec, fi, t_ns, pdu_ref, rosctr, param, sdata);
            // Ack_Data 失败单列事件(fault 级)
            if rosctr == 3 && sdata.len() >= 2 && sdata[0] != 0x0A {
                dec.ev(
                    EventKind::Rule,
                    format!(
                        "[S7comm] pdu_ref={} Ack_Data 失败: {}({:#04x},{:#04x}) fn={}",
                        pdu_ref,
                        ret_code_name(sdata[0]),
                        sdata[0],
                        sdata[1],
                        fn_name(param.first().copied().unwrap_or(0))
                    ),
                    None,
                );
            }
            let text = match rosctr_name(rosctr) {
                "Userdata" => format!("Userdata pdu_ref={pdu_ref}"),
                _ => format!("{fname} pdu_ref={pdu_ref} {detail}"),
            };
            Some((top, text))
        }
    }
}

/// S7 参数/数据解码:ROSCTR + 功能 + Read/Write Var 项 + Ack_Data 返回码
fn decode_s7(rosctr: u8, pdu_ref: u16, param: &[u8], sdata: &[u8]) -> (&'static str, String) {
    let Some(&fnb) = param.first() else { return ("", String::new()) };
    let fname = fn_name(fnb);
    match fnb {
        0xF0 => {
            if rosctr == 1 {
                let max_ampdu = param.get(4..6).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0);
                ("通信建立", format!("Setup Communication(max PDU {})", max_ampdu))
            } else {
                ("通信建立确认", format!("Setup Communication ack(max PDU {})", param.get(4..6).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0)))
            }
        }
        0x04 | 0x05 => {
            let rw = if fnb == 0x04 { "读" } else { "写" };
            let count = param.get(1).copied().unwrap_or(0);
            let mut detail = format!("{rw} Var ×{count} 项(ref {pdu_ref}):");
            // 变量项:0x12 头;S7ANY(id=0x10): [access u8, count u16, db u16, area u8, addr 3B]
            let mut p = 2usize;
            let mut parsed = 0usize;
            while p + 2 <= param.len() && param[p] == 0x12 && parsed < 4 {
                let ilen = param[p + 1] as usize;
                if p + 2 + ilen > param.len() {
                    break;
                }
                let item = &param[p + 2..p + 2 + ilen];
                if ilen >= 9 && item[0] == 0x10 {
                    let cnt = u16::from_be_bytes([item[1], item[2]]);
                    let db = u16::from_be_bytes([item[3], item[4]]);
                    let area = item[5];
                    let addr = ((item[6] as u32) << 16) | ((item[7] as u32) << 8) | item[8] as u32;
                    let byte_addr = addr / 8;
                    let d = match area {
                        0x84 => format!("DB{db}.DBX{byte_addr}.{} ×{cnt}", access_name(item[0])),
                        a => format!("{} {byte_addr} ×{cnt}", area_name(a)),
                    };
                    detail.push_str(&format!(" [{d}]"));
                    parsed += 1;
                }
                p += 2 + ilen;
            }
            if rosctr == 3 && sdata.len() >= 2 {
                let rc = sdata[0];
                detail.push_str(&format!(" → {}", ret_code_name(rc)));
            }
            (fname, detail)
        }
        _ => (fname, String::new()),
    }
}

fn access_name(a: u8) -> &'static str {
    match a {
        0x01 => "位",
        0x02 => "字节",
        0x03 => "字",
        0x04 => "双字",
        _ => "?",
    }
}

/// S7 Job/Ack_Data 事务配对:pdu_ref 匹配 → 读/写事务事件(RTT+帧号引用)
pub struct S7Pairer {
    pending: std::collections::HashMap<u16, (u32, u64, u8)>, // pdu_ref → (请求帧号, t_ns, fn)
}

impl S7Pairer {
    pub fn new() -> Self {
        Self { pending: Default::default() }
    }

    pub fn feed(&mut self, dec: &mut Dec, fi: u32, t_ns: u64, pdu_ref: u16, rosctr: u8, param: &[u8], sdata: &[u8]) {
        match rosctr {
            1 => {
                let fnb = param.first().copied().unwrap_or(0);
                // 同 ref 旧请求被覆盖 → 无响应
                if let Some((rfi, rt, old_fn)) = self.pending.insert(pdu_ref, (fi, t_ns, fnb)) {
                    let dt = (t_ns.saturating_sub(rt)) as f64 / 1e6;
                    dec.ev(
                        EventKind::Timeout,
                        format!(
                            "[S7comm] pdu_ref={pdu_ref} {} 无响应(请求被 {dt:.1}ms 后的后续请求覆盖,请求帧 #{rfi})",
                            fn_name(old_fn)
                        ),
                        Some(rfi),
                    );
                }
            }
            3 => {
                if let Some((rfi, rt, old_fn)) = self.pending.remove(&pdu_ref) {
                    let dt = (t_ns.saturating_sub(rt)) as f64 / 1e6;
                    // Setup Communication(0xF0)无返回码字段,恒"完成";其余按 Ack_Data 首字节判
                    let ok = if old_fn == 0xF0 { true } else { sdata.first().copied().map(|c| c == 0x0A).unwrap_or(false) };
                    dec.ev(
                        if ok { EventKind::Info } else { EventKind::Timeout },
                        format!(
                            "[S7comm] pdu_ref={pdu_ref} {} {}(RTT {dt:.1}ms,请求帧 #{rfi} → 响应帧 #{fi})",
                            fn_name(old_fn),
                            if ok { "完成" } else { "失败" }
                        ),
                        Some(fi),
                    );
                }
            }
            _ => {}
        }
    }
}

impl Default for S7Pairer {
    fn default() -> Self {
        Self::new()
    }
}
