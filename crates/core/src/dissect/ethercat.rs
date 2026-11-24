//! EtherCAT 报文解析(EtherType 0x88A4):报文头 + 数据报 + CoE SDO 简析 + WKC 异常事件。

use super::Dec;
use crate::model::{EventKind, Field, Value};

fn cmd_name(c: u8) -> &'static str {
    match c {
        0x00 => "NOP",
        0x01 => "APRD",
        0x02 => "APWR",
        0x03 => "APRMW",
        0x04 => "FPRD",
        0x05 => "FPWR",
        0x06 => "FPRMW",
        0x07 => "BRD",
        0x08 => "BWR",
        0x09 => "BRMW",
        0x0A => "LRD",
        0x0B => "LWR",
        0x0C => "LRW",
        0x0D => "LRMW",
        _ => "RESV",
    }
}

#[derive(Clone, Debug)]
pub struct Dgram {
    pub off: usize,
    pub cmd: u8,
    pub idx: u8,
    pub addr: u32,
    pub len: u16,
    pub wkc: u16,
}

/// 解析整帧的报文数据,返回报文列表(帧头之后)。None = 不是合法 EtherCAT 命令帧。
pub fn scan(data: &[u8]) -> Option<Vec<Dgram>> {
    if data.len() < 2 {
        return None;
    }
    let hdr = u16::from_le_bytes([data[0], data[1]]);
    let ftype = hdr >> 12;
    if ftype != 1 {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 2usize;
    while i + 12 <= data.len() {
        let cmd = data[i];
        let idx = data[i + 1];
        let addr = u32::from_le_bytes([data[i + 2], data[i + 3], data[i + 4], data[i + 5]]);
        let lenring = u16::from_le_bytes([data[i + 6], data[i + 7]]);
        let len = lenring & 0x7FF;
        if len > 2048 || i + 12 + len as usize > data.len() {
            break;
        }
        let wkc = u16::from_le_bytes([data[i + 10 + len as usize], data[i + 11 + len as usize]]);
        out.push(Dgram { off: i, cmd, idx, addr, len, wkc });
        i += 12 + len as usize;
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn coe_service_name(s: u8) -> &'static str {
    match s {
        1 => "Emergency",
        2 => "SDO",
        3 => "SDO Info",
        4 => "TxPDO",
        5 => "RxPDO",
        6 => "TxPDV",
        7 => "RxPDV",
        _ => "RESV",
    }
}

/// 解码一帧 EtherCAT(调用方已确认 scan 成功)。返回 summary。报文数据从偏移 0 开始(摄入层已剥去以太网头)。
pub fn decode(dec: &mut Dec, data: &[u8]) -> String {
    let Some(dgrams) = scan(data) else { return "无效EtherCAT".into() };
    let mut root: Vec<Field> = Vec::new();
    let mut summary_parts = vec![];
    for d in &dgrams {
        let mut kids: Vec<Field> = vec![
            dec.f("命令", Value::S(cmd_name(d.cmd).into()), d.off, 1, false, ""),
            dec.f("序号", Value::U(d.idx as u64), d.off + 1, 1, false, ""),
            dec.f("地址", Value::U(d.addr as u64), d.off + 2, 4, false, ""),
        ];
        // CoE 邮箱探测
        let data_off = d.off + 10;
        let dend = data_off + d.len as usize;
        let mut coe_txt: Option<String> = None;
        if d.len >= 10 && dend <= data.len() {
            let mblen = (u16::from_le_bytes([data[data_off], data[data_off + 1]]) & 0x03FF) as usize;
            let ty = u16::from_le_bytes([data[data_off + 4], data[data_off + 5]]);
            let mbtype = (ty >> 12) & 0xF;
            if mbtype == 3 && mblen >= 8 && data_off + 6 + mblen <= dend + 0 && mblen <= d.len as usize - 6 {
                // CoE
                let coe_hdr = u16::from_le_bytes([data[data_off + 6], data[data_off + 7]]);
                let svc = (coe_hdr >> 8) & 0x1F;
                let coe_body = data_off + 8;
                if svc == 2 && coe_body + 4 <= data.len() {
                    let c = data[coe_body];
                    let ccs = c & 0x7;
                    let idx = u16::from_le_bytes([data[coe_body + 1], data[coe_body + 2]]);
                    let sub = data[coe_body + 3];
                    let act = match ccs {
                        1 => "写",
                        2 => "读",
                        3 => "Abort",
                        4 => "写段",
                        5 => "读段",
                        _ => "?",
                    };
                    coe_txt = Some(format!("CoE SDO {} 0x{:04X}:{}", act, idx, sub));
                    kids.push(dec.f("CoE", Value::S(format!("SDO {} obj=0x{:04X} sub={}", act, idx, sub)), data_off + 6, 6, false, ""));
                    kids.push(dec.f("对象", Value::U(idx as u64), coe_body + 1, 2, false, ""));
                    kids.push(dec.f("子索引", Value::U(sub as u64), coe_body + 3, 1, false, ""));
                } else {
                    coe_txt = Some(format!("CoE {}", coe_service_name(svc as u8)));
                    kids.push(dec.f("CoE服务", Value::S(coe_service_name(svc as u8).into()), data_off + 6, 2, false, ""));
                }
            }
        }
        kids.push(dec.f("WKC", Value::U(d.wkc as u64), data_off + d.len as usize, 2, true, ""));
        let mut sum = format!("{} idx=0x{:02X} addr=0x{:08X} len={} wkc={}", cmd_name(d.cmd), d.idx, d.addr, d.len, d.wkc);
        if let Some(c) = &coe_txt {
            sum = format!("{sum} [{c}]");
        }
        // 报文节点
        let node = dec.f_named(&format!("报文#{} {}", summary_parts.len() + 1, sum), Value::None, d.off, (12 + d.len as usize) as u16, false, "", kids);
        root.push(node);
        if d.wkc == 0 {
            dec.ev(
                EventKind::WkcError,
                format!("{} datagram idx=0x{:02X} 无从站应答 (wkc=0)", cmd_name(d.cmd), d.idx),
                Some(dec.frame),
            );
        }
        dec.sig(&format!("EtherCAT·wkc(0x{:02X})", d.idx), "", d.wkc as f64);
        summary_parts.push(sum);
    }
    dec.take_fields(root);
    summary_parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Strings;

    fn lrw_frame(idx: u8, payload: &[u8], wkc: u16) -> Vec<u8> {
        let dgram_len = payload.len() as u16;
        let total = 2 + 12 + payload.len();
        let mut f = Vec::with_capacity(total);
        let fhdr = ((total - 2) as u16 & 0x7FF) | (1 << 12);
        f.extend_from_slice(&fhdr.to_le_bytes());
        f.push(0x0C); // LRW
        f.push(idx);
        f.extend_from_slice(&0x00010000u32.to_le_bytes());
        f.extend_from_slice(&dgram_len.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes()); // irq
        f.extend_from_slice(payload);
        f.extend_from_slice(&wkc.to_le_bytes());
        f
    }

    #[test]
    fn parse_lrw() {
        let f = lrw_frame(0x12, &[0x01, 0x02, 0x03, 0x04], 2);
        let dgrams = scan(&f).unwrap();
        assert_eq!(dgrams.len(), 1);
        assert_eq!(dgrams[0].cmd, 0x0C);
        assert_eq!(dgrams[0].wkc, 2);
        assert_eq!(dgrams[0].len, 4);
        let mut strings = Strings::default();
        let mut sigs = super::super::SigAcc::default();
        let mut events = vec![];
        let mut dec = Dec { strings: &mut strings, sigs: &mut sigs, events: &mut events, map: None, map104: None, frame: 0, t_ns: 0, source: 0, channel: 0, chan_label: "test".into(), fields: vec![] };
        let s = decode(&mut dec, &f);
        assert!(s.contains("LRW"));
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn wkc_zero_event() {
        let f = lrw_frame(0x20, &[0xAA; 8], 0);
        let mut strings = Strings::default();
        let mut sigs = super::super::SigAcc::default();
        let mut events = vec![];
        let mut dec = Dec { strings: &mut strings, sigs: &mut sigs, events: &mut events, map: None, map104: None, frame: 0, t_ns: 0, source: 0, channel: 0, chan_label: "test".into(), fields: vec![] };
        decode(&mut dec, &f);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::WkcError);
    }
}
