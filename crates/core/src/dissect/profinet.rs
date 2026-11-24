//! PROFINET 解析 v1(任务卡 I7 延伸;真实样本:ChangeIPUsingDCP.pcap,Wireshark wiki PROFINET/DCP):
//! EtherType 0x8892 家族按 FrameID 分类:
//! - **DCP(发现与基础配置,FrameID 0xFEFE/0xFEFF/0xFEFD 等私有变体)**:
//!   ServiceID(Identify/Get/Set/Hello) + ServiceType(req/resp) + XID 事务号 + 块遍历
//!   (Option/Suboption: 1.2=设备名, 2.3=IP 套件(IP/掩码/网关), 2.4=完整 IP, 5.5=控制)
//!   IP 块内容点分显示;**Set 请求(改设备名/改 IP)单列事件**——现场误改配置立即可见
//! - PTCP(同步,FrameID 0x0080 段):标注 Precision Time 协议帧
//! - RT(实时数据,FrameID 0x8000..0xBFFF):标注 RT 数据 + CycleCounter 载荷长度
//!   (RT 循环数据语义化需 GSDML 设备描述——等真实产线样本+GSDML 再开工)
//! - 已知样本为私有变体(FrameID 0xFEFE/0xFEFF/0xFEFD 混用),按"FEFE=Get、FEFF=Get 响应、
//!   FEFD=Set"经验映射,Summary 如实标注 FrameID 供人工复核

use super::Dec;
use crate::model::{EventKind, Value};

fn frameid_name(fid: u16) -> &'static str {
    match fid {
        0xFEFE | 0xFEFF | 0xFEFD => "DCP",
        0x0080 => "PTCP",
        0x8000..=0xBFFF => "RT",
        _ => "?",
    }
}

fn service_name(s: u8) -> &'static str {
    match s {
        1 => "Identify",
        2 => "Hello",
        4 => "Set",
        5 => "Get",
        6 => "Hello",
        _ => "?",
    }
}

/// DCP 块语义名(option, suboption)
fn block_name(o: u8, so: u8) -> &'static str {
    match (o, so) {
        (1, 2) => "设备名(NameOfStation)",
        (1, 3) => "设备 ID",
        (1, 4) => "设备角色",
        (2, 3) => "IP 套件(IP/掩码/网关)",
        (2, 4) => "完整 IP 套件",
        (2, 5) => "IP 控制",
        (5, 5) => "控制(订阅起止)",
        _ => "?",
    }
}

fn ip_str(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// DCP 块遍历:XID/头之后的所有 [option sub len(2) data] 块
fn dcp_blocks(dec: &mut Dec, payload: &[u8], start: usize) -> usize {
    let mut p = start;
    let mut n = 0usize;
    while p + 4 <= payload.len() {
        let o = payload[p];
        let so = payload[p + 1];
        let bl = u16::from_be_bytes([payload[p + 2], payload[p + 3]]) as usize;
        let d = p + 4;
        if d + bl > payload.len() {
            break;
        }
        let bdata = &payload[d..d + bl];
        let bn = block_name(o, so);
        let (txt, val) = match (o, so) {
            (2, 3) if bl >= 14 => (
                format!(
                    "IP={} 掩码={} 网关={}",
                    ip_str(&bdata[2..6]),
                    ip_str(&bdata[6..10]),
                    ip_str(&bdata[10..14])
                ),
                Value::Hex(bdata.to_vec()),
            ),
            (1, 2) => (
                format!("设备名 \"{}\"", String::from_utf8_lossy(bdata)),
                Value::Hex(bdata.to_vec()),
            ),
            _ => (
                format!("opt{o}.{so} ×{bl}B {}", bdata.iter().take(8).map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")),
                Value::Hex(bdata.to_vec()),
            ),
        };
        dec.f_named(&format!("DCP 块 {bn} [{txt}]"), val, 0, 0, false, "", vec![]);
        n += 1;
        p = d + bl;
    }
    n
}

/// 解码一帧 PROFINET(EtherType 0x8892 载荷,FrameID 起);返回摘要文本(事件经 dec.ev 直写)。
pub fn decode(dec: &mut Dec, payload: &[u8]) -> String {
    if payload.len() < 4 {
        return "PROFINET 短帧".into();
    }
    let fid = u16::from_be_bytes([payload[0], payload[1]]);
    let kind = frameid_name(fid);
    match kind {
        "DCP" => {
            if payload.len() < 12 {
                return format!("DCP FrameID={fid:#06x} 短帧");
            }
            let svc = payload[2];
            let stype = payload[3];
            let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            // 真实样本(ChangeIPUsingDCP):ServiceType 0x00=请求、0x01=响应(厂商用 bit0;
// 规范 bit7 变体等真实多厂商样本再兼容)
            let is_resp = stype != 0;
            let svc_s = service_name(svc);
            // 块遍历起点:XID(4)+rsvd(2)+delay(2) 之后
            let nblk = dcp_blocks(dec, payload, 12);
            if svc == 4 && !is_resp {
                // Set 请求:读出被改的块语义 → 事件(现场误改配置立即可见)
                let mut changed = vec![];
                let mut p = 12usize;
                while p + 4 <= payload.len() {
                    let o = payload[p];
                    let so = payload[p + 1];
                    let bl = u16::from_be_bytes([payload[p + 2], payload[p + 3]]) as usize;
                    let d = p + 4;
                    if d + bl > payload.len() {
                        break;
                    }
                    let bdata = &payload[d..d + bl];
                    match (o, so) {
                        (1, 2) => changed.push(format!("设备名 → \"{}\"", String::from_utf8_lossy(bdata))),
                        (2, 3) if bl >= 14 => {
                            changed.push(format!(
                                "IP → {} 掩码 {} 网关 {}",
                                ip_str(&bdata[2..6]),
                                ip_str(&bdata[6..10]),
                                ip_str(&bdata[10..14])
                            ))
                        }
                        _ => {}
                    }
                    p = d + bl;
                }
                if !changed.is_empty() {
                    dec.ev(
                        EventKind::Rule,
                        format!("[PROFINET] DCP Set XID={xid:#x}: {}", changed.join("; ")),
                        None,
                    );
                }
            }
            format!(
                "DCP {svc_s}{} XID={xid:#x} 块{nblk}",
                if is_resp { "响应" } else { "请求" }
            )
        }
        "PTCP" => format!("PTCP 同步帧(FrameID={fid:#06x})"),
        "RT" => format!("PROFINET RT 数据(FrameID={fid:#06x}) {}B", payload.len() - 2),
        _ => format!("PROFINET FrameID={fid:#06x}"),
    }
}
