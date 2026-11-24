//! 链路层/IP/TCP/UDP 解码 + TCP 流重组(按 seq 排序拼接,缺段显式标注)。

use super::rec;
use crate::model::{Dir, Proto, Record};
use std::collections::BTreeMap;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Pkt {
    pub t_ns: u64,
    pub link: u16,
    pub data: Vec<u8>,
}

pub fn ip2str(ip: &[u8]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

struct TcpConn {
    id: u16,
    label: String,
    dir_bufs: [BTreeMap<u32, (Vec<u8>, u64)>; 2],
}

struct ConnTable {
    conns: Vec<TcpConn>,
    map: HashMap<(([u8; 4], u16), ([u8; 4], u16)), usize>, // 首包方向 key → conn
    udp_map: HashMap<(([u8; 4], u16), ([u8; 4], u16)), u16>,
    next_id: u16,
}

impl ConnTable {
    fn new() -> Self {
        ConnTable { conns: vec![], map: HashMap::new(), udp_map: HashMap::new(), next_id: 1 }
    }
    fn conn_for(&mut self, src: ([u8; 4], u16), dst: ([u8; 4], u16)) -> usize {
        if let Some(&i) = self.map.get(&(src, dst)) {
            return i;
        }
        if let Some(&i) = self.map.get(&(dst, src)) {
            return i;
        }
        let id = self.next_id;
        self.next_id += 1;
        let label = format!("{}:{} ↔ {}:{}", ip2str(&src.0), src.1, ip2str(&dst.0), dst.1);
        self.conns.push(TcpConn { id, label, dir_bufs: [BTreeMap::new(), BTreeMap::new()] });
        self.map.insert((src, dst), self.conns.len() - 1);
        self.conns.len() - 1
    }
    fn udp_chan(&mut self, src: ([u8; 4], u16), dst: ([u8; 4], u16)) -> u16 {
        if let Some(&i) = self.udp_map.get(&(src, dst)) {
            return i;
        }
        if let Some(&i) = self.udp_map.get(&(dst, src)) {
            return i;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.udp_map.insert((src, dst), id);
        id
    }
}

pub fn build_streams(
    pkts: &[Pkt],
    out: &mut Vec<Record>,
    labels: &mut HashMap<u16, String>,
    warns: &mut Vec<String>,
) {
    let mut ct = ConnTable::new();
    let mut skipped = 0usize;
    for p in pkts {
        let (link_data, l3type) = match strip_link(p) {
            Some(x) => x,
            None => {
                skipped += 1;
                continue;
            }
        };
        match l3type {
            0x8892 => {
                // PROFINET 家族(EtherType 0x8892):DCP/PTCP/RT 按 FrameID 在解码层分类
                let mut r = rec(p.t_ns, Dir::Unknown, Proto::Pn, link_data.to_vec());
                r.channel = 0;
                labels.entry(0).or_insert_with(|| "PROFINET".into());
                out.push(r);
            }
            0x88A4 => {
                let mut r = rec(p.t_ns, Dir::Unknown, Proto::EtherCat, link_data.to_vec());
                r.channel = 0;
                labels.entry(0).or_insert_with(|| "EtherCAT".into());
                out.push(r);
            }
            204 => {
                // LINKTYPE_CAN_SOCKETCAN:Wireshark 抓的 CAN 总线
                if !parse_socketcan(p.t_ns, link_data, out) {
                    skipped += 1;
                }
                labels.entry(0).or_insert_with(|| "SocketCAN".into());
            }
            0x0806 => {
                let mut r = rec(p.t_ns, Dir::Unknown, Proto::Arp, link_data.to_vec());
                r.channel = 0xFFFF;
                labels.entry(0xFFFF).or_insert_with(|| "ARP".into());
                out.push(r);
            }
            0x0800 => {
                if !parse_ipv4(p.t_ns, link_data, &mut ct, out) {
                    skipped += 1;
                }
            }
            _ => skipped += 1,
        }
    }
    // 冲刷 TCP 流
    for conn in &ct.conns {
        labels.insert(conn.id, conn.label.clone());
        for side in 0..2 {
            flush_dir(conn, side, out);
        }
    }
    if skipped > pkts.len() / 2 && !pkts.is_empty() {
        warns.push(format!("抓包中 {skipped}/{} 个数据包无法识别(IPv6/未知协议?)", pkts.len()));
    }
}

/// DLT_CAN_SOCKETCAN(204):struct can_frame(16B) / canfd_frame(id,len,flags,res0,res1,data[64])
fn parse_socketcan(t_ns: u64, data: &[u8], out: &mut Vec<Record>) -> bool {
    if data.len() < 8 {
        return false;
    }
    let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let eff = raw & 0x8000_0000 != 0;
    let _rtr = raw & 0x4000_0000 != 0;
    let id = (raw & 0x1FFF_FFFF) | ((eff as u32) << 31);
    let (proto, d) = if data.len() > 16 {
        // canfd_frame:len 在 byte4,flags 在 byte5,数据从 byte8
        let len = (data[4] as usize).min(data.len() - 8);
        (Proto::CanFd, &data[8..8 + len])
    } else {
        // can_frame:dlc 在 byte4,数据从 byte8
        let dlc = (data[4] as usize & 0x0F).min(8).min(data.len() - 8);
        (Proto::Can, &data[8..8 + dlc])
    };
    let mut r = rec(t_ns, Dir::Unknown, proto, d.to_vec());
    r.can_id = Some(id);
    out.push(r);
    true
}

fn strip_link(p: &Pkt) -> Option<(&[u8], u16)> {    match p.link {
        1 => {
            // Ethernet
            if p.data.len() < 14 {
                return None;
            }
            let mut et = u16::from_be_bytes([p.data[12], p.data[13]]);
            let mut off = 14;
            while et == 0x8100 || et == 0x88A8 {
                if p.data.len() < off + 4 {
                    return None;
                }
                et = u16::from_be_bytes([p.data[off + 2], p.data[off + 3]]);
                off += 4;
            }
            Some((&p.data[off..], et))
        }
        113 => {
            // Linux SLL
            if p.data.len() < 16 {
                return None;
            }
            let et = u16::from_be_bytes([p.data[14], p.data[15]]);
            Some((&p.data[16..], et))
        }
        101 | 12 => Some((&p.data[..], 0x0800)), // RAW IP
        204 => Some((&p.data[..], 204)), // CAN_SOCKETCAN(原始 can_frame)
        0 => {
            if p.data.len() < 4 {
                return None;
            }
            Some((&p.data[4..], 0x0800)) // NULL/loopback
        }
        _ => None,
    }
}

fn parse_ipv4(t_ns: u64, data: &[u8], ct: &mut ConnTable, out: &mut Vec<Record>) -> bool {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return false;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return false;
    }
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    let end = total.clamp(ihl, data.len());
    let proto = data[9];
    let src: [u8; 4] = [data[12], data[13], data[14], data[15]];
    let dst: [u8; 4] = [data[16], data[17], data[18], data[19]];
    let payload = &data[ihl..end];
    match proto {
        17 => {
            // UDP
            if payload.len() < 8 {
                return false;
            }
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            let chan = ct.udp_chan((src, sp), (dst, dp));
            let mut r = rec(t_ns, Dir::Unknown, Proto::Udp, payload[8..].to_vec());
            r.channel = chan;
            out.push(r);
            true
        }
        6 => {
            // TCP
            if payload.len() < 20 {
                return false;
            }
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let doff = (payload[12] >> 4) as usize * 4;
            let flags = payload[13];
            if doff < 20 || doff > payload.len() {
                return false;
            }
            let body = &payload[doff..];
            let idx = ct.conn_for((src, sp), (dst, dp));
            // side: 与建连方向一致(A→B = side0)
            let side = if ct.map.contains_key(&((src, sp), (dst, dp))) { 0 } else { 1 };
            if body.is_empty() {
                return true; // 纯 ACK/SYN 等
            }
            let conn = &mut ct.conns[idx];
            let s = if flags & 0x02 != 0 { seq.wrapping_add(1) } else { seq }; // SYN 占一个序号
            // 同 seq 重复段:按序追加(合成/漏抓抓包常出现同 seq 载荷不同的段,
            // 直接覆盖会把整条单向流吞成 1 条记录 —— threat 104 样本回归发现)
            match conn.dir_bufs[side].get_mut(&s) {
                Some((prev, _)) => prev.extend_from_slice(body),
                None => {
                    conn.dir_bufs[side].insert(s, (body.to_vec(), t_ns));
                }
            }
            true
        }
        _ => false,
    }
}

const MAX_RUN: usize = 1 << 20;

fn flush_dir(conn: &TcpConn, side: usize, out: &mut Vec<Record>) {
    let buf = &conn.dir_bufs[side];
    let dir = if side == 0 { Dir::Tx } else { Dir::Rx };
    let mut pos: u32 = 0;
    let mut started = false;
    let mut cur: Vec<u8> = Vec::new();
    let mut cur_t = 0u64;
    let mut gap = false;
    let mut drops = 0usize;
    for (&seq, (data, t)) in buf.iter() {
        if !started {
            pos = seq;
            cur_t = *t;
            started = true;
        }
        let end = seq.wrapping_add(data.len() as u32);
        if seq > pos {
            // 缺段
        if !cur.is_empty() {
            let mut r = rec(cur_t, dir, Proto::Tcp, std::mem::take(&mut cur));
            r.channel = conn.id;
            r.gap_n = if gap { 1 } else { 0 };
            out.push(r);
        }
        drops += (seq.wrapping_sub(pos)) as usize;
            pos = seq;
            cur_t = *t;
            gap = true;
        }
        if end.wrapping_sub(pos) > 0 && end > pos {
            let skip = pos.wrapping_sub(seq) as usize;
            if skip < data.len() {
                cur.extend_from_slice(&data[skip..]);
            }
            pos = end;
        }
        if cur.len() >= MAX_RUN {
            let mut r = rec(cur_t, dir, Proto::Tcp, std::mem::take(&mut cur));
            r.channel = conn.id;
            r.gap_n = if gap { 1 } else { 0 };
            out.push(r);
            gap = false;
            cur_t = *t;
        }
    }
    if !cur.is_empty() {
        let mut r = rec(cur_t, dir, Proto::Tcp, cur);
        r.channel = conn.id;
        r.gap_n = if gap { 1 } else { 0 };
        out.push(r);
    }
    if drops > 0 {
        // 丢段信息通过 record.gap 标注,dissect 阶段生成事件
    }
    let _ = drops;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![];
        h.extend_from_slice(&sp.to_be_bytes());
        h.extend_from_slice(&dp.to_be_bytes());
        h.extend_from_slice(&seq.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes());
        h.push(0x50);
        h.push(0x18);
        h.extend_from_slice(&8192u16.to_be_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]);
        h.extend_from_slice(payload);
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&((20 + h.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&1u16.to_be_bytes());
        ip.extend_from_slice(&[0x40, 0x00, 64, 6]);
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&h);
        ip
    }

    fn eth_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![];
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x66]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn tcp_reassembly_modbus() {
        let src = [192, 168, 1, 10];
        let dst = [192, 168, 1, 50];
        let req = vec![0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02];
        let resp = vec![0x00u8, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x41, 0x20, 0x00, 0x00];
        let pkts = vec![
            Pkt { t_ns: 1000, link: 1, data: eth_frame(&ipv4_tcp(src, dst, 52000, 502, 1000, &req)) },
            Pkt { t_ns: 2000, link: 1, data: eth_frame(&ipv4_tcp(dst, src, 502, 52000, 5000, &resp)) },
        ];
        let mut out = vec![];
        let mut labels = std::collections::HashMap::new();
        let mut warns = vec![];
        build_streams(&pkts, &mut out, &mut labels, &mut warns);
        assert_eq!(out.len(), 2, "应有 TX/RX 两条流记录, got {out:?}");
        assert_eq!(out[0].dir, Dir::Tx);
        assert_eq!(out[0].data.as_ref(), &req[..]);
        assert_eq!(out[1].dir, Dir::Rx);
        assert_eq!(out[1].data.as_ref(), &resp[..]);
        assert!(labels.contains_key(&out[0].channel));
    }
}
