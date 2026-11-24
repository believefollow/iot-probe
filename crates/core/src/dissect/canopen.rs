//! CANopen 解析(任务卡 F1,机器人域第一优先):CAN/CANFD+DBC 之上的对象字典语义层。
//! - 覆盖:NMT(0x000 状态机命令)、SYNC(0x080)、EMCY(0x081+node 错误码表)、
//!   心跳(0x700+node 状态)、SDO 客户端请求(0x600+node)/服务端响应(0x580+node) 逐帧解码
//! - **SDO 请求/响应配对事件**(`SdoPairer`):node+index+sub 匹配,读/写事务 + RTT;
//!   abort 单列事件;请求被覆盖报"无响应"(与 Modbus 事务口径一致)
//! - TPDO/RPDO(0x180..0x5FF 函数区):标注节点/PDO 号 + 载荷
//!   (PDO 信号命名需 EDS 对象字典——**等真实 EDS 样本再开工**)
//! - 判定门槛:11 位 ID + 严格帧结构校验(NMT 命令字在码表内、心跳长度 1/状态合法、
//!   SDO 命令字模式匹配且长度 8);不满足即不判 CANopen,避免在非 CANopen 总线上误标
//! - 调用方(mod.rs CAN 分支)在 DBC 未命中时尝试本层;`decode` 返回顶层字段,None=非 CANopen

use super::Dec;
use crate::model::{EventKind, Field, Value};

/// COB-ID 函数段(11 位:id = 函数码<<7 | node,node=1..127)
pub const FC_NMT: u32 = 0x000;
pub const FC_SYNC: u32 = 0x080;
pub const FC_EMCY: u32 = 0x080; // EMCY 区 = 0x080+node(1..127)
pub const FC_TIME: u32 = 0x100;
pub const FC_SDO_TX: u32 = 0x580; // 服务端→客户端
pub const FC_SDO_RX: u32 = 0x600; // 客户端→服务端
pub const FC_HEARTBEAT: u32 = 0x700;

fn nmt_cmd_name(c: u8) -> &'static str {
    match c {
        0x01 => "Start Node",
        0x02 => "Stop Node",
        0x80 => "Enter Pre-Operational",
        0x81 => "Reset Node",
        0x82 => "Reset Communication",
        _ => "",
    }
}

/// NMT/心跳节点状态
fn node_state_name(s: u8) -> &'static str {
    match s {
        0x00 => "Boot-up",
        0x04 => "Stopped",
        0x05 => "Operational",
        0x7F => "Pre-Operational",
        _ => "",
    }
}

/// EMCY 错误码分段可读(CiA 301 eec 分段)
fn emcy_name(eec: u16) -> &'static str {
    match eec {
        0x0000 => "错误复位/无错误",
        0x1000 => "通用错误",
        0x2100..=0x21FF => "电流异常",
        0x2200..=0x22FF => "电压异常",
        0x2300..=0x23FF => "温度异常",
        0x3100..=0x31FF => "通信异常(设备)",
        0x4200..=0x42FF => "协议错误(设备)",
        0x8100..=0x81FF => "通信异常(通用)",
        0x8200..=0x82FF => "协议错误(通用)",
        0xF000..=0xF0FF => "辅助段",
        _ => "厂商/保留段",
    }
}

/// SDO 命令字节可读(客户端/服务端分开)
fn sdo_cmd_name(cmd: u8, from_server: bool) -> &'static str {
    let hi = cmd & 0xE0;
    if from_server {
        match hi {
            0x40 => "上传响应",
            0x60 => "下载响应",
            0x80 => "中止(abort)",
            0xE0 => "分段",
            _ => "",
        }
    } else {
        match hi {
            0x20 => "下载请求",
            0x40 => "上传请求",
            0x60 => "分段/流控",
            0x80 => "中止(abort)",
            0xE0 => "分段",
            _ => "",
        }
    }
}

/// expedited 数据字节数(命令字 bit2..0;0 = 分段头/非 expedited)
fn sdo_exp_len(cmd: u8) -> usize {
    if cmd & 0x02 != 0 {
        4 - ((cmd >> 1) & 0x03) as usize
    } else {
        0
    }
}

fn sdo_abort_code(data: &[u8]) -> u32 {
    // CiA 301 abort 帧:data[4..8] = 32 位中止码(LE)
    if data.len() >= 8 {
        (data[4] as u32) | ((data[5] as u32) << 8) | ((data[6] as u32) << 16) | ((data[7] as u32) << 24)
    } else {
        0
    }
}

/// 一帧 CANopen 解码入口(ext=false 由调用方保证)。
/// 返回本层顶层字段(None = 非 CANopen);事件经 dec.ev 直写。
pub fn decode(dec: &mut Dec, id: u32, data: &[u8]) -> Option<Field> {
    if id == FC_NMT {
        if data.len() == 2 && !nmt_cmd_name(data[0]).is_empty() {
            let node_s = if data[1] == 0 { "全体".into() } else { format!("node{}", data[1]) };
            let fld = dec.f_named(
                &format!("CANopen·NMT {} → {node_s}", nmt_cmd_name(data[0])),
                Value::U(data[0] as u64),
                0,
                0,
                false,
                "",
                vec![],
            );
            dec.ev(EventKind::Info, format!("[CANopen] NMT {} → {node_s}", nmt_cmd_name(data[0])), None);
            return Some(fld);
        }
        return None;
    }
    if id == FC_SYNC && data.len() <= 1 {
        return Some(dec.f("CANopen·SYNC", Value::U(data.first().copied().unwrap_or(0) as u64), 0, 0, false, ""));
    }
    let node = id & 0x7F;
    if !(1..=127).contains(&node) || data.is_empty() {
        return None;
    }
    match id >> 7 {
        1 if id > FC_EMCY => {
            // EMCY:0x081..0x0FF(node≥1)
            if data.len() < 3 {
                return None;
            }
            let eec = ((data[1] as u16) << 8) | data[0] as u16;
            let fld = dec.f_named(
                &format!("CANopen·EMCY node{node} {eec:#06X}({})", emcy_name(eec)),
                Value::U(eec as u64),
                0,
                0,
                false,
                "",
                vec![],
            );
            dec.ev(EventKind::Rule, format!("[CANopen] node{node} EMCY {eec:#06X} {}", emcy_name(eec)), None);
            Some(fld)
        }
        2 => Some(dec.f("CANopen·TIME", Value::Hex(data.to_vec()), 0, 0, false, "")),
        3..=9 => {
            // PDO 函数区:TPDO1..4(0x180/280/380/480)+ RPDO1..4(0x200/300/400/500)
            let fc = id >> 7;
            let pdo = if (3..=6).contains(&fc) { format!("TPDO{}", fc - 2) } else { format!("RPDO{}", fc - 6) };
            Some(dec.f_named(
                &format!("CANopen·{pdo}(node{node}) {}B", data.len()),
                Value::Hex(data.to_vec()),
                0,
                0,
                false,
                "",
                vec![],
            ))
        }
        11 => {
            // SDO 服务端响应
            if data.len() != 8 || sdo_cmd_name(data[0], true).is_empty() {
                return None;
            }
            let idx = ((data[2] as u16) << 8) | data[1] as u16;
            Some(sdo_frame(dec, data, idx, data[3], true, node as u8))
        }
        12 => {
            // SDO 客户端请求
            if data.len() != 8 || sdo_cmd_name(data[0], false).is_empty() {
                return None;
            }
            let idx = ((data[2] as u16) << 8) | data[1] as u16;
            Some(sdo_frame(dec, data, idx, data[3], false, node as u8))
        }
        14 => {
            // 心跳
            if data.len() != 1 || node_state_name(data[0]).is_empty() {
                return None;
            }
            Some(dec.f_named(
                &format!("CANopen·心跳 node{node} {}", node_state_name(data[0])),
                Value::U(data[0] as u64),
                0,
                0,
                false,
                "",
                vec![],
            ))
        }
        _ => None,
    }
}

fn sdo_frame(dec: &mut Dec, data: &[u8], idx: u16, sub: u8, from_server: bool, node: u8) -> Field {
    let cmd = data[0];
    let dir_word = if from_server { "SDO响应" } else { "SDO请求" };
    let n = sdo_exp_len(cmd);
    let val_s = if n > 0 {
        let raw: u64 = data[4..4 + n].iter().rev().fold(0u64, |a, b| (a << 8) | *b as u64);
        format!(" = {raw:#x}({raw})")
    } else if cmd & 0xE0 == 0x80 {
        format!(" 中止码 {:#010x}", sdo_abort_code(data))
    } else {
        String::new()
    };
    let fld = dec.f_named(
        &format!("CANopen·{dir_word} node{node} {} OD {idx:#06x}:{sub:02x}{val_s}", sdo_cmd_name(cmd, from_server)),
        Value::Hex(data.to_vec()),
        0,
        0,
        false,
        "",
        vec![],
    );
    if cmd & 0xE0 == 0x80 {
        dec.ev(
            EventKind::Rule,
            format!("[CANopen] node{node} SDO abort OD {idx:#06x}:{sub:02x} 中止码 {:#010x}", sdo_abort_code(data)),
            None,
        );
    }
    fld
}

/// SDO 请求/响应配对(F1 验收核心):node+index+sub 匹配,读/写事务 + RTT + 帧号引用。
/// 请求被同键新请求覆盖 → "无响应";abort → "被中止"(带中止码)。与 Modbus 事务口径一致。
pub struct SdoPairer {
    pending: std::collections::HashMap<(u8, u16, u8), (u32, u64, bool)>, // key → (请求帧号, t_ns, is_upload)
}

impl SdoPairer {
    pub fn new() -> Self {
        Self { pending: Default::default() }
    }

    /// 喂一帧(调用方已确认是 SDO 函数段 11/12 的 8 字节帧)
    pub fn feed(&mut self, dec: &mut Dec, fi: u32, t_ns: u64, id: u32, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let from_server = (id >> 7) == 11;
        let node = (id & 0x7F) as u8;
        let cmd = data[0];
        let idx = ((data[2] as u16) << 8) | data[1] as u16;
        let sub = data[3];
        if cmd & 0xE0 == 0x80 {
            // abort:清 pending 并报"被中止"
            if let Some((rfi, rt, up)) = self.pending.remove(&(node, idx, sub)) {
                let dt = (t_ns.saturating_sub(rt)) as f64 / 1e6;
                dec.ev(
                    EventKind::Timeout,
                    format!(
                        "[CANopen] node{node} SDO {} OD {idx:#06x}:{sub:02x} 被中止(距请求 {dt:.1}ms,中止码 {:#010x},请求帧 #{rfi})",
                        if up { "读" } else { "写" },
                        sdo_abort_code(data)
                    ),
                    Some(rfi),
                );
            }
            return;
        }
        if !from_server {
            let is_upload = cmd & 0xE0 == 0x40;
            // 同键旧请求被覆盖 → 无响应(Modbus"请求被后续请求覆盖"同款语义)
            if let Some((rfi, rt, up)) = self.pending.insert((node, idx, sub), (fi, t_ns, is_upload)) {
                let dt = (t_ns.saturating_sub(rt)) as f64 / 1e6;
                dec.ev(
                    EventKind::Timeout,
                    format!(
                        "[CANopen] node{node} SDO {} OD {idx:#06x}:{sub:02x} 无响应(请求被 {dt:.1}ms 后的后续请求覆盖,请求帧 #{rfi})",
                        if up { "读" } else { "写" }
                    ),
                    Some(rfi),
                );
            }
            return;
        }
        if let Some((rfi, rt, up)) = self.pending.remove(&(node, idx, sub)) {
            let dt = (t_ns.saturating_sub(rt)) as f64 / 1e6;
            let n = sdo_exp_len(cmd);
            let val_s = if n > 0 {
                let raw: u64 = data[4..4 + n].iter().rev().fold(0u64, |a, b| (a << 8) | *b as u64);
                format!(" = {raw:#x}({raw})")
            } else {
                "(分段/空)".into()
            };
            dec.ev(
                EventKind::Info,
                format!(
                    "[CANopen] node{node} SDO {} OD {idx:#06x}:{sub:02x}{val_s}(RTT {dt:.1}ms,请求帧 #{rfi} → 响应帧 #{fi})",
                    if up { "读" } else { "写" }
                ),
                Some(fi),
            );
        }
    }
}

impl Default for SdoPairer {
    fn default() -> Self {
        Self::new()
    }
}
