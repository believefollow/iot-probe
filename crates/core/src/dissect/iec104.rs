//! IEC 60870-5-104(以及 101 平衡式线路上同构 APDU)的定界与解码。
//! 结构:APCI(0x68 长度 + 4 字节控制域)+ ASDU(类型/VSQ/COT/CA/信息体)。
//! 只做报文级解码与信号提取,不做链路状态机;APDU 可跨 TCP 段的前提由
//! 摄入层 TCP 重组保证(与 MQTT 同假设)。

use super::{Dec, map104};
use crate::model::Value;

/// 控制域种类(scan 的第三个返回值):1=I 帧,2=S 帧,3=U 帧
pub const KIND_I: u8 = 1;
pub const KIND_S: u8 = 2;
pub const KIND_U: u8 = 3;

/// ASDU 类型表:名称 + 单信息体"值区"字节数(不含 3 字节 IOA;含质量位/时标)。
/// None 表示不认识的结构,只按条数推进(仍可定界)。
fn type_info(t: u8) -> Option<(&'static str, usize)> {
    Some(match t {
        1 => ("M_SP_NA_1", 1),    // 单点遥信
        2 => ("M_SP_TA_1", 4),    // 单点(时标 3B)
        3 => ("M_DP_NA_1", 1),    // 双点遥信
        4 => ("M_DP_TA_1", 4),
        5 => ("M_ST_NA_1", 2),    // 步位置
        7 => ("M_BO_NA_1", 5),    // 32bit 串
        9 => ("M_ME_NA_1", 3),    // 归一化遥测
        10 => ("M_ME_TA_1", 6),
        11 => ("M_ME_NB_1", 3),   // 标度化遥测
        12 => ("M_ME_TB_1", 6),
        13 => ("M_ME_NC_1", 5),   // 短浮点遥测
        14 => ("M_ME_TC_1", 8),
        15 => ("M_IT_NA_1", 5),   // 累计量
        16 => ("M_IT_TA_1", 8),
        30 => ("M_SP_TB_1", 8),   // 带时标 CP56
        31 => ("M_DP_TB_1", 8),
        32 => ("M_ST_TB_1", 9),
        34 => ("M_ME_TD_1", 10),
        35 => ("M_ME_TE_1", 10),
        36 => ("M_ME_TF_1", 12),
        45 => ("C_SC_NA_1", 1),   // 单点遥控
        46 => ("C_DC_NA_1", 1),   // 双点遥控
        47 => ("C_RC_NA_1", 1),   // 步调节遥控
        48 => ("C_SE_NA_1", 3),   // 设定值(归一化)
        49 => ("C_SE_NB_1", 3),   // 设定值(标度化)
        50 => ("C_SE_NC_1", 5),   // 设定值(短浮点)
        58 => ("C_SC_TA_1", 8),
        59 => ("C_DC_TA_1", 8),
        70 => ("M_EI_NA_1", 1),   // 初始化结束
        100 => ("C_IC_NA_1", 1),  // 总召唤
        101 => ("C_CI_NA_1", 1),  // 电度总召唤
        102 => ("C_RD_NA_1", 0),  // 读
        103 => ("C_CS_NA_1", 7),  // 时钟同步
        104 => ("C_TS_NA_1", 1),  // 测试命令
        _ => return None,
    })
}

fn cot_name(c: u8) -> &'static str {
    match c {
        1 => "周期",
        2 => "背景",
        3 => "突发",
        4 => "初始化",
        5 => "请求",
        6 => "激活",
        7 => "激活确认",
        8 => "停止激活",
        9 => "激活结束",
        10 => "停止确认",
        11 => "结束确认",
        20 => "响应总召",
        44 => "未知类型",
        _ => "",
    }
}

fn qds_str(q: u8) -> String {
    // 质量位:IV NT SB BL(高 4 位)
    let mut s = vec![];
    if q & 0x80 != 0 { s.push("IV"); }
    if q & 0x40 != 0 { s.push("NT"); }
    if q & 0x20 != 0 { s.push("SB"); }
    if q & 0x10 != 0 { s.push("BL"); }
    if s.is_empty() { "良好".into() } else { s.join("/") }
}

/// CP56Time2a → (ms, 可读串)。IV 位无效时标注。
fn cp56(b: &[u8]) -> Option<(u64, String)> {
    if b.len() < 7 { return None; }
    let ms = b[0] as u64 | (b[1] as u64) << 8;
    let min = b[2] & 0x3F;
    let hour = b[3] & 0x1F;
    let day = b[4] & 0x1F;
    let month = b[5] & 0x0F;
    let year = 2000 + (b[6] & 0x7F) as i32;
    let iv = b[2] & 0x80 != 0;
    let s = format!("{year}-{month:02}-{day:02} {hour:02}:{min:02}.{ms:03}{}",
        if iv { "(IV)" } else { "" });
    Some((ms, s))
}

/// 扫描字节流,定界 104 APDU。返回 (帧列表 (off, len, kind), 未定界字节数)。
/// 宽松在"未识别类型仍可定界",严格在结构:0x68 起始、长度 4..=253、恰好收尾、
/// U/S 帧长度必须 4、I 帧 ASDU 至少 2 字节且类型/VSQ/COT 合法。
pub fn scan(data: &[u8]) -> (Vec<(usize, usize, u8)>, usize) {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut junk = 0usize;
    while i + 2 <= data.len() {
        if data[i] != 0x68 {
            i += 1;
            junk += 1;
            continue;
        }
        let len = data[i + 1] as usize;
        if !(4..=253).contains(&len) {
            i += 1;
            junk += 1;
            continue;
        }
        let total = 2 + len;
        if i + total > data.len() {
            break; // 尾部残包:不计 junk(可能被截断)
        }
        let c1 = data[i + 2];
        // 控制域分类(IEC 60870-5-104):C1 低两位 = I:00 / S:01 / U:11。
        // (回归:先前用 c1&0x02 分 S/U,S 帧带奇数 VR 时误判 U 丢帧——S 帧序号在 C3/C4,C1 恒 0x01)
        // I: c1 bit0=0;S: c1 bit0=1 且 c2 bit0=0;U: c1/c2 bit0 都=1
        // (回归:S 帧带奇数 VR 时 c1&0x02 会误判 U,c1&0xFC 不在 U 码表 → 整流被丢)
        // 控制域分类(IEC 60870-5-104):C1 bit0=0 → I 帧(VS 左移 1 位编码,bit0 恒 0;
        // 奇数 VS 时 C1 低两位=0x02 → 不可用 c1&0x03 三分支,否则奇数序号 I 帧整帧丢失);
        // C1=0x01(bit0=1,bit1=0) → S 帧;C1 低两位=11 → U 帧
        let kind = if c1 & 0x01 == 0 { KIND_I } else if c1 & 0x02 == 0 { KIND_S } else { KIND_U };
        let ok = match kind {
            KIND_U => len == 4 && matches!(c1 & 0xFC, 0x04 | 0x08 | 0x10 | 0x14 | 0x40 | 0x44 | 0x80),
            KIND_S => len == 4,
            _ => {
                // I 帧:ASDU ≥ 2B,类型非 0,VSQ 数量 1..=64,COT 主域 ≤ 47
                if len < 6 { false } else {
                    let t = data[i + 6];
                    let vsq = data[i + 7];
                    let cot = data[i + 8] & 0x3F;
                    t != 0 && (vsq & 0x7F) >= 1 && (vsq & 0x7F) <= 64 && cot <= 47
                }
            }
        };
        if !ok {
            i += 1;
            junk += 1;
            continue;
        }
        out.push((i, total, kind));
        i += total;
    }
    if i < data.len() {
        // 走到结尾仍剩余:残包或垃圾
        let rest = data.len() - i;
        if rest > 253 {
            junk += rest; // 太长不是残包,全算垃圾
        }
    }
    (out, junk)
}

/// 解码单个 APDU(已在 scan 中定界),返回摘要。字段树 + 信号写入 dec。
pub fn decode(dec: &mut Dec, data: &[u8], off: usize, len: usize) -> String {
    if off + len > data.len() || len < 6 {
        return format!("104 短帧 {len}B");
    }
    // 点表(MVP ②):(类型,IOA) → 工程名/变比/单位;通配(ty=0)条目两级命中
    let pt_idx: std::collections::HashMap<(u8, u32), &map104::Pt104> = dec
        .map104
        .map(|m| m.index())
        .unwrap_or_default();
    let apdu = &data[off..off + len];
    let c1 = apdu[2];
    let kind = if c1 & 0x01 == 0 { KIND_I } else if c1 & 0x02 == 0 { KIND_S } else { KIND_U };
    let mut kids = vec![];
    match kind {
        KIND_U => {
            let name = match c1 & 0xFC {
                0x04 => "STARTDT_ACT",
                0x08 => "STARTDT_CON",
                0x10 => "STOPDT_ACT",
                0x14 => "STOPDT_CON",
                0x40 => "TESTFR_ACT",
                _ => "TESTFR_CON",
            };
            kids.push(dec.f(name, Value::None, 2, 4, false, ""));
            return format!("U {name}");
        }
        KIND_S => {
            let nr = ((apdu[3] as u16) >> 1) | ((apdu[4] as u16) & 1) << 7;
            kids.push(dec.f("SUPERVISORY", Value::U(nr as u64), 2, 4, false, ""));
            return format!("S NR={nr}");
        }
        _ => {}
    }
    // I 帧:VS/VR + ASDU
    let vs = (c1 >> 1) as u16 | ((apdu[3] as u16) & 1) << 7;
    let vr = ((apdu[4] as u16) >> 1) | ((apdu[5] as u16) & 1) << 7;
    let asdu = &apdu[6..];
    if asdu.len() < 2 {
        return format!("I VS={vs} VR={vr} 空ASDU");
    }
    let t = asdu[0];
    let vsq = asdu[1];
    let sq = vsq & 0x80 != 0;
    let num = (vsq & 0x7F) as usize;
    let cot_raw = asdu[2];
    let cot = cot_raw & 0x3F;
    let pn = if cot_raw & 0x40 != 0 { "-" } else { "+" };
    // 标准布局(含 OA,2026-11-21 真实样本裁决):[0]ty [1]vsq [2]cot [3]OA [4]ca_lo [5]ca_hi [6..9]ioa
    // ca 在 [4..6](LE & 0x0FFF);body 从 [6..] 起(此前错读 [5..],IOA 全体 ×256 偏移)
    let ca = if asdu.len() >= 6 { u16::from_le_bytes([asdu[4], asdu[5]]) & 0x0FFF } else { 0 };
    let body = if asdu.len() >= 6 { &asdu[6..] } else { &[][..] };
    let (tname, vlen) = match type_info(t) {
        Some(x) => x,
        None => {
            kids.push(dec.f(&format!("TYPE_{t}"), Value::None, 6, 1, false, ""));
            return format!("I VS={vs} VR={vr} TYPE_{t} ca={ca} ×{num}(未知类型)");
        }
    };
    let cot_s = cot_name(cot);
    // 信息体遍历
    let mut sigs_n = 0usize;
    for i in 0..num {
        let base = if sq {
            // 序列:仅首对象带 IOA
            if i == 0 {
                if body.len() < 3 { break; }
                let ioa = ioa_of(body);
                if decode_obj(dec, t, tname, vlen, Some(ioa), &body[3..], &mut kids, ca, &pt_idx) { sigs_n += 1; }
                3 + vlen
            } else {
                let p = 3 + vlen + i * vlen;
                if p + vlen > body.len() { break; }
                let ioa0 = ioa_of(body);
                if decode_obj(dec, t, tname, vlen, Some(ioa0 + i as u32), &body[p..], &mut kids, ca, &pt_idx) { sigs_n += 1; }
                p + vlen
            }
        } else {
            let p = i * (3 + vlen);
            if p + 3 + vlen > body.len() {
                // C_RD_NA_1 等 vlen=0 的命令体不足时按已知长度收尾
                if vlen == 0 && p + 3 <= body.len() {
                    let ioa = ioa_of(&body[p..]);
                    decode_obj(dec, t, tname, 0, Some(ioa), &[], &mut kids, ca, &pt_idx);
                }
                break;
            }
            let ioa = ioa_of(&body[p..]);
            if decode_obj(dec, t, tname, vlen, Some(ioa), &body[p + 3..], &mut kids, ca, &pt_idx) { sigs_n += 1; }
            p + 3 + vlen
        };
        let _ = base;
    }
    if num > 0 && sigs_n == 0 {
        // 结构存在但值区不足(截断):仅列字段
        kids.push(dec.f("截断", Value::None, 6, len as u16 - 6, false, ""));
    }
    let cot_disp = if cot_s.is_empty() { format!("COT{cot}{pn}") } else { format!("{cot_s}{pn}") };
    let head = format!("{tname} ca={ca} ×{num} ({cot_disp})");
    let mut root = vec![
        dec.f("VS", Value::U(vs as u64), 2, 2, false, ""),
        dec.f("VR", Value::U(vr as u64), 4, 2, false, ""),
        dec.f("类型", Value::S(tname.into()), 6, 1, false, ""),
        dec.f("公共地址", Value::U(ca as u64), 9, 2, false, ""),
        dec.f("传送原因", Value::S(cot_disp.clone()), 8, 1, false, ""),
    ];
    root.append(&mut kids);
    dec.take_fields(root);
    format!("I VS={vs} VR={vr} {head}")
}

fn ioa_of(b: &[u8]) -> u32 {
    (b[0] as u32) | (b[1] as u32) << 8 | (b[2] as u32) << 16
}

/// 解码一个信息体的值区(不含 IOA)→ 字段/信号。返回是否产出信号。
/// 点表命中时:信号键改工程名、值按 factor/offset 换算、单位随表;显示名保留 IOA 便于回查。
fn decode_obj(
    dec: &mut Dec,
    t: u8,
    tname: &str,
    vlen: usize,
    ioa: Option<u32>,
    v: &[u8],
    kids: &mut Vec<crate::model::Field>,
    ca: u16,
    pt_idx: &std::collections::HashMap<(u8, u32), &map104::Pt104>,
) -> bool {
    let ioa = ioa.unwrap_or(0);
    if v.len() < vlen {
        return false;
    }
    // 点表:精确 (t,ioa) → 通配 (0,ioa);CA 仍按条目可选约束
    let pt = pt_idx
        .get(&(t, ioa))
        .or_else(|| pt_idx.get(&(0, ioa)))
        .copied()
        .filter(|p| p.ca.map_or(true, |c| c == ca));
    let pt_name = pt.map(|p| p.name.as_str()).filter(|s| !s.is_empty());
    let sig_key = |dec: &mut Dec, name: &str, unit: &str, val: f64| {
        // 键 = 104 {工程名或 类型·IOA}{可选子名};单位:点表优先,其次解码器推断
        let base = match pt_name {
            Some(n) => format!("104 {n}"),
            None => format!("104 {tname}·IOA{ioa}{name}"),
        };
        let u = match pt {
            Some(p) if !p.unit.is_empty() => p.unit.as_str(),
            _ => unit,
        };
        let val = pt.map_or(val, |p| map104::scaled(p, val));
        dec.sig(&base, u, val);
    };
    let mut mk = |dec: &mut Dec, disp: String, val: Value, plot: bool| {
        kids.push(dec.f(&disp, val, 0, 0, plot, ""));
    };
    // 点表命中时的字段树前缀:`主变油温` 或 `主变油温`→`IOA256`(双写便于回查原始地址)
    let pt_disp = |ioa: u32| -> String {
        match pt_name {
            Some(n) => format!("{n}·IOA{ioa}"),
            None => format!("IOA{ioa}"),
        }
    };
    match t {
        // 单/双点:值在低 2 位,高 4 位质量
        1 | 3 | 45 | 46 | 2 | 4 | 30 | 31 | 58 | 59 => {
            let dval = (v[0] & 0x03) as f64;
            let time = if matches!(t, 2 | 4 | 30 | 31 | 58 | 59) {
                cp56(&v[1..]).map(|(_, s)| s)
            } else { None };
            let q_off = if time.is_some() { 8 } else { 1 };
            let q = if v.len() >= q_off { qds_str(v[q_off - 1]) } else { "良好".into() };
            let mut disp = format!("{} = {}", pt_disp(ioa), if t == 1 || t == 2 || t == 30 { if dval > 0.5 { "合" } else { "分" } } else { match dval as u32 { 0 => "不确定", 1 => "分", 2 => "合", _ => "不确定" } });
            if let Some(ts) = &time { disp.push_str(&format!(" @{ts}")); }
            disp.push_str(&format!(" [{q}]"));
            sig_key(dec, "", "", dval);
            mk(dec, disp, Value::F(dval), true);
            true
        }
        5 => { // 步位置:带符号 i16 + OV
            let raw = i16::from_le_bytes([v[0], v[1]]) >> 2;
            sig_key(dec, "", "", raw as f64);
            mk(dec, format!("{} = {raw}", pt_disp(ioa)), Value::I(raw as i64), true);
            true
        }
        7 => { // 32bit 串
            let raw = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            sig_key(dec, "", "", raw as f64);
            mk(dec, format!("{} = {raw:#x}", pt_disp(ioa)), Value::U(raw as u64), true);
            true
        }
        9 => { // NVA 归一化 i16/32768
            let raw = i16::from_le_bytes([v[0], v[1]]);
            let phys = raw as f64 / 32768.0;
            sig_key(dec, "", "", phys);
            mk(dec, format!("{} = {phys:.5} [{}]", pt_disp(ioa), qds_str(v[2])), Value::F(phys), true);
            true
        }
        11 => { // BVA 标度化 i16
            let raw = i16::from_le_bytes([v[0], v[1]]);
            sig_key(dec, "", "", raw as f64);
            mk(dec, format!("{} = {raw} [{}]", pt_disp(ioa), qds_str(v[2])), Value::I(raw as i64), true);
            true
        }
        13 | 50 => { // 短浮点:遥测 / 设定值
            let raw = f32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            sig_key(dec, "", "", raw as f64);
            let q = if v.len() >= 5 { format!(" [{}]", qds_str(v[4])) } else { String::new() };
            mk(dec, format!("{} = {}{q}", pt_disp(ioa), Value::F(raw as f64).display()), Value::F(raw as f64), true);
            true
        }
        15 => { // 累计量 i32 + 序号
            let raw = i32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            sig_key(dec, "", "", raw as f64);
            mk(dec, format!("{} = {raw} seq={}", pt_disp(ioa), v[4]), Value::I(raw as i64), true);
            true
        }
        48 => {
            let raw = i16::from_le_bytes([v[0], v[1]]);
            sig_key(dec, "", "", raw as f64 / 32768.0);
            mk(dec, format!("{} 设定 = {}", pt_disp(ioa), raw as f64 / 32768.0), Value::F(raw as f64 / 32768.0), true);
            true
        }
        49 => {
            let raw = i16::from_le_bytes([v[0], v[1]]);
            sig_key(dec, "", "", raw as f64);
            mk(dec, format!("{} 设定 = {raw}", pt_disp(ioa)), Value::I(raw as i64), true);
            true
        }
        100 => { // 总召唤 QOI
            let qoi = match v[0] { 20 => "站总召唤", 21 => "1 组", _ => "其它" };
            mk(dec, format!("IOA{ioa} QOI={}({qoi})", v[0]), Value::U(v[0] as u64), false);
            true
        }
        103 => {
            if let Some((_, s)) = cp56(v) {
                mk(dec, format!("时钟同步 → {s}"), Value::None, false);
            }
            true
        }
        104 => {
            mk(dec, format!("IOA{ioa} 测试 {:#04X}", v[0]), Value::U(v[0] as u64), false);
            true
        }
        70 => {
            mk(dec, format!("IOA{ioa} COI={} (初始化原因)", v[0] & 0x0F), Value::U(v[0] as u64), false);
            true
        }
        34 | 35 => { // 带时标遥测(3B 时标):值 2B + 质量 1B + 时间 3B
            let raw = i16::from_le_bytes([v[0], v[1]]);
            sig_key(dec, "", "", raw as f64);
            mk(dec, format!("{} = {raw} [{}]", pt_disp(ioa), qds_str(v[2])), Value::I(raw as i64), true);
            true
        }
        36 => { // CP56 短浮点
            let raw = f32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            sig_key(dec, "", "", raw as f64);
            let ts = cp56(&v[5..]).map(|(_, s)| format!(" @{s}")).unwrap_or_default();
            mk(dec, format!("{} = {}{ts}", pt_disp(ioa), Value::F(raw as f64).display()), Value::F(raw as f64), true);
            true
        }
        _ => false,
    }
}
