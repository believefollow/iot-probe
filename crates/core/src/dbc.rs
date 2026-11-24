//! DBC 解析器(增强版):
//! - BO_/SG_ 基础(Intel@1 与 Motorola@0 字节序、factor/offset)
//! - 多路复用:SG_ M(选择器)/ mN(分支信号),按选择器当前值过滤解码
//! - 扩展帧:BO_ id ≥ 0x80000000 识别为扩展帧,统一按 (29位ID | 扩展位<<31) 做键
//! - VAL_ 值表:枚举值 → 显示名
//! - SIG_VALTYPE_:float32/float64 原始位型
//! 这是 SavvyCAN 式"信号曲线"能力的基础。

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SigDef {
    pub name: String,
    pub start: u16,
    pub len: u16,
    pub le: bool,     // @1 = Intel/little-endian
    pub signed: bool, // '-'
    pub factor: f64,
    pub offset: f64,
    pub unit: String,
    /// 多路复用分支值(Some(n) = mN 信号);None = 普通信号
    pub mux: Option<u64>,
    /// 扩展复用区间(SG_MUL_VAL_):选择器值落在任一区间内即适用
    pub mux_ranges: Vec<(u64, u64)>,
    /// true = 复用选择器(M)
    pub is_mux_sel: bool,
    /// Some(0)=float32, Some(1)=float64(SIG_VALTYPE_)
    pub float: Option<u8>,
}

impl SigDef {
    fn plain(name: String, start: u16, len: u16, le: bool, signed: bool, factor: f64, offset: f64, unit: String) -> Self {
        SigDef { name, start, len, le, signed, factor, offset, unit, mux: None, mux_ranges: vec![], is_mux_sel: false, float: None }
    }
}

#[derive(Clone, Debug)]
pub struct MsgDef {
    pub name: String,
    pub dlc: u8,
    pub ext: bool,
    /// 标称周期 ms(BA_ "GenMsgCycleTime",FR-4.2 聚合视图用来比对实测周期)
    pub cycle_ms: Option<u32>,
    pub sigs: Vec<SigDef>,
}

#[derive(Clone, Debug, Default)]
pub struct Dbc {
    /// 键 = (29位ID) | (扩展位 << 31)
    pub msgs: HashMap<u32, MsgDef>,
    /// VAL_ 值表:msg键 → 信号名 → [(数值, 显示名)]
    pub vals: HashMap<u32, HashMap<String, Vec<(u64, String)>>>,
}

impl Dbc {
    /// 合并另一份 DBC 到自身(协议库多选启用):已存在的报文键不覆盖,返回被跳过的 ID 列表。
    pub fn merge(&mut self, other: Dbc) -> Vec<u32> {
        let mut skipped = vec![];
        for (k, m) in other.msgs {
            if self.msgs.insert(k, m).is_some() {
                skipped.push(k);
            }
        }
        for (k, vals) in other.vals {
            let entry = self.vals.entry(k).or_default();
            for (sig, vv) in vals {
                entry.entry(sig).or_insert(vv);
            }
        }
        skipped
    }

    /// 报文总数(含 VAL 表)
    pub fn msg_count(&self) -> usize {
        self.msgs.len()
    }
}

pub fn msg_key(id: u32, ext: bool) -> u32 {
    (id & 0x1FFF_FFFF) | ((ext as u32) << 31)
}

pub fn parse(text: &str) -> Dbc {
    let mut dbc = Dbc::default();
    let mut cur: Option<u32> = None;
    for raw in text.lines() {
        let line = raw.trim().trim_end_matches(';').trim();
        if line.starts_with("BO_ ") {
            // BO_ 416 MOTOR_STATUS: 8 MOTOR   |  BO_ 419358208 EXT_MSG: 8 ECU
            let rest = &line[4..];
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(id) = parts[0].parse::<u32>() {
                    let ext = id >= 0x8000_0000;
                    let key = msg_key(id, ext);
                    let name = parts[1].trim_end_matches(':').to_string();
                    let dlc = parts[2].parse().unwrap_or(8);
                    dbc.msgs.insert(key, MsgDef { name, dlc, ext, cycle_ms: None, sigs: vec![] });
                    cur = Some(key);
                }
            }
        } else if line.starts_with("SG_ ") {
            if let Some(key) = cur {
                if let Some(f) = parse_sg(line) {
                    if let Some(m) = dbc.msgs.get_mut(&key) {
                        m.sigs.push(f);
                    }
                }
            }
        } else if line.starts_with("VAL_ ") {
            // VAL_ 512 State 0 "Idle" 1 "Run" ;
            parse_val(line, &mut dbc);
        } else if line.starts_with("SG_MUL_VAL_ ") {
            // SG_MUL_VAL_ 512 A MuxSel 0-5 , 10-20 ;
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() >= 5 {
                if let Ok(id) = toks[1].parse::<u32>() {
                    let key = msg_key(id, id >= 0x8000_0000);
                    let sig = toks[2].to_string();
                    // 区间段:第 4 个 token 起(跳过报文ID/信号名/复用信号名)
                    let mut ranges: Vec<String> = vec![];
                    let mut num_tok = String::new();
                    for ch in line.chars().skip(line.find(toks[4]).unwrap_or(0)) {
                        if ch.is_ascii_digit() {
                            num_tok.push(ch);
                        } else if ch == '-' || ch == ',' || ch == ';' {
                            if !num_tok.is_empty() {
                                ranges.push(num_tok.clone());
                                num_tok.clear();
                            }
                        }
                    }
                    if !num_tok.is_empty() {
                        ranges.push(num_tok);
                    }
                    let pairs: Vec<(u64, u64)> = ranges.chunks(2).filter(|c| c.len() == 2).filter_map(|c| {
                        Some((c[0].parse().ok()?, c[1].parse().ok()?))
                    }).collect();
                    if let Some(m) = dbc.msgs.get_mut(&key) {
                        if let Some(sg) = m.sigs.iter_mut().find(|s| s.name == sig) {
                            sg.mux_ranges = pairs;
                        }
                    }
                }
            }
        } else if line.starts_with("BA_ ") {
            // BA_ "GenMsgCycleTime" BO_ 416 100;
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() >= 4 && toks[1].contains("GenMsgCycleTime") && toks[2] == "BO_" {
                if let Ok(id) = toks[3].parse::<u32>() {
                    let key = msg_key(id, id >= 0x8000_0000);
                    if let Ok(ms) = toks[4].trim_end_matches(';').parse::<u32>() {
                        if let Some(m) = dbc.msgs.get_mut(&key) {
                            m.cycle_ms = Some(ms);
                        }
                    }
                }
            }
        } else if line.starts_with("SIG_VALTYPE_ ") {
            // SIG_VALTYPE_ 512 Temp : 0;   (0=float32, 1=float64)
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() >= 4 {
                if let Ok(id) = toks[1].parse::<u32>() {
                    let key = msg_key(id, id >= 0x8000_0000);
                    let sig = toks[2].to_string();
                    let ty = toks[4].trim().parse::<u8>().ok();
                    if let Some(ty) = ty {
                        if let Some(m) = dbc.msgs.get_mut(&key) {
                            for s in &mut m.sigs {
                                if s.name == sig {
                                    s.float = Some(ty);
                                }
                            }
                        }
                    }
                }
            }
        }
        // CM_/BA_/BS_/NS_ 等忽略
    }
    dbc
}

fn parse_val(line: &str, dbc: &mut Dbc) {
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < 4 {
        return;
    }
    let Ok(id) = toks[1].parse::<u32>() else { return };
    let key = msg_key(id, id >= 0x8000_0000);
    let sig = toks[2].to_string();
    // 之后是 num "text" 对(字符串可能含空格)
    let rest = line.splitn(4, ' ').nth(3).unwrap_or("");
    let mut pairs: Vec<(u64, String)> = vec![];
    let mut chars = rest.char_indices().peekable();
    // 简单扫描:num 空格 "text"
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() || bytes[i] == b'-' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'-') {
                i += 1;
            }
            let Ok(n) = rest[start..i].parse::<u64>() else { break };
            // 跳过空白找引号
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'"' {
                let st = i + 1;
                let mut j = st;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                let text = rest[st..j.min(bytes.len())].to_string();
                i = (j + 1).min(bytes.len());
                pairs.push((n, text));
            } else {
                pairs.push((n, String::new()));
            }
        } else {
            i += 1;
        }
    }
    let _ = &mut chars;
    if !pairs.is_empty() {
        dbc.vals.entry(key).or_default().insert(sig, pairs);
    }
}

fn parse_sg(line: &str) -> Option<SigDef> {
    // SG_ name [M|mN] : start|len@e+ (fac,off) [min|max] "unit" [receiver]
    let after = &line[4..];
    let (name_part, rest) = after.split_once(" : ")?;
    let mut np = name_part.split_whitespace();
    let name = np.next()?.to_string();
    let marker = np.next(); // "M" / "m1" / None
    let (mut mux, mut is_mux_sel) = (None, false);
    if let Some(mk) = marker {
        if mk == "M" {
            is_mux_sel = true;
        } else if let Some(num) = mk.strip_prefix('m') {
            mux = num.parse::<u64>().ok();
        }
    }
    let toks: Vec<&str> = rest.split_whitespace().collect();
    if toks.len() < 3 {
        return None;
    }
    let sl = toks[0];
    let (s, l) = sl.split_once('|')?;
    let start: u16 = s.trim().parse().ok()?;
    let (len_str, es) = l.split_once('@')?;
    let len: u16 = len_str.trim().parse().ok()?;
    let le = es.trim().starts_with('1');
    let signed = es.contains('-');
    let fo = toks[1].trim_matches(|c| c == '(' || c == ')');
    let (fac, off) = fo.split_once(',')?;
    let unit = if toks.iter().any(|t| t.starts_with('"')) {
        let joined = toks.iter().skip_while(|t| !t.starts_with('"')).cloned().collect::<Vec<_>>().join(" ");
        joined.trim_matches('"').to_string()
    } else {
        String::new()
    };
    let mut sig = SigDef::plain(
        name,
        start,
        len,
        le,
        signed,
        fac.trim().parse().unwrap_or(1.0),
        off.trim().parse().unwrap_or(0.0),
        unit.trim().to_string(),
    );
    sig.mux = mux;
    sig.is_mux_sel = is_mux_sel;
    Some(sig)
}

/// 按 DBC 信号定义从 CAN 数据解码物理值(原始位→物理值;float 类型在 raw 阶段替换)
pub fn decode(sig: &SigDef, data: &[u8]) -> Option<f64> {
    let mut raw: u64 = 0;
    if sig.le {
        for i in 0..sig.len as usize {
            let bitpos = sig.start as usize + i;
            let byte = bitpos / 8;
            if byte >= data.len() {
                return None;
            }
            let bit = bitpos % 8;
            raw |= (((data[byte] >> bit) & 1) as u64) << i;
        }
    } else {
        // Motorola: start 为 MSB 所在位(sawtooth 编号)
        let mut pos = sig.start as i32;
        for i in 0..sig.len as usize {
            let byte = pos / 8;
            let bit = pos % 8;
            if byte >= data.len() as i32 {
                return None;
            }
            raw |= (((data[byte as usize] >> bit) & 1) as u64) << (sig.len as usize - 1 - i);
            pos = if pos % 8 == 0 { pos + 15 } else { pos - 1 };
        }
    }
    if let Some(ty) = sig.float {
        let v = match (ty, sig.len) {
            (0, 32) => f32::from_bits(raw as u32) as f64,
            (1, 64) => f64::from_bits(raw),
            _ => return None,
        };
        return Some(v * sig.factor + sig.offset);
    }
    let val: i64 = if sig.signed && sig.len < 64 && (raw >> (sig.len - 1)) & 1 == 1 {
        (raw as i64) - (1i64 << sig.len)
    } else {
        raw as i64
    };
    Some(val as f64 * sig.factor + sig.offset)
}

/// 解码一整条消息(含复用过滤与值表标签)。返回 (信号, 物理值, 枚举显示名)。
pub fn decode_message<'a>(dbc: &'a Dbc, key: u32, data: &[u8]) -> Vec<(&'a SigDef, f64, Option<String>)> {
    let Some(m) = dbc.msgs.get(&key) else { return vec![] };
    let sel = m.sigs.iter().find(|s| s.is_mux_sel).and_then(|s| decode(s, data).map(|v| v as u64));
    let mut out = Vec::new();
    for s in &m.sigs {
        if s.is_mux_sel {
            if let Some(v) = decode(s, data) {
                out.push((s, v, val_label(dbc, key, &s.name, v)));
            }
            continue;
        }
        if let Some(mx) = s.mux {
            if sel != Some(mx) {
                continue;
            }
        } else if !s.mux_ranges.is_empty() {
            // SG_MUL_VAL_ 扩展复用:任一区间命中即适用
            let hit = sel.map(|sv| s.mux_ranges.iter().any(|(a, b)| sv >= *a && sv <= *b)).unwrap_or(false);
            if !hit {
                continue;
            }
        }
        if let Some(v) = decode(s, data) {
            out.push((s, v, val_label(dbc, key, &s.name, v)));
        }
    }
    out
}

pub fn val_label(dbc: &Dbc, key: u32, sig: &str, v: f64) -> Option<String> {
    let t = dbc.vals.get(&key)?.get(sig)?;
    let n = v as u64;
    if (n as f64 - v).abs() > 1e-9 {
        return None;
    }
    t.iter().find(|(num, _)| *num == n).map(|(_, s)| s.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    const DBC_TEXT: &str = r#"
VERSION ""

BO_ 416 MOTOR_STATUS: 8 MOTOR
 SG_ Speed : 0|16@1+ (0.01,0) [0|500] "kph"
 SG_ Torque : 16|16@1- (0.1,0) [-500|500] "Nm"
 SG_ Temp : 32|8@1+ (1,-40) [-40|200] "degC"
 SG_ BigEndian : 39|16@0+ (1,0) [0|65535] ""
BO_ 2147483904 EXT_STATUS: 8 ECU
 SG_ State : 0|8@1+ (1,0) [0|5] ""
VAL_ 2147483904 State 0 "Idle" 1 "Run" 2 "Fault" ;
BO_ 512 MUX_MSG: 8 ECU
 SG_ MuxSel M : 0|8@1+ (1,0) [0|2] ""
 SG_ A m0 : 8|16@1+ (0.1,0) [0|10] "A"
 SG_ B m1 : 8|16@1+ (1,0) [0|10] "B"
 SG_ Always : 24|8@1+ (1,0) [0|255] ""
SIG_VALTYPE_ 512 Always : 0;
"#;
    #[test]
    fn parse_and_decode() {
        let dbc = parse(DBC_TEXT);
        let m = dbc.msgs.get(&416).unwrap();
        assert_eq!(m.sigs.len(), 4);
        let data = [0x34, 0x12, 0x9C, 0xFF, 0x50, 0x12, 0x34, 0x00];
        let speed = decode(&m.sigs[0], &data).unwrap();
        assert!((speed - 0x1234 as f64 * 0.01).abs() < 1e-9); // 46.6
        let torque = decode(&m.sigs[1], &data).unwrap();
        assert!((torque - (-10.0)).abs() < 1e-6);
        let temp = decode(&m.sigs[2], &data).unwrap();
        assert!((temp - 40.0).abs() < 1e-9);
    }
    #[test]
    fn motorola_basic() {
        let sig = SigDef::plain("x".into(), 7, 16, false, false, 1.0, 0.0, "".into());
        assert_eq!(decode(&sig, &[0x12, 0x34]).unwrap(), 0x1234 as f64);
    }
    #[test]
    fn signed_neg() {
        let sig = SigDef::plain("x".into(), 0, 16, true, true, 1.0, 0.0, "".into());
        assert_eq!(decode(&sig, &[0xFF, 0xFF]).unwrap(), -1.0);
    }
    #[test]
    fn extended_and_valtable() {
        let dbc = parse(DBC_TEXT);
        // 2147483904 = 0x80000100 → 扩展帧 key
        let key = msg_key(0x100, true);
        let m = dbc.msgs.get(&key).expect("扩展帧应入库");
        assert!(m.ext);
        let data = [1, 0, 0, 0, 0, 0, 0, 0];
        let out = decode_message(&dbc, key, &data);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].2.as_deref(), Some("Run"), "VAL_ 值表标签");
        // 非 DBC 扩展位不匹配
        assert!(dbc.msgs.get(&msg_key(0x100, false)).is_none());
    }
    #[test]
    fn extended_mux_and_cycle() {
        let text = r#"
BO_ 600 MIXED: 8 ECU
 SG_ Sel M : 0|8@1+ (1,0) [0|9] ""
 SG_ Low m3 : 8|16@1+ (1,0) [0|10] "A"
 SG_ High : 8|16@1+ (1,0) [0|10] "B"
 SG_MUL_VAL_ 600 High Sel 5-9 ;
BA_ "GenMsgCycleTime" BO_ 600 100;
"#;
        let dbc = parse(text);
        let key = msg_key(600, false);
        assert_eq!(dbc.msgs.get(&key).unwrap().cycle_ms, Some(100), "标称周期应解析");
        // sel=3 → Low 适用(m3)、High 不适用(区间 5-9)
        let d = [3, 0x10, 0x00, 0, 0, 0, 0, 0];
        let names: Vec<&str> = decode_message(&dbc, key, &d).iter().map(|(sg, _, _)| sg.name.as_str()).collect();
        assert!(names.contains(&"Low") && !names.contains(&"High"), "{names:?}");
        // sel=7 → High 适用(区间命中),Low 不适用
        let d7 = [7, 0x20, 0x00, 0, 0, 0, 0, 0];
        let names7: Vec<&str> = decode_message(&dbc, key, &d7).iter().map(|(sg, _, _)| sg.name.as_str()).collect();
        assert!(names7.contains(&"High") && !names7.contains(&"Low"), "{names7:?}");
    }

    #[test]
    fn multiplexed() {
        let dbc = parse(DBC_TEXT);
        let key = msg_key(512, false);
        let data0 = [0, 0x20, 0x00, 0x07, 0, 0, 0, 0]; // sel=0 → A=0x0020*0.1=3.2; Always 是 float32 raw=7
        let out0 = decode_message(&dbc, key, &data0);
        let names0: Vec<&str> = out0.iter().map(|(s, _, _)| s.name.as_str()).collect();
        assert!(names0.contains(&"A") && !names0.contains(&"B"), "{names0:?}");
        let a = out0.iter().find(|(s, _, _)| s.name == "A").unwrap();
        assert!((a.1 - 3.2).abs() < 1e-9);
        let data1 = [1, 0x05, 0x00, 0, 0, 0, 0, 0]; // sel=1 → B=5
        let out1 = decode_message(&dbc, key, &data1);
        let names1: Vec<&str> = out1.iter().map(|(s, _, _)| s.name.as_str()).collect();
        assert!(names1.contains(&"B") && !names1.contains(&"A"), "{names1:?}");
    }

    #[test]
    fn merge_multi_dbc() {
        // 协议库多选:两个 DBC 合并;同 ID 先选优先(冲突跳过)
        let a = parse("BO_ 100 MsgA: 8 ECU\n SG_ v : 0|16@1+ (0.1,0) [0|65535] \"\" ECU\n");
        let mut b = parse("BO_ 100 MsgDup: 8 OTHER\n SG_ w : 0|8@1+ (1,0) [0|255] \"\" OTHER\n BO_ 200 MsgB: 8 OTHER\n SG_ x : 0|8@1+ (1,0) [0|255] \"\" OTHER\n");
        let skipped = b.merge(a); // 把 a 并进 b(已有 100 → 跳过)
        assert_eq!(skipped, vec![msg_key(100, false)], "冲突 ID 应被跳过");
        assert_eq!(b.msgs.len(), 2, "100 不覆盖,200 新增");
        assert!(b.msgs.contains_key(&msg_key(200, false)));
    }
}
