//! 自定义协议 DSL(JSON 配置):同步头 + 长度域 + 校验 + 字段解码。
//! 覆盖"有同步头、有(或无)长度域、带校验"的常见 485/串口自定义协议。

use serde::Deserialize;

fn default_min() -> u16 {
    4
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Off {
    Abs(u16),
    EndMinus(u16),
}

impl Off {
    pub fn resolve(&self, frame_len: usize) -> Option<usize> {
        match self {
            Off::Abs(a) => {
                let a = *a as usize;
                if a <= frame_len {
                    Some(a)
                } else {
                    None
                }
            }
            Off::EndMinus(n) => {
                let n = *n as usize;
                if frame_len >= n {
                    Some(frame_len - n)
                } else {
                    None
                }
            }
        }
    }
    fn resolve_start(&self, frame_len: usize) -> Option<usize> {
        self.resolve(frame_len)
    }
    fn resolve_end(&self, frame_len: usize) -> Option<usize> {
        match self {
            Off::Abs(a) => {
                let a = *a as usize;
                if a <= frame_len {
                    Some(a)
                } else {
                    None
                }
            }
            Off::EndMinus(n) => {
                let n = *n as usize;
                if frame_len >= n {
                    Some(frame_len - n)
                } else {
                    None
                }
            }
        }
    }
}

impl serde::Serialize for Off {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            Off::Abs(a) => ser.serialize_u16(*a),
            Off::EndMinus(0) => ser.serialize_str("end"),
            Off::EndMinus(n) => ser.serialize_str(&format!("end-{n}")),
        }
    }
}

impl<'de> Deserialize<'de> for Off {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        match &v {
            serde_json::Value::Number(n) => {
                let a = n.as_u64().ok_or_else(|| serde::de::Error::custom("offset 需为非负整数"))?;
                Ok(Off::Abs(a as u16))
            }
            serde_json::Value::String(s) => {
                let s = s.trim();
                if s == "end" {
                    Ok(Off::EndMinus(0))
                } else if let Some(n) = s.strip_prefix("end-") {
                    let n: u16 = n.parse().map_err(serde::de::Error::custom)?;
                    Ok(Off::EndMinus(n))
                } else {
                    Err(serde::de::Error::custom(format!("非法 offset: {s}")))
                }
            }
            _ => Err(serde::de::Error::custom("offset 需为整数或 \"end-N\"")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

impl Default for Endian {
    fn default() -> Self {
        Endian::Little
    }
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct LenSpec {
    pub at: Off,
    #[serde(default = "d1")]
    pub size: u8,
    #[serde(default)]
    pub endian: Endian,
    /// 长度值补偿:总帧长 = 值 + bias
    #[serde(default)]
    pub bias: i32,
    /// true: 长度值已包含头部(总帧长 = 值);false: 总帧长 = 值 + bias
    #[serde(default)]
    pub include_header: bool,
}
fn d1() -> u8 {
    1
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct CksSpec {
    /// crc16_modbus | crc16_ccitt | crc16_xmodem | sum8 | xor8 | lrc
    pub algo: String,
    /// 校验字节位置
    #[serde(default)]
    pub at: Option<Off>,
    /// 参与校验的字节范围 [from, to)
    pub cover: (Off, Off),
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct BitSpec {
    pub name: String,
    pub bit: u8,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct FieldSpec {
    pub name: String,
    pub at: u16,
    /// 类型: u8 i8 u16 i16 u32 i32 u64 i64 f32 f64 bool bytes bits
    #[serde(default = "d_u8")]
    pub ty: String,
    #[serde(default)]
    pub endian: Endian,
    #[serde(default = "one")]
    pub scale: f64,
    #[serde(default)]
    pub offset: f64,
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub plot: bool,
    #[serde(default)]
    pub size: Option<u8>,
    pub bits: Option<Vec<BitSpec>>,
}
fn d_u8() -> String {
    "u8".into()
}
fn one() -> f64 {
    1.0
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct CustomSpec {
    pub name: String,
    /// 同步头,十六进制字符串,如 "AA55";缺省 = 无同步头
    #[serde(default)]
    pub sync: Option<String>,
    /// 固定帧长(与 length 二选一)
    #[serde(default)]
    pub frame_len: Option<u16>,
    /// 长度域定义
    #[serde(default)]
    pub length: Option<LenSpec>,
    #[serde(default)]
    pub checksum: Option<CksSpec>,
    #[serde(default = "default_min")]
    pub min_len: u16,
    #[serde(default)]
    pub fields: Vec<FieldSpec>,
}

pub fn parse_spec(json: &str) -> Result<CustomSpec, String> {
    serde_json::from_str(json).map_err(|e| format!("自定义协议配置解析失败: {e}"))
}

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let b = s.as_bytes();
    (0..b.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn syncs(spec: &CustomSpec) -> Vec<Vec<u8>> {
    spec.sync.as_ref().map(|s| vec![hex_to_bytes(s)]).unwrap_or_default()
}

/// 帧长度推断(start 为帧起始)
fn frame_len_at(data: &[u8], start: usize, spec: &CustomSpec) -> Option<usize> {
    if let Some(fl) = spec.frame_len {
        return Some(fl as usize);
    }
    if let Some(ls) = &spec.length {
        // 长度域偏移相对帧起始
        let rel = match ls.at {
            Off::Abs(a) => a as usize,
            Off::EndMinus(_) => return None,
        };
        let at = start + rel;
        if at + ls.size as usize > data.len() {
            return None;
        }
        let v: i64 = match ls.size {
            1 => data[at] as i64,
            2 => {
                if ls.endian == Endian::Little {
                    u16::from_le_bytes([data[at], data[at + 1]]) as i64
                } else {
                    u16::from_be_bytes([data[at], data[at + 1]]) as i64
                }
            }
            4 => {
                let b = [data[at], data[at + 1], data[at + 2], data[at + 3]];
                if ls.endian == Endian::Little {
                    u32::from_le_bytes(b) as i64
                } else {
                    u32::from_be_bytes(b) as i64
                }
            }
            _ => return None,
        };
        // 总帧长 = 长度值 + bias(bias 用于补偿头部/校验等)
        let total = v + ls.bias as i64;
        if total <= 0 || total > 4096 {
            return None;
        }
        return Some(total as usize);
    }
    None
}

fn check_cksum(data: &[u8], spec: &CustomSpec) -> bool {
    let Some(cs) = &spec.checksum else { return true };
    let (from, to) = match (cs.cover.0.resolve_start(data.len()), cs.cover.1.resolve_end(data.len())) {
        (Some(a), Some(b)) if a < b => (a, b),
        _ => return false,
    };
    let Some(expected) = crate::crc::calc(&cs.algo, &data[from..to]) else { return false };
    if expected.is_empty() {
        return true;
    }
    let at = match cs
        .at
        .as_ref()
        .copied()
        .or_else(|| Some(Off::EndMinus(expected.len() as u16)))
    {
        Some(o) => o,
        None => return false,
    };
    let Some(at) = at.resolve_start(data.len()) else { return false };
    if at + expected.len() > data.len() {
        return false;
    }
    data[at..at + expected.len()] == expected[..]
}

/// 在一段数据中定界,返回 (帧偏移, 帧长) 列表
pub fn deframe(data: &[u8], spec: &CustomSpec) -> (Vec<(usize, usize)>, usize) {
    let sync = syncs(spec);
    let sync_len = sync.first().map(|v| v.len()).unwrap_or(0);
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut skipped = 0usize;
    let fixed = spec.frame_len.map(|v| v as usize);
    while i < data.len() {
        // 找同步头
        let start = if sync.is_empty() {
            i
        } else {
            let mut found = None;
            'outer: for k in i..data.len() {
                for s in &sync {
                    if data.len() >= k + s.len() && &data[k..k + s.len()] == s.as_slice() {
                        found = Some(k);
                        break 'outer;
                    }
                }
            }
            match found {
                Some(k) => k,
                None => {
                    skipped += data.len() - i;
                    break;
                }
            }
        };
        let len = fixed.or_else(|| frame_len_at(data, start, spec)).or_else(|| {
            // 无长度域:到下一个同步头为止
            if sync.is_empty() || start + sync_len > data.len() {
                None
            } else {
                let mut found = data.len();
                for s in &sync {
                    if let Some(k) = find_sub(&data[start + sync_len..], s) {
                        found = found.min(start + sync_len + k);
                    }
                }
                Some(found - start)
            }
        });
        match len {
            Some(l) if l >= spec.min_len as usize && start + l <= data.len() => {
                if check_cksum(&data[start..start + l], spec) {
                    out.push((start, l));
                    skipped += start - i;
                    i = start + l;
                } else {
                    i = start + sync_len.max(1);
                }
            }
            _ => {
                i = start + sync_len.max(1);
            }
        }
    }
    (out, skipped)
}

fn find_sub(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&k| &h[k..k + n.len()] == n)
}

/// 字段类型字节长度
fn ty_size(ty: &str, fs: &FieldSpec) -> usize {
    if fs.size.is_some() {
        return fs.size.unwrap() as usize;
    }
    match ty {
        "u8" | "i8" | "bool" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        _ => 1,
    }
}

/// 解码一帧为字段树(plot 字段由调用方 walk 提取)
pub fn decode(data: &[u8], spec: &CustomSpec, st: &mut crate::model::Strings) -> Vec<crate::model::Field> {
    use crate::model::{Field, Value};
    let mut root = Vec::new();
    for fs in &spec.fields {
        let at = fs.at as usize;
        let n = ty_size(&fs.ty, fs);
        if at + n > data.len() {
            continue;
        }
        let be = fs.endian == Endian::Big;
        let raw = &data[at..at + n];
        let (val, _plotable) = match fs.ty.as_str() {
            "u8" => (Value::U(raw[0] as u64), true),
            "i8" => (Value::I(raw[0] as i8 as i64), true),
            "u16" => (Value::U(if be { u16::from_be_bytes([raw[0], raw[1]]) } else { u16::from_le_bytes([raw[0], raw[1]]) } as u64), true),
            "i16" => (Value::I(if be { i16::from_be_bytes([raw[0], raw[1]]) } else { i16::from_le_bytes([raw[0], raw[1]]) } as i64), true),
            "u32" => {
                let b = [raw[0], raw[1], raw[2], raw[3]];
                (Value::U(if be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) } as u64), true)
            }
            "i32" => {
                let b = [raw[0], raw[1], raw[2], raw[3]];
                (Value::I(if be { i32::from_be_bytes(b) } else { i32::from_le_bytes(b) } as i64), true)
            }
            "f32" => {
                let b = [raw[0], raw[1], raw[2], raw[3]];
                (Value::F(if be { f32::from_be_bytes(b) } else { f32::from_le_bytes(b) } as f64), true)
            }
            "f64" => {
                let mut b = [0u8; 8];
                b.copy_from_slice(raw);
                (Value::F(if be { f64::from_be_bytes(b) } else { f64::from_le_bytes(b) }), true)
            }
            "u64" | "i64" => {
                let mut b = [0u8; 8];
                b.copy_from_slice(raw);
                let u = if be { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) };
                (Value::U(u), true)
            }
            "bytes" => (Value::Hex(raw.to_vec()), false),
            _ => (Value::U(raw[0] as u64), true),
        };
        let scaled = match (&val, fs.scale, fs.offset) {
            (Value::U(u), s, o) if s != 1.0 || o != 0.0 => Value::F(*u as f64 * s + o),
            (Value::I(i), s, o) if s != 1.0 || o != 0.0 => Value::F(*i as f64 * s + o),
            (Value::F(f), s, o) if s != 1.0 || o != 0.0 => Value::F(*f * s + o),
            (v, _, _) => v.clone(),
        };
        let children = match (&fs.bits, &fs.ty.as_str()) {
            (Some(bits), _) => bits
                .iter()
                .map(|b| Field {
                    name: st.intern(&b.name),
                    val: Value::B((data[at] >> (b.bit % 8)) & 1 == 1),
                    start: at as u16,
                    len: 0,
                    plot: true,
                    unit: None,
                    children: vec![],
                })
                .collect(),
            _ => vec![],
        };
        root.push(Field {
            name: st.intern(&fs.name),
            val: scaled,
            start: at as u16,
            len: n as u16,
            plot: fs.plot,
            unit: if fs.unit.is_empty() { None } else { Some(st.intern(&fs.unit)) },
            children,
        });
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::crc16_modbus;

    fn build_frame(cmd: u8, temp: i16) -> Vec<u8> {
        let mut f = vec![0xAA, 0x55, cmd, 0x00, 0x00, 0x00, 0x00, 0x00];
        // len at offset 3 (payload len = 4)
        f[3] = 4;
        f[4] = (temp & 0xFF) as u8;
        f[5] = (temp >> 8) as u8;
        f[6] = 0x27; // rpm hi(BE)=0x27
        f[7] = 0x10; // rpm lo → 0x2710 = 10000
        let c = crc16_modbus(&f[..8]);
        f.push(c as u8);
        f.push((c >> 8) as u8);
        f
    }

    fn spec() -> CustomSpec {
        parse_spec(
            r#"{
              "name": "acme",
              "sync": "AA55",
              "min_len": 10,
              "length": {"at": 3, "size": 1, "bias": 6},
              "checksum": {"algo": "crc16_modbus", "cover": [0, "end-2"]},
              "fields": [
                {"name": "cmd", "at": 2, "ty": "u8"},
                {"name": "temp", "at": 4, "ty": "i16", "scale": 0.1, "unit": "C", "plot": true},
                {"name": "rpm", "at": 6, "ty": "u16", "endian": "big", "plot": true}
              ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn deframe_and_decode() {
        let s = spec();
        let mut buf = vec![0xFF, 0x00]; // 前导噪声
        buf.extend_from_slice(&build_frame(0x10, 235));
        buf.extend_from_slice(&build_frame(0x10, -125));
        buf.push(0x99); // 尾部噪声
        let (frames, skipped) = deframe(&buf, &s);
        assert_eq!(frames.len(), 2);
        assert_eq!(skipped, 3);
        let f0 = &buf[frames[0].0..frames[0].0 + frames[0].1];
        assert_eq!(f0.len(), 10);
        let mut st = crate::model::Strings::default();
        let fields = decode(f0, &s, &mut st);
        let temp = fields.iter().find(|f| st.get(f.name) == "temp").unwrap();
        match &temp.val {
            crate::model::Value::F(v) => assert!((v - 23.5).abs() < 1e-9),
            v => panic!("{v:?}"),
        }
        let rpm = fields.iter().find(|f| st.get(f.name) == "rpm").unwrap();
        assert_eq!(rpm.val, crate::model::Value::U(10000));
    }

    #[test]
    fn crc_fail_resync() {
        let s = spec();
        let mut good = build_frame(0x10, 100);
        let mut buf = good.clone();
        buf[4] ^= 0xFF; // 破坏校验
        buf.extend_from_slice(&good);
        let (frames, _) = deframe(&buf, &s);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 10); // 第二帧
        let _ = &mut good;
    }
}
