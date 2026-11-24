//! 未知协议试探引擎。
//! 思路:提议-确认式逆向 —— 统计同步头候选 → 长度域假设验证 → 校验算法网格试配
//! → 常量/计数器/载荷区域识别 → 生成 CustomSpec 草案,由用户人工确认采纳。
//! 不追求全自动,但把"人肉找规律"变成"看报告改两个字段"。

use super::custom::{CustomSpec, CksSpec, Endian, FieldSpec, LenSpec, Off};
use crate::crc;
use crate::model::Record;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    /// 疑似定界帧结构(有草案)
    Framed,
    /// 纯文本日志
    Text,
    /// 每行 JSON(NDJSON)
    NDJson,
    /// 无法给出结构判断
    Opaque,
}

#[derive(Clone, Debug)]
pub struct FieldHint {
    pub pos: usize,
    pub kind: String, // 常量 / 计数器 / 载荷
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct UnknownReport {
    pub channel: String,
    pub n_records: usize,
    pub total_bytes: usize,
    pub verdict: Verdict,
    pub sync: Option<String>,
    pub length: Option<(usize, u8, bool, i32)>, // pos, size, little_endian, bias
    pub fixed_len: Option<u16>,
    pub checksum: Option<(String, usize, usize)>, // algo, cover_start, 校验字节数
    pub confidence: f64,
    pub hints: Vec<FieldHint>,
    pub draft: Option<CustomSpec>,
    pub notes: Vec<String>,
}

const ALGOS2: &[(&str, usize)] = &[("crc16_modbus", 2), ("crc16_ccitt", 2), ("crc16_xmodem", 2)];
const ALGOS1: &[(&str, usize)] = &[("sum8", 1), ("xor8", 1), ("lrc", 1)];

fn printable_ratio(d: &[u8]) -> f64 {
    if d.is_empty() {
        return 0.0;
    }
    let ok = d.iter().filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7F).contains(&b) || b >= 0x80).count();
    ok as f64 / d.len() as f64
}

/// 对一组记录做未知协议试探
pub fn probe(channel: &str, recs: &[&Record]) -> UnknownReport {
    let total_bytes: usize = recs.iter().map(|r| r.data.len()).sum();
    let mut rep = UnknownReport {
        channel: channel.to_string(),
        n_records: recs.len(),
        total_bytes,
        verdict: Verdict::Opaque,
        sync: None,
        length: None,
        fixed_len: None,
        checksum: None,
        confidence: 0.0,
        hints: vec![],
        draft: None,
        notes: vec![],
    };
    if recs.is_empty() || total_bytes < 32 {
        rep.notes.push("样本太少,无法试探".into());
        return rep;
    }

    // ---- 0) 文本 / NDJSON ----
    let printable: f64 = recs.iter().map(|r| printable_ratio(&r.data)).sum::<f64>() / recs.len() as f64;
    if printable > 0.9 {
        let mut json_n = 0;
        let mut json_ok = 0;
        for r in recs.iter().take(200) {
            let t = String::from_utf8_lossy(&r.data);
            let t = t.trim();
            if t.starts_with('{') || t.starts_with('[') {
                json_n += 1;
                if serde_json::from_str::<serde_json::Value>(t).is_ok() {
                    json_ok += 1;
                }
            }
        }
        if json_n > 0 && json_ok as f64 / json_n as f64 > 0.8 {
            rep.verdict = Verdict::NDJson;
            rep.confidence = 1.0;
        } else {
            rep.verdict = Verdict::Text;
            rep.confidence = printable;
        }
        return rep;
    }

    // ---- 1) "记录即帧"假设:整行校验网格 ----
    let sample: Vec<&[u8]> = recs.iter().take(400).map(|r| &r.data[..]).collect();
    let min_len = sample.iter().map(|d| d.len()).min().unwrap_or(0);
    if min_len < 6 {
        rep.notes.push("记录过短".into());
        return rep;
    }
    let cks = probe_checksum_over_records(&sample);
    if let Some((algo, cover_start, el, rate)) = &cks {
        rep.verdict = Verdict::Framed;
        rep.checksum = Some((algo.clone(), *cover_start, *el));
        rep.confidence = *rate;
        rep.notes.push(format!("整行校验命中率 {:.0}%", rate * 100.0));
    }

    // ---- 2) 长度域优先,固定帧长兜底 ----
    let (fixed_len, fl_rate) = probe_fixed_len(&sample);
    let lenfield = probe_length_field(&sample, true);
    if let Some((p, w, le, bias, rate)) = lenfield {
        rep.length = Some((p, w, le, bias));
        rep.verdict = Verdict::Framed;
        rep.notes.push(format!(
            "长度域 @{} 大小{} {} 偏移{}(命中率 {:.0}%)",
            p,
            w,
            if le { "LE" } else { "BE" },
            bias,
            rate * 100.0
        ));
        rep.confidence = rep.confidence.max(rate.min(0.99));
    } else if let Some(fl) = fixed_len {
        rep.fixed_len = Some(fl);
        rep.verdict = Verdict::Framed;
        rep.notes.push(format!("固定帧长 {fl}(命中率 {:.0}%)", fl_rate * 100.0));
        rep.confidence = rep.confidence.max(fl_rate.min(0.95));
    }

    // ---- 3) 同步头候选 ----
    let sync = probe_sync(&sample, rep.length.map(|(p, _, _, _)| p));
    if let Some((s, freq)) = &sync {
        rep.sync = Some(s.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(""));
        rep.verdict = Verdict::Framed;
        rep.notes.push(format!("同步头命中率 {:.0}%", freq * 100.0));
        rep.confidence = rep.confidence.max(*freq * 0.6);
    }

    // ---- 4) 流式回退:无"记录即帧"结构时按同步头+间隙定界 ----
    if rep.verdict != Verdict::Framed && rep.sync.is_none() {
        if let Some((s, conf, _frames)) = probe_stream_mode(&sample) {
            rep.sync = Some(s.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(""));
            rep.verdict = Verdict::Framed;
            rep.confidence = conf;
            rep.notes.push("按流内同步头间隙定界(弱结构)".into());
        }
    }

    // ---- 5) 字段区域猜测 ----
    if rep.verdict == Verdict::Framed {
        rep.hints = probe_field_hints(&sample, &rep);
    }

    // ---- 6) 生成草案 ----
    rep.draft = build_draft(&rep);
    rep
}

/// 整行即帧:测试校验算法网格(cover_start ∈ {0,1,2} 跳过可能的同步头,at = 行尾-k)
fn probe_checksum_over_records(sample: &[&[u8]]) -> Option<(String, usize, usize, f64)> {
    let mut best: Option<(String, usize, usize, f64)> = None;
    for start in [0usize, 1, 2] {
        for (algo, el) in ALGOS2.iter().chain(ALGOS1.iter()) {
            let mut ok = 0usize;
            let mut n = 0usize;
            for d in sample {
                if d.len() < start + *el + 3 {
                    continue;
                }
                n += 1;
                let at = d.len() - el;
                if let Some(expect) = crc::calc(algo, &d[start..at]) {
                    if d[at..at + el] == expect[..] {
                        ok += 1;
                    }
                }
            }
            if n == 0 {
                continue;
            }
            let rate = ok as f64 / n as f64;
            if rate >= 0.85 && best.as_ref().map(|b| rate > b.3).unwrap_or(true) {
                best = Some((algo.to_string(), start, *el, rate));
            }
        }
    }
    best
}

/// 固定帧长:记录长度众数占比 ≥ 0.9
fn probe_fixed_len(sample: &[&[u8]]) -> (Option<u16>, f64) {
    let mut freq: HashMap<usize, usize> = HashMap::new();
    for d in sample {
        *freq.entry(d.len()).or_default() += 1;
    }
    if let Some((&l, &c)) = freq.iter().max_by_key(|(_, c)| **c) {
        let rate = c as f64 / sample.len() as f64;
        if rate >= 0.9 && l >= 6 {
            return (Some(l as u16), rate);
        }
        return (None, rate);
    }
    (None, 0.0)
}

/// 长度域:位置 p、宽度 w、字节序 → bias = 记录长 − 值 的众数
fn probe_length_field(sample: &[&[u8]], enable: bool) -> Option<(usize, u8, bool, i32, f64)> {
    if !enable {
        return None;
    }
    let min_len = sample.iter().map(|d| d.len()).min().unwrap_or(0);
    let max_p = min_len.min(6);
    let mut best: Option<(usize, u8, bool, i32, f64)> = None;
    for p in 1..max_p {
        for w in [1u8, 2] {
            for le in [true, false] {
                let mut bias_freq: HashMap<i32, usize> = HashMap::new();
                let mut n = 0usize;
                for d in sample {
                    if d.len() < p + w as usize {
                        continue;
                    }
                    let v: i64 = if w == 1 {
                        d[p] as i64
                    } else if le {
                        u16::from_le_bytes([d[p], d[p + 1]]) as i64
                    } else {
                        u16::from_be_bytes([d[p], d[p + 1]]) as i64
                    };
                    n += 1;
                    *bias_freq.entry((d.len() as i64 - v).clamp(-64, 4096) as i32).or_default() += 1;
                }
                if n == 0 {
                    continue;
                }
                if let Some((&bias, &c)) = bias_freq.iter().max_by_key(|(_, c)| **c) {
                    let rate = c as f64 / n as f64;
                    if rate >= 0.8 && bias > 0 && bias < 4096 {
                        if best.as_ref().map(|b| rate > b.4).unwrap_or(true) {
                            best = Some((p, w, le, bias, rate));
                        }
                    }
                }
            }
        }
    }
    best
}

/// 同步头:记录起始 n-gram 的高频候选(排除全 0x00/0xFF 填充)
fn probe_sync(sample: &[&[u8]], len_pos: Option<usize>) -> Option<(Vec<u8>, f64)> {
    let min_len = sample.iter().map(|d| d.len()).min().unwrap_or(0);
    if min_len < 3 {
        return None;
    }
    // 1-2 字节同步头最常见(AA55/5AA5/68/7E…):2 字节频率不低于 1 字节时优先取 2 字节;n=3 仅兜底
    let ngram_freq = |n: usize| -> Vec<(Vec<u8>, f64)> {
        let mut freq: HashMap<Vec<u8>, usize> = HashMap::new();
        for d in sample {
            if d.len() >= n {
                *freq.entry(d[..n].to_vec()).or_default() += 1;
            }
        }
        freq.into_iter()
            .filter(|(k, c)| {
                let f = *c as f64 / sample.len() as f64;
                f >= 0.5 && !k.iter().all(|&b| b == 0x00 || b == 0xFF)
            })
            .map(|(k, c)| (k, c as f64 / sample.len() as f64))
            .filter(|(k, _)| len_pos.map(|p| p as usize >= k.len()).unwrap_or(true))
            .collect()
    };
    let f1 = ngram_freq(1).into_iter().max_by(|a, b| a.1.total_cmp(&b.1));
    let f2 = ngram_freq(2).into_iter().max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.len().cmp(&a.0.len())));
    let pick2 = match (&f1, &f2) {
        (Some(a), Some(b)) => b.1 >= a.1 - 1e-9,
        (None, Some(_)) => true,
        _ => false,
    };
    if pick2 {
        return f2;
    }
    if let Some(a) = f1 {
        return Some(a);
    }
    // 兜底:3 字节
    ngram_freq(3).into_iter().max_by(|a, b| a.1.total_cmp(&b.1))
}

/// 流式回退:在拼接流里找高频 n-gram,验证其出现间隙的稳定性
fn probe_stream_mode(sample: &[&[u8]]) -> Option<(Vec<u8>, f64, usize)> {
    let mut stream = Vec::new();
    for d in sample.iter().take(200) {
        stream.extend_from_slice(d);
        if stream.len() > 128 * 1024 {
            break;
        }
    }
    // 候选:出现次数多的 2-3 字节 n-gram
    let mut cands: Vec<Vec<u8>> = vec![];
    for n in [2usize, 3] {
        let mut freq: HashMap<Vec<u8>, usize> = HashMap::new();
        for k in 0..stream.len().saturating_sub(n) {
            *freq.entry(stream[k..k + n].to_vec()).or_default() += 1;
        }
        let mut v: Vec<(Vec<u8>, usize)> = freq.into_iter().filter(|(k, c)| *c >= 20 && !k.iter().all(|&b| b == 0)).collect();
        v.sort_by_key(|(_, c)| -(*c as i64));
        cands.extend(v.into_iter().take(4).map(|(k, _)| k));
    }
    for s in &cands {
        let positions: Vec<usize> = (0..stream.len().saturating_sub(s.len()))
            .filter(|&k| &stream[k..k + s.len()] == s.as_slice())
            .collect();
        if positions.len() < 10 {
            continue;
        }
        // 间隙众数占比
        let mut gaps: HashMap<usize, usize> = HashMap::new();
        for w in positions.windows(2) {
            *gaps.entry(w[1] - w[0]).or_default() += 1;
        }
        if let Some((&g, &c)) = gaps.iter().max_by_key(|(_, c)| **c) {
            let share = c as f64 / (positions.len() - 1) as f64;
            if g >= 6 && share >= 0.6 {
                // 固定间隙 → 定界帧并试校验
                let frames: Vec<&[u8]> = positions.iter().filter_map(|&p| stream.get(p..p + g)).collect();
                if let Some((_, _, _, rate)) = probe_checksum_over_records(&frames) {
                    if rate >= 0.85 {
                        return Some((s.clone(), (share * 0.5 + rate * 0.5).min(0.99), frames.len()));
                    }
                }
                return Some((s.clone(), share * 0.6, frames.len()));
            }
        }
    }
    None
}

/// 字段区域猜测:常量 / 计数器 / 高熵载荷
fn probe_field_hints(sample: &[&[u8]], rep: &UnknownReport) -> Vec<FieldHint> {
    let hdr = rep.sync.as_ref().map(|s| s.len() / 2).unwrap_or(0);
    let tail = rep.checksum.as_ref().map(|(_, _, el)| *el).unwrap_or(0);
    let body_start = rep.length.map(|(p, _, _, _)| p + 1).unwrap_or(hdr.max(2));
    let max_len = sample.iter().map(|d| d.len()).min().unwrap_or(0).saturating_sub(tail);
    let body_end = max_len;
    if body_start >= body_end {
        return vec![];
    }
    let mut hints = vec![];
    for p in body_start..body_end.min(body_start + 64) {
        let vals: Vec<u8> = sample.iter().filter(|d| d.len() > p).map(|d| d[p]).collect();
        if vals.len() < sample.len() / 2 {
            continue;
        }
        if vals.iter().all(|&v| v == vals[0]) {
            hints.push(FieldHint { pos: p, kind: "常量".into(), detail: format!("恒为 0x{:02X}", vals[0]) });
            continue;
        }
        // 计数器:+1 步进占比
        let step1 = vals.windows(2).filter(|w| w[1] == w[0].wrapping_add(1)).count();
        let rate = step1 as f64 / (vals.len().saturating_sub(1)) as f64;
        if rate >= 0.85 {
            hints.push(FieldHint { pos: p, kind: "计数器".into(), detail: format!("递增步进率 {:.0}%", rate * 100.0) });
        }
    }
    // 中部高熵区标记为载荷
    if body_end > body_start + 2 {
        hints.push(FieldHint {
            pos: body_start,
            kind: "载荷".into(),
            detail: format!("区域 [{}, {}) 值变化较大,大概率是数据域", body_start, body_end),
        });
    }
    hints
}

/// 组装 CustomSpec 草案
fn build_draft(rep: &UnknownReport) -> Option<CustomSpec> {
    if rep.verdict != Verdict::Framed {
        return None;
    }
    let mut fields: Vec<FieldSpec> = vec![];
    let hdr = rep.sync.as_ref().map(|s| s.len() / 2).unwrap_or(0);
    for h in &rep.hints {
        if h.kind == "常量" || h.kind == "计数器" {
            fields.push(FieldSpec {
                name: format!("pos{}_{}", h.pos, if h.kind == "常量" { "const" } else { "cnt" }),
                at: h.pos as u16,
                ty: "u8".into(),
                endian: Endian::Little,
                scale: 1.0,
                offset: 0.0,
                unit: String::new(),
                plot: h.kind == "计数器",
                size: None,
                bits: None,
            });
        }
    }
    let _ = hdr;
    Some(CustomSpec {
        name: format!("probe_{}", rep.channel.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>()),
        sync: rep.sync.clone(),
        frame_len: rep.fixed_len,
        length: rep.length.map(|(p, w, le, bias)| LenSpec {
            at: Off::Abs(p as u16),
            size: w,
            endian: if le { Endian::Little } else { Endian::Big },
            bias,
            include_header: false,
        }),
        checksum: rep.checksum.as_ref().map(|(algo, cover_start, el)| CksSpec {
            algo: algo.clone(),
            at: Some(Off::EndMinus(*el as u16)),
            cover: (Off::Abs(*cover_start as u16), Off::EndMinus(*el as u16)),
        }),
        min_len: 6,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Proto;

    fn build_frame(t: u32) -> Vec<u8> {
        // 5A A5 | type(0x81) | len(6) | pressure u16 BE | flow i16 LE | status | counter | sum8(cover[2..end-1])
        let mut f = vec![0x5A, 0xA5, 0x81, 0x06];
        f.extend_from_slice(&(1200 + (t % 100) as u16).to_be_bytes());
        f.extend_from_slice(&((t % 50) as i16).to_le_bytes());
        f.push(0x03);
        f.push((t & 0xFF) as u8);
        let s = crc::sum8(&f[2..]);
        f.push(s);
        f
    }

    fn mkrecs(frames: Vec<Vec<u8>>) -> Vec<Record> {
        frames
            .into_iter()
            .map(|d| Record {
                t_ns: 0,
                ts_src: crate::model::TsSrc::Sw,
                dir: crate::model::Dir::Rx,
                source: 0,
                channel: 0,
                proto: Proto::Raw,
                gap_n: 0,
                can_id: None,
                data: d.into(),
            })
            .collect()
    }

    #[test]
    fn probe_finds_structure() {
        let frames: Vec<Vec<u8>> = (0..100).map(build_frame).collect();
        let recs = mkrecs(frames);
        let refs: Vec<&Record> = recs.iter().collect();
        let rep = probe("test", &refs);
        assert_eq!(rep.verdict, Verdict::Framed);
        assert_eq!(rep.sync.as_deref(), Some("5AA5"));
        assert!(rep.confidence > 0.8, "conf={}", rep.confidence);
        assert_eq!(rep.length, Some((3, 1, true, 5)), "长度域应定位到 pos3/LE/bias5(帧总长11-长度值6)");
        assert!(rep.checksum.as_ref().map(|(a, cs, el)| a == "sum8" && *el == 1).unwrap_or(false));
        // 计数器提示
        assert!(rep.hints.iter().any(|h| h.kind == "计数器"), "hints={:?}", rep.hints);
        // 草案可序列化且能反解
        let spec = rep.draft.expect("应有草案");
        let json = serde_json::to_string_pretty(&spec).unwrap();
        let spec2: CustomSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec2.sync, spec.sync);
        // 用草案真正去定界原始数据 —— 闭环验证
        let d = &recs[0].data;
        let (frames, skipped) = crate::dissect::custom::deframe(d, &spec2);
        assert_eq!(frames.len(), 1, "草案应能定界一帧");
        assert_eq!(skipped, 0);
    }

    #[test]
    fn probe_text_and_ndjson() {
        let recs = mkrecs((0..30).map(|i| format!(r#"{{"t":{i},"v":{}}}"#, i * 2).into_bytes()).collect());
        let refs: Vec<&Record> = recs.iter().collect();
        let rep = probe("t", &refs);
        assert_eq!(rep.verdict, Verdict::NDJson);
        let recs2 = mkrecs((0..30).map(|i| format!("INFO device{} started ok", i).into_bytes()).collect());
        let refs2: Vec<&Record> = recs2.iter().collect();
        let rep2 = probe("t", &refs2);
        assert_eq!(rep2.verdict, Verdict::Text);
    }
}
