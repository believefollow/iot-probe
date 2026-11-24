//! 解析正确性基线(任务卡 C3,对应任务卡 T-0.2/T-1.5 的 golden 思路):
//! 用独立参照实现 cantools 生成的期望值( scripts/gen_golden.py → test-corpus/golden/*.expected.jsonl )
//! 逐信号比对 iotprobe-core 的 DBC 解码(浮点 1e-6 相对误差)。
//! 语料在仓库外(D:\dev\tools\test-corpus);缺语料或缺 golden 文件时跳过(不 fail)——
//! 基线是 bench 资产,不是 CI 依赖。

use std::path::PathBuf;

use iotprobe_core::dbc;
use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use iotprobe_core::ingest::read_file;
use iotprobe_core::model::Proto;

const CORPUS: &str = r"D:\dev\tools\test-corpus";

struct Pair {
    log: &'static str,
    dbc: &'static str,
    golden: &'static str,
}

const PAIRS: &[Pair] = &[
    Pair { log: "jxdcdc.asc", dbc: "JXDCDC_CAN通讯协议_V0.2 20261008.dbc", golden: "jxdcdc" },
    Pair { log: "04-gb27930/test_27930.asc", dbc: "04-gb27930/gbt27930.dbc", golden: "gb27930" },
];

fn corpus_path(rel: &str) -> PathBuf {
    PathBuf::from(CORPUS).join(rel)
}

/// 期望值:帧序号 → (id, signals)
fn load_golden(name: &str) -> Option<Vec<(u64, u32, std::collections::HashMap<String, f64>)>> {
    let p = corpus_path("golden").join(format!("{name}.expected.jsonl"));
    let txt = std::fs::read_to_string(p).ok()?;
    let mut out = vec![];
    for line in txt.lines() {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        let sigs = v
            .get("signals")?
            .as_object()?
            .iter()
            .filter_map(|(k, x)| x.as_f64().map(|f| (k.clone(), f)))
            .collect();
        out.push((v.get("i")?.as_u64()?, v.get("id")?.as_u64()? as u32, sigs));
    }
    Some(out)
}

#[test]
fn golden_decode_matches_cantools() {
    for pair in PAIRS {
        let Some(expected) = load_golden(pair.golden) else {
            eprintln!("[skip] {} 无 golden 基线(先跑 scripts/gen_golden.py)", pair.golden);
            continue;
        };
        if expected.is_empty() {
            eprintln!("[skip] {} golden 为空", pair.golden);
            continue;
        }
        let log_p = corpus_path(pair.log);
        let dbc_p = corpus_path(pair.dbc);
        if !log_p.exists() || !dbc_p.exists() {
            eprintln!("[skip] 语料缺失: {}", log_p.display());
            continue;
        }
        let sd = read_file(&log_p).unwrap_or_else(|e| panic!("读取 {}: {e}", log_p.display()));
        // 与 GUI 同一入口:GBK DBC 自动回退(textio)
        let (dbc_text, _enc) = iotprobe_core::textio::read_text(&dbc_p).unwrap_or_else(|e| panic!("读取 {}: {e}", dbc_p.display()));
        let db = dbc::parse(&dbc_text);
        let cfg = AnalyzeCfg { dbc: Some(db.clone()), ..Default::default() };
        let ds = analyze(vec![sd], &cfg);
        // 只取 CAN 帧(iotprobe 与 gen_golden 的帧序号口径一致:过滤后顺序)
        let can_frames: Vec<_> = ds
            .frames
            .iter()
            .enumerate()
            .filter(|(_, f)| matches!(f.proto, Proto::Can | Proto::CanFd))
            .collect();
        assert!(
            can_frames.len() >= expected.len(),
            "{}: iotprobe CAN 帧数 {} 少于 golden {}(ASC 解析回归?)",
            pair.golden,
            can_frames.len(),
            expected.len()
        );
        let mut checked = 0usize;
        let mut mismatches: Vec<String> = vec![];
        for (i, id, sigs) in &expected {
            let fi = *i as usize - 1; // golden 的 i 从 1 起
            let Some((_, f)) = can_frames.get(fi) else {
                mismatches.push(format!("帧 {i}: 越界"));
                continue;
            };
            let rec = &ds.records[f.record as usize];
            let data = &rec.data[f.off as usize..(f.off + f.len) as usize];
            // CAN id 在 record 层(bit31=ext),Frame 只带 proto/摘要
            let raw = rec.can_id.unwrap_or(0);
            let ext = raw & 0x8000_0000 != 0;
            let fid = raw & 0x1FFF_FFFF;
            if fid != *id {
                mismatches.push(format!("帧 {i}: id 不一致 golden={:#x} got={:#x}", id, fid));
                continue;
            }
            let key = dbc::msg_key(fid, ext);
            let got = dbc::decode_message(&db, key, data);
            for (sig_name, exp_v) in sigs {
                match got.iter().find(|(s, _, _)| s.name == *sig_name) {
                    Some((_, v, _)) => {
                        let ok = (v - exp_v).abs() <= 1e-9
                            || (exp_v.abs() > 1e-12 && ((v - exp_v) / exp_v).abs() < 1e-6);
                        if !ok {
                            mismatches.push(format!("帧 {i} 信号 {sig_name}: golden={exp_v} got={v}"));
                        } else {
                            checked += 1;
                        }
                    }
                    None => mismatches.push(format!("帧 {i} 信号 {sig_name}: iotprobe 未解出(golden={exp_v})")),
                }
            }
        }
        let mismatch_n = mismatches.len();
        assert!(
            mismatch_n == 0,
            "{}: {} 处不一致(前 10):\n{}",
            pair.golden,
            mismatch_n,
            mismatches.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
        );
        eprintln!("[ok] {} 逐信号比对通过: {} 个信号值", pair.golden, checked);
    }
}
