//! 摄入线程(live Pipeline 累积 Record)+ 分析线程(周期 analyze → 信号/事件增量广播)。
//! 会话策略(ADR-0012):记录全量累积,保证规则 for 持续时长与速率窗口语义稳定;
//! 信号/事件按 t_ns 增量发送,(t_ns,code,message) 去重防止重分析重发。

use crate::{Hub, StatsCounters};
use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use iotprobe_core::ingest::live::{self, LiveSession};
use iotprobe_core::ingest::SourceData;
use iotprobe_core::model::Record;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
pub struct RecStore {
    pub records: Vec<Record>,
    pub labels: HashMap<u16, String>,
    pub warnings: Vec<String>,
    pub epoch_ns: Option<u64>,
    /// 会话解析计数(诊断用):ok=有效帧 bad=坏行
    pub ok: u64,
    pub bad: u64,
}

const MAX_RECORDS: usize = 150_000; // 演示软上限(约 20 分钟),超限停止摄入(ADR-0012)

pub fn spawn_ingest(
    mut src: crate::sim::SimSource,
    store: Arc<Mutex<RecStore>>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("web-ingest".into())
        .spawn(move || {
            let mut pipe = live::Pipeline::new(None, Some("BMS-CAN"));
            let mut on_batch = move |batch: Vec<Record>, sess: &mut LiveSession| {
                let mut st = store.lock().unwrap();
                if st.records.len() >= MAX_RECORDS {
                    return;
                }
                st.records.extend(batch);
                let s = sess.stats();
                st.ok = s.ok;
                st.bad = s.bad;
                for (k, v) in sess.labels() {
                    st.labels.insert(k, v);
                }
                let w = sess.take_warnings();
                if !w.is_empty() {
                    st.warnings.extend(w);
                }
                if st.epoch_ns.is_none() {
                    st.epoch_ns = sess.epoch_ns();
                }
            };
            let _ = live::pump(&mut src, &stop, &mut pipe, &mut on_batch);
        })
        .expect("启动摄入线程失败")
}

pub fn spawn_analyzer(
    cfg: Arc<AnalyzeCfg>,
    store: Arc<Mutex<RecStore>>,
    hub: Arc<Hub>,
    stats: Arc<StatsCounters>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("web-analyze".into())
        .spawn(move || {
            let sent_signal_t: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
            let sent_events: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
            let ev_seq: AtomicU64 = AtomicU64::new(1);
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(700));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let (records, labels, epoch, warnings) = {
                    let st = store.lock().unwrap();
                    if st.records.is_empty() {
                        continue;
                    }
                    (st.records.clone(), st.labels.clone(), st.epoch_ns, st.warnings.clone())
                };
                let sd = SourceData {
                    name: "web-demo".into(),
                    records,
                    epoch_ns: epoch,
                    warnings,
                    chan_labels: labels,
                };
                let ds = analyze(vec![sd], &cfg);

                // 信号增量:每键只发新点(按 t_ns 单调)
                {
                    let mut sent = sent_signal_t.lock().unwrap();
                    for s in &ds.signals {
                        let last = sent.get(&s.key).copied().unwrap_or(0);
                        let mut maxt = last;
                        let mut n = 0u64;
                        for &(t, v, fi) in &s.pts {
                            if t <= last {
                                continue;
                            }
                            let payload = json!({
                                "name": s.key, "unit": s.unit, "t_ns": t, "value": v, "frame_idx": fi,
                            })
                            .to_string();
                            hub.push("signal", &payload, 0, "");
                            n += 1;
                            if t > maxt {
                                maxt = t;
                            }
                        }
                        sent.insert(s.key.clone(), maxt);
                        stats.signal_pts.fetch_add(n, Ordering::Relaxed);
                    }
                }

                // 事件增量:按 (t_ns|code|message) 去重后广播
                {
                    let mut sent = sent_events.lock().unwrap();
                    for e in &ds.events {
                        let (code, level, rule_ref, sigs) = match &e.rule {
                            Some(r) => (
                                r.rule_id.clone(),
                                r.level.clone(),
                                json!({"pack": r.pack, "file": r.file, "rule_id": r.rule_id}),
                                r.signals
                                    .iter()
                                    .map(|(n, v, u)| {
                                        let mut o = json!({"name": n, "value": v});
                                        if !u.is_empty() {
                                            o["unit"] = json!(u);
                                        }
                                        o
                                    })
                                    .collect::<Vec<_>>(),
                            ),
                            None => (
                                e.kind.diag_code().to_string(),
                                e.kind.diag_level().to_string(),
                                json!({"pack": "builtin-diag", "file": "crates/core/src/dissect", "rule_id": format!("{:?}", e.kind)}),
                                vec![json!({"name": "t_s", "value": e.t_ns as f64 / 1e9})],
                            ),
                        };
                        let key = format!("{}|{}|{}", e.t_ns, code, e.detail);
                        if !sent.insert(key) {
                            continue;
                        }
                        let fref = e
                            .frame
                            .and_then(|fi| ds.frames.get(fi as usize))
                            .map(|f| format!("{}:{}:{}", f.source, f.channel, f.seq))
                            .unwrap_or_else(|| format!("{}:{}", e.source, e.channel));
                        let id = format!("webdemo:{}", ev_seq.fetch_add(1, Ordering::Relaxed));
                        let payload = json!({
                            "id": id,
                            "ts_ns": e.t_ns,
                            "level": level,
                            "code": code,
                            "source": {"bus_type": "can", "ch": e.channel, "alias": "BMS-CAN"},
                            "message": e.detail,
                            "evidence": {"signals": sigs, "frames_ref": vec![fref], "rule_ref": rule_ref},
                        })
                        .to_string();
                        hub.push("event", &payload, 0, "");
                        stats.events.fetch_add(1, Ordering::Relaxed);
                    }
                    if sent.len() > 100_000 {
                        sent.clear();
                    }
                }
            }
        })
        .expect("启动分析线程失败")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// 隔离实验:SimSource 字节手动喛进 Pipeline,验证 sess.ok 增长(定位 records=0 问题)
    #[test]
    fn sim_through_pipeline_produces_records() {
        let inject = Arc::new(crate::Inject {
            temp_fault: AtomicBool::new(false),
            hb_stall_until: Mutex::new(None),
        });
        let hub = Arc::new(crate::Hub::default());
        let stats = Arc::new(crate::StatsCounters {
            t0: std::time::Instant::now(),
            frames: AtomicU64::new(0),
            signal_pts: AtomicU64::new(0),
            events: AtomicU64::new(0),
        });
        let mut src = crate::sim::SimSource::new(inject, hub, stats.clone());
        let mut pipe = live::Pipeline::new(None, Some("BMS-CAN"));
        let mut batch: Vec<Record> = Vec::new();
        let mut buf = [0u8; 8192];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut reads = 0usize;
        while std::time::Instant::now() < deadline {
            match Read::read(&mut src, &mut buf) {
                Ok(0) => {
                    eprintln!("[test] read 返回 Ok(0) @reads={reads}");
                    break;
                }
                Ok(n) => {
                    pipe.feed_bytes(&buf[..n], &mut batch);
                    reads += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(e) => panic!("read 失败: {e}"),
            }
            if batch.len() > 50 {
                break;
            }
        }
        let st = pipe.sess.stats();
        eprintln!("[test] reads={reads} batch={} frames={} ok={} bad={}", batch.len(), stats.frames.load(Ordering::Relaxed), st.ok, st.bad);
        assert!(batch.len() > 50, "管线应产出记录,实际 {} (ok={}, bad={}, reads={})", batch.len(), st.ok, st.bad, reads);
    }
}
