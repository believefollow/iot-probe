//! 实时接入(FR-S1)/会话录制(FR-S2)集成测试:
//! 本地 mock TCP 源(std::net::TcpListener)推送样例 NDJSON → 解析映射 → 复用现有 analyze 管线。

use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use iotprobe_core::ingest::live::{self, Pipeline};
use iotprobe_core::model::*;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const MOCK: &str = include_str!("data/mock_live.ndjson");

/// 用 Pipeline 逐行解析样例文件,返回 (records, session)
fn feed_mock(alias: Option<&str>) -> (Vec<Record>, live::LiveSession) {
    let mut pipe = Pipeline::new(None, alias);
    let mut recs = vec![];
    for l in MOCK.lines() {
        pipe.feed_line(l, &mut recs);
    }
    pipe.flush_eof(&mut recs);
    let mut sess = pipe.sess;
    sess.take_warnings(); // 清空告警,便于单独断言(用 helper 再取)
    (recs, sess)
}

#[test]
fn mock_lines_map_to_records() {
    // 不清告警版本,用于 warnings 断言
    let mut pipe = Pipeline::new(None, None);
    let mut recs = vec![];
    for l in MOCK.lines() {
        pipe.feed_line(l, &mut recs);
    }
    pipe.flush_eof(&mut recs);
    let st = pipe.sess.stats();
    // 9 行:8 条有效帧(uart rx/tx、can std/ext、canfd、坏行 1 条)
    assert_eq!(st.ok, 8, "8 条有效帧");
    assert_eq!(st.bad, 1, "1 条坏行进 warnings");
    assert_eq!(st.gaps, 1, "seq 2→5 应检出 1 次丢帧");
    assert_eq!(recs.len(), 8);

    // 通道映射:uart ch0 → 0(带 alias),can ch0(canfd 合并)→ 1,uart ch1 → 2
    let labels = pipe.sess.labels();
    assert_eq!(labels.get(&0).unwrap(), "电表-485");
    assert_eq!(labels.get(&1).unwrap(), "BMS-CAN");
    assert_eq!(labels.get(&2).unwrap(), "UART1", "无 alias 用默认名");
    assert_eq!(labels.len(), 3);

    // 时间戳相对化:首帧 t=0,第二帧 10ms;墙钟 ts 记入 epoch
    assert_eq!(recs[0].t_ns, 0);
    assert_eq!(recs[1].t_ns, 10_000_000);
    assert_eq!(pipe.sess.epoch_ns(), Some(1_767_225_600_000_000_000));

    // 字段映射:uart → Raw + dir;ts_src 从 schema 透传
    assert_eq!(recs[0].proto, Proto::Raw);
    assert_eq!(recs[0].dir, Dir::Tx);
    assert_eq!(recs[0].ts_src, TsSrc::Mcu);
    assert_eq!(recs[0].data.as_ref(), &[1, 3, 0, 0, 0, 2, 196, 11]);
    assert_eq!(recs[0].can_id, None);

    // CAN:std id 不带 ext 位;ext id 置 bit31(与 candump/asc 摄入一致)
    assert!(recs.iter().any(|r| r.can_id == Some(0x200)), "std id 0x200");
    assert!(recs.iter().any(|r| r.can_id == Some(0x1FFF_FFFF | 0x8000_0000)), "ext id + bit31");
    assert!(recs.iter().any(|r| r.proto == Proto::CanFd), "canfd 帧映射");
    // 丢帧:gap_n 标注在 seq=5 的帧上(2→5 缺 2 帧)
    let gapped: Vec<&Record> = recs.iter().filter(|r| r.gap_n > 0).collect();
    assert_eq!(gapped.len(), 1);
    assert_eq!(gapped[0].gap_n, 2);

    // 坏行进 warnings
    let warns = pipe.sess.take_warnings();
    assert!(warns.iter().any(|w| w.contains("坏行")), "warns={warns:?}");
    assert!(warns.iter().any(|w| w.contains("丢帧")), "丢帧告警存在");
}

#[test]
fn tcp_mock_end_to_end() {
    // 本地 mock:起 TcpListener,分两段推送样例(验证跨 chunk 的行重组),然后断开
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let b = MOCK.as_bytes();
        s.write_all(&b[..b.len() / 2]).unwrap();
        s.flush().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        s.write_all(&b[b.len() / 2..]).unwrap();
        s.flush().unwrap();
        s.shutdown(std::net::Shutdown::Both).ok();
    });

    let stop = std::sync::Arc::new(AtomicBool::new(false));
    // alias 前缀:帧内无 alias 的通道显示「前缀·默认名」
    let mut pipe = Pipeline::new(None, Some("serbox"));
    let mut got: Vec<Record> = vec![];
    let mut stream = live::open_tcp_client(&addr, &stop).expect("连接 mock 服务端");
    live::pump(&mut stream, &stop, &mut pipe, |batch, _sess| {
        got.extend(batch);
    })
    .expect("读取循环正常结束(对端关闭)");
    srv.join().unwrap();

    assert_eq!(got.len(), 8, "TCP 流应还原全部有效帧");
    assert_eq!(pipe.sess.stats().bad, 1);
    assert_eq!(pipe.sess.labels().get(&0).unwrap(), "电表-485", "帧内 alias 优先");
    assert_eq!(pipe.sess.labels().get(&2).unwrap(), "serbox·UART1", "无 alias 用前缀·默认名");
    assert_eq!(got[0].t_ns, 0, "相对化从 0 开始");
}

#[test]
fn replay_ndjson_file() {
    // 回放 = 同一解析器走文件路径(replay_file)
    let path = std::env::temp_dir().join("iotprobe_replay_test.ndjson");
    std::fs::write(&path, MOCK).unwrap();
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let mut pipe = Pipeline::new(None, None);
    let mut got = vec![];
    live::replay_file(&path, &stop, &mut pipe, |batch, _| got.extend(batch)).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(got.len(), 8);
    assert_eq!(pipe.sess.stats().bad, 1);
    assert_eq!(got[1].data.as_ref(), &[1, 3, 4, 65, 32, 0, 0, 239, 197]);
}

#[test]
fn session_recording_roundtrip() {
    // FR-S2:live 会话期间原始 NDJSON 行追加落盘,离线重新打开同一解析器
    let path = std::env::temp_dir().join("iotprobe_recording_test.ndjson");
    let _ = std::fs::remove_file(&path);
    {
        let recorder = live::Recorder::create(&path).unwrap();
        let mut pipe = Pipeline::new(Some(recorder), None);
        let mut recs = vec![];
        for l in MOCK.lines() {
            pipe.feed_line(l, &mut recs);
        }
        pipe.flush_eof(&mut recs);
        assert_eq!(recs.len(), 8);
    }
    // 录制内容与原始输入逐行一致(含坏行,保真)
    let recorded = std::fs::read_to_string(&path).unwrap();
    let orig: Vec<&str> = MOCK.lines().collect();
    let back: Vec<&str> = recorded.lines().collect();
    assert_eq!(back.len(), orig.len(), "坏行也应落盘");
    for (a, b) in orig.iter().zip(back.iter()) {
        assert_eq!(a.trim(), b.trim());
    }
    // 离线重新打开:read_file 按 .ndjson 路由到同一解析器
    let src = iotprobe_core::ingest::read_file(&path).unwrap();
    assert_eq!(src.records.len(), 8);
    assert_eq!(src.epoch_ns, Some(1_767_225_600_000_000_000));
    assert!(src.warnings.iter().any(|w| w.contains("坏行")));
    assert_eq!(src.chan_labels.get(&0).unwrap(), "电表-485");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn analyze_reuses_existing_pipeline() {
    // 接入现有管线:NDJSON 记录 → analyze → Modbus RTU / CAN 通道、RTT、无响应、流丢段事件
    let (recs, sess) = feed_mock(None);
    let src = sess.into_source("mock", recs);
    let ds = analyze(vec![src], &AnalyzeCfg::default());
    let protos: Vec<Proto> = ds.channels.iter().map(|c| c.proto).collect();
    // uart ch0 的 Modbus RTU 请求/响应对 → 自动识别并配对
    assert!(protos.contains(&Proto::ModbusRtu), "protos={protos:?}");
    // can ch0(含 canfd 帧)→ CAN 通道
    assert!(protos.contains(&Proto::Can), "protos={protos:?}");
    assert!(protos.contains(&Proto::Raw), "uart ch1 走 RAW 兜底,protos={protos:?}");
    // RTT 信号(Rx 响应相对 Tx 请求)
    assert!(
        ds.signals.iter().any(|s| s.key.starts_with("RTT·")),
        "signals={:?}",
        ds.signals.iter().map(|s| &s.key).collect::<Vec<_>>()
    );
    // 第三条请求无响应 → 事务超时事件
    assert!(ds.events.iter().any(|e| e.kind == EventKind::Timeout), "events={:?}", ds.events.iter().map(|e| e.kind).collect::<Vec<_>>());
    // seq 丢帧 → 流丢段事件
    assert!(ds.events.iter().any(|e| e.kind == EventKind::StreamDrop));
    // 时基等级:mcu 帧流 → 通道标注 mcu(L2)
    assert!(ds.channels.iter().any(|c| c.ts_src == TsSrc::Mcu));
}
