//! 实时接入(FR-S1)/会话录制(FR-S2):后台线程把数据源喂给 core 的 NDJSON 管线,
//! 批次消息推给 UI 累积,由现有 analyze 管线重建 Dataset。
//! 串口(COM)源在本 crate(serialport 依赖不进 core);TCP/回放循环直接复用 core 的 live 模块。

use iotprobe_core::ingest::live::{self, BusKind, LiveSession, LiveStats};
use iotprobe_core::model::{Dir, Record};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// 数据源类型
#[derive(Clone)]
pub enum SourceKind {
    /// 主动连接 serbox(TCP 客户端)
    TcpClient { addr: String },
    /// 监听端口等板子连入(TCP 服务端)
    TcpServer { addr: String },
    /// 本机串口 COM
    Serial { port: String, baud: u32 },
    /// 回放现场录制的 .ndjson(与实时同一解析器)
    Replay { path: PathBuf },
    /// ZLG(周立功)USBCANFD 硬件源(Q3 选型,ADR-0010):动态加载 zlgcan.dll,硬件时戳
    Zlg {
        device_type: String,
        device_index: u32,
        channels: u32,
        bitrate: u32,
        data_bitrate: u32,
        ts_unit_ns: u64,
        listen_only: bool,
    },
    /// 模拟 CAN 总线(无硬件开发/演示)
    Sim,
    /// Modbus RTU over TCP 串口服务器(live 二期 P1,Q4:485 为辅)
    RtuTcp { addr: String, gap_ms: u64 },
    /// SocketCAN 虚拟口(Linux vcan0;Windows 下隐藏,SLCAN 为等效路径)
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    SocketCan { iface: String },
    /// 通用 CAN 硬件卡(VCI/SLCAN/PEAK/Kvaser/GCAN;canhw.rs 后端注册表)
    CanHw {
        vendor: u8, // 0=VCI 1=SLCAN 2=PEAK 3=Kvaser 4=GCAN(ECanVci)
        model: String,
        device_index: u32,
        channels: u32,
        bitrate: u32,
        listen_only: bool,
        fd: bool,
        port: String,
    },
}

pub struct LiveReq {
    pub kind: SourceKind,
    /// 发送面板队列(FR-4.7;仅 ZLG 硬件源消费)
    pub tx_hub: Option<std::sync::Arc<crate::tx::TxHub>>,
    /// 通道别名前缀:帧内无 bus.alias 的通道显示为「前缀·默认名」
    pub alias: Option<String>,
    /// FR-S2 会话录制:原始 NDJSON 行追加落盘
    pub record_path: Option<PathBuf>,
    /// 帧流转发 tee 槽(W:指向其他端口):契约行同步推给转发器;App 可热插拔
    pub tee: Option<Arc<std::sync::Mutex<Option<Sender<String>>>>>,
}

/// 一批新记录 + 会话快照(UI 累积用)
pub struct Batch {
    pub records: Vec<Record>,
    pub labels: HashMap<u16, String>,
    /// 会话统计:None = 来自并入生产者(如回放并入),不覆盖主源统计
    pub stats: Option<LiveStats>,
    pub warnings: Vec<String>,
    pub epoch_ns: Option<u64>,
}

pub enum LiveMsg {
    Batch(Batch),
    /// 线程结束:Ok=停止/对端关闭;Err=出错原因
    Ended(Result<(), String>),
    /// 轻量状态通知(如「并入回放完成」),不影响会话存活
    Info(String),
}

pub struct LiveHandle {
    pub rx: Receiver<LiveMsg>,
    pub stop: Arc<AtomicBool>,
    /// 发送端(独立的模拟器泵线程直接把 Batch 发进同一通道)
    pub tx: Sender<LiveMsg>,
}

impl Drop for LiveHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// 空 sink 通道:不跑任何源,仅供独立的模拟器泵线程推 Batch(界面按 poll_live 正常消费)。
/// stop 置位时泵线程收到 Ended 结束。
pub fn spawn_sink() -> LiveHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    LiveHandle { rx, stop, tx }
}

pub fn spawn(req: LiveReq) -> LiveHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let tx2 = tx.clone();
    std::thread::Builder::new()
        .name("live-ingest".into())
        .spawn(move || {
            let res = run(&req, &tx2, &stop2);
            let _ = tx2.send(LiveMsg::Ended(res));
        })
        .expect("启动实时线程失败");
    LiveHandle { rx, stop, tx }
}

/// 「回放并入实时」运行句柄:drop 即停
pub struct ReplayIntoHandle {
    pub stop: Arc<AtomicBool>,
}

impl Drop for ReplayIntoHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// 起回放并入线程:把录制(.ndjson)/抓包(.asc)文件重映射到目标设备通道,
/// 经既有 live 通道推进当前会话(与主源同屏混流,模拟现场)。
/// t_offset_ns = 并入点在目标时间轴上的位置;speed:1.0 原速 / >1 加速 / 0 极速。
pub fn spawn_replay_into(
    path: &std::path::Path,
    target_ch: u16,
    speed: f64,
    t_offset_ns: u64,
    tx: Sender<LiveMsg>,
) -> Result<ReplayIntoHandle, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let path2 = path.to_path_buf();
    let tx2 = tx.clone();
    std::thread::Builder::new()
        .name("replay-into".into())
        .spawn(move || {
            let mut pipe = live::Pipeline::new(None, None);
            let mut frames: u64 = 0;
            {
                let mut on_batch = |batch: Vec<Record>, sess: &mut LiveSession| {
                    frames += batch.len() as u64;
                    // 通道已重写为目标设备:不携带文件侧标签(避免覆盖目标设备名),不覆盖主源统计
                    let _ = tx2.send(LiveMsg::Batch(Batch {
                        records: batch,
                        labels: HashMap::new(),
                        stats: None,
                        warnings: sess.take_warnings(),
                        epoch_ns: None,
                    }));
                };
                let _ = live::replay_into(&path2, target_ch, speed, t_offset_ns, &stop2, &mut pipe, &mut on_batch);
            }
            let msg = if stop2.load(Ordering::Relaxed) {
                "并入回放已停止".to_string()
            } else {
                format!("并入回放完成:共 {frames} 帧 → 通道 {target_ch}")
            };
            let _ = tx2.send(LiveMsg::Info(msg));
        })
        .map_err(|e| format!("启动并入线程失败: {e}"))?;
    Ok(ReplayIntoHandle { stop })
}

fn run(req: &LiveReq, tx: &Sender<LiveMsg>, stop: &AtomicBool) -> Result<(), String> {
    // FR-S2:录制器在解析前截获原始行(含坏行,保真落盘)
    let recorder = match &req.record_path {
        Some(p) => Some(live::Recorder::create(p)?),
        None => None,
    };
    let mut pipe = live::Pipeline::new(recorder, req.alias.as_deref());
    if let Some(slot) = &req.tee {
        pipe.set_tee_slot(slot.clone());
    }
    let tx2 = tx.clone();
    let mut on_batch = move |batch: Vec<Record>, sess: &mut LiveSession| {
        let _ = tx2.send(LiveMsg::Batch(Batch {
            records: batch,
            labels: sess.labels(),
            stats: Some(sess.stats()),
            warnings: sess.take_warnings(),
            epoch_ns: sess.epoch_ns(),
        }));
    };
    match &req.kind {
        SourceKind::Replay { path } => {
            // .asc 抓包直接回放(ASC→Record→同一实时管线);其余按 NDJSON 流式
            let is_asc = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("asc"))
                .unwrap_or(false);
            if is_asc {
                live::replay_asc_file(path, stop, &mut pipe, &mut on_batch)?;
            } else {
                live::replay_file(path, stop, &mut pipe, &mut on_batch)?;
            }
        }
        SourceKind::TcpClient { addr } => {
            let mut stream = live::open_tcp_client(addr, stop)?;
            live::pump(&mut stream, stop, &mut pipe, &mut on_batch)?;
        }
        SourceKind::TcpServer { addr } => {
            let mut stream = live::open_tcp_server(addr, stop)?;
            live::pump(&mut stream, stop, &mut pipe, &mut on_batch)?;
        }
        SourceKind::Serial { port, baud } => {
            let mut port_ = serialport::new(port, *baud)
                .timeout(Duration::from_millis(100))
                .open()
                .map_err(|e| format!("打开串口 {port}@{baud} 失败: {e}"))?;
            live::pump(&mut *port_, stop, &mut pipe, &mut on_batch)?;
        }
        SourceKind::Zlg { device_type, device_index, channels, bitrate, data_bitrate, ts_unit_ns, listen_only } => {
            let mut src = crate::zlg::ZlgSource::open(
                crate::zlg::ZlgConfig {
                device_type: device_type.clone(),
                device_index: *device_index,
                channels: *channels,
                bitrate: *bitrate,
                data_bitrate: *data_bitrate,
                ts_unit_ns: *ts_unit_ns,
                listen_only: *listen_only,
            }, req.tx_hub.clone().unwrap_or_else(|| std::sync::Arc::new(crate::tx::TxHub::new())))?;
            live::pump(&mut src, stop, &mut pipe, &mut on_batch)?;
        }
        SourceKind::Sim => {
            let mut src = crate::sim::SimSource::new();
            live::pump(&mut src, stop, &mut pipe, &mut on_batch)?;
        }
        SourceKind::SocketCan { iface } => {
            #[cfg(target_os = "linux")]
            {
                let mut src = crate::canhw::SocketCanSource::open(&iface)?;
                live::pump(&mut src, stop, &mut pipe, &mut on_batch)?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = iface;
                Err("SocketCAN 仅在 Linux 可用(vcan0);Windows 请用「CAN卡·SLCAN」连接 CANable,效果等同虚拟 CAN 口".to_string())?;
                unreachable!()
            }
        }
        SourceKind::CanHw { vendor, model, device_index, channels, bitrate, listen_only, fd, port } => {
            let cfg = crate::canhw::HwConfig {
                vendor: crate::canhw::hw_vendor(*vendor),
                model: model.clone(),
                device_index: *device_index,
                channels: *channels,
                bitrate: *bitrate,
                listen_only: *listen_only,
                fd: *fd,
                port: port.clone(),
            };
            let hub = req.tx_hub.clone().unwrap_or_else(|| std::sync::Arc::new(crate::tx::TxHub::new()));
            let mut src = crate::canhw::open(&cfg, hub)?;
            live::pump(&mut src, stop, &mut pipe, &mut on_batch)?;
        }
        SourceKind::RtuTcp { addr, gap_ms } => {
            let stream = live::open_tcp_client(addr, stop)?;
            let mut src = crate::rtu_tcp::RtuTcpSource::new(stream, *gap_ms);
            live::pump(&mut src, stop, &mut pipe, &mut on_batch)?;
        }
    }
    Ok(())
}

/// LiveFrame → frame.schema.json 形态的契约 NDJSON 行(ZLG/模拟源共用)。
/// 硬件源与回放文件同一表示,录制文件天然可回放(FR-S2 闭环)。
pub fn live_frame_to_jsonl(f: &iotprobe_core::ingest::live::LiveFrame) -> String {
    let bus_type = match f.bus_type {
        BusKind::Can => "can",
        BusKind::CanFd => "canfd",
        BusKind::Uart => "uart",
        BusKind::Ecat => "ecat",
        BusKind::Tcp => "tcp",
    };
    let dir = match f.dir {
        Dir::Rx => "rx",
        Dir::Tx => "tx",
        Dir::Unknown => "rx", // ADR-0007:无方向 → rx + assumed_dir
    };
    let id_type = match f.bus_type {
        BusKind::Can | BusKind::CanFd => {
            if f.id_ext { "ext" } else { "std" }
        }
        _ => "none",
    };
    let mut meta = serde_json::Map::new();
    if let Some(sq) = f.seq {
        meta.insert("seq".into(), serde_json::json!(sq));
    }
    if let Some(g) = f.meta_gap {
        meta.insert("gap".into(), serde_json::json!(g));
    }
    if f.dir == Dir::Unknown {
        meta.insert("assumed_dir".into(), serde_json::json!(true));
    }
    // alias 为 None 时必须省略字段：core 解析器对 alias 无条件 parse_string，
    // 输出 null 会被整行判坏行（schema 中 alias 为 optional，省略才是正确形态）；
    // 与 websrv 侧同源修复（2026-11-16，回归测试见本文件末尾）
    let bus = match &f.alias {
        Some(a) => serde_json::json!({"type": bus_type, "ch": f.ch, "alias": a}),
        None => serde_json::json!({"type": bus_type, "ch": f.ch}),
    };
    let obj = serde_json::json!({
        "ts_ns": f.ts_ns,
        "ts_src": f.ts_src.label(),
        "bus": bus,
        "dir": dir,
        "id": f.id,
        "id_type": id_type,
        "dlc": f.data.len(),
        "data": f.data.iter().map(|b| serde_json::json!(b)).collect::<Vec<_>>(),
        "meta": meta,
    });
    serde_json::to_string(&obj).unwrap_or_default()
}

/// 扫描本机串口(COM 口名列表,供下拉选择)
pub fn available_ports() -> Vec<String> {
    match serialport::available_ports() {
        Ok(ps) => ps.into_iter().map(|p| p.port_name).collect(),
        Err(_) => vec![],
    }
}

/// 弹窗表单状态(main.rs 持有)
#[derive(Clone)]
pub struct LiveForm {
    /// 0=TCP 客户端 1=TCP 服务端 2=串口 3=回放(默认) 4=ZLG USBCANFD 5=模拟CAN 6=RTU-TCP 7=Modbus设备模拟器 8=VCI 9=SLCAN
    pub kind: usize,
    /// Modbus 设备模拟器:点位表路径(kind=7)
    pub moddev_yaml: Option<PathBuf>,
    /// CAN 硬件卡(kind=8/9/11/12/13):VCI/GCAN 型号(数字直传) / 通用波特率 / 只听 / FD
    pub hw_model: String,
    pub hw_baud: u32,
    pub hw_listen_only: bool,
    pub hw_fd: bool,
    pub addr: String,
    pub port_name: String,
    pub baud: u32,
    pub alias: String,
    pub record: bool,
    pub record_path: Option<PathBuf>,
    pub replay_path: Option<PathBuf>,
    pub replay_merge: bool,
    pub replay_speed_idx: usize,
    pub replay_target_ch: u16,
    pub ports: Vec<String>,
    /// ZLG 配置(Q3:ZLG USBCAN-FD2 → 设备类型 USBCANFD-200U,双通道)
    pub device_type: String,
    pub device_index: u32,
    pub channels: u32,
    /// 仲裁/数据段波特率(kbps,ZLG 配置口径)
    pub baud_k: u32,
    pub data_baud_k: u32,
    /// 硬件时戳单位:0=0.1ms(默认) 1=10µs 2=1µs(T-1.3 bench 核对)
    pub ts_unit: usize,
    /// 只听模式(FR-10.4 只读)
    pub listen_only: bool,
    /// RTU-over-TCP 静默间隙 ms(live Modbus 485,P1)
    pub rtu_gap_ms: u64,
    /// 设备模拟器:NDJSON 录制开关与落盘路径(模拟联调留档/回放)
    pub sim_record: bool,
    pub sim_record_path: Option<PathBuf>,
    /// 发送表单(FR-4.7)
    pub tx_id: String,
    pub tx_ext: bool,
    pub tx_fd: bool,
    pub tx_brs: bool,
    pub tx_data: String,
    pub tx_interval_ms: u32,
}

impl Default for LiveForm {
    fn default() -> Self {
        Self {
            // 默认文件导入(回放):拿到录制/抓包文件即可重现现场
            kind: 3,
            // serbox AP 模式默认网段;端口按板子固件默认占位,可改
            addr: "192.168.4.1:9000".into(),
            port_name: "COM3".into(),
            baud: 115200,
            alias: String::new(),
            record: false,
            record_path: None,
            replay_path: None,
            replay_merge: false,
            replay_speed_idx: 0,
            replay_target_ch: 0,
            moddev_yaml: None,
            hw_model: "USBCAN2".into(),
            hw_baud: 500_000,
            hw_listen_only: false,
            hw_fd: false,
            ports: vec![],
            device_type: "USBCANFD-200U".into(),
            device_index: 0,
            channels: 2,
            baud_k: 500,
            data_baud_k: 2000,
            ts_unit: 0,
            listen_only: true, // 默认只听,防误发干扰现场(FR-10.4)
            rtu_gap_ms: 30,
            sim_record: false,
            sim_record_path: None,
            tx_id: "0x1A0".into(),
            tx_ext: false,
            tx_fd: false,
            tx_brs: false,
            tx_data: "01 02 03 04 05 06 07 08".into(),
            tx_interval_ms: 0,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iotprobe_core::ingest::live::{parse_line, BusKind, LiveFrame};
    use iotprobe_core::model::{Dir, TsSrc};

    fn frame(alias: Option<String>) -> LiveFrame {
        LiveFrame {
            ts_ns: 12_000_000,
            ts_src: TsSrc::Sw,
            bus_type: BusKind::Can,
            ch: 0,
            alias,
            dir: Dir::Rx,
            id: 0x1A0,
            id_ext: false,
            dlc: 2,
            data: vec![1, 2],
            seq: Some(1),
            meta_gap: None,
        }
    }

    /// 回归：alias=None 序列化必须省略 alias 字段且能被 core 解析器接受
    /// （修复前输出 "alias":null → parse_line 整行判坏行，GUI 模拟源路径受影响）
    #[test]
    fn alias_none_omitted_and_parseable() {
        let line = live_frame_to_jsonl(&frame(None));
        assert!(!line.contains("\"alias\""), "alias=None 不应输出 alias 字段: {line}");
        let parsed = parse_line(&line).expect("序列化行必须能被 core 解析器接受");
        assert_eq!(parsed.id, 0x1A0);
        assert!(parsed.alias.is_none());
    }

    #[test]
    fn alias_some_roundtrip() {
        let line = live_frame_to_jsonl(&frame(Some("BMS-CAN".into())));
        let parsed = parse_line(&line).expect("序列化行必须能被 core 解析器接受");
        assert_eq!(parsed.alias.as_deref(), Some("BMS-CAN"));
    }

    #[test]
    fn replay_into_merges_via_tx() {
        // 回归:并入批次必须重写通道、不带 labels/stats,并以 Info 报完成
        let dir = std::env::temp_dir().join("iotprobe_replay_into_app");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.ndjson");
        let base: u64 = 1_700_000_000_000_000_000;
        let mut text = String::new();
        for i in 0..3u64 {
            text.push_str(&format!(
                "{{\"ts_ns\":{},\"ts_src\":\"sw\",\"bus\":{{\"type\":\"uart\",\"ch\":1}},\"dir\":\"rx\",\"id\":0,\"id_type\":\"none\",\"dlc\":2,\"data\":[1,{}]}}\n",
                base + i * 100_000_000,
                i
            ));
        }
        std::fs::write(&p, text).unwrap();
        let h = spawn_sink();
        let rh = spawn_replay_into(&p, 9, 0.0, 0, h.tx.clone()).unwrap();
        let mut recs = 0usize;
        let mut saw_info = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            match h.rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(LiveMsg::Batch(b)) => {
                    recs += b.records.len();
                    assert!(b.records.iter().all(|r| r.channel == 9), "通道应重写为 9");
                    assert!(b.labels.is_empty(), "并入批次不携带文件侧标签");
                    assert!(b.stats.is_none(), "并入批次不覆盖主源统计");
                }
                Ok(LiveMsg::Info(s)) => {
                    assert!(s.contains("完成"), "自然结束应报完成: {s}");
                    saw_info = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert_eq!(recs, 3);
        assert!(saw_info, "应收到完成 Info");
        drop(rh); // drop 即停
    }
}

// ==================== 帧流转发(MVP:指向其他端口,模块独立交互) ====================
// 现场 A 机连硬件采集 → 本转发器把契约帧流(NDJSON)广播到 TCP 端口 →
// 任意脚本/第二台 iotprobe/BI 工具实时消费。与录制同一契约格式(frame.schema.json)。
// 设计:accept+broadcast 单线程(非阻塞):App 经 mpsc 推行,慢客户端写失败即剔除,绝不阻塞采集。

use std::sync::atomic::AtomicUsize;

/// 帧流转发器:监听 TCP 端口,把契约帧行广播给全部已连客户端
pub struct Forwarder {
    pub stop: Arc<AtomicBool>,
    /// 槽位同款:行级发送(管线每契约行一笔;转发线程批量广播)
    pub tx: std::sync::mpsc::Sender<String>,
    pub clients: Arc<AtomicUsize>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Forwarder {
    pub fn client_count(&self) -> usize {
        self.clients.load(Ordering::Relaxed)
    }
}

/// 起帧流转发器(port 0 = 系统分配,bind_port 如实回传)
pub fn spawn_forwarder(port: u16) -> Result<(Forwarder, u16), String> {
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|e| format!("转发端口 {port} 绑定失败: {e}"))?;
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    listener.set_nonblocking(true).ok();
    let stop = Arc::new(AtomicBool::new(false));
    let clients = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    {
        let stop2 = stop.clone();
        let clients2 = clients.clone();
        std::thread::Builder::new()
            .name("fwd-broadcast".into())
            .spawn(move || {
                let mut sinks: Vec<TcpStream> = vec![];
                loop {
                    if stop2.load(Ordering::Relaxed) {
                        return;
                    }
                    // 新客户端
                    if let Ok((stream, _)) = listener.accept() {
                        stream.set_nodelay(true).ok();
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
                        clients2.fetch_add(1, Ordering::Relaxed);
                        sinks.push(stream);
                    }
                    // 推行广播(App 经 mpsc 送来)
                    let lines: Vec<String> = rx.try_iter().collect();
                    if !lines.is_empty() {
                        let mut payload = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
                        for l in lines {
                            payload.push_str(&l);
                            payload.push('\n');
                        }
                        let bytes = payload.as_bytes();
                        sinks.retain_mut(|s| s.write_all(bytes).is_ok());
                        clients2.store(sinks.len(), Ordering::Relaxed);
                    }
                    std::thread::sleep(Duration::from_millis(30));
                }
            })
            .ok();
    }
    Ok((Forwarder { stop, tx, clients }, bound))
}

#[cfg(test)]
mod forwarder_tests {
    use super::*;

    #[test]
    fn forwarder_loopback() {
        // W-转发:契约行 → TCP 客户端收到(现场 A 机采集 → 远端消费 的最小闭环)
        let (fw, port) = spawn_forwarder(0).unwrap();
        assert!(port > 0);
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        std::thread::sleep(Duration::from_millis(120)); // 等 accept
        assert_eq!(fw.client_count(), 1, "客户端应已连入");
        fw.tx.send("{\"ts_ns\":0,\"bus\":{\"type\":\"can\",\"ch\":0}}".into()).unwrap();
        let mut buf = vec![0u8; 256];
        let n = std::io::Read::read(&mut c, &mut buf).unwrap();
        let got = String::from_utf8_lossy(&buf[..n]);
        assert!(got.contains("\"type\":\"can\""), "应收到契约行: {got}");
        // 广播批量化:第二行也到
        fw.tx.send("line2".into()).unwrap();
        let mut buf2 = vec![0u8; 64];
        let n2 = std::io::Read::read(&mut c, &mut buf2).unwrap();
        assert!(String::from_utf8_lossy(&buf2[..n2]).contains("line2"));
        drop(fw); // stop
    }
}
