//! IEC 104 从机模拟(任务卡 A5):监听 TCP 端口,按 IEC 60870-5-104 从机语义应答与主动上送。
//! - U 帧:STARTDT/STOPDT/TESTFR act→con;I 帧序号每连接独立(ss 发送序号 / vr 接收序号)
//! - 总召唤 C_IC_NA_1(100):激活确认(COT=7)→ 逐点响应(COT=20)→ 激活结束(COT=10)
//! - 时钟同步 C_CS_NA_1(103):COT=7 回读
//! - 遥控 C_SC/DC_NA_1(45/46):激活确认(COT=7)→ 写点位 → 激活结束(COT=10)
//! - 遥信/遥测值来源 = 104 点表 YAML(ioa→ty/init/min/max);Random 场景抖动、Fault 场景翻转遥信
//! - 主动上送:点位值变化(场景/遥控引起)→ COT=3 突发;仅在 STARTDT 之后
//! - 每帧转一条 NDJSON(bus=tcp,一行一 APDU,ADR-0017)进管线 —— 104 解析器直接可用,
//!   主站帧 dir=Tx、从机帧 dir=Rx(与 Modbus 模拟器同口径,事务配对天然成立)

use crate::moddev::{LinkHealth, Scene};
pub use crate::moddev::LinkState;
use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::{BusKind, LiveFrame};
use iotprobe_core::model::{Dir, TsSrc};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------- 点位表 ----------

/// 一个 104 点位(ty = ASDU 类型号:1 单点 / 3 双点 / 9 归一化 / 11 标度化 / 13 短浮点)
#[derive(Clone, Debug)]
pub struct Pt104 {
    pub ioa: u16,
    pub ty: u8,
    pub name: String,
    pub init: f64,
    pub rw: bool,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

/// 一个 104 从机站(单监听端口;公共地址 CA 统一)
#[derive(Clone, Debug)]
pub struct Dev104 {
    pub name: String,
    pub port: u16,
    pub ca: u16,
    pub poll_ms: u64,
    pub points: Vec<Pt104>,
}

fn default_name() -> String { "模拟104从机".into() }
fn default_port() -> u16 { 2404 }
fn default_ca() -> u16 { 1 }
fn default_poll() -> u64 { 5000 }

fn ty_of(s: &str) -> Option<u8> {
    match s.to_ascii_lowercase().as_str() {
        "sp" | "单点" => Some(1),
        "dp" | "双点" => Some(3),
        "na" | "归一化" => Some(9),
        "nb" | "标度化" => Some(11),
        "nc" | "浮点" | "短浮点" => Some(13),
        _ => None,
    }
}

/// 解析 104 点表 YAML;ioa 键支持十进制/0x 十六进制。
/// 兼容两种形态:`dev104: {name,port,ca,poll_ms}` 包裹 + 根级 points;或全部字段平铺在根级。
pub fn parse_104_yaml(text: &str) -> Result<(Dev104, Vec<String>), String> {
    let mut warns = vec![];
    let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).map_err(|e| format!("104 点表 YAML 解析失败: {e}"))?;
    // 站参数:dev104 包裹优先,缺省回退根级
    let dev_node = doc.get("dev104").unwrap_or(&doc);
    fn g<'a>(node: &'a serde_yaml_ng::Value, key: &str) -> Option<&'a serde_yaml_ng::Value> {
        node.get(key)
    }
    let name = g(dev_node, "name").and_then(|x| x.as_str()).unwrap_or(default_name().as_str()).to_string();
    let port = g(dev_node, "port").and_then(|x| x.as_u64()).map(|x| x as u16).unwrap_or_else(default_port);
    let ca = g(dev_node, "ca").and_then(|x| x.as_u64()).map(|x| x as u16).unwrap_or_else(default_ca);
    let poll_ms = g(dev_node, "poll_ms").and_then(|x| x.as_u64()).unwrap_or_else(default_poll);
    let Some(points_node) = doc.get("points").and_then(|p| p.as_mapping()) else {
        return Err("104 点表缺 points 表(dev104 头 + points: <IOA>: {...})".into());
    };
    let mut points = vec![];
    for (k, v) in points_node.iter() {
        // YAML 会把数字键解析成 u64、带 0x 前缀的是字符串——两种形态都收
        let ioa: u16 = if let Some(n) = k.as_u64() {
            u16::try_from(n).map_err(|_| format!("IOA 越界: {k:?}"))?
        } else if let Some(k) = k.as_str() {
            if let Some(hex) = k.strip_prefix("0x") {
                u16::from_str_radix(hex, 16).map_err(|_| format!("IOA 非法: {k}"))?
            } else {
                k.parse::<u16>().map_err(|_| format!("IOA 非法: {k}(十进制或 0x 十六进制)"))?
            }
        } else {
            warns.push(format!("跳过非法 IOA 键: {k:?}"));
            continue;
        };
        let m = v.as_mapping().ok_or_else(|| format!("IOA {ioa} 配置应为映射"))?;
        let get = |key: &str| m.get(serde_yaml_ng::Value::String(key.into()));
        let ty_s = get("ty").and_then(|x| x.as_str()).unwrap_or("nc");
        let ty = ty_of(ty_s).ok_or_else(|| format!("IOA {ioa}: ty 非法 {ty_s}(sp/dp/na/nb/nc)"))?;
        let name = get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if name.is_empty() {
            warns.push(format!("IOA {ioa}: 缺 name,按 IOA 显示"));
        }
        let init = get("init").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let rw = get("rw").and_then(|x| x.as_i64()).map(|x| x != 0).unwrap_or(false);
        let min = get("min").and_then(|x| x.as_f64());
        let max = get("max").and_then(|x| x.as_f64());
        points.push(Pt104 { ioa, ty, name, init, rw, min, max });
    }
    if points.is_empty() {
        return Err("104 点表为空:至少定义一个点位".into());
    }
    Ok((Dev104 { name, port, ca, poll_ms, points }, warns))
}

// ---------- 运行值空间 ----------

#[derive(Clone, Copy)]
pub struct PtState {
    val: f64,
    /// 最近一次上送/总召后的值(变化检测 → COT=3)
    sent: f64,
}

impl PtState {
    fn changed(&self, def: &Pt104) -> bool {
        match def.ty {
            // 遥信/双点:任何变化都算;遥测:超出 ±2% 相对变化才报(压抖)
            1 | 3 => (self.val - self.sent).abs() > 0.5,
            _ => (self.val - self.sent).abs() > (self.sent.abs() * 0.02 + 1e-6),
        }
    }
}

/// 运行中的 104 从机(跨线程与 GUI 共享)
pub struct ModDev104Runtime {
    pub dev: Dev104,
    pub stop: Arc<AtomicBool>,
    pub bus: Arc<Mutex<Vec<String>>>,
    #[allow(dead_code)] // serve 线程持有同源克隆;字段保留供后续 GUI 场景切换
    pub scene: Arc<Mutex<Scene>>,
    /// ioa → (值, 最近上送值)
    pub space: Arc<Mutex<BTreeMap<u16, PtState>>>,
    pub port_bound: bool,
    pub bound_port: u16,
    #[allow(dead_code)] // 测试/面板显示用
    pub bind_addr: String,
    #[allow(dead_code)] // 面板"最近请求"预留
    pub last_req: Arc<Mutex<Option<Instant>>>,
    pub health: Arc<Mutex<LinkHealth>>,
}

impl ModDev104Runtime {
    pub fn link_state(&self) -> LinkState {
        let Ok(h) = self.health.lock() else { return LinkState::Gray };
        if !h.ever_connected && h.clients == 0 {
            return LinkState::Gray;
        }
        if h.link_down && h.clients == 0 {
            return LinkState::Red("连接已断开".into());
        }
        if h.clients > 0 {
            LinkState::Green
        } else {
            LinkState::Red("无连接".into())
        }
    }

    /// GUI 手动置值(ioa)
    pub fn set_ioa(&self, ioa: u16, v: f64) -> bool {
        let Ok(mut sp) = self.space.lock() else { return false };
        if let Some(st) = sp.get_mut(&ioa) {
            st.val = v;
            true
        } else {
            false
        }
    }

    /// GUI 点位视图:(ioa, 名称, 类型名, 当前值)
    pub fn points_view(&self) -> Vec<(u16, String, String, f64)> {
        let Ok(sp) = self.space.lock() else { return vec![] };
        self.dev
            .points
            .iter()
            .filter_map(|d| sp.get(&d.ioa).map(|st| (d.ioa, d.name.clone(), ty_name(d.ty).to_string(), st.val)))
            .collect()
    }
}

fn ty_name(ty: u8) -> &'static str {
    match ty {
        1 => "单点",
        3 => "双点",
        9 => "归一化",
        11 => "标度化",
        13 => "短浮点",
        _ => "?",
    }
}

// ---------- APDU/ASDU 编码 ----------

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

/// 序号 → 控制域两字节(IEC 104:16 位原始值 = 序号 << 1,bit0 恒 0;发送方向 c4 bit0=1)
fn enc_vs(v: u16) -> [u8; 2] {
    let raw = (v as u32) << 1;
    [(raw & 0xFF) as u8, ((raw >> 8) & 0xFF) as u8]
}

/// I 帧:APCI(4) + ASDU
fn apdu_i(ss: u16, vr: u16, asdu: &[u8]) -> Vec<u8> {
    let s = enc_vs(ss);
    let mut r = enc_vs(vr);
    r[1] |= 0x01; // 接收序号方向的 bit0 恒 1
    let mut f = vec![0x68u8, (asdu.len() + 4) as u8, s[0], s[1], r[0], r[1]];
    f.extend_from_slice(asdu);
    f
}

/// U 帧 / S 帧(4 字节控制域)
fn apdu_ctrl(c: [u8; 4]) -> Vec<u8> {
    vec![0x68, 0x04, c[0], c[1], c[2], c[3]]
}

fn u_startdt_con() -> Vec<u8> { apdu_ctrl([0x0B, 0, 0, 0]) }
fn u_stopdt_con() -> Vec<u8> { apdu_ctrl([0x23, 0, 0, 0]) }
fn u_testfr_con() -> Vec<u8> { apdu_ctrl([0x83, 0, 0, 0]) }
#[allow(dead_code)] // v1 不空口回 S 帧(主站靠 I 帧确认);接口就位,接 t2/t3 定时器时启用
fn s_ack(vr: u16) -> Vec<u8> {
    // S 帧:C1 恒 0x01,C2=0,接收序号在 C3/C4(C4 bit1=1)
    let r = enc_vs(vr);
    apdu_ctrl([0x01, 0x00, r[0], r[1] | 0x01])
}

/// ASDU 公共头:类型/VSQ/COT/OA/CA
fn asdu_head(ty: u8, n: u8, cot: u8, oa: u8, ca: u16) -> Vec<u8> {
    vec![ty, n, cot, oa, (ca & 0xFF) as u8, (ca >> 8) as u8]
}

fn ioa_bytes(ioa: u16) -> [u8; 3] {
    [(ioa & 0xFF) as u8, (ioa >> 8) as u8, 0]
}

/// CP56Time2a(当前墙钟;毫秒+分+时+日+月+年,IV=0)
#[allow(dead_code)] // C_CS/带时标 ASDU 上送时启用
fn cp56_now() -> [u8; 7] {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    // 不引外部时间库:用 epoch 拆解粗算(UTC;联调够用,消息里如实是本机时基)
    let secs = d.as_secs();
    let ms = d.subsec_millis() as u64;
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, mi, _s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 1970-01-01 起的年月日(民用序数法,UTC)
    let (y, mo, day) = civil_from_days(days as i64);
    let min_of_day = h * 60 + mi;
    [
        (ms & 0xFF) as u8,
        (ms >> 8) as u8,
        ((min_of_day % 60) & 0x3F) as u8,
        (h & 0x1F) as u8,
        (day & 0x1F) as u8,
        (mo & 0x0F) as u8,
        (((y - 2000).max(0)) as u8) & 0x7F,
    ]
}

/// 民用日历(Howards days→y/m/d;公历)
#[allow(dead_code)] // cp56_now 依赖
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((y + if m <= 2 { 1 } else { 0 }) as i32, m, d)
}

/// 遥测值按类型编码进 ASDU 体(单元素:ioa3 + 值 + QDS 0x00)
fn enc_point(asdu: &mut Vec<u8>, def: &Pt104, val: f64, cot: u8, ca: u16) {
    asdu.extend_from_slice(&asdu_head(def.ty, 1, cot, 0, ca));
    asdu.extend_from_slice(&ioa_bytes(def.ioa));
    match def.ty {
        1 => {
            asdu.push(if val != 0.0 { 0x01 } else { 0x00 });
            asdu.push(0x00); // QDS 良好
        }
        3 => {
            asdu.push(match val as i64 { 1 => 0x01, 2 => 0x02, _ => 0x00 });
            asdu.push(0x00);
        }
        9 => {
            let v = (val / 1.0).clamp(-1.0, 1.0);
            let raw = (v * 32767.0).round() as i16;
            asdu.extend_from_slice(&raw.to_le_bytes());
            asdu.push(0x00);
        }
        11 => {
            let raw = val.clamp(-32767.0, 32767.0).round() as i16;
            asdu.extend_from_slice(&raw.to_le_bytes());
            asdu.push(0x00);
        }
        13 => {
            asdu.extend_from_slice(&(val as f32).to_le_bytes());
            asdu.push(0x00);
        }
        _ => {}
    }
}

// ---------- 服务 ----------

impl ModDev104Runtime {
    /// 启动:绑定端口 + 每连接一线程(阻塞读超时驱动自轮询/主动上送)
    pub fn start(yaml_text: &str) -> Result<(Arc<ModDev104Runtime>, Vec<String>), String> {
        let (dev, mut warns) = parse_104_yaml(yaml_text)?;
        let stop = Arc::new(AtomicBool::new(false));
        let scene = Arc::new(Mutex::new(Scene::Normal));
        let bus: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let space: Arc<Mutex<BTreeMap<u16, PtState>>> = Arc::new(Mutex::new(
            dev.points.iter().map(|p| (p.ioa, PtState { val: p.init, sent: f64::NAN })).collect(),
        ));
        let last_req = Arc::new(Mutex::new(None));
        let health = Arc::new(Mutex::new(LinkHealth::default()));
        let bind_addr = "0.0.0.0".to_string();
        let mut rt = ModDev104Runtime {
            dev: dev.clone(),
            stop: stop.clone(),
            bus: bus.clone(),
            scene: scene.clone(),
            space: space.clone(),
            port_bound: false,
            bound_port: 0,
            bind_addr: bind_addr.clone(),
            last_req: last_req.clone(),
            health: health.clone(),
        };
        match TcpListener::bind((bind_addr.as_str(), dev.port)) {
            Ok(listener) => {
                rt.port_bound = true;
                rt.bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(dev.port);
                let stop2 = stop.clone();
                std::thread::Builder::new()
                    .name("moddev104-serve".into())
                    .spawn(move || serve(listener, dev, stop2, scene, bus, space, health, last_req))
                    .ok();
            }
            Err(e) => warns.push(format!("绑定 {}:{}, 失败: {e}(端口被占?)", bind_addr, dev.port)),
        }
        Ok((Arc::new(rt), warns))
    }

    pub fn stop_all(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for ModDev104Runtime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
fn serve(
    listener: TcpListener,
    dev: Dev104,
    stop: Arc<AtomicBool>,
    scene: Arc<Mutex<Scene>>,
    bus: Arc<Mutex<Vec<String>>>,
    space: Arc<Mutex<BTreeMap<u16, PtState>>>,
    health: Arc<Mutex<LinkHealth>>,
    last_req: Arc<Mutex<Option<Instant>>>,
) {
    listener.set_nonblocking(true).ok();
    let mut conns: Vec<TcpStream> = vec![];
    let mut scene_tick = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // 场景引擎(全站):每 500ms 推进一步
        if scene_tick.elapsed() >= Duration::from_millis(500) {
            scene_tick = Instant::now();
            let sc = { *scene.lock().unwrap_or_else(|e| e.into_inner()) };
            if let Ok(mut sp) = space.lock() {
                for d in &dev.points {
                    if let Some(st) = sp.get_mut(&d.ioa) {
                        match sc {
                            Scene::Normal => {}
                            Scene::Random => {
                                // 带域抖动(域=物理 min/max;无域 ±2% 微抖)
                                if let (Some(mn), Some(mx)) = (d.min, d.max) {
                                    let jitter = (rand01() - 0.5) * (mx - mn) * 0.1;
                                    st.val = (st.val + jitter).clamp(mn, mx);
                                } else {
                                    st.val += (rand01() - 0.5) * st.val.abs().max(1.0) * 0.04;
                                }
                            }
                            Scene::Fault => {
                                // 每拍翻转遥信/双点(强变位上送演示)
                                if d.ty == 1 || d.ty == 3 {
                                    st.val = if st.val != 0.0 { 0.0 } else { 1.0 };
                                }
                            }
                        }
                    }
                }
            }
        }
        // accept(非阻塞)
        if let Ok((stream, _)) = listener.accept() {
            stream.set_nodelay(true).ok();
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .ok();
            if let Ok(mut h) = health.lock() {
                h.clients += 1;
                h.ever_connected = true;
                h.link_down = false;
            }
            let stop2 = stop.clone();
            let dev2 = dev.clone();
            let space2 = space.clone();
            let bus2 = bus.clone();
            let health2 = health.clone();
            let last_req2 = last_req.clone();
            let scene2 = scene.clone();
            std::thread::Builder::new()
                .name("moddev104-conn".into())
                .spawn(move || {
                    handle_conn(stream, dev2, stop2, scene2, bus2, space2, health2, last_req2);
                })
                .ok();
        }
        // 清理死连接(探测:peek 无数据且错误非 WouldBlock 的连接由 handle_conn 自行上报)
        conns.retain(|c| c.peer_addr().is_ok());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn rand01() -> f64 {
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos() as f64 % 1000.0) / 1000.0
}

/// 一条连接 = 一个 104 会话(独立序号)
fn handle_conn(
    mut stream: TcpStream,
    dev: Dev104,
    stop: Arc<AtomicBool>,
    scene: Arc<Mutex<Scene>>,
    bus: Arc<Mutex<Vec<String>>>,
    space: Arc<Mutex<BTreeMap<u16, PtState>>>,
    health: Arc<Mutex<LinkHealth>>,
    last_req: Arc<Mutex<Option<Instant>>>,
) {
    let mut ss: u16 = 0;
    let mut vr: u16 = 0;
    let mut started = false;
    let mut buf: Vec<u8> = vec![];
    let mut next_poll = Instant::now() + Duration::from_millis(dev.poll_ms.max(100));
    let mut readbuf = [0u8; 2048];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // 读(100ms 超时驱动定时任务)
        match stream.read(&mut readbuf) {
            Ok(0) => {
                // 对端关闭
                if let Ok(mut h) = health.lock() {
                    h.clients = h.clients.saturating_sub(1);
                    if h.clients == 0 {
                        h.link_down = true;
                    }
                }
                return;
            }
            Ok(n) => buf.extend_from_slice(&readbuf[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {}
            Err(_) => {
                if let Ok(mut h) = health.lock() {
                    h.clients = h.clients.saturating_sub(1);
                    if h.clients == 0 {
                        h.link_down = true;
                    }
                }
                return;
            }
        }
        // 定帧:0x68 + len(一次可到多个 APDU)
        let mut replies: Vec<Vec<u8>> = vec![];
        loop {
            if buf.len() < 2 {
                break;
            }
            if buf[0] != 0x68 {
                buf.remove(0); // 失步丢一字节
                continue;
            }
            let len = buf[1] as usize;
            if len < 4 {
                buf.remove(0);
                continue;
            }
            let total = 2 + len;
            if buf.len() < total {
                break;
            }
            let apdu: Vec<u8> = buf.drain(..total).collect();
            // 主站发送序号:16 位原始值 >> 1;期望主站下一帧 → vr = vs+1
            let vs_m = (((apdu[3] as u16) << 8) | apdu[2] as u16) >> 1;
            vr = vs_m.wrapping_add(1);
            if let Ok(mut t) = last_req.lock() {
                *t = Some(Instant::now());
            }
            emit(&bus, Dir::Tx, &apdu); // 主站帧 → Tx
            if apdu[2] & 0x03 == 0x03 {
                // U 帧(C1 低两位=11)
                match apdu[2] & 0xFC {
                    0x04 => {
                        started = true;
                        replies.push(u_startdt_con());
                    }
                    0x08 => {
                        started = false;
                        replies.push(u_stopdt_con());
                    }
                    0x10 | 0x14 => replies.push(u_testfr_con()),
                    _ => {}
                }
            } else if apdu[2] & 0x03 == 0x01 {
                // S 帧:主站 ACK,从机无需应答
            } else {
                // I 帧:ASDU 从字节 6 起
                let asdu = &apdu[6..];
                if asdu.len() >= 6 {
                    let ty = asdu[0];
                    let cot = asdu[2] & 0x3F;
                    let ca = (asdu[4] as u16) | ((asdu[5] as u16) << 8);
                    let body = &asdu[6..];
                    match (ty, cot) {
                        (100, 6) => {
                            // 总召唤激活:确认 → 逐点 COT=20 → 结束
                            let qoi = body.first().copied().unwrap_or(20);
                            let mut f = asdu_head(100, 1, 7, 0, ca);
                            f.push(qoi);
                            replies.push(apdu_i(ss, vr, &f));
                            ss = ss.wrapping_add(1);
                            let sp = space.lock().unwrap_or_else(|e| e.into_inner());
                            for d in &dev.points {
                                if let Some(st) = sp.get(&d.ioa) {
                                    let mut f2 = Vec::with_capacity(16);
                                    enc_point(&mut f2, d, st.val, 20, ca);
                                    replies.push(apdu_i(ss, vr, &f2));
                                    ss = ss.wrapping_add(1);
                                }
                            }
                            drop(sp);
                            let mut f3 = asdu_head(100, 1, 10, 0, ca);
                            f3.push(qoi);
                            replies.push(apdu_i(ss, vr, &f3));
                            ss = ss.wrapping_add(1);
                        }
                        (103, 6) => {
                            // 时钟同步:回读(带主站发来的 CP56)
                            let mut f = asdu_head(103, 1, 7, 0, ca);
                            f.extend_from_slice(&body[..7.min(body.len())]);
                            replies.push(apdu_i(ss, vr, &f));
                            ss = ss.wrapping_add(1);
                        }
                        (45 | 46, 6) => {
                            // 遥控(直接执行语义):激活确认 → 写点位 → 激活结束
                            if body.len() >= 4 {
                                let ioa = (body[0] as u16) | ((body[1] as u16) << 8);
                                let valb = body[3];
                                let mut con = asdu_head(ty, 1, 7, 0, ca);
                                con.extend_from_slice(&body[..4]);
                                replies.push(apdu_i(ss, vr, &con));
                                ss = ss.wrapping_add(1);
                                let v = match ty {
                                    45 => if valb & 0x01 != 0 { 1.0 } else { 0.0 },
                                    _ => match valb & 0x03 { 1 => 1.0, 2 => 2.0, _ => 0.0 },
                                };
                                if let Ok(mut sp) = space.lock() {
                                    if let Some(st) = sp.get_mut(&ioa) {
                                        st.val = v;
                                    }
                                }
                                let mut term = asdu_head(ty, 1, 10, 0, ca);
                                term.extend_from_slice(&body[..4]);
                                replies.push(apdu_i(ss, vr, &term));
                                ss = ss.wrapping_add(1);
                            }
                        }
                        _ => {} // 其余命令(设定值等)v1 不支持:主站按超时判
                    }
                }
            }
        }
        // 变位/周期主动上送(STARTDT 后才发)
        if started && scene_tick_due(&mut next_poll, dev.poll_ms) {
            let sc = { *scene.lock().unwrap_or_else(|e| e.into_inner()) };
            let _ = sc;
            let sp = space.lock().unwrap_or_else(|e| e.into_inner());
            for d in &dev.points {
                if let Some(st) = sp.get(&d.ioa) {
                    if st.changed(d) {
                        let mut f = Vec::with_capacity(16);
                        enc_point(&mut f, d, st.val, 3, dev.ca);
                        replies.push(apdu_i(ss, vr, &f));
                        ss = ss.wrapping_add(1);
                    }
                }
            }
            drop(sp);
            // 更新 sent 基准
            if let Ok(mut sp) = space.lock() {
                for d in &dev.points {
                    if let Some(st) = sp.get_mut(&d.ioa) {
                        st.sent = st.val;
                    }
                }
            }
        }
        // 发送(逐帧写 + NDJSON)
        for apdu in replies {
            if stream.write_all(&apdu).is_err() {
                if let Ok(mut h) = health.lock() {
                    h.clients = h.clients.saturating_sub(1);
                    if h.clients == 0 {
                        h.link_down = true;
                    }
                }
                return;
            }
            emit(&bus, Dir::Rx, &apdu); // 从机帧 → Rx
        }
    }
}

fn scene_tick_due(next: &mut Instant, poll_ms: u64) -> bool {
    if Instant::now() >= *next {
        *next = Instant::now() + Duration::from_millis(poll_ms.max(100));
        true
    } else {
        false
    }
}

/// 推一条 APDU 进 live 管线(bus=tcp,ch=0,一行一帧;ADR-0017)
fn emit(bus: &Arc<Mutex<Vec<String>>>, dir: Dir, apdu: &[u8]) {
    let f = LiveFrame {
        ts_ns: now_ns(),
        ts_src: TsSrc::Sw,
        bus_type: BusKind::Tcp,
        ch: 0,
        alias: None,
        dir,
        id: 0,
        id_ext: false,
        dlc: apdu.len(),
        data: apdu.to_vec(),
        seq: None,
        meta_gap: None,
    };
    bus.lock().unwrap_or_else(|e| e.into_inner()).push(live_frame_to_jsonl(&f));
}

/// 独立启停:起服务线程 + NDJSON→管线泵线程(与 Modbus 模拟器同款对接)
pub fn spawn_104(
    yaml_path: &std::path::Path,
    tx: std::sync::mpsc::Sender<crate::live::LiveMsg>,
    record_path: Option<PathBuf>,
    tee: Option<Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>>,
) -> Result<(Arc<ModDev104Runtime>, Vec<String>), String> {
    let yaml = std::fs::read_to_string(yaml_path).map_err(|e| format!("读取 104 点表 {} 失败: {e}", yaml_path.display()))?;
    let (rt, warns) = ModDev104Runtime::start(&yaml)?;
    let stop = rt.stop.clone();
    let bus = rt.bus.clone();
    let t2 = tx.clone();
    std::thread::Builder::new()
        .name("moddev104-pump".into())
        .spawn(move || {
            let mut recorder = record_path
                .as_deref()
                .and_then(|p| match iotprobe_core::ingest::live::Recorder::create(p) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        let _ = t2.send(crate::live::LiveMsg::Info(format!("录制文件打开失败: {e}")));
                        None
                    }
                });
            let mut pipe = iotprobe_core::ingest::live::Pipeline::new(None, None);
    if let Some(slot) = &tee {
        pipe.set_tee_slot(slot.clone());
    }

            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let lines: Vec<String> = std::mem::take(&mut bus.lock().unwrap_or_else(|e| e.into_inner()));
                if lines.is_empty() {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                let mut batch: Vec<iotprobe_core::model::Record> = vec![];
                for l in &lines {
                    if let Some(rec) = pipe.sess.map_line(l) {
                        batch.push(rec);
                    }
                }
                if let Some(rec) = recorder.as_mut() {
                    for l in &lines {
                        rec.write_line(l);
                    }
                }
                if !batch.is_empty() {
                    let _ = t2.send(crate::live::LiveMsg::Batch(crate::live::Batch {
                        records: batch,
                        labels: pipe.sess.labels(),
                        stats: Some(pipe.sess.stats()),
                        epoch_ns: pipe.sess.epoch_ns(),
                        warnings: pipe.sess.take_warnings(),
                    }));
                }
            }
        })
        .ok();
    Ok((rt, warns))
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
dev104: {name: 测试104从机, port: 0, ca: 1, poll_ms: 100}
points:
  1: {name: 断路器合位, ty: sp, init: 1}
  101: {name: 电网电压, ty: nc, init: 220.5, min: 200, max: 240}
  110: {name: 开关状态, ty: dp, init: 1}
"#;

    fn start_sim() -> Arc<ModDev104Runtime> {
        let (rt, warns) = ModDev104Runtime::start(YAML).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        assert!(rt.port_bound);
        rt
    }

    fn read_apdu(c: &mut TcpStream) -> Vec<u8> {
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut hdr = [0u8; 2];
        std::io::Read::read_exact(c, &mut hdr).unwrap();
        assert_eq!(hdr[0], 0x68);
        let len = hdr[1] as usize;
        let mut rest = vec![0u8; len];
        std::io::Read::read_exact(c, &mut rest).unwrap();
        let mut f = hdr.to_vec();
        f.extend_from_slice(&rest);
        f
    }

    fn asdu_of(apdu: &[u8]) -> &[u8] {
        // I 帧:C1 bit1=0(SN 最低位可能落在这里,奇数序号 → C1=0x02 也是 I 帧)
        if apdu[2] & 0x01 == 0 { &apdu[6..] } else { &[] }
    }

    #[test]
    fn startdt_and_gi() {
        // 验收 A5:STARTDT → con;总召唤 → 激活确认 + 逐点 COT=20 + 激活结束
        let rt = start_sim();
        let addr = if rt.bind_addr == "0.0.0.0" { "127.0.0.1" } else { rt.bind_addr.as_str() };
        let mut c = TcpStream::connect((addr, rt.bound_port)).unwrap();
        c.write_all(&apdu_ctrl([0x07, 0, 0, 0])).unwrap(); // STARTDT act
        let con = read_apdu(&mut c);
        assert_eq!(con[2], 0x0B, "STARTDT con");
        // 总召唤激活(type100/cot6/qoi20,ca=1,vs=0)
        let gi = apdu_i(0, 1, &{
            let mut f = asdu_head(100, 1, 6, 0, 1);
            f.push(20);
            f
        });
        c.write_all(&gi).unwrap();
        // 激活确认
        let ack = read_apdu(&mut c);
        let a = asdu_of(&ack);
        assert_eq!(a[0], 100, "总召确认类型");
        assert_eq!(a[2] & 0x3F, 7, "COT=7");
        // 逐点响应 3 点(COT=20)
        for (k, expect_ty) in [0usize, 1, 2].iter().zip([1u8, 13, 3]) {
            let resp = read_apdu(&mut c);
            let r = asdu_of(&resp);
            assert_eq!(r[0], expect_ty, "第 {k} 点类型(顺序=点表序)");
            assert_eq!(r[2] & 0x3F, 20, "COT=20 响应总召");
        }
        // 激活结束
        let term = read_apdu(&mut c);
        let t = asdu_of(&term);
        assert_eq!(t[2] & 0x3F, 10, "COT=10 激活结束");
        rt.stop_all();
    }

    #[test]
    fn spontaneous_upload_on_change() {
        // 验收 A5:STARTDT 后写点位 → 主动上送 COT=3(Fault 场景翻转遥信亦可)
        let rt = start_sim();
        let addr = if rt.bind_addr == "0.0.0.0" { "127.0.0.1" } else { rt.bind_addr.as_str() };
        let mut c = TcpStream::connect((addr, rt.bound_port)).unwrap();
        c.write_all(&apdu_ctrl([0x07, 0, 0, 0])).unwrap();
        let _ = read_apdu(&mut c); // con
        std::thread::sleep(Duration::from_millis(150));
        // 遥控写 IOA=1 → 0(断路器分)
        let cmd = apdu_i(1, 1, &{
            let mut f = asdu_head(45, 1, 6, 0, 1);
            f.extend_from_slice(&ioa_bytes(1));
            f.push(0x00); // SCS=0
            f.push(0x01); // QOE=execute
            f
        });
        c.write_all(&cmd).unwrap();
        let con = read_apdu(&mut c);
        assert_eq!(asdu_of(&con)[2] & 0x3F, 7, "遥控激活确认");
        let term = read_apdu(&mut c);
        assert_eq!(asdu_of(&term)[2] & 0x3F, 10, "遥控激活结束");
        // poll_ms=100 → ≤300ms 内应收到 COT=3 突发(值变了)
        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut got_spont = false;
        let _ = c.set_read_timeout(Some(Duration::from_millis(200)));
        while Instant::now() < deadline {
            match read_apdu(&mut c) {
                apdu => {
                    let a = asdu_of(&apdu);
                    if !a.is_empty() && a[2] & 0x3F == 3 {
                        got_spont = true;
                        break;
                    }
                }
            }
        }
        assert!(got_spont, "写点位后应收到 COT=3 突发上送");
        rt.stop_all();
    }
}

#[cfg(test)]
mod repro {
    use super::*;
    #[test]
    fn bind_accept_repro() {
        let l = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            l.set_nonblocking(true).ok();
            for _ in 0..200 {
                if let Ok(_s) = l.accept() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let c = TcpStream::connect(("127.0.0.1", port));
        assert!(c.is_ok(), "connect: {c:?}");
        let _ = h.join();
    }
}
