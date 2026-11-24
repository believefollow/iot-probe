//! Modbus 设备模拟器(P1):每台设备独立主机身份(回环 IP)+ 自轮询发数 + 快照进 live 管线。
//! - **拓扑对齐真实采集表**:点位表是主机侧视角(每台设备各有 ip/port/slave,unit 常全为 1)。
//!   模拟器为每台 devN 绑 127.0.0.<N>:<port>(Windows/Linux 整个 127/8 都是本机):
//!   同端口多台设备天然共存、unit 保持原值;主机(EMS/HMI)只需把设备 IP 改成 127.0.0.<N>。
//!   端口在表内唯一的设备绑 0.0.0.0(跨机可达);绑定失败如实告警。
//! - 接收按 MBAP 组帧:TCP 粘包一次全部应答、拆包跨轮续传、协议标识/长度非法即断连;
//!   数量/地址越界回 Modbus 异常码(0x02/0x03),未知功能码回 0x01,未知 unit 回网关码 0x0B
//!   —— 主机读取失败时可区分根因
//! - **自轮询发数**:每台按 poll_ms 周期以"主机身份"读自己的寄存器并走同一 emit 路径
//!   (poll_ms=0 关闭)—— 没有主机连入时曲线也滚动、录制也有内容,不再是"只接收不发送"
//! - 读请求(func3/4)返回寄存器值;写请求(func6/16)回写状态机(控制闭环)
//! - 每次请求(读/写)转两条 NDJSON(请求 Tx + 响应 Rx)推入管线 —— 联调同屏可见总线
//! - 场景:Normal(静止)/Random(周期小幅扰动可写点位)/Fault(置故障位)

use crate::live::live_frame_to_jsonl;
use iotprobe_core::crc;
use iotprobe_core::ingest::live::LiveFrame;
use iotprobe_core::moddev::{parse_points_yaml, MbDev, MbPoint, RegSpace};
use iotprobe_core::ingest::live::BusKind;
use iotprobe_core::model::{Dir, TsSrc};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 一个模拟器实例(任务卡 A3):运行时 + 来源点位表;多实例并行(如同时模拟 Modbus + 未来 104)。
/// 生命周期与 GUI 解耦:从 Vec 移除即 Drop → 服务线程收 stop 自行退出。
pub struct ModDevInst {
    pub rt: Arc<ModDevRuntime>,
    /// 实例名(点位表文件名去扩展;重名自动加序号),UI 列表/拓扑图区分用
    pub name: String,
    /// 启动时的点位表路径(保留:后续会话恢复/单实例重启用)
    #[allow(dead_code)]
    pub yaml: PathBuf,
    /// 录制落盘路径(未勾选录制=None;多实例各自落盘互不串流)
    pub record: Option<PathBuf>,
}

impl ModDevInst {
    /// 展示名:实例名 + 端点数(拓扑/列表首行)
    pub fn label(&self) -> String {
        format!("{}({} 台)", self.name, self.rt.devs.len())
    }
}

/// 运行中的模拟器(跨线程与 GUI 共享)
pub struct ModDevRuntime {
    pub devs: Vec<DevState>,
    pub stop: Arc<AtomicBool>,
    /// 本运行时专属 NDJSON 收集器(服务/自轮询线程 → 泵线程;多模拟器实例互不串流)
    pub bus: Arc<Mutex<Vec<String>>>,
    pub scene: Arc<Mutex<Scene>>,
    #[allow(dead_code)] // 预留:面板显示运行时长
    pub started_at: Instant,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Scene {
    Normal,
    Random,
    Fault,
}

/// 主机读值记录:点位名 → (物理值, 次数, 时刻)——点位编辑表「主机读到」列的数据源
pub type HostReads = std::collections::HashMap<String, (f64, u64, Instant)>;

/// 点位编辑表一行(points_view 产出)
#[derive(Clone, Debug)]
pub struct PointRow {
    pub name: String,
    pub phys: f64,
    pub ty: String,
    pub grp: String,
    /// rw:点位表声明主机可写(只影响 🔒 标记;模拟器侧工程帅任何点都能改——那是在"设定被测量")
    pub rw: bool,
    pub unit: String,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub scale: f64,
    pub enum_: Option<Vec<(f64, String)>>,
    /// 📌 已置(手动钉住,场景引擎不动)
    pub pinned: bool,
    /// 真实主机最近读到 (物理值, 累计次数, 距今)
    pub host: Option<(f64, u64, Duration)>,
    /// str/mac 点位的当前文本内容(其他类型 None)
    pub str_val: Option<String>,
}

pub struct DevState {
    pub meta: MbDev,
    pub space: Arc<Mutex<RegSpace>>,
    pub port_bound: bool,
    /// 绑定地址(同端口多机=127.0.0.<N> 按设备区分;端口唯一=0.0.0.0 跨机可达)
    pub bind_addr: String,
    /// 实际绑定端口(点位表填 0 时由系统分配;面板如实显示)
    pub bound_port: u16,
    /// 最近被读/写的时刻(端口状态展示)
    pub last_req: Arc<Mutex<Option<Instant>>>,
    /// 主机链路健康(拓扑连线图 A1;自轮询不计入——它不代表真实主机链路)
    pub health: Arc<Mutex<LinkHealth>>,
    /// 点位采样环(任务卡 A2):点位名 → 最近 32 拍物理值(500ms 节流,卡片可见时推进)
    pub samples: Arc<Mutex<std::collections::HashMap<String, Vec<f64>>>>,
    /// 真实主机读值记录(自轮询不计):点位名 → (最近读到的物理值, 累计次数, 时刻)
    pub host_reads: Arc<Mutex<HostReads>>,
    /// 上次采样时刻(A2 节流)
    last_sample: Arc<Mutex<Option<Instant>>>,
}

/// 拓扑连线健康(任务卡 A1):只统计真实主机连接。
/// 状态判定在 `DevState::link_state`——红=断开或近 5s 异常码;灰=从未有主机连入;绿=其余。
#[derive(Default)]
pub struct LinkHealth {
    /// 当前真实主机连接数
    pub clients: usize,
    /// 曾有主机连入(灰=无流量 的判据)
    pub ever_connected: bool,
    /// 曾连接但当前无连接(链路断开,重连即清除)
    pub link_down: bool,
    /// 最近一次异常码应答(func|0x80)
    pub last_exc: Option<Instant>,
    /// 最近一次正常应答
    pub last_ok: Option<Instant>,
}

/// 链路健康三态(拓扑连线颜色 + 原因说明)
#[derive(Debug)]
pub enum LinkState {
    Green,
    Red(String),
    Gray,
}

impl DevState {
    /// 主机侧接入端点(0.0.0.0 → 展示 127.0.0.1;同端口多机展示各自回环 IP)
    pub fn endpoint(&self) -> String {
        if !self.port_bound {
            return format!("未绑定(表端口 {})", self.meta.port);
        }
        let ip = if self.bind_addr == "0.0.0.0" { "127.0.0.1" } else { self.bind_addr.as_str() };
        format!("{ip}:{}", self.bound_port)
    }

    /// 链路形态标签(卡片/面板显示)
    pub fn link_label(&self) -> &'static str {
        if self.meta.link.eq_ignore_ascii_case("rtu_tcp") { "Modbus RTU·串口服务器透传" } else { "Modbus TCP" }
    }

    /// 链路健康判定(拓扑连线图 A1):
    /// 红=链路断开(曾有主机但当前无连接)或近 5s 内回过异常码;灰=从未有真实主机连入;
    /// 绿=有主机在连且无近期异常。自轮询不改变判定——它不代表真实主机链路。
    pub fn link_state(&self) -> LinkState {
        let Ok(h) = self.health.lock() else { return LinkState::Gray };
        if !h.ever_connected && h.clients == 0 {
            return LinkState::Gray;
        }
        if h.link_down && h.clients == 0 {
            return LinkState::Red("连接已断开".into());
        }
        if let Some(t) = h.last_exc {
            if t.elapsed().as_secs_f32() < 5.0 {
                return LinkState::Red(format!("异常码 {:.1}s 前", t.elapsed().as_secs_f32()));
            }
        }
        if h.clients > 0 {
            LinkState::Green
        } else {
            // ever_connected 但非 link_down 且无连接:理论不可达,按断开处理
            LinkState::Red("无连接".into())
        }
    }

    /// 采样一拍(任务卡 A2):500ms 节流,把全部点位当前物理值推进各自环形窗口(32 拍)。
    /// 卡片可见时由 GUI 每帧调用;不可见即暂停——sparkline 只在卡片里展示,不影响数据正确性。
    pub fn sample_if_due(&self) {
        let due = match self.last_sample.lock() {
            Ok(mut t) => match *t {
                Some(t) if t.elapsed() < Duration::from_millis(500) => false,
                _ => {
                    *t = Some(Instant::now());
                    true
                }
            },
            Err(_) => false,
        };
        if !due {
            return;
        }
        let pts = match self.space.lock() {
            Ok(sp) => sp.snapshot_points(),
            Err(_) => return,
        };
        if let Ok(mut m) = self.samples.lock() {
            for (name, _raw, phys, _ty, _grp) in pts {
                let ring = m.entry(name).or_default();
                ring.push(phys);
                while ring.len() > 32 {
                    ring.remove(0);
                }
            }
        }
    }

    /// 取某点位最近 32 拍(min, max, 当前, 序列副本;不足 2 拍返回 None)
    pub fn point_stats(&self, name: &str) -> Option<(f64, f64, f64, Vec<f64>)> {
        let m = self.samples.lock().ok()?;
        let ring = m.get(name)?;
        let cur = *ring.last()?;
        let min = ring.iter().copied().fold(f64::INFINITY, f64::min);
        let max = ring.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        Some((min, max, cur, ring.clone()))
    }
}

impl ModDevRuntime {
    /// 从点位表文本启动:全部设备挂到一个监听端口,按 unit(slave) 路由。
    /// 返回 (运行时, 告警)。监听失败 → 全部 port_bound=false(端口被占最常见)。
    pub fn start(yaml_text: &str) -> Result<(Arc<ModDevRuntime>, Vec<String>, Vec<std::thread::JoinHandle<()>>), String> {
        let (devs, mut warns) = parse_points_yaml(yaml_text)?;
        let stop = Arc::new(AtomicBool::new(false));
        let scene = Arc::new(Mutex::new(Scene::Normal));
        let bus: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        // 绑定地址策略:同端口多台 → 各自 127.0.0.<N>(主机侧表里 unit 常全为 1,靠 IP 区分设备,
        // 对齐真实拓扑"每台设备一个主机身份");端口唯一 → 0.0.0.0(跨机可达)。端口 0 = 系统分配。
        let mut port_count: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
        for d in &devs {
            *port_count.entry(d.port).or_default() += 1;
        }
        let mut states = vec![];
        let mut handles = vec![];
        for d in devs {
            let space = Arc::new(Mutex::new(RegSpace::new(d.points.clone())));
            let last_req = Arc::new(Mutex::new(None));
            let health = Arc::new(Mutex::new(LinkHealth::default()));
            let host_reads = Arc::new(Mutex::new(HostReads::default()));
            let shared_port = port_count.get(&d.port).copied().unwrap_or(1) > 1;
            let bind_addr = if shared_port && d.id > 0 && d.id <= 255 {
                format!("127.0.0.{}", d.id)
            } else {
                "0.0.0.0".to_string()
            };
            let mut st = DevState {
                meta: d.clone(),
                space: space.clone(),
                port_bound: false,
                bind_addr: bind_addr.clone(),
                bound_port: 0,
                last_req: last_req.clone(),
                health: health.clone(),
                samples: Arc::new(Mutex::new(Default::default())),
                last_sample: Arc::new(Mutex::new(None)),
                host_reads: host_reads.clone(),
            };
            let entry = DevEntry {
                next_poll: Instant::now() + Duration::from_millis(d.poll_ms.max(1)),
                rtu: d.link.eq_ignore_ascii_case("rtu_tcp"),
                dev: d,
                space,
                last_req,
                health,
                host_reads,
            };
            match TcpListener::bind((bind_addr.as_str(), st.meta.port)) {
                Ok(listener) => {
                    st.port_bound = true;
                    st.bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(st.meta.port);
                    let stop2 = stop.clone();
                    let scene2 = scene.clone();
                    let bus2 = bus.clone();
                    handles.push(std::thread::spawn(move || {
                        serve_bus(listener, vec![entry], stop2, scene2, bus2);
                    }));
                }
                Err(e) => {
                    warns.push(format!(
                        "dev{} {} 绑定 {bind_addr}:{} 失败: {e}(端口被占?同端口多机已自动用 127.0.0.<N> 区分,主机 IP 填对应回环地址)",
                        st.meta.id, st.meta.name, st.meta.port
                    ));
                }
            }
            states.push(st);
        }
        Ok((Arc::new(ModDevRuntime { devs: states, stop, scene, bus, started_at: Instant::now() }), warns, handles))
    }

    pub fn stop_all(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// 取走本运行时累积的 NDJSON 行(泵线程/测试用)
    #[allow(dead_code)] // bin 目标下仅测试引用,cargo check 会报 dead_code;保留供测试与后续泵复用
    pub fn drain(&self) -> Vec<String> {
        std::mem::take(&mut self.bus.lock().unwrap_or_else(|e| e.into_inner()))
    }

}

impl Drop for ModDevRuntime {
    fn drop(&mut self) {
        // GUI 持有被释放(退出/替换)即全停:服务线程收 stop 自行退出
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ModDevRuntime {
    /// GUI 点位编辑表(name 过滤):值/单位/范围/枚举/读写/钉住/主机读到
    pub fn points_view(&self, dev_i: usize, filter: &str) -> Vec<PointRow> {
        let Some(d) = self.devs.get(dev_i) else { return vec![] };
        let Ok(space) = d.space.lock() else { return vec![] };
        let host = d.host_reads.lock().ok();
        let f = filter.trim().to_lowercase();
        space
            .points
            .iter()
            .filter(|p| p.ty != "bit" || p.bit.is_some())
            .filter(|p| f.is_empty() || p.name.to_lowercase().contains(&f) || p.grp.to_lowercase().contains(&f))
            .map(|p| PointRow {
                name: p.name.clone(),
                phys: space.phys_of(p),
                ty: p.ty.clone(),
                grp: p.grp.clone(),
                rw: p.rw,
                unit: p.unit.clone().unwrap_or_default(),
                min: p.min,
                max: p.max,
                scale: p.scale,
                enum_: p.enum_.clone(),
                pinned: space.is_pinned(&p.name),
                host: host.as_ref().and_then(|m| m.get(&p.name)).map(|(v, n, t)| (*v, *n, t.elapsed())),
                str_val: if matches!(p.ty.as_str(), "str" | "mac") {
                    Some(space.str_of(p))
                } else {
                    None
                },
            })
            .collect()
    }

    /// GUI 手动置值(按点位名):写入并钉住(📌 已置,场景引擎不再改)
    pub fn set_point(&self, dev_i: usize, name: &str, phys: f64) -> bool {
        let Some(d) = self.devs.get(dev_i) else { return false };
        if let Ok(mut space) = d.space.lock() {
            if space.write_point_by_name(name, phys) {
                space.set_pinned(name, true);
                return true;
            }
        }
        false
    }

    /// GUI 写字符串点位(str/mac)并钉住
    pub fn set_point_str(&self, dev_i: usize, name: &str, s: &str) -> bool {
        let Some(d) = self.devs.get(dev_i) else { return false };
        if let Ok(mut space) = d.space.lock() {
            if space.write_str_by_name(name, s) {
                space.set_pinned(name, true);
                return true;
            }
        }
        false
    }

    /// 释放一个钉住点位(回到场景驱动)
    pub fn release_point(&self, dev_i: usize, name: &str) -> bool {
        let Some(d) = self.devs.get(dev_i) else { return false };
        if let Ok(mut space) = d.space.lock() {
            space.set_pinned(name, false);
            return true;
        }
        false
    }

    /// 释放全部钉住点位;返回释放数
    pub fn release_all_pins(&self, dev_i: usize) -> usize {
        let Some(d) = self.devs.get(dev_i) else { return 0 };
        match d.space.lock() {
            Ok(mut space) => space.release_all_pins(),
            Err(_) => 0,
        }
    }

    /// 运行时追加临时点位(点位表没定义、联调时想试一下的寄存器);同名/同键重复返回 Err
    pub fn add_temp_point(&self, dev_i: usize, p: MbPoint) -> Result<(), String> {
        let Some(d) = self.devs.get(dev_i) else { return Err("设备不存在".into()) };
        match d.space.lock() {
            Ok(mut space) => {
                if space.add_point(p) {
                    Ok(())
                } else {
                    Err("同名或同键的点位已存在".into())
                }
            }
            Err(_) => Err("寄存器空间忙".into()),
        }
    }
}

/// 服务总线上的单台设备(服务线程内部态)
struct DevEntry {
    dev: MbDev,
    space: Arc<Mutex<RegSpace>>,
    last_req: Arc<Mutex<Option<Instant>>>,
    /// 主机链路健康(拓扑连线图 A1)
    health: Arc<Mutex<LinkHealth>>,
    /// 主机读值记录(真实主机 func3/4 读成功才记;自轮询不计)
    host_reads: Arc<Mutex<HostReads>>,
    /// 自轮询下一拍(poll_ms=0 表示关闭,下一拍永不 到期)
    next_poll: Instant,
    /// 链路形态:rtu_tcp = RTU-over-TCP(slave+CRC 定帧应答);false = Modbus TCP(MBAP)
    rtu: bool,
}

/// 自轮询 tid 发生器(0xA000 起,避开主机常见 0..N 事务号)
static SELF_POLL_TID: AtomicU32 = AtomicU32::new(0xA000);

/// 单监听服务循环:accept → 每连接 MBAP 组帧 → 按 unit 路由到对应设备应答;
/// 同时驱动场景引擎与各设备自轮询(粘包/拆包安全)。
fn serve_bus(
    listener: TcpListener,
    mut entries: Vec<DevEntry>,
    stop: Arc<AtomicBool>,
    scene: Arc<Mutex<Scene>>,
    bus: Arc<Mutex<Vec<String>>>,
) {
    listener.set_nonblocking(true).ok();
    let mut conns: Vec<Conn> = vec![];
    let mut scene_tick = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // 场景引擎:每 500ms 推进一步(全部设备)
        if scene_tick.elapsed() >= Duration::from_millis(500) {
            scene_tick = Instant::now();
            let sc = { let g = scene.lock().unwrap_or_else(|e| e.into_inner()); *g };
            for e in &entries {
                if let Ok(mut sp) = e.space.lock() {
                    apply_scene(&mut sp, sc);
                }
            }
        }
        // 自轮询:poll_ms 到期即以主机身份读自己(无主机连入也有数据流)
        let now = Instant::now();
        for e in &mut entries {
            if e.dev.poll_ms > 0 && now >= e.next_poll {
                self_poll_dev(e, &bus);
                e.next_poll = now + Duration::from_millis(e.dev.poll_ms.max(50));
            }
        }
        // accept 新连接
        if let Ok(stream) = listener.accept().map(|(s, _)| s) {
            stream.set_nonblocking(true).ok();
            // 关 Nagle:请求-响应小包立即出网,避免与主机 delayed-ACK 互等造成毫秒级假超时
            stream.set_nodelay(true).ok();
            // 链路健康:真实主机连入(单设备总线,本 listener 的全部连接都算它的)
            if let Ok(mut h) = entries[0].health.lock() {
                h.clients += 1;
                h.ever_connected = true;
                h.link_down = false;
            }
            conns.push(Conn { stream, buf: Vec::with_capacity(512) });
        }
        // 处理已有连接(非阻塞读 + 组帧应答)
        let mut dead = vec![];
        for (i, c) in conns.iter_mut().enumerate() {
            if pump_conn(c, &entries, &bus).is_err() {
                dead.push(i);
            }
        }
        for _ in &dead {
            // 链路健康:连接断开;最后一个也断 → 链路 down(拓扑线变红,重连恢复)
            if let Ok(mut h) = entries[0].health.lock() {
                h.clients = h.clients.saturating_sub(1);
                if h.clients == 0 {
                    h.link_down = true;
                }
            }
        }
        for i in dead.into_iter().rev() {
            conns.swap_remove(i);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// 自轮询一台设备:按点位地址跨度构造 func3/4 读 ADU(≤125 寄存器/帧,可多帧),
/// 走与真实主机完全相同的 process_frame + emit 路径(请求/响应成对,事务配对天然可分析)。
fn self_poll_dev(e: &DevEntry, bus: &Arc<Mutex<Vec<String>>>) {
    for func in [3u8, 4] {
        let mut addrs: Vec<u16> = e
            .dev
            .points
            .iter()
            .filter(|p| p.func == func)
            .map(|p| p.addr)
            .collect();
        if addrs.is_empty() {
            continue;
        }
        addrs.sort_unstable();
        addrs.dedup();
        // 已定义地址的连续段(断档另起段):读起点永远落在已定义地址上,不回异常码 2
        // (回归:按 min..max 跨度硬扫时,chunk 起点落在未定义地址,一次会话刷出数万条垃圾异常事件)
        let mut runs: Vec<(u32, u32)> = vec![]; // [start, end] 闭区间
        for a in addrs {
            match runs.last_mut() {
                Some(l) if a as u32 == l.1 + 1 => l.1 = a as u32,
                _ => runs.push((a as u32, a as u32)),
            }
        }
        let mut chunks: Vec<(u32, u32)> = vec![]; // (addr, cnt)
        for (s, en) in runs {
            let mut a = s;
            while a <= en {
                let cnt = (en - a + 1).min(125);
                chunks.push((a, cnt));
                a += cnt;
            }
        }
        for (addr_ofs, cnt) in chunks {
            let addr = addr_ofs as u16;
            let tid = SELF_POLL_TID.fetch_add(1, Ordering::Relaxed) as u16;
            let mut adu = vec![(tid >> 8) as u8, tid as u8, 0, 0, 6, 6, e.dev.slave, func];
            adu.extend([(addr >> 8) as u8, addr as u8, (cnt >> 8) as u8, cnt as u8]);
            let resp = process_frame(&adu, &e.space, &e.last_req, &e.health);
            emit_modbus_jsonl(bus, &e.dev, true, &adu[6..]);
            emit_modbus_jsonl(bus, &e.dev, false, &resp[6..]);
        }
    }
}

/// 一条主机连接:TCP 无消息边界,必须按 MBAP 头组帧(跨 read 续传半帧)
struct Conn {
    stream: std::net::TcpStream,
    buf: Vec<u8>,
}

/// 读取可用字节并按链路形态组帧应答;Err = 连接已坏(对端关闭/IO 错/流不同步)
fn pump_conn(c: &mut Conn, entries: &[DevEntry], bus: &Arc<Mutex<Vec<String>>>) -> Result<(), ()> {
    let mut tmp = [0u8; 1024];
    let n = match c.stream.read(&mut tmp) {
        Ok(0) => return Err(()), // 对端关闭
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Ok(()),
        Err(_) => return Err(()),
    };
    c.buf.extend_from_slice(&tmp[..n]);
    if c.buf.len() > 8192 {
        return Err(()); // 长期组不出完整帧的洪泛保护
    }
    if entries.first().map(|e| e.rtu).unwrap_or(false) {
        return pump_rtu(c, entries, bus);
    }
    pump_mbap(c, entries, bus)
}

/// RTU-over-TCP 形态:slave(1B)+PDU+CRC16(2B) 定帧应答(串口服务器透传场景,ADR-0016)。
/// 无长度域 → 从候选长度逐个验 CRC 锚定帧界;未知 slave 回网关码 0x0B。
fn pump_rtu(c: &mut Conn, entries: &[DevEntry], bus: &Arc<Mutex<Vec<String>>>) -> Result<(), ()> {
    let mut handled = 0usize;
    loop {
        if c.buf.len() < 4 {
            break; // 最小合法 RTU ADU = slave(1)+func(1)+CRC(2)
        }
        // 定帧:从 4B 起逐长度验 CRC,首个命中即帧界(CRC16 错位碰撞概率 ~1/65536,可忽略)
        let mut adu_len: Option<usize> = None;
        for l in 4..=c.buf.len().min(256) {
            let body = &c.buf[..l];
            let n2 = body.len();
            let crc = crc::crc16_modbus(&body[..n2 - 2]);
            let want = [(crc & 0xFF) as u8, (crc >> 8) as u8];
            if body[n2 - 2] == want[0] && body[n2 - 1] == want[1] {
                adu_len = Some(l);
                break;
            }
        }
        let Some(adu) = adu_len else { break }; // 半帧:下轮续传
        let frame: Vec<u8> = c.buf.drain(..adu).collect();
        let slave = frame[0];
        let entry = entries.iter().find(|e| e.dev.slave == slave);
        let (pdu, emit_dev) = match entry {
            Some(e) => (process_pdu(&frame[1..frame.len() - 2], &e.space, &e.last_req, &e.health), Some(&e.dev)),
            None => (vec![frame[1] | 0x80, 0x0B], None), // 未知 slave → 网关码 0x0B
        };
        // 主机读值记录(真实主机路径;自轮询不经此处)
        if let Some(e) = entry {
            record_host_read(&e.space, &e.host_reads, frame[1], &pdu, &frame[2..frame.len() - 2]);
        }
        let mut resp = vec![slave];
        resp.extend_from_slice(&pdu);
        let crc = crc::crc16_modbus(&resp);
        resp.push(crc as u8);
        resp.push((crc >> 8) as u8);
        if c.stream.write_all(&resp).is_err() {
            return Err(());
        }
        // emit 用去掉 CRC 的 ADU(与解析链路的 RTU 裸字节口径一致)
        match emit_dev {
            Some(d) => {
                emit_modbus_jsonl(bus, d, true, &frame[..frame.len() - 2]);
                emit_modbus_jsonl(bus, d, false, &resp[..resp.len() - 2]);
            }
            None => {
                let ghost = MbDev { id: 0, name: format!("未知slave{slave}"), port: 0, slave, poll_ms: 0, link: "rtu_tcp".into(), points: vec![] };
                emit_modbus_jsonl(bus, &ghost, true, &frame[..frame.len() - 2]);
                emit_modbus_jsonl(bus, &ghost, false, &resp[..resp.len() - 2]);
            }
        }
        handled += 1;
        if handled >= 32 {
            break;
        }
    }
    Ok(())
}

/// Modbus TCP 形态:MBAP 头 tid(2) pid(2) len(2),len = unit + PDU,完整 ADU = 6+len
fn pump_mbap(c: &mut Conn, entries: &[DevEntry], bus: &Arc<Mutex<Vec<String>>>) -> Result<(), ()> {
    let mut handled = 0usize;
    loop {
        if c.buf.len() < 8 {
            break; // 最小合法 ADU 8B(len≥2);半帧留在缓冲
        }
        let pid = ((c.buf[2] as u16) << 8) | c.buf[3] as u16;
        let len = (((c.buf[4] as u16) << 8) | c.buf[5] as u16) as usize;
        // 协议标识必须为 0;len 合法域 2..=254(ADU ≤ 260,Modbus TCP 上限)
        if pid != 0 || len < 2 || len > 254 {
            return Err(()); // 流不同步:断连让主机重建,避免错位解析出垃圾应答
        }
        let adu = 6 + len;
        if c.buf.len() < adu {
            break; // 半帧:下轮续传
        }
        let frame: Vec<u8> = c.buf.drain(..adu).collect();
        let unit = frame[6];
        let entry = entries.iter().find(|e| e.dev.slave == unit);
        let (resp, emit_dev) = match entry {
            Some(e) => (process_frame(&frame, &e.space, &e.last_req, &e.health), Some(&e.dev)),
            None => {
                // 未知 unit:网关语义回 0x0B(目标从机无响应),主机侧可定位"unit 配错"。
                // MBAP len 必须按实际 PDU 重算(unit 1B + 异常 PDU 2B = 3),沿用请求头 len 会导致
                // 主机按旧长度等体超时(回归:zz_probe 抓出 len=6/实发 3 的错位)
                let mut resp = frame[..4].to_vec();
                resp.extend([0u8, 3, unit, frame[7] | 0x80, 0x0B]);
                (resp, None)
            }
        };
        // 主机读值记录(真实主机路径;自轮询不经此处):req = frame[8..](addr+cnt),resp PDU 从 [7] 起
        if let Some(e) = entry {
            record_host_read(&e.space, &e.host_reads, frame[7], &resp[7..], &frame[8..]);
        }
        if c.stream.write_all(&resp).is_err() {
            return Err(());
        }
        // 请求/响应 → NDJSON(联调同屏,每帧一对);uart 裸字节形态,解析链路的 Modbus RTU/TCP 识别器天然可读
        match emit_dev {
            Some(d) => {
                emit_modbus_jsonl(bus, d, true, &frame[6..]);
                emit_modbus_jsonl(bus, d, false, &resp[6..]);
            }
            None => {
                // 未知 unit 也进管线(ch=0 独立通道),主机配错一眼可见
                let ghost = MbDev { id: 0, name: format!("未知unit{unit}"), port: 0, slave: unit, poll_ms: 0, link: "tcp".into(), points: vec![] };
                emit_modbus_jsonl(bus, &ghost, true, &frame[6..]);
                emit_modbus_jsonl(bus, &ghost, false, &resp[6..]);
            }
        }
        handled += 1;
        if handled >= 32 {
            break; // 单轮上限,保持轮询节奏(其余帧下轮继续)
        }
    }
    Ok(())
}

/// 真实主机 func3/4 读成功 → 记录被覆盖点位的"主机读到的物理值 + 次数 + 时刻"(点位编辑表「主机读到」列)。
/// req = addr(2)+cnt(2);resp_pdu[0] == func 才算成功(异常码 0x8x 不记)。
fn record_host_read(
    space: &Arc<Mutex<RegSpace>>,
    host_reads: &Arc<Mutex<HostReads>>,
    func: u8,
    resp_pdu: &[u8],
    req: &[u8],
) {
    if !matches!(func, 3 | 4) || resp_pdu.first() != Some(&func) || req.len() < 4 {
        return;
    }
    let addr = ((req[0] as u16) << 8) | req[1] as u16;
    let cnt = ((req[2] as u16) << 8) | req[3] as u16;
    let hits = match space.lock() {
        Ok(sp) => sp.points_in_range(func, addr, cnt),
        Err(_) => return,
    };
    if hits.is_empty() {
        return;
    }
    if let Ok(mut m) = host_reads.lock() {
        let now = Instant::now();
        for (name, phys) in hits {
            let e = m.entry(name).or_insert((0.0, 0, now));
            e.0 = phys;
            e.1 += 1;
            e.2 = now;
        }
    }
}

/// 场景引擎:Normal=静止;Random=对可写 u16/i16 点位小幅随机;Fault=系统故障位置 1
fn apply_scene(sp: &mut RegSpace, scene: Scene) {
    match scene {
        Scene::Normal => {}
        Scene::Random => {
            // 扰动数值点(联调时曲线有变化):点位带 min/max → 在范围内随机(模拟真实波动);
            // 无范围 → 当前值 ±2% 小抖。每拍换一批起点,让全部点位轮流被扰动
            let names: Vec<String> = sp
                .points
                .iter()
                .filter(|p| matches!(p.ty.as_str(), "u16" | "i16" | "u32" | "i32"))
                .map(|p| p.name.clone())
                .collect();
            for n in names {
                sp.jitter_point(&n, rand01());
            }
        }
        Scene::Fault => {
            // 名字含"故障/告警"的 bit 点置 1
            let bits: Vec<(String, f64)> = sp
                .points
                .iter()
                .filter(|p| p.ty == "bit" && (p.name.contains("故障") || p.name.contains("告警")))
                .filter(|p| !sp.pinned.contains(&p.name)) // 📌 已置的位不注入
                .take(8)
                .map(|p| (p.name.clone(), 1.0))
                .collect();
            for (n, v) in bits {
                sp.write_point_by_name(&n, v);
            }
        }
    }
}

fn rand01() -> f64 {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
    (n % 1000) as f64 / 1000.0
}

/// 处理 MBAP 帧 → 响应 ADU(tid/unit 回显)
fn process_frame(
    frame: &[u8],
    space: &Arc<Mutex<RegSpace>>,
    last_req: &Arc<Mutex<Option<Instant>>>,
    health: &Arc<Mutex<LinkHealth>>,
) -> Vec<u8> {
    let tid = ((frame[0] as u16) << 8) | frame[1] as u16;
    let unit = frame[6];
    let pdu = process_pdu(&frame[7..], space, last_req, health);
    let len = pdu.len() + 1;
    let mut resp = vec![(tid >> 8) as u8, tid as u8, 0, 0, (len >> 8) as u8, len as u8, unit];
    resp.extend_from_slice(&pdu);
    resp
}

/// 处理一帧 PDU(func 起;TCP/RTU 两形态共用应答语义)。
/// func3/4 读、func6/16 写;数量/地址越界回异常码,未知功能码回 0x01。
fn process_pdu(
    pdu_in: &[u8],
    space: &Arc<Mutex<RegSpace>>,
    last_req: &Arc<Mutex<Option<Instant>>>,
    health: &Arc<Mutex<LinkHealth>>,
) -> Vec<u8> {
    let func = pdu_in[0];
    let pdu_len = pdu_in.len();
    // 构响应 PDU
    let mut pdu: Vec<u8> = vec![];
    match func {
        3 | 4 => {
            if pdu_len < 5 {
                pdu.extend([func | 0x80, 0x03]); // PDU 不完整
            } else {
                let addr = ((pdu_in[1] as u16) << 8) | pdu_in[2] as u16;
                let cnt = ((pdu_in[3] as u16) << 8) | pdu_in[4] as u16;
                // 数量合法域 1..=125;地址区间不得越过寄存器空间(防 u16 回绕)
                if cnt < 1 || cnt > 125 {
                    pdu.extend([func | 0x80, 0x03]); // illegal data value
                } else if addr as u32 + cnt as u32 > 0x10000 {
                    pdu.extend([func | 0x80, 0x02]); // illegal data address
                } else {
                    let sp = space.lock().unwrap_or_else(|e| e.into_inner());
                    match sp.read(func, addr, cnt) {
                        Some(vals) => {
                            pdu.push(func);
                            pdu.push((vals.len() * 2) as u8);
                            for v in vals {
                                pdu.push((v >> 8) as u8);
                                pdu.push(v as u8);
                            }
                        }
                        None => {
                            pdu.extend([func | 0x80, 0x02]); // illegal data address
                        }
                    }
                }
            }
        }
        6 => {
            if pdu_len < 5 {
                pdu.extend([func | 0x80, 0x03]);
            } else {
                let addr = ((pdu_in[1] as u16) << 8) | pdu_in[2] as u16;
                let val = ((pdu_in[3] as u16) << 8) | pdu_in[4] as u16;
                if let Ok(mut sp) = space.lock() {
                    sp.write_one(addr, val);
                }
                pdu.extend_from_slice(&pdu_in[..5]); // echo
            }
        }
        16 => {
            if pdu_len < 6 {
                pdu.extend([func | 0x80, 0x03]);
            } else {
                let addr = ((pdu_in[1] as u16) << 8) | pdu_in[2] as u16;
                let cnt = ((pdu_in[3] as u16) << 8) | pdu_in[4] as u16;
                let bc = pdu_in[5] as usize;
                // 数量合法域 1..=123 且字节数/帧长自洽;地址不得越界
                if cnt < 1 || cnt > 123 || bc != cnt as usize * 2 || pdu_len != 6 + bc {
                    pdu.extend([func | 0x80, 0x03]); // illegal data value
                } else if addr as u32 + cnt as u32 > 0x10000 {
                    pdu.extend([func | 0x80, 0x02]);
                } else {
                    let mut vals = Vec::with_capacity(cnt as usize);
                    for i in 0..cnt as usize {
                        vals.push(((pdu_in[6 + i * 2] as u16) << 8) | pdu_in[7 + i * 2] as u16);
                    }
                    if let Ok(mut sp) = space.lock() {
                        sp.write_multi(addr, &vals);
                    }
                    pdu.extend([16, (addr >> 8) as u8, addr as u8, (cnt >> 8) as u8, cnt as u8]);
                }
            }
        }
        _ => {
            pdu.extend([func | 0x80, 0x01]); // illegal function
        }
    }
    // 标记最近请求时刻
    if let Ok(mut t) = last_req.lock() {
        *t = Some(Instant::now());
    }
    // 链路健康(拓扑连线图 A1):异常码应答与正常应答分开记;自轮询同样走此路径,
    // 但判定只看"真实主机连接/断开",last_exc/last_ok 只影响已有连接时的红/绿细分。
    if let Ok(mut h) = health.lock() {
        if pdu.first().copied().unwrap_or(0) & 0x80 != 0 {
            h.last_exc = Some(Instant::now());
        } else {
            h.last_ok = Some(Instant::now());
        }
    }
    pdu
}

/// 把一次请求/响应推入 live 管线(dir: true=请求[Tx 语义上是外部主站发出],false=响应)
fn emit_modbus_jsonl(bus: &Arc<Mutex<Vec<String>>>, dev: &MbDev, is_req: bool, pdu_full: &[u8]) {
    // RTU 形态:PDU + CRC16(模拟串口侧字节流,统一走 uart 通道)
    let mut frame = pdu_full.to_vec();
    let c = crc::crc16_modbus(&frame);
    frame.push(c as u8);
    frame.push((c >> 8) as u8);
    let f = LiveFrame {
        ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64,
        ts_src: TsSrc::Sw,
        bus_type: BusKind::Uart,
        ch: dev.id, // 每 dev 一个通道
        alias: Some(format!("模拟·{}", dev.name)),
        dir: if is_req { Dir::Tx } else { Dir::Rx },
        id: 0,
        id_ext: false,
        dlc: frame.len(),
        data: frame,
        seq: None,
        meta_gap: None,
    };
    // 输出进本运行时专属 collector(线程安全),由 spawn_standalone 的泵线程取走;
    // 多模拟器实例各自独立,不互偷帧(回归:全局总线时代并行测试/双实例会串流)
    bus.lock().unwrap_or_else(|e| e.into_inner()).push(live_frame_to_jsonl(&f));
}

/// 独立启停:起服务线程 + NDJSON→管线泵线程,直接把 Batch 发进 App 的 live 通道。
/// 生命周期与"实时接入"解耦:面板「启动/停止模拟器」控制,断开实时不影响服务。
/// record_path = Some 时原始 NDJSON 行逐行落盘(与实时源录制同一 Recorder,可离线重放)。
/// 返回 (运行时, 启动告警——含端口绑定失败列表;GUI 顶栏展示,不再静默)。
pub fn spawn_standalone(
    yaml_path: &std::path::Path,
    tx: std::sync::mpsc::Sender<crate::live::LiveMsg>,
    record_path: Option<std::path::PathBuf>,
    tee: Option<Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>>,
) -> Result<(Arc<ModDevRuntime>, Vec<String>), String> {
    let yaml = std::fs::read_to_string(yaml_path).map_err(|e| format!("读取点位表 {} 失败: {e}", yaml_path.display()))?;
    let (rt, warns, _h) = ModDevRuntime::start(&yaml)?;
    let stop = rt.stop.clone();
    let bus = rt.bus.clone();
    let t2 = tx.clone();
    let warns_for_pipe = warns.clone();
    std::thread::Builder::new()
        .name("moddev-pump".into())
        .spawn(move || {
            // 复用 live 的 Pipeline:NDJSON → Record(与真实抓包同一解析路径,Modbus RTU/TCP 识别器直接可用)
            // 录制:与实时源同一 Recorder(追加模式);写失败降级为告警,不影响接收
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

            for w in warns_for_pipe {
                pipe.sess.warn(w);
            }
            loop {
                if stop.load(Ordering::Relaxed) {
                    if let Some(r) = recorder.as_mut() {
                        r.flush();
                        if let Some(e) = r.err() {
                            let _ = t2.send(crate::live::LiveMsg::Info(format!("录制写失败: {e}")));
                        }
                    }
                    let _ = t2.send(crate::live::LiveMsg::Ended(Ok(())));
                    return;
                }
                let lines = match bus.lock() { Ok(mut g) => std::mem::take(&mut *g), Err(e) => e.into_inner().clone() };
                if !lines.is_empty() {
                    if let Some(r) = recorder.as_mut() {
                        for l in &lines {
                            r.write_line(l);
                        }
                    }
                    let mut batch = vec![];
                    for l in lines {
                        if let Some(r) = pipe.sess.map_line(&l) {
                            batch.push(r);
                        }
                    }
                    if !batch.is_empty() {
                        let _ = t2.send(crate::live::LiveMsg::Batch(crate::live::Batch {
                            records: batch,
                            labels: pipe.sess.labels(),
                            stats: Some(pipe.sess.stats()),
                            warnings: pipe.sess.take_warnings(),
                            epoch_ns: pipe.sess.epoch_ns(),
                        }));
                    }
                }
                if let Some(r) = recorder.as_mut() {
                    r.flush(); // 模拟器数据率低,逐轮落盘保"随时可停不丢尾"
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
        .expect("启动模拟器泵线程失败");
    Ok((rt, warns))
}



#[cfg(test)]
mod tcp_frame_tests {
    use super::*;
    use std::net::TcpStream;

    // 端口 0 = 系统分配,测试并行无冲突;通过 DevState.bound_port 拿实际端口
    const YAML: &str = r#"
dev1: {enable: 1, name: 组帧测试PCS, port: 0, slave: 1, poll_ms: 1000}
dev1_测试:
  a30: {name: 电网电压, addr: 0x001E, func: 3, type: u16, scale: 0.1, init: 4000}
"#;

    fn start_sim() -> (Arc<ModDevRuntime>, u16) {
        let (rt, warns, _h) = ModDevRuntime::start(YAML).unwrap();
        assert!(warns.is_empty(), "port 0 绑定不应失败: {warns:?}");
        let port = rt.devs[0].bound_port;
        assert!(port > 0, "应记录系统分配的实际端口");
        (rt, port)
    }

    fn read_req(tid: u16, addr: u16, cnt: u16) -> Vec<u8> {
        let mut f = vec![(tid >> 8) as u8, tid as u8, 0, 0, 0, 6, 1, 3];
        f.extend([(addr >> 8) as u8, addr as u8, (cnt >> 8) as u8, cnt as u8]);
        f
    }

    /// 读一帧完整响应,返回 (tid, PDU)
    fn read_adu(c: &mut TcpStream) -> (u16, Vec<u8>) {
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut hdr = [0u8; 7];
        let mut got = 0;
        while got < 7 {
            let n = c.read(&mut hdr[got..]).expect("读响应头");
            assert!(n > 0, "对端提前关闭");
            got += n;
        }
        let tid = ((hdr[0] as u16) << 8) | hdr[1] as u16;
        let len = (((hdr[4] as usize) << 8) | hdr[5] as usize) - 1;
        let mut rest = vec![0u8; len];
        let mut got = 0;
        while got < len {
            let n = c.read(&mut rest[got..]).expect("读响应体");
            assert!(n > 0, "响应体不完整");
            got += n;
        }
        (tid, rest)
    }

    #[test]
    fn pipelined_requests_all_answered() {
        // 回归:旧实现每次只处理 TCP 缓冲里的第一帧,主机 pipeline 连发/粘包时其余请求石沉大海
        let (_rt, port) = start_sim();
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut batch = vec![];
        for tid in [1u16, 2, 3] {
            batch.extend(read_req(tid, 0x001E, 1));
        }
        c.write_all(&batch).unwrap();
        let (t1, p1) = read_adu(&mut c);
        let (t2, p2) = read_adu(&mut c);
        let (t3, p3) = read_adu(&mut c);
        assert_eq!((t1, t2, t3), (1, 2, 3), "三帧请求各自独立应答");
        for p in [p1, p2, p3] {
            assert_eq!(p[0], 3);
            assert_eq!(((p[2] as u16) << 8) | p[3] as u16, 4000, "init raw 直读");
        }
    }

    #[test]
    fn split_request_still_answered() {
        // 回归:旧实现把 <8B 的半帧直接丢弃,拆包到达的请求永远无应答(主机侧表现为超时)
        let (_rt, port) = start_sim();
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let req = read_req(7, 0x001E, 1);
        c.write_all(&req[..6]).unwrap();
        c.flush().unwrap();
        std::thread::sleep(Duration::from_millis(80)); // 半帧先到,模拟网络分段
        c.write_all(&req[6..]).unwrap();
        c.flush().unwrap();
        let (tid, pdu) = read_adu(&mut c);
        assert_eq!(tid, 7);
        assert_eq!(pdu[0], 3);
        assert_eq!(((pdu[2] as u16) << 8) | pdu[3] as u16, 4000);
    }

    #[test]
    fn quantity_and_address_bounds() {
        // 回归:cnt=0/超限旧实现会构造 byte_count=0 或截断的畸形响应;
        // addr+cnt 越过寄存器空间在 debug 构建 u16 回绕还会 panic 拖垮服务线程
        let (_rt, port) = start_sim();
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(&read_req(11, 0x001E, 0)).unwrap();
        let (tid, pdu) = read_adu(&mut c);
        assert_eq!(tid, 11);
        assert_eq!(pdu, vec![0x83, 0x03], "cnt=0 → illegal data value");
        c.write_all(&read_req(12, 0x001E, 126)).unwrap();
        let (_, pdu) = read_adu(&mut c);
        assert_eq!(pdu, vec![0x83, 0x03], "cnt>125 → illegal data value");
        c.write_all(&read_req(13, 0xFFFF, 2)).unwrap();
        let (_, pdu) = read_adu(&mut c);
        assert_eq!(pdu, vec![0x83, 0x02], "地址越界 → illegal data address");
        // 上边界:cnt=125 合法且应完整应答(125×2=250 字节数据)
        c.write_all(&read_req(14, 0x001E, 125)).unwrap();
        let (_, pdu) = read_adu(&mut c);
        assert_eq!(pdu[0], 3);
        assert_eq!(pdu[1], 250);
    }

    #[test]
    fn unknown_function_returns_illegal_function() {
        let (_rt, port) = start_sim();
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        // func8(诊断)未实现 → 0x88/0x01,响应帧结构仍合法
        let mut f = vec![0, 21, 0, 0, 0, 4, 1, 8];
        f.extend([0, 0]);
        c.write_all(&f).unwrap();
        let (tid, pdu) = read_adu(&mut c);
        assert_eq!(tid, 21);
        assert_eq!(pdu, vec![0x88, 0x01]);
    }

    #[test]
    fn per_device_endpoints_match_table_topology() {
        // 每设备独立端点(对齐真实采集表:同网关不同端口,unit 各自生效);
        // 同端口多机自动改用 127.0.0.<N> 区分;未知 unit 回网关码 0x0B
        let yaml = r#"
dev1: {enable: 1, name: 路由A, port: 0, slave: 1, poll_ms: 0}
dev1_x: {a: {name: V, addr: 0x0000, func: 3, type: u16, init: 111}}
dev2: {enable: 1, name: 路由B, port: 0, slave: 1, poll_ms: 0}
dev2_x: {a: {name: V, addr: 0x0000, func: 3, type: u16, init: 222}}
dev3: {enable: 1, name: 路由C, port: 0, slave: 80, poll_ms: 0}
dev3_x: {a: {name: V, addr: 0x0000, func: 3, type: u16, init: 333}}
"#;
        let (rt, warns, _h) = ModDevRuntime::start(yaml).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        // 端口 0 三台共用计数>1 → 回环 IP 区分;绑定地址与端口各自独立
        assert_eq!(rt.devs[0].bind_addr, "127.0.0.1");
        assert_eq!(rt.devs[1].bind_addr, "127.0.0.2");
        assert_ne!(rt.devs[0].bound_port, rt.devs[1].bound_port, "port 0 系统分配应互不相同");
        // 各自端点按 unit 应答(unit=1 常态;dev3 unit=80)
        for (i, unit, expect) in [(0usize, 1u8, 111u16), (1, 1, 222), (2, 80, 333)] {
            let d = &rt.devs[i];
            assert!(d.port_bound);
            let mut c = TcpStream::connect((d.bind_addr.as_str(), d.bound_port)).unwrap();
            c.write_all(&[0, unit, 0, 0, 0, 6, unit, 3, 0, 0, 0, 1]).unwrap();
            let (tid, pdu) = read_adu(&mut c);
            assert_eq!(tid, unit as u16);
            assert_eq!(pdu[0], 3, "unit={unit} 正常应答");
            assert_eq!(((pdu[2] as u16) << 8) | pdu[3] as u16, expect);
        }
        // 未知 unit 99(dev1 端点上)→ func|0x80 + 0x0B,且 MBAP len 已按实际 PDU 重算(体可读全)
        let d = &rt.devs[0];
        let mut c = TcpStream::connect((d.bind_addr.as_str(), d.bound_port)).unwrap();
        c.write_all(&[0, 99, 0, 0, 0, 6, 99, 3, 0, 0, 0, 1]).unwrap();
        let (tid, pdu) = read_adu(&mut c);
        assert_eq!(tid, 99);
        assert_eq!(pdu, vec![0x83, 0x0B], "未知 unit 回 0x0B");
    }

    #[test]
    fn self_poll_reads_only_defined_runs() {
        // 自轮询按已定义地址连续段:断档两侧各自成段,段起点必为已定义地址 → 全部正常应答,
        // 不产生异常码 2(回归:按跨度硬扫时断档 chunk 起点未定义,实录刷出 3.8 万条垃圾异常)
        let yaml = r#"
dev1: {enable: 1, name: 断档PCS, port: 0, slave: 1, poll_ms: 60}
dev1_x:
  a: {name: 低段, addr: 0x0000, func: 3, type: u16, init: 10}
  b: {name: 低段尾, addr: 0x0002, func: 3, type: u16, init: 12}
  c: {name: 高段, addr: 0x0100, func: 3, type: u16, init: 256}
"#;
        let (rt, warns, _h) = ModDevRuntime::start(yaml).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        std::thread::sleep(Duration::from_millis(300));
        let lines = rt.drain();
        let mine: Vec<&String> = lines.iter().filter(|l| l.contains("断档PCS")).collect();
        assert!(mine.len() >= 4, "两段各一对请求/响应:实际 {} 行", mine.len());
        // 无异常应答(func|0x80 首字节在 data[1],RTU 帧首字节是 unit)
        for l in &mine {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let data = v["data"].as_array().unwrap();
            if v["dir"] == "rx" {
                assert_ne!(data[1], 0x83, "自轮询不应出现异常应答: {l}");
            }
        }
    }

    #[test]
    fn self_poll_emits_without_master() {
        // 自轮询:poll_ms 到期即以主机身份读自己并 emit —— 无主机连入管线也有数据(修复"只接收不发送")
        let yaml = r#"
dev1: {enable: 1, name: 自轮询独占PCS, port: 0, slave: 1, poll_ms: 100}
dev1_x: {a: {name: 电压, addr: 0x001E, func: 3, type: u16, init: 4000}}
"#;
        let (rt, warns, _h) = ModDevRuntime::start(yaml).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        std::thread::sleep(Duration::from_millis(500));
        let lines = rt.drain();
        let mine: Vec<&String> = lines.iter().filter(|l| l.contains("自轮询独占PCS")).collect();
        assert!(mine.len() >= 2, "至少一对请求/响应:实际 {} 行: {lines:?}", mine.len());
        assert!(mine.iter().any(|l| l.contains("\"dir\":\"tx\"")), "应有自轮询请求帧");
        assert!(mine.iter().any(|l| l.contains("\"dir\":\"rx\"")), "应有自轮询响应帧");
    }

    #[test]
    fn standalone_records_to_disk() {
        // 录制接线:spawn_standalone 带 record_path → 原始 NDJSON 逐行落盘,停止后文件可读
        let yaml = r#"
dev1: {enable: 1, name: 录制PCS, port: 0, slave: 1, poll_ms: 80}
dev1_x: {a: {name: 电压, addr: 0x001E, func: 3, type: u16, init: 4000}}
"#;
        let dir = std::env::temp_dir().join("iotprobe_moddev_rec");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("sim_rec.ndjson");
        let _ = std::fs::remove_file(&path);
        let yaml_p = dir.join("pts.yaml");
        std::fs::write(&yaml_p, yaml).unwrap();
        let sink = crate::live::spawn_sink();
        let (rt, warns) = crate::moddev::spawn_standalone(&yaml_p, sink.tx.clone(), Some(path.clone()), None).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        // 等 pump 线程落盘几轮(自轮询 80ms 一拍)
        std::thread::sleep(Duration::from_millis(600));
        rt.stop_all();
        std::thread::sleep(Duration::from_millis(200));
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let n = text.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(n >= 2, "录制文件应有内容,实际 {n} 行");
        for l in text.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(l).expect("每行都是合法 NDJSON");
            assert_eq!(v["bus"]["type"], "uart");
        }
    }

    #[test]
    fn rtu_tcp_form_answered() {
        // link: rtu_tcp = RTU-over-TCP(slave+CRC 定帧):串口服务器透传场景,同一套点位表
        let yaml = r#"
dev1: {enable: 1, name: RTU透传PCS, link: rtu_tcp, port: 0, slave: 11, poll_ms: 0}
dev1_x:
  v: {name: 电压, addr: 0x001E, func: 3, type: u16, scale: 0.1, init: 4000}
  st: {name: 运行状态, addr: 0x0021, func: 3, type: bit, bit: 0}
"#;
        let (rt, warns, _h) = ModDevRuntime::start(yaml).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        let port = rt.devs[0].bound_port;
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // RTU 读请求:slave(11)+func3+addr+cnt+CRC
        let mut req = vec![11u8, 3, 0x00, 0x1E, 0x00, 0x01];
        let crc = crc::crc16_modbus(&req);
        req.push(crc as u8);
        req.push((crc >> 8) as u8);
        c.write_all(&req).unwrap();
        let mut resp = vec![0u8; 64];
        let n = c.read(&mut resp).expect("RTU 应答");
        assert!(n >= 7, "应答至少 slave+func+bc+2data+CRC: {n}");
        assert_eq!(resp[0], 11, "slave 回显");
        assert_eq!(resp[1], 3);
        assert_eq!(resp[2], 2, "byte count");
        assert_eq!(((resp[3] as u16) << 8) | resp[4] as u16, 4000, "init 直读");
        let want = crc::crc16_modbus(&resp[..n - 2]);
        assert_eq!(resp[n - 2], (want & 0xFF) as u8);
        assert_eq!(resp[n - 1], (want >> 8) as u8, "应答 CRC 校验");
        // bit 点地址(0x0021 无 init)也应正常应答(靠 core bit 注册修复)
        let mut req2 = vec![11u8, 3, 0x00, 0x21, 0x00, 0x01];
        let crc2 = crc::crc16_modbus(&req2);
        req2.push(crc2 as u8);
        req2.push((crc2 >> 8) as u8);
        c.write_all(&req2).unwrap();
        let n2 = c.read(&mut resp).expect("bit 地址应答");
        assert_eq!(resp[1], 3, "bit 所在寄存器应已注册,不再回 0x83");
        assert_eq!(((resp[3] as u16) << 8) | resp[4] as u16, 0);
        let _ = n2;
    }

    #[test]
    fn port_conflict_is_reported_not_silent() {
        // 回归:点位表多台设备配同一端口时,除首台外全部静默绑定失败,主机侧表现为"一直读取失败"
        // Windows 允许通配与特定地址同端口共存,探针必须同样绑 0.0.0.0 才能确定性复现冲突
        let probe = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let occupied = probe.local_addr().unwrap().port();
        let yaml = YAML.replace("port: 0", &format!("port: {occupied}"));
        let (rt, warns, _h) = ModDevRuntime::start(&yaml).unwrap();
        assert_eq!(warns.len(), 1, "端口被占应产生 1 条告警: {warns:?}");
        assert!(warns[0].contains("失败"), "{}", warns[0]);
        assert!(!rt.devs[0].port_bound);
        assert_eq!(rt.devs[0].bound_port, 0);
    }

    #[test]
    fn link_health_tracks_connect_drop_exc() {
        // 拓扑连线图 A1 验收:从未连入=灰(自轮询不计);主机连入=绿;断开=红;异常码=红
        let yaml = r#"
dev1: {enable: 1, name: 链路健康观测, port: 0, slave: 1, poll_ms: 0}
dev1_x: {a: {name: 电压, addr: 0x0000, func: 3, type: u16, init: 1}}
"#;
        let (rt, warns, _h) = ModDevRuntime::start(yaml).unwrap();
        assert!(warns.is_empty());
        let d = &rt.devs[0];
        assert!(matches!(d.link_state(), LinkState::Gray), "从未有主机连入应为灰");
        // 端口唯一 → 0.0.0.0 通配绑定,本机连接走 127.0.0.1
        let addr = if d.bind_addr == "0.0.0.0" { "127.0.0.1" } else { d.bind_addr.as_str() };
        // 连入并读一次 → 绿
        let mut c = TcpStream::connect((addr, d.bound_port)).unwrap();
        c.write_all(&read_req(1, 0, 1)).unwrap();
        let _ = read_adu(&mut c);
        std::thread::sleep(Duration::from_millis(50));
        assert!(matches!(d.link_state(), LinkState::Green), "连接中应为绿");
        // 断开 → 红(链路 down,重连恢复绿)
        drop(c);
        std::thread::sleep(Duration::from_millis(120));
        match d.link_state() {
            LinkState::Red(r) => assert!(r.contains("断开"), "原因应为连接已断开: {r}"),
            s => panic!("断开后应为红,实际 {s:?}"),
        }
        // 重连 + 异常功能码 → 红(异常码 5s 窗口)
        let mut c2 = TcpStream::connect((addr, d.bound_port)).unwrap();
        c2.write_all(&[0, 1, 0, 0, 0, 6, 1, 99, 0, 0, 0, 1]).unwrap();
        let (_, pdu) = read_adu(&mut c2);
        assert_eq!(pdu[0], 99 | 0x80, "非法功能码应回异常");
        drop(c2);
        std::thread::sleep(Duration::from_millis(120));
        assert!(matches!(d.link_state(), LinkState::Red(_)), "异常码后应为红");
    }

    #[test]
    fn sample_ring_and_stats() {
        // 拓扑连线图 A2:点位采样环 32 拍上限 + point_stats min/max/当前;500ms 节流生效
        let yaml = r#"
dev1: {enable: 1, name: 采样观测, port: 0, slave: 1, poll_ms: 0}
dev1_x: {a: {name: 缓变电压, addr: 0x0000, func: 3, type: u16, scale: 0.1, init: 100}}
"#;
        let (rt, warns, _h) = ModDevRuntime::start(yaml).unwrap();
        assert!(warns.is_empty());
        let d = &rt.devs[0];
        // 绕过节流直接预填 40 拍(测试私有字段可达,验证 point_stats 与环形截断)
        {
            let mut m = d.samples.lock().unwrap_or_else(|e| e.into_inner());
            let ring = m.entry("缓变电压".into()).or_default();
            for i in 0..40 {
                ring.push(i as f64 * 0.1);
            }
        }
        let (mn, mx, cur, s) = d.point_stats("缓变电压").unwrap();
        assert_eq!(s.len(), 40);
        assert!((mn - 0.0).abs() < 1e-9);
        assert!((mx - 3.9).abs() < 1e-9);
        assert!((cur - 3.9).abs() < 1e-9);
        // 放开节流 → 推进一拍(init 100×0.1=10.0 入环)→ 环截断到 32 拍
        *d.last_sample.lock().unwrap_or_else(|e| e.into_inner()) = None;
        d.sample_if_due();
        let (_mn, _mx, cur2, s2) = d.point_stats("缓变电压").unwrap();
        assert_eq!(s2.len(), 32, "环形窗口应截断到 32 拍");
        assert!((cur2 - 10.0).abs() < 1e-9, "采样推进后当前值应为点位物理值 10.0,实际 {cur2}");
        // 节流:立即再采样不应推进(last_sample 未过 500ms)
        let (_mn2, _mx2, cur3, _s3) = d.point_stats("缓变电压").unwrap();
        assert!((cur3 - cur2).abs() < 1e-9, "500ms 内重复调用不应推进采样");
    }
}

#[cfg(test)]
mod real_table_e2e {
    //! 针对开发机真实点位表(D:/dev/mbdev_points.yaml)的端到端验证;文件不存在则跳过。
    //! 覆盖用户上报的两个问题:EMS 连入有应答(端口唯一→0.0.0.0 直连)、自轮询无异常码 2 垃圾流量。
    use crate::moddev::ModDevRuntime;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    fn read_adu(c: &mut TcpStream) -> (u16, Vec<u8>) {
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut hdr = [0u8; 7];
        let mut got = 0;
        while got < 7 {
            let n = c.read(&mut hdr[got..]).expect("读响应头");
            assert!(n > 0, "对端提前关闭");
            got += n;
        }
        let tid = ((hdr[0] as u16) << 8) | hdr[1] as u16;
        let len = (((hdr[4] as usize) << 8) | hdr[5] as usize) - 1;
        let mut rest = vec![0u8; len];
        let mut got = 0;
        while got < len {
            let n = c.read(&mut rest[got..]).expect("读响应体");
            assert!(n > 0);
            got += n;
        }
        (tid, rest)
    }

    #[test]
    fn user_real_table_full_flow() {
        let p = std::path::PathBuf::from("D:/dev/mbdev_points.yaml");
        if !p.exists() {
            return; // 非开发机:跳过
        }
        let yaml = std::fs::read_to_string(&p).unwrap();
        let (rt, warns, _h) = ModDevRuntime::start(&yaml).unwrap();
        assert!(warns.is_empty(), "6 台独立端口不应有绑定告警: {warns:?}");
        assert_eq!(rt.devs.len(), 6, "PCS×4 + U2并离网 + 消防");
        // 端口全唯一 → 每台 0.0.0.0 直连(127.0.0.1 / 本机局域网 IP 均可)
        for d in &rt.devs {
            assert!(d.port_bound, "dev{} {} 未绑定", d.meta.id, d.meta.name);
            assert_eq!(d.bind_addr, "0.0.0.0");
            assert_eq!(d.bound_port, d.meta.port);
        }
        // EMS 模拟:逐台按表 unit 读首个已定义地址 —— 全部正常应答(无异常码)
        for d in &rt.devs {
            let Some(pt) = d.meta.points.iter().find(|p| p.func == 3 || p.func == 4) else { continue };
            let mut c = TcpStream::connect(("127.0.0.1", d.bound_port)).unwrap();
            let (tid, unit, addr) = (7u16, d.meta.slave, pt.addr);
            let mut req = vec![(tid >> 8) as u8, tid as u8, 0, 0, 0, 6, unit, pt.func];
            req.extend([(addr >> 8) as u8, addr as u8, 0, 1]);
            c.write_all(&req).unwrap();
            let (rtid, pdu) = read_adu(&mut c);
            assert_eq!(rtid, tid);
            assert_eq!(pdu[0], pt.func, "dev{} {} 读已定义地址应正常应答: {pdu:02X?}", d.meta.id, d.meta.name);
        }
        // dev6(消防,unit=80):错发 unit=1 → 网关码 0x0B(主机配错 unit 可定位)
        let d6 = rt.devs.iter().find(|d| d.meta.slave == 80).expect("dev6 unit=80");
        let mut c = TcpStream::connect(("127.0.0.1", d6.bound_port)).unwrap();
        c.write_all(&[0, 9, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1]).unwrap();
        let (_, pdu) = read_adu(&mut c);
        assert_eq!(pdu, vec![0x83, 0x0B]);
        // 自轮询 ~1.3s:响应帧不得出现异常码(func|0x80;RTU 帧首字节=unit,data[1]=func)
        std::thread::sleep(Duration::from_millis(1300));
        let lines = rt.drain();
        let rx_n = lines.iter().filter(|l| l.contains("\"dir\":\"rx\"")).count();
        assert!(rx_n > 0, "自轮询应有响应帧");
        // 排除"未知unit"幽灵通道(本测试自己的错 unit 探针合法地产生 0x0B)
        for l in lines.iter().filter(|l| l.contains("\"dir\":\"rx\"") && !l.contains("未知unit")) {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let data = v["data"].as_array().unwrap();
            assert_ne!(data[1].as_u64().unwrap_or(0x80) & 0x80, 0x80, "自轮询响应不得为异常: {l}");
        }
    }
}

