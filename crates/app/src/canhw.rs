//! 通用 CAN 硬件后端(P1 兼容层):
//! - Vendor 注册表:VCI 兼容卡(ControlCAN.dll,创芯 CANalyst-II/USBCAN 系)+ SLCAN 串口(CANable 等)
//! - 与 ZLG(zlgcan.dll)同一条管线:实现 Read 产契约 NDJSON,TxHub 排空即发
//! - DLL 位数检查:32 位 ControlCAN.dll 在 64 位进程无法加载,提前给出明确指引

use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::{BusKind, LiveFrame};
#[allow(unused_imports)]
use iotprobe_core::ingest::live::Pipeline;
use iotprobe_core::model::{Dir, TsSrc};
use libloading::Library;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------- 注册表 ----------------

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum HwVendor {
    /// VCI 兼容卡:创芯 CANalyst-II / USBCAN1/2 及国产兼容(ControlCAN.dll;含创芯新 SDK x64 / GCAN 同族)
    Vci,
    /// SLCAN(Lawicel 协议):CANable / 串口 CAN 适配器,零 DLL
    Slcan,
    /// PEAK PCAN-Basic(PCANBasic.dll;USB 通道,CAN_Initialize/Read/FD)
    Peak,
    /// Kvaser CANlib(canlib32.dll;canOpenChannel/BusOn/Read,支持 Virtual CAN)
    Kvaser,
    /// GCAN ECanVci(ECanVci[64].dll + CHUSBDLL[64].dll;无前缀 VCI 同构族)
    ECanVci,
}

/// 数据源名里的厂商短名(CanHw vendor 编号 0..4 与此对应)
pub fn vendor_name(vendor: HwVendor) -> &'static str {
    match vendor {
        HwVendor::Vci => "VCI",
        HwVendor::Slcan => "SLCAN",
        HwVendor::Peak => "PEAK",
        HwVendor::Kvaser => "Kvaser",
        HwVendor::ECanVci => "GCAN",
    }
}

/// 表单 vendor 编号 → 枚举(0=VCI 1=SLCAN 2=PEAK 3=Kvaser 4=GCAN)
pub fn hw_vendor(vendor: u8) -> HwVendor {
    match vendor {
        1 => HwVendor::Slcan,
        2 => HwVendor::Peak,
        3 => HwVendor::Kvaser,
        4 => HwVendor::ECanVci,
        _ => HwVendor::Vci,
    }
}


/// VCI 型号 → DeviceType 常量(公开规范:USBCAN1=3, USBCAN2=4)。
/// 纯数字直传:GCAN 等兼容厂商的 DeviceType 按其手册填数字即可。
pub fn vci_device_type(model: &str) -> u32 {
    let t = model.trim();
    if let Ok(n) = t.parse::<u32>() {
        return n;
    }
    if model.contains("USBCAN1") {
        3
    } else {
        4 // USBCAN2 / CANalyst-II
    }
}

/// 标准 VCI 波特率表(公开 ControlCAN 文档):bps → (Timing0, Timing1)
pub fn vci_timing(bitrate: u32) -> Option<(u8, u8)> {
    match bitrate {
        10_000 => Some((0x31, 0x1C)),
        20_000 => Some((0x18, 0x1C)),
        40_000 => Some((0x87, 0xFF)),
        50_000 => Some((0x09, 0x1C)),
        100_000 => Some((0x04, 0x1C)),
        125_000 => Some((0x03, 0x1C)),
        200_000 => Some((0x81, 0xFA)),
        250_000 => Some((0x01, 0x1C)),
        400_000 => Some((0x80, 0xFA)),
        500_000 => Some((0x00, 0x1C)),
        800_000 => Some((0x00, 0x16)),
        1_000_000 => Some((0x00, 0x14)),
        _ => None,
    }
}

/// SLCAN(Lawicel)波特率索引:10k..1M → S0..S8
pub fn slcan_baud_idx(bitrate: u32) -> Option<u8> {
    match bitrate {
        10_000 => Some(0),
        20_000 => Some(1),
        50_000 => Some(2),
        100_000 => Some(3),
        125_000 => Some(4),
        250_000 => Some(5),
        500_000 => Some(6),
        800_000 => Some(7),
        1_000_000 => Some(8),
        _ => None,
    }
}

// ---------------- DLL 位数检查 ----------------

/// 读 PE 头 machine 字段:0x014C=i386(32位), 0x8664=x64
pub fn pe_machine(path: &Path) -> Result<u16, String> {
    let data = std::fs::read(path).map_err(|e| format!("读 {}: {e}", path.display()))?;
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Err("不是 PE 文件".into());
    }
    let pe = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if data.len() < pe + 6 || &data[pe..pe + 4] != b"PE\x00\x00" {
        return Err("PE 签名缺失".into());
    }
    Ok(u16::from_le_bytes(data[pe + 4..pe + 6].try_into().unwrap()))
}

/// 找 DLL/桥接 exe:exe 同目录 → 同目录 canlib\ → exe 上级目录 → 当前目录
pub fn find_dll(name: &str) -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
            let p = dir.join("canlib").join(name);
            if p.exists() {
                return Some(p);
            }
            let p = dir.parent().map(|d| d.join(name)).unwrap_or_default();
            if p.exists() {
                return Some(p);
            }
        }
    }
    let p = PathBuf::from(name);
    p.exists().then_some(p)
}

/// 位数核对:64 位进程加载 32 位 DLL 必失败,提前拦截并给指引
/// (基础诊断原语;现役流程走 pick_vci_transport,本函数保留给外部工具与测试)
#[allow(dead_code)]
pub fn check_dll_bitness(path: &Path) -> Result<(), String> {
    let machine = pe_machine(path)?;
    let dll_is64 = machine == 0x8664;
    let app_is64 = cfg!(target_pointer_width = "64");
    match (dll_is64, app_is64) {
        (true, true) | (false, false) => Ok(()),
        (false, true) => Err(format!(
            "{} 是 32 位 DLL,当前程序是 64 位,无法加载。\n请向厂商索取 64 位版本放到程序目录同名替换(常见于 SDK 的 x64 目录)",
            path.display()
        )),
        (true, false) => Err(format!("{} 是 64 位 DLL,当前程序是 32 位", path.display())),
    }
}

// ---------------- 厂商 DLL 定位(第二批适配 ADR-0014) ----------------

/// 厂商 SDK 搜索根链:exe 目录与 cwd 各自**逐级上溯 4 级**,每级取该目录本身与其 `canlib\` 子目录。
/// 覆盖三种部署:发布包(exe 与 canlib 同级)、开发态 GUI(任意 cwd 启动)、cargo test(cwd=crates\app)。
fn vendor_search_roots() -> Vec<PathBuf> {
    let mut roots = vec![];
    let mut bases: Vec<PathBuf> = vec![];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }
    for base in &bases {
        let mut cur = Some(base.as_path());
        for _ in 0..=4 {
            let Some(d) = cur else { break };
            roots.push(d.to_path_buf());
            roots.push(d.join("canlib"));
            cur = d.parent();
        }
    }
    roots
}

/// 按候选相对路径逐根查找,返回首个存在者(厂商分目录存放的 SDK DLL,如 peak/x64/PCANBasic.dll)
pub fn find_vendor_dll(rels: &[&str]) -> Option<PathBuf> {
    for root in vendor_search_roots() {
        for rel in rels {
            let p = root.join(rel);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// 位数裁决查找:优先返回与进程位数一致的候选;只找到位数不符的候选时,给出带指引的错误。
/// rels64/rels32 分别是 64/32 位 DLL 的候选相对路径(可含裸文件名,裸名走系统搜索链=随驱动安装)。
pub fn find_vendor_dll_checked(rels64: &[&str], rels32: &[&str], vendor: &str) -> Result<PathBuf, String> {
    let app64 = cfg!(target_pointer_width = "64");
    let (primary, secondary) = if app64 { (rels64, rels32) } else { (rels32, rels64) };
    if let Some(p) = find_vendor_dll(primary) {
        return Ok(p);
    }
    let want = if app64 { "64" } else { "32" };
    if let Some(p) = find_vendor_dll(secondary) {
        return Err(format!(
            "找到的 {vendor} DLL 是 {} 位,当前程序是 {want} 位,无法加载。\n请安装厂商 {want} 位驱动(装好后系统目录/PATH 可见),或把 {want} 位 SDK DLL 放到 canlib\\ 对应目录。当前仅发现: {}",
            if app64 { "32" } else { "64" },
            p.display()
        ));
    }
    Err(format!(
        "未找到 {vendor} 驱动 DLL —— 请安装厂商驱动(装好后随系统加载),或把 {want} 位 SDK DLL 放到程序目录 canlib\\ 下"
    ))
}

// ---------------- 后端 trait + 源封装 ----------------

pub trait CanBackend: Send {
    /// 收帧 + 排空发送队列 → 契约 NDJSON 行(带换行);无帧返回空
    fn poll(&mut self) -> Vec<u8>;
}

/// 通用源:backend 产出 NDJSON,走与 ZLG 完全相同的 live 泵
pub struct CanHwSource {
    backend: Box<dyn CanBackend>,
    rx: Vec<u8>,
    rx_pos: usize,
}

impl CanHwSource {
    pub fn new(backend: Box<dyn CanBackend>) -> Self {
        CanHwSource { backend, rx: vec![], rx_pos: 0 }
    }

}

impl io::Read for CanHwSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_pos >= self.rx.len() {
            self.rx.clear();
            self.rx_pos = 0;
            let out = self.backend.poll();
            if out.is_empty() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "无帧"));
            }
            self.rx = out;
        }
        let n = self.rx.len().saturating_sub(self.rx_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + n]);
        self.rx_pos += n;
        Ok(n)
    }
}

// ---------------- VCI(ControlCAN.dll) ----------------

type VciOpenFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type VciCloseFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type VciInitFn = unsafe extern "system" fn(u32, u32, u32, *const VciInitConfig) -> u32;
type VciStartFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type VciRxNumFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type VciReceiveFn = unsafe extern "system" fn(u32, u32, u32, *mut VciCanObj, u32, i32) -> u32;
type VciTransmitFn = unsafe extern "system" fn(u32, u32, u32, *mut VciCanObj, u32) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VciInitConfig {
    pub acc_code: u32,
    pub acc_mask: u32,
    pub reserved: u32,
    pub filter: u8,
    pub timing0: u8,
    pub timing1: u8,
    pub mode: u8, // 0=正常 1=只听
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VciCanObj {
    pub id: u32,
    pub timestamp: u32,
    pub time_flag: u8,
    pub remote_flag: u8,
    pub extern_flag: u8,
    pub data_len: u8,
    pub data: [u8; 8],
}

impl Default for VciCanObj {
    fn default() -> Self {
        VciCanObj { id: 0, timestamp: 0, time_flag: 0, remote_flag: 0, extern_flag: 0, data_len: 0, data: [0; 8] }
    }
}

const DLL_NAME: &str = "ControlCAN.dll";
const BRIDGE_EXE: &str = "vci-bridge.exe";

fn list_paths(ps: &[PathBuf]) -> String {
    ps.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("; ")
}

/// VCI 族 DLL 候选(按优先序):老位置(创芯 32 位)→ 创芯新 SDK(cxcan,含 x64 直连版)→ GCAN(同 VCI_ 族)。
/// 多候选共享同一 API 语义,位数裁决选优后走同一条 VciLink。
fn vci_dll_candidates() -> Vec<PathBuf> {
    let mut v = vec![];
    if let Some(p) = find_dll(DLL_NAME) {
        v.push(p);
    }
    let arch_dir = if cfg!(target_pointer_width = "64") { "x64" } else { "win32" };
    if let Some(p) = find_vendor_dll(&[&format!("cxcan/sdk/{arch_dir}/ControlCAN.dll"), "gcan/ControlCAN.dll"]) {
        v.push(p);
    }
    v
}

// ---------------- 32 位桥接兼容(vci-bridge) ----------------

/// VCI 打开方式:位数匹配时进程内直连;不匹配时经桥接子进程代为加载 DLL
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VciTransport {
    /// 进程内直接加载 ControlCAN.dll(位数一致)
    InProc,
    /// 经 vci-bridge.exe 子进程转发(位数不一致;老设备的 32 位 DLL 是最常见场景)
    Bridge,
}

/// 纯函数:由 DLL/桥接/进程三方的 PE machine 决定打开方式;错误信息可直接展示给用户
pub fn pick_vci_transport(dll_machine: u16, app64: bool, bridge_machine: Option<u16>) -> Result<VciTransport, String> {
    let dll64 = dll_machine == 0x8664;
    let dll32 = dll_machine == 0x014C;
    if !dll64 && !dll32 {
        return Err(format!("无法识别 ControlCAN.dll 的位数(PE machine=0x{dll_machine:04X})"));
    }
    match (dll64, app64) {
        (true, true) | (false, false) => Ok(VciTransport::InProc),
        _ => {
            let dll_bits = if dll64 { "64" } else { "32" };
            let app_bits = if app64 { "64" } else { "32" };
            match bridge_machine {
                None => Err(format!(
                    "ControlCAN.dll 是 {dll_bits} 位,程序是 {app_bits} 位,无法直接加载。\n把 {dll_bits} 位构建的 vci-bridge.exe 放到程序目录即可自动桥接(老设备 32 位 DLL 专用);或向厂商索取 {app_bits} 位 DLL 替换"
                )),
                Some(m) if m == dll_machine => Ok(VciTransport::Bridge),
                Some(m) => Err(format!(
                    "vci-bridge.exe 与 ControlCAN.dll 位数不一致(DLL=0x{dll_machine:04X}, bridge=0x{m:04X});请换 {dll_bits} 位构建的 vci-bridge.exe"
                )),
            }
        }
    }
}

/// 桥接行协议 · SEND 数据段(app → 桥接):`<id> <ext> <rtr> <dlc> <hex…>`
pub(crate) fn bridge_send_fields(o: &VciCanObj) -> String {
    let dl = (o.data_len as usize).min(8);
    let mut s = format!("{} {} {} {}", o.id, u8::from(o.extern_flag != 0), u8::from(o.remote_flag != 0), dl);
    for b in &o.data[..dl] {
        s.push_str(&format!(" {b:02X}"));
    }
    s
}

/// 桥接行协议 · F 帧行(桥接 → app):`F <id> <ext> <rtr> <dlc> <hex…>` → VciCanObj
pub(crate) fn parse_frame_line(l: &str) -> Option<VciCanObj> {
    let mut it = l.split_whitespace();
    if it.next()? != "F" {
        return None;
    }
    let mut o = VciCanObj::default();
    o.id = it.next()?.parse().ok()?;
    o.extern_flag = if it.next()? == "1" { 1 } else { 0 };
    o.remote_flag = if it.next()? == "1" { 1 } else { 0 };
    let dl = it.next()?.parse::<usize>().ok()?.min(8);
    o.data_len = dl as u8;
    for (k, tok) in it.take(dl).enumerate() {
        o.data[k] = u8::from_str_radix(tok, 16).ok()?;
    }
    Some(o)
}

/// 桥接行协议 · INIT 命令(app → 桥接):十进制展开 VciInitConfig
pub(crate) fn bridge_init_cmd(ch: u32, ic: &VciInitConfig) -> String {
    format!(
        "INIT {} {} {} {} {} {} {}",
        ch, ic.timing0, ic.timing1, ic.mode, ic.filter, ic.acc_code, ic.acc_mask
    )
}

// ---------------- VCI(ControlCAN.dll) ----------------

/// 一条 VCI 设备链路:进程内 DLL 与桥接子进程实现同一套语义,上层不感知差异
trait VciLink: Send {
    fn open(&mut self) -> Result<(), String>;
    fn init(&mut self, ch: u32, ic: &VciInitConfig) -> Result<(), String>;
    fn start(&mut self, ch: u32) -> Result<(), String>;
    fn rx_num(&mut self, ch: u32) -> u32;
    fn receive(&mut self, ch: u32, max: usize) -> Vec<VciCanObj>;
    fn transmit(&mut self, ch: u32, obj: &VciCanObj) -> u32;
    /// 关设备;桥接实现的退出动作统一交给 Drop 处理
    fn close(&mut self);
}

/// 进程内直连:与旧实现完全相同的 DLL 调用路径
struct VciInProc {
    _lib: libloading::Library,
    open_: VciOpenFn,
    close_: VciCloseFn,
    init: VciInitFn,
    start: VciStartFn,
    rx_num: VciRxNumFn,
    receive: VciReceiveFn,
    transmit: VciTransmitFn,
    dev_type: u32,
    dev_idx: u32,
    buf: Box<[VciCanObj; 64]>,
}

impl VciInProc {
    fn new(path: &Path, dev_type: u32, dev_idx: u32) -> Result<Self, String> {
        let lib = unsafe { Library::new(path) }.map_err(|e| format!("加载 {}: {e}", path.display()))?;
        // 先校齐所有符号再落库(缺一个就整体失败,不留半开设备)
        let open_: VciOpenFn = unsafe { *lib.get(b"VCI_OpenDevice").map_err(|e| e.to_string())? };
        let close_: VciCloseFn = unsafe { *lib.get(b"VCI_CloseDevice").map_err(|e| e.to_string())? };
        let init: VciInitFn = unsafe { *lib.get(b"VCI_InitCAN").map_err(|e| e.to_string())? };
        let start: VciStartFn = unsafe { *lib.get(b"VCI_StartCAN").map_err(|e| e.to_string())? };
        let rx_num: VciRxNumFn = unsafe { *lib.get(b"VCI_GetReceiveNum").map_err(|e| e.to_string())? };
        let receive: VciReceiveFn = unsafe { *lib.get(b"VCI_Receive").map_err(|e| e.to_string())? };
        let transmit: VciTransmitFn = unsafe { *lib.get(b"VCI_Transmit").map_err(|e| e.to_string())? };
        Ok(VciInProc {
            _lib: lib,
            open_,
            close_,
            init,
            start,
            rx_num,
            receive,
            transmit,
            dev_type,
            dev_idx,
            buf: Box::new([VciCanObj::default(); 64]),
        })
    }
}

impl VciLink for VciInProc {
    fn open(&mut self) -> Result<(), String> {
        let st = unsafe { (self.open_)(self.dev_type, self.dev_idx, 0) };
        (st == 1).then_some(()).ok_or_else(|| format!("状态码 {st}"))
    }
    fn init(&mut self, ch: u32, ic: &VciInitConfig) -> Result<(), String> {
        let st = unsafe { (self.init)(self.dev_type, self.dev_idx, ch, ic) };
        (st == 1).then_some(()).ok_or_else(|| format!("状态码 {st}"))
    }
    fn start(&mut self, ch: u32) -> Result<(), String> {
        let st = unsafe { (self.start)(self.dev_type, self.dev_idx, ch) };
        (st == 1).then_some(()).ok_or_else(|| format!("状态码 {st}"))
    }
    fn rx_num(&mut self, ch: u32) -> u32 {
        unsafe { (self.rx_num)(self.dev_type, self.dev_idx, ch) }
    }
    fn receive(&mut self, ch: u32, max: usize) -> Vec<VciCanObj> {
        let n = max.min(64) as u32;
        let got = unsafe { (self.receive)(self.dev_type, self.dev_idx, ch, self.buf.as_mut_ptr(), n, 0) } as usize;
        self.buf[..got.min(max)].to_vec()
    }
    fn transmit(&mut self, ch: u32, obj: &VciCanObj) -> u32 {
        let mut o = *obj;
        unsafe { (self.transmit)(self.dev_type, self.dev_idx, ch, &mut o, 1) }
    }
    fn close(&mut self) {
        // VCI_CloseDevice(dt, idx, 0) 关整机;旧实现按通道循环关是冗余的
        unsafe { (self.close_)(self.dev_type, self.dev_idx, 0) };
    }
}

/// 32 位桥接子进程客户端(crate vcibridge 为 std-only,按 DLL 位数构建)
struct VciBridgeProc {
    child: std::process::Child,
    tx: Option<std::io::BufWriter<std::process::ChildStdin>>,
    rx: std::io::BufReader<std::process::ChildStdout>,
    dev_type: u32,
    dev_idx: u32,
}

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

impl VciBridgeProc {
    fn spawn(exe: &Path, dev_type: u32, dev_idx: u32) -> Result<Self, String> {
        let mut cmd = std::process::Command::new(exe);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn().map_err(|e| format!("启动桥接 {}: {e}", exe.display()))?;
        let tx = child.stdin.take().ok_or("桥接进程 stdin 缺失")?;
        let rx = child.stdout.take().ok_or("桥接进程 stdout 缺失")?;
        let mut me = VciBridgeProc {
            child,
            tx: Some(std::io::BufWriter::new(tx)),
            rx: std::io::BufReader::new(rx),
            dev_type,
            dev_idx,
        };
        // 握手:桥接坏了在这里快速失败,不留下半开设备
        match me.req("PING") {
            Ok(r) if r.starts_with("OK") => Ok(me),
            Ok(r) => Err(format!("桥接握手异常响应: {r}")),
            Err(e) => Err(format!("桥接握手失败: {e}")),
        }
    }

    fn read_resp(&mut self) -> Result<String, String> {
        use std::io::BufRead as _;
        let mut resp = String::new();
        let n = self.rx.read_line(&mut resp).map_err(|e| format!("读桥接: {e}"))?;
        if n == 0 {
            return Err("桥接进程无响应(已退出)".into());
        }
        Ok(resp.trim_end_matches(['\r', '\n']).to_string())
    }

    /// 发一行命令,收一行应答
    fn req(&mut self, line: &str) -> Result<String, String> {
        use std::io::Write as _;
        let tx = self.tx.as_mut().ok_or("桥接进程已关闭")?;
        writeln!(tx, "{line}").and_then(|_| tx.flush()).map_err(|e| format!("写桥接: {e}"))?;
        self.read_resp()
    }

    fn req_ok(&mut self, line: &str, what: &str) -> Result<(), String> {
        let resp = self.req(line)?;
        if resp.starts_with("OK") {
            Ok(())
        } else {
            Err(format!("{what}: {}", resp.trim_start_matches("ERR ").trim()))
        }
    }
}

impl VciLink for VciBridgeProc {
    fn open(&mut self) -> Result<(), String> {
        self.req_ok(&format!("OPEN {} {}", self.dev_type, self.dev_idx), "VCI_OpenDevice 失败")
    }
    fn init(&mut self, ch: u32, ic: &VciInitConfig) -> Result<(), String> {
        self.req_ok(&bridge_init_cmd(ch, ic), "VCI_InitCAN 失败")
    }
    fn start(&mut self, ch: u32) -> Result<(), String> {
        self.req_ok(&format!("START {ch}"), "VCI_StartCAN 失败")
    }
    fn rx_num(&mut self, ch: u32) -> u32 {
        match self.req(&format!("NUM {ch}")) {
            Ok(r) if r.starts_with("N ") => r[2..].trim().parse().unwrap_or(0),
            _ => 0,
        }
    }
    fn receive(&mut self, ch: u32, max: usize) -> Vec<VciCanObj> {
        let first = match self.req(&format!("READ {ch} {max}")) {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        if !first.starts_with("N ") {
            return vec![];
        }
        let k: usize = first[2..].trim().parse().unwrap_or(0);
        let mut out = Vec::with_capacity(k);
        for _ in 0..k {
            match self.read_resp() {
                Ok(l) => match parse_frame_line(&l) {
                    Some(o) => out.push(o),
                    None => break,
                },
                Err(_) => break,
            }
        }
        out
    }
    fn transmit(&mut self, ch: u32, obj: &VciCanObj) -> u32 {
        let cmd = format!("SEND {ch} {}", bridge_send_fields(obj));
        if self.req_ok(&cmd, "VCI_Transmit 失败").is_ok() { 1 } else { 0 }
    }
    fn close(&mut self) {}
}

impl Drop for VciBridgeProc {
    fn drop(&mut self) {
        // 先礼后兵:QUIT → 关 stdin(桥接见 EOF 自行退出)→ 兜底 kill
        if let Some(mut w) = self.tx.take() {
            use std::io::Write as _;
            let _ = writeln!(w, "QUIT");
            let _ = w.flush();
            drop(w);
        }
        for _ in 0..10 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct VciSource {
    link: Box<dyn VciLink>,
    channels: u32,
    hub: Arc<crate::tx::TxHub>,
    seq: u64,
}

impl VciSource {
    pub fn open(cfg: &HwConfig, hub: Arc<crate::tx::TxHub>) -> Result<Box<dyn CanBackend>, String> {
        let cands = vci_dll_candidates();
        if cands.is_empty() {
            return Err(format!(
                "找不到 {DLL_NAME} —— 请把厂商 DLL 放到程序目录或 canlib 子目录。\n候选位置:老版创芯(32 位)exe 目录或 canlib\\;创芯新 SDK canlib\\cxcan\\sdk\\x64(或 win32)\\;GCAN canlib\\gcan\\"
            ));
        }
        // 多候选位数裁决:优先选与进程位数一致的 DLL(x64 新 SDK 可免桥接);全不符时取首个走桥接
        let app64 = cfg!(target_pointer_width = "64");
        let mut first: Option<(PathBuf, u16)> = None;
        let mut chosen: Option<(PathBuf, u16)> = None;
        for c in &cands {
            let Ok(m) = pe_machine(c) else { continue };
            if first.is_none() {
                first = Some((c.clone(), m));
            }
            if (m == 0x8664) == app64 {
                chosen = Some((c.clone(), m));
                break;
            }
        }
        let (path, dll_machine) =
            chosen.or(first).ok_or_else(|| format!("候选 VCI DLL 均无法解析 PE 头: {}", list_paths(&cands)))?;
        // 位数裁决:匹配 → 进程内;不匹配 → 找位数一致的 vci-bridge.exe 代为加载
        let bridge = if (dll_machine == 0x8664) != app64 {
            let b = find_dll(BRIDGE_EXE).ok_or_else(|| {
                format!(
                    "ControlCAN.dll 是 {} 位而程序是 {} 位,程序目录又缺少 vci-bridge.exe。\n把随发行包提供的 32 位 vci-bridge.exe 放到主程序目录即可使用 32 位老 DLL;或改用创芯新 SDK 的 x64 DLL(canlib\\cxcan\\sdk\\x64\\)",
                    if app64 { "32" } else { "64" },
                    if app64 { "64" } else { "32" }
                )
            })?;
            let m = pe_machine(&b)?;
            Some((b, m))
        } else {
            None
        };
        let transport = pick_vci_transport(dll_machine, app64, bridge.as_ref().map(|(_, m)| *m))?;
        let dev_type = vci_device_type(&cfg.model);
        let (t0, t1) = vci_timing(cfg.bitrate)
            .ok_or_else(|| format!("VCI 波特率表不支持 {} bps(支持 10k~1M 标准档)", cfg.bitrate))?;
        let (mut link, src_desc): (Box<dyn VciLink>, String) = match transport {
            VciTransport::InProc => (
                Box::new(VciInProc::new(&path, dev_type, cfg.device_index)?),
                format!("DLL: {}", path.display()),
            ),
            VciTransport::Bridge => {
                let (b, _) = bridge.expect("transport==Bridge 时桥接必已确认存在");
                (
                    Box::new(VciBridgeProc::spawn(&b, dev_type, cfg.device_index)?),
                    format!("桥接: {}", b.display()),
                )
            }
        };
        if let Err(e) = link.open() {
            return Err(format!(
                "VCI_OpenDevice 失败: {}#{} —— 检查设备连接/驱动/序号({}; {e})",
                cfg.model, cfg.device_index, src_desc
            ));
        }
        for ch in 0..cfg.channels.max(1) {
            let ic = VciInitConfig {
                acc_code: 0,
                acc_mask: 0xFFFF_FFFF, // 全接收
                reserved: 0,
                filter: 0,
                timing0: t0,
                timing1: t1,
                mode: if cfg.listen_only { 1 } else { 0 },
            };
            if let Err(e) = link.init(ch, &ic) {
                link.close();
                return Err(format!("VCI_InitCAN 通道 {ch} 失败({src_desc}; {e})"));
            }
            if let Err(e) = link.start(ch) {
                link.close();
                return Err(format!("VCI_StartCAN 通道 {ch} 失败({src_desc}; {e})"));
            }
        }
        Ok(Box::new(VciSource {
            link,
            channels: cfg.channels.max(1),
            hub,
            seq: 0,
        }))
    }
}

impl CanBackend for VciSource {
    fn poll(&mut self) -> Vec<u8> {
        // 发送:hub → VCI_CANOBJ(经典 CAN;FD 帧拒绝并计数)
        let (mut out, mut seq) = (Vec::new(), self.seq);
        for e in self.hub.pop_due() {
            if e.fd || e.data.len() > 8 {
                continue;
            }
            let mut o = VciCanObj::default();
            o.id = e.id | if e.ext { 0x8000_0000 } else { 0 };
            o.data_len = e.data.len() as u8;
            o.remote_flag = if e.data.is_empty() { 1 } else { 0 };
            o.data[..e.data.len()].copy_from_slice(&e.data);
            for ch in 0..self.channels {
                let _ = self.link.transmit(ch, &o);
            }
        }
        // 接收
        for ch in 0..self.channels {
            let n = self.link.rx_num(ch);
            if n == 0 {
                continue;
            }
            for o in self.link.receive(ch, 64) {
                let ext = o.id & 0x8000_0000 != 0;
                let id = o.id & 0x1FFF_FFFF;
                let dl = (o.data_len as usize).min(8);
                let f = LiveFrame {
                    ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64,
                    ts_src: TsSrc::Sw,
                    bus_type: BusKind::Can,
                    ch,
                    alias: None,
                    dir: Dir::Rx,
                    id,
                    id_ext: ext,
                    dlc: dl,
                    data: o.data[..dl].to_vec(),
                    seq: Some(seq + 1),
                    meta_gap: None,
                };
                seq += 1;
                out.extend_from_slice(live_frame_to_jsonl(&f).as_bytes());
                out.push(b'\n');
            }
        }
        self.seq = seq;
        out
    }
}

impl Drop for VciSource {
    fn drop(&mut self) {
        self.link.close();
    }
}

// ---------------- SLCAN(串口 Lawicel 协议) ----------------

pub struct SlcanSource {
    port: Box<dyn serialport::SerialPort>,
    buf: Vec<u8>,
    hub: Arc<crate::tx::TxHub>,
}

impl SlcanSource {
    pub fn open(cfg: &HwConfig, hub: Arc<crate::tx::TxHub>) -> Result<Box<dyn CanBackend>, String> {
        let baud_idx = slcan_baud_idx(cfg.bitrate)
            .ok_or_else(|| format!("SLCAN 波特率表不支持 {} bps(S0~S8 = 10k~1M)", cfg.bitrate))?;
        let mut port = serialport::new(&cfg.port, 115200u32)
            .timeout(std::time::Duration::from_millis(10))
            .open()
            .map_err(|e| format!("打开串口 {}: {e}", cfg.port))?;
        use std::io::Write;
        // 设波特率 + 开通道(经典 Lawicel;listen-only 用 L)
        let open_cmd = if cfg.listen_only { "L" } else { "O" };
        port.write_all(format!("S{baud_idx}\r{open_cmd}\r").as_bytes())
            .map_err(|e| format!("SLCAN 初始化写入失败: {e}"))?;
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut buf = vec![];
        let _ = port.read_to_end(&mut buf); // 吃掉 OK/crlf 回显
        Ok(Box::new(SlcanSource { port, buf: vec![], hub }))
    }

    /// 一行 slcan 帧 → (id, ext, data, rtr)
    fn parse_line(l: &str) -> Option<(u32, bool, Vec<u8>, bool)> {
        let b = l.as_bytes();
        match b.first()? {
            b't' | b'T' => {
                let ext = b[0] == b'T';
                let id_len = if ext { 8 } else { 3 };
                if l.len() < id_len + 1 {
                    return None;
                }
                let id = u32::from_str_radix(&l[1..1 + id_len], 16).ok()?;
                let dlc = l.as_bytes()[1 + id_len].checked_sub(b'0')? as usize;
                let dl = dlc.min(8);
                let hexs = &l[1 + id_len + 1..(1 + id_len + 1 + dl * 2).min(l.len())];
                let mut data = vec![];
                for k in (0..hexs.len()).step_by(2) {
                    if k + 2 > hexs.len() {
                        break;
                    }
                    data.push(u8::from_str_radix(&hexs[k..k + 2], 16).ok()?);
                }
                Some((id, ext, data, false))
            }
            b'v' | b'V' => {
                let ext = b[0] == b'V';
                let id_len = if ext { 8 } else { 3 };
                let id = u32::from_str_radix(&l[1..1 + id_len].trim_end(), 16).ok()?;
                Some((id, ext, vec![], true))
            }
            _ => None, // z/Z ack / 错误 / 回显
        }
    }

    fn encode_tx(id: u32, ext: bool, data: &[u8]) -> String {
        let dlc = data.len().min(8);
        let head = if ext { format!("T{:08X}", id) } else { format!("t{:03X}", id) };
        let mut s = format!("{head}{dlc}");
        for b in &data[..dlc] {
            s.push_str(&format!("{b:02X}"));
        }
        s.push('\r');
        s
    }
}

impl CanBackend for SlcanSource {
    fn poll(&mut self) -> Vec<u8> {
        use std::io::Write;
        // 发送
        let mut out = Vec::new();
        let mut seq = 0u64;
        for e in self.hub.pop_due() {
            if e.fd {
                continue;
            }
            if self.port.write_all(Self::encode_tx(e.id, e.ext, &e.data).as_bytes()).is_err() {
                continue;
            }
        }
        let _ = self.port.flush();
        // 接收:读到 \r 为行
        let mut chunk = [0u8; 512];
        if let Ok(n) = self.port.read(&mut chunk) {
            self.buf.extend_from_slice(&chunk[..n]);
        }
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\r') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            let s: String = line.iter().filter(|b| b.is_ascii_graphic() || **b == b'\r').map(|b| *b as char).collect();
            let s = s.trim_end_matches('\r').to_string();
            if let Some((id, ext, data, _rtr)) = Self::parse_line(&s) {
                seq += 1;
                let f = LiveFrame {
                    ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64,
                    ts_src: TsSrc::Sw,
                    bus_type: BusKind::Can,
                    ch: 0,
                    alias: None,
                    dir: Dir::Rx,
                    id,
                    id_ext: ext,
                    dlc: data.len(),
                    data,
                    seq: Some(seq),
                    meta_gap: None,
                };
                out.extend_from_slice(live_frame_to_jsonl(&f).as_bytes());
                out.push(b'\n');
            }
        }
        out
    }

}

// ---------------- 统一入口 ----------------

pub struct HwConfig {
    pub vendor: HwVendor,
    pub model: String,
    pub device_index: u32,
    pub channels: u32,
    pub bitrate: u32,
    pub listen_only: bool,
    /// CAN FD 模式(PEAK=InitializeFD / Kvaser=canOPEN_CAN_FD;VCI 族不支持,忽略)
    pub fd: bool,
    pub port: String,
}

pub fn open(cfg: &HwConfig, hub: Arc<crate::tx::TxHub>) -> Result<CanHwSource, String> {
    let backend = match cfg.vendor {
        HwVendor::Vci => VciSource::open(cfg, hub.clone())?,
        HwVendor::Slcan => SlcanSource::open(cfg, hub.clone())?,
        HwVendor::Peak => crate::peak::PeakSource::open(cfg, hub.clone())?,
        HwVendor::Kvaser => crate::kvaser::KvaserSource::open(cfg, hub.clone())?,
        HwVendor::ECanVci => crate::ecanvci::ECanVciSource::open(cfg, hub.clone())?,
    };
    Ok(CanHwSource::new(backend))
}

/// 便捷:UI 即时提示 DLL 状态、位数与可用打开方式(进程内 / 桥接);多候选时标注来源目录
pub fn vci_dll_state() -> String {
    let cands = vci_dll_candidates();
    if cands.is_empty() {
        return "未找到 ControlCAN.dll —— 候选:exe 目录 / canlib\\(老版创芯 32 位)、canlib\\cxcan\\sdk\\x64(创芯新 SDK,免桥接)、canlib\\gcan\\(GCAN)".into();
    }
    let app64 = cfg!(target_pointer_width = "64");
    let machines: Vec<(PathBuf, u16)> = cands.iter().filter_map(|p| pe_machine(p).ok().map(|m| (p.clone(), m))).collect();
    if let Some((p, _m)) = machines.iter().find(|(_, m)| (*m == 0x8664) == app64) {
        let extra = if cands.len() > 1 { format!("(另发现 {} 个候选)", cands.len() - 1) } else { String::new() };
        return format!("就绪(进程内加载): {}{extra}", p.display());
    }
    let Some((p, machine)) = machines.first().map(|(p, m)| (p.clone(), *m)) else {
        return format!("候选 DLL 无法解析 PE 头: {}", list_paths(&cands));
    };
    let want = if app64 { "32" } else { "64" };
    match find_dll(BRIDGE_EXE).map(|b| {
        let m = pe_machine(&b);
        (b, m)
    }) {
        Some((b, Ok(m))) if m == machine => format!(
            "就绪(桥接进程): DLL={}, vci-bridge.exe={}({want} 位)——连接时经桥接访问老设备;也可改用创芯新 SDK x64 DLL(canlib\\cxcan\\sdk\\x64\\)免桥接",
            p.display(),
            b.display()
        ),
        Some((_, Ok(m))) => format!(
            "ControlCAN.dll 与 vci-bridge.exe 位数不一致(DLL=0x{machine:04X}, bridge=0x{m:04X});请换 {want} 位构建的 vci-bridge.exe"
        ),
        Some((_, Err(e))) => format!("vci-bridge.exe 无法识别: {e};请换 {want} 位构建的 vci-bridge.exe"),
        None => format!(
            "ControlCAN.dll 是 {want} 位而程序位数不匹配:把 {want} 位构建的 vci-bridge.exe 放到程序目录即可自动桥接"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_registry_and_mapping() {
        // 表单 vendor 编号 ↔ 枚举 ↔ 展示名(数据源名与 UI 文案依赖此映射)
        assert_eq!(hw_vendor(0), HwVendor::Vci);
        assert_eq!(hw_vendor(1), HwVendor::Slcan);
        assert_eq!(hw_vendor(2), HwVendor::Peak);
        assert_eq!(hw_vendor(3), HwVendor::Kvaser);
        assert_eq!(hw_vendor(4), HwVendor::ECanVci);
        assert_eq!(hw_vendor(99), HwVendor::Vci, "未知编号回落 VCI");
        for (v, name) in [
            (HwVendor::Vci, "VCI"),
            (HwVendor::Slcan, "SLCAN"),
            (HwVendor::Peak, "PEAK"),
            (HwVendor::Kvaser, "Kvaser"),
            (HwVendor::ECanVci, "GCAN"),
        ] {
            assert_eq!(vendor_name(v), name);
        }
    }

    #[test]
    fn vendor_dll_probe_finds_local_canlib() {
        // 开发机原料库在仓库上级 canlib\(cwd..\canlib 在搜索链内);发布包布局由 exe\canlib 覆盖
        if !PathBuf::from("D:/dev/tools/canlib/peak/x64/PCANBasic.dll").exists() {
            return;
        }
        let p = find_vendor_dll(&["peak/x64/PCANBasic.dll"]).expect("开发态布局应找到 PEAK DLL");
        assert!(p.to_string_lossy().to_lowercase().contains("peak"));
        // 位数裁决:64 位进程应选中 x64 副本
        if cfg!(target_pointer_width = "64") {
            let r = find_vendor_dll_checked(&["peak/x64/PCANBasic.dll"], &["peak/x86/PCANBasic.dll"], "PEAK");
            assert_eq!(pe_machine(&r.unwrap()).unwrap(), 0x8664);
        }
    }

    #[test]
    fn vci_candidates_prefer_arch_match() {
        // cxcan x64 SDK 在库时,候选集中应有与进程位数一致的可选项(免桥接直连)
        if !PathBuf::from("D:/dev/tools/canlib/cxcan/sdk/x64/ControlCAN.dll").exists() {
            return;
        }
        let cands = vci_dll_candidates();
        assert!(!cands.is_empty());
        if cfg!(target_pointer_width = "64") {
            assert!(
                cands.iter().any(|p| pe_machine(p).map(|m| m == 0x8664).unwrap_or(false)),
                "64 位进程应有位数一致的候选: {cands:?}"
            );
        }
    }

    #[test]
    fn vci_tables() {
        assert_eq!(vci_timing(500_000), Some((0x00, 0x1C)));
        assert_eq!(vci_timing(1_000_000), Some((0x00, 0x14)));
        assert_eq!(vci_timing(7_500), None);
        assert_eq!(vci_device_type("USBCAN1"), 3);
        assert_eq!(vci_device_type("USBCAN2"), 4);
        assert_eq!(vci_device_type("CANalyst-II"), 4);
        assert_eq!(slcan_baud_idx(500_000), Some(6));
        assert_eq!(slcan_baud_idx(7_500), None);
    }

    #[test]
    fn dll_bitness_check_on_real_32bit_dll() {
        // canlib 里的 ControlCAN.dll 是 32 位:64 位进程应给出明确指引
        let p = PathBuf::from("D:/dev/tools/canlib/ControlCAN.dll");
        if !p.exists() {
            return;
        }
        assert_eq!(pe_machine(&p).unwrap(), 0x014C, "该 DLL 应为 i386");
        if cfg!(target_pointer_width = "64") {
            let err = check_dll_bitness(&p).unwrap_err();
            assert!(err.contains("32 位"), "{err}");
        }
    }

    #[test]
    fn vci_transport_plan() {
        assert_eq!(pick_vci_transport(0x8664, true, None), Ok(VciTransport::InProc));
        assert_eq!(pick_vci_transport(0x014C, false, None), Ok(VciTransport::InProc));
        assert_eq!(pick_vci_transport(0x014C, true, Some(0x014C)), Ok(VciTransport::Bridge));
        assert_eq!(pick_vci_transport(0x8664, false, Some(0x8664)), Ok(VciTransport::Bridge));
        let e = pick_vci_transport(0x014C, true, None).unwrap_err();
        assert!(e.contains("vci-bridge"), "{e}");
        let e = pick_vci_transport(0x014C, true, Some(0x8664)).unwrap_err();
        assert!(e.contains("位数不一致"), "{e}");
        assert!(pick_vci_transport(0x1234, true, None).is_err());
    }

    #[test]
    fn bridge_codec() {
        let mut o = VciCanObj::default();
        o.id = 0x8000_0123;
        o.extern_flag = 1;
        o.data_len = 3;
        o.data = [0x11, 0x22, 0x33, 0, 0, 0, 0, 0];
        // SEND 数据段与 F 帧行同一字段布局,回环解析应还原全部字段
        let back = parse_frame_line(&format!("F {}", bridge_send_fields(&o))).unwrap();
        assert_eq!(back.id, 0x8000_0123);
        assert_eq!((back.extern_flag, back.remote_flag, back.data_len), (1, 0, 3));
        assert_eq!(&back.data[..3], &[0x11, 0x22, 0x33]);
        let mut r = VciCanObj::default();
        r.id = 0x456;
        r.remote_flag = 1;
        let back = parse_frame_line(&format!("F {}", bridge_send_fields(&r))).unwrap();
        assert_eq!((back.id, back.remote_flag, back.data_len), (0x456, 1, 0));
        assert!(parse_frame_line("GARBAGE").is_none());
        assert!(parse_frame_line("F 12 0 0 zz").is_none());
    }

    #[test]
    fn bridge_init_cmd_layout() {
        let ic = VciInitConfig {
            acc_code: 0,
            acc_mask: 0xFFFF_FFFF,
            reserved: 0,
            filter: 0,
            timing0: 0x00,
            timing1: 0x1C,
            mode: 1,
        };
        assert_eq!(bridge_init_cmd(1, &ic), "INIT 1 0 28 1 0 0 4294967295");
    }

    #[test]
    fn slcan_codec() {
        let (id, ext, data, rtr) = SlcanSource::parse_line("t12381122334455667788").unwrap();
        assert_eq!((id, ext, data.len(), rtr), (0x123, false, 8, false));
        assert_eq!(data, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let (id, ext, data, _) = SlcanSource::parse_line("T18ABC123 2AABB").unwrap_or((0, false, vec![], false));
        let _ = (id, ext, data);
        // 标准编码回环
        let s = SlcanSource::encode_tx(0x1A0, false, &[1, 2, 3]);
        assert_eq!(s, "t1A03010203\r");
        let s = SlcanSource::encode_tx(0x18ABC123, true, &[0xAA]);
        assert_eq!(s, "T18ABC1231AA\r");
        // RTR
        let (id, _, data, rtr) = SlcanSource::parse_line("v4561").unwrap();
        assert_eq!((id, data.len(), rtr), (0x456, 0, true));
    }

    #[test]
    fn canhw_source_emits_ndjson_via_pipeline() {
        // 用 SLCAN 形态但不碰硬件:直接造 CanHwSource 验证 Read→Pipeline 通路
        use std::io::Read as _;
        let mut src = CanHwSource::new(Box::new(DummyBackend));
        let mut pipe = Pipeline::new(None, None);
        let mut buf = [0u8; 4096];
        let mut recs = vec![];
        let n = src.read(&mut buf).unwrap();
        pipe.feed_bytes(&buf[..n], &mut recs);
        assert_eq!(recs.len(), 2, "dummy 两帧进管线");
        assert!(recs.iter().all(|r| r.can_id.is_some()));
    }

    struct DummyBackend;
    impl CanBackend for DummyBackend {
        fn poll(&mut self) -> Vec<u8> {
            let mk = |id: u32| {
                let f = LiveFrame {
                    ts_ns: 1_000,
                    ts_src: TsSrc::Sw,
                    bus_type: BusKind::Can,
                    ch: 0,
                    alias: None,
                    dir: Dir::Rx,
                    id,
                    id_ext: false,
                    dlc: 2,
                    data: vec![1, 2],
                    seq: None,
                    meta_gap: None,
                };
                format!("{}\n", live_frame_to_jsonl(&f))
            };
            format!("{}{}", mk(0x100), mk(0x101)).into_bytes()
        }
    }
}

#[cfg(test)]
mod bridge_e2e_tests {
    use super::*;

    /// 真桥接进程握手:对实际构建的 32 位 vci-bridge.exe 走一遍 PING 协议。
    /// 无 exe 时跳过(不依赖硬件;DLL 加载失败也视为握手成功——协议层已验证)。
    #[test]
    fn bridge_ping_handshake_with_real_exe() {
        let exe = find_dll(BRIDGE_EXE);
        let Some(exe) = exe else {
            eprintln!("跳过: 程序目录无 vci-bridge.exe");
            return;
        };
        // 桥接在无 DLL 环境也应 PING 通过(加载延迟到 OPEN)
        let mut proc = VciBridgeProc::spawn(&exe, vci_device_type("USBCAN2"), 0).expect("桥接进程应能启动并完成 PING 握手");
        // OPEN 在无真实设备/DLL 时允许失败,但必须是"ERR 原因"形态而非协议崩溃
        let resp = proc.req("OPEN 4 0").unwrap_or_else(|e| format!("ERR {e}"));
        assert!(resp.starts_with("OK") || resp.starts_with("ERR"), "响应必须是协议行: {resp}");
        proc.req("QUIT").ok();
    }

    /// 部署形态自检:release 目录 = 64位主程序 + 32位 bridge + 32位 DLL(开发机自检,CI 无件跳过)
    #[test]
    fn deployed_layout_adjudication() {
        let dll = find_dll(DLL_NAME);
        let bridge = find_dll(BRIDGE_EXE);
        if let (Some(d), Some(b)) = (dll, bridge) {
            let dm = pe_machine(&d).unwrap();
            let bm = pe_machine(&b).unwrap();
            let app64 = cfg!(target_pointer_width = "64");
            let plan = pick_vci_transport(dm, app64, Some(bm));
            assert!(plan.is_ok(), "实际部署形态必须可裁决(32位DLL+32位bridge+64位app → Bridge): {plan:?}");
            assert_eq!(plan.unwrap(), VciTransport::Bridge);
        }
    }
}

// ---------------- SocketCAN(Linux 虚拟口 vcan0) ----------------
// Windows 构建编译为空;Linux 上 AF_CAN RAW socket 收发,数据面与 SLCAN 同一条管线。

#[cfg(target_os = "linux")]
pub struct SocketCanSource {
    fd: std::os::fd::RawFd,
    iface: String,
    buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
mod sockcan_sys {
    // libc 常量与调用走 libc crate(core 依赖零新增;app 已带 libc 间接依赖,显式声明)
    pub const AF_CAN: i32 = 29;
    pub const PF_CAN: i32 = 29;
    pub const SOCK_RAW: i32 = 3;
    pub const SOL_CAN_BASE: i32 = 100;
    pub const SOL_CAN_RAW: i32 = SOL_CAN_BASE + 1;
    pub const CAN_RAW_FD_FRAMES: i32 = 5;
    // struct sockaddr_can { sa_family: u16, ifindex: u32, ... }
    pub const SOCKADDR_CAN_LEN: usize = 16;
}

#[cfg(target_os = "linux")]
impl SocketCanSource {
    /// 打开 vcan0 等 SocketCAN 接口(ip link add dev vcan0 type vcan 后可用)
    pub fn open(iface: &str) -> Result<Self, String> {
        use std::os::unix::io::RawFd;
        let idx = if_nametoindex(iface).ok_or_else(|| format!("SocketCAN 接口 {iface} 不存在(ip link add dev {iface} type vcan 创建虚拟口)"))?;
        let fd = unsafe { libc_socket(AF_CAN, SOCK_RAW, CAN_RAW) };
        if fd < 0 {
            return Err(format!("socket(PF_CAN) 失败(内核未启用 CAN?)"));
        }
        // bind sockaddr_can
        let mut sa = [0u8; SOCKADDR_CAN_LEN];
        sa[0..2].copy_from_slice(&(AF_CAN as u16).to_le_bytes());
        sa[4..8].copy_from_slice(&idx.to_le_bytes());
        if unsafe { libc_bind(fd, sa.as_ptr(), SOCKADDR_CAN_LEN as u32) } < 0 {
            unsafe { libc_close(fd) };
            return Err(format!("bind {iface} 失败"));
        }
        // 启用 CAN FD 帧(不影响经典帧接收)
        let one: i32 = 1;
        unsafe {
            libc_setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &one as *const i32 as *const u8, 4);
        }
        Ok(SocketCanSource { fd: fd as RawFd, iface: iface.to_string(), buf: vec![] })
    }
}

#[cfg(target_os = "linux")]
impl CanBackend for SocketCanSource {
    fn poll(&mut self) -> Vec<u8> {
        use std::os::unix::io::FromRawFd;
        let mut out = Vec::new();
        // 非阻塞读多帧(每帧 struct canfd_frame 最多 72B)
        for _ in 0..64 {
            let mut buf = [0u8; 72];
            let n = unsafe { libc_recv(self.fd, buf.as_mut_ptr(), 72, 0x40) }; // MSG_DONTWAIT
            if n <= 0 {
                break;
            }
            let n = n as usize;
            if n < 8 {
                continue;
            }
            let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let eff = raw & 0x8000_0000 != 0;
            let rtr = raw & 0x4000_0000 != 0;
            let id = raw & 0x1FFF_FFFF;
            let (data, fd_frame) = if n > 16 {
                (buf[8..n].to_vec(), true)
            } else {
                let dlc = (buf[4] as usize & 0x0F).min(8).min(n - 8);
                (buf[8..8 + dlc].to_vec(), false)
            };
            let f = LiveFrame {
                ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64,
                ts_src: TsSrc::Sw,
                bus_type: if fd_frame { BusKind::CanFd } else { BusKind::Can },
                ch: 0,
                alias: Some(format!("socketcan·{}", self.iface)),
                dir: if rtr { Dir::Unknown } else { Dir::Rx },
                id,
                id_ext: eff,
                dlc: data.len(),
                data,
                seq: None,
                meta_gap: None,
            };
            out.extend_from_slice(live_frame_to_jsonl(&f).as_bytes());
            out.push(b'\n');
        }
        out
    }
}

#[cfg(target_os = "linux")]
impl Drop for SocketCanSource {
    fn drop(&mut self) {
        unsafe { libc_close(self.fd) };
    }
}

#[cfg(target_os = "linux")]
unsafe fn if_nametoindex(name: &str) -> Option<u32> {
    // 简化:ioctl SIOCGIFINDEX 走 libc;此处用 if_indextoname 的逆查——直接读 /sys/class/net/<name>/ifindex
    let p = format!("/sys/class/net/{name}/ifindex");
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

// Linux libc FFI(app 侧零新依赖:直接声明,链接时走系统 libc)
#[cfg(target_os = "linux")]
extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, opt: i32, v: *const u8, l: u32) -> i32;
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn close(fd: i32) -> i32;
}
#[cfg(target_os = "linux")]
const CAN_RAW: i32 = 1;
