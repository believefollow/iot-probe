//! Kvaser CANlib 适配层(ADR-0014,第二批厂商适配)。
//! 设计(与 zlg.rs 同构):
//! - **动态加载** canlib32.dll(名字带 32 是历史沿革;装好 Kvaser Drivers for Windows 后随系统加载,
//!   SDK 包内副本见 canlib\kvaser\sdk\——注意该副本为 32 位,64 位进程需装驱动取系统 64 位版)。
//! - 入口:canInitializeLibrary / canGetNumberOfChannels / canOpenChannel / canSetBusParams(Fd) /
//!   canSetBusOutputControl / canBusOn / canRead / canWrite / canIoctl / canClose。
//! - 输出统一为 frame.schema.json 契约 NDJSON(实现 CanBackend);读取失败写 stderr 不伪造报文。
//! - 时间戳:头文件注明默认 1ms/格,open 后经 canIoctl(SET_TIMER_SCALE) 显式设为 10µs,ts_src=hw(ADR-5 L1)。
//! - 通道:canOpenChannel 带 ACCEPT_VIRTUAL,无硬件可用 Kvaser Virtual CAN Bus 演示整条链路;
//!   FD 经 canOPEN_CAN_FD + canSetBusParamsFd(数据段默认 2M@80%)。
//! - 只听 = canSetBusOutputControl(canDRIVER_SILENT):连 ACK 都不发,需要 init access,且对端需另有两节点应答。
//!
//! FFI 事实出自随包 canlib.h(5.53;CANLIBAPI=__stdcall;x64 上 "system" ABI)与官方 canstat.h 常量
//! (canMSG_*/canERR_* 不在 canlib.h 中,数值经官方文档与 python-can 常量镜像核对)。

use crate::canhw::{find_vendor_dll, pe_machine, CanBackend, HwConfig};
use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::{BusKind, LiveFrame};
use iotprobe_core::model::{Dir, TsSrc};
use libloading::Library;
use std::path::PathBuf;
use std::sync::Arc;

// ================= canlib.h / canstat.h 常量 =================

type CanHandle = i32;
type CanStatus = i32;

const CAN_OK: CanStatus = 0;
const CAN_ERR_NOMSG: CanStatus = -2; // canstat.h:读队列为空(正常轮询终态)

/// 波特率 → canBITRATE_* 负值哨兵(库按频率填默认位时序)
pub fn kvaser_bitrate(bitrate: u32) -> Option<i32> {
    match bitrate {
        1_000_000 => Some(-1), // canBITRATE_1M
        500_000 => Some(-2),   // canBITRATE_500K
        250_000 => Some(-3),
        125_000 => Some(-4),
        100_000 => Some(-5),
        50_000 => Some(-7),
        10_000 => Some(-9),
        _ => None,
    }
}

/// FD 数据段波特率 → canFD_BITRATE_* 哨兵(80% 采样点)
pub fn kvaser_fd_data_bitrate(bitrate: u32) -> i32 {
    match bitrate {
        500_000 => -1000, // canFD_BITRATE_500K_80P
        1_000_000 => -1001,
        2_000_000 => -1002,
        4_000_000 => -1003,
        _ => -1002, // 缺省 2M@80%
    }
}

const CAN_OPEN_ACCEPT_VIRTUAL: i32 = 0x0020; // 允许虚拟通道(无硬件演示)
const CAN_OPEN_CAN_FD: i32 = 0x0400; // ISO CAN FD

const CAN_MSG_RTR: u32 = 0x0001;
const CAN_MSG_STD: u32 = 0x0002;
const CAN_MSG_EXT: u32 = 0x0004;
const CAN_FDMSG_FDF: u32 = 0x0100_00;
const CAN_FDMSG_BRS: u32 = 0x0200_00;

const CAN_DRIVER_SILENT: u32 = 1; // canSetBusOutputControl:只听(不发 ACK)
const CAN_IOCTL_SET_TIMER_SCALE: i32 = 6; // buf = DWORD µs/格

const DLL_NAME: &str = "canlib32.dll";

// ================= FFI 入口 =================

type InitLibFn = unsafe extern "system" fn() -> CanStatus;
type NumChFn = unsafe extern "system" fn(*mut i32) -> CanStatus;
type OpenChFn = unsafe extern "system" fn(i32, i32) -> CanHandle;
type CloseFn = unsafe extern "system" fn(CanHandle) -> CanStatus;
type BusOnFn = unsafe extern "system" fn(CanHandle) -> CanStatus;
type SetBusParamsFn = unsafe extern "system" fn(CanHandle, i32, u32, u32, u32, u32, u32) -> CanStatus;
type SetBusParamsFdFn = unsafe extern "system" fn(CanHandle, i32, u32, u32, u32, u32) -> CanStatus;
type SetOutputCtrlFn = unsafe extern "system" fn(CanHandle, u32) -> CanStatus;
type ReadFn = unsafe extern "system" fn(CanHandle, *mut i32, *mut u8, *mut u32, *mut u32, *mut u64) -> CanStatus;
type WriteFn = unsafe extern "system" fn(CanHandle, i32, *mut u8, u32, u32) -> CanStatus;
type IoctlFn = unsafe extern "system" fn(CanHandle, i32, *mut core::ffi::c_void, u32) -> CanStatus;

// ================= 适配器 =================

pub struct KvaserSource {
    _lib: Library,
    close: CloseFn,
    read: ReadFn,
    write: WriteFn,
    hnd: CanHandle,
    fd: bool,
    hub: Arc<crate::tx::TxHub>,
    rid: Box<i32>,
    rdata: Box<[u8; 64]>,
    rdlc: Box<u32>,
    rflag: Box<u32>,
    rtime: Box<u64>,
    seq: u64,
    closed: bool,
}

/// 驱动安装后的系统副本(64 位在 System32,32 位在 SysWOW64)
fn system_dll() -> Option<PathBuf> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let sub = if cfg!(target_pointer_width = "64") { "System32" } else { "SysWOW64" };
    let p = PathBuf::from(root).join(sub).join(DLL_NAME);
    p.exists().then_some(p)
}

/// 定位 canlib32.dll:优先本地 SDK 解包副本(kvaser/x64|sdk,按位数核对),其次驱动安装的系统副本。
/// 注意:旧 sdk/ 副本为 32 位;5.53 解包出的 kvaser\x64\canlib32.dll 为 64 位(PE 已核),64 位进程免装驱动即可加载
/// (真机/Virtual CAN 仍需装驱动)。
fn resolve_dll() -> Result<(Option<PathBuf>, String), String> {
    let want: u16 = if cfg!(target_pointer_width = "64") { 0x8664 } else { 0x014C };
    let (primary, secondary): (&[&str], &[&str]) = if cfg!(target_pointer_width = "64") {
        (&["kvaser/x64/canlib32.dll", "kvaser/sdk/canlib32.dll"], &["kvaser/x86/canlib32.dll"])
    } else {
        (&["kvaser/x86/canlib32.dll", "kvaser/sdk/canlib32.dll"], &["kvaser/x64/canlib32.dll"])
    };
    let mut mismatch: Option<PathBuf> = None;
    if let Some(p) = find_vendor_dll(primary) {
        if let Ok(m) = pe_machine(p.as_path()) {
            if m == want {
                return Ok((Some(p.clone()), format!("本地副本: {}", p.display())));
            }
            mismatch = Some(p);
        }
    }
    if let Some(p) = system_dll() {
        let desc = format!("驱动安装副本: {}", p.display());
        return Ok((Some(p), desc));
    }
    let _ = secondary;
    // 系统副本也可能不在 System32(自定义安装),让 Windows 搜索链兜底;本地只有位数不符副本时在描述里如实标注
    let desc = match &mismatch {
        Some(p) => format!("系统搜索链(随 Kvaser 驱动安装);注意本地仅有位数不符的副本: {}", p.display()),
        None => "系统搜索链(随 Kvaser 驱动安装)".into(),
    };
    Ok((None, desc))
}

/// UI 即时提示:canlib32.dll 状态
pub fn dll_state() -> String {
    match resolve_dll() {
        Ok((Some(p), desc)) => format!("就绪({desc}): {}", p.display()),
        Ok((None, desc)) => format!("就绪({desc})"),
        Err(e) => e,
    }
}

impl KvaserSource {
    /// 打开通道并上线。DLL 缺失/通道不存在时返回带指引的错误。
    pub fn open(cfg: &HwConfig, hub: Arc<crate::tx::TxHub>) -> Result<Box<dyn CanBackend>, String> {
        let (dll, dll_desc) = resolve_dll()?;
        let lib = unsafe {
            match &dll {
                Some(p) => Library::new(p).map_err(|e| format!("加载 {}: {e}", p.display()))?,
                None => Library::new(DLL_NAME).map_err(|e| {
                    format!(
                        "按名称加载 canlib32.dll 失败: {e}\n请安装 Kvaser Drivers for Windows(SDK 包内副本为 32 位,64 位程序需系统驱动)"
                    )
                })?,
            }
        };
        let init_lib: InitLibFn = unsafe { *lib.get(b"canInitializeLibrary").map_err(|e| e.to_string())? };
        let num_ch: NumChFn = unsafe { *lib.get(b"canGetNumberOfChannels").map_err(|e| e.to_string())? };
        let open_ch: OpenChFn = unsafe { *lib.get(b"canOpenChannel").map_err(|e| e.to_string())? };
        let close: CloseFn = unsafe { *lib.get(b"canClose").map_err(|e| e.to_string())? };
        let bus_on: BusOnFn = unsafe { *lib.get(b"canBusOn").map_err(|e| e.to_string())? };
        let set_params: SetBusParamsFn = unsafe { *lib.get(b"canSetBusParams").map_err(|e| e.to_string())? };
        let set_params_fd: SetBusParamsFdFn = unsafe { *lib.get(b"canSetBusParamsFd").map_err(|e| e.to_string())? };
        let set_out: SetOutputCtrlFn = unsafe { *lib.get(b"canSetBusOutputControl").map_err(|e| e.to_string())? };
        let read: ReadFn = unsafe { *lib.get(b"canRead").map_err(|e| e.to_string())? };
        let write: WriteFn = unsafe { *lib.get(b"canWrite").map_err(|e| e.to_string())? };
        let ioctl: IoctlFn = unsafe { *lib.get(b"canIoctl").map_err(|e| e.to_string())? };

        let _ = unsafe { init_lib() };
        let mut n_ch: i32 = 0;
        let st = unsafe { num_ch(&mut n_ch) };
        if st != CAN_OK {
            return Err(format!("canGetNumberOfChannels 失败({st}):驱动是否已装好?({dll_desc})"));
        }
        let ch = cfg.device_index as i32;
        if ch < 0 || ch >= n_ch {
            return Err(format!(
                "通道 {ch} 不存在:本机 CANlib 共 {n_ch} 个通道(含虚拟)。通道号从 0 起;无硬件时可用 Kvaser Virtual CAN"
            ));
        }
        let flags = if cfg.fd { CAN_OPEN_ACCEPT_VIRTUAL | CAN_OPEN_CAN_FD } else { CAN_OPEN_ACCEPT_VIRTUAL };
        let hnd = unsafe { open_ch(ch, flags) };
        if hnd < 0 {
            return Err(format!(
                "canOpenChannel({ch}) 失败({hnd})——通道被占用(独占)?设备未上电?装驱动后可在 Kvaser Device Guide 查看通道号"
            ));
        }
        // 波特率:负值哨兵由库填默认位时序;任一步失败即回滚关闭,不留半开通道
        let br = kvaser_bitrate(cfg.bitrate)
            .ok_or_else(|| format!("CANlib 波特率表不支持 {} bps(支持 10k~1M 标准档)", cfg.bitrate))?;
        if cfg.fd {
            let st = unsafe { set_params_fd(hnd, kvaser_fd_data_bitrate(2_000_000), 0, 0, 0, 0) };
            if st != CAN_OK {
                unsafe { close(hnd) };
                return Err(format!("canSetBusParamsFd 失败({st}):通道是否支持 CAN FD?"));
            }
        }
        let st = unsafe { set_params(hnd, br, 0, 0, 0, 0, 0) };
        if st != CAN_OK {
            unsafe { close(hnd) };
            return Err(format!("canSetBusParams {} bps 失败({st})", cfg.bitrate));
        }
        if cfg.listen_only {
            let st = unsafe { set_out(hnd, CAN_DRIVER_SILENT) };
            if st != CAN_OK {
                unsafe { close(hnd) };
                return Err(format!("canSetBusOutputControl(SILENT) 失败({st}):只听模式需要 init access"));
            }
        }
        // 时戳显式定标 10µs/格(默认 1ms 粒度对抖动分析太粗);失败不致命,精度降级为 1ms
        let scale: u32 = 10;
        let st = unsafe { ioctl(hnd, CAN_IOCTL_SET_TIMER_SCALE, &scale as *const u32 as *mut core::ffi::c_void, 4) };
        if st != CAN_OK {
            eprintln!("[kvaser] 设置 10µs 时戳粒度失败({st}),退化为默认 1ms");
        }
        if unsafe { bus_on(hnd) } != CAN_OK {
            unsafe { close(hnd) };
            return Err(format!("canBusOn 通道 {ch} 失败:总线参数被拒(波特率不在该卡支持集?)"));
        }
        Ok(Box::new(KvaserSource {
            _lib: lib,
            close,
            read,
            write,
            hnd,
            fd: cfg.fd,
            hub,
            rid: Box::new(0),
            rdata: Box::new([0; 64]),
            rdlc: Box::new(0),
            rflag: Box::new(0),
            rtime: Box::new(0),
            seq: 0,
            closed: false,
        }))
    }

    /// canMSG_* 位掩码 → (id_ext, rtr)
    fn parse_flags(flags: u32) -> (bool, bool) {
        (flags & CAN_MSG_EXT != 0, flags & CAN_MSG_RTR != 0)
    }
}

impl CanBackend for KvaserSource {
    fn poll(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut errs: Vec<String> = Vec::new();
        // 发送面板队列排空(FR-4.7):FD 帧走同一 canWrite(通道以 canOPEN_CAN_FD 打开)
        for e in self.hub.pop_due() {
            if e.data.len() > 64 || (e.fd && !self.fd) {
                errs.push(if e.fd && !self.fd { "Kvaser 非 FD 通道拒绝 FD 帧".into() } else { "帧长超 64".into() });
                continue;
            }
            let mut flag = if e.ext { CAN_MSG_EXT } else { CAN_MSG_STD };
            if e.data.is_empty() && !e.fd {
                flag |= CAN_MSG_RTR;
            }
            if e.fd {
                flag |= CAN_FDMSG_FDF;
                if e.brs {
                    flag |= CAN_FDMSG_BRS;
                }
            }
            let dlc = e.data.len() as u32;
            let data_ptr = e.data.as_ptr() as *mut u8;
            let st = unsafe { (self.write)(self.hnd, e.id as i32, data_ptr, dlc, flag) };
            if st != CAN_OK {
                errs.push(format!("canWrite: {st}"));
            }
        }
        // 接收:轮询至 NOMSG(单批上限 64)
        let mut seq = self.seq;
        let mut n = 0u32;
        while n < 64 {
            let st = unsafe {
                (self.read)(
                    self.hnd,
                    self.rid.as_mut() as *mut i32,
                    self.rdata.as_mut_ptr().cast::<u8>(),
                    self.rdlc.as_mut() as *mut u32,
                    self.rflag.as_mut() as *mut u32,
                    self.rtime.as_mut() as *mut u64,
                )
            };
            if st == CAN_ERR_NOMSG {
                break;
            }
            if st != CAN_OK {
                errs.push(format!("canRead: {st}"));
                break;
            }
            let (ext, rtr) = Self::parse_flags(*self.rflag);
            let dlc = (*self.rdlc as usize).min(64);
            let data = if rtr { vec![] } else { self.rdata[..dlc].to_vec() };
            let fd = *self.rflag & CAN_FDMSG_FDF != 0;
            let f = LiveFrame {
                ts_ns: self.rtime.saturating_mul(10_000), // 10µs/格(SET_TIMER_SCALE 已设)
                ts_src: TsSrc::Hw,
                bus_type: if fd { BusKind::CanFd } else { BusKind::Can },
                ch: 0,
                alias: None,
                dir: Dir::Rx,
                id: (*self.rid).max(0) as u32,
                id_ext: ext,
                dlc: data.len(),
                data,
                seq: Some(seq + 1),
                meta_gap: None,
            };
            seq += 1;
            out.extend_from_slice(live_frame_to_jsonl(&f).as_bytes());
            out.push(b'\n');
            n += 1;
        }
        for e in &errs {
            eprintln!("[kvaser] {e}");
        }
        self.seq = seq;
        out
    }
}

impl Drop for KvaserSource {
    fn drop(&mut self) {
        if !self.closed {
            unsafe { (self.close)(self.hnd) };
            self.closed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitrate_sentinels_match_header() {
        // canlib.h:canBITRATE_1M(-1) .. canBITRATE_10K(-9)
        assert_eq!(kvaser_bitrate(1_000_000), Some(-1));
        assert_eq!(kvaser_bitrate(500_000), Some(-2));
        assert_eq!(kvaser_bitrate(125_000), Some(-4));
        assert_eq!(kvaser_bitrate(10_000), Some(-9));
        assert_eq!(kvaser_bitrate(7_500), None);
    }

    #[test]
    fn fd_data_bitrate_sentinels() {
        // canlib.h:canFD_BITRATE_500K_80P(-1000) .. 8M_80P(-1005)
        assert_eq!(kvaser_fd_data_bitrate(500_000), -1000);
        assert_eq!(kvaser_fd_data_bitrate(1_000_000), -1001);
        assert_eq!(kvaser_fd_data_bitrate(2_000_000), -1002);
        assert_eq!(kvaser_fd_data_bitrate(999_999), -1002, "缺省 2M@80%");
    }

    #[test]
    fn msg_flag_semantics() {
        // canstat.h:canMSG_RTR=0x1, canMSG_STD=0x2, canMSG_EXT=0x4;FD 位在 16 位以上
        assert_eq!(CAN_MSG_RTR, 0x1);
        assert_eq!(CAN_MSG_STD, 0x2);
        assert_eq!(CAN_MSG_EXT, 0x4);
        assert_eq!(CAN_FDMSG_FDF, 0x0100_00);
        assert!(KvaserSource::parse_flags(CAN_MSG_EXT).0);
        assert!(KvaserSource::parse_flags(CAN_MSG_RTR).1);
        assert!(!KvaserSource::parse_flags(CAN_MSG_STD).0);
    }

    #[test]
    fn open_flag_values() {
        assert_eq!(CAN_OPEN_ACCEPT_VIRTUAL, 0x20);
        assert_eq!(CAN_OPEN_CAN_FD, 0x400);
    }
}
