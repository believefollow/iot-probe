//! PEAK PCAN-Basic 适配层(ADR-0014,第二批厂商适配)。
//! 设计(与 zlg.rs 同构):
//! - **动态加载** PCANBasic.dll(canlib\peak\<x64|x86>\ 随 SDK 分发,或驱动安装后随系统),无链接期依赖。
//! - 只调用长期稳定入口:CAN_Initialize(FD) / CAN_Read(FD) / CAN_Write(FD) / CAN_SetValue /
//!   CAN_GetErrorText / CAN_Uninitialize。
//! - 输出统一为 frame.schema.json 契约 NDJSON(实现 CanBackend),录制/回放/解析/曲线/事件全复用;
//!   读取/发送失败写 stderr,不伪造报文污染数据流。
//! - 时间戳:经典帧 TPCANTimestamp(millis/overflow/micros,官方换算式)→ ts_src = hw(ADR-5 L1);
//!   FD 帧为 u64 微秒 ×1000。真机核对属 bench 任务。
//! - 通道:PCAN_USBBUS1..16(0x51 起);只听 = PCAN_LISTEN_ONLY 参数(发送被硬件抑制,FR-10.4)。
//!
//! FFI 事实均出自随包 PCANBasic.h(2025-10-24 版;x64 导出无装饰名;__stdcall == x64 下 "system" ABI)。

use crate::canhw::{find_vendor_dll_checked, CanBackend, HwConfig};
use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::{BusKind, LiveFrame};
use iotprobe_core::model::{Dir, TsSrc};
use libloading::Library;
use std::sync::Arc;

// ================= PCANBasic.h 常量与结构体(布局以官方头文件为准) =================

type TPCANHandle = u16;
type TPCANStatus = u32;
type TPCANBaudrate = u16;

/// USB 通道 1..16(高半字节 5=USB 类型;1..8 = 0x51..0x58,9..16 = 0x509..)
pub fn pcan_usb_bus(n: u32) -> TPCANHandle {
    if n <= 8 {
        0x50 + n as u16
    } else {
        0x500 + n as u16
    }
}

/// 波特率 → BTR0BTR1 码(PCAN_BAUD_* 常量,出自官方头文件)
pub fn pcan_baud(bitrate: u32) -> Option<TPCANBaudrate> {
    match bitrate {
        1_000_000 => Some(0x0014),
        800_000 => Some(0x0016),
        500_000 => Some(0x001C),
        250_000 => Some(0x011C),
        125_000 => Some(0x031C),
        100_000 => Some(0x432F),
        50_000 => Some(0x472F),
        20_000 => Some(0x532F),
        10_000 => Some(0x672F),
        _ => None,
    }
}

const PCAN_ERROR_OK: TPCANStatus = 0x0000_0000;
const PCAN_ERROR_QRCVEMPTY: TPCANStatus = 0x0000_0020;
const PCAN_ERROR_BUSLIGHT: TPCANStatus = 0x0000_0004;
const PCAN_ERROR_BUSHEAVY: TPCANStatus = 0x0000_0008;
const PCAN_ERROR_BUSPASSIVE: TPCANStatus = 0x0004_0000;
const PCAN_ERROR_BUSOFF: TPCANStatus = 0x0000_0010;

const PCAN_MESSAGE_STANDARD: u8 = 0x00;
const PCAN_MESSAGE_RTR: u8 = 0x01;
const PCAN_MESSAGE_EXTENDED: u8 = 0x02;
const PCAN_MESSAGE_FD: u8 = 0x04;
const PCAN_MESSAGE_BRS: u8 = 0x08;

const PCAN_PARAMETER_ON: u8 = 0x01;
const PCAN_LISTEN_ONLY: u8 = 0x08;

/// 经典帧:16 字节(id@0,msgtype@4,len@5,data@6..14)
#[repr(C)]
#[derive(Clone, Copy)]
struct TPCANMsg {
    id: u32,
    msgtype: u8,
    len: u8,
    data: [u8; 8],
}
/// 经典时戳:8 字节;总微秒 = micros + 1000*millis + 2^32*1000*millis_overflow(官方公式)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TPCANTimestamp {
    millis: u32,
    millis_overflow: u16,
    micros: u16,
}
/// FD 帧:72 字节(dlc 0..15,data 至多 64)
#[repr(C)]
#[derive(Clone, Copy)]
struct TPCANMsgFD {
    id: u32,
    msgtype: u8,
    dlc: u8,
    data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<TPCANMsg>() == 16);
const _: () = assert!(std::mem::size_of::<TPCANTimestamp>() == 8);
const _: () = assert!(std::mem::size_of::<TPCANMsgFD>() == 72);
const _: () = assert!(std::mem::offset_of!(TPCANMsg, data) == 6);
const _: () = assert!(std::mem::offset_of!(TPCANMsgFD, data) == 6);

// ================= FFI 入口 =================

type InitializeFn = unsafe extern "system" fn(TPCANHandle, TPCANBaudrate, u8, u32, u16) -> TPCANStatus;
type InitializeFdFn = unsafe extern "system" fn(TPCANHandle, *const i8) -> TPCANStatus;
type UninitializeFn = unsafe extern "system" fn(TPCANHandle) -> TPCANStatus;
type ReadFn = unsafe extern "system" fn(TPCANHandle, *mut TPCANMsg, *mut TPCANTimestamp) -> TPCANStatus;
type ReadFdFn = unsafe extern "system" fn(TPCANHandle, *mut TPCANMsgFD, *mut u64) -> TPCANStatus;
type WriteFn = unsafe extern "system" fn(TPCANHandle, *mut TPCANMsg) -> TPCANStatus;
type WriteFdFn = unsafe extern "system" fn(TPCANHandle, *mut TPCANMsgFD) -> TPCANStatus;
type SetValueFn = unsafe extern "system" fn(TPCANHandle, u8, *mut core::ffi::c_void, u32) -> TPCANStatus;
type ErrorTextFn = unsafe extern "system" fn(TPCANStatus, u16, *mut i8) -> TPCANStatus;

const DLL_NAME: &str = "PCANBasic.dll";

// ================= 适配器 =================

pub struct PeakSource {
    _lib: Library,
    uninit: UninitializeFn,
    read: ReadFn,
    read_fd: ReadFdFn,
    write: WriteFn,
    write_fd: WriteFdFn,
    handle: TPCANHandle,
    fd: bool,
    hub: Arc<crate::tx::TxHub>,
    msg: Box<TPCANMsg>,
    ts: Box<TPCANTimestamp>,
    msg_fd: Box<TPCANMsgFD>,
    ts_fd: Box<u64>,
    seq: u64,
    closed: bool,
}

/// CAN_GetErrorText 包装:状态码 → 英文描述,进错误信息便于排障
fn error_text(f: &ErrorTextFn, st: TPCANStatus) -> String {
    let mut buf = [0u8; 256];
    let r = unsafe { f(st, 0, buf.as_mut_ptr() as *mut i8) };
    if r == PCAN_ERROR_OK {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).trim().to_string()
    } else {
        format!("状态码 0x{st:08X}")
    }
}

/// PEAK FD bitrate 参数段(80% 采样点,8MHz 时基;数据段 2M)。仲裁段按经典波特率给常用档。
fn fd_params(bitrate: u32) -> (&'static str, &'static str) {
    let nom = match bitrate {
        1_000_000 => "nom_brp=4,nom_tseg1=15,nom_tseg2=4,nom_sjw=1",
        500_000 => "nom_brp=8,nom_tseg1=15,nom_tseg2=4,nom_sjw=1",
        250_000 => "nom_brp=16,nom_tseg1=15,nom_tseg2=4,nom_sjw=1",
        _ => "nom_brp=8,nom_tseg1=15,nom_tseg2=4,nom_sjw=1", // 缺省 500k
    };
    (nom, "data_brp=2,data_tseg1=15,data_tseg2=5,data_sjw=1")
}

/// 经典帧时戳 → ns(官方公式:micros + 1000*millis + 2^32*1000*millis_overflow)
fn timestamp_ns(t: &TPCANTimestamp) -> u64 {
    let millis = t.millis as u64 + ((t.millis_overflow as u64) << 32);
    t.micros as u64 + millis.saturating_mul(1_000)
}

impl PeakSource {
    /// 加载 DLL 并初始化通道。DLL 缺失/无设备时返回带指引的错误。
    pub fn open(cfg: &HwConfig, hub: Arc<crate::tx::TxHub>) -> Result<Box<dyn CanBackend>, String> {
        // DLL:SDK 目录按位数选,其次驱动安装后的系统副本(裸名走系统搜索链)
        let path = find_vendor_dll_checked(
            &["peak/x64/PCANBasic.dll", DLL_NAME],
            &["peak/x86/PCANBasic.dll", DLL_NAME],
            "PEAK PCAN-Basic",
        )?;
        let lib = unsafe { Library::new(&path) }.map_err(|e| format!("加载 {}: {e}", path.display()))?;
        let init: InitializeFn = unsafe { *lib.get(b"CAN_Initialize").map_err(|e| e.to_string())? };
        let init_fd: InitializeFdFn = unsafe { *lib.get(b"CAN_InitializeFD").map_err(|e| e.to_string())? };
        let uninit: UninitializeFn = unsafe { *lib.get(b"CAN_Uninitialize").map_err(|e| e.to_string())? };
        let read: ReadFn = unsafe { *lib.get(b"CAN_Read").map_err(|e| e.to_string())? };
        let read_fd: ReadFdFn = unsafe { *lib.get(b"CAN_ReadFD").map_err(|e| e.to_string())? };
        let write: WriteFn = unsafe { *lib.get(b"CAN_Write").map_err(|e| e.to_string())? };
        let write_fd: WriteFdFn = unsafe { *lib.get(b"CAN_WriteFD").map_err(|e| e.to_string())? };
        let set_value: SetValueFn = unsafe { *lib.get(b"CAN_SetValue").map_err(|e| e.to_string())? };
        let err_text: ErrorTextFn = unsafe { *lib.get(b"CAN_GetErrorText").map_err(|e| e.to_string())? };

        let n = cfg.device_index.max(1);
        let ch = pcan_usb_bus(n);
        if cfg.fd {
            // FD:官方 bitrate 字符串口径;数据段默认 2M@80%(bench 待核对)
            let (nom, dat) = fd_params(cfg.bitrate);
            let cs = std::ffi::CString::new(format!("f_clock=80000000,{nom},{dat}"))
                .map_err(|_| "FD bitrate 字符串含 \\0".to_string())?;
            let st = unsafe { init_fd(ch, cs.as_ptr() as *const i8) };
            if st != PCAN_ERROR_OK {
                return Err(format!(
                    "CAN_InitializeFD 通道 USB{n} 失败: {}({})——检查设备是否 FD 型号/连接/驱动",
                    error_text(&err_text, st),
                    path.display()
                ));
            }
        } else {
            let btr = pcan_baud(cfg.bitrate)
                .ok_or_else(|| format!("PCAN 波特率表不支持 {} bps(支持 10k~1M 标准档)", cfg.bitrate))?;
            // 后三参为官方已废弃占位(HwType/IOPort/Interrupt),USB 通道一律传 0
            let st = unsafe { init(ch, btr, 0, 0, 0) };
            if st != PCAN_ERROR_OK {
                return Err(format!(
                    "CAN_Initialize 通道 USB{n} 失败: {}({})——检查设备连接/驱动/通道号;BUSLIGHT/BUSHEAVY=总线忙",
                    error_text(&err_text, st),
                    path.display()
                ));
            }
        }
        if cfg.listen_only {
            let v: u8 = PCAN_PARAMETER_ON;
            let st = unsafe { set_value(ch, PCAN_LISTEN_ONLY, &v as *const u8 as *mut core::ffi::c_void, 1) };
            if st != PCAN_ERROR_OK {
                return Err(format!("设置只听模式失败: {}(通道未受影响,可断开重试)", error_text(&err_text, st)));
            }
        }
        Ok(Box::new(PeakSource {
            _lib: lib,
            uninit,
            read,
            read_fd,
            write,
            write_fd,
            handle: ch,
            fd: cfg.fd,
            hub,
            msg: Box::new(TPCANMsg { id: 0, msgtype: 0, len: 0, data: [0; 8] }),
            ts: Box::new(TPCANTimestamp::default()),
            msg_fd: Box::new(TPCANMsgFD { id: 0, msgtype: 0, dlc: 0, data: [0; 64] }),
            ts_fd: Box::new(0),
            seq: 0,
            closed: false,
        }))
    }

    /// 发送面板队列排空(FR-4.7):hub 由 UI 显式解锁后写入;FD 帧走 WriteFD
    fn drain_tx(&mut self, errs: &mut Vec<String>) {
        for e in self.hub.pop_due() {
            if self.fd {
                let dl = e.data.len().min(64);
                let mut m = TPCANMsgFD { id: e.id, msgtype: PCAN_MESSAGE_FD, dlc: dl as u8, data: [0; 64] };
                if e.ext {
                    m.msgtype |= PCAN_MESSAGE_EXTENDED;
                }
                if e.brs {
                    m.msgtype |= PCAN_MESSAGE_BRS;
                }
                m.data[..dl].copy_from_slice(&e.data[..dl]);
                let st = unsafe { (self.write_fd)(self.handle, &mut m) };
                if st != PCAN_ERROR_OK {
                    errs.push(format!("CAN_WriteFD: 0x{st:08X}"));
                }
            } else {
                if e.fd || e.data.len() > 8 {
                    errs.push("PEAK 经典模式拒绝 FD/超长帧".into());
                    continue;
                }
                let mut m = TPCANMsg {
                    id: e.id,
                    msgtype: PCAN_MESSAGE_STANDARD,
                    len: e.data.len() as u8,
                    data: [0; 8],
                };
                if e.ext {
                    m.msgtype |= PCAN_MESSAGE_EXTENDED;
                }
                if e.data.is_empty() {
                    m.msgtype |= PCAN_MESSAGE_RTR;
                }
                m.data[..e.data.len()].copy_from_slice(&e.data);
                let st = unsafe { (self.write)(self.handle, &mut m) };
                if st != PCAN_ERROR_OK {
                    errs.push(format!("CAN_Write: 0x{st:08X}"));
                }
            }
        }
    }
}

impl CanBackend for PeakSource {
    fn poll(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut errs: Vec<String> = Vec::new();
        self.drain_tx(&mut errs);
        let mut seq = self.seq;
        let mut n = 0u32;
        while n < 64 {
            if self.fd {
                let st = unsafe {
                    (self.read_fd)(self.handle, self.msg_fd.as_mut() as *mut TPCANMsgFD, self.ts_fd.as_mut() as *mut u64)
                };
                if st & PCAN_ERROR_QRCVEMPTY != 0 {
                    break;
                }
                if st != PCAN_ERROR_OK {
                    errs.push(format!("CAN_ReadFD: 0x{st:08X}"));
                    break;
                }
                let m = &*self.msg_fd;
                let dl = (m.dlc as usize).min(64);
                let f = LiveFrame {
                    ts_ns: self.ts_fd.saturating_mul(1_000), // FD 时戳 = u64 微秒
                    ts_src: TsSrc::Hw,
                    bus_type: BusKind::CanFd,
                    ch: 0,
                    alias: None,
                    dir: Dir::Rx,
                    id: m.id,
                    id_ext: m.msgtype & PCAN_MESSAGE_EXTENDED != 0,
                    dlc: dl,
                    data: m.data[..dl].to_vec(),
                    seq: Some(seq + 1),
                    meta_gap: None,
                };
                seq += 1;
                out.extend_from_slice(live_frame_to_jsonl(&f).as_bytes());
                out.push(b'\n');
            } else {
                let st = unsafe {
                    (self.read)(self.handle, self.msg.as_mut() as *mut TPCANMsg, self.ts.as_mut() as *mut TPCANTimestamp)
                };
                if st & PCAN_ERROR_QRCVEMPTY != 0 {
                    break;
                }
                if st != PCAN_ERROR_OK {
                    // 总线状态类(轻/重/被动/离线):告警并断流等待恢复;未初始化=通道被外部复位
                    if st & (PCAN_ERROR_BUSLIGHT | PCAN_ERROR_BUSHEAVY | PCAN_ERROR_BUSPASSIVE | PCAN_ERROR_BUSOFF) != 0 {
                        errs.push(format!("总线状态告警: 0x{st:08X}(总线忙/离线,等待恢复)"));
                    } else {
                        errs.push(format!("CAN_Read: 0x{st:08X}"));
                    }
                    break;
                }
                let m = &*self.msg;
                let dl = (m.len as usize).min(8);
                let rtr = m.msgtype & PCAN_MESSAGE_RTR != 0;
                let data = if rtr { vec![] } else { m.data[..dl].to_vec() };
                let f = LiveFrame {
                    ts_ns: timestamp_ns(&*self.ts),
                    ts_src: TsSrc::Hw,
                    bus_type: BusKind::Can,
                    ch: 0,
                    alias: None,
                    dir: Dir::Rx,
                    id: m.id,
                    id_ext: m.msgtype & PCAN_MESSAGE_EXTENDED != 0,
                    dlc: data.len(),
                    data,
                    seq: Some(seq + 1),
                    meta_gap: None,
                };
                seq += 1;
                out.extend_from_slice(live_frame_to_jsonl(&f).as_bytes());
                out.push(b'\n');
            }
            n += 1;
        }
        for e in &errs {
            eprintln!("[peak] {e}");
        }
        self.seq = seq;
        out
    }
}

impl Drop for PeakSource {
    fn drop(&mut self) {
        if !self.closed {
            unsafe { (self.uninit)(self.handle) };
            self.closed = true;
        }
    }
}

/// UI 即时提示:PEAK DLL 状态(位数一致 → 就绪;否则给安装指引)
pub fn dll_state() -> String {
    match find_vendor_dll_checked(
        &["peak/x64/PCANBasic.dll", DLL_NAME],
        &["peak/x86/PCANBasic.dll", DLL_NAME],
        "PEAK PCAN-Basic",
    ) {
        Ok(p) => format!("就绪: {}", p.display()),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baud_table_matches_header() {
        assert_eq!(pcan_baud(500_000), Some(0x001C));
        assert_eq!(pcan_baud(1_000_000), Some(0x0014));
        assert_eq!(pcan_baud(125_000), Some(0x031C));
        assert_eq!(pcan_baud(10_000), Some(0x672F));
        assert_eq!(pcan_baud(7_500), None);
    }

    #[test]
    fn usb_channel_handles() {
        assert_eq!(pcan_usb_bus(1), 0x51);
        assert_eq!(pcan_usb_bus(8), 0x58);
        assert_eq!(pcan_usb_bus(9), 0x509);
        assert_eq!(pcan_usb_bus(16), 0x510);
    }

    #[test]
    fn struct_layouts_match_header() {
        assert_eq!(std::mem::size_of::<TPCANMsg>(), 16);
        assert_eq!(std::mem::size_of::<TPCANTimestamp>(), 8);
        assert_eq!(std::mem::size_of::<TPCANMsgFD>(), 72);
        assert_eq!(std::mem::offset_of!(TPCANMsg, data), 6);
        assert_eq!(std::mem::offset_of!(TPCANMsgFD, data), 6);
    }

    #[test]
    fn timestamp_formula() {
        // 官方公式:micros + 1000*millis + 2^32*1000*overflow(millis 本身含在总毫秒数内,无 +1)
        let t = TPCANTimestamp { millis: 1, millis_overflow: 0, micros: 999 };
        assert_eq!(timestamp_ns(&t), 1_999);
        let t = TPCANTimestamp { millis: u32::MAX, millis_overflow: 1, micros: 500 };
        assert_eq!(timestamp_ns(&t), 500 + (u32::MAX as u64 + (1u64 << 32)) * 1_000);
    }

    #[test]
    fn fd_params_shape() {
        let (nom, dat) = fd_params(500_000);
        assert!(nom.contains("nom_brp=8") && nom.contains("nom_tseg1=15"));
        assert!(dat.contains("data_brp=2"));
    }
}
