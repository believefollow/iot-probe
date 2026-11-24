//! GCAN ECanVci 适配层(ADR-0014,第二批厂商适配)。
//! 设计(与 canhw.rs 的 VCI 族同构,但为独立实现):
//! - **动态加载** ECanVci[64].dll(GCAN SDK,canlib\gcan\win64|win32\);该 DLL 依赖同目录
//!   CHUSBDLL[64].dll(USB 传输层)。libloading 走 LoadLibraryExW(flags=0)不搜 DLL 自身目录,
//!   所以**先按全路径预载 CHUSBDLL**,再加载 ECanVci —— 依赖按模块名命中已载入副本。
//! - API 与创芯 ControlCAN 同构但**导出名无 VCI_ 前缀**,且 CAN_OBJ 为 24 字节
//!   (id/timestamp/time_flag/send_type/remote_flag/extern_flag/data_len/data[8]/resv[3],
//!   data 在偏移 13;创芯 VciCanObj 为 20 字节,data 在偏移 8)——结构体必须独立定义。
//! - 语义:控制调用 1=成功;Receive 返回帧数(0=无),WaitTime 单位 ms(本实现恒传 0 轮询);
//!   Transmit 返回实发帧数。DeviceType 头文件未定义,表单按厂商手册填数字(例程用 16)。
//! - 时戳:TimeStamp 单位文档未标注(TimeFlag=0 表示无效)→ 一律用本机软件时戳,
//!   ts_src = sw(ADR-5 诚实标注;真机 bench 后如确认口径可升级为 hw)。
//! - 波特率:SJA1000 BTR0/BTR1 表直接复用 canhw::vci_timing(10k~1M 标准档)。

use crate::canhw::{find_vendor_dll_checked, vci_timing, CanBackend, HwConfig, VciInitConfig};
use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::{BusKind, LiveFrame};
use iotprobe_core::model::{Dir, TsSrc};
use libloading::Library;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ================= ECanVci.h 结构体(默认对齐,无 pack pragma) =================

/// CAN_OBJ:24 字节(注意与创芯 VciCanObj 20 字节不同构,字段顺序也不同)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ECanVciObj {
    pub id: u32,         // @0
    pub timestamp: u32,  // @4(单位文档未标注;TimeFlag=0 表示无效)
    pub time_flag: u8,   // @8
    pub send_type: u8,   // @9(0=正常发送)
    pub remote_flag: u8, // @10
    pub extern_flag: u8, // @11(0=标准 11 位,1=扩展 29 位)
    pub data_len: u8,    // @12(0..8)
    pub data: [u8; 8],   // @13..20
    pub resv: [u8; 3],   // @21..23
}

impl Default for ECanVciObj {
    fn default() -> Self {
        ECanVciObj {
            id: 0,
            timestamp: 0,
            time_flag: 0,
            send_type: 0,
            remote_flag: 0,
            extern_flag: 0,
            data_len: 0,
            data: [0; 8],
            resv: [0; 3],
        }
    }
}

const _: () = assert!(std::mem::size_of::<ECanVciObj>() == 24);
const _: () = assert!(std::mem::offset_of!(ECanVciObj, data) == 13);
const _: () = assert!(std::mem::offset_of!(ECanVciObj, resv) == 21);
// INIT_CONFIG 与创芯 VCI_INIT_CONFIG 同构:复用 VciInitConfig(16 字节)由 size_of 断言背书
const _: () = assert!(std::mem::size_of::<VciInitConfig>() == 16);

// ================= FFI 入口 =================

type OpenFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type CloseFn = unsafe extern "system" fn(u32, u32) -> u32;
type InitFn = unsafe extern "system" fn(u32, u32, u32, *const VciInitConfig) -> u32;
type StartFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type ResetFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type RxNumFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type ReceiveFn = unsafe extern "system" fn(u32, u32, u32, *mut ECanVciObj, u32, i32) -> u32;
type TransmitFn = unsafe extern "system" fn(u32, u32, u32, *mut ECanVciObj, u32) -> u32;

// ================= 适配器 =================

pub struct ECanVciSource {
    _lib: Library,
    _usb: Option<Library>, // CHUSBDLL 预载副本(保活)
    close: CloseFn,
    reset: ResetFn,
    rx_num: RxNumFn,
    receive: ReceiveFn,
    transmit: TransmitFn,
    dev_type: u32,
    dev_idx: u32,
    channels: u32,
    hub: Arc<crate::tx::TxHub>,
    buf: Box<[ECanVciObj; 64]>,
    seq: u64,
    closed: bool,
}

/// SDK DLL 按位数选:ECanVci64.dll(win64)/ ECanVci.dll(win32)
pub fn dll_state() -> String {
    let rels = if cfg!(target_pointer_width = "64") {
        &["gcan/win64/ECanVci64.dll"][..]
    } else {
        &["gcan/win32/ECanVci.dll"][..]
    };
    match find_vendor_dll_checked(rels, rels, "GCAN ECanVci") {
        Ok(p) => format!("就绪: {}(依赖同目录 CHUSBDLL 已预载)", p.display()),
        Err(e) => e,
    }
}

/// 预载 USB 传输层依赖:libloading(flags=0)不搜 DLL 自身目录,依赖必须先在进程内按名就位
fn preload_usb_dependency(dll_dir: &Path) -> Option<Library> {
    let name = if cfg!(target_pointer_width = "64") { "CHUSBDLL64.dll" } else { "CHUSBDLL.dll" };
    let p = dll_dir.join(name);
    if p.exists() {
        match unsafe { Library::new(&p) } {
            Ok(lib) => Some(lib),
            Err(e) => {
                eprintln!("[ecanvci] 预载 {name} 失败: {e}(若 ECanVci 不依赖可忽略)");
                None
            }
        }
    } else {
        None
    }
}

fn sw_ts_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

impl ECanVciSource {
    /// 加载 DLL、打开设备、逐通道初始化并启动。
    pub fn open(cfg: &HwConfig, hub: Arc<crate::tx::TxHub>) -> Result<Box<dyn CanBackend>, String> {
        let rels: &[&str] = if cfg!(target_pointer_width = "64") {
            &["gcan/win64/ECanVci64.dll"]
        } else {
            &["gcan/win32/ECanVci.dll"]
        };
        let path: PathBuf = find_vendor_dll_checked(rels, rels, "GCAN ECanVci")?;
        let usb = preload_usb_dependency(path.parent().unwrap_or(Path::new(".")));
        let lib = unsafe { Library::new(&path) }.map_err(|e| {
            format!(
                "加载 {}: {e}\n若报依赖缺失,请把 SDK 的 CHUSBDLL64.dll(或 32 位 CHUSBDLL.dll)放到 ECanVci DLL 同目录",
                path.display()
            )
        })?;
        let open_: OpenFn = unsafe { *lib.get(b"OpenDevice").map_err(|e| e.to_string())? };
        let close: CloseFn = unsafe { *lib.get(b"CloseDevice").map_err(|e| e.to_string())? };
        let init: InitFn = unsafe { *lib.get(b"InitCAN").map_err(|e| e.to_string())? };
        let start: StartFn = unsafe { *lib.get(b"StartCAN").map_err(|e| e.to_string())? };
        let reset: ResetFn = unsafe { *lib.get(b"ResetCAN").map_err(|e| e.to_string())? };
        let rx_num: RxNumFn = unsafe { *lib.get(b"GetReceiveNum").map_err(|e| e.to_string())? };
        let receive: ReceiveFn = unsafe { *lib.get(b"Receive").map_err(|e| e.to_string())? };
        let transmit: TransmitFn = unsafe { *lib.get(b"Transmit").map_err(|e| e.to_string())? };

        // DeviceType:表单模型填数字直传(厂商手册口径;GCAN 例程用 16)
        let dev_type = crate::canhw::vci_device_type(&cfg.model);
        let (t0, t1) = vci_timing(cfg.bitrate)
            .ok_or_else(|| format!("GCAN 波特率表不支持 {} bps(与 VCI 同表,支持 10k~1M 标准档)", cfg.bitrate))?;
        let dev_idx = cfg.device_index;
        let st = unsafe { open_(dev_type, dev_idx, 0) };
        if st != 1 {
            return Err(format!(
                "OpenDevice({dev_type}#{dev_idx}) 失败(返回 {st})——检查 DeviceType 数字(厂商手册口径)/连接/驱动;GCAN 例程用 16"
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
            if unsafe { init(dev_type, dev_idx, ch, &ic) } != 1 {
                unsafe { close(dev_type, dev_idx) };
                return Err(format!("InitCAN 通道 {ch} 失败(波特率 {}/BTR 0x{t0:02X}0x{t1:02X} 是否受支持?)", cfg.bitrate));
            }
            if unsafe { start(dev_type, dev_idx, ch) } != 1 {
                unsafe { close(dev_type, dev_idx) };
                return Err(format!("StartCAN 通道 {ch} 失败"));
            }
        }
        Ok(Box::new(ECanVciSource {
            _lib: lib,
            _usb: usb,
            close,
            reset,
            rx_num,
            receive,
            transmit,
            dev_type,
            dev_idx,
            channels: cfg.channels.max(1),
            hub,
            buf: Box::new([ECanVciObj::default(); 64]),
            seq: 0,
            closed: false,
        }))
    }
}

impl CanBackend for ECanVciSource {
    fn poll(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut errs: Vec<String> = Vec::new();
        // 发送面板队列排空(FR-4.7):经典 CAN;FD 帧拒绝并计数
        for e in self.hub.pop_due() {
            if e.fd || e.data.len() > 8 {
                errs.push("GCAN 适配为经典 CAN,拒绝 FD/超长帧".into());
                continue;
            }
            let mut o = ECanVciObj {
                id: e.id | if e.ext { 0x8000_0000 } else { 0 },
                send_type: 0,
                remote_flag: if e.data.is_empty() { 1 } else { 0 },
                extern_flag: if e.ext { 1 } else { 0 },
                data_len: e.data.len() as u8,
                ..Default::default()
            };
            o.data[..e.data.len()].copy_from_slice(&e.data);
            for ch in 0..self.channels {
                let sent = unsafe { (self.transmit)(self.dev_type, self.dev_idx, ch, &mut o, 1) };
                if sent != 1 {
                    errs.push(format!("Transmit 通道 {ch} 返回 {sent}"));
                }
            }
        }
        // 接收:GetReceiveNum 先探,Receive 批取(WaitTime=0 非阻塞)
        let mut seq = self.seq;
        for ch in 0..self.channels {
            let n = unsafe { (self.rx_num)(self.dev_type, self.dev_idx, ch) };
            if n == 0 {
                continue;
            }
            let got = unsafe { (self.receive)(self.dev_type, self.dev_idx, ch, self.buf.as_mut_ptr(), 64, 0) } as usize;
            for k in 0..got.min(64) {
                let o = &self.buf[k];
                let raw = o.id;
                let ext = raw & 0x8000_0000 != 0;
                let dl = (o.data_len as usize).min(8);
                let f = LiveFrame {
                    // TimeStamp 单位文档未标注 → 软件时戳(ADR-5 诚实标注;bench 确认口径后可升级)
                    ts_ns: sw_ts_ns(),
                    ts_src: TsSrc::Sw,
                    bus_type: BusKind::Can,
                    ch,
                    alias: None,
                    dir: Dir::Rx,
                    id: raw & 0x1FFF_FFFF,
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
        for e in &errs {
            eprintln!("[ecanvci] {e}");
        }
        self.seq = seq;
        out
    }
}

impl Drop for ECanVciSource {
    fn drop(&mut self) {
        if !self.closed {
            for ch in 0..self.channels {
                unsafe { (self.reset)(self.dev_type, self.dev_idx, ch) };
            }
            unsafe { (self.close)(self.dev_type, self.dev_idx) };
            self.closed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_layouts_match_header() {
        // ECanVci.h:CAN_OBJ 24 字节,data@13,resv@21(与创芯 20 字节 VciCanObj 不同构)
        assert_eq!(std::mem::size_of::<ECanVciObj>(), 24);
        assert_eq!(std::mem::offset_of!(ECanVciObj, data), 13);
        assert_eq!(std::mem::offset_of!(ECanVciObj, resv), 21);
        // INIT_CONFIG 与 VciInitConfig 同构(16 字节)
        assert_eq!(std::mem::size_of::<VciInitConfig>(), 16);
    }

    #[test]
    fn device_type_numeric_passthrough() {
        // GCAN DeviceType 头文件未定义:模型填数字直传(例程 16);名字仍走创芯映射
        assert_eq!(crate::canhw::vci_device_type("16"), 16);
        assert_eq!(crate::canhw::vci_device_type(" 4 "), 4);
        assert_eq!(crate::canhw::vci_device_type("USBCAN2"), 4);
    }

    #[test]
    fn default_send_type_zero() {
        let o = ECanVciObj { id: 0x123, ..Default::default() };
        assert_eq!(o.send_type, 0, "0=正常发送(例程口径)");
        assert_eq!(o.data_len, 0);
    }
}
