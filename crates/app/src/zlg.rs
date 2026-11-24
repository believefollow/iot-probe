//! ZLG(周立功)USBCANFD 系列适配层(ADR-0010,Q3 选型:ZLG USBCAN-FD2)。
//! 设计:
//! - **动态加载** zlgcan.dll(随 ZLG 驱动安装;无链接期依赖),只调用长期稳定的五个入口:
//!   OpenDevice / CloseDevice / InitCAN / StartCAN / Receive(采集只读,发送面板后置)。
//! - 输出统一为 **frame.schema.json 契约 NDJSON 字节流**(实现 std::io::Read),
//!   接入 core 的 live::Pipeline —— 录制/回放/相对化/丢帧检测/解析/曲线**全部复用**,
//!   后续换 TCP 网关适配器时上层不动(风险备注 #2)。
//! - 时间戳:设备硬件时戳 → ts_src = hw(ADR-5 L1);单位按 ZLG 通用函数库文档默认
//!   0.1ms,表单可切(10µs/1µs)。**真机核对属 T-1.3 bench 任务**(ADR-0010)。
//! - 结构体布局以 ZLG 随驱动发布的 zlgcan.h 为准:ReceiveData 24B / ReceiveFDData 80B /
//!   ReceiveMsg 96B(含 static assert);初始化配置以零填充大结构体传递(缺省参数全 0),
//!   减小布局猜测面。**开发期无硬件也能跑**:SimSource(模拟 CAN 总线)走同一管线。

use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::LiveFrame;
use iotprobe_core::ingest::live::BusKind;
use iotprobe_core::model::{Dir, TsSrc};
use libloading::Library;
use std::io;
use std::os::raw::c_char;

// ================= zlgcan.h 结构体(布局以官方头文件为准) =================

#[repr(C)]
#[derive(Clone, Copy)]
struct ReceiveData {
    can_id: u32,
    dlc: u8,
    _pad: [u8; 3],
    data: [u8; 8],
    _resv: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ReceiveFdData {
    can_id: u32,
    dlc: u8,
    /// bit0=0? bit1=BRS, bit2=ESI(ZLG FD 帧标志;采集侧仅透传,不参与逻辑)
    flags: u8,
    _pad: [u8; 2],
    data: [u8; 64],
    _resv: [u8; 8],
}

/// ZCAN_ReceiveMsg:timestamp(u64) + type(u32) + union(取 FD 最大布局)
#[repr(C)]
#[derive(Clone, Copy)]
struct ReceiveMsg {
    timestamp: u64,
    rtype: u32,
    _pad: u32,
    payload: [u8; 80],
}

const _: () = assert!(std::mem::size_of::<ReceiveData>() == 24);
const _: () = assert!(std::mem::size_of::<ReceiveFdData>() == 80);
const _: () = assert!(std::mem::size_of::<ReceiveMsg>() == 96);

const TYPE_CAN: u32 = 0;
const TYPE_CANFD: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct TransmitData {
    can_id: u32,
    dlc: u8,
    _pad: [u8; 3],
    data: [u8; 8],
    _resv: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TransmitFdData {
    can_id: u32,
    dlc: u8,
    /// bit1 = BRS(数据段加速);bench 核对
    flags: u8,
    _pad: [u8; 2],
    data: [u8; 64],
    _resv: [u8; 8],
}

/// ZCAN_TransmitMsg:type(u32) + pad + union(FD 布局)
#[repr(C)]
#[derive(Clone, Copy)]
struct TransmitMsg {
    rtype: u32,
    _pad: u32,
    payload: [u8; 80],
}

const _: () = assert!(std::mem::size_of::<TransmitData>() == 24);
const _: () = assert!(std::mem::size_of::<TransmitFdData>() == 80);
const _: () = assert!(std::mem::size_of::<TransmitMsg>() == 88);

/// CANFD 通道初始化配置:常用字段前置,尾部以零填充吸收版本差异。
/// mode:0=正常,1=只听(listen-only,FR-10.4 只读模式)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CanFdChConfig {
    pub mode: u32,
    /// 仲裁段波特率(kbps,ZLG 配置口径)
    pub bitrate: u32,
    pub sbt: u32,
    /// 数据段波特率(kbps)
    pub data_bitrate: u32,
    pub dbsbt: u32,
    pub resv: [u8; 512],
}

impl Default for CanFdChConfig {
    fn default() -> Self {
        CanFdChConfig { mode: 0, bitrate: 0, sbt: 0, data_bitrate: 0, dbsbt: 0, resv: [0; 512] }
    }
}

// ================= FFI 入口 =================

type OpenDeviceFn = unsafe extern "system" fn(*const c_char, u32, u32) -> usize;
type CloseDeviceFn = unsafe extern "system" fn(usize) -> i32;
type InitCanFn = unsafe extern "system" fn(*const c_char, u32, u32, *mut CanFdChConfig) -> usize;
type StartCanFn = unsafe extern "system" fn(usize) -> i32;
type ReceiveFn = unsafe extern "system" fn(usize, *mut ReceiveMsg, u32, i32) -> u32;
type ResetCanFn = unsafe extern "system" fn(usize) -> i32;
type TransmitFn = unsafe extern "system" fn(usize, *mut TransmitMsg, u32) -> u32;

const DLL_NAME: &str = "zlgcan.dll";

// ================= 适配器 =================

pub struct ZlgConfig {
    /// ZCAN_OpenDevice 设备类型串(USBCANFD-200U / USBCANFD-100U / USBCANFD-800U …)
    pub device_type: String,
    pub device_index: u32,
    /// 通道数(200U=2)
    pub channels: u32,
    /// 仲裁段波特率(kbps)
    pub bitrate: u32,
    /// 数据段波特率(kbps)
    pub data_bitrate: u32,
    /// 时间戳单位:raw × unit → ns
    pub ts_unit_ns: u64,
    /// 只听模式(FR-10.4)
    pub listen_only: bool,
}

pub struct ZlgSource {
    _lib: Library,
    _dev_type: std::ffi::CString,
    dev: usize,
    chs: Vec<usize>,
    reset: ResetCanFn,
    close: CloseDeviceFn,
    receive: ReceiveFn,
    transmit: TransmitFn,
    msgs: Box<[ReceiveMsg; 64]>,
    cfg: ZlgConfig,
    hub: std::sync::Arc<crate::tx::TxHub>,
    rx: Vec<u8>,
    rx_pos: usize,
    seq: u64,
    closed: bool,
    pub tx_fail: std::sync::atomic::AtomicUsize,
}

impl ZlgSource {
    /// 加载 DLL 并打开设备。DLL 缺失/设备不存在时返回带指引的错误。
    pub fn open(cfg: ZlgConfig, hub: std::sync::Arc<crate::tx::TxHub>) -> Result<Self, String> {
        let lib = unsafe { Library::new(DLL_NAME) }
            .map_err(|e| format!("加载 {DLL_NAME} 失败: {e}\n请安装 ZLG 设备驱动(通用函数库),并把 zlgcan.dll 放到程序目录或 PATH"))?;
        let open: OpenDeviceFn = unsafe { *lib.get(b"ZCAN_OpenDevice").map_err(|e| e.to_string())? };
        let init: InitCanFn = unsafe { *lib.get(b"ZCAN_InitCAN").map_err(|e| e.to_string())? };
        let start: StartCanFn = unsafe { *lib.get(b"ZCAN_StartCAN").map_err(|e| e.to_string())? };
        let receive: ReceiveFn = unsafe { *lib.get(b"ZCAN_Receive").map_err(|e| e.to_string())? };
        let reset: ResetCanFn = unsafe { *lib.get(b"ZCAN_ResetCAN").map_err(|e| e.to_string())? };
        let close: CloseDeviceFn = unsafe { *lib.get(b"ZCAN_CloseDevice").map_err(|e| e.to_string())? };
        let transmit: TransmitFn = unsafe { *lib.get(b"ZCAN_Transmit").map_err(|e| e.to_string())? };
        let dev_type = std::ffi::CString::new(cfg.device_type.clone())
            .map_err(|_| "设备类型串不能含 \\0".to_string())?;
        let dev = unsafe { open(dev_type.as_ptr(), cfg.device_index, 0) };
        if dev == 0 {
            return Err(format!(
                "打开设备失败: {}#{},请检查连接/驱动/设备序号",
                cfg.device_type, cfg.device_index
            ));
        }
        let mut chs = vec![];
        for ch in 0..cfg.channels.max(1) {
            let mut cc = CanFdChConfig {
                mode: if cfg.listen_only { 1 } else { 0 },
                bitrate: cfg.bitrate,
                data_bitrate: cfg.data_bitrate,
                ..Default::default()
            };
            let h = unsafe { init(dev_type.as_ptr(), cfg.device_index, ch, &mut cc) };
            if h == 0 {
                unsafe { close(dev) };
                return Err(format!("初始化通道 {ch} 失败(波特率 {}/{}kbps 是否受支持?)", cfg.bitrate, cfg.data_bitrate));
            }
            if unsafe { start(h) } != 1 {
                unsafe { close(dev) };
                return Err(format!("通道 {ch} StartCAN 失败"));
            }
            chs.push(h);
        }
        Ok(ZlgSource {
            _lib: lib,
            _dev_type: dev_type,
            dev,
            chs,
            reset,
            close,
            receive,
            transmit,
            msgs: Box::new([ReceiveMsg { timestamp: 0, rtype: 0, _pad: 0, payload: [0; 80] }; 64]),
            cfg,
            hub,
            rx: vec![],
            rx_pos: 0,
            seq: 0,
            closed: false,
            tx_fail: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// 拉取一批硬件帧 → 契约 JSONL 行(带 \n)。0 帧 = None。
    /// 发送面板队列排空(FR-4.7):hub 由 UI 显式解锁后写入,白名单双重校验
    fn drain_tx(&mut self) {
        for e in self.hub.pop_due() {
            let ch = *self.chs.first().unwrap_or(&0);
            let mut msg = TransmitMsg { rtype: if e.fd { TYPE_CANFD } else { TYPE_CAN }, _pad: 0, payload: [0; 80] };
            if e.fd {
                let d = unsafe { &mut *(msg.payload.as_mut_ptr() as *mut TransmitFdData) };
                d.can_id = e.id | if e.ext { 0x8000_0000 } else { 0 };
                d.dlc = e.data.len() as u8;
                d.flags = if e.brs { 0x02 } else { 0 };
                d.data[..e.data.len()].copy_from_slice(&e.data);
            } else {
                let d = unsafe { &mut *(msg.payload.as_mut_ptr() as *mut TransmitData) };
                d.can_id = e.id | if e.ext { 0x8000_0000 } else { 0 };
                d.dlc = e.data.len() as u8;
                d.data[..e.data.len()].copy_from_slice(&e.data);
            }
            let sent = unsafe { (self.transmit)(ch, &mut msg, 1) };
            if sent == 0 {
                self.tx_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn poll(&mut self) -> Option<()> {
        self.drain_tx();
        let mut got = 0usize;
        for &ch in &self.chs {
            let n = unsafe { (self.receive)(ch, self.msgs.as_mut_ptr(), 64, 10) };
            for k in 0..n as usize {
                let m = &self.msgs[k];
                let is_fd = m.rtype == TYPE_CANFD;
                let (id_raw, data): (u32, Vec<u8>) = if is_fd {
                    let d = unsafe { &*(m.payload.as_ptr() as *const ReceiveFdData) };
                    let dl = (d.dlc as usize).min(64);
                    (d.can_id, d.data[..dl].to_vec())
                } else {
                    let d = unsafe { &*(m.payload.as_ptr() as *const ReceiveData) };
                    let dl = (d.dlc as usize).min(8);
                    (d.can_id, d.data[..dl].to_vec())
                };
                let ext = id_raw & 0x8000_0000 != 0;
                let id = id_raw & 0x1FFF_FFFF;
                let f = LiveFrame {
                    ts_ns: m.timestamp.saturating_mul(self.cfg.ts_unit_ns),
                    ts_src: TsSrc::Hw, // ADR-5 L1:适配器硬件时戳
                    bus_type: if is_fd { BusKind::CanFd } else { BusKind::Can },
                    ch: self.chs.iter().position(|&c| c == ch).unwrap_or(0) as u32,
                    alias: None,
                    dir: Dir::Rx,
                    id,
                    id_ext: ext,
                    dlc: data.len(),
                    data,
                    seq: Some(self.seq + 1),
                    meta_gap: None,
                };
                self.seq += 1;
                let line = live_frame_to_jsonl(&f);
                self.rx.extend_from_slice(line.as_bytes());
                self.rx.push(b'\n');
                got += 1;
            }
        }
        (got > 0).then_some(())
    }
}

impl io::Read for ZlgSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_pos >= self.rx.len() {
            self.rx.clear();
            self.rx_pos = 0;
            match self.poll() {
                Some(()) => {}
                None => return Err(io::Error::new(io::ErrorKind::WouldBlock, "无帧")),
            }
        }
        let n = self.rx.len().saturating_sub(self.rx_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + n]);
        self.rx_pos += n;
        Ok(n)
    }
}

impl Drop for ZlgSource {
    fn drop(&mut self) {
        if !self.closed {
            for &h in &self.chs {
                unsafe { (self.reset)(h) };
            }
            unsafe { (self.close)(self.dev) };
            self.closed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::live_frame_to_jsonl;

    #[test]
    fn struct_layouts_match_zlgcan_h() {
        assert_eq!(std::mem::size_of::<ReceiveData>(), 24);
        assert_eq!(std::mem::size_of::<ReceiveFdData>(), 80);
        assert_eq!(std::mem::size_of::<ReceiveMsg>(), 96);
        // FD 数据字段偏移:can_id(4)+dlc(1)+flags(1)+pad(2) = 8
        assert_eq!(std::mem::offset_of!(ReceiveFdData, data), 8);
        assert_eq!(std::mem::offset_of!(ReceiveData, data), 8);
    }

    /// 契约 NDJSON 输出必须能被 core 的 live 管线解析(闭环:硬件→管线)
    #[test]
    fn jsonl_shape_accepted_by_pipeline() {
        let f = LiveFrame {
            ts_ns: 123_400_000, // 0.1ms × 1234
            ts_src: TsSrc::Hw,
            bus_type: BusKind::CanFd,
            ch: 0,
            alias: None,
            dir: Dir::Rx,
            id: 0x1A0,
            id_ext: false,
            dlc: 12,
            data: (0..12).collect(),
            seq: Some(1),
            meta_gap: None,
        };
        let line = live_frame_to_jsonl(&f);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["ts_src"], "hw");
        assert_eq!(v["bus"]["type"], "canfd");
        assert_eq!(v["id"], 0x1A0);
        assert_eq!(v["dlc"], 12);
        assert_eq!(v["data"].as_array().unwrap().len(), 12);
    }
}
