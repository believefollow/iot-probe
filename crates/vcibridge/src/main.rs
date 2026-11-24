//! vci-bridge —— 32 位 VCI 桥接子进程(std-only,便于按厂商 DLL 位数单独构建)。
//!
//! 背景:大量老 CAN 卡只提供 32 位厂商 DLL(ControlCAN.dll),64 位主程序无法加载。
//! 主程序检测到位数不匹配时拉起本进程代为加载 DLL,经 stdin/stdout 行协议转发调用,
//! 主程序侧 CanBackend 语义与进程内加载完全一致。
//!
//! 协议(每行一个命令,一行一个应答,纯 ASCII):
//! - `PING`                                       → `OK v1 <i386|x86_64>`
//! - `OPEN <dev_type> <dev_idx>`                  → `OK` | `ERR <原因>`
//! - `INIT <ch> <t0> <t1> <mode> <filter> <acc_code> <acc_mask>` → `OK` | `ERR <原因>`
//! - `START <ch>`                                 → `OK` | `ERR <原因>`
//! - `NUM <ch>`                                   → `N <n>` | `ERR <原因>`
//! - `READ <ch> <max>`                            → `N <k>` 后随 k 行 F 帧行 | `ERR <原因>`
//! - `SEND <ch> <id> <ext> <rtr> <dlc> <hex…>`    → `OK` | `ERR <原因>`
//! - `CLOSE`                                      → `OK`(关整机)
//! - `QUIT`(或 stdin EOF)                        → 进程退出
//!
//! F 帧行:`F <id十进制> <ext 0/1> <rtr 0/1> <dlc> <hex 数据字节…>`;id 带 0x80000000 位即扩展帧。

use std::io::{BufRead, Write};

#[repr(C)]
#[derive(Clone, Copy)]
struct VciInitConfig {
    acc_code: u32,
    acc_mask: u32,
    reserved: u32,
    filter: u8,
    timing0: u8,
    timing1: u8,
    mode: u8, // 0=正常 1=只听
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VciCanObj {
    id: u32,
    timestamp: u32,
    time_flag: u8,
    remote_flag: u8,
    extern_flag: u8,
    data_len: u8,
    data: [u8; 8],
}

impl Default for VciCanObj {
    fn default() -> Self {
        VciCanObj { id: 0, timestamp: 0, time_flag: 0, remote_flag: 0, extern_flag: 0, data_len: 0, data: [0; 8] }
    }
}

type OpenFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type CloseFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type InitFn = unsafe extern "system" fn(u32, u32, u32, *const VciInitConfig) -> u32;
type StartFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type RxNumFn = unsafe extern "system" fn(u32, u32, u32) -> u32;
type ReceiveFn = unsafe extern "system" fn(u32, u32, u32, *mut VciCanObj, u32, i32) -> u32;
type TransmitFn = unsafe extern "system" fn(u32, u32, u32, *mut VciCanObj, u32) -> u32;

const DLL_NAME: &str = "ControlCAN.dll";
const ARCH: &str = if cfg!(target_arch = "x86") { "i386" } else { "x86_64" };

// 直接走 kernel32:零第三方依赖,i686 目标也能编译
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(name: *const u8) -> isize;
    fn GetProcAddress(module: isize, name: *const u8) -> isize;
    fn GetLastError() -> u32;
}

unsafe fn load_library(path: &[u8]) -> isize {
    let mut buf = path.to_vec();
    buf.push(0);
    LoadLibraryA(buf.as_ptr())
}

/// 解析导出符号为函数指针(仅用于函数指针类型)
unsafe fn resolve<T: Copy>(h: isize, name: &str) -> Option<T> {
    let mut buf = name.as_bytes().to_vec();
    buf.push(0);
    let p = GetProcAddress(h, buf.as_ptr());
    if p == 0 {
        return None;
    }
    Some(std::mem::transmute_copy(&p))
}

struct VciLib {
    /// 模块句柄:进程存活期间保持 DLL 加载,不调用 FreeLibrary
    #[allow(dead_code)]
    h: isize,
    open_: OpenFn,
    close_: CloseFn,
    init: InitFn,
    start: StartFn,
    rx_num: RxNumFn,
    receive: ReceiveFn,
    transmit: TransmitFn,
}

impl VciLib {
    unsafe fn load(path: &std::path::Path) -> Result<VciLib, String> {
        let mut pb = path.as_os_str().to_string_lossy().into_owned().into_bytes();
        pb.push(0);
        let h = load_library(&pb);
        if h == 0 {
            let err = GetLastError();
            let hint = match err {
                126 | 127 => ";缺依赖 DLL:老 SDK 常缺 VC2008 运行库(MFC90/MSVCR90),装 VC++ 2008 SP1 x86 运行库或把厂商 SDK 内其它 DLL 一并放到同目录",
                5 => ";拒绝访问:文件被占用或权限不足",
                193 => ";位数不匹配",
                _ => "",
            };
            return Err(format!("LoadLibrary 失败: {} (GetLastError={err}{hint})", path.display()));
        }
        let open_: OpenFn = resolve(h, "VCI_OpenDevice").ok_or("DLL 缺少导出 VCI_OpenDevice")?;
        let close_: CloseFn = resolve(h, "VCI_CloseDevice").ok_or("DLL 缺少导出 VCI_CloseDevice")?;
        let init: InitFn = resolve(h, "VCI_InitCAN").ok_or("DLL 缺少导出 VCI_InitCAN")?;
        let start: StartFn = resolve(h, "VCI_StartCAN").ok_or("DLL 缺少导出 VCI_StartCAN")?;
        let rx_num: RxNumFn = resolve(h, "VCI_GetReceiveNum").ok_or("DLL 缺少导出 VCI_GetReceiveNum")?;
        let receive: ReceiveFn = resolve(h, "VCI_Receive").ok_or("DLL 缺少导出 VCI_Receive")?;
        let transmit: TransmitFn = resolve(h, "VCI_Transmit").ok_or("DLL 缺少导出 VCI_Transmit")?;
        Ok(VciLib { h, open_, close_, init, start, rx_num, receive, transmit })
    }
}

struct State {
    lib: Option<VciLib>,
    load_err: Option<String>,
    dev: Option<(u32, u32)>,
}

impl Drop for State {
    fn drop(&mut self) {
        // 兜底:退出前关设备
        if let (Some(l), Some((dt, di))) = (self.lib.as_ref(), self.dev) {
            unsafe { (l.close_)(dt, di, 0) };
        }
    }
}

fn find_dll() -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for cand in [dir.join(DLL_NAME), dir.join("canlib").join(DLL_NAME)] {
                if cand.exists() {
                    return Some(cand);
                }
            }
        }
    }
    let p = std::path::PathBuf::from(DLL_NAME);
    p.exists().then_some(p)
}

fn num(t: &[&str], i: usize) -> Option<u32> {
    t.get(i)?.parse().ok()
}

/// F 帧行(桥接 → 主程序)
fn frame_line(o: &VciCanObj) -> String {
    let dl = (o.data_len as usize).min(8);
    let mut s = format!("F {} {} {} {}", o.id, u8::from(o.extern_flag != 0), u8::from(o.remote_flag != 0), dl);
    for b in &o.data[..dl] {
        s.push_str(&format!(" {b:02X}"));
    }
    s
}

/// SEND 命令解析:`SEND <ch> <id> <ext> <rtr> <dlc> <hex…>`
fn parse_send(t: &[&str]) -> Option<(u32, VciCanObj)> {
    let ch: u32 = t.get(1)?.parse().ok()?;
    let id: u32 = t.get(2)?.parse().ok()?;
    let ext = if *t.get(3)? == "1" { 1 } else { 0 };
    let rtr = if *t.get(4)? == "1" { 1 } else { 0 };
    let dlc: usize = t.get(5)?.parse().ok()?;
    let dl = dlc.min(8);
    let mut o = VciCanObj::default();
    o.id = id;
    o.extern_flag = ext;
    o.remote_flag = rtr;
    o.data_len = dl as u8;
    for k in 0..dl {
        o.data[k] = u8::from_str_radix(t.get(6 + k)?, 16).ok()?;
    }
    Some((ch, o))
}

/// 处理一行命令;返回 false = 退出
fn handle(line: &str, st: &mut State, out: &mut dyn Write) -> bool {
    let t: Vec<&str> = line.split_whitespace().collect();
    macro_rules! say {
        ($($a:tt)*) => {{
            let _ = writeln!(out, $($a)*);
        }};
    }
    match t.first().copied().unwrap_or("") {
        "" => say!("ERR 空命令"),
        "PING" => say!("OK v1 {ARCH}"),
        "QUIT" => return false,
        "OPEN" => {
            let (Some(dt), Some(di)) = (num(&t, 1), num(&t, 2)) else {
                say!("ERR 参数不足");
                return true;
            };
            match st.lib.as_mut() {
                None => say!("ERR {}", st.load_err.clone().unwrap_or_else(|| "DLL 未加载".into())),
                Some(l) => unsafe {
                    if (l.open_)(dt, di, 0) == 1 {
                        st.dev = Some((dt, di));
                        say!("OK");
                    } else {
                        say!("ERR VCI_OpenDevice != 1(检查设备连接/驱动/序号)");
                    }
                },
            }
        }
        "INIT" => {
            let (Some(l), Some((dt, di))) = (st.lib.as_mut(), st.dev) else {
                say!("ERR 设备未打开");
                return true;
            };
            let (Some(ch), Some(t0), Some(t1), Some(mode), Some(filter), Some(ac), Some(am)) = (
                num(&t, 1),
                num(&t, 2),
                num(&t, 3),
                num(&t, 4),
                num(&t, 5),
                num(&t, 6),
                num(&t, 7),
            ) else {
                say!("ERR 参数不足");
                return true;
            };
            let ic = VciInitConfig {
                acc_code: ac,
                acc_mask: am,
                reserved: 0,
                filter: filter as u8,
                timing0: t0 as u8,
                timing1: t1 as u8,
                mode: mode as u8,
            };
            unsafe {
                if (l.init)(dt, di, ch, &ic) == 1 {
                    say!("OK");
                } else {
                    say!("ERR VCI_InitCAN != 1");
                }
            }
        }
        "START" => {
            let (Some(l), Some((dt, di))) = (st.lib.as_mut(), st.dev) else {
                say!("ERR 设备未打开");
                return true;
            };
            let Some(ch) = num(&t, 1) else {
                say!("ERR 参数不足");
                return true;
            };
            unsafe {
                if (l.start)(dt, di, ch) == 1 {
                    say!("OK");
                } else {
                    say!("ERR VCI_StartCAN != 1");
                }
            }
        }
        "NUM" => {
            let (Some(l), Some((dt, di))) = (st.lib.as_mut(), st.dev) else {
                say!("ERR 设备未打开");
                return true;
            };
            let Some(ch) = num(&t, 1) else {
                say!("ERR 参数不足");
                return true;
            };
            unsafe { say!("N {}", (l.rx_num)(dt, di, ch)) }
        }
        "READ" => {
            let (Some(l), Some((dt, di))) = (st.lib.as_mut(), st.dev) else {
                say!("ERR 设备未打开");
                return true;
            };
            let Some(ch) = num(&t, 1) else {
                say!("ERR 参数不足");
                return true;
            };
            let max = num(&t, 2).unwrap_or(0).min(256) as usize;
            unsafe {
                let mut objs = [VciCanObj::default(); 256];
                let got = (l.receive)(dt, di, ch, objs.as_mut_ptr(), max as u32, 0) as usize;
                let got = got.min(max);
                say!("N {got}");
                for o in &objs[..got] {
                    say!("{}", frame_line(o));
                }
            }
        }
        "SEND" => {
            let (Some(l), Some((dt, di))) = (st.lib.as_mut(), st.dev) else {
                say!("ERR 设备未打开");
                return true;
            };
            let Some((ch, o)) = parse_send(&t) else {
                say!("ERR 参数不足/帧格式错");
                return true;
            };
            unsafe {
                let mut o = o;
                if (l.transmit)(dt, di, ch, &mut o, 1) == 1 {
                    say!("OK");
                } else {
                    say!("ERR VCI_Transmit != 1");
                }
            }
        }
        "CLOSE" => {
            if let (Some(l), Some((dt, di))) = (st.lib.as_ref(), st.dev) {
                unsafe { (l.close_)(dt, di, 0) };
                st.dev = None;
            }
            say!("OK");
        }
        cmd => say!("ERR 未知命令 {cmd}"),
    }
    true
}

fn main() {
    let mut st = State { lib: None, load_err: None, dev: None };
    match find_dll() {
        Some(p) => unsafe {
            match VciLib::load(&p) {
                Ok(l) => st.lib = Some(l),
                Err(e) => st.load_err = Some(e),
            }
        },
        None => {
            st.load_err = Some(format!("找不到 {DLL_NAME}(放在 vci-bridge.exe 同目录或其 canlib 子目录)"));
        }
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if !handle(&line, &mut st, &mut out) {
            break;
        }
    }
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_line_format() {
        let mut o = VciCanObj::default();
        o.id = 0x123;
        o.remote_flag = 1;
        o.data_len = 2;
        o.data = [1, 2, 0, 0, 0, 0, 0, 0];
        assert_eq!(frame_line(&o), "F 291 0 1 2 01 02");
    }

    #[test]
    fn send_parse_roundtrip() {
        // 0x80000123 = 2147483939(带扩展位)
        let t: Vec<&str> = "SEND 1 2147483939 1 0 3 AA BB CC".split_whitespace().collect();
        let (ch, back) = parse_send(&t).unwrap();
        assert_eq!(ch, 1);
        assert_eq!((back.id, back.extern_flag, back.remote_flag, back.data_len), (0x8000_0123, 1, 0, 3));
        assert_eq!(&back.data[..3], &[0xAA, 0xBB, 0xCC]);
        assert!(parse_send(&"SEND 1 12 0 0 zz".split_whitespace().collect::<Vec<&str>>()).is_none());
        assert!(parse_send(&"SEND 1".split_whitespace().collect::<Vec<&str>>()).is_none());
    }
}
