//! 串口终端(任务卡 E1):设备 CLI/AT 命令交互,补 MobaXterm 重叠区。
//! - hex/文本双视图、时间戳行、发送区单发/周期
//! - 「同录可选」:双向字节按 frame.schema 落 NDJSON(Recorder 与实时源同款,可离线重放进解析管线)
//! - 终端独立于实时接入管线(不占解析流量;录制文件可另开回放分析)
//! - 读线程收字节推共享行缓冲;发送经写句柄锁(单发走 GUI 线程,周期走线程);
//!   录制在产生点就地落盘(读线程记 Rx,发送点记 Tx),不做二次搬运

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iotprobe_core::ingest::live::{BusKind, LiveFrame, Recorder};
use iotprobe_core::model::{Dir, TsSrc};

/// 一行终端记录:一个读/写块的原始字节 + 相对开窗毫秒时戳(按块展示,设备吐半行也如实显示)
#[derive(Clone)]
pub struct TermLine {
    pub t_ms: u64,
    pub dir: TermDir,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum TermDir {
    Tx,
    Rx,
}

impl TermDir {
    pub fn mark(&self) -> &'static str {
        match self {
            TermDir::Tx => "→",
            TermDir::Rx => "←",
        }
    }
}

/// 运行中的终端(跨线程与 GUI 共享)
pub struct TermHandle {
    pub stop: Arc<AtomicBool>,
    /// 开窗时刻:行时戳 = 相对它的毫秒(终端时戳,不承诺墙钟精度)
    pub t0: Instant,
    pub lines: Arc<Mutex<Vec<TermLine>>>,
    /// 写句柄:GUI 单发与周期线程共用(读端归读线程)
    wport: Arc<Mutex<Option<Box<dyn serialport::SerialPort>>>>,
    /// 周期发送内容与间隔(GUI 改,线程读)
    pub periodic_input: Arc<Mutex<String>>,
    pub periodic: Arc<AtomicBool>,
    pub interval_ms: Arc<Mutex<u32>>,
    /// NDJSON 录制(同录可选;Some 即双向落盘)
    recorder: Arc<Mutex<Option<Recorder>>>,
}

impl Drop for TermHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl TermHandle {
    fn now_ms(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }

    /// 记录一条终端字节到 NDJSON(录制未开 = no-op)
    fn record(&self, dir: TermDir, data: &[u8]) {
        let mut g = self.recorder.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rec) = g.as_mut() {
            let f = LiveFrame {
                ts_ns: self.now_ms() * 1_000_000,
                ts_src: TsSrc::Wall,
                bus_type: BusKind::Uart,
                ch: 0,
                alias: None, // 终端不带业务别名;回放侧按 uart 通道识别
                dir: match dir {
                    TermDir::Tx => Dir::Tx,
                    TermDir::Rx => Dir::Rx,
                },
                id: 0,
                id_ext: false,
                dlc: data.len(),
                data: data.to_vec(),
                seq: None,
                meta_gap: None,
            };
            rec.write_line(&crate::live::live_frame_to_jsonl(&f));
        }
    }

    /// 推一行进缓冲(5000 行上限,旧的丢弃)
    fn push_line(lines: &Arc<Mutex<Vec<TermLine>>>, t_ms: u64, dir: TermDir, data: Vec<u8>) {
        let mut ls = lines.lock().unwrap_or_else(|e| e.into_inner());
        ls.push(TermLine { t_ms, dir, data });
        let n = ls.len();
        if n > 5000 {
            ls.drain(..n - 5000);
        }
    }

    /// 发送字节(单发/周期共用):写串口 + 缓冲 + 录制
    pub fn send_bytes(&self, data: &[u8]) -> Result<(), String> {
        {
            let mut g = self.wport.lock().unwrap_or_else(|e| e.into_inner());
            match g.as_mut() {
                Some(p) => p.write_all(data).map_err(|e| format!("串口写入失败: {e}"))?,
                None => return Err("串口未打开".into()),
            }
        }
        Self::push_line(&self.lines, self.now_ms(), TermDir::Tx, data.to_vec());
        self.record(TermDir::Tx, data);
        Ok(())
    }

    /// 取走缓冲行(UI 渲染)
    pub fn snapshot(&self) -> Vec<TermLine> {
        self.lines.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// 打开串口终端:读线程 + 周期发送线程;record_path=Some 时双向字节落 NDJSON。
pub fn open(port: &str, baud: u32, record_path: Option<PathBuf>) -> Result<TermHandle, String> {
    let mut p = serialport::new(port, baud)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| format!("打开串口 {port}@{baud} 失败: {e}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let lines: Arc<Mutex<Vec<TermLine>>> = Arc::new(Mutex::new(Vec::new()));
    let wport: Arc<Mutex<Option<Box<dyn serialport::SerialPort>>>> = Arc::new(Mutex::new(None));
    let periodic_input: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let periodic = Arc::new(AtomicBool::new(false));
    let interval_ms: Arc<Mutex<u32>> = Arc::new(Mutex::new(1000));
    let recorder: Arc<Mutex<Option<Recorder>>> = Arc::new(Mutex::new(match record_path {
        Some(rp) => Some(Recorder::create(&rp)?),
        None => None,
    }));
    // 串口不 Clone:读端归读线程,写端 try_clone(Windows/Linux 均支持)
    let w = p.try_clone().map_err(|e| format!("串口句柄克隆失败(写端): {e}"))?;
    *wport.lock().unwrap_or_else(|e| e.into_inner()) = Some(w);
    let t0 = Instant::now();
    // 读线程
    {
        let stop2 = stop.clone();
        let lines2 = lines.clone();
        let rec2 = recorder.clone();
        std::thread::Builder::new()
            .name("term-rx".into())
            .spawn(move || {
                let mut buf = [0u8; 512];
                loop {
                    if stop2.load(Ordering::Relaxed) {
                        return;
                    }
                    match p.read(&mut buf) {
                        Ok(0) => {}
                        Ok(n) => {
                            let t_ms = t0.elapsed().as_millis() as u64;
                            rxbuf::push_line_pub(&lines2, t_ms, TermDir::Rx, buf[..n].to_vec());
                            if let Some(rec) = rec2.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                                let f = LiveFrame {
                                    ts_ns: t_ms * 1_000_000,
                                    ts_src: TsSrc::Wall,
                                    bus_type: BusKind::Uart,
                                    ch: 0,
                                    alias: None,
                                    dir: Dir::Rx,
                                    id: 0,
                                    id_ext: false,
                                    dlc: n,
                                    data: buf[..n].to_vec(),
                                    seq: None,
                                    meta_gap: None,
                                };
                                rec.write_line(&crate::live::live_frame_to_jsonl(&f));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(_) => {
                            // 设备拔出等读错误:留提示行并退出(写端下次 send 会报错)
                            rxbuf::push_line_pub(&lines2, t0.elapsed().as_millis() as u64, TermDir::Rx, "<<串口读错误,终端已停止>>".as_bytes().to_vec());
                            return;
                        }
                    }
                }
            })
            .ok();
    }
    // 周期发送线程
    {
        let stop2 = stop.clone();
        let wport2 = wport.clone();
        let input2 = periodic_input.clone();
        let periodic2 = periodic.clone();
        let interval2 = interval_ms.clone();
        std::thread::Builder::new()
            .name("term-tx".into())
            .spawn(move || {
                let mut next = Instant::now();
                loop {
                    if stop2.load(Ordering::Relaxed) {
                        return;
                    }
                    if !periodic2.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(100));
                        next = Instant::now();
                        continue;
                    }
                    let iv = (*interval2.lock().unwrap_or_else(|e| e.into_inner())).max(1) as u64;
                    if Instant::now() >= next {
                        let data = input2.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        if !data.is_empty() {
                            let mut g = wport2.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(port) = g.as_mut() {
                                let _ = port.write_all(data.as_bytes());
                            }
                            drop(g);
                        }
                        next = Instant::now() + Duration::from_millis(iv);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
            .ok();
    }
    Ok(TermHandle { stop, lines, wport, periodic_input, periodic, interval_ms, recorder, t0 })
}

/// 读线程内的模块级辅助(闭包 move 进线程后调不到 impl 方法;保持小而直白)
mod rxbuf {
    use super::{TermDir, TermLine};
    use std::sync::{Arc, Mutex};

    pub fn push_line_pub(lines: &Arc<Mutex<Vec<TermLine>>>, t_ms: u64, dir: TermDir, data: Vec<u8>) {
        let mut ls = lines.lock().unwrap_or_else(|e| e.into_inner());
        ls.push(TermLine { t_ms, dir, data });
        let n = ls.len();
        if n > 5000 {
            ls.drain(..n - 5000);
        }
    }
}

/// 枚举本机串口(打开表单下拉用)
pub fn list_ports() -> Vec<String> {
    match serialport::available_ports() {
        Ok(ps) => ps.into_iter().map(|p| p.port_name).collect(),
        Err(_) => vec![],
    }
}
