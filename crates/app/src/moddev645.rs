//! DL/T 645-2007 电表从机模拟(任务卡 J1 顺带项):装表前扮演一块表给 EMS/采集终端抄,
//! 验采集侧配置。复用 104/自定义从机的"TCP 监听 + 契约帧入管线"模式:
//! - 监听 TCP 端口(透明透传形态:很多采集器支持 645 over TCP),收 645 帧 → 按 DI 回寄存器值
//! - 每次请求/响应转两条契约 NDJSON(Tx=采集器请求 / Rx=表应答)推入管线——解析/曲线/规则全复用
//! - 点表 YAML:DI → 名称/init/min/max(BCD 值域内随机扰动),支持 Random/Fault 场景
//! - 地址 6 字节(低位在前 wire 形态),缺省 000000001234;广播/通配请求按标准应答
//!
//! v1 范围(与解析器同口径):只读 0x11;广播校时仅观测;不做写/费控/ESAM。
//! 串口形态(2400/Even/8/1)由用户侧串口服务器转 TCP 接入——本模块只管 TCP。

use crate::live::live_frame_to_jsonl;
use iotprobe_core::dissect::dl645;
use iotprobe_core::ingest::live::{BusKind, LiveFrame, Recorder};
use iotprobe_core::model::{Dir, TsSrc};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 一个 DI 点位(min/max/随机场景预留:接 Random/Fault 场景引擎时启用)
#[derive(Clone, Debug)]
pub struct Pt645 {
    pub di: u32,
    pub name: String,
    pub init: f64,
    pub scale: f64,
    #[allow(dead_code)] // 预留:随机场景上下界
    pub min: Option<f64>,
    #[allow(dead_code)]
    pub max: Option<f64>,
    #[allow(dead_code)] // 预留:曲线单位
    pub unit: &'static str,
}

/// 从机配置
#[derive(serde::Deserialize, Default)]
pub struct Dev645Cfg {
    #[serde(default = "d6_name")]
    pub name: String,
    #[serde(default = "d6_port")]
    #[allow(dead_code)]
    pub port: u16,
    /// 表号(BCD 显示串,如 "000000001234";wire 低位在前自动转换)
    #[serde(default = "d6_addr")]
    pub addr: String,
    #[serde(default = "d6_poll")]
    pub poll_ms: u64,
    /// DI → init(min/max)点表
    pub points: BTreeMap<String, serde_yaml_ng::Value>,
}

fn d6_name() -> String {
    "模拟645电表".into()
}
fn d6_port() -> u16 {
    6452
}
fn d6_addr() -> String {
    "000000001234".into()
}
fn d6_poll() -> u64 {
    5000
}

#[allow(dead_code)] // 预留:表号 BCD 数值化
fn bcd_of(s: &str) -> u32 {
    // "02010100" → u32(每字符一 nibble,从左到右高位→低位)
    s.chars().fold(0u32, |a, c| a * 16 + c.to_digit(16).unwrap_or(0))
}

/// 解析 645 从机配置 YAML
pub fn parse_645_yaml(text: &str) -> Result<(Dev645Cfg, Vec<Pt645>, Vec<String>), String> {
    let cfg: Dev645Cfg = serde_yaml_ng::from_str(text).map_err(|e| format!("645 点表 YAML 解析失败: {e}"))?;
    let mut warns = vec![];
    let mut pts = vec![];
    for (k, v) in &cfg.points {
        // 键 = DI 显示串(如 "02010100";YAML 数字键已被 String 化)
        let di: u32 = if let Some(hex) = k.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).map_err(|e| format!("DI 非法: {k} ({e})"))?
        } else {
            match u32::from_str_radix(k, 16) {
                Ok(v) => v,
                Err(e) => return Err(format!("DI 非法: {k} ({e})")),
            }
        };
        let m = v.as_mapping().ok_or_else(|| format!("DI {k} 配置应为映射"))?;
        let get = |key: &str| m.get(serde_yaml_ng::Value::String(key.into()));
        let name = get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let init = get("init").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let min = get("min").and_then(|x| x.as_f64());
        let max = get("max").and_then(|x| x.as_f64());
        // 645 数值倍率:DI 高字节=组(00 电量/02 电测),次字节=类(01 电压/02 电流/03 功率)
        let scale = match di >> 24 & 0xFF {
            0x00 => 0.01,
            0x02 => match di >> 16 & 0xFF {
                0x01 => 0.1,
                0x02 => 0.001,
                _ => 0.0001,
            },
            _ => 0.0001,
        };
        if name.is_empty() {
            warns.push(format!("DI {di:#010x}: 缺 name"));
        }
        let unit: &'static str = match di >> 16 & 0xFF {
            0x02 => match di >> 8 & 0xFF {
                0x01 => "V",
                0x02 => "A",
                _ => "kW",
            },
            _ => "kWh",
        };
        pts.push(Pt645 { di, name, init, scale, min, max, unit });
    }
    if pts.is_empty() {
        return Err("645 点表为空:至少一个 DI 点位".into());
    }
    Ok((cfg, pts, warns))
}

/// 地址显示串 → wire 6 字节(低位在前)
pub fn addr_to_wire(s: &str) -> [u8; 6] {
    let mut out = [0x00; 6];
    let s = s.strip_prefix("0x").unwrap_or(s);
    let digits: Vec<u8> = s.chars().filter_map(|c| c.to_digit(16).map(|d| d as u8)).collect();
    // BCD 低位在前:wire[k] = 显示串倒数第 (2k+1)(2k+2) 位;每字节高 nibble = 前一数字
    let n = digits.len();
    for k in 0..6 {
        let hi = digits.get(n.checked_sub(k * 2 + 2).unwrap_or(999)).copied().unwrap_or(0);
        let lo = digits.get(n.checked_sub(k * 2 + 1).unwrap_or(999)).copied().unwrap_or(0);
        out[k] = hi << 4 | lo;
    }
    out
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

/// 运行中的 645 从机
pub struct ModDev645Runtime {
    pub name: String,
    pub addr_display: String,
    pub stop: Arc<AtomicBool>,
    pub bus: Arc<Mutex<Vec<String>>>,
    /// DI → 当前值
    pub space: Arc<Mutex<BTreeMap<u32, f64>>>,
    pub points: Vec<Pt645>,
    #[allow(dead_code)] // 预留:周期主动上送
    pub poll_ms: u64,
    pub port_bound: bool,
    pub bound_port: u16,
}

impl ModDev645Runtime {
    pub fn stop_all(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn points_view(&self) -> Vec<(u32, String, f64)> {
        let Ok(sp) = self.space.lock() else { return vec![] };
        self.points.iter().filter_map(|d| sp.get(&d.di).map(|v| (d.di, d.name.clone(), *v))).collect()
    }

    #[allow(dead_code)] // 预留:GUI 置值按钮接 Random 场景时启用
    pub fn set_di(&self, di: u32, v: f64) -> bool {
        let Ok(mut sp) = self.space.lock() else { return false };
        if sp.contains_key(&di) {
            sp.insert(di, v);
            true
        } else {
            false
        }
    }
}

impl Drop for ModDev645Runtime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn emit645(bus: &Arc<Mutex<Vec<String>>>, dir: Dir, frame: &[u8]) {
    let f = LiveFrame {
        ts_ns: now_ns(),
        ts_src: TsSrc::Wall,
        bus_type: BusKind::Uart,
        ch: 0,
        alias: Some("645模拟".into()),
        dir,
        id: 0,
        id_ext: false,
        dlc: frame.len(),
        data: frame.to_vec(),
        seq: None,
        meta_gap: None,
    };
    bus.lock().unwrap_or_else(|e| e.into_inner()).push(live_frame_to_jsonl(&f));
}

impl ModDev645Runtime {
    pub fn start(cfg: Dev645Cfg, pts: Vec<Pt645>) -> Result<(Arc<ModDev645Runtime>, Vec<String>), String> {
        let stop = Arc::new(AtomicBool::new(false));
        let bus: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let space: Arc<Mutex<BTreeMap<u32, f64>>> =
            Arc::new(Mutex::new(pts.iter().map(|p| (p.di, p.init)).collect()));
        let mut warns = vec![];
        let addr_wire = addr_to_wire(&cfg.addr);
        let mut rt = ModDev645Runtime {
            name: cfg.name.clone(),
            addr_display: cfg.addr.clone(),
            stop: stop.clone(),
            bus: bus.clone(),
            space: space.clone(),
            points: pts.clone(),
            poll_ms: cfg.poll_ms,
            port_bound: false,
            bound_port: 0,
        };
        match TcpListener::bind(("0.0.0.0", cfg.port)) {
            Ok(listener) => {
                rt.port_bound = true;
                rt.bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(cfg.port);
                let stop2 = stop.clone();
                let pts2 = pts.clone();
                let addr2 = addr_wire;
                let ca = cfg.addr.clone();
                std::thread::Builder::new()
                    .name("moddev645-serve".into())
                    .spawn(move || serve(listener, pts2, addr2, ca, stop2, bus, space))
                    .ok();
            }
            Err(e) => warns.push(format!("绑定 0.0.0.0:{} 失败: {e}", cfg.port)),
        }
        Ok((Arc::new(rt), warns))
    }
}

#[allow(dead_code)] // 预留:随机场景
fn rand01() -> f64 {
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos() as f64 % 1000.0) / 1000.0
}

fn bcd_encode(v: f64, scale: f64, n_bytes: usize) -> Vec<u8> {
    let scaled = (v / if scale == 0.0 { 1.0 } else { scale }).round() as u64;
    let mut digits: Vec<u8> = Vec::new();
    let mut x = scaled;
    for _ in 0..n_bytes * 2 {
        digits.push((x % 10) as u8);
        x /= 10;
    }
    digits.reverse();
    // 每 2 个数字一字节,低位字节在前
    let mut out = vec![];
    for k in (0..digits.len()).step_by(2) {
        out.push(digits[k] << 4 | digits[k + 1]);
    }
    out.reverse();
    out
}

fn serve(
    listener: TcpListener,
    pts: Vec<Pt645>,
    addr_wire: [u8; 6],
    _ca: String,
    stop: Arc<AtomicBool>,
    bus: Arc<Mutex<Vec<String>>>,
    space: Arc<Mutex<BTreeMap<u32, f64>>>,
) {
    listener.set_nonblocking(true).ok();
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_nodelay(true).ok();
            stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
            let pts2 = pts.clone();
            let space2 = space.clone();
            let bus2 = bus.clone();
            let stop2 = stop.clone();
            std::thread::Builder::new()
                .name("moddev645-conn".into())
                .spawn(move || handle_conn(&mut stream, &pts2, &addr_wire, &stop2, &bus2, &space2))
                .ok();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn handle_conn(
    stream: &mut TcpStream,
    pts: &[Pt645],
    addr_wire: &[u8; 6],
    stop: &Arc<AtomicBool>,
    bus: &Arc<Mutex<Vec<String>>>,
    space: &Arc<Mutex<BTreeMap<u32, f64>>>,
) {
    let mut buf: Vec<u8> = vec![];
    let mut rb = [0u8; 512];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match stream.read(&mut rb) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&rb[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {}
            Err(_) => return,
        }
        // 定界:用解析器同款 scan(自纠逻辑共享)
        let (frames, junk) = dl645::scan(&buf);
        let consumed = frames.iter().map(|(o, l)| o + l).max().unwrap_or(0);
        let _ = junk;
        for (o, l) in frames {
            let frame: Vec<u8> = buf[o..o + l].to_vec();
            emit645(&bus, Dir::Tx, &frame); // 采集器请求 → Tx
            // 只响应读数据 0x11;广播(999999999999)/通配(AAAAAAAAAAAA)也按标准应答
            let resp = build_response(&frame, pts, &space.lock().unwrap_or_else(|e| e.into_inner()), addr_wire);
            if let Some(r) = resp {
                if stream.write_all(&r).is_err() {
                    return;
                }
                emit645(&bus, Dir::Rx, &r);
            }
        }
        buf.drain(..consumed.min(buf.len()));
    }
}

/// 构造读响应帧(0x91);非读请求/未知 DI → None(静默,与真表一致:未知 DI 回出错帧更好——回 ERR=其它错)
fn build_response(
    frame: &[u8],
    pts: &[Pt645],
    space: &BTreeMap<u32, f64>,
    _addr: &[u8; 6],
) -> Option<Vec<u8>> {
    if frame.len() < 12 {
        return None;
    }
    let ctrl = frame[8];
    let func = ctrl & 0x3F;
    if func != 0x11 || ctrl & 0x80 != 0 {
        return None; // 只应答主站读请求
    }
    let data_area = &frame[10..frame.len() - 2];
    if data_area.len() < 4 {
        return None;
    }
    let di = (data_area[0] as u32) | ((data_area[1] as u32) << 8) | ((data_area[2] as u32) << 16) | ((data_area[3] as u32) << 24);
    let Some(pt) = pts.iter().find(|p| p.di == di) else {
        // 未知 DI → 出错响应(ERR=其它错 0x01)
        return Some(build_frame_resp(frame, &[data_area[0..4].to_vec(), vec![0x01]].concat(), true));
    };
    let v = space.get(&di).copied().unwrap_or(pt.init);
    // 值 BCD 编码(电量 4B / 其他 2-4B;简化:统一 4B)
    let val_bcd = bcd_encode(v, pt.scale, 4);
    let mut data = data_area[0..4].to_vec();
    data.extend_from_slice(&val_bcd);
    Some(build_frame_resp(frame, &data, false))
}

/// 构造响应帧:回显地址/帧头,控制码 = 请求 | 0x80(异常时再 | 0x40),CS 重算
fn build_frame_resp(req: &[u8], data: &[u8], is_err: bool) -> Vec<u8> {
    let mut f = vec![0x68u8];
    f.extend_from_slice(&req[1..7]); // 地址回显
    f.push(0x68);
    let ctrl = req[8] | 0x80 | if is_err { 0x40 } else { 0 };
    f.push(ctrl);
    f.push(data.len() as u8);
    f.extend_from_slice(data);
    let cs = f.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    f.push(cs);
    f.push(0x16);
    f
}

/// 独立启停:服务线程 + NDJSON 泵线程(与 Modbus/104/自定义从机同款对接)
pub fn spawn_645(
    yaml_path: &std::path::Path,
    tx: std::sync::mpsc::Sender<crate::live::LiveMsg>,
    record_path: Option<PathBuf>,
) -> Result<(Arc<ModDev645Runtime>, Vec<String>), String> {
    let yaml = std::fs::read_to_string(yaml_path).map_err(|e| format!("读取 645 点表 {} 失败: {e}", yaml_path.display()))?;
    let (cfg, pts, mut warns) = parse_645_yaml(&yaml)?;
    let (rt, mut warns2) = ModDev645Runtime::start(cfg, pts)?;
    warns.append(&mut warns2);
    let stop = rt.stop.clone();
    let bus = rt.bus.clone();
    let t2 = tx.clone();
    std::thread::Builder::new()
        .name("moddev645-pump".into())
        .spawn(move || {
            let mut recorder = record_path
                .as_deref()
                .and_then(|p| match Recorder::create(p) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        let _ = t2.send(crate::live::LiveMsg::Info(format!("录制文件打开失败: {e}")));
                        None
                    }
                });
            let mut sess = iotprobe_core::ingest::live::LiveSession::new(None);
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
                    if let Some(rec) = sess.map_line(l) {
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
                        labels: sess.labels(),
                        stats: Some(sess.stats()),
                        epoch_ns: sess.epoch_ns(),
                        warnings: sess.take_warnings(),
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
name: 测试645电表
port: 0
addr: "000000001234"
poll_ms: 0
points:
  "02010100": {name: A相电压, init: 220.1, min: 200, max: 240}
  "00000000": {name: 有功总电量, init: 1500.25}
"#;

    #[test]
    fn parse_and_respond_read() {
        // 点表解析 + 读请求回响应(端到端最小闭环:模拟器直接回 645 帧)
        let (cfg, pts, warns) = parse_645_yaml(YAML).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(pts.len(), 2);
        // 地址 wire 转换:000000001234 → [34,12,00,00,00,00]
        let wire = addr_to_wire(&cfg.addr);
        assert_eq!(wire, [0x34, 0x12, 0x00, 0x00, 0x00, 0x00]);
        // 值编码:220.1V 电压 ×0.1 → BCD 2201 → [0x01, 0x22, 0x00, 0x00]
        let pt = pts.iter().find(|p| p.di == 0x02010100).unwrap();
        let enc = bcd_encode(220.1, pt.scale, 4);
        assert_eq!(enc, vec![0x01, 0x22, 0x00, 0x00], "BCD 编码应低位字节在前");
        // 起服务并读
        let (rt, warns2) = ModDev645Runtime::start(cfg, pts).unwrap();
        assert!(warns2.is_empty(), "{warns2:?}");
        assert!(rt.port_bound);
        let mut c = TcpStream::connect(("127.0.0.1", rt.bound_port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // 主站读 A相电压(0x11,DI 02010100)
        let mut req = vec![0x68u8];
        req.extend_from_slice(&addr_to_wire(&rt.addr_display));
        req.push(0x68);
        req.push(0x11);
        req.push(0x04);
        req.extend_from_slice(&0x02010100u32.to_le_bytes()); // DI 低位在前
        let cs = req.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        req.push(cs);
        req.push(0x16);
        c.write_all(&req).unwrap();
        let mut buf = vec![0u8; 64];
        let n = std::io::Read::read(&mut c, &mut buf).unwrap();
        // 响应:68 + addr + 68 + 91 + 0A + DI + BCD值 + CS + 16
        assert_eq!(buf[0], 0x68);
        assert_eq!(buf[8], 0x91);
        assert_eq!(buf[9], 0x08, "响应 DATA 8B(DI4+BCD4)");
        let resp_cs = buf[18];
        let cs_calc = buf[..18].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        assert_eq!(resp_cs, cs_calc, "CS 校验");
        assert_eq!(buf[19], 0x16);
        rt.stop_all();
    }

    #[test]
    fn unknown_di_returns_err() {
        let (cfg, pts, _w) = parse_645_yaml(YAML).unwrap();
        let (rt, _w2) = ModDev645Runtime::start(cfg, pts).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", rt.bound_port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // 读未定义 DI
        let mut req = vec![0x68u8];
        req.extend_from_slice(&addr_to_wire(&rt.addr_display));
        req.push(0x68);
        req.push(0x11);
        req.push(0x04);
        req.extend_from_slice(&0x99999999u32.to_le_bytes());
        let cs = req.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        req.push(cs);
        req.push(0x16);
        c.write_all(&req).unwrap();
        let mut buf = vec![0u8; 64];
        let n = std::io::Read::read(&mut c, &mut buf).unwrap();
        // 出错响应:ctrl = 91|40|80? → 0xD1,ERR 字节在 DI 后
        assert_eq!(buf[8], 0xD1, "异常响应控制码");
        
        rt.stop_all();
    }
}
