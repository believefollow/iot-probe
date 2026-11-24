//! 自定义协议从机模拟(任务卡 A6):用 CustomSpec(JSON DSL)扮演未知/自定义协议的从机端。
//! - 接收:deframe 定界 → 逐字段解码 → 全部字段值进存储(联调时看到主机发了什么)
//! - 应答:echo=true 时原帧回显(主机拿到字节级回环,RTT/校验联调);echo=false 静默
//! - 自轮询:按 spec 反向编码一帧(全部字段写当前存储值 + 长度域/校验重算),poll_ms 周期发数
//!   —— 没有主机连入曲线也滚动,与 Modbus/104 模拟器同款体验
//! - 帧进同一管线:bus=tcp 一行一帧(ADR-0017),custom_stream_best 识别后字段/曲线/规则全复用
//! - 限制:bits 字段不参与编码(独立存储随宿主字节);bytes 字段按 0 填充

use crate::live::live_frame_to_jsonl;
use iotprobe_core::dissect::custom::{deframe, hex_to_bytes, parse_spec, CustomSpec, FieldSpec};
use iotprobe_core::ingest::live::{BusKind, LiveFrame, Recorder};
use iotprobe_core::model::{Dir, TsSrc};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 运行中的自定义协议从机
pub struct ModDevCustomRuntime {
    pub spec: CustomSpec,
    pub poll_ms: u64,
    pub echo: bool,
    pub stop: Arc<AtomicBool>,
    pub bus: Arc<Mutex<Vec<String>>>,
    /// 字段名 → 当前值(GUI 置值 / 主机写入更新)
    pub values: Arc<Mutex<BTreeMap<String, f64>>>,
    pub port_bound: bool,
    pub bound_port: u16,
}

impl ModDevCustomRuntime {
    /// GUI 字段视图:(名称, 类型, 当前值)
    pub fn fields_view(&self) -> Vec<(String, String, f64)> {
        let Ok(v) = self.values.lock() else { return vec![] };
        self.spec
            .fields
            .iter()
            .filter_map(|f| v.get(&f.name).map(|x| (f.name.clone(), f.ty.clone(), *x)))
            .collect()
    }

    /// GUI 置值
    pub fn set_field(&self, name: &str, v: f64) -> bool {
        let Ok(mut m) = self.values.lock() else { return false };
        if m.contains_key(name) {
            m.insert(name.to_string(), v);
            true
        } else {
            false
        }
    }

    pub fn stop_all(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for ModDevCustomRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// 启动配置(spec JSON + 端口/节拍/回显)
#[derive(serde::Deserialize, Default)]
pub struct CustomSlaveCfg {
    pub spec: Option<String>,
    pub spec_file: Option<String>,
    #[serde(default = "d_port")]
    pub port: u16,
    #[serde(default = "d_poll")]
    pub poll_ms: u64,
    #[serde(default = "d_echo")]
    pub echo: bool,
    #[serde(default)]
    pub init: BTreeMap<String, f64>,
}

fn d_port() -> u16 {
    9000
}
fn d_poll() -> u64 {
    1000
}
fn d_echo() -> bool {
    true
}

/// 解析从机配置:spec 内联 JSON 或 spec_file 路径
pub fn parse_custom_slave_yaml(text: &str, base_dir: &std::path::Path) -> Result<(CustomSlaveCfg, CustomSpec, Vec<String>), String> {
    let cfg: CustomSlaveCfg = serde_yaml_ng::from_str(text).map_err(|e| format!("自定义从机 YAML 解析失败: {e}"))?;
    let spec_json = match (&cfg.spec, &cfg.spec_file) {
        (Some(j), _) => j.clone(),
        (None, Some(f)) => {
            let p = if std::path::Path::new(f).is_absolute() { PathBuf::from(f) } else { base_dir.join(f) };
            std::fs::read_to_string(&p).map_err(|e| format!("读取 spec_file {f} 失败: {e}"))?
        }
        _ => return Err("自定义从机 YAML 缺 spec(内联 JSON)或 spec_file(路径)".into()),
    };
    let spec = parse_spec(&spec_json)?;
    Ok((cfg, spec, vec![]))
}

// ---------- 帧编码(按 spec 反向构建) ----------

fn field_ty_size(f: &FieldSpec) -> usize {
    match f.ty.as_str() {
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        _ => 1,
    }
    .max(f.size.unwrap_or(1) as usize)
    .min(f.size.map(|s| s as usize).unwrap_or(usize::MAX))
}

/// 把值按字段定义编码写进帧
fn write_field(buf: &mut [u8], f: &FieldSpec, v: f64) {
    let at = f.at as usize;
    let le = matches!(f.endian, iotprobe_core::dissect::custom::Endian::Little);
    let physical = v / if f.scale == 0.0 { 1.0 } else { f.scale } - f.offset;
    let put = |b: &mut [u8], i: usize, n: usize, raw: u64| {
        for k in 0..n {
            let byte = ((raw >> (8 * k)) & 0xFF) as u8;
            let idx = if le { i + k } else { i + n - 1 - k };
            if idx < b.len() {
                b[idx] = byte;
            }
        }
    };
    match f.ty.as_str() {
        "u8" => put(buf, at, 1, physical.round().clamp(0.0, 255.0) as u64),
        "i8" => put(buf, at, 1, (physical.round().clamp(-128.0, 127.0) as i8) as u64),
        "u16" => put(buf, at, 2, physical.round().clamp(0.0, 65535.0) as u64),
        "i16" => put(buf, at, 2, (physical.round().clamp(-32768.0, 32767.0) as i16) as u64),
        "u32" => put(buf, at, 4, physical.round().clamp(0.0, u32::MAX as f64) as u64),
        "i32" => put(buf, at, 4, (physical.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32) as u64),
        "u64" => put(buf, at, 8, physical.round().clamp(0.0, u64::MAX as f64 / 2.0) as u64),
        "i64" => put(buf, at, 8, (physical.round().clamp(i64::MIN as f64 / 2.0, i64::MAX as f64 / 2.0) as i64) as u64),
        "f32" => {
            let raw = ((physical as f32).to_bits()) as u64;
            put(buf, at, 4, raw);
        }
        "f64" => {
            let raw = physical.to_bits();
            put(buf, at, 8, raw);
        }
        "bool" => put(buf, at, 1, if physical != 0.0 { 1 } else { 0 }),
        _ => {} // bits/bytes:v1 不编码(见模块头)
    }
}

/// 校验算法(与 custom::decode 支持一致)
fn compute_cks(algo: &str, bytes: &[u8]) -> Vec<u8> {
    match algo {
        "crc16_modbus" => {
            let c = iotprobe_core::crc::crc16_modbus(bytes);
            vec![c as u8, (c >> 8) as u8]
        }
        "crc16_ccitt" | "crc16_xmodem" => {
            // 与 dissect 侧同源:xmodem/ccitt 均为 CCITT-FALSE 初值 0xFFFF
            let mut c: u16 = 0xFFFF;
            for b in bytes {
                c ^= (*b as u16) << 8;
                for _ in 0..8 {
                    c = if c & 0x8000 != 0 { (c << 1) ^ 0x1021 } else { c << 1 };
                }
            }
            vec![(c >> 8) as u8, c as u8]
        }
        "sum8" => vec![bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b))],
        "xor8" => vec![bytes.iter().fold(0u8, |a, b| a ^ *b)],
        "lrc" => vec![bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)).wrapping_neg()],
        _ => vec![],
    }
}

/// 按 spec 构建一帧:sync + 字段值 + 长度域 + 校验
pub fn build_frame(spec: &CustomSpec, values: &BTreeMap<String, f64>) -> Vec<u8> {
    // 帧长:固定 > 字段最大端 + 校验宽度
    let cks_len = spec.checksum.as_ref().map(|c| if c.algo.starts_with("crc16") { 2 } else { 1 }).unwrap_or(0);
    let max_end = spec
        .fields
        .iter()
        .map(|f| f.at as usize + field_ty_size(f))
        .max()
        .unwrap_or(spec.min_len as usize);
    let total = spec.frame_len.map(|x| x as usize).unwrap_or_else(|| max_end.max(spec.min_len as usize) + cks_len);
    let mut buf = vec![0u8; total];
    if let Some(sy) = &spec.sync {
        let sb = hex_to_bytes(sy);
        for (k, b) in sb.iter().enumerate() {
            if k < total {
                buf[k] = *b;
            }
        }
    }
    for f in &spec.fields {
        if let Some(v) = values.get(&f.name) {
            write_field(&mut buf, f, *v);
        }
    }
    // 长度域重算
    if let Some(len) = &spec.length {
        let at = len.at.resolve(total).unwrap_or(0);
        let val: u32 = if len.include_header { total as u32 } else { (total as i64 - 2 - len.bias as i64).max(0) as u32 };
        let size = len.size.max(1) as usize;
        let le = matches!(len.endian, iotprobe_core::dissect::custom::Endian::Little);
        for k in 0..size.min(4) {
            let byte = ((val >> (8 * k)) & 0xFF) as u8;
            let idx = if le { at + k } else { at + size - 1 - k };
            if idx < total {
                buf[idx] = byte;
            }
        }
    }
    // 校验重算
    if let Some(cks) = &spec.checksum {
        let (from, to) = (&cks.cover.0, &cks.cover.1);
        let f0 = from.resolve(total).unwrap_or(0);
        let t1 = to.resolve(total).unwrap_or(total);
        if f0 < t1 && t1 <= total {
            let c = compute_cks(&cks.algo, &buf[f0..t1]);
            let at = cks.at.as_ref().and_then(|a| a.resolve(total)).unwrap_or(t1);
            for (k, b) in c.iter().enumerate() {
                if at + k < total {
                    buf[at + k] = *b;
                }
            }
        }
    }
    buf
}

// ---------- 运行 ----------

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

fn emit(bus: &Arc<Mutex<Vec<String>>>, dir: Dir, frame: &[u8]) {
    let f = LiveFrame {
        ts_ns: now_ns(),
        ts_src: TsSrc::Sw,
        bus_type: BusKind::Tcp,
        ch: 0,
        alias: None,
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

/// 字段值解码(轻量:不复用 decode 的字段树,直接按定义读数值)
fn read_fields(frame: &[u8], spec: &CustomSpec) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for f in &spec.fields {
        let n = field_ty_size(f);
        let at = f.at as usize;
        if at + n > frame.len() {
            continue;
        }
        let le = matches!(f.endian, iotprobe_core::dissect::custom::Endian::Little);
        let mut raw: u64 = 0;
        for k in 0..n {
            let b = frame[at + k] as u64;
            raw |= if le { b << (8 * k) } else { b << (8 * (n - 1 - k)) };
        }
        let v = match f.ty.as_str() {
            "u8" | "u16" | "u32" | "u64" => raw as f64,
            "i8" => (raw as u8) as i8 as f64,
            "i16" => (raw as u16) as i16 as f64,
            "i32" => (raw as u32) as i32 as f64,
            "i64" => (raw as u64) as i64 as f64,
            "f32" => f32::from_bits(raw as u32) as f64,
            "f64" => f64::from_bits(raw),
            "bool" => (raw != 0) as i32 as f64,
            _ => continue,
        };
        out.insert(f.name.clone(), v * if f.scale == 0.0 { 1.0 } else { f.scale } + f.offset);
    }
    out
}

impl ModDevCustomRuntime {
    pub fn start(cfg: CustomSlaveCfg, spec: CustomSpec) -> Result<(Arc<ModDevCustomRuntime>, Vec<String>), String> {
        let stop = Arc::new(AtomicBool::new(false));
        let bus: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let values: Arc<Mutex<BTreeMap<String, f64>>> = Arc::new(Mutex::new(BTreeMap::new()));
        {
            let mut m = values.lock().unwrap_or_else(|e| e.into_inner());
            for f in &spec.fields {
                let init = cfg.init.get(&f.name).copied().unwrap_or(0.0);
                m.insert(f.name.clone(), init);
            }
        }
        let mut warns = vec![];
        let mut rt = ModDevCustomRuntime {
            spec,
            poll_ms: cfg.poll_ms,
            echo: cfg.echo,
            stop: stop.clone(),
            bus: bus.clone(),
            values: values.clone(),
            port_bound: false,
            bound_port: 0,
        };
        match TcpListener::bind(("0.0.0.0", cfg.port)) {
            Ok(listener) => {
                rt.port_bound = true;
                rt.bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(cfg.port);
                let stop2 = stop.clone();
                let spec2 = rt.spec.clone();
                let values2 = values.clone();
                let bus2 = bus.clone();
                let echo = cfg.echo;
                std::thread::Builder::new()
                    .name("moddev-custom-serve".into())
                    .spawn(move || serve(listener, spec2, echo, stop2, bus2, values2))
                    .ok();
            }
            Err(e) => warns.push(format!("绑定 0.0.0.0:{} 失败: {e}(端口被占?)", cfg.port)),
        }
        // 自轮询线程:按 spec 编码周期发数(与连接无关,总线侧持续有帧)
        {
            let stop2 = stop.clone();
            let bus2 = bus.clone();
            let spec2 = rt.spec.clone();
            let values2 = values.clone();
            let poll = rt.poll_ms.max(50);
            std::thread::Builder::new()
                .name("moddev-custom-poll".into())
                .spawn(move || {
                    let mut next = Instant::now() + Duration::from_millis(poll);
                    loop {
                        if stop2.load(Ordering::Relaxed) {
                            return;
                        }
                        if Instant::now() >= next {
                            let frame = {
                                let v = values2.lock().unwrap_or_else(|e| e.into_inner());
                                build_frame(&spec2, &v)
                            };
                            emit(&bus2, Dir::Rx, &frame); // 从机侧发出的帧 → Rx(事务配对口径与 Modbus 一致)
                            next = Instant::now() + Duration::from_millis(poll);
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                })
                .ok();
        }
        Ok((Arc::new(rt), warns))
    }
}

fn serve(listener: TcpListener, spec: CustomSpec, echo: bool, stop: Arc<AtomicBool>, bus: Arc<Mutex<Vec<String>>>, values: Arc<Mutex<BTreeMap<String, f64>>>) {
    listener.set_nonblocking(true).ok();
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if let Ok((stream, _)) = listener.accept() {
            stream.set_nodelay(true).ok();
            stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
            let spec2 = spec.clone();
            let values2 = values.clone();
            let bus2 = bus.clone();
            let stop2 = stop.clone();
            std::thread::Builder::new()
                .name("moddev-custom-conn".into())
                .spawn(move || handle_conn(stream, spec2, echo, stop2, bus2, values2))
                .ok();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn handle_conn(mut stream: TcpStream, spec: CustomSpec, echo: bool, stop: Arc<AtomicBool>, bus: Arc<Mutex<Vec<String>>>, values: Arc<Mutex<BTreeMap<String, f64>>>) {
    let mut buf: Vec<u8> = vec![];
    let mut rb = [0u8; 4096];
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
        if buf.is_empty() {
            continue;
        }
        // 定界:先取帧(偏移基于当前 buf),再按最大消费位移
        let (frames, _junk) = deframe(&buf, &spec);
        let consumed = frames.iter().map(|(o, l)| o + l).max().unwrap_or(0);
        for (off, len) in frames {
            let frame: Vec<u8> = buf[off..off + len].to_vec();
            emit(&bus, Dir::Tx, &frame); // 主机帧 → Tx
            // 全部字段解码进存储(联调可见主机写了什么)
            let fields = read_fields(&frame, &spec);
            if !fields.is_empty() {
                let mut m = values.lock().unwrap_or_else(|e| e.into_inner());
                for (k, v) in fields {
                    m.insert(k, v);
                }
            }
            // 回显(主机拿到字节级回环:RTT/校验联调)
            if echo && stream.write_all(&frame).is_err() {
                return;
            }
        }
        buf.drain(..consumed.min(buf.len()));
    }
}

/// 独立启停:服务线程 + NDJSON→管线泵线程(与 Modbus/104 模拟器同款对接)
pub fn spawn_custom_slave(
    yaml_path: &std::path::Path,
    tx: std::sync::mpsc::Sender<crate::live::LiveMsg>,
    record_path: Option<PathBuf>,
    tee: Option<Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>>,
) -> Result<(Arc<ModDevCustomRuntime>, Vec<String>), String> {
    let base = yaml_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    let yaml = std::fs::read_to_string(yaml_path).map_err(|e| format!("读取自定义从机配置 {} 失败: {e}", yaml_path.display()))?;
    let (cfg, spec, mut warns) = parse_custom_slave_yaml(&yaml, &base)?;
    let (rt, mut warns2) = ModDevCustomRuntime::start(cfg, spec)?;
    warns.append(&mut warns2);
    let stop = rt.stop.clone();
    let bus = rt.bus.clone();
    let t2 = tx.clone();
    std::thread::Builder::new()
        .name("moddev-custom-pump".into())
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
                    // 帧流转发 tee(W):契约行推给外部消费方(与 Pipeline 行为一致)
                    if let Some(slot) = &tee {
                        if let Ok(g) = slot.lock() {
                            if let Some(sender) = g.as_ref() {
                                let _ = sender.send(l.clone());
                            }
                        }
                    }
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

    /// 验证 A6:build_frame 按值域编码 + 长度域/校验重算;收到的帧能被 deframe 定界并读回同值
    const SPEC: &str = r#"{"name":"测试协议","sync":"AA55","length":{"at":2,"size":2,"endian":"big","include_header":true},"checksum":{"algo":"crc16_modbus","cover":[0,"end-2"],"at":"end-2"},"fields":[{"name":"电压","at":4,"ty":"u16","endian":"big","scale":0.1,"unit":"V"},{"name":"电流","at":6,"ty":"u16","endian":"little","scale":0.01},{"name":"运行","at":8,"ty":"bool"}]}"#;

    fn spec_of() -> CustomSpec {
        parse_spec(SPEC).unwrap()
    }

    #[test]
    fn build_frame_roundtrip() {
        let spec = spec_of();
        let mut vals = BTreeMap::new();
        vals.insert("电压".to_string(), 220.5);
        vals.insert("电流".to_string(), 5.25);
        vals.insert("运行".to_string(), 1.0);
        let frame = build_frame(&spec, &vals);
        // 结构:sync 2 + len 2 + 电压 2 + 电流 2 + bool 1 + cks 2 = 11B(长度域 include_header=true → 值=11)
        assert_eq!(frame.len(), 11, "帧长 = 字段最大端 9 + cks 2");
        assert_eq!(&frame[..2], &[0xAA, 0x55]);
        assert_eq!(((frame[2] as u16) << 8) | frame[3] as u16, 11, "长度域=总帧长");
        // 电压 220.5/0.1=2205=0x089D big-endian
        assert_eq!(&frame[4..6], &[0x08, 0x9D]);
        // 电流 5.25/0.01=525=0x020D little-endian
        assert_eq!(&frame[6..8], &[0x0D, 0x02]);
        assert_eq!(frame[8], 1);
        // 校验:crc16_modbus over [0..9)
        let c = iotprobe_core::crc::crc16_modbus(&frame[..9]);
        assert_eq!(&frame[9..11], &[c as u8, (c >> 8) as u8]);
        // 收方视角:deframe 定界 + read_fields 读回同值(缩放还原)
        let (frames, junk) = deframe(&frame, &spec);
        assert_eq!(junk, 0, "自编码帧应零垃圾定界");
        assert_eq!(frames.len(), 1);
        let got = read_fields(&frame, &spec);
        assert!((got["电压"] - 220.5).abs() < 1e-6, "电压读回: {}", got["电压"]);
        assert!((got["电流"] - 5.25).abs() < 1e-6, "电流读回: {}", got["电流"]);
        assert_eq!(got["运行"], 1.0);
    }

    #[test]
    fn echo_slave_roundtrip() {
        // A6 从机行为:收帧 → 字段更新 → 原帧回显(客户联调口径)
        let (rt, warns) = {
            let cfg_txt = format!(
                r#"spec: |
  {}
port: 0
poll_ms: 0
echo: true
init: {{电压: 0.0}}
"#,
                SPEC.replace('\n', "\n  ")
            );
            let base = std::env::temp_dir();
            let p = base.join(format!("iotprobe_custom_test_{}.yaml", std::process::id()));
            std::fs::write(&p, &cfg_txt).unwrap();
            let (rt, w) = spawn_custom_slave(&p, std::sync::mpsc::channel().0, None, None).unwrap();
            let _ = std::fs::remove_file(&p);
            (rt, w)
        };
        assert!(warns.is_empty(), "{warns:?}");
        assert!(rt.port_bound);
        // 主机视角:发一帧构造帧 → 应收到字节级回显
        let addr = if rt.bound_port > 0 { "127.0.0.1" } else { unreachable!() };
        let mut c = std::net::TcpStream::connect((addr, rt.bound_port)).unwrap();
        let mut vals = BTreeMap::new();
        vals.insert("电压".to_string(), 230.0);
        vals.insert("电流".to_string(), 1.0);
        vals.insert("运行".to_string(), 0.0);
        let frame = build_frame(&rt.spec, &vals);
        c.write_all(&frame).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut echo = vec![0u8; frame.len()];
        std::io::Read::read_exact(&mut c, &mut echo).unwrap();
        assert_eq!(echo, frame, "回显应字节一致");
        // 字段值已更新
        let v = rt.values.lock().unwrap_or_else(|e| e.into_inner());
        assert!((v["电压"] - 230.0).abs() < 1e-6);
        rt.stop_all();
    }
}
