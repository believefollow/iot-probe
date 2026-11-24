//! 发送面板(FR-4.7/FR-10.4/FR-10.5):
//! - TxHub:UI ↔ live 线程 之间的发送队列(ZLG 适配器 poll 时排空并 ZCAN_Transmit)
//! - FR-10.4 只读默认:enabled 原子开关,UI 显式「解锁发送」才置位
//! - FR-10.5 白名单:id 白名单(单 id / 区间),入队与出队双重校验,越界拒绝并告警

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct SendEntry {
    pub id: u32,
    pub ext: bool,
    pub fd: bool,
    pub brs: bool,
    pub data: Vec<u8>,
    /// None = 单次;Some(n) = 周期 n 毫秒重发
    pub interval_ms: Option<u64>,
    pub last: Option<Instant>,
}

/// 白名单:All(未配置,但仍受 enabled 门控)/ 单 id 列表 / id 区间
#[derive(Clone, Debug)]
pub enum Whitelist {
    All,
    Ids(Vec<(u32, u32)>), // [start, end] 闭区间列表
}

impl Whitelist {
    pub fn allows(&self, id: u32) -> bool {
        match self {
            Whitelist::All => true,
            Whitelist::Ids(ranges) => ranges.iter().any(|(a, b)| id >= *a && id <= *b),
        }
    }
}

/// 解析数据十六进制串:"01 02 3F"(空格分隔)→ 字节
pub fn parse_data_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.is_empty() {
        return Some(vec![]);
    }
    if cleaned.len() % 2 != 0 {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&cleaned[k..k + 2], 16).ok())
        .collect()
}

/// 解析白名单文本:"0x1A0, 0x200-0x2FF"(十进制/0x 十六进制混排,区间用 -)
pub fn parse_whitelist(text: &str) -> Result<Whitelist, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(Whitelist::All);
    }
    let mut ranges = vec![];
    for part in t.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let parse = |s: &str| -> Result<u32, String> {
            let s = s.trim();
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(h, 16).map_err(|_| format!("非法 id '{s}'"))
            } else {
                s.parse::<u32>().map_err(|_| format!("非法 id '{s}'"))
            }
        };
        if let Some((a, b)) = p.split_once('-') {
            let a = parse(a)?;
            let b = parse(b)?;
            if a > b {
                return Err(format!("区间反了: {a}-{b}"));
            }
            ranges.push((a, b));
        } else {
            let v = parse(p)?;
            ranges.push((v, v));
        }
    }
    if ranges.is_empty() {
        return Ok(Whitelist::All);
    }
    Ok(Whitelist::Ids(ranges))
}

pub struct TxHub {
    queue: Mutex<VecDeque<SendEntry>>,
    pub enabled: AtomicBool,
    pub whitelist: Mutex<Whitelist>,
    pub rejected: std::sync::atomic::AtomicUsize,
}

impl Default for TxHub {
    fn default() -> Self {
        Self::new()
    }
}

impl TxHub {
    pub fn new() -> Self {
        TxHub {
            queue: Mutex::new(VecDeque::new()),
            enabled: AtomicBool::new(false),
            whitelist: Mutex::new(Whitelist::All),
            rejected: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// 入队(FR-10.4/10.5:未解锁或越白名单一律拒绝)。返回 Err = 拒绝原因。
    pub fn enqueue(&self, mut e: SendEntry) -> Result<(), String> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Err("发送未解锁(FR-10.4:显式解锁后才可发送)".into());
        }
        if e.data.len() > (if e.fd { 64 } else { 8 }) {
            return Err(format!("数据长度 {} 超出 {} 上限", e.data.len(), if e.fd { 64 } else { 8 }));
        }
        let wl = self.whitelist.lock().unwrap();
        if !wl.allows(e.id) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(format!("id 0x{:X} 不在发送白名单内(FR-10.5)", e.id));
        }
        drop(wl);
        e.last = None;
        self.queue.lock().unwrap().push_back(e);
        Ok(())
    }

    /// live 线程排空:单次帧出队;周期帧到点克隆并续期
    pub fn pop_due(&self) -> Vec<SendEntry> {
        if !self.enabled.load(Ordering::Relaxed) {
            return vec![];
        }
        let now = Instant::now();
        let wl = self.whitelist.lock().unwrap().clone();
        let mut q = self.queue.lock().unwrap();
        let mut out = vec![];
        let len = q.len();
        let mut keep: VecDeque<SendEntry> = VecDeque::with_capacity(len);
        for mut e in q.drain(..) {
            if !wl.allows(e.id) {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                continue; // 白名单变了:拦截已入队项
            }
            let due = match e.interval_ms {
                None => true,
                Some(iv) => match e.last {
                    None => true,
                    Some(t) => now.saturating_duration_since(t) >= Duration::from_millis(iv.max(1)),
                },
            };
            if due {
                out.push(e.clone());
                match e.interval_ms {
                    None => continue, // 单次:出队不保留
                    Some(_) => {
                        e.last = Some(now);
                        keep.push_back(e); // 周期:续期
                    }
                }
            } else {
                keep.push_back(e);
            }
        }
        *q = keep;
        out
    }

    pub fn clear(&self) {
        self.queue.lock().unwrap().clear();
    }

    pub fn pending(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_hex_parse() {
        assert_eq!(parse_data_hex("01 02 3F"), Some(vec![1, 2, 0x3F]));
        assert_eq!(parse_data_hex("01023F"), Some(vec![1, 2, 0x3F]));
        assert_eq!(parse_data_hex("01 0"), None);
        assert_eq!(parse_data_hex(""), Some(vec![]));
    }

    #[test]
    fn whitelist_parse_and_allow() {
        let w = parse_whitelist("0x1A0, 0x200-0x2FF, 256").unwrap();
        assert!(w.allows(0x1A0));
        assert!(w.allows(0x250));
        assert!(w.allows(256));
        assert!(!w.allows(0x300));
        assert!(matches!(parse_whitelist("0x2FF-0x200"), Err(_)));
        assert!(matches!(parse_whitelist("0xGG"), Err(_)));
        assert!(matches!(parse_whitelist(""), Ok(Whitelist::All)));
    }

    #[test]
    fn hub_gating_and_periods() {
        let hub = TxHub::new();
        let e = SendEntry {
            id: 0x100,
            ext: false,
            fd: false,
            brs: false,
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            interval_ms: None,
            last: None,
        };
        // FR-10.4:默认未解锁 → 拒绝
        assert!(hub.enqueue(e.clone()).is_err());
        hub.enabled.store(true, Ordering::Relaxed);
        // FR-10.5:越白名单 → 拒绝
        *hub.whitelist.lock().unwrap() = parse_whitelist("0x200-0x300").unwrap();
        assert!(hub.enqueue(e.clone()).is_err());
        assert_eq!(hub.rejected.load(Ordering::Relaxed), 1);
        *hub.whitelist.lock().unwrap() = parse_whitelist("").unwrap();
        assert!(hub.enqueue(e.clone()).is_ok());
        assert_eq!(hub.pop_due().len(), 1);
        assert_eq!(hub.pop_due().len(), 0, "单次帧出队后不再重复");
        // 周期帧:出队后保留
        let p = SendEntry { interval_ms: Some(50), ..e.clone() };
        hub.enqueue(p).unwrap();
        assert_eq!(hub.pop_due().len(), 1);
        assert_eq!(hub.pop_due().len(), 0, "未到周期");
        std::thread::sleep(Duration::from_millis(55));
        assert_eq!(hub.pop_due().len(), 1, "周期到点");
        hub.clear();
        assert_eq!(hub.pending(), 0);
    }
}

/// 回放注入(P2):录制的抓包帧按时间轴(可加速)发往真实总线。
/// 白名单预检在启动时完成;hub 入队仍二次校验(FR-10.4/10.5 不变)。急停即停。
pub struct InjHandle {
    pub stop: std::sync::Arc<AtomicBool>,
    pub sent: Arc<AtomicUsize>,
    pub skipped: Arc<AtomicUsize>,
    pub total: usize,
}

impl InjHandle {
    pub fn progress(&self) -> (usize, usize, usize) {
        (self.sent.load(Ordering::Relaxed), self.skipped.load(Ordering::Relaxed), self.total)
    }
}

/// frames: (t_ns 相对时间, id, ext, data)——已过白名单预检;speed<=0 = 极速(不等待)
pub fn spawn_injection(
    frames: Vec<(u64, u32, bool, Vec<u8>)>,
    speed: f64,
    hub: Arc<TxHub>,
) -> InjHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));
    let total = frames.len();
    let (stop2, sent2, skipped2) = (stop.clone(), sent.clone(), skipped.clone());
    std::thread::Builder::new()
        .name("tx-inject".into())
        .spawn(move || {
            let mut prev: Option<u64> = None;
            for (t_ns, id, ext, data) in frames {
                if stop2.load(Ordering::Relaxed) {
                    return;
                }
                if let Some(p) = prev {
                    let dt_ns = t_ns.saturating_sub(p);
                    if speed > 0.0 && dt_ns > 0 {
                        let wait_us = (dt_ns as f64 / 1_000.0 / speed) as u64;
                        let deadline = Instant::now() + Duration::from_micros(wait_us);
                        while Instant::now() < deadline {
                            if stop2.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
                prev = Some(t_ns);
                // FD 修复:录制层无 fd 标志,>8B 载荷必为 CAN FD(否则经典帧入队即拒)
                let entry = SendEntry { id, ext, fd: data.len() > 8, brs: false, data, interval_ms: None, last: None };
                match hub.enqueue(entry) {
                    Ok(()) => sent2.fetch_add(1, Ordering::Relaxed),
                    Err(_) => skipped2.fetch_add(1, Ordering::Relaxed),
                };
            }
        })
        .expect("启动注入线程失败");
    InjHandle { stop, sent, skipped, total }
}
