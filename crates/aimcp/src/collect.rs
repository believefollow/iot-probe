//! 帧收集:serbox TCP 3333 直连 / 回放 .ndjson 文件 → Record 列表。
//!
//! 复用 core 的 live 管线(LineSplitter + LiveSession),与 GUI 实时接入同一套解析器。
//! 与 core::live::pump 的差别:这里带收集上限(max_frames / seconds / 空闲超时),
//! 保证 AI 调用工具时总能「有限时间内返回」,不会挂在无界读取上。

use iotprobe_core::ingest::live::Pipeline;
// 再导出:session.rs 的会话统计字段类型
pub use iotprobe_core::ingest::live::LiveStats;
use iotprobe_core::model::Record;
use std::collections::HashMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// 收集上限的默认值(TCP 源必带,避免工具调用无限阻塞)
pub const DEFAULT_MAX_FRAMES: usize = 200;
/// TCP 源默认最长收集时长(秒)
pub const DEFAULT_SECONDS: f64 = 10.0;
/// 连接超时(秒)
pub const CONNECT_TIMEOUT_S: u64 = 5;
/// TCP 空闲超时:这么久没有新数据就认为「这一波帧发完了」,提前返回
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(3);
/// 硬上限:防止参数给得过大把上下文/内存撑爆
pub const HARD_MAX_FRAMES: usize = 100_000;

/// 收集停止原因(返回给 AI,便于理解拿到多少帧)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// 对端关闭 / 文件读完
    Eof,
    /// 达到 max_frames
    MaxFrames,
    /// 达到 seconds 时限
    SecondsElapsed,
    /// 空闲超时(连续 IDLE_TIMEOUT 无新数据)
    IdleTimeout,
    /// 文件内容短于 max_frames,自然读完
    FileEof,
}

impl StopReason {
    pub fn label(&self) -> &'static str {
        match self {
            StopReason::Eof => "eof",
            StopReason::MaxFrames => "max_frames",
            StopReason::SecondsElapsed => "seconds",
            StopReason::IdleTimeout => "idle_timeout",
            StopReason::FileEof => "eof",
        }
    }
    pub fn text(&self) -> &'static str {
        match self {
            StopReason::Eof => "对端关闭连接",
            StopReason::MaxFrames => "达到 max_frames 上限",
            StopReason::SecondsElapsed => "达到 seconds 时限",
            StopReason::IdleTimeout => "空闲超时(连续 3s 无新数据,认为这一波帧已结束)",
            StopReason::FileEof => "文件读完",
        }
    }
}

/// 一次收集的结果
#[derive(Clone)]
pub struct CollectResult {
    pub records: Vec<Record>,
    pub labels: HashMap<u16, String>,
    pub warnings: Vec<String>,
    pub epoch_ns: Option<u64>,
    pub stats: LiveStats,
    pub stop: StopReason,
}

impl CollectResult {
    /// 截断警告条数(防上下文爆炸)
    pub fn warnings_capped(&self, n: usize) -> Vec<String> {
        let mut v: Vec<String> = self.warnings.iter().take(n).cloned().collect();
        if self.warnings.len() > n {
            v.push(format!("…共 {} 条警告,仅显示前 {n} 条", self.warnings.len()));
        }
        v
    }
}

/// 规整参数:None → 默认值;超过硬上限 → 硬上限
fn norm_max(max_frames: Option<usize>) -> usize {
    max_frames.unwrap_or(DEFAULT_MAX_FRAMES).clamp(1, HARD_MAX_FRAMES)
}

fn norm_secs(seconds: Option<f64>) -> f64 {
    let s = seconds.unwrap_or(DEFAULT_SECONDS);
    if !(s.is_finite()) || s <= 0.0 {
        return DEFAULT_SECONDS;
    }
    s.min(300.0)
}

/// 直连 serbox TCP 3333 收 NDJSON 帧。
/// 停止条件(任一满足即断开返回):max_frames / seconds / 空闲 IDLE_TIMEOUT / 对端关闭。
pub fn collect_tcp(
    addr: &str,
    max_frames: Option<usize>,
    seconds: Option<f64>,
    alias_prefix: Option<&str>,
) -> Result<CollectResult, String> {
    let max = norm_max(max_frames);
    let secs = norm_secs(seconds);
    use std::net::ToSocketAddrs;
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| format!("地址 {addr} 无法解析: {e}"))?
        .next()
        .ok_or_else(|| format!("地址 {addr} 无法解析"))?;
    let mut stream = TcpStream::connect_timeout(&sa, Duration::from_secs(CONNECT_TIMEOUT_S))
        .map_err(|e| format!("连接 {addr} 失败(超时 {CONNECT_TIMEOUT_S}s): {e}"))?;
    stream
        .set_nonblocking(true)
        .map_err(|e| format!("设置非阻塞失败: {e}"))?;

    let mut pipe = Pipeline::new(None, alias_prefix);
    let mut out: Vec<Record> = vec![];
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    let mut last_data = Instant::now();
    let mut buf = [0u8; 8192];
    // 循环内所有 break 都先给 stop 赋值,故无需初始化
    let stop;
    loop {
        if out.len() >= max {
            stop = StopReason::MaxFrames;
            break;
        }
        if Instant::now() >= deadline {
            stop = StopReason::SecondsElapsed;
            break;
        }
        if last_data.elapsed() >= IDLE_TIMEOUT {
            stop = StopReason::IdleTimeout;
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                stop = StopReason::Eof;
                break;
            }
            Ok(n) => {
                last_data = Instant::now();
                pipe.feed_bytes(&buf[..n], &mut out);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                // 与 core pump 一致的小睡轮询
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => return Err(format!("读取 {addr} 失败: {e}")),
        }
    }
    let mut lines: Vec<Record> = vec![];
    pipe.flush_eof(&mut lines);
    out.extend(lines);
    out.truncate(max);
    Ok(finish(pipe, out, stop))
}

/// 读回放 .ndjson / .jsonl 文件(与实时同一解析器)。
/// max_frames 只做「取最早 N 帧」的截断;文件读完后即返回。
pub fn collect_file(
    path: &std::path::Path,
    max_frames: Option<usize>,
    alias_prefix: Option<&str>,
) -> Result<CollectResult, String> {
    let max = norm_max(max_frames);
    let bytes =
        std::fs::read(path).map_err(|e| format!("打开回放文件 {} 失败: {e}", path.display()))?;
    let mut pipe = Pipeline::new(None, alias_prefix);
    let mut recs: Vec<Record> = vec![];
    pipe.feed_bytes(&bytes, &mut recs);
    pipe.flush_eof(&mut recs);
    let full = recs.len();
    let stop = if full >= max {
        recs.truncate(max);
        StopReason::MaxFrames
    } else {
        StopReason::FileEof
    };
    Ok(finish(pipe, recs, stop))
}

/// 收口:从管线取会话状态(take_warnings 需要可变借用)
fn finish(mut pipe: Pipeline, records: Vec<Record>, stop: StopReason) -> CollectResult {
    CollectResult {
        labels: pipe.sess.labels(),
        warnings: pipe.sess.take_warnings(),
        epoch_ns: pipe.sess.epoch_ns(),
        stats: pipe.sess.stats(),
        records,
        stop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 本地 mock TCP 推 NDJSON → collect_tcp 在空闲超时前收齐
    #[test]
    fn collect_tcp_mock() {
        const MOCK: &str = include_str!("../../core/tests/data/mock_live.ndjson");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(MOCK.as_bytes()).unwrap();
            s.flush().unwrap();
            // 保持连接不断,验证空闲超时提前返回(否则要等对端关闭)
            std::thread::sleep(Duration::from_millis(3500));
            s.shutdown(std::net::Shutdown::Both).ok();
        });
        let r = collect_tcp(&addr, Some(50), None, None).unwrap();
        assert_eq!(r.records.len(), 8, "8 条有效帧");
        assert_eq!(r.stats.bad, 1, "1 条坏行");
        assert_eq!(r.stop, StopReason::IdleTimeout, "mock 不断开,靠空闲超时返回");
        assert_eq!(r.labels.get(&0).unwrap(), "电表-485");
        srv.join().unwrap();
    }

    #[test]
    fn collect_tcp_max_frames_cuts_early() {
        const MOCK: &str = include_str!("../../core/tests/data/mock_live.ndjson");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(MOCK.as_bytes()).unwrap();
            s.flush().unwrap();
            std::thread::sleep(Duration::from_millis(300));
            s.shutdown(std::net::Shutdown::Both).ok();
        });
        let r = collect_tcp(&addr, Some(3), None, None).unwrap();
        assert_eq!(r.records.len(), 3);
        assert_eq!(r.stop, StopReason::MaxFrames);
        srv.join().unwrap();
    }

    #[test]
    fn collect_file_truncates() {
        let dir = std::env::temp_dir().join("iotprobe_aimcp_collect_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.ndjson");
        std::fs::write(&path, include_str!("../../core/tests/data/mock_live.ndjson")).unwrap();
        let r = collect_file(&path, Some(2), None).unwrap();
        assert_eq!(r.records.len(), 2);
        assert_eq!(r.stop, StopReason::MaxFrames);
        let r2 = collect_file(&path, None, None).unwrap();
        assert_eq!(r2.records.len(), 8);
        assert_eq!(r2.stop, StopReason::FileEof);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn collect_tcp_bad_addr_errors() {
        assert!(collect_tcp("127.0.0.1:1", Some(5), Some(1.0), None).is_err(), "无监听端口应报错");
    }
}
