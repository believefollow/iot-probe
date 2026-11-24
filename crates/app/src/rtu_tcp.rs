//! Modbus RTU over TCP 适配器(live 二期,Q4:P1):
//! 串口服务器(有人/周立功 串口转网口)把 RS485 透传成 TCP 裸字节流。
//! 定帧策略(ADR-0011):字节到达时间 + CRC 双重启发 —— 与 dissect::modbus::scan
//! 同一套 CRC 规则,流中段按静默间隙(gap,默认 30ms)触发冲刷。
//! 输出:契约 NDJSON(bus.type=uart, ts_src=sw=L0 如实标注,dir Unknown + assumed_dir,
//! ADR-0007),接入同一 live 管线 —— 录制/回放/解析/规则全复用。

use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::LiveFrame;
use iotprobe_core::model::{Dir, TsSrc};
use std::io;
use std::time::{Duration, Instant, SystemTime};

const MAX_RTU_FRAME: usize = 256; // Modbus RTU 帧上限(256B 规约 + 余量)
const MAX_TAIL_AGE_MS: u128 = 500; // 无法定界的尾字节保留窗口

/// RTU 流式分帧状态机(与 IO 解耦,便于测试)
pub struct RtuFramer {
    pub gap_ms: u64,
    buf: Vec<u8>,
    times: Vec<Instant>,
    pub frames_ok: usize,
    pub bytes_dropped: usize,
}

impl RtuFramer {
    pub fn new(gap_ms: u64) -> Self {
        RtuFramer { gap_ms, buf: vec![], times: vec![], frames_ok: 0, bytes_dropped: 0 }
    }

    pub fn push(&mut self, chunk: &[u8], now: Instant) {
        for &b in chunk {
            if self.buf.len() >= MAX_RTU_FRAME {
                self.drop_tail(now);
            }
            self.buf.push(b);
            self.times.push(now);
        }
    }

    /// 静默间隙到达:尝试 CRC 定帧冲刷;残尾保留(可能跨块补齐)
    pub fn flush_if_gap(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = vec![];
        if self.buf.is_empty() {
            return out;
        }
        // CRC 扫描(方向未知,由 CRC 决定)
        let frames = iotprobe_core::dissect::modbus::scan(&self.buf, iotprobe_core::model::Dir::Unknown);
        if let Some(&(last_o, last_l)) = frames.last() {
            let end = last_o + last_l;
            for (o, l) in frames {
                out.push(self.buf[o..o + l].to_vec());
                self.frames_ok += 1;
            }
            // 帧前的未定界前缀 = 丢弃计数(含老噪声)
            self.bytes_dropped += last_o;
            let tail: Vec<u8> = self.buf[end..].to_vec();
            let tail_times: Vec<Instant> = self.times[end..].to_vec();
            self.buf = tail;
            self.times = tail_times;
        }
        // 尾部老化:开头字节超过保留窗口 → 从头部逐字节丢弃(其定帧机会已过)
        while let Some(&t0) = self.times.first() {
            if now.saturating_duration_since(t0).as_millis() > MAX_TAIL_AGE_MS {
                self.buf.remove(0);
                self.times.remove(0);
                self.bytes_dropped += 1;
            } else {
                break;
            }
        }
        out
    }

    fn drop_tail(&mut self, now: Instant) {
        self.bytes_dropped += self.buf.len();
        self.buf.clear();
        self.times.clear();
        let _ = now;
    }
}

fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn rtu_to_jsonl(data: &[u8], arrival_ns: u64) -> String {
    let f = LiveFrame {
        ts_ns: arrival_ns,
        ts_src: TsSrc::Sw, // 串口服务器无硬件时戳,L0 如实标注(ADR-5)
        bus_type: iotprobe_core::ingest::live::BusKind::Uart,
        ch: 0,
        alias: None,
        dir: Dir::Unknown, // 总线监听无方向 → ADR-0007 assumed_dir
        id: 0,
        id_ext: false,
        dlc: data.len(),
        data: data.to_vec(),
        seq: None,
        meta_gap: None,
    };
    live_frame_to_jsonl(&f)
}

/// TCP 串口服务器源(实现 Read,接入 live::pump)
pub struct RtuTcpSource {
    stream: std::net::TcpStream,
    framer: RtuFramer,
    out: Vec<u8>,
    out_pos: usize,
    last_arrival: Option<Instant>,
}

impl RtuTcpSource {
    pub fn new(stream: std::net::TcpStream, gap_ms: u64) -> Self {
        let _ = stream.set_nonblocking(true);
        RtuTcpSource { stream, framer: RtuFramer::new(gap_ms), out: vec![], out_pos: 0, last_arrival: None }
    }

    fn flush_out(&mut self, frames: Vec<Vec<u8>>) {
        for f in frames {
            let line = rtu_to_jsonl(&f, wall_ns());
            self.out.extend_from_slice(line.as_bytes());
            self.out.push(b'\n');
        }
    }
}

impl io::Read for RtuTcpSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // 1) 先吐已就绪的契约行
        if self.out_pos < self.out.len() {
            let n = self.out.len().saturating_sub(self.out_pos).min(buf.len());
            buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
            if self.out_pos >= self.out.len() {
                self.out.clear();
                self.out_pos = 0;
            }
            return Ok(n);
        }
        // 2) 读 TCP;有字节 → 定帧尝试
        let mut tmp = [0u8; 2048];
        match self.stream.read(&mut tmp) {
            Ok(n) if n > 0 => {
                let now = Instant::now();
                self.framer.push(&tmp[..n], now);
                self.last_arrival = Some(now);
                // 立即尝试 CRC 定帧(整帧通常随块到达)
                let frames = self.framer.flush_if_gap(now);
                self.flush_out(frames);
                self.read(buf)
            }
            Ok(0) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "串口服务器断开")),
            Ok(_) => unreachable!(),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => {
                // 静默间隙冲刷(服务器把一个 RTU 帧拆成多包到达时)
                let now = Instant::now();
                if let Some(la) = self.last_arrival {
                    if now.saturating_duration_since(la).as_millis() >= self.framer.gap_ms as u128
                        && !self.framer.buf.is_empty()
                    {
                        self.framer.times = vec![la; self.framer.buf.len()]; // 静默期按到达时刻近似
                        let frames = self.framer.flush_if_gap(now + Duration::from_millis(self.framer.gap_ms + 1));
                        self.flush_out(frames);
                        self.last_arrival = None;
                        return self.read(buf);
                    }
                }
                Err(io::Error::new(io::ErrorKind::WouldBlock, "等待数据"))
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("TCP 读取失败: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::live_frame_to_jsonl;
    use iotprobe_core::ingest::live::LiveFrame;
    use std::sync::Arc;

    /// 规范响应帧:addr func bc data... crc
    fn mkresp(addr: u8, func: u8, regs: &[u16]) -> Vec<u8> {
        let mut d = vec![addr, func, (regs.len() * 2) as u8];
        for r in regs {
            d.push((r >> 8) as u8);
            d.push((r & 0xFF) as u8);
        }
        let c = iotprobe_core::crc::crc16_modbus(&d);
        d.push(c as u8);
        d.push((c >> 8) as u8);
        d
    }

    /// 规范请求帧:addr func start qty crc
    fn mkreq(addr: u8, func: u8, start: u16, qty: u16) -> Vec<u8> {
        let mut d = vec![addr, func];
        d.extend_from_slice(&start.to_be_bytes());
        d.extend_from_slice(&qty.to_be_bytes());
        let c = iotprobe_core::crc::crc16_modbus(&d);
        d.push(c as u8);
        d.push((c >> 8) as u8);
        d
    }

    /// 分帧状态机:拆包到达 + 静默冲刷,应还原全部 CRC 帧并转成可解析契约行
    #[test]
    fn framer_reassembles_split_frames() {
        let f1 = mkresp(0x01, 0x03, &[0x1234]);            // 响应 9B
        let f2 = mkreq(0x01, 0x03, 0x0000, 0x0002);        // 请求 8B(经典 C4 0B)
        let mut fr = RtuFramer::new(30);
        let now = Instant::now();
        // 两帧连排,切成 5 字节小包喂入(模拟 TCP 分段)
        let all = [f1.clone(), f2.clone()].concat();
        let mut emitted = vec![];
        for chunk in all.chunks(5) {
            fr.push(chunk, now);
            emitted.extend(fr.flush_if_gap(now + Duration::from_millis(1)));
        }
        // 静默冲刷残帧
        emitted.extend(fr.flush_if_gap(now + Duration::from_millis(100)));
        assert_eq!(emitted.len(), 2, "应还原 2 帧,got {:?}", emitted);
        assert_eq!(emitted[0], f1);
        assert_eq!(emitted[1], f2);
        assert_eq!(fr.bytes_dropped, 0);
        // 契约行可被 live 管线解析
        let line = rtu_to_jsonl(&emitted[0], wall_ns());
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["bus"]["type"], "uart");
        assert_eq!(v["ts_src"], "sw");
        assert_eq!(v["meta"]["assumed_dir"], true);
    }

    /// 坏字节(无 CRC 帧)老化丢弃,不阻塞后续定帧
    #[test]
    fn framer_drops_aged_tail() {
        let mut fr = RtuFramer::new(30);
        let t0 = Instant::now() - Duration::from_millis(600);
        fr.push(&[0xDE, 0xAD, 0xBE, 0xEF], t0); // 老噪声
        let good = mkresp(0x01, 0x03, &[1]);
        fr.push(&good, Instant::now()); // 新帧
        let out = fr.flush_if_gap(Instant::now());
        assert_eq!(out, vec![good.clone()], "CRC 命中的新帧应跨过老噪声被还原");
        assert!(fr.bytes_dropped >= 4, "老噪声应被计数丢弃");
    }

    /// 老化/噪声后管线仍认帧(录制闭环)
    #[test]
    fn emitted_lines_parse_as_contract() {
        let f = mkresp(0x7F, 0x10, &[0x1122, 0x3344]);
        let line = live_frame_to_jsonl(&LiveFrame {
            ts_ns: 1767225600_000_000_000,
            ts_src: TsSrc::Sw,
            bus_type: iotprobe_core::ingest::live::BusKind::Uart,
            ch: 0,
            alias: None,
            dir: Dir::Unknown,
            id: 0,
            id_ext: false,
            dlc: f.len(),
            data: f.clone(),
            seq: None,
            meta_gap: None,
        });
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], 0);
        assert_eq!(v["dlc"], f.len());
        let _ = Arc::new(());
    }
}
