//! 模拟 CAN 总线源(开发/UI 验证用,无需硬件):
//! 与 samples/motor.dbc 同源的速度/扭矩/温度曲线 + 心跳计数 + 64B CAN FD 帧,
//! 实时节奏按墙钟推进;输出契约 NDJSON 字节流,与 ZLG/NDJSON 源走同一条管线。
//! 真机联调通过后此源仅作演示与回归测试。

use crate::live::live_frame_to_jsonl;
use iotprobe_core::ingest::live::LiveFrame;
use iotprobe_core::ingest::live::BusKind;
use iotprobe_core::model::{Dir, TsSrc};
use std::io;
use std::time::Instant;

pub struct SimSource {
    t0: Instant,
    /// 已推进到的模拟时间(ms)
    t_ms: u64,
    buf: Vec<u8>,
    rx_pos: usize,
    seq: u64,
    hb: u8,
}

impl SimSource {
    pub fn new() -> Self {
        SimSource { t0: Instant::now(), t_ms: 0, buf: vec![], rx_pos: 0, seq: 0, hb: 0 }
    }

    fn frame(&mut self, t_ms: u64, id: u32, ext: bool, data: Vec<u8>, fd: bool) {
        self.seq += 1;
        let f = LiveFrame {
            ts_ns: t_ms * 1_000_000,
            ts_src: TsSrc::Sw, // 上电单调时间(相对启动),ADR-5 的 sw 档
            bus_type: if fd { BusKind::CanFd } else { BusKind::Can },
            ch: 0,
            alias: None,
            dir: Dir::Rx,
            id,
            id_ext: ext,
            dlc: data.len(),
            data,
            seq: Some(self.seq),
            meta_gap: None,
        };
        let line = live_frame_to_jsonl(&f);
        self.buf.extend_from_slice(line.as_bytes());
        self.buf.push(b'\n');
    }

    /// 推进模拟时间到墙钟;返回本步帧数
    fn advance(&mut self) -> usize {
        let elapsed_ms = self.t0.elapsed().as_millis() as u64;
        let mut n = 0usize;
        while self.t_ms < elapsed_ms {
            self.t_ms += 10;
            let t = self.t_ms as f64 / 1000.0;
            // 0x1A0 MOTOR_STATUS @10ms:速度/扭矩/温度正弦(与 motor.dbc 同构)
            let speed = ((40.0 + 20.0 * (t * 2.0).sin()) * 100.0).round() as u16;
            let torque = ((15.0 + 8.0 * (t * 1.1).sin()) * 10.0).round() as i16;
            let mut d = speed.to_le_bytes().to_vec();
            d.extend_from_slice(&torque.to_le_bytes());
            d.push((55.0 + 10.0 * (t * 0.3).sin()).round() as u8);
            d.push((self.t_ms % 256) as u8);
            d.extend_from_slice(&[0, 0, 0, 0]);
            self.frame(self.t_ms, 0x1A0, false, d, false);
            n += 1;
            // 心跳 @500ms
            if self.t_ms % 500 == 0 {
                self.hb = self.hb.wrapping_add(1);
                self.frame(self.t_ms, 0x100, false, vec![self.hb, 3, 0, 0, 0, 0, 0, 0], false);
                n += 1;
            }
            // 64B CAN FD 扩展帧 @2s
            if self.t_ms % 2000 == 0 {
                let payload: Vec<u8> = (0..64).map(|k| ((self.t_ms as usize + k) % 251) as u8).collect();
                self.frame(self.t_ms, 0x18FF0102, true, payload, true);
                n += 1;
            }
        }
        n
    }
}

impl io::Read for SimSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_pos >= self.buf.len() {
            self.buf.clear();
            self.rx_pos = 0;
            if self.advance() == 0 {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "等待下一帧"));
            }
        }
        let n = self.buf.len().saturating_sub(self.rx_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.buf[self.rx_pos..self.rx_pos + n]);
        self.rx_pos += n;
        Ok(n)
    }
}
