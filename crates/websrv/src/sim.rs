//! 模拟 CAN 总线源(演示用):与 app/sim.rs 同构的速度/扭矩/温度正弦 + 心跳 + 64B CAN FD 帧,
//! 另加两个演示注入:①温度故障(1.5s 爬升到越限,松开 600ms 回落→触发 rate 骤降规则)
//! ②心跳停发 3s(→聚合视图周期抖动 + 间隔异常诊断事件)。
//! 实时节奏按墙钟推进;输出契约 NDJSON 供 core live 管线,同时每帧按 frame.schema 推给 Hub 广播。

use crate::{contract, Hub, Inject, StatsCounters};
use iotprobe_core::ingest::live::{BusKind, LiveFrame};
use iotprobe_core::model::{Dir, TsSrc};
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

pub struct SimSource {
    t0: Instant,
    t_ms: u64,
    buf: Vec<u8>,
    rx_pos: usize,
    seq: u64,
    hb: u8,
    inject: Arc<Inject>,
    hub: Arc<Hub>,
    stats: Arc<StatsCounters>,
    prev_fault: bool,
    fault_since_ms: u64,
    ramp_down_start: Option<u64>,
}

impl SimSource {
    pub fn new(inject: Arc<Inject>, hub: Arc<Hub>, stats: Arc<StatsCounters>) -> Self {
        SimSource {
            t0: Instant::now(),
            t_ms: 0,
            buf: vec![],
            rx_pos: 0,
            seq: 0,
            hb: 0,
            inject,
            hub,
            stats,
            prev_fault: false,
            fault_since_ms: 0,
            ramp_down_start: None,
        }
    }

    fn push_frame(&mut self, t_ms: u64, id: u32, ext: bool, data: Vec<u8>, fd: bool) {
        self.seq += 1;
        let f = LiveFrame {
            ts_ns: t_ms * 1_000_000,
            ts_src: TsSrc::Sw, // ADR-5:模拟源=收包时刻(sw/L0),UI 如实标注
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
        let line = contract::live_frame_json(&f);
        self.hub.push("frame", &line, f.id, "rx");
        self.stats.frames.fetch_add(1, Ordering::Relaxed);
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

            // 故障注入状态机
            let fault = self.inject.temp_fault.load(Ordering::Relaxed);
            if fault && !self.prev_fault {
                self.fault_since_ms = self.t_ms;
                self.ramp_down_start = None;
            }
            if !fault && self.prev_fault {
                self.ramp_down_start = Some(self.t_ms);
            }
            self.prev_fault = fault;
            let mut temp_raw = 55.0 + 10.0 * (t * 0.3).sin(); // 常态 Temp = 5..25 °C
            if fault {
                let r = ((self.t_ms - self.fault_since_ms) as f64 / 1500.0).min(1.0);
                temp_raw += (104.0 - temp_raw) * r; // → Temp 最高 64 °C
            } else if let Some(rd) = self.ramp_down_start {
                let r = 1.0 - ((self.t_ms - rd) as f64 / 600.0).min(1.0);
                temp_raw += (104.0 - temp_raw) * r.max(0.0);
                if r <= 0.0 {
                    self.ramp_down_start = None;
                }
            }
            let temp_byte = temp_raw.round().clamp(0.0, 255.0) as u8;

            // 0x1A0 MOTOR_STATUS @10ms(与 samples/motor.dbc 同构)
            let speed = ((40.0 + 20.0 * (t * 2.0).sin()) * 100.0).round() as u16;
            let torque = ((15.0 + 8.0 * (t * 1.1).sin()) * 10.0).round() as i16;
            let mut d = speed.to_le_bytes().to_vec();
            d.extend_from_slice(&torque.to_le_bytes());
            d.push(temp_byte);
            d.push((self.t_ms % 256) as u8);
            d.extend_from_slice(&[0, 0, 0, 0]);
            self.push_frame(self.t_ms, 0x1A0, false, d, false);
            n += 1;

            // 心跳 @500ms(演示「心跳停发 3s」)
            if self.t_ms % 500 == 0 {
                let stalled = self
                    .inject
                    .hb_stall_until
                    .lock()
                    .unwrap()
                    .map(|d| Instant::now() < d)
                    .unwrap_or(false);
                if !stalled {
                    self.hb = self.hb.wrapping_add(1);
                    self.push_frame(self.t_ms, 0x100, false, vec![self.hb, 3, 0, 0, 0, 0, 0, 0], false);
                    n += 1;
                }
            }

            // 64B CAN FD 扩展帧 @2s
            if self.t_ms % 2000 == 0 {
                let payload: Vec<u8> = (0..64).map(|k| ((self.t_ms as usize + k) % 251) as u8).collect();
                self.push_frame(self.t_ms, 0x18FF0102, true, payload, true);
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
