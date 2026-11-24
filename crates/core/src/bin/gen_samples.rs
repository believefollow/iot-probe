//! 样例数据生成器:生成 tests/demo 用的日志与抓包。
//! 运行:cargo run -p iotprobe-core --bin gen_samples -- [输出目录,默认 samples]

use iotprobe_core::crc::crc16_modbus;
use std::path::PathBuf;

fn main() {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| "samples".into());
    let out = PathBuf::from(&out_dir);
    std::fs::create_dir_all(out.join("configs")).unwrap();
    gen_modbus_rtu(&out);
    gen_custom(&out);
    gen_candump(&out);
    gen_pcap(&out);
    gen_unknown(&out);
    gen_asc(&out);
    gen_socketcan(&out);
    gen_104_pcap(&out);
    gen_rule_packs(&out);
    println!("样例已生成到 {}/", out.display());
}

// ================= 未知协议日志(供试探引擎演示) =================

fn gen_unknown(out: &PathBuf) {
    let base = iotprobe_core::timeutil::wall_to_epoch_ns(2026, 1, 5, 10, 20, 0, 0);
    let mut lines = Vec::new();
    let mut t = 0.0f64;
    for i in 0..400u32 {
        // 5A A5 | type | len(6) | pressure u16 BE | flow i16 LE | status | counter | sum8
        let mut f = vec![0x5A, 0xA5, if i % 10 == 0 { 0x82u8 } else { 0x81 }, 0x06];
        f.extend_from_slice(&(1000 + (i % 80) as u16).to_be_bytes());
        f.extend_from_slice(&((i % 30) as i16).to_le_bytes());
        f.push(if (120..125).contains(&i) { 0x04 } else { 0x01 });
        f.push((i & 0xFF) as u8);
        let s = iotprobe_core::crc::sum8(&f[2..]);
        f.push(s);
        let hexs = f.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
        lines.push(format!("RX {} {}", wall_stamp(base, t), hexs));
        t += 50.0;
    }
    std::fs::write(out.join("unknown_protocol.log"), lines.join("\n")).unwrap();
}

// ================= 内置规则包(ADR-6) =================

fn gen_rule_packs(out: &PathBuf) {
    let pack_dir = out.join("rules-pack/generic-bms");
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::write(pack_dir.join("rules.yaml"), "pack: generic-bms
meta: { vendor: generic, model: bms, version: \"1.0\" }
rules:
  - id: TEMP_OVER_LIMIT
    level: fault
    on: signal
    signal: TempSensor
    when: \"$ > 32.0\"
    message: \"温度越限 {value} °C(阈值 32.0)\"
  - id: TEMP_HIGH
    level: warn
    on: signal
    signal: TempSensor
    when: \"$ > 30.0 && $ <= 32.0\"
    message: \"温度偏高 {value} °C\"
  - id: MOTOR_IDLE
    level: info
    on: signal
    signal: RunState
    when: \"$ == 2\"
    once: true
    message: \"电机怠速(RunState=2)\"
").unwrap();
    std::fs::write(pack_dir.join("meta.yaml"), "vendor: generic
model: bms
version: \"1.0\"
contributor: IoTProbe 内置
").unwrap();
    let hb_dir = out.join("rules-pack/generic-heartbeat");
    std::fs::create_dir_all(&hb_dir).unwrap();
    std::fs::write(hb_dir.join("rules.yaml"), "pack: generic-heartbeat
rules:
  - id: BUS_SILENCE
    level: warn
    on: timeout
    channel: \"candump\"
    timeout: 80ms
    message: \"通道静默超 {timeout}(实测 {silence})\"
").unwrap();
}

// ================= Vector ASC(CANoe/ZCANPro 导出风格) =================

fn gen_asc(out: &PathBuf) {
    let mut lines = vec![
        "date Sun Jan 05 10:00:00 2026".to_string(),
        "base hex timestamps relative".to_string(),
        "internal events logged".to_string(),
        "Begin Triggerblock Sun Jan 05 10:00:00 2026".to_string(),
    ];
    let mut t = 0.0f64;
    for i in 0..300u32 {
        let speed = (40.0 + 20.0 * (t * 2.0).sin()).round() as u16;
        let mut d = speed.to_le_bytes().to_vec();
        d.extend_from_slice(&[0x00, 0x32, 0x00, 0x00, 0x00, 0x00]);
        let hexs = d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
        lines.push(format!("{:.6} 1  1A0            Rx   d 8 {hexs}", t));
        t += 0.01;
        if i % 20 == 0 {
            let hb = [((i / 20) & 0xFF) as u8, 3u8, 0, 0, 0, 0, 0, 0];
            let hb_hexs = hb.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            lines.push(format!("{:.6} 1  100            Rx   d 8 {hb_hexs}", t));
        }
        if i % 50 == 0 {
            // 扩展帧
            let ext_d = [(i % 256) as u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
            let ext_hexs = ext_d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            lines.push(format!("{:.6} 2  18FF0102x       Tx   d 8 {ext_hexs}", t));
        }
    }
    lines.push("End TriggerBlock".into());
    std::fs::write(out.join("vector.asc"), lines.join("\n")).unwrap();
}

// ================= SocketCAN 抓包(linktype 204) =================

fn gen_socketcan(out: &PathBuf) {
    let mut buf = vec![];
    let push32 = |v: u32, b: &mut Vec<u8>| b.extend_from_slice(&v.to_le_bytes());
    push32(0xa1b2c3d4, &mut buf);
    buf.extend_from_slice(&2u16.to_le_bytes()); // 版本主
    buf.extend_from_slice(&4u16.to_le_bytes()); // 版本次
    push32(0, &mut buf); // thiszone
    push32(0, &mut buf); // sigfigs
    push32(65535, &mut buf);
    push32(204, &mut buf); // LINKTYPE_CAN_SOCKETCAN
    let mut t = 1767225600.0f64;
    for i in 0..65u32 {
        // 经典帧:can_id u32 LE + dlc u8 + pad3 + data8
        let speed = (40.0 + 20.0 * ((i as f64) * 0.02).sin()).round() as u16;
        let mut frame = vec![];
        frame.extend_from_slice(&0x1A0u32.to_le_bytes());
        frame.push(8);
        frame.extend_from_slice(&[0, 0, 0]);
        let mut d = speed.to_le_bytes().to_vec();
        d.extend_from_slice(&[0x10, 0x05, 0x00, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&d);
        let sec = t.floor() as u32;
        let us = ((t - sec as f64) * 1e6) as u32;
        push32(sec, &mut buf);
        push32(us, &mut buf);
        push32(16, &mut buf);
        push32(16, &mut buf);
        buf.extend_from_slice(&frame);
        t += 0.01;
        // 每 13 帧插一条 CAN FD 帧(canfd_frame:id4 + len1 + flags1 + res2 + data)
        if i % 13 == 0 {
            let mut fd = vec![];
            fd.extend_from_slice(&(0x123 | 0x8000_0000u32).to_le_bytes()); // 扩展帧
            fd.push(16); // len
            fd.push(0); // flags
            fd.extend_from_slice(&[0, 0]);
            fd.extend_from_slice(&(0..16).map(|k| (i as usize + k) as u8).collect::<Vec<u8>>());
            let sec2 = t.floor() as u32;
            let us2 = ((t - sec2 as f64) * 1e6) as u32;
            push32(sec2, &mut buf);
            push32(us2, &mut buf);
            push32(24, &mut buf); // caplen(截断到24以模拟常见写法)
            push32(24, &mut buf);
            buf.extend_from_slice(&fd[..24.min(fd.len())]);
            t += 0.01;
        }
    }
    std::fs::write(out.join("can_socketcan.pcap"), buf).unwrap();
}

// ================= Modbus RTU 日志 =================

fn rtu_frame(body: &[u8]) -> String {
    let c = crc16_modbus(body);
    let mut s = body.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
    s += &format!(" {:02X} {:02X}", c as u8, (c >> 8) as u8);
    s
}

fn wall_stamp(base_ns: u64, off_ms: f64) -> String {
    let ns = base_ns + (off_ms * 1e6) as u64;
    let (y, mo, d, h, mi, s, frac) = iotprobe_core::timeutil::epoch_ns_to_wall(ns);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}.{:03}", frac / 1_000_000)
}

fn regs_u32_cdab(v: u32) -> [u16; 2] {
    // 值字节 A,B,C,D = v 的四个字节;CDAB 线缆序 → C,D,A,B
    let a = (v >> 24) as u16;
    let b = ((v >> 16) & 0xFF) as u16;
    let c = ((v >> 8) & 0xFF) as u16;
    let d = (v & 0xFF) as u16;
    [(c << 8) | d, (a << 8) | b]
}

fn gen_modbus_rtu(out: &PathBuf) {
    let base = iotprobe_core::timeutil::wall_to_epoch_ns(2026, 1, 5, 10, 0, 0, 0);
    let req = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x05];
    let mut lines = Vec::new();
    let mut t = 0.0f64;
    let mut pair = 0usize;
    while pair < 600 {
        let skip_gap = pair >= 300 && pair < 315; // 1.5s 断流
        if !skip_gap {
            lines.push(format!("TX {} {}", wall_stamp(base, t), rtu_frame(&req)));
            // 响应:reg0=温度(正弦), reg1=设定值
            let temp = ((t as f64 * 0.8).sin() * 80.0 + 250.0).round() as u16; // raw, ×0.1°C
            let sp = 500u16;
            // 5 个寄存器:temp(1) + setpoint(1) + energy 32bit CDAB(2) + runstate 枚举(1)
            let energy = regs_u32_cdab((pair as u32 * 97) % 100000);
            let state: u16 = if (pair % 7) == 0 { 2 } else { 1 };
            let resp: Vec<u8> = if pair == 450 {
                vec![0x01, 0x83, 0x02] // 异常响应
            } else {
                let mut r = vec![0x01, 0x03, 0x0A];
                for reg in [temp, sp, energy[0], energy[1], state] {
                    r.push((reg >> 8) as u8);
                    r.push((reg & 0xFF) as u8);
                }
                r
            };
            let mut frame = resp.clone();
            let c = crc16_modbus(&frame);
            frame.push(c as u8);
            frame.push((c >> 8) as u8);
            if pair == 200 {
                frame[3] ^= 0x01; // 先加 CRC 再破坏 → 真实的 CRC 校验失败
            }
            let hexs = frame.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            lines.push(format!("RX {} {}", wall_stamp(base, t + 8.0), hexs));
        }
        t += 100.0;
        pair += 1;
    }
    std::fs::write(out.join("modbus_rtu.log"), lines.join("\n")).unwrap();
}

// ================= 自定义 485 日志 + 配置 =================

fn gen_custom(out: &PathBuf) {
    let base = iotprobe_core::timeutil::wall_to_epoch_ns(2026, 1, 5, 10, 5, 0, 0);
    let spec = r#"{
  "name": "ACME-485",
  "sync": "AA55",
  "min_len": 11,
  "length": {"at": 3, "size": 1, "bias": 7},
  "checksum": {"algo": "crc16_modbus", "cover": [0, "end-2"]},
  "fields": [
    {"name": "cmd",  "at": 2, "ty": "u8"},
    {"name": "temp", "at": 4, "ty": "i16", "scale": 0.1, "unit": "°C", "plot": true},
    {"name": "rpm",  "at": 6, "ty": "u16", "endian": "big", "plot": true},
    {"name": "flags","at": 8, "ty": "u8", "bits": [
      {"name": "running", "bit": 0},
      {"name": "fault",   "bit": 3}
    ]}
  ]
}"#;
    std::fs::write(out.join("configs/custom_example.json"), spec).unwrap();

    let map = r#"{
  "regs": [
    {"addr": 0, "name": "TempSensor", "scale": 0.1, "unit": "°C"},
    {"addr": 1, "name": "SetPoint",   "scale": 0.1, "unit": "°C"},
    {"addr": 2, "name": "Energy", "width": 2, "byte_order": "CDAB", "scale": 0.01, "unit": "kWh"},
    {"addr": 4, "name": "RunState", "enums": {"1": "Run", "2": "Idle", "3": "Fault"}}
  ]
}"#;
    std::fs::write(out.join("configs/modbus_map.json"), map).unwrap();

    let mut lines = Vec::new();
    let mut t = 0.0f64;
    for i in 0..300usize {
        let temp: i16 = ((t as f64 * 1.3).sin() * 150.0).round() as i16; // ×0.1°C
        let rpm: u16 = (1500.0 + (t as f64 * 0.5).sin() * 300.0).round() as u16;
        let mut flags = 0x01u8; // running
        if (150..160).contains(&i) {
            flags |= 0x08; // fault 抖动
        }
        let mut f = vec![0xAA, 0x55, 0x10, 0x04];
        f.extend_from_slice(&(temp as u16).to_le_bytes());
        f.push((rpm >> 8) as u8);
        f.push((rpm & 0xFF) as u8);
        f.push(flags);
        let c = crc16_modbus(&f);
        f.push(c as u8);
        f.push((c >> 8) as u8);
        if i == 100 {
            f[4] ^= 0x33; // 先加 CRC 再破坏 → 真实的校验失败
        }
        let mut hexs = f.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
        if i == 150 {
            hexs = hexs.replacen("AA 55", "AA 54", 1); // 同步头坏
        }
        lines.push(format!("RX {} {}", wall_stamp(base, t), hexs));
        t += 50.0;
    }
    std::fs::write(out.join("custom_485.log"), lines.join("\n")).unwrap();
}

// ================= candump 日志 + DBC =================

fn gen_candump(out: &PathBuf) {
    let dbc = r#"VERSION ""

BO_ 416 MOTOR_STATUS: 8 MOTOR
 SG_ Speed : 0|16@1+ (0.01,0) [0|500] "kph"
 SG_ Torque : 16|16@1- (0.1,0) [-500|500] "Nm"
 SG_ Temp : 32|8@1+ (1,-40) [0|200] "degC"

BO_ 256 HEARTBEAT: 8 MOTOR
 SG_ Counter : 0|8@1+ (1,0) [0|255] ""
 SG_ State : 8|8@1+ (1,0) [0|5] ""
"#;
    std::fs::write(out.join("motor.dbc"), dbc).unwrap();

    let base = 1767225600.0f64;
    let mut lines = Vec::new();
    let mut cnt = 0u16;
    let mut t = 0.0f64;
    while t < 5.0 {
        let skip = t >= 2.0 && t < 2.1; // 100ms CAN 断流
        if !skip {
            let speed = 40.0 + 20.0 * (t * 2.0).sin();
            let torque = 15.0 + 8.0 * (t * 1.1).sin();
            let temp = 55.0 + 10.0 * (t * 0.3).sin();
            let mut d = vec![];
            let s_raw = (speed / 0.01).round() as u16;
            d.extend_from_slice(&s_raw.to_le_bytes());
            let tq_raw = (torque / 0.1).round() as i16;
            d.extend_from_slice(&tq_raw.to_le_bytes());
            d.push((temp + 40.0).round() as u8);
            d.push(0);
            d.extend_from_slice(&[0, 0, 0, 0]);
            lines.push(format!("({:.6}) can0  1A0#{}", base + t, d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("")));
        }
        t += 0.01;
        // 心跳
        if (t * 2.0) as u32 % 2 == 0 && (t % 0.5) < 0.01 {
            let hb = [cnt as u8, 3u8, 0, 0, 0, 0, 0, 0];
            lines.push(format!("({:.6}) can0  100#{}", base + t, hb.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("")));
            cnt = cnt.wrapping_add(1);
        }
    }
    std::fs::write(out.join("candump.log"), lines.join("\n")).unwrap();
}

// ================= pcap:Modbus TCP + MQTT + EtherCAT =================

fn cksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for k in (0..data.len()).step_by(2) {
        let w = if k + 1 < data.len() {
            u16::from_be_bytes([data[k], data[k + 1]]) as u32
        } else {
            (data[k] as u32) << 8
        };
        sum += w;
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    !(sum as u16)
}

fn eth(dst: &[u8; 6], src: &[u8; 6], et: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(dst);
    f.extend_from_slice(src);
    f.extend_from_slice(&et.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&[0x40, 0x00]); // DF
    h.push(64);
    h.push(proto);
    h.extend_from_slice(&[0, 0]); // 校验和占位
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let c = cksum16(&h);
    h[10] = c as u8;
    h[11] = (c >> 8) as u8;
    h.extend_from_slice(payload);
    h
}

#[allow(clippy::too_many_arguments)]
fn tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![];
    h.extend_from_slice(&sp.to_be_bytes());
    h.extend_from_slice(&dp.to_be_bytes());
    h.extend_from_slice(&seq.to_be_bytes());
    h.extend_from_slice(&ack.to_be_bytes());
    h.push(0x50);
    h.push(flags);
    h.extend_from_slice(&8192u16.to_be_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    let mut pseudo = vec![];
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&h);
    pseudo.extend_from_slice(payload);
    let c = cksum16(&pseudo);
    h[16] = c as u8;
    h[17] = (c >> 8) as u8;
    h.extend_from_slice(payload);
    h
}

fn mqtt_pkt(b0: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![b0];
    let mut r = body.len();
    loop {
        let mut x = (r % 128) as u8;
        r /= 128;
        if r > 0 {
            x |= 0x80;
        }
        p.push(x);
        if r == 0 {
            break;
        }
    }
    p.extend_from_slice(body);
    p
}

fn mqtt_str(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

fn gen_pcap(out: &PathBuf) {
    let mut pkts: Vec<(f64, Vec<u8>)> = vec![];
    let base = 1767225600.0f64;
    let mut ip_id = 1u16;

    // --- Modbus TCP:192.168.1.10:52000 → 192.168.1.50:502 ---
    let m_src = [192, 168, 1, 10];
    let m_dst = [192, 168, 1, 50];
    let mut seq_c = 1000u32;
    let mut seq_s = 5000u32;
    for i in 0..20u8 {
        let t = i as f64 * 0.1;
        // 请求:读 HR0 x2
        let req: Vec<u8> = vec![0x00, 0x10 + i, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02];
        pkts.push((
            t,
            eth(
                &[0x00, 0x11, 0x22, 0x33, 0x44, 0x50],
                &[0x00, 0x11, 0x22, 0x33, 0x44, 0x10],
                0x0800,
                &ipv4(m_src, m_dst, 6, ip_id, &tcp(m_src, m_dst, 52000, 502, seq_c, seq_s, 0x18, &req)),
            ),
        ));
        ip_id = ip_id.wrapping_add(1);
        seq_c += req.len() as u32;
        // 响应:0x4120=1667.2°C... 用真实温度曲线
        let temp = ((t * 0.8).sin() * 80.0 + 250.0).round() as u16;
        let resp = vec![0x00, 0x10 + i, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, (temp >> 8) as u8, (temp & 0xFF) as u8, 0x01, 0xF4];
        pkts.push((
            t + 0.005,
            eth(
                &[0x00, 0x11, 0x22, 0x33, 0x44, 0x10],
                &[0x00, 0x11, 0x22, 0x33, 0x44, 0x50],
                0x0800,
                &ipv4(m_dst, m_src, 6, ip_id, &tcp(m_dst, m_src, 502, 52000, seq_s, seq_c, 0x18, &resp)),
            ),
        ));
        ip_id = ip_id.wrapping_add(1);
        seq_s += resp.len() as u32;
    }

    // --- MQTT:192.168.1.20:51000 → 192.168.1.60:1883 ---
    let q_src = [192, 168, 1, 20];
    let q_dst = [192, 168, 1, 60];
    let mut seq_q = 2000u32;
    let mut seq_b = 7000u32;
    let mut push_mqtt = |t: f64, from_client: bool, pkt: &[u8], pkts: &mut Vec<(f64, Vec<u8>)>, seq_q: &mut u32, seq_b: &mut u32| {
        let (s, d, sp, dp, seq, ack, msrc, mdst, dstmac, srcmac) = if from_client {
            (q_src, q_dst, 51000, 1883, *seq_q, *seq_b, q_src, q_dst, [0x00, 0x11, 0x22, 0x33, 0x44, 0x60], [0x00, 0x11, 0x22, 0x33, 0x44, 0x20])
        } else {
            (q_dst, q_src, 1883, 51000, *seq_b, *seq_q, q_dst, q_src, [0x00, 0x11, 0x22, 0x33, 0x44, 0x20], [0x00, 0x11, 0x22, 0x33, 0x44, 0x60])
        };
        let _ = (msrc, mdst);
        let frame = eth(
            &dstmac,
            &srcmac,
            0x0800,
            &ipv4(s, d, 6, ip_id, &tcp(s, d, sp, dp, seq, ack, 0x18, pkt)),
        );
        ip_id = ip_id.wrapping_add(1);
        if from_client {
            *seq_q += pkt.len() as u32;
        } else {
            *seq_b += pkt.len() as u32;
        }
        pkts.push((t, frame));
    };

    let mut connect_body = mqtt_str(b"MQTT");
    connect_body.push(4);
    connect_body.push(0x02);
    connect_body.extend_from_slice(&60u16.to_be_bytes());
    connect_body.extend_from_slice(&mqtt_str(b"sensor-01"));
    let connect = mqtt_pkt(0x10, &connect_body);
    push_mqtt(3.0, true, &connect, &mut pkts, &mut seq_q, &mut seq_b);
    let connack = mqtt_pkt(0x20, &[0x00, 0x00]);
    push_mqtt(3.01, false, &connack, &mut pkts, &mut seq_q, &mut seq_b);
    let mut sub_body = vec![0x00, 0x01];
    sub_body.extend_from_slice(&mqtt_str(b"factory/line1/temp"));
    sub_body.push(0);
    let subscribe = mqtt_pkt(0x82, &sub_body);
    push_mqtt(3.02, true, &subscribe, &mut pkts, &mut seq_q, &mut seq_b);
    let suback = mqtt_pkt(0x90, &[0x00, 0x01, 0x00]);
    push_mqtt(3.03, false, &suback, &mut pkts, &mut seq_q, &mut seq_b);
    for i in 0..20u32 {
        let t = 3.1 + i as f64 * 0.2;
        let temp = (25.0 + (i as f64 * 0.5).sin() * 5.0).round() * 10.0;
        let payload = format!(r#"{{"temp":{:.1},"seq":{i}}}"#, temp / 10.0);
        let mut pub_body = mqtt_str(b"factory/line1/temp");
        pub_body.extend_from_slice(&payload.as_bytes());
        let publish = mqtt_pkt(0x30, &pub_body);
        push_mqtt(t, true, &publish, &mut pkts, &mut seq_q, &mut seq_b);
    }
    // 断连 + 重连意图(DIY: 发 DISCONNECT 后又有 PUBLISH → 展示异常)
    let disc = mqtt_pkt(0xE0, &[]);
    push_mqtt(7.5, true, &disc, &mut pkts, &mut seq_q, &mut seq_b);

    // --- EtherCAT:每 1ms ---
    for i in 0..150u8 {
        let t = i as f64 * 0.001;
        let mut payload: Vec<u8> = (0..8).map(|k| ((i as usize + k) * 3 % 256) as u8).collect();
        let wkc: u16 = if i == 100 { 0 } else { 2 };
        if i == 100 {
            payload = vec![0xFF; 8];
        }
        let dg_len = payload.len() as u16;
        let total = 2 + 12 + payload.len();
        let mut ec = vec![];
        let fhdr = ((total - 2) as u16 & 0x7FF) | (1 << 12);
        ec.extend_from_slice(&fhdr.to_le_bytes());
        ec.push(0x0C); // LRW
        ec.push(i);
        ec.extend_from_slice(&0x00010000u32.to_le_bytes());
        ec.extend_from_slice(&dg_len.to_le_bytes());
        ec.extend_from_slice(&0u16.to_le_bytes());
        ec.extend_from_slice(&payload);
        ec.extend_from_slice(&wkc.to_le_bytes());
        pkts.push((
            t,
            eth(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x01], &[0x00, 0x60, 0x6E, 0x00, 0x00, 0x01], 0x88A4, &ec),
        ));
    }

    pkts.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    // 写 pcap(µs)
    let mut buf = vec![];
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    for (t, frame) in &pkts {
        let sec = base + t;
        let s = sec.floor() as u32;
        let us = ((sec - s as f64) * 1e6) as u32;
        buf.extend_from_slice(&s.to_le_bytes());
        buf.extend_from_slice(&us.to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(frame);
    }
    std::fs::write(out.join("net.pcap"), buf).unwrap();
}

// ================= IEC 104 合成样例(map104 e2e 基线,H1 修复) =================
// 此前 tests/data/iec104.pcap 用 wiki 真实样本:缺 IOA512 M_ME_NB(标度化)帧,
// 点表 ty:11 永不命中 → map104/topology e2e 失败。本生成器产出覆盖点表全部 ty 的最小会话:
// U 帧(STARTDT TX) / 总召唤流程 / SP·DP·DP_TB(带时标)·NA·NB·NC·TF·C_SC·C_SE / SQ 多信息体补信号数。

fn pcap_write(out: &PathBuf, name: &str, pkts: &[(f64, Vec<u8>)], base: f64) {
    let mut buf = vec![];
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    for (t, frame) in pkts {
        let sec = base + t;
        let s = sec.floor() as u32;
        let us = ((sec - s as f64) * 1e6) as u32;
        buf.extend_from_slice(&s.to_le_bytes());
        buf.extend_from_slice(&us.to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(frame);
    }
    std::fs::write(out.join(name), buf).unwrap();
}

fn apdu_i104(vs: u16, vr: u16, asdu: &[u8]) -> Vec<u8> {
    // 序号左移 1 位编码(C1 bit0 恒 0;C4 bit0 恒 1)——与 moddev104/scan 同语义
    let s = ((vs as u32) << 1) as u16;
    let r = ((vr as u32) << 1) as u16;
    let mut f = vec![0x68u8, (asdu.len() + 4) as u8, (s & 0xFF) as u8, ((s >> 8) & 0x7F) as u8, (r & 0xFF) as u8, ((r >> 8) & 0x7F) as u8 | 0x01];
    f.extend_from_slice(asdu);
    f
}

fn asdu104(ty: u8, n: u8, cot: u8, ca: u16) -> Vec<u8> {
    // 标准 ASDU 头(含 OA,2026-11-21 裁决):[ty,vsq,cot,OA,ca2];OA=0(主站发起)
    vec![ty, n, cot, 0x00, (ca & 0xFF) as u8, (ca >> 8) as u8]
}

fn ioa104(ioa: u16) -> Vec<u8> {
    vec![(ioa & 0xFF) as u8, (ioa >> 8) as u8, 0]
}

fn cp56104() -> [u8; 7] {
    [0x30, 0x12, 0x1E, 0x0A, 0x15, 0x0B, 0x1A] // 2026-11-21 10:30 固定 dummy 时标
}

/// TCP 载荷包(104 会话:master:4000 → slave:2404;dir=true=master→slave)
fn pkt104(t: f64, dir: bool, seq_c: &mut u32, seq_s: &mut u32, apdu: &[u8], ip_id: &mut u16, pkts: &mut Vec<(f64, Vec<u8>)>) {
    let (src, dst, sp, dp, seq, ack) = if dir {
        ([192, 168, 7, 20], [192, 168, 7, 60], 4000u16, 2404u16, *seq_c, *seq_s)
    } else {
        ([192, 168, 7, 60], [192, 168, 7, 20], 2404u16, 4000u16, *seq_s, *seq_c)
    };
    let tcp = tcp(src, dst, sp, dp, seq, ack, 0x18, apdu); // PSH+ACK
    let ip = ipv4(src, dst, 6, *ip_id, &tcp);
    *ip_id = ip_id.wrapping_add(1);
    let frame = eth(
        if dir { &[0x00, 0x60, 0x6E, 0x00, 0x00, 0x02] } else { &[0x00, 0x60, 0x6E, 0x00, 0x00, 0x01] },
        if dir { &[0x00, 0x60, 0x6E, 0x00, 0x00, 0x01] } else { &[0x00, 0x60, 0x6E, 0x00, 0x00, 0x02] },
        0x0800,
        &ip,
    );
    let n = apdu.len() as u32; // TCP seq 推进 = 完整载荷(APDU 整体)
    if dir {
        *seq_c = seq.wrapping_add(n);
    } else {
        *seq_s = seq.wrapping_add(n);
    }
    pkts.push((t, frame));
}

struct St104 {
    seq_c: u32,
    seq_s: u32,
    ip_id: u16,
}

/// 响应总召数据帧(RX 方向):时间推进 + 序号推进一体
fn send_data104(pkts: &mut Vec<(f64, Vec<u8>)>, t: &mut f64, vs: &mut u16, vr: u16, st: &mut St104, asdu: Vec<u8>, dt: f64) {
    *t += dt;
    let apdu = apdu_i104(*vs, vr, &asdu);
    *vs += 1;
    pkt104(*t, false, &mut st.seq_c, &mut st.seq_s, &apdu, &mut st.ip_id, pkts);
}

fn gen_104_pcap(out: &PathBuf) {
    let mut pkts: Vec<(f64, Vec<u8>)> = vec![];
    let base = 1767225600.0f64;
    let mut st = St104 { seq_c: 2000, seq_s: 8000, ip_id: 7 };
    let _ = &mut st;
    let ca = 1u16;
    let mut vs = 0u16;
    let mut vr = 0u16;
    let mut t = 0.0f64;
    macro_rules! nxt {
        ($t:expr, $dt:expr) => {{
            $t += $dt;
            $t
        }};
    }

    // TX:STARTDT act(U 帧;iec104_e2e 断言 "TX U " 开头摘要)
    pkt104(nxt!(t, 0.0), true, &mut st.seq_c, &mut st.seq_s, &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00], &mut st.ip_id, &mut pkts);
    // RX:STARTDT con
    pkt104(nxt!(t, 0.02), false, &mut st.seq_c, &mut st.seq_s, &[0x68, 0x04, 0x0B, 0x00, 0x00, 0x00], &mut st.ip_id, &mut pkts);
    // TX:总召唤激活
    let gi_req = {
        let mut f = asdu104(100, 1, 6, ca);
        f.push(20);
        apdu_i104(vs, vr, &f)
    };
    vs += 1;
    pkt104(nxt!(t, 0.05), true, &mut st.seq_c, &mut st.seq_s, &gi_req, &mut st.ip_id, &mut pkts);
    vr += 1;
    // RX:总召唤确认
    let gi_con = {
        let mut f = asdu104(100, 1, 7, ca);
        f.push(20);
        apdu_i104(vs, vr, &f)
    };
    vs += 1;
    pkt104(nxt!(t, 0.03), false, &mut st.seq_c, &mut st.seq_s, &gi_con, &mut st.ip_id, &mut pkts);

    // RX:响应总召数据(COT=20)
    {
        let mut f = asdu104(1, 1, 20, ca);
        f.extend_from_slice(&ioa104(100));
        f.push(0x01);
        f.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    {
        let mut f = asdu104(1, 1, 20, ca);
        f.extend_from_slice(&ioa104(101));
        f.push(0x00);
        f.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // 双点(未映射 ty3 IOA256 → 默认键名保留;map104_e2e 断言)
    {
        let mut f = asdu104(3, 1, 20, ca);
        f.extend_from_slice(&ioa104(256));
        f.push(0x02);
        f.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // 带时标双点(IOA2816 → 断路器1位置)
    {
        let mut f = asdu104(31, 1, 20, ca);
        f.extend_from_slice(&ioa104(2816));
        f.push(0x01);
        f.push(0x00);
        f.extend_from_slice(&cp56104());
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // 归一化(IOA256 → 电池SOC ×100)
    {
        let mut f = asdu104(9, 1, 20, ca);
        f.extend_from_slice(&ioa104(256));
        f.extend_from_slice(&16384i16.to_le_bytes());
        f.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // 标度化(IOA512 → 直流电压 ×0.1)← 此前真实样本缺失的关键帧
    {
        let mut f = asdu104(11, 1, 20, ca);
        f.extend_from_slice(&ioa104(512));
        f.extend_from_slice(&2205i16.to_le_bytes()); // 2205 × 0.1 = 220.5V
        f.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // 短浮点(IOA256 → 有功功率P)
    {
        let mut f = asdu104(13, 1, 20, ca);
        f.extend_from_slice(&ioa104(256));
        f.extend_from_slice(&150.5f32.to_le_bytes());
        f.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // 带时标短浮点(IOA4096 → 电网频率)
    {
        let mut f = asdu104(36, 1, 20, ca);
        f.extend_from_slice(&ioa104(4096));
        f.extend_from_slice(&50.0f32.to_le_bytes());
        f.push(0x00);
        f.extend_from_slice(&cp56104());
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // SQ 多信息体:短浮点 ×10(IOA 260..269,未映射 → 默认键名,信号数>30 断言)
    // SQ=1:仅首元素带 IOA,后续元素=值+QDS(IEC 104 连续地址语义)
    {
        let mut f = asdu104(13, 10, 20, ca);
        f[1] |= 0x80;
        f.extend_from_slice(&ioa104(260));
        for k in 0..10u16 {
            f.extend_from_slice(&(40.0 + k as f32).to_le_bytes());
            f.push(0x00);
        }
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // SQ 多信息体:标度化 ×10(IOA 520..529)
    {
        let mut f = asdu104(11, 10, 20, ca);
        f[1] |= 0x80;
        f.extend_from_slice(&ioa104(520));
        for k in 0..10u16 {
            f.extend_from_slice(&(500i16 + k as i16).to_le_bytes());
            f.push(0x00);
        }
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // SQ 多信息体:双点 ×6(IOA 260..265,ty3 未映射)
    {
        let mut f = asdu104(3, 6, 20, ca);
        f[1] |= 0x80;
        f.extend_from_slice(&ioa104(260));
        for k in 0..6u16 {
            f.push(if k % 2 == 0 { 0x01 } else { 0x02 });
            f.push(0x00);
        }
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.02);
    }
    // RX:总召唤结束
    let gi_end = {
        let mut f = asdu104(100, 1, 10, ca);
        f.push(20);
        apdu_i104(vs, vr, &f)
    };
    vs += 1;
    pkt104(nxt!(t, 0.03), false, &mut st.seq_c, &mut st.seq_s, &gi_end, &mut st.ip_id, &mut pkts);

    // TX:遥控(C_SC_NA_1 直接执行)→ RX:激活确认(iec104_e2e 断言 C_SC 信号)
    let cmd = {
        let mut f = asdu104(45, 1, 6, ca);
        f.extend_from_slice(&ioa104(3328));
        f.push(0x01);
        f.push(0x01);
        apdu_i104(vs, vr, &f)
    };
    vs += 1;
    pkt104(nxt!(t, 0.10), true, &mut st.seq_c, &mut st.seq_s, &cmd, &mut st.ip_id, &mut pkts);
    vr += 1;
    let cmd_con = {
        let mut f = asdu104(45, 1, 7, ca);
        f.extend_from_slice(&ioa104(3328));
        f.push(0x01);
        f.push(0x01);
        apdu_i104(vs, vr, &f)
    };
    vs += 1;
    pkt104(nxt!(t, 0.02), false, &mut st.seq_c, &mut st.seq_s, &cmd_con, &mut st.ip_id, &mut pkts);
    // TX:设定值(C_SE_NC_1;iec104_e2e 断言 C_SE 信号)
    let setp = {
        let mut f = asdu104(50, 1, 6, ca);
        f.extend_from_slice(&ioa104(3072));
        f.extend_from_slice(&75.0f32.to_le_bytes());
        f.push(0x01);
        apdu_i104(vs, vr, &f)
    };
    vs += 1;
    pkt104(nxt!(t, 0.10), true, &mut st.seq_c, &mut st.seq_s, &setp, &mut st.ip_id, &mut pkts);
    vr += 1;
    // RX:周期上送(COT=1)两拍:NB IOA512 与 NC IOA256 各一次(信号 pts>1)
    for (k, vnb) in [2300i16, 2250i16].iter().enumerate() {
        let mut f = asdu104(11, 1, 1, ca);
        f.extend_from_slice(&ioa104(512));
        f.extend_from_slice(&(*vnb).to_le_bytes());
        f.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f, 0.5 + k as f64);
        let mut f2 = asdu104(13, 1, 1, ca);
        f2.extend_from_slice(&ioa104(256));
        f2.extend_from_slice(&(149.0 + k as f32).to_le_bytes());
        f2.push(0x00);
        send_data104(&mut pkts, &mut t, &mut vs, vr, &mut st, f2, 0.05);
    }

    pcap_write(out, "iec104.pcap", &pkts, base);
}
