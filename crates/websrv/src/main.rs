//! iotprobe-web — Web 实时台·可演示版本(ADR-0008 双 UI 策略 / ADR-0012)。
//!
//! 数据面:模拟 CAN 源(温度故障/心跳停发注入) → core live 管线 → 周期 analyze(DBC+规则包) →
//! 契约 WS(frame/event/signal 三类信封) → 浏览器(零构建前端)。
//! 边界:与 egui 台共享 iotprobe-core,无反向依赖;contracts/ 只读;不引入新第三方依赖。

mod contract;
mod http;
mod pipeline;
mod sim;
mod ws;

use iotprobe_core::dbc;
use iotprobe_core::dissect::AnalyzeCfg;
use iotprobe_core::rules::parse_pack_yaml;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const WEB_INDEX: &str = include_str!("../web/index.html");
pub const WEB_APP_JS: &str = include_str!("../web/app.js");
pub const WEB_STYLE: &str = include_str!("../web/style.css");
pub const MOTOR_DBC: &str = include_str!("../../../samples/motor.dbc");
pub const DEMO_RULES: &str = include_str!("../assets/demo-bms.rules.yaml");

static CLIENT_SEQ: AtomicU64 = AtomicU64::new(1);

/// 故障注入控制(HTTP 按钮状态 → sim 线程)
pub struct Inject {
    pub temp_fault: AtomicBool,
    pub hb_stall_until: Mutex<Option<Instant>>,
}

/// 服务端帧过滤(T-1.11):ids None/空=全部;dir 空=全部
#[derive(Clone, Default)]
pub struct Filter {
    pub ids: Option<Vec<u32>>,
    pub dir: String, // "" | "rx" | "tx"
}

impl Filter {
    pub fn matches(&self, id: u32, dir: &str) -> bool {
        if let Some(ids) = &self.ids {
            if !ids.is_empty() && !ids.contains(&id) {
                return false;
            }
        }
        if !self.dir.is_empty() && self.dir != dir {
            return false;
        }
        true
    }
}

pub struct ClientHandle {
    pub id: u64,
    pub tx: std::sync::mpsc::SyncSender<String>,
    pub filter: Arc<Mutex<Filter>>,
    pub stop: Arc<AtomicBool>,
}

#[derive(Default)]
pub struct Hub {
    pub clients: Mutex<Vec<ClientHandle>>,
    pub seq: AtomicU64,
}

impl Hub {
    /// 广播一条信封消息 {"type","seq","payload"}(主 spec 10.3);type=frame 时按各客户端过滤器放行
    pub fn push(&self, typ: &str, payload: &str, id: u32, dir: &str) {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let msg = format!("{{\"type\":\"{typ}\",\"seq\":{n},\"payload\":{payload}}}");
        let clients = self.clients.lock().unwrap();
        for c in clients.iter() {
            if typ == "frame" {
                let f = c.filter.lock().unwrap();
                if !f.matches(id, dir) {
                    continue;
                }
            }
            let _ = c.tx.try_send(msg.clone());
        }
    }
}

pub struct StatsCounters {
    pub t0: Instant,
    pub frames: AtomicU64,
    pub signal_pts: AtomicU64,
    pub events: AtomicU64,
}

pub struct HttpState {
    pub hub: Arc<Hub>,
    pub inject: Arc<Inject>,
    pub stats: Arc<StatsCounters>,
    pub store: Arc<Mutex<pipeline::RecStore>>,
    pub web_index: &'static str,
    pub web_app: &'static str,
    pub web_style: &'static str,
}

fn main() {
    let mut port = 8791u16;
    let mut bind = "127.0.0.1".to_string();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(8791);
            }
            "--bind" => {
                i += 1;
                bind = args.get(i).cloned().unwrap_or_else(|| bind.clone());
            }
            "--help" | "-h" => {
                println!("用法: iotprobe-web [--port 8791] [--bind 127.0.0.1]");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let pack = parse_pack_yaml(DEMO_RULES, "demo-bms.rules.yaml").expect("demo-bms 规则包解析失败");
    let cfg = Arc::new(AnalyzeCfg {
        dbc: Some(dbc::parse(MOTOR_DBC)),
        rule_packs: vec![pack],
        ..Default::default()
    });

    let hub = Arc::new(Hub::default());
    let store = Arc::new(Mutex::new(pipeline::RecStore::default()));
    let inject = Arc::new(Inject {
        temp_fault: AtomicBool::new(false),
        hb_stall_until: Mutex::new(None),
    });
    let stats = Arc::new(StatsCounters {
        t0: Instant::now(),
        frames: AtomicU64::new(0),
        signal_pts: AtomicU64::new(0),
        events: AtomicU64::new(0),
    });
    let stop = Arc::new(AtomicBool::new(false));

    let sim = sim::SimSource::new(inject.clone(), hub.clone(), stats.clone());
    let _ingest = pipeline::spawn_ingest(sim, store.clone(), stop.clone());
    let _analyze = pipeline::spawn_analyzer(cfg, store.clone(), hub.clone(), stats.clone(), stop.clone());

    let state = Arc::new(HttpState {
        hub: hub.clone(),
        inject: inject.clone(),
        stats: stats.clone(),
        store: store.clone(),
        web_index: WEB_INDEX,
        web_app: WEB_APP_JS,
        web_style: WEB_STYLE,
    });

    let listener = match TcpListener::bind((bind.as_str(), port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("端口 {bind}:{port} 绑定失败: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("IoTProbe Web 实时台(演示) → http://{bind}:{port}");
    eprintln!("模拟 CAN 源: 0x1A0 MOTOR_STATUS@10ms · 0x100 HEARTBEAT@500ms · CAN FD 0x18FF0102@2s(时基 sw/L0,ADR-5)");
    eprintln!("演示剧本: docs/DEMO-web.md · Ctrl+C 停止");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = state.clone();
                std::thread::spawn(move || http::handle_conn(&st, s));
            }
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_match() {
        let f = Filter { ids: Some(vec![0x1A0, 0x100]), dir: "rx".into() };
        assert!(f.matches(0x1A0, "rx"));
        assert!(f.matches(0x100, "rx"));
        assert!(!f.matches(0x123, "rx"));
        assert!(!f.matches(0x1A0, "tx"));
        let all = Filter::default();
        assert!(all.matches(0x18FF0102, "rx"));
    }

    #[test]
    fn demo_rules_parse() {
        let pack = parse_pack_yaml(DEMO_RULES, "demo-bms.rules.yaml").expect("解析失败");
        assert_eq!(pack.pack, "demo-bms");
        assert_eq!(pack.rules.len(), 3);
        assert!(pack.rules.iter().any(|r| r.id == "MOTOR_TEMP_FAULT" && r.level == "fault"));
        assert!(pack.rules.iter().any(|r| r.on == iotprobe_core::rules::OnKind::Rate));
    }
}
