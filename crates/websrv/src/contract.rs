//! LiveFrame → frame.schema.json 形态的契约 JSON。
//! 与 crates/app/src/live.rs 的 live_frame_to_jsonl 同源移植(ADR-0012:两 UI/服务共享同一契约表示)。

use iotprobe_core::ingest::live::{BusKind, LiveFrame};
use iotprobe_core::model::Dir;
use serde_json::json;

pub fn live_frame_json(f: &LiveFrame) -> String {
    let bus_type = match f.bus_type {
        BusKind::Can => "can",
        BusKind::CanFd => "canfd",
        BusKind::Uart => "uart",
        BusKind::Ecat => "ecat",
    };
    let dir = match f.dir {
        Dir::Rx => "rx",
        Dir::Tx => "tx",
        Dir::Unknown => "rx", // ADR-0007:无方向 → rx + assumed_dir
    };
    let id_type = match f.bus_type {
        BusKind::Can | BusKind::CanFd => {
            if f.id_ext {
                "ext"
            } else {
                "std"
            }
        }
        _ => "none",
    };
    let mut meta = serde_json::Map::new();
    if let Some(sq) = f.seq {
        meta.insert("seq".into(), json!(sq));
    }
    if let Some(g) = f.meta_gap {
        meta.insert("gap".into(), json!(g));
    }
    if f.dir == Dir::Unknown {
        meta.insert("assumed_dir".into(), json!(true));
    }
    // alias 为 None 时必须省略字段:core 解析器对 alias 无条件 parse_string,
    // 输出 null 会被判坏行(schema 中 alias 本为 optional,省略才是正确形态)
    let bus = match &f.alias {
        Some(a) => json!({"type": bus_type, "ch": f.ch, "alias": a}),
        None => json!({"type": bus_type, "ch": f.ch}),
    };
    let obj = json!({
        "ts_ns": f.ts_ns,
        "ts_src": f.ts_src.label(),
        "bus": bus,
        "dir": dir,
        "id": f.id,
        "id_type": id_type,
        "dlc": f.data.len(),
        "data": f.data.iter().map(|b| json!(b)).collect::<Vec<_>>(),
        "meta": meta,
    });
    serde_json::to_string(&obj).unwrap_or_default()
}
