//! 储能拓扑视图(MVP ③,FR-3.5 前置):站点 → 设备(电池簇/PCS/电表/…)卡片。
//! 拓扑定义 YAML:每个设备绑定若干信号(子串/结尾匹配,与规则引擎同约定),
//! 评估 = 把数据集里匹配到的信号最新值/单位/异常事件归到设备卡片上。
//! 核心零依赖;YAML 解析用 serde_yaml_ng(core 既有依赖)。

use crate::model::{Dataset, EventKind};
use std::collections::HashMap;

/// 单个设备卡片的信号绑定
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bind {
    /// 信号键匹配:全等 或 以 `·{name}` 结尾(与 rules 信号匹配同约定)
    pub signal: String,
    /// 卡片上显示的标签(缺省用 signal)
    #[serde(default)]
    pub label: String,
    /// 越限判定(表达式同规则引擎 $ / prev;None = 只显示不判级)
    #[serde(default)]
    pub warn: Option<String>,
    #[serde(default)]
    pub fault: Option<String>,
}

/// 一台设备(电池簇/PCS/电表/…)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Device {
    pub id: String,
    /// 设备类型:cluster(电池簇)| pcs(变流器)| meter(电表)| other
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub binds: Vec<Bind>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Topology {
    #[serde(default)]
    pub name: String,
    pub devices: Vec<Device>,
}

impl Topology {
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_yaml_ng::from_str::<Topology>(text).map_err(|e| format!("拓扑定义解析失败: {e}"))
    }

    pub fn load_file(p: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        Self::parse(&text)
    }

    /// 序列化为 YAML(GUI 保存用;GUI 不直接依赖 YAML crate)
    pub fn to_yaml(&self) -> String {
        serde_yaml_ng::to_string(self).unwrap_or_default()
    }
}

// ================= 评估 =================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    /// 未绑定任何信号(没数据)
    NoData,
    Ok,
    Warn,
    Fault,
}

impl Health {
    pub fn label(&self) -> &'static str {
        match self {
            Health::NoData => "无数据",
            Health::Ok => "正常",
            Health::Warn => "告警",
            Health::Fault => "故障",
        }
    }
}

/// 一个绑定在数据集里的落点
#[derive(Clone, Debug)]
pub struct BoundSig {
    pub bind_label: String,
    pub series_key: String,
    pub unit: String,
    pub last: f64,
    pub level: Health,
    /// 最新值所在帧(点击跳帧)
    pub frame: Option<u32>,
    pub t_ns: u64,
}

#[derive(Clone, Debug)]
pub struct DeviceState {
    pub id: String,
    pub kind: String,
    pub health: Health,
    pub sigs: Vec<BoundSig>,
    /// 归到该设备的异常事件数(按通道标签含设备 id 匹配)
    pub event_n: usize,
}

#[derive(Clone, Debug, Default)]
pub struct TopoState {
    pub devices: Vec<DeviceState>,
    /// 未被任何设备捕获的信号数(绑定覆盖度)
    pub unbound: usize,
}

/// 简单阈值表达式:`$ > x` / `$ >= x` / `$ < x` / `$ <= x` / `$ != x`(常量右值,够用)
fn eval_cmp(expr: &str, v: f64) -> Option<bool> {
    let s = expr.trim();
    let (op, rhs) = [">=", "<=", "!=", ">", "<"]
        .iter()
        .find_map(|&op| s.split_once(op).map(|(_, r)| (op, r)))?;
    let x: f64 = rhs.trim().parse().ok()?;
    Some(match op {
        ">=" => v >= x,
        "<=" => v <= x,
        "!=" => v != x,
        ">" => v > x,
        "<" => v < x,
        _ => false,
    })
}

/// 评估拓扑:把数据集信号匹配到设备,计算每卡健康级与事件计数。
/// 纯函数,不改 ds;卡片级取绑定中最严重的一级。
pub fn evaluate(ds: &Dataset, topo: &Topology) -> TopoState {
    // 每通道标签(事件归属用)
    let chan_labels: HashMap<(u16, u16), String> = ds
        .channels
        .iter()
        .map(|c| ((c.source, c.id), c.label.clone()))
        .collect();

    let mut st = TopoState::default();
    let mut captured: std::collections::HashSet<String> = Default::default();
    for d in &topo.devices {
        let mut dev = DeviceState { id: d.id.clone(), kind: d.kind.clone(), health: Health::NoData, sigs: vec![], event_n: 0 };
        for b in &d.binds {
            // 与规则引擎同约定:全等或以 ·name 结尾
            let hits: Vec<&crate::model::Series> = ds
                .signals
                .iter()
                .filter(|s| s.key == b.signal || s.key.ends_with(&format!("·{}", b.signal)))
                .collect();
            for s in hits {
                captured.insert(s.key.clone());
                let Some(&(t, v, fi)) = s.pts.last() else { continue };
                let level = if let Some(e) = &b.fault {
                    if eval_cmp(e, v) == Some(true) {
                        Health::Fault
                    } else if let Some(w) = &b.warn {
                        if eval_cmp(w, v) == Some(true) { Health::Warn } else { Health::Ok }
                    } else {
                        Health::Ok
                    }
                } else if let Some(w) = &b.warn {
                    if eval_cmp(w, v) == Some(true) { Health::Warn } else { Health::Ok }
                } else {
                    Health::Ok
                };
                dev.sigs.push(BoundSig {
                    bind_label: if b.label.is_empty() { b.signal.clone() } else { b.label.clone() },
                    series_key: s.key.clone(),
                    unit: s.unit.clone(),
                    last: v,
                    level,
                    frame: Some(fi),
                    t_ns: t,
                });
                if level as u8 > dev.health as u8 {
                    dev.health = level;
                }
            }
        }
        // 事件归属:通道标签含设备 id 或绑定信号键含设备 id 的诊断事件
        for e in &ds.events {
            if e.kind == EventKind::Info {
                continue; // 重组完成等正常信息不算异常
            }
            let lab = chan_labels.get(&(e.source, e.channel)).cloned().unwrap_or_default();
            let hit = lab.contains(&d.id)
                || e.detail.contains(&d.id)
                || e.rule.as_ref().map(|r| r.signals.iter().any(|(k, _, _)| k.contains(&d.id))).unwrap_or(false);
            if hit {
                dev.event_n += 1;
            }
        }
        if dev.event_n > 0 && (dev.health == Health::Ok || dev.health == Health::NoData) {
            dev.health = Health::Warn;
        }
        st.devices.push(dev);
    }
    st.unbound = ds.signals.iter().filter(|s| !captured.contains(&s.key)).count();
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_eval_thresholds() {
        let t = Topology::parse(
            "name: demo\n\ndevices:\n  - id: 簇1\n    kind: cluster\n    binds:\n      - {signal: TempSensor, label: 温度, warn: '$ > 30', fault: '$ > 45'}\n",
        )
        .unwrap();
        assert_eq!(t.devices.len(), 1);
        assert_eq!(eval_cmp("$ > 30", 31.0), Some(true));
        assert_eq!(eval_cmp("$ <= 45", 50.0), Some(false));
    }
}
