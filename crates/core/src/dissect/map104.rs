//! IEC 60870-5-104 信息体点表(MVP ②:配置编辑器 / FR-3.2 变比偏移的 104 侧)。
//! 点表 = (类型, IOA[, CA]) → 工程名 / 缩放 / 偏移 / 单位 / 勾画。
//! YAML 与 JSON 双格式:生态惯例是 YAML(盘点脚本自动产出),GUI 编辑保存 JSON。
//! 短浮点(类型 13/36/50)factor/offset 通常为 1/0,主要用于命名与单位;
//! 整型遥测(9/11/15/48/49)与遥控回显(45/46/58/59)可自由变比。

use serde::Deserialize;
use std::collections::HashMap;

/// 单个信息体地址的工程配置
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Pt104 {
    pub ioa: u32,
    /// ASDU 类型 ID(45=单点遥控,13=短浮点遥测…);0 = 不限类型
    #[serde(default)]
    pub ty: u8,
    /// 公共地址(站点号);None = 任意 CA
    #[serde(default)]
    pub ca: Option<u16>,
    /// 工程信号名(空 = 保持默认 `IOA{n}`)
    #[serde(default)]
    pub name: String,
    #[serde(default = "one")]
    pub factor: f64,
    #[serde(default)]
    pub offset: f64,
    #[serde(default)]
    pub unit: String,
    /// 是否进时序曲线(遥信默认 true,命令类默认 false)
    #[serde(default = "yes")]
    pub plot: bool,
}

fn one() -> f64 {
    1.0
}
fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Map104 {
    pub points: Vec<Pt104>,
}

impl Map104 {
    /// 查找:(类型, IOA, CA) → 命中优先级 ty+ca > ty > 仅 IOA
    pub fn meta(&self, ty: u8, ioa: u32, ca: u16) -> Option<&Pt104> {
        let exact = self.points.iter().find(|p| {
            p.ioa == ioa && (p.ty == 0 || p.ty == ty) && p.ca.map_or(true, |c| c == ca)
        });
        exact.or_else(|| self.points.iter().find(|p| p.ioa == ioa && p.ty == 0 && p.ca.is_none()))
    }

    /// 从 YAML/JSON 文本加载(按扩展名无从判断时先试 YAML 再试 JSON)
    pub fn parse(text: &str) -> Result<Self, String> {
        if let Ok(m) = serde_yaml_ng::from_str::<Map104>(text) {
            if !m.points.is_empty() {
                return Ok(m);
            }
        }
        serde_json::from_str::<Map104>(text).map_err(|e| format!("点表解析失败(YAML/JSON 均不识别): {e}"))
    }
}

/// 从 104 抓包自动盘点的 YAML(生成脚本形态:`points:` 下 `{type_id, ioa, ca, hits}`)
/// 合成初始点表:name 空、factor 1,供 GUI 编辑补全语义。
pub fn from_inventory(text: &str) -> Result<Map104, String> {
    #[derive(Deserialize)]
    struct Inv {
        #[serde(default)]
        points: Vec<InvPt>,
    }
    #[derive(Deserialize)]
    struct InvPt {
        type_id: u8,
        ioa: String,
        #[serde(default)]
        ca: u16,
    }
    let inv: Inv = serde_yaml_ng::from_str(text).map_err(|e| format!("盘点表解析失败: {e}"))?;
    let mut points = Vec::new();
    for p in inv.points {
        // "256" 或 "(序列/无IOA)" —— 后者无法按 IOA 配置,跳过并如实丢弃
        if let Ok(ioa) = p.ioa.trim().parse::<u32>() {
            points.push(Pt104 {
                ioa,
                ty: p.type_id,
                ca: (p.ca > 0).then_some(p.ca),
                name: String::new(),
                factor: 1.0,
                offset: 0.0,
                unit: String::new(),
                plot: true,
            });
        }
    }
    Ok(Map104 { points })
}

// ================= 解码侧 =================

/// 应用变比/偏移:f = raw × factor + offset
pub fn scaled(p: &Pt104, raw: f64) -> f64 {
    raw * p.factor + p.offset
}

// ================= 点表编辑器(增量 API,GUI 直接操作 Map104) =================

impl Map104 {
    /// 按显示名排序快照(编辑表单行序稳定)
    pub fn sorted(&self) -> Vec<&Pt104> {
        let mut v: Vec<&Pt104> = self.points.iter().collect();
        v.sort_by_key(|p| (p.ioa, p.ty));
        v
    }
    /// upsert:同 (ioa, ty) 覆盖,否则插入
    pub fn upsert(&mut self, p: Pt104) {
        if let Some(s) = self.points.iter_mut().find(|x| x.ioa == p.ioa && x.ty == p.ty) {
            *s = p;
        } else {
            self.points.push(p);
        }
    }
    /// (ty,ioa)→点 索引(解码器热路径用)。同 IOA 可挂多个类型(遥测/遥信分址),
    /// 通配条目 ty=0 单独落在 (0, ioa) 键下,查找时按 精确→通配 两级命中。
    pub fn index(&self) -> HashMap<(u8, u32), &Pt104> {
        self.points.iter().map(|p| ((if p.ty == 0 { 0 } else { p.ty }, p.ioa), p)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_yaml_minimal() {
        let m = Map104::parse("points:\n  - {ioa: 256, name: 主变油温, factor: 0.1, unit: °C}\n").unwrap();
        assert_eq!(m.points.len(), 1);
        let p = m.meta(13, 256, 512).unwrap();
        assert_eq!(p.name, "主变油温");
        assert_eq!(scaled(p, 123.0), 12.3);
    }

    #[test]
    fn parse_json_and_lookup_priority() {
        let m = Map104::parse(r#"{"points":[{"ioa":256,"ty":13,"ca":512,"name":"Ua","unit":"V"}]}"#).unwrap();
        // ty+ca 精确命中
        assert_eq!(m.meta(13, 256, 512).unwrap().name, "Ua");
        // 类型不匹配则回退到仅 IOA 条目(此处无)→ None
        assert!(m.meta(9, 256, 512).is_none());
    }

    #[test]
    fn inventory_yaml_to_points() {
        let inv = "points:\n  - {type_id: 13, type_name: M_ME_NC_1, ioa: 256, cot: 20, ca: 512, hits: 2}\n  - {type_id: 5, ioa: (序列/无IOA), ca: 512, hits: 1}\n";
        let m = from_inventory(inv).unwrap();
        assert_eq!(m.points.len(), 1, "无 IOA 条目应跳过");
        assert_eq!(m.points[0].ioa, 256);
        assert_eq!(m.points[0].ca, Some(512));
    }
}
