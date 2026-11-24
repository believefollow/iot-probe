//! Modbus 设备模拟器数据面(P1):
//! - 点位表解析(mbdev_points.yaml 形态:devN 全局节 + devN_分节 点位)
//! - 寄存器状态机:每 dev 一块 0x10000 寄存器空间,按点位类型初始化,
//!   支持 func3/4 读、func6/16 写;读走快照 → NDJSON 进 live 管线(联调同屏可见)。
//! server 传输层(TcpListener)在 app 侧,这里只做纯逻辑,便于单测。

use serde_yaml_ng::Value as Yv;
use std::collections::HashMap;

/// 一个 Modbus 模拟设备(devN 节)
#[derive(Clone, Debug)]
pub struct MbDev {
    pub id: u32,
    pub name: String,
    pub port: u16,
    pub slave: u8,
    pub poll_ms: u64,
    /// 链路形态:tcp = Modbus TCP(MBAP 头);rtu_tcp = RTU-over-TCP(串口服务器透传,slave+CRC 定帧)。
    /// 其余取值按 tcp 处理(兼容旧表)
    pub link: String,
    /// 全部点位(跨分节合并;键=dev内唯一键)
    pub points: Vec<MbPoint>,
}

/// 一个点位
#[derive(Clone, Debug)]
pub struct MbPoint {
    pub key: String,
    pub name: String,
    pub addr: u16,
    /// func 3=保持寄存器 4=输入寄存器;bit 点归 func3
    pub func: u8,
    /// 类型:u16/i16/i32/u32/str/mac/bit
    pub ty: String,
    pub regs: u16,
    pub scale: f64,
    /// bit 点的位号
    pub bit: Option<u16>,
    /// 分节名(grp / devN_分节)
    pub grp: String,
    /// rw:1 = 可写
    pub rw: bool,
    /// 随机扰动下限(物理值;Random 场景用;缺省 = init 或 0)
    pub min: Option<f64>,
    /// 随机扰动上限(物理值;缺省 = init 或 0)
    pub max: Option<f64>,
    /// 启动初值(raw 寄存器值;不经 scale)
    pub init: Option<f64>,
    /// 字符串初值
    pub init_str: Option<String>,
    /// 单位(仅展示;点位表 unit 字段)
    pub unit: Option<String>,
    /// 枚举表(物理值 → 含义;点位表 enum 字段,如 {0: 停机, 1: 运行});无则按数值显示
    pub enum_: Option<Vec<(f64, String)>>,
}

/// 解析整个点位表;返回 (设备列表, 告警)。
/// 常见坑自动容错:YAML 指示符 `unit: %`(裸 % 不能作为标量开头)自动加引号再解析。
pub fn parse_points_yaml(text: &str) -> Result<(Vec<MbDev>, Vec<String>), String> {
    let cleaned = text.replace(": %,", ": \"%\",");
    let y: Yv = serde_yaml_ng::from_str(&cleaned).map_err(|e| format!("YAML 解析失败({e});请检查报错位置的引号/缩进/特殊字符"))?;
    let map = y.as_mapping().ok_or("顶层应为映射")?;
    let mut warns = vec![];
    // devN 全局节:{enable, name, link, ip, port, slave, poll_ms}
    let mut devs: Vec<MbDev> = vec![];
    let mut dev_secs: HashMap<u32, Vec<(&Yv, &Yv)>> = HashMap::new();
    let mut dev_order: Vec<u32> = vec![];
    for (k, v) in map {
        let Some(ks) = k.as_str() else { continue };
        if let Some(m) = ks.strip_prefix("dev").and_then(|r| r.parse::<u32>().ok()) {
            // 纯 devN 节 = 设备定义(enable:0 跳过)
            if v.as_mapping().is_some() {
                match parse_dev_head(m, v) {
                    Ok(d) => {
                        devs.push(d);
                        dev_order.push(m);
                    }
                    Err(e) if e == "disabled" => {}
                    Err(e) => return Err(e),
                }
            }
        } else if let Some((dn, _rest)) = ks.strip_prefix("dev").and_then(|r| r.split_once('_')) {
            if let Ok(dn) = dn.parse::<u32>() {
                // 点位分节是映射:{a0: {...}, a11: {...}}
                if let Some(vm) = v.as_mapping() {
                    dev_secs.entry(dn).or_default().extend(vm.iter().map(|(pk, pv)| (pk, pv)));
                }
            }
        }
    }
    // 组装点位(按 dev 顺序 + 分节出现顺序)
    let mut out = vec![];
    for dn in dev_order {
        let Some(mut dev) = devs.iter().find(|d| d.id == dn).cloned() else { continue };
        dev.points = dev_secs.remove(&dn).unwrap_or_default().iter()
            .filter_map(|(pk, pv)| {
                let pk_str = pk.as_str()?;
                parse_point(pk_str, pv, &dev.name).map(|r| (pk_str.to_string(), r))
            })
            .filter_map(|(k, r)| match r {
                Ok(p) => Some(p),
                Err(e) => {
                    warns.push(format!("dev{dn} 点 {k}: {e}"));
                    None
                }
            })
            .collect();
        out.push(dev);
    }
    if out.is_empty() {
        return Err("点位表中没有可用的 devN 设备定义".into());
    }
    Ok((out, warns))
}

fn parse_dev_head(id: u32, v: &Yv) -> Result<MbDev, String> {
    let m = v.as_mapping().ok_or("devN 应为映射")?;
    let get = |k: &str| m.get(Yv::String(k.into()));
    let enable = get("enable").and_then(|x| x.as_i64()).unwrap_or(1);
    if enable == 0 {
        return Err("disabled".into());
    }
    Ok(MbDev {
        id,
        name: get("name").and_then(|x| x.as_str()).unwrap_or("未命名").to_string(),
        port: get("port").and_then(|x| x.as_u64()).unwrap_or(502) as u16,
        slave: get("slave").and_then(|x| x.as_u64()).unwrap_or(1) as u8,
        poll_ms: get("poll_ms").and_then(|x| x.as_u64()).unwrap_or(1000),
        link: get("link").and_then(|x| x.as_str()).unwrap_or("tcp").to_string(),
        points: vec![],
    })
}

fn parse_point(key: &str, v: &Yv, _dev: &str) -> Option<Result<MbPoint, String>> {
    let m = v.as_mapping()?;
    let get = |k: &str| m.get(Yv::String(k.into()));
    let name = get("name").and_then(|x| x.as_str()).unwrap_or(key).to_string();
    let Some(addr) = get("addr").and_then(|x| parse_addr(x)) else {
        return Some(Err("缺少/无法解析 addr".into()));
    };
    let func = get("func").and_then(|x| x.as_u64()).unwrap_or(3) as u8;
    let ty = get("type").and_then(|x| x.as_str()).unwrap_or("u16").to_string();
    let regs = get("regs").and_then(|x| x.as_u64()).unwrap_or(1).max(1) as u16;
    let scale = get("scale").and_then(|x| x.as_f64()).unwrap_or(1.0);
    let bit = get("bit").and_then(|x| x.as_u64()).map(|b| b as u16);
    let rw = get("rw").and_then(|x| x.as_u64()).unwrap_or(0) == 1;
    let grp = get("grp").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let init = get("init").and_then(|x| x.as_f64());
    let init_str = get("init").and_then(|x| x.as_str()).map(|s| s.to_string());
    let min = get("min").and_then(|x| x.as_f64());
    let max = get("max").and_then(|x| x.as_f64());
    let unit = get("unit").and_then(|x| x.as_str()).map(|s| s.to_string());
    // enum: {0: 停机, 1: 运行} → 有序 (物理值, 含义);键可为整数或数字字符串
    let enum_ = get("enum")
        .and_then(|x| x.as_mapping())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    let key = k
                        .as_f64()
                        .or_else(|| k.as_str().and_then(|s| s.trim().parse::<f64>().ok()))?;
                    let label = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| key.to_string());
                    Some((key, label))
                })
                .collect::<Vec<_>>()
        })
        .filter(|v: &Vec<(f64, String)>| !v.is_empty());
    // bit 点不占额外寄存器(宿主寄存器由同地址 u16 点创建;自己只记位号)
    let span = if ty == "bit" { 0 } else { regs };
    Some(Ok(MbPoint { key: key.to_string(), name, addr, func, ty, regs: span, scale, bit, grp, rw, min, max, init, init_str, unit, enum_ }))
}

/// addr 支持 0x1A2B 十六进制与十进制两种写法
fn parse_addr(v: &Yv) -> Option<u16> {
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u16::from_str_radix(h, 16).ok();
        }
        return s.parse().ok();
    }
    v.as_u64().map(|n| n as u16)
}

// ---------------- 寄存器状态机 ----------------

/// 一台设备的寄存器空间 + 点位索引
#[derive(Clone, Default)]
pub struct RegSpace {
    /// addr → 值(func3 与 func4 分开:键高位置 func 位)
    regs: HashMap<u32, u16>,
    pub points: Vec<MbPoint>,
    /// 写计数(联调观测)
    pub writes: u64,
    /// 手动置值钉住的点位名(GUI 置值 = 📌 已置):Random 场景与 Fault 注入都不再改动它们,
    /// 直到释放——"大部分点随机波动、个别点手动钉住"的真实联调形态
    pub pinned: std::collections::HashSet<String>,
}

impl RegSpace {
    pub fn new(points: Vec<MbPoint>) -> Self {
        let mut rs = RegSpace { regs: HashMap::new(), points, writes: 0, pinned: Default::default() };
        rs.apply_inits();
        rs
    }

    fn key(addr: u16, func: u8) -> u32 {
        ((func as u32) << 16) | addr as u32
    }

    /// 按 init/类型初始化寄存器
    pub fn apply_inits(&mut self) {
        // 收集占位(addr 集合),str/mac 先置 0 再填字符。
        // bit 点位也必须注册所在寄存器:否则该地址从未注册,主机读它必回 0x02 非法地址
        // (回归:真实点位表状态段几乎全是无 init 的 bit 点,EMS 逐点位读全踩 0x02)
        for p in self.points.clone() {
            if p.ty == "bit" {
                self.regs.entry(Self::key(p.addr, p.func)).or_insert(0);
                continue;
            }
            for i in 0..p.regs {
                self.regs.entry(Self::key(p.addr + i, p.func)).or_insert(0);
            }
        }
        for p in &self.points {
            match p.ty.as_str() {
                "bit" => {
                    if let Some(b) = p.bit {
                        if p.init.map(|v| v != 0.0).unwrap_or(false) {
                            let k = Self::key(p.addr, p.func);
                            let e = self.regs.entry(k).or_insert(0);
                            *e |= 1 << b;
                        }
                    }
                }
                "str" | "mac" => {
                    if let Some(s) = &p.init_str {
                        let bytes = s.as_bytes();
                        for (i, r) in (0..p.regs).enumerate() {
                            let b0 = bytes.get(i * 2).copied().unwrap_or(0) as u16;
                            let b1 = bytes.get(i * 2 + 1).copied().unwrap_or(0) as u16;
                            self.regs.insert(Self::key(p.addr + r as u16, p.func), (b0 << 8) | b1);
                        }
                    }
                }
                "i32" | "u32" => {
                    if let Some(v) = p.init {
                        // init 为 raw 值(与 Excel 导出的寄存器值一致,不经 scale)
                        let raw = v as i64;
                        let (hi, lo) = ((raw >> 16) as u16, (raw & 0xFFFF) as u16);
                        self.regs.insert(Self::key(p.addr, p.func), hi);
                        self.regs.insert(Self::key(p.addr + 1, p.func), lo);
                    }
                }
                _ => {
                    if let Some(v) = p.init {
                        let raw = (v as i64).clamp(i16::MIN as i64, u16::MAX as i64) as u16;
                        self.regs.insert(Self::key(p.addr, p.func), raw);
                    }
                }
            }
        }
    }

    /// func3/4 读 n 个寄存器;返回 None = 地址未定义(交异常码)
    pub fn read(&self, func: u8, addr: u16, n: u16) -> Option<Vec<u16>> {
        let mut out = vec![];
        for i in 0..n {
            match self.regs.get(&Self::key(addr + i, func)) {
                Some(v) => out.push(*v),
                None => {
                    if out.is_empty() && i == 0 {
                        return None;
                    }
                    out.push(0); // 区域内未定义的寄存器补 0(方便大块读)
                }
            }
        }
        Some(out)
    }

    /// func6 写单寄存器;返回 true=地址存在
    pub fn write_one(&mut self, addr: u16, val: u16) -> bool {
        // 写到任意已定义 func(以 func3 优先;点位表里同一地址 func 一致)
        for func in [3u8, 4] {
            let k = Self::key(addr, func);
            if self.regs.contains_key(&k) {
                self.regs.insert(k, val);
                self.writes += 1;
                return true;
            }
        }
        self.regs.insert(Self::key(addr, 3), val);
        self.writes += 1;
        false
    }

    /// func16 写多寄存器
    pub fn write_multi(&mut self, addr: u16, vals: &[u16]) -> bool {
        let mut known = true;
        for (i, v) in vals.iter().enumerate() {
            if !self.write_one(addr + i as u16, *v) {
                known = false;
            }
        }
        known
    }

    /// 范围感知随机扰动:jitter = (0..1) 均匀数。
    /// 点位有 min/max → 物理值落在 [min,max] 内按 jitter 线性取值(确定性可复现);
    /// 无 min/max → 当前值 ±2% 小幅抖动(旧行为)。返回是否写了。
    pub fn jitter_point(&mut self, name: &str, jitter: f64) -> bool {
        let Some(p) = self.points.iter().find(|p| p.name == name) else { return false };
        if self.pinned.contains(&p.name) {
            return false; // 📌 已置点位:场景引擎不碰
        }
        if let (Some(lo), Some(hi)) = (p.min, p.max) {
            if hi > lo {
                let phys = lo + (hi - lo) * jitter.clamp(0.0, 1.0);
                return self.write_point_by_name(name, phys);
            }
        }
        // 旧行为:当前物理值 ±2%
        let cur = self
            .snapshot_points()
            .into_iter()
            .find(|(n, _, _, _, _)| n == name)
            .map(|(_, _, phys, _, _)| phys)
            .unwrap_or(0.0);
        let delta = (jitter - 0.5) * cur.abs().max(1.0) * 0.02;
        self.write_point_by_name(name, cur + delta)
    }

    /// 按点位名写物理值(scale 折算);GUI 手动置值/场景引擎用
    pub fn write_point_by_name(&mut self, name: &str, phys: f64) -> bool {
        let Some(p) = self.points.iter().find(|p| p.name == name) else { return false };
        let raw = if p.scale != 0.0 { (phys / p.scale).round() as i64 } else { phys as i64 };
        match p.ty.as_str() {
            "bit" => {
                if let Some(b) = p.bit {
                    let k = Self::key(p.addr, p.func);
                    let e = self.regs.entry(k).or_insert(0);
                    if raw != 0 {
                        *e |= 1 << b;
                    } else {
                        *e &= !(1 << b);
                    }
                    self.writes += 1;
                    true
                } else {
                    false
                }
            }
            "i32" | "u32" => {
                let (hi, lo) = ((raw >> 16) as u16, raw as u16);
                self.write_multi(p.addr, &[hi, lo])
            }
            _ => self.write_one(p.addr, raw.clamp(i16::MIN as i64, u16::MAX as i64) as u16),
        }
    }

    /// 单个点位的当前物理值(bit→0/1;i32/u32 两寄存器拼回;其余 × scale)——表格/主机读值记录共用
    pub fn phys_of(&self, p: &MbPoint) -> f64 {
        match p.ty.as_str() {
            "bit" => self.regs.get(&Self::key(p.addr, p.func)).copied().unwrap_or(0)
                .checked_shr(p.bit.unwrap_or(0) as u32)
                .map(|v| (v & 1) as f64)
                .unwrap_or(0.0),
            "i32" => {
                let hi = self.regs.get(&Self::key(p.addr, p.func)).copied().unwrap_or(0) as u32;
                let lo = self.regs.get(&Self::key(p.addr + 1, p.func)).copied().unwrap_or(0) as u32;
                ((((hi << 16) | lo) as i32) as f64) * p.scale
            }
            "u32" => {
                let hi = self.regs.get(&Self::key(p.addr, p.func)).copied().unwrap_or(0) as u32;
                let lo = self.regs.get(&Self::key(p.addr + 1, p.func)).copied().unwrap_or(0) as u32;
                (((hi << 16) | lo) as f64) * p.scale
            }
            "i16" => (self.regs.get(&Self::key(p.addr, p.func)).copied().unwrap_or(0) as i16 as f64) * p.scale,
            _ => (self.regs.get(&Self::key(p.addr, p.func)).copied().unwrap_or(0) as f64) * p.scale,
        }
    }

    /// 📌 钉住/释放一个点位(手动置值后钉住,场景引擎不再改它)
    pub fn set_pinned(&mut self, name: &str, on: bool) {
        if on {
            self.pinned.insert(name.to_string());
        } else {
            self.pinned.remove(name);
        }
    }

    pub fn is_pinned(&self, name: &str) -> bool {
        self.pinned.contains(name)
    }

    /// 释放全部钉住点位(回到场景驱动);返回释放数
    pub fn release_all_pins(&mut self) -> usize {
        let n = self.pinned.len();
        self.pinned.clear();
        n
    }

    /// 运行时追加一个点位(GUI「临时点」):按类型注册寄存器并初始化;同键/同名重复返回 false
    pub fn add_point(&mut self, p: MbPoint) -> bool {
        if self.points.iter().any(|q| q.key == p.key || q.name == p.name) {
            return false;
        }
        if p.ty == "bit" {
            self.regs.entry(Self::key(p.addr, p.func)).or_insert(0);
        } else {
            for i in 0..p.regs.max(1) {
                self.regs.entry(Self::key(p.addr + i, p.func)).or_insert(0);
            }
        }
        self.points.push(p);
        self.apply_inits();
        true
    }

    /// 写字符串点位(str/mac):按 2 字节/寄存器 高字节在前 编码,不足补 0,超长截断到 regs
    pub fn write_str_by_name(&mut self, name: &str, s: &str) -> bool {
        let Some(p) = self.points.iter().find(|p| p.name == name) else { return false };
        if !matches!(p.ty.as_str(), "str" | "mac") {
            return false;
        }
        let regs = p.regs.max(1) as usize;
        let bytes = s.as_bytes();
        let mut vals = Vec::with_capacity(regs);
        for i in 0..regs {
            let b0 = bytes.get(i * 2).copied().unwrap_or(0) as u16;
            let b1 = bytes.get(i * 2 + 1).copied().unwrap_or(0) as u16;
            vals.push((b0 << 8) | b1);
        }
        let addr = p.addr;
        self.write_multi(addr, &vals)
    }

    /// 字符串点位当前内容(str/mac;2 字节/寄存器 高字节在前,去尾部 NUL;非 UTF8 字节按 U+FFFD)
    pub fn str_of(&self, p: &MbPoint) -> String {
        let regs = p.regs.max(1) as usize;
        let mut bytes = Vec::with_capacity(regs * 2);
        for i in 0..regs {
            let v = self.regs.get(&Self::key(p.addr + i as u16, p.func)).copied().unwrap_or(0);
            bytes.push((v >> 8) as u8);
            bytes.push(v as u8);
        }
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// 某次主机读(func/addr/cnt)覆盖到的点位及当时物理值——「主机读到」列的数据源
    pub fn points_in_range(&self, func: u8, addr: u16, cnt: u16) -> Vec<(String, f64)> {
        let (start, end) = (addr as u32, addr as u32 + cnt as u32);
        self.points
            .iter()
            .filter(|p| {
                let span = if p.ty == "bit" { 1 } else { p.regs.max(1) } as u32;
                p.func == func && (p.addr as u32) < end && (p.addr as u32 + span) > start
            })
            .map(|p| (p.name.clone(), self.phys_of(p)))
            .collect()
    }

    /// 当前点位物理值读数(GUI 表格用):name → (raw, phys, ty, grp)
    pub fn snapshot_points(&self) -> Vec<(String, String, f64, String, String)> {
        self.points
            .iter()
            .filter(|p| p.ty != "bit" || p.bit.is_some())
            .map(|p| {
                let raw = match p.ty.as_str() {
                    "bit" => {
                        let host = self.regs.get(&Self::key(p.addr, p.func)).copied().unwrap_or(0);
                        let b = p.bit.unwrap_or(0);
                        ((host >> b) & 1).to_string()
                    }
                    _ => {
                        let v0 = self.regs.get(&Self::key(p.addr, p.func)).copied().unwrap_or(0);
                        match p.ty.as_str() {
                            "i32" | "u32" => {
                                let v1 = self.regs.get(&Self::key(p.addr + 1, p.func)).copied().unwrap_or(0);
                                format!("{}{}", v0, format!("{:04X}", v1))
                            }
                            _ => v0.to_string(),
                        }
                    }
                };
                let phys = self.phys_of(p);
                (p.name.clone(), raw, phys, p.ty.clone(), p.grp.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_points_register_their_register_without_init() {
        // 回归:bit 点位无 init 时也必须注册所在寄存器 —— 否则主机读该地址回 0x02 非法地址。
        // 真实点位表状态段几乎全是无 init 的 bit 点,EMS 逐点位读全部踩 0x02(2026-11-20 实录定位)
        let sp = RegSpace::new(vec![MbPoint {
            key: "a32_b0".into(),
            name: "系统故障状态".into(),
            addr: 0x0020,
            func: 3,
            ty: "bit".into(),
            bit: Some(0),
            scale: 1.0,
            rw: false,
            min: None,
            max: None,
            init: None,
            init_str: None,
            unit: None,
            enum_: None,
            regs: 1,
            grp: "状态数据".into(),
        }]);
        assert!(sp.read(3, 0x0020, 1).is_some(), "bit 点位所在寄存器必须可读");
        assert_eq!(sp.read(3, 0x0020, 1).unwrap()[0], 0, "无 init 位值为 0");
    }

    #[test]
    fn jitter_point_respects_min_max_range() {
        let mk = |min: Option<f64>, max: Option<f64>| {
            RegSpace::new(vec![MbPoint {
                key: "v".into(),
                name: "电压".into(),
                addr: 0x10,
                func: 3,
                ty: "u16".into(),
                regs: 1,
                scale: 0.1,
                bit: None,
                grp: "g".into(),
                rw: false,
                min,
                max,
                init: Some(4000.0),
                init_str: None,
                unit: None,
                enum_: None,
            }])
        };
        // 有 min/max:jitter=0 → min;jitter=1 → max(raw = phys/scale)
        let mut sp = mk(Some(3800.0), Some(4200.0));
        sp.jitter_point("电压", 0.0);
        assert_eq!(sp.read(3, 0x10, 1).unwrap()[0], 38000, "jitter=0 → raw=min/scale");
        sp.jitter_point("电压", 1.0);
        assert_eq!(sp.read(3, 0x10, 1).unwrap()[0], 42000, "jitter=1 → raw=max/scale");
        // 无 min/max:±2% 抖动,值仍可读(不 panic)
        let mut sp = mk(None, None);
        assert!(sp.jitter_point("电压", 0.3));
        assert!(sp.read(3, 0x10, 1).is_some());
    }

    const SAMPLE: &str = r#"
global: {dev_max: 8}
dev1: {enable: 1, name: PCS-1号, link: tcp, port: 502, slave: 1, poll_ms: 1000}
dev2: {enable: 0, name: PCS-2号, port: 503}
dev3: {enable: 1, name: 消防主机, port: 504, slave: 1}
dev1_状态:
  a20: {name: 系统启停状态, addr: 0x0021, func: 3, type: bit, bit: 0, grp: 状态}
  a30: {name: 电网电压, addr: 0x001E, func: 3, type: u16, scale: 0.1, grp: 状态, init: 4000}
  a40: {name: 母线功率, addr: 0x0028, func: 3, type: i32, regs: 2, scale: 1, grp: 状态, init: -100}
dev1_控制:
  a1001: {name: 总开机, addr: 0x03E9, func: 3, type: u16, rw: 1, wfunc: 6, grp: 控制}
"#;

    #[test]
    fn parse_and_state() {
        let (devs, _warns) = parse_points_yaml(SAMPLE).unwrap();
        assert_eq!(devs.len(), 2, "dev2 enable:0 跳过");
        assert_eq!(devs[0].name, "PCS-1号");
        assert_eq!(devs[0].port, 502);
        assert_eq!(devs[0].points.len(), 4);
        // init 折算
        let mut rs = RegSpace::new(devs[0].points.clone());
        let v = rs.read(3, 0x001E, 1).unwrap();
        assert_eq!(v[0], 4000, "init 为 raw 值,直写寄存器");
    }

    #[test]
    fn rw_loop() {
        let (devs, _) = parse_points_yaml(SAMPLE).unwrap();
        let mut rs = RegSpace::new(devs[0].points.clone());
        // HMI 写 0x03E9=1(总开机)
        assert!(rs.write_one(0x03E9, 1), "rw 点地址应已定义");
        let v = rs.read(3, 0x03E9, 1).unwrap();
        assert_eq!(v[0], 1, "写后回读 = 1(控制闭环)");
        // bit 点置位
        assert!(rs.write_point_by_name("系统启停状态", 1.0));
        let v = rs.read(3, 0x0021, 1).unwrap();
        assert_eq!(v[0] & 1, 1);
        // i32 负数
        let v = rs.read(3, 0x0028, 2).unwrap();
        let word = (((v[0] as u32) << 16) | v[1] as u32) as i32;
        assert_eq!(word, -100);
    }

    #[test]
    fn pinned_point_is_left_alone_by_scene_and_temp_point_registers() {
        let (devs, _) = parse_points_yaml(SAMPLE).unwrap();
        let mut rs = RegSpace::new(devs[0].points.clone());
        // 手动置值 + 钉住:Random 不再动它
        assert!(rs.write_point_by_name("电网电压", 4100.0));
        rs.set_pinned("电网电压", true);
        assert!(rs.is_pinned("电网电压"));
        assert!(!rs.jitter_point("电网电压", 1.0), "钉住的点 Random 不动");
        assert_eq!(rs.read(3, 0x001E, 1).unwrap()[0], 41000);
        // 释放后场景可动
        assert_eq!(rs.release_all_pins(), 1);
        assert!(rs.jitter_point("电网电压", 0.5));
        // 临时点:注册即可被主机读到,init 直写寄存器
        let tmp = MbPoint {
            key: "tmp_1".into(),
            name: "临时电压".into(),
            addr: 0x0100,
            func: 3,
            ty: "u16".into(),
            regs: 1,
            scale: 0.1,
            bit: None,
            grp: "临时".into(),
            rw: true,
            min: None,
            max: None,
            init: Some(500.0),
            init_str: None,
            unit: Some("V".into()),
            enum_: Some(vec![(0.0, "停机".into()), (1.0, "运行".into())]),
        };
        assert!(rs.add_point(tmp));
        assert!(!rs.add_point(devs[0].points[0].clone()), "同名/同键重复拒绝");
        assert_eq!(rs.read(3, 0x0100, 1).unwrap()[0], 500, "init 直写寄存器");
        // 主机读区间覆盖 → 点位 + 当时物理值
        let hit = rs.points_in_range(3, 0x00FF, 2);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].0, "临时电压");
        assert!((hit[0].1 - 50.0).abs() < 1e-9, "phys = raw × scale");
        // 字符串点位写入
        let s = MbPoint {
            key: "tmp_s".into(),
            name: "序列号".into(),
            addr: 0x0200,
            func: 3,
            ty: "str".into(),
            regs: 4,
            scale: 1.0,
            bit: None,
            grp: "临时".into(),
            rw: false,
            min: None,
            max: None,
            init: None,
            init_str: None,
            unit: None,
            enum_: None,
        };
        assert!(rs.add_point(s));
        assert!(rs.write_str_by_name("序列号", "SN001"));
        let v = rs.read(3, 0x0200, 4).unwrap();
        assert_eq!((v[0] >> 8) as u8, b'S');
        assert_eq!(v[0] as u8, b'N');
        assert_eq!(v[3], 0);
    }

    #[test]
    fn parse_unit_and_enum() {
        let y = "dev1: {enable: 1, name: BMS, port: 15020}\ndev1_状态:\n  a1: {name: 运行状态, addr: 0x01, func: 3, type: u16, enum: {0: 停机, 1: 运行, 2: 待机}, init: 1}\n  a2: {name: 电压, addr: 0x02, func: 3, type: u16, scale: 0.1, unit: V, init: 400}\n";
        let (devs, _) = parse_points_yaml(y).unwrap();
        let p = &devs[0].points[0];
        assert_eq!(p.enum_.as_ref().unwrap().len(), 3);
        assert_eq!(p.enum_.as_ref().unwrap()[1], (1.0, "运行".to_string()));
        assert!(p.unit.is_none());
        assert_eq!(devs[0].points[1].unit.as_deref(), Some("V"));
    }
}

