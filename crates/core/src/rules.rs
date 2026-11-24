//! 规则引擎(最小版,ADR-6 / T-2.1):
//! - YAML 规则包:rules-pack/<vendor>/<model>/rules.yaml
//! - 表达式:阈值/四则/位运算/布尔/括号,$=当前值 prev=上一值,`for <n>s|ms>` 持续时长
//! - 触发:on_signal(信号条件)/ on_timeout(通道静默)/ on_frame(帧匹配)
//!   / on_rate(变化率:滑动窗口 Δ值/Δ时间,检测爬坡/跳变)
//! - 产出契约事件:EventKind::Rule + code + rule_ref + signal_evidence(ADR-0009)
//! 禁区(遵守 spec):无函数定义、无循环、无 IO;代码不内置任何厂商。

use crate::model::{Event, EventKind};
use serde::Deserialize;
use std::collections::HashMap;

// ================= 规则包结构 =================

#[derive(Clone, Debug)]
pub struct RulePack {
    pub pack: String,
    pub file: String,
    pub vendor: String,
    pub model: String,
    pub version: String,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub level: String, // info | warn | fault
    pub on: OnKind,
    pub signal: Option<String>,
    pub channel: Option<String>, // 通道别名/标签 子串匹配
    pub when: Option<Expr>,
    pub for_ms: u64,
    pub timeout_ms: Option<u64>,
    /// 变化率规则(on_rate):滑动窗口时长;rate = (最新值 − 窗口首值) / 窗口秒数
    pub window_ms: Option<u64>,
    /// 变化率阈值表达式:变量 rate(每秒变化量)、delta(窗口内原始差值)、$(最新值)
    pub rate: Option<Expr>,
    pub match_proto: Option<String>,
    pub match_dir: Option<String>,
    pub match_id: Option<String>,
    pub message: String,
    pub once: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OnKind {
    Signal,
    Timeout,
    Frame,
    Rate,
}

// ================= YAML 解析 =================

#[derive(Deserialize)]
struct PackFile {
    pack: String,
    #[serde(default)]
    meta: MetaYaml,
    #[serde(default)]
    rules: Vec<RuleYaml>,
}

#[derive(Deserialize, Default)]
struct MetaYaml {
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize)]
struct RuleYaml {
    id: String,
    #[serde(default = "d_level")]
    level: String,
    on: String,
    #[serde(default)]
    signal: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default, rename = "when")]
    when_str: Option<String>,
    #[serde(default, rename = "for")]
    for_str: Option<String>,
    #[serde(default)]
    timeout: Option<String>,
    /// 变化率规则:滑动窗口时长(如 "5s")
    #[serde(default)]
    window: Option<String>,
    /// 变化率阈值表达式(rate/delta/$)
    #[serde(default)]
    rate: Option<String>,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    dir: Option<String>,
    /// 帧规则:匹配帧摘要首 token(如 "0x1A0")
    #[serde(default, rename = "frame_id")]
    match_id: Option<String>,
    #[serde(default = "d_msg")]
    message: String,
    #[serde(default)]
    once: bool,
}
fn d_level() -> String {
    "warn".into()
}
fn d_msg() -> String {
    String::new()
}

/// "3s" / "500ms" / "1m" → 毫秒
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("ms") {
        n.trim().parse().ok()
    } else if let Some(n) = s.strip_suffix('s') {
        n.trim().parse::<f64>().ok().map(|v| (v * 1000.0) as u64)
    } else if let Some(n) = s.strip_suffix('m') {
        n.trim().parse::<f64>().ok().map(|v| (v * 60_000.0) as u64)
    } else {
        None
    }
}

/// 从 YAML 文本解析规则包(热加载工作流:改完文本重跑,不必经文件)
pub fn parse_pack_yaml(text: &str, file: &str) -> Result<RulePack, String> {
    parse_pack(text, file)
}

fn parse_pack(text: &str, file: &str) -> Result<RulePack, String> {
    let pf: PackFile = serde_yaml_ng::from_str(text).map_err(|e| format!("{file}: {e}"))?;
    let mut rules = vec![];
    for r in pf.rules {
        let on = match r.on.as_str() {
            "signal" => OnKind::Signal,
            "timeout" => OnKind::Timeout,
            "frame" => OnKind::Frame,
            "rate" => OnKind::Rate,
            other => return Err(format!("{file}: 规则 {} 未知触发类型 '{other}'(signal/timeout/frame/rate)", r.id)),
        };
        let for_ms = match &r.for_str {
            Some(s) => parse_duration(s).ok_or_else(|| format!("{file}: 规则 {} 非法时长 '{s}'", r.id))?,
            None => 0,
        };
        let timeout_ms = match &r.timeout {
            Some(s) => Some(parse_duration(s).ok_or_else(|| format!("{file}: 规则 {} 非法超时 '{s}'", r.id))?),
            None => None,
        };
        let window_ms = match &r.window {
            Some(s) => Some(parse_duration(s).ok_or_else(|| format!("{file}: 规则 {} 非法窗口 '{s}'", r.id))?),
            None => None,
        };
        let rate = match &r.rate {
            Some(s) => Some(parse_expr(s).map_err(|e| format!("{file}: 规则 {} 变化率表达式错误: {e}", r.id))?),
            None => None,
        };
        let level_ok = matches!(r.level.as_str(), "info" | "warn" | "fault");
        if !level_ok {
            return Err(format!("{file}: 规则 {} level 必须是 info/warn/fault", r.id));
        }
        if rules.iter().any(|x: &Rule| x.id == r.id) {
            return Err(format!("{file}: 规则 id 重复: {}", r.id));
        }
        if on == OnKind::Rate && (r.signal.is_none() || window_ms.is_none() || rate.is_none()) {
            return Err(format!("{file}: 规则 {} on: rate 需要 signal + window + rate", r.id));
        }
        let when = match &r.when_str {
            Some(s) => Some(parse_expr(s).map_err(|e| format!("{file}: 规则 {} 表达式错误: {e}", r.id))?),
            None => None,
        };
        rules.push(Rule {
            id: r.id,
            level: r.level,
            on,
            signal: r.signal,
            channel: r.channel,
            when,
            for_ms,
            timeout_ms,
            window_ms,
            rate,
            match_proto: r.proto,
            match_dir: r.dir,
            match_id: r.match_id,
            message: r.message,
            once: r.once,
        });
    }
    Ok(RulePack {
        pack: pf.pack,
        file: file.to_string(),
        vendor: pf.meta.vendor,
        model: pf.meta.model,
        version: pf.meta.version,
        rules,
    })
}

/// 加载一个规则包目录(读取其中的 rules.yaml)
pub fn load_pack_dir(dir: &std::path::Path) -> Result<RulePack, String> {
    let f = dir.join("rules.yaml");
    let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
    let mut pack = parse_pack(&text, &f.display().to_string())?;
    // meta.yaml 可选:补充 vendor/model/version
    let meta_f = dir.join("meta.yaml");
    if let Ok(mtext) = std::fs::read_to_string(&meta_f) {
        if let Ok(m) = serde_yaml_ng::from_str::<MetaYaml>(&mtext) {
            if !m.vendor.is_empty() {
                pack.vendor = m.vendor;
            }
            if !m.model.is_empty() {
                pack.model = m.model;
            }
            if !m.version.is_empty() {
                pack.version = m.version;
            }
        }
    }
    Ok(pack)
}

// ================= 表达式求值器(自研递归下降) =================

#[derive(Clone, Debug)]
pub enum Expr {
    Num(f64),
    Var(String),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Clone, Copy, Debug)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Gt,
    Lt,
    Ge,
    Le,
    Eq,
    Ne,
    And,
    Or,
    BitAnd,
    BitOr,
    Shl,
    Shr,
}

pub fn parse_expr(s: &str) -> Result<Expr, String> {
    let toks = tokenize(s)?;
    let mut p = Parser { toks, pos: 0 };
    let e = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err(format!("多余的内容: '{}'", p.toks[p.pos].0));
    }
    Ok(e)
}

type Tok = (String, TokKind);

#[derive(Clone, Copy, PartialEq, Debug)]
enum TokKind {
    Num,
    Ident,
    Op,
    LParen,
    RParen,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = s.chars().collect();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() || (c == '.' && i + 1 < b.len() && b[i + 1].is_ascii_digit()) {
            let start = i;
            if c == '0' && i + 1 < b.len() && (b[i + 1] == 'x' || b[i + 1] == 'X') {
                // 十六进制字面量
                i += 2;
                while i < b.len() && b[i].is_ascii_hexdigit() {
                    i += 1;
                }
            } else {
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == '.') {
                    i += 1;
                }
            }
            out.push((s.chars().skip(start).take(i - start).collect(), TokKind::Num));
            continue;
        }
        if c.is_alphabetic() || c == '$' || c == '_' {
            let start = i;
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_' || b[i] == '$' || b[i] == '·') {
                i += 1;
            }
            out.push((s.chars().skip(start).take(i - start).collect(), TokKind::Ident));
            continue;
        }
        // 双字符运算符
        let two: String = b[i..(i + 2).min(b.len())].iter().collect();
        let d = match two.as_str() {
            ">=" | "<=" | "==" | "!=" | "&&" | "||" | "<<" | ">>" => Some(two.clone()),
            _ => None,
        };
        if let Some(op) = d {
            out.push((op, TokKind::Op));
            i += 2;
            continue;
        }
        let single = match c {
            '>' | '<' | '+' | '-' | '*' | '/' | '&' | '|' | '!' => Some(c.to_string()),
            '(' => {
                out.push((c.to_string(), TokKind::LParen));
                i += 1;
                continue;
            }
            ')' => {
                out.push((c.to_string(), TokKind::RParen));
                i += 1;
                continue;
            }
            _ => return Err(format!("非法字符 '{c}'(位置 {i})")),
        };
        if let Some(op) = single {
            out.push((op, TokKind::Op));
            i += 1;
            continue;
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn eat_op(&mut self, op: &str) -> bool {
        // 按 token 文本匹配(括号是独立 TokKind,文本比较统一处理)
        if let Some((t, _)) = self.peek() {
            if t == op {
                self.pos += 1;
                return true;
            }
        }
        false
    }
    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_and()?;
        while self.eat_op("||") {
            let r = self.parse_and()?;
            l = Expr::Bin(BinOp::Or, Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_cmp()?;
        while self.eat_op("&&") {
            let r = self.parse_cmp()?;
            l = Expr::Bin(BinOp::And, Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn parse_cmp(&mut self) -> Result<Expr, String> {
        let l = self.parse_bit()?;
        for op in ["==", "!=", ">=", "<=", ">", "<"] {
            if self.eat_op(op) {
                let r = self.parse_bit()?;
                let o = match op {
                    "==" => BinOp::Eq,
                    "!=" => BinOp::Ne,
                    ">=" => BinOp::Ge,
                    "<=" => BinOp::Le,
                    ">" => BinOp::Gt,
                    _ => BinOp::Lt,
                };
                return Ok(Expr::Bin(o, Box::new(l), Box::new(r)));
            }
        }
        Ok(l)
    }
    fn parse_bit(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_term()?;
        loop {
            let op = if self.eat_op("&") {
                BinOp::BitAnd
            } else if self.eat_op("|") {
                BinOp::BitOr
            } else if self.eat_op("<<") {
                BinOp::Shl
            } else if self.eat_op(">>") {
                BinOp::Shr
            } else {
                break;
            };
            let r = self.parse_term()?;
            l = Expr::Bin(op, Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn parse_term(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_factor()?;
        loop {
            let op = if self.eat_op("+") {
                BinOp::Add
            } else if self.eat_op("-") {
                BinOp::Sub
            } else if self.eat_op("*") {
                BinOp::Mul
            } else if self.eat_op("/") {
                BinOp::Div
            } else {
                break;
            };
            let r = self.parse_factor()?;
            l = Expr::Bin(op, Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn parse_factor(&mut self) -> Result<Expr, String> {
        if self.eat_op("!") {
            let e = self.parse_factor()?;
            return Ok(Expr::Not(Box::new(e)));
        }
        if self.eat_op("-") {
            let e = self.parse_factor()?;
            return Ok(Expr::Bin(BinOp::Mul, Box::new(Expr::Num(-1.0)), Box::new(e)));
        }
        let Some((tok, kind)) = self.peek().cloned() else {
            return Err("表达式意外结束".into());
        };
        match kind {
            TokKind::Num => {
                self.pos += 1;
                let v: f64 = if let Some(h) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
                    u64::from_str_radix(h, 16).map(|x| x as f64).map_err(|_| format!("非法十六进制 '{tok}'"))?
                } else {
                    tok.parse().map_err(|_| format!("非法数字 '{tok}'"))?
                };
                Ok(Expr::Num(v))
            }
            TokKind::Ident => {
                self.pos += 1;
                Ok(Expr::Var(tok))
            }
            TokKind::LParen => {
                self.pos += 1;
                let e = self.parse_or()?;
                if !self.eat_op(")") {
                    return Err("缺少右括号".into());
                }
                Ok(e)
            }
            TokKind::Op if tok == "+" => {
                self.pos += 1;
                self.parse_factor()
            }
            _ => Err(format!("意外的 token '{tok}'")),
        }
    }
}

/// 求值:env 提供 $ / prev 等变量。布尔语义:非零 = true。
pub fn eval_expr(e: &Expr, env: &HashMap<String, f64>) -> Result<f64, String> {
    Ok(match e {
        Expr::Num(n) => *n,
        Expr::Var(v) => *env.get(v).ok_or_else(|| format!("未知变量 '{v}'"))?,
        Expr::Not(x) => {
            let v = eval_expr(x, env)?;
            if v == 0.0 { 1.0 } else { 0.0 }
        }
        Expr::Bin(op, a, b) => {
            let x = eval_expr(a, env)?;
            let y = eval_expr(b, env)?;
            let out = match op {
                BinOp::Add => x + y,
                BinOp::Sub => x - y,
                BinOp::Mul => x * y,
                BinOp::Div => {
                    if y == 0.0 {
                        return Err("除零".into());
                    }
                    x / y
                }
                BinOp::Gt => (x > y) as i64 as f64,
                BinOp::Lt => (x < y) as i64 as f64,
                BinOp::Ge => (x >= y) as i64 as f64,
                BinOp::Le => (x <= y) as i64 as f64,
                BinOp::Eq => (x == y) as i64 as f64,
                BinOp::Ne => (x != y) as i64 as f64,
                BinOp::And => (x != 0.0 && y != 0.0) as i64 as f64,
                BinOp::Or => (x != 0.0 || y != 0.0) as i64 as f64,
                BinOp::BitAnd => ((x as i64) & (y as i64)) as f64,
                BinOp::BitOr => ((x as i64) | (y as i64)) as f64,
                BinOp::Shl => ((x as i64) << (y as i64).min(32)) as f64,
                BinOp::Shr => ((x as i64) >> (y as i64).min(32)) as f64,
            };
            out
        }
    })
}

// ================= 运行器 =================

const MAX_EVENTS_PER_RULE: usize = 100;

struct SignalRuleState {
    holding_since: Option<u64>,
    emitted: bool,
    prev: Option<f64>,
}

/// 在数据集分析完成后运行规则,产出规则事件(追加进 events,随后统一按时间排序)
pub fn run_rules(packs: &[RulePack], ds: &mut crate::model::Dataset) {
    for pack in packs {
        for rule in &pack.rules {
            match rule.on {
                OnKind::Signal => run_signal_rule(pack, rule, ds),
                OnKind::Timeout => run_timeout_rule(pack, rule, ds),
                OnKind::Frame => run_frame_rule(pack, rule, ds),
                OnKind::Rate => run_rate_rule(pack, rule, ds),
            }
        }
    }
}

/// FR-3.7 规则热加载:替换数据集上的规则事件,不动报文解码/信号/诊断事件。
/// 按包名剔除旧规则事件(诊断事件与未重载包的事件保留),重跑后按时间重排序。
pub fn reload_rules(packs: &[RulePack], ds: &mut crate::model::Dataset) {
    let names: std::collections::HashSet<&str> = packs.iter().map(|p| p.pack.as_str()).collect();
    ds.events.retain(|e| e.rule.as_ref().map(|r| !names.contains(r.pack.as_str())).unwrap_or(true));
    run_rules(packs, ds);
    ds.events.sort_by_key(|e| e.t_ns);
}

fn rule_event(
    pack: &RulePack,
    rule: &Rule,
    t_ns: u64,
    frame: Option<u32>,
    detail: String,
    source: u16,
    channel: u16,
    sigs: Vec<(String, f64, String)>,
) -> Event {
    Event {
        t_ns,
        frame,
        kind: EventKind::Rule,
        detail,
        source,
        channel,
        rule: Some(crate::model::RuleEventMeta {
            pack: pack.pack.clone(),
            file: pack.file.clone(),
            rule_id: rule.id.clone(),
            level: rule.level.clone(),
            signals: sigs,
        }),
    }
}

fn run_signal_rule(pack: &RulePack, rule: &Rule, ds: &mut crate::model::Dataset) {
    let Some(expr) = &rule.when else { return };
    let Some(sig_name) = &rule.signal else { return };
    let mut emitted = 0usize;
    // 预取通道标签(避免循环内借用冲突)
    let labels: HashMap<(u16, u16), String> = ds
        .channels
        .iter()
        .map(|c| ((c.source, c.id), c.label.clone()))
        .collect();
    for s in &ds.signals {
        // 信号匹配:键以 signal 名结尾(或全等),支持 "unit1·TempSensor" 与 "CAN 0x1A0·Speed"
        if !(s.key == *sig_name || s.key.ends_with(&format!("·{sig_name}"))) {
            continue;
        }
        let mut state = SignalRuleState { holding_since: None, emitted: false, prev: None };
        for &(t, v, fi) in &s.pts {
            let mut env = HashMap::new();
            env.insert("$".to_string(), v);
            if let Some(p) = state.prev {
                env.insert("prev".to_string(), p);
            }
            let cond = eval_expr(expr, &env).unwrap_or(0.0) != 0.0;
            if cond {
                // 通道过滤:经帧引用取通道标签子串匹配
                if let Some(ch) = &rule.channel {
                    let fkey = ds.frames.get(fi as usize).map(|f| (f.source, f.channel));
                    let lab_ok = fkey
                        .and_then(|k| labels.get(&k))
                        .map(|l| l.contains(ch))
                        .unwrap_or(false);
                    if !lab_ok {
                        state.prev = Some(v);
                        continue;
                    }
                }
                if state.holding_since.is_none() {
                    state.holding_since = Some(t);
                }
                let held = t.saturating_sub(state.holding_since.unwrap_or(t));
                if !state.emitted && held >= rule.for_ms {
                    let msg = rule
                        .message
                        .replace("{value}", &format!("{v:.3}"))
                        .replace("{key}", &s.key)
                        .replace("{signal}", sig_name);
                    let frame_ref = ds.frames.get(fi as usize);
                    let (src, ch) = frame_ref.map(|f| (f.source, f.channel)).unwrap_or((0, 0));
                    ds.events.push(rule_event(
                        pack,
                        rule,
                        t,
                        Some(fi),
                        msg,
                        src,
                        ch,
                        vec![(s.key.clone(), v, s.unit.clone())],
                    ));
                    state.emitted = true;
                    emitted += 1;
                    if emitted >= MAX_EVENTS_PER_RULE {
                        return;
                    }
                }
            } else {
                // 条件复位:允许下一轮再次触发
                state.holding_since = None;
                state.emitted = false;
            }
            state.prev = Some(v);
        }
    }
}

/// on_rate 变化率规则:滑动窗口 Δ值/Δ时间,检测爬坡/跳变(SOC 突变、温度骤升…)。
/// 每个信号维护窗口内点队列;rate = (最新值 − 窗口首值)/窗口秒数,delta = 原始差值。
/// 阈值表达式变量:rate / delta / $(最新值);触发后冷却到窗口滑出该峰值区(简单防抖:
/// 触发点后窗口清空,重新积累),不重复报同一个爬坡过程。
fn run_rate_rule(pack: &RulePack, rule: &Rule, ds: &mut crate::model::Dataset) {
    let Some(sig_name) = &rule.signal else { return };
    let Some(window_ms) = rule.window_ms else { return };
    let Some(rate_expr) = &rule.rate else { return };
    let window_ns = (window_ms as f64) * 1e6;
    let labels: HashMap<(u16, u16), String> = ds
        .channels
        .iter()
        .map(|c| ((c.source, c.id), c.label.clone()))
        .collect();
    let mut emitted = 0usize;
    for s in &ds.signals {
        if !(s.key == *sig_name || s.key.ends_with(&format!("·{sig_name}"))) {
            continue;
        }
        let mut win: Vec<(u64, f64, u32)> = vec![]; // 窗口内 (t, v, frame)
        let mut cooled_until = 0u64; // 触发后冷却:该时刻前的点不再评估(防同一段爬坡连报)
        for &(t, v, fi) in &s.pts {
            win.push((t, v, fi));
            let cutoff = t.saturating_sub(window_ns as u64);
            while win.len() > 1 && win[0].0 < cutoff {
                win.remove(0);
            }
            // 窗口至少两点、时间跨度非零才可评估
            if win.len() < 2 || t <= win[0].0 || t < cooled_until {
                continue;
            }
            let dt_s = (t - win[0].0) as f64 / 1e9;
            let delta = v - win[0].1;
            let rate = delta / dt_s;
            let mut env = HashMap::new();
            env.insert("rate".to_string(), rate);
            env.insert("delta".to_string(), delta);
            env.insert("$".to_string(), v);
            let cond = eval_expr(rate_expr, &env).unwrap_or(0.0) != 0.0;
            if cond {
                if let Some(ch) = &rule.channel {
                    let fkey = ds.frames.get(fi as usize).map(|f| (f.source, f.channel));
                    let lab_ok = fkey
                        .and_then(|k| labels.get(&k))
                        .map(|l| l.contains(ch))
                        .unwrap_or(false);
                    if !lab_ok {
                        continue;
                    }
                }
                let msg = rule
                    .message
                    .replace("{rate}", &format!("{rate:.3}"))
                    .replace("{delta}", &format!("{delta:.3}"))
                    .replace("{value}", &format!("{v:.3}"))
                    .replace("{window}", &(window_ms as f64 / 1000.0).to_string())
                    .replace("{key}", &s.key)
                    .replace("{signal}", sig_name);
                let frame_ref = ds.frames.get(fi as usize);
                let (src, ch) = frame_ref.map(|f| (f.source, f.channel)).unwrap_or((0, 0));
                ds.events.push(rule_event(
                    pack,
                    rule,
                    t,
                    Some(fi),
                    msg,
                    src,
                    ch,
                    vec![(s.key.clone(), v, s.unit.clone()), (format!("{sig_name}·rate"), rate, "/s".into())],
                ));
                emitted += 1;
                // 冷却:滑出一个窗口时长再评估,同一段爬坡只报一次
                cooled_until = t + window_ns as u64;
                win.clear();
                if emitted >= MAX_EVENTS_PER_RULE {
                    return;
                }
            }
        }
    }
}

fn run_timeout_rule(pack: &RulePack, rule: &Rule, ds: &mut crate::model::Dataset) {
    let Some(timeout_ms) = rule.timeout_ms else { return };
    let timeout_ns = timeout_ms * 1_000_000;
    // 每通道按时间序遍历:帧间隔 ≥ timeout → 在 prev_t + timeout 处触发(流中段静默语义)
    let mut per_chan: HashMap<(u16, u16), Vec<usize>> = HashMap::new();
    for (i, f) in ds.frames.iter().enumerate() {
        per_chan.entry((f.source, f.channel)).or_default().push(i);
    }
    let mut emitted = 0usize;
    let mut chans: Vec<((u16, u16), Vec<usize>)> = per_chan.into_iter().collect();
    chans.sort_by_key(|(k, _)| *k);
    for ((src, ch), idxs) in chans {
        let label = ds.channel_label(src, ch);
        if let Some(pat) = &rule.channel {
            if !label.contains(pat) {
                continue;
            }
        }
        let mut prev: Option<usize> = None;
        for &i in &idxs {
            let f = &ds.frames[i];
            if let Some(p) = prev {
                let dt = f.t_ns.saturating_sub(ds.frames[p].t_ns);
                if dt >= timeout_ns && emitted < MAX_EVENTS_PER_RULE {
                    let silence_s = dt as f64 / 1e9;
                    let msg = rule
                        .message
                        .replace("{timeout}", &(timeout_ms as f64 / 1000.0).to_string())
                        .replace("{channel}", &label)
                        .replace("{silence}", &format!("{:.3}", silence_s));
                    ds.events.push(rule_event(
                        pack,
                        rule,
                        ds.frames[p].t_ns + timeout_ns,
                        Some(p as u32),
                        format!("{msg} [静默自 {:.3}s]", ds.frames[p].t_ns as f64 / 1e9),
                        src,
                        ch,
                        vec![(format!("{label}·静默"), dt as f64 / 1e6, "ms".into())],
                    ));
                    emitted += 1;
                }
            }
            prev = Some(i);
        }
    }
}

fn run_frame_rule(pack: &RulePack, rule: &Rule, ds: &mut crate::model::Dataset) {
    let mut emitted = 0usize;
    for (i, f) in ds.frames.iter().enumerate() {
        if let Some(p) = &rule.match_proto {
            let pl = f.proto.label().to_lowercase();
            if !pl.contains(&p.to_lowercase()) {
                continue;
            }
        }
        if let Some(d) = &rule.match_dir {
            if !f.dir.label().eq_ignore_ascii_case(d) {
                continue;
            }
        }
        if let Some(idp) = &rule.match_id {
            let tok = f.summary.split_whitespace().next().unwrap_or("");
            if !tok.to_lowercase().starts_with(&idp.to_lowercase()) {
                continue;
            }
        }
        let msg = rule.message.replace("{id}", f.summary.split_whitespace().next().unwrap_or(""));
        ds.events.push(rule_event(
            pack,
            rule,
            f.t_ns,
            Some(i as u32),
            if msg.is_empty() { f.summary.clone() } else { msg },
            f.source,
            f.channel,
            vec![],
        ));
        emitted += 1;
        if rule.once && emitted >= 1 {
            break;
        }
        if emitted >= MAX_EVENTS_PER_RULE {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Dataset, Dir, Frame, Proto, Series, TsSrc};

    fn envof(pairs: &[(&str, f64)]) -> HashMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn expr_threshold_and_bool() {
        let e = parse_expr("$ > 45.0").unwrap();
        assert_eq!(eval_expr(&e, &envof(&[("$", 50.0)])).unwrap(), 1.0);
        assert_eq!(eval_expr(&e, &envof(&[("$", 40.0)])).unwrap(), 0.0);
        let e2 = parse_expr("$ > 80 && prev < 80").unwrap();
        assert_eq!(eval_expr(&e2, &envof(&[("$", 85.0), ("prev", 70.0)])).unwrap(), 1.0);
        let e3 = parse_expr("($ & 0x08) != 0").unwrap();
        assert_eq!(eval_expr(&e3, &envof(&[("$", 0x0A as f64)])).unwrap(), 1.0);
        let e4 = parse_expr("$ * 0.1 + 2 >= 12").unwrap();
        assert_eq!(eval_expr(&e4, &envof(&[("$", 100.0)])).unwrap(), 1.0);
    }

    #[test]
    fn expr_errors() {
        assert!(parse_expr("$ > ").is_err());
        assert!(parse_expr("$ @ 3").is_err());
        assert!(parse_expr("(1 + 2").is_err());
        let e = parse_expr("$ > 1").unwrap();
        assert!(eval_expr(&e, &envof(&[])).is_err(), "未知变量应报错");
    }

    #[test]
    fn duration_parse() {
        assert_eq!(parse_duration("3s"), Some(3000));
        assert_eq!(parse_duration("500ms"), Some(500));
        assert_eq!(parse_duration("1m"), Some(60000));
        assert_eq!(parse_duration("3x"), None);
    }

    #[test]
    fn yaml_pack_parse() {
        let text = r#"
pack: demo-bms
meta: { vendor: generic, model: bms, version: "1.0" }
rules:
  - id: OVER_TEMP
    level: fault
    on: signal
    signal: TempSensor
    when: "$ > 45.0"
    for: 2s
    message: "温度越限 {value}"
  - id: NO_BEAT
    on: timeout
    channel: "BMS"
    timeout: 2s
    message: "心跳超时"
"#;
        let pack = parse_pack(text, "rules.yaml").unwrap();
        assert_eq!(pack.pack, "demo-bms");
        assert_eq!(pack.rules.len(), 2);
        assert_eq!(pack.rules[0].for_ms, 2000);
        assert_eq!(pack.rules[1].timeout_ms, Some(2000));
        // 坏规则
        let bad = "pack: x\nrules:\n  - id: A\n    on: wifi\n";
        assert!(parse_pack(bad, "f").is_err());
        let dup = "pack: x\nrules:\n  - id: A\n    on: frame\n  - id: A\n    on: frame\n";
        assert!(parse_pack(dup, "f").is_err());
    }

    fn mkds() -> Dataset {
        // 一条 TempSensor 信号:2s 期间持续 > 45(for: 2s 应触发一次)
        let pts = vec![
            (0u64, 50.0f64, 0u32),
            (1_000_000_000, 52.0, 1),
            (2_100_000_000, 48.0, 2),
            (3_000_000_000, 20.0, 3),
            (4_000_000_000, 60.0, 4),
        ];
        Dataset {
            name: "t".into(),
            epoch_ns: None,
            records: vec![],
            frames: (0..5)
                .map(|i| Frame {
                    record: 0,
                    off: 0,
                    len: 8,
                    t_ns: pts[i as usize].0,
                    ts_src: TsSrc::Sw,
                    dir: Dir::Rx,
                    source: 0,
                    channel: 0,
                    proto: Proto::ModbusRtu,
                    seq: i + 1,
                    gap_n: 0,
                    summary: format!("frame{i}"),
                })
                .collect(),
            decoded: vec![],
            signals: vec![Series { key: "unit1·TempSensor".into(), unit: "°C".into(), pts }],
            events: vec![],
            channels: vec![],
            strings: Default::default(),
            warnings: vec![],
            decode_ctx: Default::default(),
        }
    }

    #[test]
    fn signal_rule_fires_after_hold() {
        let text = r#"
pack: t
rules:
  - id: OVER_TEMP
    level: fault
    on: signal
    signal: TempSensor
    when: "$ > 45.0"
    for: 2s
    message: "温度越限 {value}"
"#;
        let pack = parse_pack(text, "r").unwrap();
        let mut ds = mkds();
        run_rules(&[pack], &mut ds);
        let rules: Vec<&Event> = ds.events.iter().filter(|e| e.kind == EventKind::Rule).collect();
        assert_eq!(rules.len(), 1, "持续 2s 后触发一次,回落后再涨不应重复: got {}", rules.len());
        assert_eq!(rules[0].rule.as_ref().unwrap().rule_id, "OVER_TEMP");
        assert_eq!(rules[0].rule.as_ref().unwrap().level, "fault");
        assert!(rules[0].rule.as_ref().unwrap().signals[0].1 > 45.0);
    }

    #[test]
    fn reload_rules_hot_swap() {
        // FR-3.7:改阈值重跑 → 旧规则事件被替换;诊断事件与其它包事件保留;时间重排序
        let pack_v1 = parse_pack(
            r#"
pack: t
rules:
  - id: OVER_TEMP
    level: fault
    on: signal
    signal: TempSensor
    when: "$ > 45.0"
    for: 2s
    message: "温度越限 {value}"
"#,
            "r1",
        )
        .unwrap();
        let pack_v2 = parse_pack(
            r#"
pack: t
rules:
  - id: OVER_TEMP
    level: warn
    on: signal
    signal: TempSensor
    when: "$ > 48.0"
    message: "温度偏高 {value}"
"#,
            "r1",
        )
        .unwrap();
        let other = parse_pack("pack: other\nrules:\n  - id: X\n    on: frame\n", "r2").unwrap();

        let mut ds = mkds();
        run_rules(&[pack_v1, other.clone()], &mut ds);
        // 混入一条诊断事件
        ds.events.push(Event::diag(1_500_000_000, None, EventKind::CrcError, "诊断".into(), 0, 0));
        let n_v1 = ds.events.iter().filter(|e| e.kind == EventKind::Rule && e.rule.as_ref().unwrap().pack == "t").count();
        let n_other = ds.events.iter().filter(|e| e.kind == EventKind::Rule && e.rule.as_ref().unwrap().pack == "other").count();
        assert_eq!(n_v1, 1);
        assert_eq!(n_other, ds.frames.len(), "frame 规则每帧一条");

        // 热加载:阈值 45→48(for 去掉):v1(fault,>45,for 2s)事件应被剔除,
        // v2(warn,>48)在 t=0(50)与 t=4s(60,20 回落复位后)各触发一次 → 共 2 条
        reload_rules(&[pack_v2, other], &mut ds);
        let t_rules: Vec<&Event> = ds.events.iter().filter(|e| e.kind == EventKind::Rule && e.rule.as_ref().unwrap().pack == "t").collect();
        assert_eq!(t_rules.len(), 2, "v1 事件剔除,v2 触发 2 次: got {}", t_rules.len());
        assert!(t_rules.iter().all(|e| e.rule.as_ref().unwrap().rule_id == "OVER_TEMP" && e.rule.as_ref().unwrap().level == "warn"), "全部为 v2 语义");
        assert_eq!(ds.events.iter().filter(|e| e.kind == EventKind::CrcError).count(), 1, "诊断事件保留");
        assert_eq!(ds.events.iter().filter(|e| e.kind == EventKind::Rule && e.rule.as_ref().unwrap().pack == "other").count(), n_other, "其它包事件保留");
        // 时间有序
        for w in ds.events.windows(2) {
            assert!(w[0].t_ns <= w[1].t_ns, "重载后事件应按时间排序");
        }
    }

    #[test]
    fn rate_rule_window() {
        // 变化率:慢爬坡(2/s)不报,快爬坡(10/s)报;冷却后第二段再报;解析校验
        let pack = parse_pack(
            r#"
pack: r
rules:
  - id: SOC_JUMP
    level: warn
    on: rate
    signal: Soc
    window: 5s
    rate: "rate > 5.0"
    message: "SOC 变化过快 {rate}/s(窗口 {window}s)"
"#,
            "r",
        )
        .unwrap();
        // pts:0-4s 慢爬坡 100→108(2/s,不报);5-6s 快跳 108→130(10/s+,报);
        // 6.5-11s 再快跳 130→150(约 3.6/s 不报);12-13.5s 快跳 150→170(>5/s,冷却结束后报)
        let pts = vec![
            (0u64, 100.0f64, 0u32),
            (1_000_000_000, 102.0, 1),
            (2_000_000_000, 104.0, 2),
            (3_000_000_000, 106.0, 3),
            (4_000_000_000, 108.0, 4),
            (5_000_000_000, 120.0, 5),
            (6_000_000_000, 130.0, 6),
            (8_000_000_000, 140.0, 7),
            (11_000_000_000, 150.0, 8),
            (12_000_000_000, 160.0, 9),
            (13_000_000_000, 170.0, 10),
        ];
        let frames = pts.iter().enumerate().map(|(i, &(t, _, _))| Frame {
            record: 0, off: 0, len: 8, t_ns: t, ts_src: TsSrc::Sw, dir: Dir::Rx,
            source: 0, channel: 0, proto: Proto::ModbusRtu, seq: i as u32 + 1, gap_n: 0,
            summary: format!("f{i}"),
        }).collect();
        let mut ds = Dataset {
            name: "t".into(), epoch_ns: None, records: vec![], frames,
            decoded: vec![],
            signals: vec![Series { key: "unit1·Soc".into(), unit: "%".into(), pts }],
            events: vec![], channels: vec![], strings: Default::default(), warnings: vec![], decode_ctx: Default::default(),
        };
        run_rules(&[pack], &mut ds);
        let rules: Vec<&Event> = ds.events.iter().filter(|e| e.kind == EventKind::Rule).collect();
        assert_eq!(rules.len(), 2, "慢爬坡不报,快爬坡 t=5s 报;t=13s 冷却结束后第二段报: got {}", rules.len());
        assert_eq!(rules[0].rule.as_ref().unwrap().rule_id, "SOC_JUMP");
        // 证据:值 + 变化率
        let ev = &rules[0].rule.as_ref().unwrap().signals;
        assert_eq!(ev.len(), 2);
        assert!(ev[1].0.ends_with("·rate") && ev[1].1 > 5.0, "rate 证据应 >5: {:?}", ev);
        // 坏规则:缺 window/rate
        let bad = "pack: x\nrules:\n  - id: A\n    on: rate\n    signal: S\n    rate: \"$ > 1\"\n";
        assert!(parse_pack(bad, "f").is_err(), "on:rate 缺 window 应报错");
    }
}
