//! 后台加载线程:文件读取 + 解析不阻塞 UI。

use iotprobe_core::dissect::{analyze, AnalyzeCfg};
use iotprobe_core::ingest;
use iotprobe_core::model::Dataset;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::thread;

pub struct LoadReq {
    pub name: String,
    pub files: Vec<PathBuf>,
    pub custom: Vec<PathBuf>,
    /// UI 里"采纳"的试探草案(不经文件)
    pub inline_custom: Vec<iotprobe_core::dissect::CustomSpec>,
    /// 启用的 DBC 集合(协议库多选;按序合并,ID 冲突先选中的优先)
    pub dbcs: Vec<PathBuf>,
    pub map: Option<PathBuf>,
    /// IEC 104 信息体点表(YAML/JSON)
    pub map104: Option<PathBuf>,
    /// 规则包目录(含 rules.yaml)
    pub rule_dirs: Vec<PathBuf>,
    pub gap_ms: f64,
}

pub enum LoadMsg {
    Progress(String),
    Done(Box<Result<Dataset, String>>),
}

pub fn spawn_load(req: LoadReq) -> Receiver<LoadMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let mut sources = vec![];
        let mut warnings = vec![];
        let (mut cfg, cfg_warns) = build_cfg(&req.custom, &req.inline_custom, &req.dbcs, &req.map);
        if let Some(p) = &req.map104 {
            load_map104(&mut cfg, p, &mut warnings);
        }
        cfg.gap_threshold_ms = req.gap_ms;
        warnings.extend(cfg_warns);
        for d in &req.rule_dirs {
            match iotprobe_core::rules::load_pack_dir(d) {
                Ok(pack) => cfg.rule_packs.push(pack),
                Err(e) => warnings.push(e),
            }
        }

        let total = req.files.len();
        for (i, f) in req.files.iter().enumerate() {
            let _ = tx.send(LoadMsg::Progress(format!("读取 {}/{}: {}", i + 1, total, f.display())));
            match ingest::read_file(f) {
                Ok(s) => sources.push(s),
                Err(e) => warnings.push(e),
            }
        }
        if sources.is_empty() {
            let _ = tx.send(LoadMsg::Done(Box::new(Err(if warnings.is_empty() {
                "没有可解析的文件".into()
            } else {
                warnings.join("\n")
            }))));
            return;
        }
        let _ = tx.send(LoadMsg::Progress("解析协议与生成时序…".into()));
        let mut ds = analyze(sources, &cfg);
        ds.name = req.name;
        ds.warnings.extend(warnings);
        let _ = tx.send(LoadMsg::Done(Box::new(Ok(ds))));
    });
    rx
}

/// 组装分析配置(自定义协议/内联草案/DBC(可多选合并)/寄存器映射)。返回 (cfg, 配置告警)。
pub fn build_cfg(
    custom: &[PathBuf],
    inline: &[iotprobe_core::dissect::CustomSpec],
    dbcs: &[PathBuf],
    map: &Option<PathBuf>,
) -> (AnalyzeCfg, Vec<String>) {
    let mut cfg = AnalyzeCfg::default();
    let mut warnings = vec![];
    for p in custom {
        match iotprobe_core::textio::read_text_simple(p) {
            Ok(text) => match serde_json::from_str::<iotprobe_core::dissect::CustomSpec>(&text) {
                Ok(spec) => cfg.custom.push(spec),
                Err(e) => warnings.push(format!("自定义协议 {}: {e}", p.display())),
            },
            Err(e) => warnings.push(format!("自定义协议 {}: {e}", p.display())),
        }
    }
    cfg.custom.extend_from_slice(inline);
    if !dbcs.is_empty() {
        let mut merged = iotprobe_core::dbc::Dbc::default();
        let mut loaded = 0usize;
        for p in dbcs {
            match iotprobe_core::textio::read_text(p) {
                Ok((text, enc)) => {
                    if enc != "UTF-8" {
                        warnings.push(format!("DBC {} 非 UTF-8(按 {enc} 解码,建议转存 UTF-8)", p.display()));
                    }
                    let skipped = merged.merge(iotprobe_core::dbc::parse(&text));
                    loaded += 1;
                    if !skipped.is_empty() {
                        warnings.push(format!("DBC {} 与先前启用的报文 ID 冲突,{} 条未覆盖(先选优先)", p.display(), skipped.len()));
                    }
                }
                Err(e) => warnings.push(format!("DBC {}: {e}", p.display())),
            }
        }
        if loaded > 0 {
            cfg.dbc = Some(merged);
        }
    }
    if let Some(p) = map {
        match iotprobe_core::textio::read_text_simple(p) {
            Ok(text) => match serde_json::from_str::<iotprobe_core::dissect::ModbusMap>(&text) {
                Ok(m) => cfg.map = Some(m),
                Err(e) => warnings.push(format!("寄存器映射 {}: {e}", p.display())),
            },
            Err(e) => warnings.push(format!("寄存器映射 {}: {e}", p.display())),
        }
    }
    (cfg, warnings)
}

/// 读一个 104 点表文件(YAML/JSON 自动识别)进 cfg
pub fn load_map104(cfg: &mut AnalyzeCfg, p: &PathBuf, warnings: &mut Vec<String>) {
    match iotprobe_core::textio::read_text_simple(p)
        .map_err(|e| e.to_string())
        .and_then(|t| iotprobe_core::dissect::Map104::parse(&t))
    {
        Ok(m) => cfg.map104 = Some(m),
        Err(e) => warnings.push(format!("104 点表 {}: {e}", p.display())),
    }
}

/// 实时重建(FR-S1):把已累积的 SourceData 直接送入分析(不读文件),复用 LoadMsg 通道。
pub fn spawn_analyze(
    name: String,
    sources: Vec<iotprobe_core::ingest::SourceData>,
    cfg: AnalyzeCfg,
) -> Receiver<LoadMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let _ = tx.send(LoadMsg::Progress("重建实时数据集…".into()));
        let mut ds = analyze(sources, &cfg);
        ds.name = name;
        let _ = tx.send(LoadMsg::Done(Box::new(Ok(ds))));
    });
    rx
}
