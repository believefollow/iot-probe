#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! IoTProbe — IoT 日志多协议解析与时序分析台
//! Wireshark 的解析 + SavvyCAN 的信号时序 + 三联动交互。

mod live;
mod rtu_tcp;
mod sim;
mod tx;
mod zlg;
mod canhw;
mod peak;
mod kvaser;
mod ecanvci;
mod load;
mod moddev;
mod moddev104;
mod moddev_custom;
mod moddev645;
mod plot;
mod terminal;
mod views;

use egui::{Align, Align2, Color32, FontId, Pos2, ScrollArea, Sense, TextEdit, Ui};
use std::sync::atomic::Ordering;
use iotprobe_core::model::{Dataset, Proto};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{mpsc::Receiver, Arc};

// ---- Design tokens(主题感知):文字/弱文字/选中底/悬停底,亮暗两套 ----
fn default_true() -> bool {
    true
}
fn txt(u: &Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(205, 210, 218) } else { Color32::from_rgb(38, 43, 52) }
}
fn dim(u: &Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(128, 136, 148) } else { Color32::from_rgb(104, 112, 122) }
}

/// 场景视图清单(配置中心):按任务只显相关设置,步骤化操作;下标即快捷键 1~5。
/// 场景对齐 G2 验收清单(S1/S2/S3)+ 离线分析 + 模拟联调;产线抽测并入现场排故
/// (两场景卡片高度重叠,可合并到四场景)。「全部配置」= 七卡铺开的高级视图。
const SCENES: [(&str, &str); 5] = [
    ("离线分析", "打开日志 → 挂协议 → 工作台看曲线"),
    ("现场排故", "连硬件 → 挂协议 → 挂规则 → 发送(可选) → 证据包(含产线抽测)"),
    ("数据喂 AI", "导出契约 JSONL → MCP 注册 → 对话排障"),
    ("模拟联调", "启动模拟器 → 连源 → 挂规则"),
    ("全部配置", "七张卡铺开(高级视图)"),
];

/// GUI 添加的临时点位(会话内有效;可回写为点位表分节 devN_临时点位,重启模拟器后仍生效)
#[derive(Clone, Debug)]
struct ModTempPoint {
    dev_id: u32,
    key: String,
    name: String,
    addr: u16,
    func: u8,
    ty: String,
    regs: u16,
    scale: f64,
    unit: String,
    /// 初值(raw 寄存器值;写回点位表 init)
    init_raw: f64,
}

/// YAML 双引号字符串转义(名字/单位里可能出现引号或反斜杠)
fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 临时点位 → YAML 分节文本(分节名固定 devN_临时点位;一行一点位)
fn moddev_temp_section(dev_id: u32, pts: &[ModTempPoint]) -> String {
    let mut s = format!("\n# 点位编辑窗回写:会话临时点(联调验证后可并入正式分节)\ndev{dev_id}_临时点位:\n");
    for p in pts.iter().filter(|p| p.dev_id == dev_id) {
        s.push_str(&format!(
            "  {}: {{name: \"{}\", addr: 0x{:04X}, func: {}, type: {}, regs: {}, scale: {}, unit: \"{}\", rw: 1, init: {}, grp: 临时}}\n",
            p.key,
            yaml_escape(&p.name),
            p.addr,
            p.func,
            p.ty,
            p.regs,
            p.scale,
            yaml_escape(&p.unit),
            p.init_raw
        ));
    }
    s
}

/// 把临时点位追加回点位表文件(按 dev 分节追加;分节已存在 → 报错请手动合并,不覆盖)
fn moddev_writeback(path: &std::path::Path, pts: &[ModTempPoint]) -> Result<usize, String> {
    if path.as_os_str().is_empty() {
        return Err("点位表路径不可用(实例已重启?)".into());
    }
    let old = std::fs::read_to_string(path).map_err(|e| format!("读 {}: {e}", path.display()))?;
    let dev_ids: Vec<u32> = {
        let mut v: Vec<u32> = pts.iter().map(|p| p.dev_id).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let mut out = old;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    let mut added = 0usize;
    for id in dev_ids {
        let header = format!("dev{id}_临时点位:");
        if out.lines().any(|l| l.trim_end() == header) {
            return Err(format!("{} 已有 dev{id}_临时点位 分节,请手动合并后重试(避免重复键)", path.display()));
        }
        added += pts.iter().filter(|p| p.dev_id == id).count();
        out.push_str(&moddev_temp_section(id, pts));
    }
    std::fs::write(path, &out).map_err(|e| format!("写 {}: {e}", path.display()))?;
    Ok(added)
}

/// 行内 sparkline:34×12 px 微曲线,纵轴=最近拍值域(不足 2 拍/值恒定 → 基线)
fn spark(ui: &mut Ui, series: &[f64], mn: f64, mx: f64) {
    let (sw, sh) = (34.0, 12.0);
    let (r, _) = ui.allocate_exact_size(egui::vec2(sw, sh), egui::Sense::hover());
    let p = ui.painter();
    let line_c = Color32::from_rgb(86, 182, 224);
    if series.len() >= 2 && (mx - mn).abs() > f64::EPSILON {
        let pts: Vec<egui::Pos2> = series
            .iter()
            .enumerate()
            .map(|(k, v)| {
                let x = r.left() + k as f32 / (series.len() - 1) as f32 * sw;
                let y = r.bottom() - ((v - mn) / (mx - mn)) as f32 * sh;
                egui::Pos2::new(x, y.clamp(r.top(), r.bottom()))
            })
            .collect();
        for w in pts.windows(2) {
            p.line_segment([w[0], w[1]], egui::Stroke::new(1.0_f32, line_c));
        }
    } else {
        p.line_segment(
            [egui::Pos2::new(r.left(), r.center().y), egui::Pos2::new(r.right(), r.center().y)],
            egui::Stroke::new(1.0_f32, line_c.gamma_multiply(0.5)),
        );
    }
}

fn num_key(n: u8) -> egui::Key {
    match n {
        0 => egui::Key::Num0,
        1 => egui::Key::Num1,
        2 => egui::Key::Num2,
        3 => egui::Key::Num3,
        4 => egui::Key::Num4,
        5 => egui::Key::Num5,
        _ => egui::Key::Num6,
    }
}

/// C4 内存护栏:实时累积记录上限(约数小时满负载;超出滚动丢弃最旧并在状态栏诚实标注,
/// 完整数据靠源头录制 NDJSON——录制不受此护栏影响)
const LIVE_RECS_CAP: usize = 2_000_000;

/// 一路实时源(C1 多通道并行):句柄 + 该源自己的统计;记录统一进 live_recs 按通道合并,
/// 通道标签经 Batch.labels 进 live_labels(UI 通道面板本就按通道分组,无需改)。
struct LiveSlot {
    h: live::LiveHandle,
    name: String,
    stats: iotprobe_core::ingest::live::LiveStats,
    epoch: Option<u64>,
}

/// 实时源类型的下拉显示名(分类见「配置中心 → 实时接入与录制」卡)
fn live_kind_label(kind: usize) -> &'static str {
    match kind {
        0 => "TCP 客户端",
        1 => "TCP 服务端",
        2 => "串口(COM)",
        3 => "回放",
        4 => "ZLG USBCANFD",
        5 => "模拟 CAN(开发演示)",
        6 => "Modbus RTU(TCP)",
        7 => "设备模拟器",
        8 => "CAN卡·VCI兼容",
        9 => "CAN卡·SLCAN",
        11 => "CAN卡·PEAK",
        12 => "CAN卡·Kvaser",
        13 => "CAN卡·GCAN",
        #[cfg(target_os = "linux")]
        10 => "SocketCAN vcan",
        _ => "未知源类型",
    }
}

/// 分类下拉里的单个选项
fn live_kind_item(ui: &mut Ui, kind: &mut usize, id: usize, name: &str) {
    if ui.selectable_label(*kind == id, name).clicked() {
        *kind = id;
    }
}

/// 分类下拉的分组标题
fn live_kind_group(ui: &mut Ui, name: &str) {
    ui.label(egui::RichText::new(format!("─ {name} ─")).size(9.5).color(egui::Color32::GRAY));
}
#[allow(dead_code)] // 供 views.rs 同名实现使用;main.rs 内暂无调用点
fn sel_bg(u: &Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(46, 60, 82) } else { Color32::from_rgb(212, 228, 250) }
}
#[allow(dead_code)]
fn hover_bg(u: &Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(36, 40, 48) } else { Color32::from_rgb(230, 234, 240) }
}

/// 主题应用:暗色=现有定制样式;亮色=egui 浅色 Visuals + 同等间距
fn apply_theme(ctx: &egui::Context, dark: bool) {
    let mut style = (*ctx.style()).clone();
    if dark {
        style.visuals = egui::Visuals::dark();
        style.visuals.panel_fill = Color32::from_rgb(24, 26, 31);
        style.visuals.extreme_bg_color = Color32::from_rgb(15, 16, 19);
        style.visuals.window_fill = Color32::from_rgb(28, 30, 36);
        style.visuals.selection.bg_fill = Color32::from_rgb(52, 86, 130);
        style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(40, 44, 52);
        style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(52, 58, 68);
    } else {
        style.visuals = egui::Visuals::light();
        style.visuals.extreme_bg_color = Color32::from_rgb(252, 252, 254);
        style.visuals.panel_fill = Color32::from_rgb(246, 247, 250);
        style.visuals.window_fill = Color32::from_rgb(250, 250, 253);
    }
    style.spacing.item_spacing = egui::vec2(6.0, 4.0);
    ctx.set_style(style);
}

/// 回放注入预览(加载时统计)
struct InjPreview {
    frames: Vec<(u64, u32, bool, Vec<u8>)>,
    duration_s: f64,
    out_of_wl: u32,
}

pub struct App {
    ds: Option<Arc<Dataset>>,
    rx: Option<Receiver<load::LoadMsg>>,
    status: String,
    sel: Option<u32>,
    sel_path: Vec<usize>,
    want_scroll: Option<u32>,
    filter: String,
    proto_filter: HashMap<Proto, bool>,
    shown: Vec<u32>,
    sig_sel: HashSet<String>,
    /// 收藏的信号(侧栏「常用」组置顶;随会话持久化)
    fav_sigs: HashSet<String>,
    /// 亮/暗主题(true=暗)
    dark: bool,
    /// 用户改过色的信号(key → RGB);未设置的按序取调色板
    color_ov: HashMap<String, [u8; 3]>,
    /// 帧表 hover 的帧(绘图预览线)
    hover_frame: Option<u32>,
    /// 告警列表窗口
    warn_open: bool,
    /// 设备模拟器面板:点位搜索/当前 dev
    moddev_filter: String,
    moddev_dev_idx: usize,
    /// 点位编辑窗口(模拟联调主工位)与表格过滤状态
    show_ptedit: bool,
    moddev_only_rw: bool,
    moddev_only_pinned: bool,
    moddev_only_host: bool,
    /// 临时点(会话内)与表单
    moddev_temp_open: bool,
    moddev_temp: Vec<ModTempPoint>,
    tmp_name: String,
    tmp_addr: String,
    tmp_func: u8,
    tmp_ty: String,
    tmp_regs: u16,
    tmp_scale: f64,
    tmp_unit: String,
    tmp_val: f64,
    /// 模拟器实例选择(点位表视图用;A3 多实例)
    moddev_inst_idx: usize,
    /// 独立运行的模拟器实例(A3 多实例并行;与实时接入生命周期解耦;移除即停)
    moddev_rts: Vec<crate::moddev::ModDevInst>,
    /// IEC 104 从机模拟(A5):运行时与表单
    moddev104_rt: Option<std::sync::Arc<crate::moddev104::ModDev104Runtime>>,
    moddev104_yaml: Option<PathBuf>,
    moddev104_record: bool,
    moddev104_record_path: Option<PathBuf>,
    /// 自定义协议从机模拟(A6):运行时与表单
    moddev_custom_rt: Option<std::sync::Arc<crate::moddev_custom::ModDevCustomRuntime>>,
    /// DL/T 645 电表从机模拟(J1):运行时与表单
    moddev645_rt: Option<std::sync::Arc<crate::moddev645::ModDev645Runtime>>,
    moddev645_yaml: Option<PathBuf>,
    moddev645_record: bool,
    moddev645_record_path: Option<PathBuf>,
    moddev_custom_yaml: Option<PathBuf>,
    moddev_custom_record: bool,
    moddev_custom_record_path: Option<PathBuf>,
    /// 回放并入实时(模拟现场):运行句柄;drop 即停
    replay_into: Option<crate::live::ReplayIntoHandle>,
    /// 回放注入(P2):文件/速度/预览/运行句柄
    inj_path: Option<PathBuf>,
    inj_speed_idx: usize,
    inj_preview: Option<InjPreview>,
    inj_handle: Option<crate::tx::InjHandle>,
    /// 底部视图 tab(0=帧表 1=通道 2=聚合)
    bottom_view: usize,
    /// 主页面切换(0=工作台 1=配置中心):配置整页铺开,不再散落弹窗
    page: usize,
    /// 配置中心场景视图(0=离线分析 1=现场排故含产线抽测 2=数据喂AI 3=模拟联调 4=全部配置)
    scene: usize,
    /// 快捷键帮助窗口(F1)
    help_open: bool,
    /// 工具弹窗开关(事件/试探/任务/拓扑/发送)
    show_events: bool,
    show_probe: bool,
    show_tasks: bool,
    show_topo: bool,
    /// 拓扑连线图(A1):主机→模拟器设备,连线=链路健康
    show_topolink: bool,
    /// 串口终端(E1):设备 CLI/AT 命令交互,补 MobaXterm 重叠区
    show_terminal: bool,
    /// 单帧解码(W4):粘贴一帧 hex 秒解——复用 analyze 管线,语义层(DBC/CANopen/自定义)全可用
    show_single: bool,
    /// 向导模式(true=主界面即向导,每屏一步;false=平铺专家视图)——首启 true,完成后自动切 false
    wizard_mode: bool,
    wizard_task: usize, // 选中任务(场景 idx);usize::MAX = 任务选择页
    wizard_step: usize,
    single_kind: usize, // 0=经典 CAN 1=CAN FD 2=UART 字节流
    single_id: String,
    single_data: String,
    single_ext: bool,
    single_dir_tx: bool,
    single_result: Option<Arc<iotprobe_core::model::Dataset>>,
    /// 串口终端运行句柄与表单
    term: Option<std::sync::Arc<terminal::TermHandle>>,
    term_port: String,
    term_baud: u32,
    term_hex: bool,
    term_input: String,
    term_crlf: bool,
    term_periodic: bool,
    term_interval_ms: u32,
    term_record: bool,
    term_record_path: Option<PathBuf>,
    term_err: Option<String>,
    show_tx: bool,
    /// 选中帧横条展开态(false=仅一行摘要)
    sel_expanded: bool,
    /// 解析后的 DBC(与 dbc_path 同步;信号分组显示报文名用)
    dbc: Option<iotprobe_core::dbc::Dbc>,
    /// 已折叠的信号组(组键;内存态不持久化)
    sig_group_closed: HashSet<String>,
    /// 信号搜索框内容(匹配报文名/信号名)
    sig_filter: String,
    plot_state: plot::PlotState,
    reset_plot: bool,
    follow: bool,
    gap_ms: f64,
    custom_paths: Vec<PathBuf>,
    dbc_path: Option<PathBuf>,
    /// DBC 协议库:库内条目(protocols/ 目录)
    dbc_library: Vec<DbcLibEntry>,
    /// 报文键 → 定义它的 DBC 名(侧栏分节展示;apply_dataset 时重建)
    dbc_attr: HashMap<u32, String>,
    /// 本次数据集是否已尝试过自动匹配(防循环)
    auto_match_done: bool,
    /// 当前启用的 DBC 路径集(可多选,按序合并)
    dbc_paths: Vec<PathBuf>,
    dbc_library_remove: Option<PathBuf>,
    map_path: Option<PathBuf>,
    /// IEC 104 信息体点表(MVP ②)
    map104_path: Option<PathBuf>,
    /// 储能拓扑定义(MVP ③;YAML)
    topo_path: Option<PathBuf>,
    topo: Option<iotprobe_core::topology::Topology>,
    /// 拓扑评估缓存(随数据集重建)
    topo_state: Option<iotprobe_core::topology::TopoState>,
    /// 104 点表编辑窗口的内存副本(None=窗口关闭)
    edit_map104: Option<iotprobe_core::dissect::Map104>,
    edit_map104_path: Option<PathBuf>,
    edit_map104_dirty: bool,
    inline_specs: Vec<iotprobe_core::dissect::CustomSpec>,
    rule_dirs: Vec<PathBuf>,
    probe_results: Vec<iotprobe_core::dissect::unknown::UnknownReport>,
    last_files: Vec<PathBuf>,
    sort: (views::SortKey, bool),
    dt_cache: Vec<f64>,
    dec_cache: HashMap<u32, Arc<iotprobe_core::model::Decoded>>,
    saved_sigs: Vec<String>,
    // ---- 实时接入(FR-S1)/会话录制(FR-S2) ----
    /// 实时源线程列表(C1 多通道并行:第二路 485/第二张 CAN 卡直接并入同一会话,按通道合并)
    lives: Vec<LiveSlot>,
    /// 帧流转发(W:指向其他端口):开关/端口/句柄/tee 槽
    fwd_on: bool,
    fwd_port: u16,
    fwd: Option<crate::live::Forwarder>,
    fwd_slot: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>,
    /// 数据源名(Dataset.name;多源时用 + 连接)
    live_name: String,
    /// 累积的实时记录(重建时快照进 analyze;C4 内存护栏:超 LIVE_RECS_CAP 滚动丢弃最旧,
    /// 丢弃数进 live_rolled 诚实标注——完整数据靠源头录制落盘,不受护栏影响)
    live_recs: std::collections::VecDeque<iotprobe_core::model::Record>,
    /// C4:因内存护栏滚动丢弃的最旧记录数
    live_rolled: u64,
    live_labels: HashMap<u16, String>,
    live_warns: Vec<String>,
    live_stats: iotprobe_core::ingest::live::LiveStats,
    live_epoch: Option<u64>,
    live_dirty: bool,
    /// 在途的实时重建结果通道
    live_rx: Option<Receiver<load::LoadMsg>>,
    last_rebuild: std::time::Instant,
    live_form: live::LiveForm,
    // ---- 聚合视图(FR-4.2) ----
    agg_cache: Option<Vec<AggRow>>,
    agg_sort: u8,
    // ---- 发送面板(FR-4.7/10.4/10.5) ----
    tx_hub: Option<std::sync::Arc<crate::tx::TxHub>>,
    tx_unlocked: bool,
    tx_whitelist: String,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);
        seed_default_dbcs();
        ensure_guide();
        apply_theme(&cc.egui_ctx, true);

        let mut app = App {
            ds: None,
            rx: None,
            status: String::new(),
            sel: None,
            sel_path: vec![],
            want_scroll: None,
            filter: String::new(),
            proto_filter: HashMap::new(),
            shown: vec![],
            sig_sel: HashSet::new(),
            fav_sigs: HashSet::new(),
            dark: true,
            color_ov: HashMap::new(),
            hover_frame: None,
            warn_open: false,
            moddev_filter: String::new(),
            moddev_dev_idx: 0,
            show_ptedit: false,
            moddev_only_rw: false,
            moddev_only_pinned: false,
            moddev_only_host: false,
            moddev_temp_open: false,
            moddev_temp: vec![],
            tmp_name: String::new(),
            tmp_addr: String::new(),
            tmp_func: 3,
            tmp_ty: "u16".into(),
            tmp_regs: 4,
            tmp_scale: 1.0,
            tmp_unit: String::new(),
            tmp_val: 0.0,
            moddev_inst_idx: 0,
            moddev_rts: Vec::new(),
            moddev104_rt: None,
            moddev104_yaml: None,
            moddev104_record: false,
            moddev104_record_path: None,
            moddev_custom_rt: None,
            moddev_custom_yaml: None,
            moddev_custom_record: false,
            moddev_custom_record_path: None,
            moddev645_rt: None,
            moddev645_yaml: None,
            moddev645_record: false,
            moddev645_record_path: None,
            replay_into: None,
            inj_path: None,
            inj_speed_idx: 0,
            inj_preview: None,
            inj_handle: None,
            bottom_view: 0,
            page: 0,
            scene: 0,
            help_open: false,
            show_events: false,
            show_probe: false,
            show_tasks: false,
            show_topo: false,
            show_topolink: false,
            show_terminal: false,
            wizard_mode: true,
            wizard_task: usize::MAX,
            wizard_step: 0,
            show_single: false,
            single_kind: 0,
            single_id: String::new(),
            single_data: String::new(),
            single_ext: false,
            single_dir_tx: false,
            single_result: None,
            term: None,
            term_port: String::new(),
            term_baud: 115200,
            term_hex: false,
            term_input: String::new(),
            term_crlf: true,
            term_periodic: false,
            term_interval_ms: 1000,
            term_record: false,
            term_record_path: None,
            term_err: None,
            show_tx: false,
            sel_expanded: false,
            dbc: None,
            sig_group_closed: HashSet::new(),
            sig_filter: String::new(),
            plot_state: plot::PlotState { t0: 0.0, t1: 1.0, normalized: true, cursor_a: None, cursor_b: None, box_drag: None },
            reset_plot: false,
            follow: false,
            gap_ms: 0.0,
            custom_paths: vec![],
            dbc_path: None,
            dbc_library: dbc_library_load(),
            dbc_attr: HashMap::new(),
            auto_match_done: false,
            dbc_paths: vec![],
            dbc_library_remove: None,
            map_path: None,
            map104_path: None,
            topo_path: None,
            topo: None,
            topo_state: None,
            edit_map104: None,
            edit_map104_path: None,
            edit_map104_dirty: false,
            inline_specs: vec![],
            rule_dirs: vec![],            probe_results: vec![],
            last_files: vec![],
            sort: (views::SortKey::Idx, false),
            dt_cache: vec![],
            dec_cache: HashMap::new(),
            saved_sigs: vec![],
            lives: vec![],
            fwd_on: false,
            fwd_port: 9101,
            fwd: None,
            fwd_slot: Arc::new(std::sync::Mutex::new(None)),
            live_name: String::new(),
            live_recs: Default::default(),
            live_rolled: 0,
            live_labels: HashMap::new(),
            live_warns: vec![],
            live_stats: Default::default(),
            live_epoch: None,
            live_dirty: false,
            live_rx: None,
            last_rebuild: std::time::Instant::now(),
            live_form: live::LiveForm::default(),
            agg_cache: None,
            agg_sort: 0,
            tx_hub: None,
            tx_unlocked: false,
            tx_whitelist: String::new(),
        };
        // D2:上次异常退出提示(crash 日志在 exe 目录)
        if let Some(p) = latest_crash_log() {
            app.status = format!("⚠ 上次异常退出,crash 日志: {}", p.display());
        }
        // D1:发现新版本(update/manifest.json,离线提示不自动下载)
        if let Some((ver, notes)) = check_update_manifest() {
            let hint = format!("🆕 发现新版本 v{ver}(update/ 目录):{notes} —— 手动替换 exe/zip 即可");
            if app.status.is_empty() {
                app.status = hint;
            }
        }
        // 会话恢复优先;无会话时加载示例
        if let Some(sess) = load_session() {
            if !sess.files.is_empty() {
                app.custom_paths = sess.custom_paths;
                app.dbc_path = sess.dbc;
                app.dbc_paths = sess.dbcs;
                app.dbc = parse_dbc_of(&app.dbc_path);
                app.map_path = sess.map;
                app.map104_path = sess.map104;
                app.topo_path = sess.topo.clone();
                if let Some(p) = &sess.topo {
                    match iotprobe_core::topology::Topology::load_file(p) {
                        Ok(t) => app.topo = Some(t),
                        Err(e) => eprintln!("拓扑加载失败: {e}"),
                    }
                }
                app.inline_specs = sess.inline_specs;
                app.rule_dirs = sess.rule_dirs;
                app.gap_ms = sess.gap_ms;
                app.filter = sess.filter.clone();
                app.saved_sigs = sess.sig_sel;
                app.fav_sigs = sess.fav_sigs.into_iter().collect();
                app.color_ov = sess.color_ov;
                app.dark = sess.dark;
                app.scene = sess.scene.min(SCENES.len() - 1);
                app.wizard_task = app.scene; // 恢复上次任务的步骤;任务选择页只在首启/菜单引导出现
                apply_theme(&cc.egui_ctx, app.dark);
                app.status = "已恢复上次会话".into();
                app.start_load(sess.files, "上次会话".into());
                return app;
            }
        }
        app.try_load_demo();
        // 首启分流(使用体验):无数据可演示(无会话且 samples 缺失)→ 默认进「离线分析」场景,
        // 按步骤走(打开文件 → 体检 → 报告),不让新用户停在空工作台
        if app.ds.is_none() && !PathBuf::from("samples").exists() {
            // 首启分流(I11/I13 落地):打开即引导——主界面停在配置中心「这次想做什么?」任务选择页
            // (向导=主页面一屏一事,不再弹浮窗);此前只设 wizard_mode 不切页,实际停在空工作台
            app.wizard_mode = true;
            app.wizard_task = usize::MAX;
            app.wizard_step = 0;
            app.page = 1;
        }
        app
    }

    fn try_load_demo(&mut self) {
        let dir = PathBuf::from("samples");
        if dir.exists() {
            let mut files: Vec<PathBuf> = [
                "modbus_rtu.log",
                "custom_485.log",
                "candump.log",
                "net.pcap",
                "unknown_protocol.log",
                "vector.asc",
                "can_socketcan.pcap",
            ]
                .iter()
                .map(|f| dir.join(f))
                .filter(|p| p.exists())
                .collect();
            if !files.is_empty() {
                files.sort();
                self.custom_paths = vec![dir.join("configs/custom_example.json")]
                    .into_iter()
                    .filter(|p| p.exists())
                    .collect();
                self.map_path = Some(dir.join("configs/modbus_map.json")).filter(|p| p.exists());
                self.dbc_path = Some(dir.join("motor.dbc")).filter(|p| p.exists());
                self.dbc = parse_dbc_of(&self.dbc_path);
                self.rule_dirs = std::fs::read_dir(dir.join("rules-pack"))
                    .map(|rd| {
                        rd.filter_map(|e| e.ok())
                            .filter(|e| e.path().join("rules.yaml").exists())
                            .map(|e| e.path())
                            .collect()
                    })
                    .unwrap_or_default();
                self.start_load(files, "示例数据".into());
                return;
            }
        }
        self.status = "未找到 samples/ 示例。点击「打开文件」加载你的日志。".into();
    }

    fn start_load(&mut self, files: Vec<PathBuf>, name: String) {
        // 实时接入与离线文件互斥:加载文件时先断开实时源并放弃在途的实时重建
        if !self.lives.is_empty() {
            self.disconnect_live("已断开实时接入(改为加载离线文件)");
        }
        self.live_rx = None;
        self.live_dirty = false;
        self.last_files = files.clone();
        // 新数据集:重新给自动匹配一次机会
        self.auto_match_done = false;
        let req = load::LoadReq {
            name,
            files,
            custom: self.custom_paths.clone(),
            inline_custom: self.inline_specs.clone(),
            dbcs: self.active_dbc_paths(),
            map: self.map_path.clone(),
            map104: self.map104_path.clone(),
            rule_dirs: self.rule_dirs.clone(),
            gap_ms: self.gap_ms,
        };
        self.rx = Some(load::spawn_load(req));
        self.status = "加载中…".into();
    }

    fn poll_load(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut done: Option<Box<Result<Dataset, String>>> = None;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                load::LoadMsg::Progress(s) => self.status = s,
                load::LoadMsg::Done(r) => done = Some(r),
            }
        }
        if let Some(r) = done {
            self.rx = None;
            match *r {
                Ok(ds) => self.apply_dataset(ds, false),
                Err(e) => self.status = format!("加载失败: {e}"),
            }
        }
    }

    /// 数据集落地:重建派生状态(信号勾选/Δt 缓存/帧表/曲线)。
    /// live=true 为实时增量重建:保留选中帧与曲线视窗,不覆盖会话持久化。
    fn apply_dataset(&mut self, ds: Dataset, live: bool) {
        self.sig_sel = ds
            .signals
            .iter()
            .filter(|s| !s.key.starts_with("Δt"))
            .take(6)
            .map(|s| s.key.clone())
            .collect();
        if live {
            // 新帧按时间追加在尾部,旧帧索引稳定:保留当前选中帧
            self.sel_path.clear();
            if self.sel.map(|s| s as usize >= ds.frames.len()).unwrap_or(false) {
                self.sel = None;
            }
        } else {
            self.sel = None;
            self.sel_path.clear();
        }
        self.status = format!(
            "已加载:{} — {}帧 / {}信号 / {}事件",
            ds.name,
            ds.frames.len(),
            ds.signals.len(),
            ds.events.len()
        );
        // CAN 数据未启用协议:给出下一步引导(协议库空→导入;有库→自动匹配)
        let can_cnt = ds.frames.iter().filter(|f| matches!(f.proto, Proto::Can | Proto::CanFd)).count();
        if can_cnt > 0 && self.active_dbc_paths().is_empty() {
            if self.dbc_library.is_empty() {
                self.status
                    .push_str(&format!(" | 检测到 CAN 帧 ×{can_cnt}:去【配置中心】协议库导入对应 DBC 可解码命名信号"));
            } else {
                self.status
                    .push_str(&format!(" | 检测到 CAN 帧 ×{can_cnt}:协议库已有 {} 个 DBC,可「⚡ 自动匹配」一键启用", self.dbc_library.len()));
            }
        }
        if !live {
            self.reset_plot = true;
        }
        self.dt_cache = ds
            .frames
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if i > 0 {
                    let p = &ds.frames[i - 1];
                    if p.channel == f.channel && p.source == f.source {
                        f.t_ns.saturating_sub(p.t_ns) as f64 / 1e6
                    } else {
                        0.0
                    }
                } else {
                    0.0
                }
            })
            .collect();
        self.dec_cache.clear();
        // 恢复上次勾选的信号(交集);为空则自动选前 6 条
        let keys: std::collections::HashSet<&String> = ds.signals.iter().map(|s| &s.key).collect();
        let kept: HashSet<String> = self.saved_sigs.iter().filter(|k| keys.contains(k)).cloned().collect();
        self.sig_sel = if kept.is_empty() {
            ds.signals
                .iter()
                .filter(|s| !s.key.starts_with("Δt") && !s.key.starts_with("RTT"))
                .take(6)
                .map(|s| s.key.clone())
                .collect()
        } else {
            kept
        };
        self.saved_sigs.clear();
        // 分组显示用的 DBC 缓存 = 当前启用集的合并结果(协议库多选后信号组标题同步)
        self.dbc = self.dbc_all();
        self.rebuild_dbc_attr();
        self.ds = Some(Arc::new(ds));
        // D2:会话标签随数据源更新(crash 日志带上它)
        set_session_tag(&self.ds.as_ref().unwrap().name);
        // 拓扑评估(MVP ③):有拓扑定义时重算缓存
        self.topo_state = self
            .topo
            .as_ref()
            .and_then(|topo| self.ds.as_ref().map(|ds| iotprobe_core::topology::evaluate(ds, topo)));
        self.rebuild_shown();
        if !live {
            // 智能自动匹配:CAN 数据 + 协议库有货 + (未启用任何 DBC 或 启用集对新数据零命中)
            // → 静默换最优协议并重新解码(每数据集一次,防循环)
            let ds_now = self.ds.clone();
            if let Some(ds_now) = ds_now {
                let can_cnt = ds_now.frames.iter().filter(|f| matches!(f.proto, Proto::Can | Proto::CanFd)).count();
                if can_cnt > 0 && !self.dbc_library.is_empty() && !self.auto_match_done {
                    self.auto_match_done = true;
                    if self.active_dbc_paths().is_empty() || self.dbc_paths_hits(&ds_now) == 0 {
                        if let Some((score, p)) = self.dbc_match_best(&ds_now) {
                            let name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                            self.dbc_paths.clear();
                            self.dbc_paths.push(p);
                            self.rebuild_dbc_attr();
                            self.dbc = self.dbc_all();
                            self.status = format!("已自动匹配协议: {name}(命中 {score} 个信号定义),正在重新解码…");
                            let files = self.last_files.clone();
                            let dsname = ds_now.name.clone();
                            self.start_load(files, dsname);
                        } else {
                            self.status.push_str(" | 协议库中没有 DBC 能匹配此数据的 CAN ID(可导入自定义协议)");
                        }
                    }
                } else if can_cnt > 0 && self.active_dbc_paths().is_empty() && self.dbc_library.is_empty() && !self.auto_match_done {
                    self.status.push_str(" | 协议库为空:把 .dbc 放进 protocols/ 目录或【配置中心 → 协议解析】导入");
                    self.auto_match_done = true;
                }
            }
            self.save_session();
        }
    }

    // ================= 实时接入(FR-S1)/ 会话录制(FR-S2) =================

    fn poll_live(&mut self) {
        let mut ended: Vec<(usize, Result<(), String>)> = vec![];
        // C1 多通道:逐槽拉取;各槽统计独立,记录/标签/告警并入会话级状态
        for (i, slot) in self.lives.iter_mut().enumerate() {
            while let Ok(msg) = slot.h.rx.try_recv() {
                match msg {
                    live::LiveMsg::Batch(b) => {
                        self.live_recs.extend(b.records);
                        // C4 内存护栏:超上限滚动丢弃最旧(录制在源头落盘,完整数据不受影响)
                        while self.live_recs.len() > LIVE_RECS_CAP {
                            self.live_recs.pop_front();
                            self.live_rolled += 1;
                        }
                        for (k, v) in b.labels {
                            self.live_labels.insert(k, v);
                        }
                        // None = 并入生产者(回放并入):不覆盖该源统计
                        if let Some(s) = b.stats {
                            slot.stats = s;
                        }
                        self.live_warns.extend(b.warnings);
                        if slot.epoch.is_none() {
                            slot.epoch = b.epoch_ns;
                            if self.live_epoch.is_none() {
                                self.live_epoch = b.epoch_ns; // 会话 epoch 取首源
                            }
                        }
                        self.live_dirty = true;
                    }
                    live::LiveMsg::Info(s) => self.status = s,
                    live::LiveMsg::Ended(r) => ended.push((i, r)),
                }
            }
        }
        // 汇总统计(顶栏/卡片显示合并口径)
        self.live_stats = self.lives.iter().fold(Default::default(), |a, s: &LiveSlot| iotprobe_core::ingest::live::LiveStats {
            ok: a.ok + s.stats.ok,
            bad: a.bad + s.stats.bad,
            gaps: a.gaps + s.stats.gaps,
        });
        if !ended.is_empty() {
            // 移除已结束的槽(倒序删,索引不漂移)
            for (i, r) in ended.into_iter().rev() {
                if i < self.lives.len() {
                    let slot = self.lives.remove(i);
                    self.live_name = self.live_names_joined();
                    self.live_dirty = true; // 触发最后一次重建
                    match r {
                        Ok(()) => self.status = format!("实时源 {} 结束:共 {} 帧,坏行 {}", slot.name, slot.stats.ok, slot.stats.bad),
                        Err(e) => self.status = format!("实时源 {} 中断: {e}", slot.name),
                    }
                }
            }
        }
        // 节流重建:有新数据、无在途分析,且(距上次重建 ≥1s 或源已结束)
        if self.live_dirty && self.rx.is_none() && self.live_rx.is_none() {
            if self.lives.is_empty() || self.last_rebuild.elapsed() >= std::time::Duration::from_millis(1000) {
                self.start_live_rebuild();
            }
        }
        // 在途重建结果
        if let Some(rx) = &self.live_rx {
            let mut done: Option<Box<Result<Dataset, String>>> = None;
            while let Ok(msg) = rx.try_recv() {
                if let load::LoadMsg::Done(r) = msg {
                    done = Some(r);
                }
            }
            if let Some(r) = done {
                self.live_rx = None;
                match *r {
                    Ok(ds) => self.apply_dataset(ds, true),
                    Err(e) => self.status = format!("实时数据重建失败: {e}"),
                }
                self.live_dirty = false;
            }
        }
    }

    /// 用现有 analyze 管线把累积的实时记录重建为 Dataset
    fn start_live_rebuild(&mut self) {
        self.last_rebuild = std::time::Instant::now();
        if self.live_recs.is_empty() {
            self.live_dirty = !self.lives.is_empty(); // 尚无数据,等下一批
            return;
        }
        let src = iotprobe_core::ingest::SourceData {
            name: self.live_name.clone(),
            records: self.live_recs.iter().cloned().collect(),
            epoch_ns: self.live_epoch,
            warnings: self.live_warns.clone(),
            chan_labels: self.live_labels.clone(),
        };
        // 保留当前信号勾选(重建后按 key 交集恢复)
        self.saved_sigs = self.sig_sel.iter().cloned().collect();
        let (mut cfg, cfg_warns) = load::build_cfg(&self.custom_paths, &self.inline_specs, &self.active_dbc_paths(), &self.map_path);
        let mut warns = cfg_warns;
        if let Some(p) = &self.map104_path {
            load::load_map104(&mut cfg, p, &mut warns);
        }
        if let Some(w) = warns.first() {
            self.status = format!("配置告警: {w}");
        }
        let name = self.live_name.clone();
        self.live_rx = Some(load::spawn_analyze(name, vec![src], cfg));
    }

    fn connect_live(&mut self) {
        let alias = {
            let a = self.live_form.alias.trim().to_string();
            (!a.is_empty()).then_some(a)
        };
        let kind = match self.live_form.kind {
            0 => {
                let addr = self.live_form.addr.trim().to_string();
                if addr.is_empty() {
                    self.status = "请填写 TCP 地址(host:port)".into();
                    return;
                }
                live::SourceKind::TcpClient { addr }
            }
            1 => {
                let addr = self.live_form.addr.trim().to_string();
                if addr.is_empty() {
                    self.status = "请填写监听地址(host:port 或 0.0.0.0:port)".into();
                    return;
                }
                live::SourceKind::TcpServer { addr }
            }
            2 => {
                let port = self.live_form.port_name.trim().to_string();
                if port.is_empty() {
                    self.status = "请填写 COM 口(如 COM3)".into();
                    return;
                }
                live::SourceKind::Serial { port, baud: self.live_form.baud }
            }
            4 => live::SourceKind::Zlg {
                device_type: self.live_form.device_type.trim().to_string(),
                device_index: self.live_form.device_index,
                channels: self.live_form.channels,
                bitrate: self.live_form.baud_k,
                data_bitrate: self.live_form.data_baud_k,
                ts_unit_ns: match self.live_form.ts_unit {
                    0 => 100_000,
                    1 => 10_000,
                    _ => 1_000,
                },
                listen_only: self.live_form.listen_only,
            },
            5 => live::SourceKind::Sim,
            6 => {
                let addr = self.live_form.addr.trim().to_string();
                if addr.is_empty() {
                    self.status = "请填写串口服务器地址(host:port)".into();
                    return;
                }
                live::SourceKind::RtuTcp { addr, gap_ms: self.live_form.rtu_gap_ms }
            }
            8 => live::SourceKind::CanHw {
                vendor: 0,
                model: self.live_form.hw_model.clone(),
                device_index: self.live_form.device_index,
                channels: self.live_form.channels,
                bitrate: self.live_form.hw_baud,
                listen_only: self.live_form.hw_listen_only,
                fd: false,
                port: String::new(),
            },
            9 => live::SourceKind::CanHw {
                vendor: 1,
                model: String::new(),
                device_index: 0,
                channels: 1,
                bitrate: self.live_form.hw_baud,
                listen_only: false,
                fd: false,
                port: self.live_form.port_name.trim().to_string(),
            },
            11 => live::SourceKind::CanHw {
                vendor: 2, // PEAK PCAN-Basic
                model: String::new(),
                device_index: self.live_form.device_index.max(1), // USB1 起
                channels: 1,
                bitrate: self.live_form.hw_baud,
                listen_only: self.live_form.hw_listen_only,
                fd: self.live_form.hw_fd,
                port: String::new(),
            },
            12 => live::SourceKind::CanHw {
                vendor: 3, // Kvaser CANlib
                model: String::new(),
                device_index: self.live_form.device_index, // 0 起
                channels: 1,
                bitrate: self.live_form.hw_baud,
                listen_only: self.live_form.hw_listen_only,
                fd: self.live_form.hw_fd,
                port: String::new(),
            },
            13 => live::SourceKind::CanHw {
                vendor: 4, // GCAN ECanVci
                model: self.live_form.hw_model.clone(), // DeviceType 数字直传
                device_index: self.live_form.device_index,
                channels: self.live_form.channels,
                bitrate: self.live_form.hw_baud,
                listen_only: self.live_form.hw_listen_only,
                fd: false,
                port: String::new(),
            },
            #[cfg(target_os = "linux")]
            10 => live::SourceKind::SocketCan {
                iface: self.live_form.port_name.trim().to_string(),
            },
            3 if self.live_form.replay_merge => {
                self.status = "已选「并入当前实时」模式:请用下方「▶ 并入实时」按钮(并入不经过「连接」)".into();
                return;
            }
            _ => match self.live_form.replay_path.clone() {
                Some(p) => live::SourceKind::Replay { path: p },
                None => {
                    self.status = "请先选择回放文件(.ndjson 录制 或 .asc 抓包)".into();
                    return;
                }
            },
        };
        // FR-S2 录制路径:勾选但未选文件时现场弹保存对话框
        let record_path = if self.live_form.record {
            match self.live_form.record_path.clone() {
                Some(p) => Some(p),
                None => match rfd::FileDialog::new()
                    .set_file_name("live_session.ndjson")
                    .add_filter("NDJSON", &["ndjson"])
                    .save_file()
                {
                    Some(p) => {
                        self.live_form.record_path = Some(p.clone());
                        Some(p)
                    }
                    None => return,
                },
            }
        } else {
            None
        };
        let name = match &kind {
            live::SourceKind::TcpClient { addr } => format!("实时·TCP→{addr}"),
            live::SourceKind::TcpServer { addr } => format!("实时·TCP监听{addr}"),
            live::SourceKind::Serial { port, baud } => format!("实时·{port}@{baud}"),
            live::SourceKind::Zlg { device_type, device_index, bitrate, data_bitrate, listen_only, .. } => {
                format!("实时·ZLG {}#{} {}/{}k{}", device_type, device_index, bitrate, data_bitrate, if *listen_only { "(只听)" } else { "" })
            }
            live::SourceKind::Sim => "实时·模拟CAN".into(),
            live::SourceKind::SocketCan { iface } => format!("实时·socketcan {iface}"),
            live::SourceKind::CanHw { vendor, model, bitrate, fd, .. } => format!(
                "实时·CAN卡{} {}{}{}k{}",
                crate::canhw::vendor_name(crate::canhw::hw_vendor(*vendor)),
                model,
                if model.is_empty() { "" } else { "#" },
                bitrate / 1000,
                if *fd { "(FD)" } else { "" }
            ),
            live::SourceKind::RtuTcp { addr, gap_ms } => format!("实时·RTU-TCP {addr} gap{gap_ms}ms"),
            live::SourceKind::Replay { path } => format!(
                "回放·{}",
                path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
            ),
        };
        // 发送面板:全部 CAN 硬件源启用 hub(FR-10.4 默认锁定;此前仅 ZLG,VCI/新厂商源补齐)
        self.tx_hub = match &kind {
            live::SourceKind::Zlg { .. } | live::SourceKind::CanHw { .. } => {
                Some(std::sync::Arc::new(crate::tx::TxHub::new()))
            }
            _ => None,
        };
        // C1:首源=新会话清空累积;后续源并入(push_live_slot 内处理),不弹掉已有源
        self.live_rx = None;
        self.live_dirty = false;
        self.replay_into = None; // 并入回放随旧会话停止
        set_session_tag(&name);
        let h = live::spawn(live::LiveReq {
            kind,
            alias,
            record_path,
            tx_hub: self.tx_hub.clone(),
            tee: Some(self.fwd_slot.clone()),
        });
        let nth = self.lives.len() + 1;
        self.push_live_slot(h, &name);
        self.last_rebuild = std::time::Instant::now();
        self.status = if nth > 1 {
            format!("实时接入:第 {nth} 路「{name}」并入会话(共 {} 路源)", self.lives.len())
        } else {
            "实时接入:连接中…".into()
        };
    }

    fn disconnect_live(&mut self, note: &str) {
        self.tx_hub = None;
        self.replay_into = None; // 并入回放随之停止
        if !self.lives.is_empty() {
            // LiveHandle::drop 置 stop,线程随后自行结束;全部源断开
            self.lives.clear();
            self.live_name = self.live_names_joined();
            self.status = note.into();
        }
    }

    /// 一键启动上次现场配置(B1):源参数/录制路径/协议/规则包都随会话持久化,
    /// 第二次到现场一个按钮恢复全部接入态。上次配置是模拟器(kind=7)则一键起模拟器。
    fn quick_start_field(&mut self) {        if !self.lives.is_empty() {
            self.status = "实时源已在连接中(先「断开」再一键启动)".into();
            return;
        }
        if self.live_form.kind == 7 {
            // 上次现场用的是设备模拟器:勾录制一键起模拟器
            self.live_form.sim_record = true;
            let n_rules = self.rule_dirs.len();
            self.start_moddev();
            if !self.moddev_rts.is_empty() {
                self.status = format!(
                    "一键现场启动:模拟器 {} 个实例已运行 · 规则包 {} 个(协议 {})",
                    self.moddev_rts.len(),
                    n_rules,
                    if self.protocol_mounted() { "已挂" } else { "未挂,去步骤2" }
                );
            }
            return;
        }
        // 现场必录制:路径沿用上次;无路径时 connect_live 会现场弹保存框
        self.live_form.record = true;
        let (n_rules, proto_ok) = (self.rule_dirs.len(), self.protocol_mounted());
        self.connect_live();
        // connect_live 失败时 status 已写明缺项且 live 仍为 None;成功才补齐摘要
        if !self.lives.is_empty() {
            self.status = format!(
                "一键现场启动:已连 {} · 录制已开启 · 协议{} · 规则包 {} 个",
                live_kind_label(self.live_form.kind),
                if proto_ok { "已挂" } else { "未挂,去步骤2" },
                n_rules
            );
        }
    }

    /// 在模拟器中定位该点位(B2):帧详情右键字段 → 按点位名或寄存器地址反查运行中的模拟器,
    /// 命中即切到模拟联调场景、选实例/设备并按名过滤(列表自动滚到该行);未运行时置灰提示。
    fn locate_point_in_sim(&mut self, label: &str, fi: u32) {
        if self.moddev_rts.is_empty() {
            self.status = "模拟器未运行:先在「模拟联调」场景启动,再右键定位点位".into();
            return;
        }
        // 识别字段标签:HR/IR+十进制地址 → (addr, func);否则按点位名匹配
        let parsed = label
            .strip_prefix(['H', 'h'])
            .and_then(|s| s.strip_prefix(['R', 'r']))
            .and_then(|s| s.parse::<u16>().ok())
            .map(|a| (a, 3u8));
        let parsed = parsed.or_else(|| {
            label
                .strip_prefix(['I', 'i'])
                .and_then(|s| s.strip_prefix(['R', 'r']))
                .and_then(|s| s.parse::<u16>().ok())
                .map(|a| (a, 4u8))
        });
        let mut hit: Option<(usize, usize, &str)> = None; // (实例, 设备, 点位名)
        'outer: for (k, inst) in self.moddev_rts.iter().enumerate() {
            for (di, d) in inst.rt.devs.iter().enumerate() {
                for pt in &d.meta.points {
                    let name_hit = pt.name == label;
                    let addr_hit = parsed.map(|(a, f)| pt.addr == a && pt.func == f).unwrap_or(false);
                    // 无前缀纯数字也试地址匹配(func 3/4 都放宽)
                    let num_hit = parsed.is_none() && label.parse::<u16>().map(|a| pt.addr == a).unwrap_or(false);
                    if name_hit || addr_hit || num_hit {
                        hit = Some((k, di, pt.name.as_str()));
                        break 'outer;
                    }
                }
            }
        }
        match hit {
            Some((k, di, pt_name)) => {
                self.page = 1;
                self.scene = 3; // 模拟联调
                self.moddev_inst_idx = k;
                self.moddev_dev_idx = di;
                self.moddev_filter = pt_name.to_string();
                self.status = format!("已在模拟器中定位点位 {pt_name}(实例 {} · dev{di};右键自帧 #{fi})", self.moddev_rts[k].name);
            }
            None => {
                self.status = format!("未在运行中的模拟器找到「{label}」(按点位名/寄存器地址匹配;帧 #{fi})");
            }
        }
    }

    fn tx_panel(&mut self, ui: &mut Ui) {
        // 白名单先于连接状态:配置不依赖硬件
        ui.horizontal(|ui| {
            ui.label("白名单");
            if ui
                .add(
                    TextEdit::singleline(&mut self.tx_whitelist)
                        .hint_text("0x1A0, 0x200-0x2FF(空 = 全放行,仍需解锁)")
                        .desired_width(240.0)
                        .font(egui::TextStyle::Monospace),
                )
                .lost_focus()
            {
                match crate::tx::parse_whitelist(&self.tx_whitelist) {
                    Ok(w) => {
                        if let Some(hub) = &self.tx_hub {
                            *hub.whitelist.lock().unwrap_or_else(|e| e.into_inner()) = w;
                        }
                        self.status = "白名单已更新".into();
                    }
                    Err(e) => self.status = format!("白名单非法: {e}"),
                }
            }
        });
        let Some(hub) = self.tx_hub.clone() else {
            ui.separator();
            ui.label(egui::RichText::new("未连接 CAN 硬件 —— 发送不可用").size(12.0).color(Color32::from_rgb(235, 170, 80)));
            ui.label(
                egui::RichText::new("去【实时接入】连接硬件卡:
 · ZLG USBCANFD(下拉选型号)
 · CAN卡·VCI兼容(创芯 CANalyst-II/USBCAN)
 · CAN卡·SLCAN(CANable 等串口)
连接后回到本窗口:解锁发送 → 填 ID/数据 → 发送,或用下方回放注入")
                    .size(10.5)
                    .color(dim(ui)),
            );
            return;
        };
        ui.separator();
        if !self.tx_unlocked {
            if ui.button("🔒 解锁发送(FR-10.4 显式解锁)").clicked() {
                self.tx_unlocked = true;
                hub.enabled.store(true, std::sync::atomic::Ordering::Relaxed);
                self.status = "发送已解锁 —— 确认现场安全;白名单生效中".into();
            }
            return;
        }
        ui.horizontal(|ui| {
            if ui.button("🔓 锁定").clicked() {
                self.tx_unlocked = false;
                hub.enabled.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        });
        ui.horizontal(|ui| {
            ui.label("ID");
            ui.add(
                TextEdit::singleline(&mut self.live_form.tx_id)
                    .desired_width(70.0)
                    .font(egui::TextStyle::Monospace),
            );
            ui.checkbox(&mut self.live_form.tx_ext, "ext");
            ui.checkbox(&mut self.live_form.tx_fd, "FD");
            ui.checkbox(&mut self.live_form.tx_brs, "BRS");
            ui.label("数据");
            ui.add(
                TextEdit::singleline(&mut self.live_form.tx_data)
                    .desired_width(200.0)
                    .font(egui::TextStyle::Monospace),
            );
        });
        ui.horizontal(|ui| {
            ui.label("周期 ms(0=单次)");
            ui.add(egui::DragValue::new(&mut self.live_form.tx_interval_ms).range(0..=60000));
            if ui.button("发送").clicked() {
                let id_s = self.live_form.tx_id.trim().to_string();
                let idv = u32::from_str_radix(id_s.trim_start_matches("0x").trim_start_matches("0X"), 16)
                    .or_else(|_| id_s.parse::<u32>())
                    .ok();
                match (idv, crate::tx::parse_data_hex(&self.live_form.tx_data)) {
                    (Some(id), Some(data)) if !data.is_empty() => {
                        let e = crate::tx::SendEntry {
                            id,
                            ext: self.live_form.tx_ext,
                            fd: self.live_form.tx_fd,
                            brs: self.live_form.tx_brs && self.live_form.tx_fd,
                            data,
                            interval_ms: (self.live_form.tx_interval_ms > 0)
                                .then_some(self.live_form.tx_interval_ms as u64),
                            last: None,
                        };
                        match hub.enqueue(e) {
                            Ok(_) => self.status = "已入队发送".into(),
                            Err(e2) => self.status = format!("拒绝: {e2}"),
                        }
                    }
                    (Some(_), None) => self.status = "数据格式:十六进制字节(如 01 02 3F)".into(),
                    _ => self.status = "ID 非法(如 0x1A0 或 416)".into(),
                }
            }
            if hub.pending() > 0 {
                ui.label(egui::RichText::new(format!("队列 {}", hub.pending())).size(10.5));
            }
            if ui.small_button("清空队列").clicked() {
                hub.clear();
            }
        });

        // ---- 回放注入(P2):录制抓包 → 按时间轴发往真实总线 ----
        ui.separator();
        ui.label(egui::RichText::new("回放注入(把录制的报文按时间轴发到总线)").size(11.0));
        ui.horizontal(|ui| {
            if ui.small_button("选择录制文件…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("录制与抓包", &["ndjson", "jsonl", "asc", "log", "pcap", "pcapng"])
                    .pick_file()
                {
                    match load_injection_preview(&p, &self.tx_whitelist) {
                        Ok(prev) => {
                            self.status = format!(
                                "注入预览: {} 帧 / {:.2}s / 越界剔除 {}",
                                prev.frames.len(),
                                prev.duration_s,
                                prev.out_of_wl
                            );
                            self.inj_preview = Some(prev);
                            self.inj_path = Some(p);
                        }
                        Err(e) => self.status = format!("读取注入文件失败: {e}"),
                    }
                }
            }
            if let Some(p) = &self.inj_path {
                ui.label(
                    egui::RichText::new(p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default())
                        .size(10.5)
                        .monospace()
                        .color(dim(ui)),
                );
            }
        });
        if let Some(prev) = &self.inj_preview {
            ui.label(
                egui::RichText::new(format!(
                    "可注入 {} 帧(越界已剔除 {}) · 时长 {:.2}s · 白名单: {}",
                    prev.frames.len(),
                    prev.out_of_wl,
                    prev.duration_s,
                    if self.tx_whitelist.trim().is_empty() { "未配置(全放行)" } else { self.tx_whitelist.trim() }
                ))
                .size(10.0)
                .color(dim(ui)),
            );
            ui.horizontal(|ui| {
                ui.label("速度");
                const SPEEDS: [&str; 4] = ["原速 ×1", "×5", "×20", "极速"];
                for (i, name) in SPEEDS.iter().enumerate() {
                    if ui.selectable_label(self.inj_speed_idx == i, *name).clicked() {
                        self.inj_speed_idx = i;
                    }
                }
                let running = self.inj_handle.as_ref().map(|h| h.progress().0 < h.total).unwrap_or(false);
                if running {
                    if ui.button("■ 急停").clicked() {
                        if let Some(h) = self.inj_handle.take() {
                            h.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        self.status = "回放注入已急停".into();
                    }
                } else if ui
                    .add_enabled(
                        self.tx_unlocked,
                        egui::Button::new("▶ 开始注入"),
                    )
                    .clicked()
                {
                    let speed = [1.0f64, 5.0, 20.0, 0.0][self.inj_speed_idx];
                    let frames = self.inj_preview.as_ref().unwrap().frames.clone();
                    let h = crate::tx::spawn_injection(frames, speed, hub.clone());
                    self.inj_handle = Some(h);
                    self.status = format!("注入中({})…急停随时可用", SPEEDS[self.inj_speed_idx]);
                }
                if !self.tx_unlocked {
                    ui.label(egui::RichText::new("需先解锁发送").size(10.0).color(dim(ui)));
                }
            });
            if let Some(h) = &self.inj_handle {
                let (sent, skipped, total) = h.progress();
                ui.label(
                    egui::RichText::new(format!("进度 {sent}/{total}(队列拒绝 {skipped})"))
                        .size(10.0)
                        .color(dim(ui)),
                );
            }
        }
        let rej = hub.rejected.load(std::sync::atomic::Ordering::Relaxed);
        if rej > 0 {
            ui.label(
                egui::RichText::new(format!("白名单已拒绝 {rej} 次越界发送"))
                    .size(10.5)
                    .color(Color32::from_rgb(255, 120, 80)),
            );
        }
        ui.separator();
    }

    /// 实时源表单分块渲染(向导一屏只露必填;全部配置=全块)。位掩码:
    /// 1=源类型下拉 2=源参数 4=会话录制 8=状态行 16=连接/断开 32=模拟器控制面板(kind=7)
    fn live_form_parts(&mut self, ui: &mut Ui, parts: u8) {
            ui.label(
                egui::RichText::new(
                    "接入 serbox 的 NDJSON 帧流(frame.schema.json),记录进入现有解析/曲线/事件管线。",
                )
                .size(11.0)
                .color(dim(ui)),
            );
            ui.add_space(4.0);
            if parts & 1 != 0 {
            // 源类型:分类下拉(不再一排铺开;默认=回放文件导入)
            ui.horizontal(|ui| {
                ui.label("源类型");
                egui::ComboBox::from_id_salt("live_kind_sel")
                    .selected_text(live_kind_label(self.live_form.kind))
                    .width(190.0)
                    .show_ui(ui, |ui| {
                        ui.set_min_width(215.0);
                        live_kind_group(ui, "文件");
                        live_kind_item(ui, &mut self.live_form.kind, 3, "回放");
                        live_kind_group(ui, "网络");
                        live_kind_item(ui, &mut self.live_form.kind, 0, "TCP 客户端");
                        live_kind_item(ui, &mut self.live_form.kind, 1, "TCP 服务端");
                        live_kind_item(ui, &mut self.live_form.kind, 6, "Modbus RTU(TCP)");
                            live_kind_group(ui, "串口 / CAN 卡");
                            live_kind_item(ui, &mut self.live_form.kind, 2, "串口(COM)");
                            live_kind_item(ui, &mut self.live_form.kind, 4, "ZLG USBCANFD");
                            live_kind_item(ui, &mut self.live_form.kind, 8, "CAN卡·VCI兼容");
                            live_kind_item(ui, &mut self.live_form.kind, 9, "CAN卡·SLCAN");
                            live_kind_item(ui, &mut self.live_form.kind, 11, "CAN卡·PEAK");
                            live_kind_item(ui, &mut self.live_form.kind, 12, "CAN卡·Kvaser");
                            live_kind_item(ui, &mut self.live_form.kind, 13, "CAN卡·GCAN");
                        #[cfg(target_os = "linux")]
                        live_kind_item(ui, &mut self.live_form.kind, 10, "SocketCAN vcan");
                            live_kind_group(ui, "模拟");
                            live_kind_item(ui, &mut self.live_form.kind, 5, "模拟 CAN(开发演示)");
                            live_kind_item(ui, &mut self.live_form.kind, 7, "设备模拟器");
                    });
            });
            }
            ui.add_space(2.0);
            if parts & 2 != 0 {
            match self.live_form.kind {
                7 => {
                    ui.label(
                        egui::RichText::new("本机扮演 Modbus 从机(点位表驱动):开端口供 HMI/EMS 来读写,请求/响应同屏进解析管线。")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("选择点位表 .yaml…").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("点位表 YAML", &["yaml", "yml"])
                                .pick_file()
                            {
                                self.live_form.moddev_yaml = Some(p);
                            }
                        }
                        if let Some(p) = &self.live_form.moddev_yaml {
                            ui.label(
                                egui::RichText::new(p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default())
                                    .size(10.5)
                                    .monospace()
                                    .color(dim(ui)),
                            );
                        }
                    });
                    if self.live_form.moddev_yaml.is_none() {
                        let p = PathBuf::from("D:/dev/mbdev_points.yaml");
                        if p.exists() && ui.small_button("用 D:/dev/mbdev_points.yaml").clicked() {
                            self.live_form.moddev_yaml = Some(p);
                        }
                    }
                    ui.add_space(4.0);
                    // 独立启停:不经过下方「连接」;运行中面板/曲线照常工作;多实例各自停止(A3)
                    let mut stop_i: Option<usize> = None;
                    if !self.moddev_rts.is_empty() {
                        for (i, inst) in self.moddev_rts.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("● {}", inst.label()))
                                        .size(10.5)
                                        .monospace()
                                        .color(Color32::from_rgb(120, 200, 130)),
                                );
                                if ui.small_button("⏹ 停止").clicked() {
                                    stop_i = Some(i);
                                }
                            });
                        }
                    }
                    if let Some(i) = stop_i {
                        let inst = self.moddev_rts.remove(i);
                        inst.rt.stop_all();
                        self.moddev_inst_idx = self.moddev_inst_idx.min(self.moddev_rts.len().saturating_sub(1));
                        self.status = format!("模拟器实例 {} 已停止(端口关闭)", inst.name);
                    }
                    if self.live_form.moddev_yaml.is_some() {
                        if ui.button("▶ 启动模拟器(开端口)").clicked() {
                            self.start_moddev();
                        }
                    }
                }
                8 => {
                    // VCI 兼容卡(创芯 CANalyst-II / USBCAN1/2 及兼容):ControlCAN.dll
                    ui.label(
                        egui::RichText::new("ControlCAN.dll 兼容卡 —— 32 位老 DLL 自动经 vci-bridge.exe 桥接")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    ui.horizontal(|ui| {
                        ui.label("型号");
                        egui::ComboBox::from_id_salt("hw_vci_model")
                            .selected_text(self.live_form.hw_model.clone())
                            .show_ui(ui, |ui| {
                                for m in ["USBCAN1", "USBCAN2", "CANalyst-II"] {
                                    ui.selectable_value(&mut self.live_form.hw_model, m.to_string(), m);
                                }
                            });
                        ui.label("序号");
                        ui.add(egui::DragValue::new(&mut self.live_form.device_index).range(0..=8));
                        ui.label("通道");
                        ui.add(egui::DragValue::new(&mut self.live_form.channels).range(1..=2));
                    });
                    ui.horizontal(|ui| {
                        ui.label("波特率");
                        egui::ComboBox::from_id_salt("hw_vci_baud")
                            .selected_text(format!("{} kbps", self.live_form.hw_baud / 1000))
                            .show_ui(ui, |ui| {
                                for b in [10_000u32, 20_000, 50_000, 100_000, 125_000, 200_000, 250_000, 400_000, 500_000, 800_000, 1_000_000] {
                                    ui.selectable_value(&mut self.live_form.hw_baud, b, format!("{} kbps", b / 1000));
                                }
                            });
                        ui.checkbox(&mut self.live_form.hw_listen_only, "只听");
                    });
                    {
                        let st = crate::canhw::vci_dll_state();
                        let col = if st.starts_with("就绪") {
                            Color32::from_rgb(120, 200, 130)
                        } else if st.starts_with("未找到") {
                            dim(ui)
                        } else {
                            Color32::from_rgb(235, 120, 100)
                        };
                        ui.label(egui::RichText::new(st).size(10.0).monospace().color(col));
                    }
                }
                9 => {
                    // SLCAN 串口(CANable 等):零 DLL
                    ui.horizontal(|ui| {
                        ui.label("COM 口");
                        ui.add(
                            TextEdit::singleline(&mut self.live_form.port_name)
                                .hint_text("COM3")
                                .desired_width(100.0)
                                .font(egui::TextStyle::Monospace),
                        );
                        if ui.small_button("扫描").clicked() {
                            self.live_form.ports = live::available_ports();
                            if let Some(p) = self.live_form.ports.first() {
                                self.live_form.port_name = p.clone();
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("CAN 波特率");
                        egui::ComboBox::from_id_salt("hw_slcan_baud")
                            .selected_text(format!("{} kbps", self.live_form.hw_baud / 1000))
                            .show_ui(ui, |ui| {
                                for b in [10_000u32, 20_000, 50_000, 100_000, 125_000, 250_000, 500_000, 800_000, 1_000_000] {
                                    ui.selectable_value(&mut self.live_form.hw_baud, b, format!("{} kbps", b / 1000));
                                }
                            });
                    });
                    ui.label(egui::RichText::new("经典 Lawicel 协议(S0~S8),串口 115200;不支持 CAN FD").size(10.0).color(dim(ui)));
                }
                11 => {
                    // PEAK PCAN-Basic(第二批 ADR-0014)
                    ui.label(
                        egui::RichText::new("PEAK PCAN-Basic(PCANBasic.dll;USB 通道号 1=USBBUS1;支持 CAN FD)。未经真机 bench,连接异常时看状态栏与 stderr")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    let st = crate::peak::dll_state();
                    self.hw_vendor_rows(ui, st, true, 16);
                }
                12 => {
                    // Kvaser CANlib(第二批 ADR-0014)
                    ui.label(
                        egui::RichText::new("Kvaser CANlib(canlib32.dll;装驱动后随系统加载;通道号 0 起,接受 Virtual CAN 可无硬件演示)。SDK 包内副本为 32 位,64 位程序需装驱动")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    let st = crate::kvaser::dll_state();
                    self.hw_vendor_rows(ui, st, true, 63);
                }
                13 => {
                    // GCAN ECanVci(第二批 ADR-0014)
                    ui.label(
                        egui::RichText::new("GCAN ECanVci(ECanVci[64].dll;DeviceType 按厂商手册填数字,例程 16;经典 CAN 不支持 FD)。时戳为软件时戳(TimeStamp 口径未文档化)")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    ui.horizontal(|ui| {
                        ui.label("DeviceType");
                        ui.add(
                            TextEdit::singleline(&mut self.live_form.hw_model)
                                .desired_width(60.0)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.label("序号");
                        ui.add(egui::DragValue::new(&mut self.live_form.device_index).range(0..=8));
                        ui.label("通道");
                        ui.add(egui::DragValue::new(&mut self.live_form.channels).range(1..=2));
                    });
                    ui.horizontal(|ui| {
                        ui.label("波特率");
                        egui::ComboBox::from_id_salt("hw_gcan_baud")
                            .selected_text(format!("{} kbps", self.live_form.hw_baud / 1000))
                            .show_ui(ui, |ui| {
                                for b in [10_000u32, 20_000, 50_000, 100_000, 125_000, 250_000, 500_000, 800_000, 1_000_000] {
                                    ui.selectable_value(&mut self.live_form.hw_baud, b, format!("{} kbps", b / 1000));
                                }
                            });
                        ui.checkbox(&mut self.live_form.hw_listen_only, "只听");
                    });
                    self.dll_state_label(ui, crate::ecanvci::dll_state());
                }
                #[cfg(target_os = "linux")]
                10 => {
                    ui.label(
                        egui::RichText::new("Linux SocketCAN 虚拟口(ip link add dev vcan0 type vcan 先建口);与 candump/cansend/python-can 全互操作。")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    ui.horizontal(|ui| {
                        ui.label("接口名");
                        ui.add(
                            TextEdit::singleline(&mut self.live_form.port_name)
                                .hint_text("vcan0")
                                .desired_width(100.0)
                                .font(egui::TextStyle::Monospace),
                        );
                    });
                }
                0 | 1 => {
                    let hint = if self.live_form.kind == 0 { "192.168.4.1:9000" } else { "0.0.0.0:9000" };
                    ui.horizontal(|ui| {
                        let label = if self.live_form.kind == 0 { "地址" } else { "监听" };
                        ui.label(label);
                        ui.add(
                            TextEdit::singleline(&mut self.live_form.addr)
                                .hint_text(hint)
                                .desired_width(200.0)
                                .font(egui::TextStyle::Monospace),
                        );
                    });
                }
                2 => {
                    ui.horizontal(|ui| {
                        ui.label("COM 口");
                        ui.add(
                            TextEdit::singleline(&mut self.live_form.port_name)
                                .hint_text("COM3")
                                .desired_width(100.0)
                                .font(egui::TextStyle::Monospace),
                        );
                        if ui.small_button("扫描").clicked() {
                            self.live_form.ports = live::available_ports();
                            if let Some(p) = self.live_form.ports.first() {
                                self.live_form.port_name = p.clone();
                            }
                        }
                        if !self.live_form.ports.is_empty() {
                            ui.label(
                                egui::RichText::new(format!("找到 {} 个", self.live_form.ports.len()))
                                    .size(10.5)
                                    .color(dim(ui)),
                            );
                        }
                    });
                    if !self.live_form.ports.is_empty() {
                        ui.horizontal(|ui| {
                            for name in &self.live_form.ports {
                                let on = self.live_form.port_name == *name;
                                if ui.selectable_label(on, name).clicked() {
                                    self.live_form.port_name = name.clone();
                                }
                            }
                        });
                    }
                    ui.horizontal(|ui| {
                        ui.label("波特率");
                        ui.add(
                            egui::Slider::new(&mut self.live_form.baud, 1200..=4_000_000)
                                .logarithmic(true)
                                .text("bps"),
                        );
                    });
                }
                4 => {
                    // Q3 选型:ZLG USBCANFD 系列(下拉选择,自定义值仍可手填)
                    ui.horizontal(|ui| {
                        ui.label("设备类型");
                        egui::ComboBox::from_id_salt("hw_zlg_model")
                            .selected_text(self.live_form.device_type.clone())
                            .show_ui(ui, |ui| {
                                for m in ["USBCANFD-200U", "USBCANFD-100U", "USBCANFD-800U", "USBCANFD-MINI", "USBCAN-II"] {
                                    ui.selectable_value(&mut self.live_form.device_type, m.to_string(), m);
                                }
                            });
                        ui.label("序号");
                        ui.add(egui::DragValue::new(&mut self.live_form.device_index).range(0..=8));
                    });
                    ui.horizontal(|ui| {
                        ui.label("通道数");
                        ui.add(egui::DragValue::new(&mut self.live_form.channels).range(1..=2));
                        ui.label("波特率 kbps");
                        ui.add(egui::DragValue::new(&mut self.live_form.baud_k).range(5..=1000));
                        ui.label("数据段 kbps");
                        ui.add(egui::DragValue::new(&mut self.live_form.data_baud_k).range(5..=5000));
                    });
                    ui.horizontal(|ui| {
                        ui.label("时戳单位");
                        const UNITS: [&str; 3] = ["0.1ms", "10µs", "1µs"];
                        for (i2, name) in UNITS.iter().enumerate() {
                            if ui.selectable_label(self.live_form.ts_unit == i2, *name).clicked() {
                                self.live_form.ts_unit = i2;
                            }
                        }
                        if ui.checkbox(&mut self.live_form.listen_only, "只听(不干扰现场)").changed() {}
                    });
                    ui.label(
                        egui::RichText::new("需安装 ZLG 驱动(zlgcan.dll 在程序目录或 PATH);硬件时戳单位在真机上核对")
                            .size(10.0)
                            .color(dim(ui)),
                    );
                }
                5 => {
                    ui.label(
                        egui::RichText::new(
                            "开发/演示专用(不用于联调):0x1A0 速度/扭矩/温度曲线(motor.dbc 同源)+ 心跳 + 64B CAN FD 帧的内置曲线,用于验证界面与解析链路。真实联调用「设备模拟器」(Modbus 供数)或「CAN卡·SLCAN」(CANable 即虚拟 CAN 口)。",
                        )
                        .size(10.5)
                        .color(dim(ui)),
                    );
                }
                6 => {
                    ui.horizontal(|ui| {
                        ui.label("服务器地址");
                        ui.add(
                            TextEdit::singleline(&mut self.live_form.addr)
                                .hint_text("192.168.0.7:8899")
                                .desired_width(200.0)
                                .font(egui::TextStyle::Monospace),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label("RTU 静默间隙");
                        ui.add(
                            egui::Slider::new(&mut self.live_form.rtu_gap_ms, 5..=200)
                                .text("ms")
                                .logarithmic(true),
                        );
                    });
                    ui.label(
                        egui::RichText::new(
                            "串口服务器把 485 透传成 TCP 裸字节:按字节间隙+CRC16 定帧,帧以 uart/L0 契约入管线(监听无方向)。",
                        )
                        .size(10.0)
                        .color(dim(ui)),
                    );
                }
                _ => {
                    ui.horizontal(|ui| {
                        if ui.button("选择回放文件…").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("录制与抓包", &["ndjson", "jsonl", "asc"])
                                .add_filter("CANalyzer ASC", &["asc"])
                                .add_filter("NDJSON", &["ndjson", "jsonl"])
                                .add_filter("全部", &["*"])
                                .pick_file()
                            {
                                self.live_form.replay_path = Some(p);
                            }
                        }
                        if let Some(p) = &self.live_form.replay_path {
                            ui.label(
                                egui::RichText::new(p.display().to_string())
                                    .size(10.5)
                                    .monospace()
                                    .color(dim(ui)),
                            );
                        }
                    });
                    if self.live_form.kind == 3 {
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            ui.label("导入方式");
                            if ui.selectable_label(!self.live_form.replay_merge, "独立回放").clicked() {
                                self.live_form.replay_merge = false;
                            }
                            if ui.selectable_label(self.live_form.replay_merge, "并入当前实时(模拟现场)").clicked() {
                                self.live_form.replay_merge = true;
                            }
                        });
                        if self.live_form.replay_merge {
                            if !self.lives.is_empty() && !self.live_labels.is_empty() {
                                let chans: Vec<(u16, String)> = {
                                    let mut v: Vec<_> = self.live_labels.iter().map(|(c, n)| (*c, n.clone())).collect();
                                    v.sort_by_key(|x| x.0);
                                    v
                                };
                                let cur = chans
                                    .iter()
                                    .find(|(c, _)| *c == self.live_form.replay_target_ch)
                                    .map(|(_, n)| n.clone())
                                    .unwrap_or_else(|| format!("ch{}", self.live_form.replay_target_ch));
                                ui.horizontal(|ui| {
                                    ui.label("导入到设备");
                                    egui::ComboBox::from_id_salt("replay_target_ch")
                                        .selected_text(format!("ch{} · {}", self.live_form.replay_target_ch, cur))
                                        .show_ui(ui, |ui| {
                                            ui.set_min_width(200.0);
                                            for (c, name) in &chans {
                                                if ui.selectable_label(self.live_form.replay_target_ch == *c, format!("ch{c} · {name}")).clicked() {
                                                    self.live_form.replay_target_ch = *c;
                                                }
                                            }
                                        });
                                });
                                ui.horizontal(|ui| {
                                    ui.label("速度");
                                    const SPEEDS: [&str; 4] = ["原速 ×1", "×5", "×20", "极速"];
                                    for (i2, name) in SPEEDS.iter().enumerate() {
                                        if ui.selectable_label(self.live_form.replay_speed_idx == i2, *name).clicked() {
                                            self.live_form.replay_speed_idx = i2;
                                        }
                                    }
                                });
                                ui.horizontal(|ui| {
                                    let running = self.replay_into.is_some();
                                    let ready = !self.lives.is_empty() && self.live_form.replay_path.is_some();
                                    if ui.add_enabled(!running && ready, egui::Button::new("▶ 并入实时")).clicked() {
                                        self.start_replay_into();
                                    }
                                    if ui.add_enabled(running, egui::Button::new("⏹ 停止并入")).clicked() {
                                        self.replay_into = None; // Drop 置 stop,线程随后退出
                                        self.status = "正在停止并入回放…".into();
                                    }
                                    if running {
                                        ui.label(egui::RichText::new("并入运行中…").size(10.0).color(Color32::from_rgb(140, 200, 110)));
                                    }
                                });
                            } else {
                                ui.label(
                                    egui::RichText::new("并入需先连接一个实时源(下方「连接」);连接后此处列出其设备通道。")
                                        .size(10.0)
                                        .color(dim(ui)),
                                );
                            }
                        } else {
                            ui.label(
                                egui::RichText::new("独立回放=按文件自身时间轴整段重放;「并入当前实时」把文件映射成某台设备的实时流量(模拟现场)。")
                                    .size(10.0)
                                    .color(dim(ui)),
                            );
                        }
                    }
                }
            }
            ui.horizontal(|ui| {
                ui.label("通道别名");
                ui.add(
                    TextEdit::singleline(&mut self.live_form.alias)
                        .hint_text("可选;帧内无 alias 的通道显示为「别名·默认名」")
                        .desired_width(260.0),
                );
            });
            }
            if parts & 4 != 0 {
            ui.add_space(2.0);
            // FR-S2 会话录制
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.live_form.record, "会话录制(原始 NDJSON 落盘)");
                if self.live_form.record {
                    if ui.small_button("选择文件…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_file_name("live_session.ndjson")
                            .add_filter("NDJSON", &["ndjson"])
                            .save_file()
                        {
                            self.live_form.record_path = Some(p);
                        }
                    }
                    if let Some(p) = &self.live_form.record_path {
                        ui.label(
                            egui::RichText::new(p.display().to_string())
                                .size(10.0)
                                .monospace()
                                .color(dim(ui)),
                        );
                    }
                }
            });
            ui.add_space(4.0);
            ui.separator();
            }
            if parts & 8 != 0 {
            // 状态行
            if !self.lives.is_empty() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        egui::RichText::new(format!(
                            "接收中:{} 帧 · 坏行 {} · 丢帧 {}",
                            self.live_stats.ok, self.live_stats.bad, self.live_stats.gaps
                        ))
                        .size(11.5)
                        .color(Color32::from_rgb(140, 200, 110)),
                    );
                });
                if self.live_form.record {
                    if let Some(p) = &self.live_form.record_path {
                        ui.label(
                            egui::RichText::new(format!("录制中 → {}", p.display()))
                                .size(10.5)
                                .color(Color32::from_rgb(235, 200, 90)),
                        );
                    }
                }
            } else {
                ui.label(egui::RichText::new("未连接").size(11.5).color(dim(ui)));
            }
            if let Some(w) = self.live_warns.last() {
                ui.label(
                    egui::RichText::new(format!("最近告警:{w}"))
                        .size(10.0)
                        .color(Color32::from_rgb(220, 150, 90)),
                );
            }
            ui.add_space(4.0);
            ui.separator();
            }
            if parts & 16 != 0 {
            ui.horizontal(|ui| {
                let connected = !self.lives.is_empty();
                if ui.add_enabled(!connected, egui::Button::new("连接")).clicked() {
                    self.connect_live();
                }
                if ui.add_enabled(connected, egui::Button::new("断开")).clicked() {
                    self.disconnect_live("已断开实时接入");
                }
            });
            }

            // ---- 设备模拟器控制面板(kind=7 且运行中;A3 多实例:实例下拉选择) ----
            if parts & 32 != 0 {
            if self.live_form.kind == 7 {
                let inst_i = self.moddev_inst_idx.min(self.moddev_rts.len().saturating_sub(1));
                let rt = self.moddev_rts.get(inst_i).map(|i| i.rt.clone());
                if let Some(rt) = rt {
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("模拟器控制").size(11.5).color(Color32::from_rgb(140, 200, 110)));
                        if self.moddev_rts.len() > 1 {
                            ui.label("实例");
                            egui::ComboBox::from_id_salt("moddev_inst")
                                .selected_text(self.moddev_rts[inst_i].label())
                                .show_ui(ui, |ui| {
                                    for (i, inst) in self.moddev_rts.iter().enumerate() {
                                        ui.selectable_value(&mut self.moddev_inst_idx, i, inst.label());
                                    }
                                });
                        }
                    });
                    // 设备端口状态
                    for (i, d) in rt.devs.iter().enumerate() {
                        ui.horizontal(|ui| {
                            let st = if d.port_bound { "●" } else { "✕" };
                            let col = if d.port_bound { Color32::from_rgb(120, 200, 130) } else { Color32::from_rgb(220, 120, 100) };
                            ui.label(egui::RichText::new(st).color(col).size(11.0));
                            let port_txt = if d.port_bound {
                                format!("dev{} {} {}", d.meta.id, d.meta.name, d.endpoint())
                            } else {
                                format!("dev{} {} :{}(端口未绑定)", d.meta.id, d.meta.name, d.meta.port)
                            };
                            ui.label(egui::RichText::new(port_txt).size(11.0).monospace());
                            ui.label(egui::RichText::new(format!("{}点", d.meta.points.len())).size(10.0).color(dim(ui)));
                            if let Ok(lt) = d.last_req.lock() {
                                if let Some(t) = *lt {
                                    ui.label(egui::RichText::new(format!("最近请求 {:.1}s 前", t.elapsed().as_secs_f32())).size(10.0).color(dim(ui)));
                                } else {
                                    ui.label(egui::RichText::new("无请求").size(10.0).color(dim(ui)));
                                }
                            }
                            let _ = i;
                        });
                    }
                    // 场景切换
                    ui.horizontal(|ui| {
                        ui.label("场景");
                        let sc = { *rt.scene.lock().unwrap_or_else(|e| e.into_inner()) };
                        for (sc_i, label) in [
                            (crate::moddev::Scene::Normal, "Normal 静止"),
                            (crate::moddev::Scene::Random, "Random 随机扰动"),
                            (crate::moddev::Scene::Fault, "Fault 故障注入"),
                        ] {
                            if ui.selectable_label(sc == sc_i, label).clicked() {
                                *rt.scene.lock().unwrap_or_else(|e| e.into_inner()) = sc_i;
                                self.status = format!("模拟器场景 → {label}");
                            }
                        }
                    });
                    // 点位搜索 + 行内改值(完整表格/过滤/临时点在「点位编辑」窗口)
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut self.moddev_filter)
                                .hint_text("搜索点位名/分组…")
                                .desired_width(140.0)
                                .font(egui::TextStyle::Small),
                        );
                        if ui
                            .small_button("⛶ 点位编辑…")
                            .on_hover_text("宽表格:全部点位值就地修改(枚举下拉/位开关/数值拖拽/字符串)、过滤、分组折叠、「主机读到」列、临时点、回写点位表")
                            .clicked()
                        {
                            self.show_ptedit = true;
                        }
                    });
                    let dev_i = self.moddev_dev_idx.min(rt.devs.len().saturating_sub(1));
                    // 采样一拍(500ms 节流):sparkline/最近 min·max 列的数据源(卡片可见时推进)
                    if let Some(d) = rt.devs.get(dev_i) {
                        d.sample_if_due();
                    }
                    let rows = rt.points_view(dev_i, &self.moddev_filter);
                    egui::ScrollArea::vertical()
                        .id_salt("moddev_points")
                        .max_height(220.0)
                        .show(ui, |ui| {
                            for r in rows.iter().take(300) {
                                let stats = rt.devs.get(dev_i).and_then(|d| d.point_stats(&r.name));
                                ui.horizontal(|ui| {
                                    // 名(📌 已置 = 琥珀色)
                                    ui.add_sized(
                                        [112.0, 17.0],
                                        egui::Label::new(
                                            egui::RichText::new(r.name.as_str())
                                                .size(10.5)
                                                .monospace()
                                                .color(if r.pinned { Color32::from_rgb(235, 200, 90) } else { txt(ui) }),
                                        )
                                        .truncate(),
                                    );
                                    // 值(类型自适应控件;改即写入并钉住)
                                    if let Some(msg) = Self::ptedit_value_ui(ui, &rt, dev_i, r) {
                                        self.status = msg;
                                    }
                                    // 近拍范围 + sparkline
                                    match &stats {
                                        Some((mn, mx, _cur, series)) => {
                                            ui.label(
                                                egui::RichText::new(format!("{mn:.3}~{mx:.3}"))
                                                    .size(9.0)
                                                    .monospace()
                                                    .color(dim(ui)),
                                            );
                                            spark(ui, series, *mn, *mx);
                                        }
                                        None => {
                                            ui.label(egui::RichText::new("(采样中…)").size(9.0).color(dim(ui)));
                                        }
                                    }
                                    if !r.rw {
                                        ui.label(egui::RichText::new("🔒").size(9.5))
                                            .on_hover_text("点位表未声明 rw:1 → 主机不可写(模拟器侧仍可改,那是\"设定被测量\")");
                                    }
                                    // 主机读到:绿点 + 次数(真实主机;自轮询不算)
                                    match r.host {
                                        Some((_, n, _)) => {
                                            ui.label(
                                                egui::RichText::new(format!("●主机×{n}"))
                                                    .size(9.0)
                                                    .color(Color32::from_rgb(120, 200, 130)),
                                            );
                                        }
                                        None => {
                                            ui.label(egui::RichText::new("○").size(9.0).color(dim(ui)))
                                                .on_hover_text("主机还没读过这个点");
                                        }
                                    }
                                    if r.pinned && ui.small_button("释放").clicked() {
                                        rt.release_point(dev_i, &r.name);
                                        self.status = format!("已释放 {}(回到场景驱动)", r.name);
                                    }
                                });
                            }
                        });
                    if rows.is_empty() {
                        ui.label(egui::RichText::new("(无匹配点位)").size(10.5).color(dim(ui)));
                    }
                }
            }
            }
    }

    /// PEAK / Kvaser 共用表单行:通道号 + 波特率 + 只听 + FD(可选)+ DLL 状态
    fn hw_vendor_rows(&mut self, ui: &mut Ui, dll_state: String, fd_supported: bool, index_max: u32) {
        ui.horizontal(|ui| {
            ui.label("通道号");
            ui.add(egui::DragValue::new(&mut self.live_form.device_index).range(0..=index_max));
            ui.label("波特率");
            egui::ComboBox::from_id_salt("hw_vendor_baud")
                .selected_text(format!("{} kbps", self.live_form.hw_baud / 1000))
                .show_ui(ui, |ui| {
                    for b in [10_000u32, 20_000, 50_000, 100_000, 125_000, 250_000, 500_000, 800_000, 1_000_000] {
                        ui.selectable_value(&mut self.live_form.hw_baud, b, format!("{} kbps", b / 1000));
                    }
                });
            ui.checkbox(&mut self.live_form.hw_listen_only, "只听");
            if fd_supported {
                ui.checkbox(&mut self.live_form.hw_fd, "FD");
            }
        });
        self.dll_state_label(ui, dll_state);
    }

    /// 厂商 DLL 状态行(绿=就绪,灰=未找到,红=异常)
    fn dll_state_label(&self, ui: &mut Ui, st: String) {
        let col = if st.starts_with("就绪") {
            Color32::from_rgb(120, 200, 130)
        } else if st.starts_with("未找到") {
            dim(ui)
        } else {
            Color32::from_rgb(235, 120, 100)
        };
        ui.label(egui::RichText::new(st).size(10.0).monospace().color(col));
    }

    fn rebuild_shown(&mut self) {
        let Some(ds) = self.ds.as_ref() else { return };
        let f = self.filter.trim().to_lowercase();
        let mut v: Vec<u32> = ds
            .frames
            .iter()
            .enumerate()
            .filter(|(_, fr)| {
                let proto_ok = self.proto_filter.get(&fr.proto).copied().unwrap_or(true);
                let text_ok = f.is_empty()
                    || fr.summary.to_lowercase().contains(&f)
                    || fr.proto.label().to_lowercase().contains(&f)
                    || ds.channel_label(fr.source, fr.channel).to_lowercase().contains(&f);
                proto_ok && text_ok
            })
            .map(|(i, _)| i as u32)
            .collect();
        // 排序
        match self.sort.0 {
            views::SortKey::Idx => {}
            views::SortKey::Time => v.sort_by_key(|&i| ds.frames[i as usize].t_ns),
            views::SortKey::Dt => v.sort_by(|&a, &b| self.dt_cache[a as usize].total_cmp(&self.dt_cache[b as usize])),
            views::SortKey::Dir => v.sort_by_key(|&i| ds.frames[i as usize].dir),
            views::SortKey::Proto => v.sort_by_key(|&i| ds.frames[i as usize].proto),
            views::SortKey::Chan => v.sort_by_key(|&i| (ds.frames[i as usize].source, ds.frames[i as usize].channel)),
            views::SortKey::Len => v.sort_by_key(|&i| ds.frames[i as usize].len),
        }
        if self.sort.1 {
            v.reverse();
        }
        self.shown = v;
    }

    /// 详情解码:存储树优先,懒解码通道按需解码并缓存
    fn resolve_decoded(&mut self, fi: u32) -> Option<Arc<iotprobe_core::model::Decoded>> {
        let ds = self.ds.clone()?;
        if let Some(d) = ds.decoded.get(fi as usize).and_then(|o| o.clone()) {
            return Some(d);
        }
        if let Some(d) = self.dec_cache.get(&fi) {
            return Some(d.clone());
        }
        let d = Arc::new(iotprobe_core::dissect::decode_one(&ds, fi as usize)?);
        if self.dec_cache.len() > 1024 {
            self.dec_cache.clear();
        }
        self.dec_cache.insert(fi, d.clone());
        Some(d)
    }

    fn save_session(&self) {
        let Some(sess) = self.ds.as_ref().map(|_| ()) else { return };
        let _ = sess;
        let s = Session {
            files: self.last_files.clone(),
            custom_paths: self.custom_paths.clone(),
            dbc: self.dbc_path.clone(),
            dbcs: self.dbc_paths.clone(),
            map: self.map_path.clone(),
            map104: self.map104_path.clone(),
            topo: self.topo_path.clone(),
            inline_specs: self.inline_specs.clone(),
            rule_dirs: self.rule_dirs.clone(),
            sig_sel: self.sig_sel.iter().cloned().collect(),
            fav_sigs: self.fav_sigs.iter().cloned().collect(),
            color_ov: self.color_ov.clone(),
            dark: self.dark,
            gap_ms: self.gap_ms,
            filter: self.filter.clone(),
            scene: self.scene,
        };
        if let Ok(json) = serde_json::to_string_pretty(&s) {
            let path = session_path();
            if std::fs::write(&path, &json).is_err() {
                let _ = std::fs::write("./iotprobe_session.json", &json);
            }
        }
    }

    fn open_files(&mut self) {
        if let Some(files) = rfd::FileDialog::new()
            .add_filter("日志与抓包", &["log", "txt", "csv", "pcap", "cap", "pcapng", "asc", "ndjson", "jsonl"])
            .add_filter("CANalyzer ASC", &["asc"])
            .add_filter("全部", &["*"])
            .pick_files()
        {
            let name = files
                .iter()
                .filter_map(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                .collect::<Vec<_>>()
                .join("+");
            self.start_load(files, name);
        }
    }

    fn load_config_of(&mut self, kind: &str) {
        let title = match kind {
            "custom" => "自定义协议 JSON",
            "dbc" => "DBC 文件",
            "map104" => "IEC 104 点表(YAML/JSON)",
            "topo" => "储能拓扑定义 YAML",
            _ => "Modbus 寄存器映射",
        };
        let filter: &[&str] = match kind {
            "dbc" => &["dbc"],
            "map104" => &["yaml", "yml", "json"],
            "topo" => &["yaml", "yml"],
            _ => &["json"],
        };
        if let Some(p) = rfd::FileDialog::new().add_filter(title, filter).pick_file() {
            let mut dbc_err: Option<String> = None;
            match kind {
                "custom" => self.custom_paths.push(p),
                "dbc" => match iotprobe_core::textio::read_text(&p) {
                    Ok((text, _)) => {
                        self.dbc = Some(iotprobe_core::dbc::parse(&text));
                        self.dbc_path = Some(p);
                    }
                    Err(e) => dbc_err = Some(e.to_string()),
                },
                "map104" => self.map104_path = Some(p),
                "topo" => match iotprobe_core::topology::Topology::load_file(&p) {
                    Ok(t) => {
                        self.topo_path = Some(p);
                        self.topo = Some(t);
                        // 数据集已在手时立即重算
                        self.topo_state = self
                            .topo
                            .as_ref()
                            .and_then(|topo| self.ds.as_ref().map(|ds| iotprobe_core::topology::evaluate(ds, topo)));
                    }
                    Err(e) => self.status = format!("拓扑加载失败: {e}"),
                },
                _ => self.map_path = Some(p),
            }
            if kind != "topo" || self.topo.is_some() {
                self.status = format!("{title} 已更新");
            }
            if let Some(e) = dbc_err {
                self.status = format!("DBC 读取失败: {e}");
            }
            self.save_session();
        }
    }

    /// 信号组键 → 显示名:CAN 0x18FF2DF3x → "D2V_ST1 · 0x18FF2DF3x"(DBC 有定义时)
    fn group_label(&self, g: &str) -> String {
        let Some(idpart) = g.strip_prefix("CAN ") else {
            return g.to_string();
        };
        let (hex, ext) = match idpart.strip_suffix('x') {
            Some(h) => (h.trim_start_matches("0x"), true),
            None => (idpart.trim_start_matches("0x"), false),
        };
        let Ok(id) = u32::from_str_radix(hex, 16) else {
            return g.to_string();
        };
        let key = iotprobe_core::dbc::msg_key(id, ext);
        if let Some(m) = self.dbc.as_ref().and_then(|d| d.msgs.get(&key)) {
            return format!("{} · 0x{:X}{}", m.name, id, if ext { "x" } else { "" });
        }
        g.to_string()
    }

    /// FR-3.7 规则热加载:从磁盘重读规则包 → reload_rules 热替换规则事件。
    /// 不重读文件、不重解报文,信号/诊断事件/帧全部保留;拓扑缓存随之重算。
    fn rerun_rules(&mut self) {
        let Some(mut ds) = self.ds.as_ref().map(|a| a.as_ref().clone()) else { return };
        if self.rule_dirs.is_empty() {
            self.status = "没有挂载规则包(配置中心 → 规则引擎 → + 挂载规则包…)".into();
            return;
        }
        let mut packs = vec![];
        let mut warns = vec![];
        for d in &self.rule_dirs {
            match iotprobe_core::rules::load_pack_dir(d) {
                Ok(p) => packs.push(p),
                Err(e) => warns.push(e),
            }
        }
        iotprobe_core::rules::reload_rules(&packs, &mut ds);
        let n_rule = ds.events.iter().filter(|e| e.kind == iotprobe_core::model::EventKind::Rule).count();
        self.ds = Some(Arc::new(ds));
        self.topo_state = self
            .topo
            .as_ref()
            .and_then(|topo| self.ds.as_ref().map(|ds| iotprobe_core::topology::evaluate(ds, topo)));
        self.status = if warns.is_empty() {
            format!("规则已重跑: {} 条规则事件(热加载,未重解报文)", n_rule)
        } else {
            format!("规则重跑完成({} 条事件),但有告警: {}", n_rule, warns.join("; "))
        };
    }

    /// 证据包(FR-7.3):选中事件 ±10s 或全会话 → 单文件 JSON(事件+信号+原始帧+规则出处)
    fn export_evidence(&mut self) {        let Some(ds) = self.ds.clone() else { return };
        // 焦点:选中帧对应的事件;无选中 = 全会话
        let focus = self.sel.and_then(|fi| {
            ds.events
                .iter()
                .enumerate()
                .filter(|(_, e)| e.frame == Some(fi))
                .next_back()
                .map(|(idx, e)| (e.t_ns, format!("{}:{}", ds.name, idx)))
        });
        let packs: std::collections::BTreeMap<String, String> = ds
            .events
            .iter()
            .filter_map(|e| e.rule.as_ref())
            .map(|r| (r.pack.clone(), r.file.clone()))
            .collect();
        let (from, to, focus_id) = match &focus {
            Some((t, id)) => ((t.saturating_sub(10_000_000_000)) as f64 / 1e9, (t + 10_000_000_000) as f64 / 1e9, Some(id.clone())),
            None => (0.0, ds.t_max_ns() as f64 / 1e9, None),
        };
        let tmp = std::env::temp_dir().join("iotprobe_evidence_tmp");
        let _ = std::fs::create_dir_all(&tmp);
        let fp = tmp.join("f.jsonl");
        let ep = tmp.join("e.jsonl");
        let sp = tmp.join("s.jsonl");
        if let Err(e) = iotprobe_core::export::frames_jsonl(&ds, &fp) {
            self.status = format!("证据包失败: {e}");
            return;
        }
        let _ = iotprobe_core::export::events_jsonl(&ds, &ep);
        let _ = iotprobe_core::export::signals_jsonl(&ds, &sp);
        let load = |p: &PathBuf| -> Vec<serde_json::Value> {
            std::fs::read_to_string(p)
                .map(|t| t.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
                .unwrap_or_default()
        };
        let frames = load(&fp);
        let events = load(&ep);
        let signals = load(&sp);
        let meta = iotprobe_core::export::EvidenceMeta {
            session: ds.name.clone(),
            t_from_s: from,
            t_to_s: to,
            focus_event: focus_id,
            packs: packs.into_iter().collect(),
        };
        if let Some(out) = rfd::FileDialog::new()
            .set_file_name(&format!("{}_evidence.json", ds.name.replace(' ', "_")))
            .add_filter("证据包 JSON", &["json"])
            .save_file()
        {
            match iotprobe_core::export::build_evidence_bundle(&frames, &events, &signals, &meta, &out) {
                Ok((evs, fr, sg, trunc)) => {
                    self.status = format!(
                        "证据包已导出 {} — 事件{evs} 帧{fr} 信号{sg}{}",
                        out.display(),
                        if trunc { "(已抽稀)" } else { "" }
                    );
                }
                Err(e) => self.status = format!("证据包失败: {e}"),
            }
        }
    }

    /// 复制工单摘要(B3):选中事件 ±10s(无选中=全会话)的 Markdown——
    /// 时间线 + 事件表 + 证据帧号;普通文本框可读,帧号在 IoTProbe 事件窗可回跳。
    fn copy_evidence_markdown(&mut self, ctx: &egui::Context) {
        let Some(ds) = self.ds.clone() else {
            self.status = "未加载数据,无摘要可复制".into();
            return;
        };
        // 焦点口径与 export_evidence 一致:选中帧对应事件 ±10s;无选中 = 全会话
        let focus_t = self.sel.and_then(|fi| {
            ds.events.iter().find(|e| e.frame == Some(fi)).map(|e| e.t_ns)
        });
        let (from_s, to_s) = match focus_t {
            Some(t) => ((t.saturating_sub(10_000_000_000)) as f64 / 1e9, (t + 10_000_000_000) as f64 / 1e9),
            None => (0.0, ds.t_max_ns() as f64 / 1e9),
        };
        let evs: Vec<_> = ds
            .events
            .iter()
            .filter(|e| {
                let t = e.t_ns as f64 / 1e9;
                t >= from_s && t <= to_s
            })
            .collect();
        let fault_n = evs.iter().filter(|e| e.rule.as_ref().map(|r| r.level == "fault").unwrap_or(false)).count();
        let warn_n = evs.iter().filter(|e| e.rule.as_ref().map(|r| r.level == "warn").unwrap_or(false)).count();
        let packs: Vec<String> = ds.events.iter().filter_map(|e| e.rule.as_ref()).map(|r| r.pack.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let mut md = String::with_capacity(4096);
        md.push_str(&format!("## 故障摘要({})\n\n", ds.name));
        md.push_str(&format!("- 时间窗:{:.3}s ~ {:.3}s({})\n", from_s, to_s, if focus_t.is_some() { "选中事件 ±10s" } else { "全会话" }));
        md.push_str(&format!("- 事件:{} 条(fault {fault_n} · warn {warn_n})\n", evs.len()));
        if !packs.is_empty() {
            md.push_str(&format!("- 规则包:{}\n", packs.join("、")));
        }
        md.push_str(&format!("- 源文件:{}\n", ds.name));
        md.push_str("\n### 事件时间线\n\n");
        md.push_str("| 时刻(s) | 级别 | 事件 | 详情 | 证据帧 |\n|---|---|---|---|---|\n");
        for e in &evs {
            let lvl = e.rule.as_ref().map(|r| r.level.clone()).unwrap_or_else(|| match e.kind {
                iotprobe_core::model::EventKind::Info => "info".into(),
                iotprobe_core::model::EventKind::Rule => "warn".into(),
                _ => "fault".into(),
            });
            let rule_s = e.rule.as_ref().map(|r| format!("{}({})", r.rule_id, e.kind.label())).unwrap_or_else(|| e.kind.label().to_string());
            let frame_s = e.frame.map(|f| format!("#{f}")).unwrap_or_else(|| "-".into());
            md.push_str(&format!("| {:.3} | {} | {} | {} | {} |\n", e.t_ns as f64 / 1e9, lvl, rule_s, e.detail.replace('|', "\\|"), frame_s));
        }
        md.push_str("\n> 帧号在 IoTProbe 报文表中定位;证据包 JSON(含帧字节+规则出处)用「🧾 导出证据包」获取。\n");
        ctx.copy_text(md.clone());
        self.status = format!("工单摘要已复制到剪贴板({} 事件,Markdown {} 字符)——直接粘贴到工单/微信群", evs.len(), md.len());
    }

    /// GUI 批量回归(体检卡入口):spawn 同目录 batch_runner.exe,透传规则包与协议库(多 DBC 合并)。
    /// 完成后报告在 <目录>/batch_report.html;CI 语义(FAIL 非零退出)由子进程自持,GUI 不阻塞。
    fn run_batch_regression(&mut self, dir: std::path::PathBuf) {
        let Some(exe) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("batch_runner.exe"))) else {
            self.status = "无法定位 batch_runner.exe".into();
            return;
        };
        if !exe.exists() {
            self.status = format!("未找到 {}(源码构建请先 cargo build --release -p iotprobe-core)", exe.display());
            return;
        }
        let out = dir.join("batch_report.html");
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("--dir").arg(&dir).arg("--out").arg(&out);
        for r in &self.rule_dirs {
            cmd.arg("--rules").arg(r);
        }
        for d in &self.dbc_paths {
            cmd.arg("--dbc").arg(d);
        }
        match cmd.spawn() {
            Ok(_) => self.status = format!("批量回归已启动:目录 {} → 报告 {}(完成后可直接打开)", dir.display(), out.display()),
            Err(e) => self.status = format!("批量回归启动失败: {e}"),
        }
    }

    fn export_csv(&mut self) {
        let Some(ds) = self.ds.clone() else { return };
        if let Some(dir) = rfd::FileDialog::new().set_file_name("iotprobe_signals.csv").pick_file() {
            let stem = dir
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "export".into());
            let dir = dir.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let mut msg = vec![];
            let mk = |suffix: &str| dir.join(format!("{stem}_{suffix}.csv"));
            for (path, what) in [
                (mk("signals"), "信号"),
                (mk("frames"), "帧"),
                (mk("events"), "事件"),
                (mk("frames_schema"), "帧契约"),
                (mk("events_schema"), "事件契约"),
                (mk("signals_schema"), "信号契约"),
            ] {
                let r: Result<String, String> = match what {
                    "信号" => iotprobe_core::export::signals_csv(&ds, &path).map(|_| String::new()),
                    "帧" => iotprobe_core::export::frames_csv(&ds, &path).map(|_| String::new()),
                    "帧契约" => iotprobe_core::export::frames_jsonl(&ds, &path).map(|n| format!("{n}行")),
                    "事件契约" => iotprobe_core::export::events_jsonl(&ds, &path).map(|n| format!("{n}行")),
                    "信号契约" => iotprobe_core::export::signals_jsonl(&ds, &path).map(|n| format!("{n}行")),
                    _ => iotprobe_core::export::events_csv(&ds, &path).map(|_| String::new()),
                };
                match r {
                    Ok(_) => msg.push(format!("{what}→{}", path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default())),
                    Err(e) => msg.push(format!("{what}导出失败: {e}")),
                }
                let _ = &path;
            }
            self.status = msg.join(" | ");
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Session {
    files: Vec<PathBuf>,
    custom_paths: Vec<PathBuf>,
    dbc: Option<PathBuf>,
    #[serde(default)]
    dbcs: Vec<PathBuf>,
    map: Option<PathBuf>,
    #[serde(default)]
    map104: Option<PathBuf>,
    #[serde(default)]
    topo: Option<PathBuf>,
    inline_specs: Vec<iotprobe_core::dissect::CustomSpec>,
    rule_dirs: Vec<PathBuf>,
    sig_sel: Vec<String>,
    #[serde(default)]
    fav_sigs: Vec<String>,
    #[serde(default)]
    color_ov: HashMap<String, [u8; 3]>,
    #[serde(default = "default_true")]
    dark: bool,
    gap_ms: f64,
    filter: String,
    #[serde(default)]
    scene: usize,
}

/// 回放注入预览:离线读取录制文件 → CAN 帧列表 + 白名单预检
fn load_injection_preview(path: &PathBuf, whitelist_text: &str) -> Result<InjPreview, String> {
    let src = iotprobe_core::ingest::read_file(path)?;
    let wl = crate::tx::parse_whitelist(whitelist_text)?;
    let mut frames = vec![];
    let mut out_of_wl = 0u32;
    let mut min_t = u64::MAX;
    let mut max_t = 0u64;
    for r in &src.records {
        let Some(raw) = r.can_id else { continue };
        let id = raw & 0x1FFF_FFFF;
        let ext = raw & 0x8000_0000 != 0;
        if !wl.allows(id) {
            out_of_wl += 1;
            continue;
        }
        frames.push((r.t_ns, id, ext, r.data.to_vec()));
        min_t = min_t.min(r.t_ns);
        max_t = max_t.max(r.t_ns);
    }
    let duration_s = if max_t > min_t { (max_t - min_t) as f64 / 1e9 } else { 0.0 };
    Ok(InjPreview { frames, duration_s, out_of_wl })
}

fn session_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("iotprobe_session.json")))
        .unwrap_or_else(|| PathBuf::from("iotprobe_session.json"))
}

fn load_session() -> Option<Session> {
    let text = std::fs::read_to_string(session_path())
        .or_else(|_| std::fs::read_to_string("./iotprobe_session.json"))
        .ok()?;
    serde_json::from_str(&text).ok()
}

/// 读 DBC 文件为解析结果(路径不存在/读失败 → None;GBK 自动回退)
fn parse_dbc_of(p: &Option<PathBuf>) -> Option<iotprobe_core::dbc::Dbc> {
    let p = p.as_ref()?;
    let (text, enc) = iotprobe_core::textio::read_text(p).ok()?;
    if enc != "UTF-8" {
        eprintln!("提示: DBC 非 UTF-8(按 {enc} 解码): {}", p.display());
    }
    Some(iotprobe_core::dbc::parse(&text))
}

/// DBC 协议库条目
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct DbcLibEntry {
    name: String,
    path: PathBuf,
    msgs: usize,
    /// 与库内其他文件的报文 ID 冲突(合并时后选中的不覆盖)
    conflict: bool,
}

/// 协议库目录:与 exe 同级 protocols/(没有则空库)
fn dbc_library_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("protocols")))
}

/// 启动播种:协议库为空时,从 dbc/ 候选目录(exe 同级/上级、工作目录上级)拷贝默认 DBC 进 protocols/
/// 随程序带出多个内置协议,加载 CAN 数据即可自动匹配,无需手动导入。
fn seed_default_dbcs() {
    let Some(dir) = dbc_library_dir() else { return };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    // 一次性播种:标记文件存在则跳过(用户删除的协议不会被强行复活)
    let marker = dir.join(".seeded");
    if marker.exists() {
        return;
    }
    let mut candidates: Vec<PathBuf> = vec![];
    if let Some(exe_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        for rel in ["dbc", "../dbc", "../../dbc", "../../../dbc"] {
            candidates.push(exe_dir.join(rel));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        for rel in ["dbc", "../../dbc", "../../../dbc", "../../../../dbc"] {
            candidates.push(cwd.join(rel));
        }
    }
    let mut seeded = 0usize;
    for c in candidates {
        if let Ok(rd) = std::fs::read_dir(&c) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()).map(|x| x.eq_ignore_ascii_case("dbc")).unwrap_or(false) {
                    let dst = dir.join(p.file_name().unwrap_or_default());
                    if !dst.exists() && std::fs::copy(&p, &dst).is_ok() {
                        seeded += 1;
                    }
                }
            }
        }
    }
    let _ = std::fs::write(&marker, "1");
    if seeded > 0 {
        eprintln!("已从 dbc/ 目录播种 {seeded} 个默认协议到 protocols/");
    }
}

/// 使用指南(exe 目录常驻一份;空状态卡可一键打开)
const GUIDE: &str = r#"═══════════════════════════════════════════
  IoTProbe 使用指南(首次启动自动生成)
═══════════════════════════════════════════

【30 秒上手】
 1. 点顶栏「打开文件」,选择 .asc / .log / .candump / .pcap / .pcapng / .blf / .ndjson
 2. 程序自动识别协议;CAN 数据自动匹配内置 DBC(无需手动导入)
 3. 左侧信号按 DBC 报文分组,点组头 ◉ 整组上图,点行画单变量

【协议库】
 · 内置协议在「配置中心 → 协议解析」的 CAN DBC 协议库,可勾选多个同时解码
 · 加载 CAN 数据后自动匹配最优 DBC;也可手动「⚡ 自动匹配」
 · 想加自己的协议:把 .dbc 文件放进 protocols/ 目录(与 exe 同级)重启即可,
   或在协议库点「＋导入 DBC…」;GBK 编码(含中文/℃)的 DBC 自动兼容

【左侧信号分组】
 · 分节 = 匹配到的 DBC(如 JXDCDC / GB27930),每节下的组 = 该 DBC 的报文
 · 组头文字点击 = 折叠/展开;组头圆点 ◉ = 组内全选/全不选;组头右键 = 整组收藏
 · 行尾 ☆ = 收藏,收藏项在「★ 常用」节置顶;搜索框可按报文名/信号名/ID 过滤
 · 「全部展开/折叠」按钮在搜索框右侧

【绘图手势】
 · 左键点击      选帧 / 设游标 A
 · Shift+点击    设游标 B(与 A 组成测量:Δt / Δv / 速率)
 · 右键拖拽      框选放大;右键单击清除游标
 · 左键拖拽      平移;滚轮缩放;双击复位
 · Space 跟随 / F 复位视图 / + - 缩放 / ← → 平移
 · 归一化开关:多信号量程差大时各自缩放,小波动也看得清
 · 曲线上方图例条:点击隐藏曲线,右键改色/移除

【场景模式(配置中心)】
 · 配置中心顶部切场景:1 离线分析 / 2 现场排故(含产线抽测) / 3 数据喂AI / 4 模拟联调 / 5 全部配置
 · 打开程序或菜单「分析工具→使用引导」:「这次想做什么?」按你的处境选(有日志 / 设备在手边 / 没设备想模拟 / 让 AI 看 / 我是熟手),
   然后一屏一事:问句标题 → 只填这一步要的 → 就地看结果(✓/○)→ 下一步(没就绪会置灰并写差什么)→ 完成直接进工作台
 · 向导页右上「全部参数(专家视图)」随时切七卡平铺;顶部任务卡与快捷键 1~5 熟手直用
 · 卡片模块跨场景复用(同一个卡在不同场景出现,改一处处处生效)
【模拟联调·点位编辑】
 · 菜单「分析工具→点位编辑」或侧栏「⛶ 点位编辑…」:全部点位值就地改(枚举下拉 / 位开关 / 数值拖拽 / 文本),改完即生效并 📌 钉住(Random/Fault 不再动它,释放回场景驱动)
 · 「主机读到」列 = 真实主机 func3/4 读到的值与次数(对不上就查 scale/字节序);🔒 = 主机不可写,但模拟器侧你仍可改
 · 点位表没定义的寄存器走「临时点」:填地址/类型/scale → 添加并置值 → 可回写点位表(devN_临时点位 分节)
 · 快捷键:1~5 切场景 · Ctrl+0 回工作台 · F1 快捷键帮助(文本框聚焦时失效)

【界面布局(看/分析/配置 三分离)】
 · 顶栏「工作台 | 配置中心」页面切换:分析时看工作台,配置去配置中心
 · 工作台主线:左侧选信号 → 中央看曲线 → 点帧在图下方横条看详情
 · 配置中心 = 一页收拢全部配置:按功能分卡片,每张卡片上半是「当前生效状态」,下半是操作
   (数据源 / 协议解析 / 规则引擎 / 设备模拟器 / 实时接入 / 发送 / 界面与诊断)
 · 选中帧横条:一行摘要 + 「▸」展开完整字段树/hex(横向铺满,不再占右侧一整栏)
 · 底部视图 tab:帧表 / 通道统计 / 聚合 —— 同一数据的三种列表形态
 · 顶栏「分析工具」菜单:异常事件 / 未知协议试探 / 规则任务 / 储能拓扑(展示类,按需弹窗;已打开数在菜单名)
 · 状态栏「N 异常」红色可点,直达事件列表
 · 顶栏「📤 发送」是唯一主动操作入口,独立窗口 + 默认锁定 —— 与查看分析完全隔离

【帧详情】
 · 点击帧(曲线/帧表)后图下方出现横条;「▸」展开字段树 + hex
 · 字段左侧圆点:实心=已上图,点一下加/删曲线;点字段名=选中查看

【回放与模拟】
 · 「配置中心 → 实时接入」选回放源:支持 .ndjson 录制 与 .asc 抓包,走同一解析管线
 · 「配置中心 → 设备模拟器」启动 Modbus 从机供数,拓扑对齐真实采集表:端口唯一绑 0.0.0.0
   (主机按表里 ip:端口 连;局域网可达),同端口多机自动改 127.0.0.<N> 按设备区分;
   自轮询持续发数(点位表 poll_ms 周期,0=关),可勾选录制 .ndjson 落盘回放(独立启停);
   点位可带 min/max —— Random 场景在物理值范围内随机波动,模拟真实运行
 · CAN 硬件实时接入(配置中心 → 实时接入):ZLG USBCANFD / VCI 兼容卡(创芯老版经桥接,
   新 SDK x64 免桥接)/ SLCAN(CANable)/ PEAK PCAN-Basic / Kvaser CANlib / GCAN ECanVci
 · PEAK/Kvaser 支持 CAN FD 勾选;Kvaser 装驱动后可用 Virtual CAN 无硬件演示;
   各厂商 DLL 状态在表单内实时显示(绿=就绪);只听默认开启,发送面板默认锁定

【数据导出】
 · 顶栏「导出CSV」= 当前已勾选信号曲线
 · 事件窗「导出证据包」= 选中事件 ±10s 的帧/事件/信号 JSONL

提示:本文件位于 exe 同目录,删除后下次启动会重新生成。
"#;

fn ensure_guide() {
    let p = session_path()
        .parent()
        .map(|d| d.join("IoTProbe使用指南.txt"))
        .unwrap_or_else(|| PathBuf::from("IoTProbe使用指南.txt"));
    // 布局改版后指南内容变化:始终以内置版本覆盖,保持与界面一致
    let _ = std::fs::write(&p, GUIDE);
}

/// 信号组键 → 所属分节名:CAN 组查 dbc_attr(报文键→DBC 名),其余归「其他」,收藏归自身节
fn dbc_section_of(g: &str, attr: &HashMap<u32, String>) -> String {
    if g == "★ 常用" {
        return "★ 常用".into();
    }
    let Some(idpart) = g.strip_prefix("CAN ") else { return "其他".into() };
    let (hex, ext) = match idpart.strip_suffix('x') {
        Some(h) => (h.trim_start_matches("0x"), true),
        None => (idpart.trim_start_matches("0x"), false),
    };
    let Ok(id) = u32::from_str_radix(hex, 16) else { return "其他".into() };
    let key = iotprobe_core::dbc::msg_key(id, ext);
    attr.get(&key).cloned().unwrap_or_else(|| "未匹配报文".into())
}

/// 启动时扫描 protocols/ 目录自动发现 DBC(导入过的直接出现,无需注册表)
fn dbc_library_load() -> Vec<DbcLibEntry> {
    let Some(dir) = dbc_library_dir() else { return vec![] };
    let mut entries: Vec<DbcLibEntry> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()).map(|x| x.eq_ignore_ascii_case("dbc")).unwrap_or(false))
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            let msgs = parse_dbc_of(&Some(path.clone())).map(|d| d.msgs.len()).unwrap_or(0);
            if msgs == 0 {
                return None; // 解析不出报文的文件不入库
            }
            Some(DbcLibEntry { name, path, msgs, conflict: false })
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    // 冲突检测:同 ID 出现在多个文件 → 全部标记(合并时先入优先)
    let mut id_seen = std::collections::HashSet::new();
    let mut dup = std::collections::HashSet::new();
    for e in &entries {
        let ids = parse_dbc_of(&Some(e.path.clone()))
            .map(|d| d.msgs.keys().cloned().collect::<std::collections::HashSet<_>>())
            .unwrap_or_default();
        for id in ids {
            if !id_seen.insert(id) {
                dup.insert(id);
            }
        }
    }
    if !dup.is_empty() {
        for e in &mut entries {
            let hits = parse_dbc_of(&Some(e.path.clone()))
                .map(|d| d.msgs.keys().any(|k| dup.contains(k)))
                .unwrap_or(false);
            e.conflict = hits;
        }
    }
    entries
}

impl App {
    /// 导入 DBC 到协议库:复制文件进 protocols/,自动解析摘要;同名覆盖。
    /// 返回 Ok(true)=新导入,Ok(false)=同名已存在已覆盖。
    fn dbc_library_import(&mut self, src: &PathBuf) -> Result<bool, String> {
        let dir = dbc_library_dir().ok_or("无法定位协议库目录")?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let name = src
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .ok_or("无文件名")?;
        let dst = dir.join(&name);
        std::fs::copy(src, &dst).map_err(|e| format!("复制 {}: {e}", src.display()))?;
        let msgs = parse_dbc_of(&Some(dst.clone())).map(|d| d.msgs.len()).ok_or("DBC 解析失败")?;
        if msgs == 0 {
            let _ = std::fs::remove_file(&dst);
            return Err("DBC 中没有可识别的报文".into());
        }
        let existed = self.dbc_library.iter().any(|e| e.path == dst);
        let entry = DbcLibEntry { name: name.trim_end_matches(".dbc").to_string(), path: dst, msgs, conflict: false };
        if existed {
            self.dbc_library.retain(|e| e.path != entry.path);
        }
        self.dbc_library.push(entry);
        self.dbc_library.retain(|e| e.path.exists());
        Ok(!existed)
    }

    /// 重建库条目的冲突标记(导入/删除后)
    fn dbc_library_save(&mut self) {
        let fresh = dbc_library_load();
        // 保留启用集里指向库外文件的路径
        self.dbc_library = fresh;
    }

    /// 合并所有启用的 DBC(按启用顺序;ID 冲突时先选中的优先)
    fn dbc_all(&self) -> Option<iotprobe_core::dbc::Dbc> {
        if self.dbc_paths.is_empty() {
            return self.dbc.clone();
        }
        let mut merged = iotprobe_core::dbc::Dbc::default();
        for p in &self.dbc_paths {
            if let Some(d) = parse_dbc_of(&Some(p.clone())) {
                merged.merge(d);
            }
        }
        if merged.msgs.is_empty() {
            self.dbc.clone()
        } else {
            Some(merged)
        }
    }

    /// 用当前数据集对库内 DBC 打分(采样前 500 帧,命中报文×信号数),返回最优项
    fn dbc_match_best(&self, ds: &Dataset) -> Option<(usize, PathBuf)> {
        let mut best: Option<(usize, PathBuf)> = None;
        for e in &self.dbc_library {
            let Some(d) = parse_dbc_of(&Some(e.path.clone())) else { continue };
            let mut score = 0usize;
            let mut tried = 0usize;
            for f in &ds.frames {
                if tried >= 500 {
                    break;
                }
                let Some(raw) = ds.records.get(f.record as usize).and_then(|r| r.can_id) else { continue };
                tried += 1;
                let key = iotprobe_core::dbc::msg_key(raw & 0x1FFF_FFFF, raw & 0x8000_0000 != 0);
                if let Some(m) = d.msgs.get(&key) {
                    score += m.sigs.len() + 1;
                }
            }
            if score > 0 && best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
                best = Some((score, e.path.clone()));
            }
        }
        best
    }

    /// 报文键 → DBC 名归属表(侧栏分节用;启用集变化/加载数据后重建)
    fn rebuild_dbc_attr(&mut self) {
        self.dbc_attr.clear();
        for p in self.active_dbc_paths() {
            let Some(d) = parse_dbc_of(&Some(p.clone())) else { continue };
            let name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            for k in d.msgs.keys() {
                self.dbc_attr.entry(*k).or_insert_with(|| name.clone());
            }
        }
    }

    /// 当前启用 DBC 对该数据集的命中数(换文件时判断是否需要换协议)
    fn dbc_paths_hits(&self, ds: &Dataset) -> usize {
        let mut hits = 0usize;
        for p in self.active_dbc_paths() {
            let Some(d) = parse_dbc_of(&Some(p)) else { continue };
            for f in ds.frames.iter().take(500) {
                if let Some(raw) = ds.records.get(f.record as usize).and_then(|r| r.can_id) {
                    let key = iotprobe_core::dbc::msg_key(raw & 0x1FFF_FFFF, raw & 0x8000_0000 != 0);
                    if d.msgs.contains_key(&key) {
                        hits += 1;
                    }
                }
            }
        }
        hits
    }

    /// 分析管线实际启用的 DBC 路径(协议库多选;兼容旧单 DBC 字段)
    fn active_dbc_paths(&self) -> Vec<PathBuf> {
        if !self.dbc_paths.is_empty() {
            self.dbc_paths.clone()
        } else if let Some(p) = &self.dbc_path {
            vec![p.clone()]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod live_kind_label_tests {
    use super::*;

    #[test]
    fn vendor_kinds_have_dropdown_labels() {
        // 回归:11/12/13 未配标签时下拉回显错位(曾显示成 SocketCAN vcan)
        assert_eq!(live_kind_label(8), "CAN卡·VCI兼容");
        assert_eq!(live_kind_label(9), "CAN卡·SLCAN");
        assert_eq!(live_kind_label(11), "CAN卡·PEAK");
        assert_eq!(live_kind_label(12), "CAN卡·Kvaser");
        assert_eq!(live_kind_label(13), "CAN卡·GCAN");
        assert_eq!(live_kind_label(5), "模拟 CAN(开发演示)");
        assert_eq!(live_kind_label(3), "回放");
        #[cfg(target_os = "linux")]
        assert_eq!(live_kind_label(10), "SocketCAN vcan");
        #[cfg(not(target_os = "linux"))]
        assert_eq!(live_kind_label(10), "未知源类型");
    }
}

#[cfg(test)]
mod scene_tests {
    use super::*;

    #[test]
    fn scenes_table_and_shortcut_keys() {
        // 场景合并:产线抽测并入现场排故 → 四任务场景 + 全部配置
        assert_eq!(SCENES.len(), 5);
        assert_eq!(SCENES[0].0, "离线分析");
        assert_eq!(SCENES[1].0, "现场排故");
        assert_eq!(SCENES[2].0, "数据喂 AI");
        assert_eq!(SCENES[3].0, "模拟联调");
        assert_eq!(SCENES[4].0, "全部配置");
        // 快捷键映射:1~5 场景 / 0 工作台
        assert_eq!(num_key(0), egui::Key::Num0);
        assert_eq!(num_key(1), egui::Key::Num1);
        assert_eq!(num_key(5), egui::Key::Num5);
    }
}

#[cfg(test)]
mod sidebar_section_tests {
    use super::*;

    #[test]
    fn section_of_dbc_and_fallback() {
        let mut attr = HashMap::new();
        attr.insert(iotprobe_core::dbc::msg_key(0x18FF2DF3, true), "JXDCDC".to_string());
        // 扩展帧命中 → DBC 名节
        assert_eq!(dbc_section_of("CAN 0x18FF2DF3x", &attr), "JXDCDC");
        // 未命中 → 未匹配报文节
        assert_eq!(dbc_section_of("CAN 0x1234567x", &attr), "未匹配报文");
        // 非 CAN 组 → 其他
        assert_eq!(dbc_section_of("RTT", &attr), "其他");
        assert_eq!(dbc_section_of("Δt", &attr), "其他");
        // 收藏节独立
        assert_eq!(dbc_section_of("★ 常用", &attr), "★ 常用");
    }
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/simsun.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert("cjk".into(), egui::FontData::from_owned(bytes).into());
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                fam.push("cjk".into());
            }
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                fam.push("cjk".into());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_load();
        self.poll_live();
        // 场景/页面/帮助快捷键(全局,无文本框聚焦):1~5 切场景(5=全部配置) · Ctrl+0 工作台 · F1 帮助
        let typing = ctx.memory(|m| m.focused().is_some());
        if !typing {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::F1) {
                    self.help_open = !self.help_open;
                }
                let ctrl = i.modifiers.ctrl;
                if ctrl && i.key_pressed(num_key(0)) {
                    self.page = 0;
                }
                // 配置中心页直接按数字 1~5;任意页 Ctrl+数字 同效
                for n in 1..=5u8 {
                    if i.key_pressed(num_key(n)) && ((self.page == 1 && !ctrl) || ctrl) {
                        self.page = 1;
                        self.scene = (n - 1) as usize;
                        self.save_session();
                    }
                }
            });
        }
        // 跟随状态常驻徽章:在工作台图区右上角,任何滚动位置都看得到(误触 Space 的解药)
        if self.page == 0 && self.follow {
            egui::Area::new(egui::Id::new("follow_badge"))
                .anchor(egui::Align2::RIGHT_TOP, [-12.0, 34.0])
                .show(ctx, |ui| {
                    let badge = egui::Button::new(
                        egui::RichText::new("● 跟随中(Space 关)").size(10.5).color(Color32::from_rgb(120, 200, 130)),
                    )
                    .fill(Color32::from_rgba_unmultiplied(20, 60, 30, 200));
                    if ui.add(badge).clicked() {
                        self.follow = false;
                        self.status = "跟随已关闭(视图锁定)".into();
                    }
                });
        }

        // 工作台快捷键(仅工作台页 + 无文本聚焦 + 已加载数据):Space 跟随 / F 复位 / +− 缩放 / ←→ 平移
        if !typing && self.page == 0 && self.ds.is_some() {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::Space) {
                    self.follow = !self.follow;
                    self.status = if self.follow {
                        "跟随最新帧已开启(曲线随新数据右移;Space 或点「跟随」关闭)".into()
                    } else {
                        "跟随已关闭(视图锁定;Space 或点「跟随」重新开启)".into()
                    };
                }
                if i.key_pressed(egui::Key::F) {
                    self.reset_plot = true;
                }
                let zoom = if i.key_pressed(egui::Key::Equals) {
                    0.8
                } else if i.key_pressed(egui::Key::Minus) {
                    1.25
                } else {
                    1.0
                };
                if zoom != 1.0 {
                    let c = (self.plot_state.t0 + self.plot_state.t1) / 2.0;
                    self.plot_state.t0 = c - (c - self.plot_state.t0) * zoom;
                    self.plot_state.t1 = c + (self.plot_state.t1 - c) * zoom;
                }
                if i.key_pressed(egui::Key::ArrowLeft) || i.key_pressed(egui::Key::ArrowRight) {
                    let dir: f64 = if i.key_pressed(egui::Key::ArrowLeft) { -1.0 } else { 1.0 };
                    let span = (self.plot_state.t1 - self.plot_state.t0) * 0.2 * dir;
                    self.plot_state.t0 += span;
                    self.plot_state.t1 += span;
                }
            });
        }
        if self.edit_map104.is_some() {
            self.map104_editor_window(ctx);
        }

        // ---------- 顶栏 ----------
        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.heading(egui::RichText::new("IoTProbe").size(16.0).color(Color32::from_rgb(120, 180, 230)));
                ui.separator();
                // 页面切换:工作台=看/分析主线;配置中心=所有配置整页铺开(卡片:状态在上、操作在下)
                if ui.selectable_label(self.page == 0, "工作台").clicked() {
                    self.page = 0;
                }
                if ui.selectable_label(self.page == 1, "配置中心").clicked() {
                    self.page = 1;
                }
                ui.separator();
                if ui.button("打开文件").clicked() {
                    self.open_files();
                }
                if ui.button("示例").clicked() {
                    self.try_load_demo();
                }
                if ui.button("导出CSV").clicked() {
                    self.export_csv();
                }
                ui.separator();
                if self.dbc_library.iter().any(|e| self.dbc_paths.contains(&e.path)) {
                    ui.label(
                        egui::RichText::new(format!("协议库:{}启用", self.dbc_paths.len()))
                            .size(10.5)
                            .color(Color32::from_rgb(210, 160, 235)),
                    );
                }
                // 体检结论 chip(常驻顶栏):工作台不切场景也能看到数据健康;点击直达体检卡
                if let Some(ds) = self.ds.clone() {
                    let ck = iotprobe_core::export::Checkup::from_dataset(&ds);
                    let (verdict, _) = ck.verdict();
                    let (icon, color) = match verdict {
                        "PASS" => ("🟢", Color32::from_rgb(120, 200, 130)),
                        "WARN" => ("🟠", Color32::from_rgb(235, 170, 80)),
                        _ => ("🔴", Color32::from_rgb(235, 120, 100)),
                    };
                    if ui.button(format!("{icon} 体检 {verdict}")).on_hover_text(format!("数据体检:{verdict}(点开离线分析场景看明细/导报告)")).clicked() {
                        self.page = 1;
                        self.scene = 0;
                    }
                    let _ = color;
                }
                // 展示类窗口统一入口(异常事件/试探/任务/拓扑/拓扑连线/串口终端);已打开数显示在菜单名上
                let open_n = [self.show_events, self.show_probe, self.show_tasks, self.show_topo, self.show_topolink, self.show_terminal, self.show_single, self.show_ptedit]
                    .iter()
                    .filter(|x| **x)
                    .count();
                let menu_label = if open_n > 0 { format!("分析工具({open_n})") } else { "分析工具".to_string() };
                ui.menu_button(menu_label, |ui| {
                    if ui.button("🧭 使用引导(这次做什么,每屏一步)").clicked() {
                        self.wizard_mode = true;
                        self.wizard_task = usize::MAX;
                        self.wizard_step = 0;
                        self.page = 1;
                        ui.close();
                    }
                    let items = [
                        ("异常事件", &mut self.show_events),
                        ("未知协议试探", &mut self.show_probe),
                        ("规则任务", &mut self.show_tasks),
                        ("储能拓扑", &mut self.show_topo),
                        ("拓扑连线", &mut self.show_topolink),
                        ("串口终端", &mut self.show_terminal),
                        ("单帧解码", &mut self.show_single),
                        ("点位编辑(模拟联调)", &mut self.show_ptedit),
                    ];
                    for (label, on) in items {
                        if ui.checkbox(on, label).changed() {
                            self.status = format!("{label}窗口已{}(菜单可再切)", if *on { "打开" } else { "关闭" });
                        }
                    }
                });
                // 发送=唯一主动操作入口:高亮=窗口开着;锁定态随文案显示
                let tx_btn = if self.tx_unlocked {
                    egui::RichText::new("📤 发送(已解锁)").color(Color32::from_rgb(240, 150, 80))
                } else {
                    egui::RichText::new("📤 发送(🔒锁定)")
                };
                if ui.selectable_label(self.show_tx, tx_btn).clicked() {
                    self.show_tx = !self.show_tx;
                }
                // 主题切换(随会话记忆)
                let theme_btn = if self.dark { "☀ 亮色" } else { "🌙 暗色" };
                if ui.button(theme_btn).clicked() {
                    self.dark = !self.dark;
                    apply_theme(ctx, self.dark);
                    self.save_session();
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if !self.lives.is_empty() {
                        ui.label(
                            egui::RichText::new(format!(
                                "● {}帧 坏{} 丢{}",
                                self.live_stats.ok, self.live_stats.bad, self.live_stats.gaps
                            ))
                            .size(11.0)
                            .color(Color32::from_rgb(120, 200, 130)),
                        );
                    }
                    // status 文本移至底部状态栏;此处仅留加载 spinner
                    if self.rx.is_some() {
                        ui.spinner();
                    }
                });
            });
        });

        // ---------- 左侧栏(仅工作台页;配置中心整页铺开) ----------
        if self.page == 0 {
            egui::SidePanel::left("sidebar")
                .resizable(true)
                .default_width(250.0)
                .min_width(180.0)
                .width_range(160.0..=560.0) // 上限:防止内容/误拖把侧栏挤到不可见(Win11 高 DPI 溢出防御)
                .show(ctx, |ui| {
                    self.sidebar(ui);
                });
        }

        // ---------- 右侧详情(可折叠:折叠时主图占满全宽;点帧自动展开) ----------
        // ---------- 分析工具弹窗(展示类:按需打开,两页均可用) ----------
        self.tool_windows(ctx);

        // ---------- 底部状态栏(最底边):文件·协议·帧数·时间范围·选中帧 + 告警徽标 + 操作反馈 ----------

        // ---------- 底部状态栏(最底边):文件·协议·帧数·时间范围·选中帧 + 告警徽标 + 操作反馈 ----------
        egui::TopBottomPanel::bottom("statusbar")
            .exact_height(24.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    if let Some(ds) = &self.ds {
                        let protos: Vec<&str> = {
                            let mut seen: Vec<&str> = vec![];
                            for f in &ds.frames {
                                let l = f.proto.label();
                                if !seen.contains(&l) {
                                    seen.push(l);
                                }
                            }
                            seen
                        };
                        ui.label(egui::RichText::new(&ds.name).size(11.0).color(txt(ui)).strong());
                        ui.separator();
                        ui.label(egui::RichText::new(protos.join("+")).size(10.5).color(dim(ui)));
                        ui.label(
                            egui::RichText::new(format!("{}帧 {}信号", ds.frames.len(), ds.signals.len()))
                                .size(10.5)
                                .color(dim(ui)),
                        );
                        // 异常数:可点击直达事件窗(有异常时红色醒目)
                        let ev_n = ds.events.len();
                        let ev_btn = egui::Button::new(
                            egui::RichText::new(format!("{ev_n} 异常"))
                                .size(10.5)
                                .color(if ev_n > 0 { Color32::from_rgb(235, 120, 100) } else { dim(ui) }),
                        )
                        .frame(false);
                        if ui.add(ev_btn).clicked() {
                            self.show_events = true;
                        }
                        ui.label(
                            egui::RichText::new(format!("0 ~ {:.1}s", ds.t_max_ns() as f64 / 1e9))
                                .size(10.5)
                                .color(dim(ui)),
                        );
                        if let Some(fi) = self.sel {
                            ui.label(egui::RichText::new(format!("选中 #{fi}")).size(10.5).color(Color32::from_rgb(250, 200, 90)));
                        }
                        // 告警徽标:点击弹出完整列表(GBK 编码提示/DBC 冲突等常驻可查)
                        if !ds.warnings.is_empty() {
                            let badge = egui::Button::new(
                                egui::RichText::new(format!("⚠ {}", ds.warnings.len())).size(10.5).color(Color32::from_rgb(235, 170, 80)),
                            )
                            .small()
                            .fill(Color32::from_rgba_unmultiplied(120, 80, 20, 90));
                            if ui.add(badge).clicked() {
                                self.warn_open = true;
                            }
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if !self.status.is_empty() {
                            ui.label(egui::RichText::new(&self.status).size(11.0).color(dim(ui)));
                        }
                    });
                });
            });
        // 告警列表窗口
        if self.warn_open {
            let mut open = self.warn_open;
            egui::Window::new("告警与提示").open(&mut open).default_width(560.0).show(ctx, |ui| {
                let warns = self.ds.as_ref().map(|d| d.warnings.clone()).unwrap_or_default();
                if warns.is_empty() {
                    ui.label(egui::RichText::new("(无告警)").size(11.5).color(dim(ui)));
                }
                for w in &warns {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("·").color(Color32::from_rgb(235, 170, 80)));
                        ui.label(egui::RichText::new(w).size(11.0).color(txt(ui)));
                    });
                }
            });
            self.warn_open = open;
        }
        // 快捷键帮助窗(F1)
        if self.help_open {
            let mut open = self.help_open;
            egui::Window::new("快捷键(F1)").open(&mut open).default_width(420.0).show(ctx, |ui| {
                ui.label(egui::RichText::new("配置中心(任一页)").size(12.0).strong());
                ui.monospace("1 ~ 4        切场景(离线分析/现场排故/数据喂AI/模拟联调)");
                ui.monospace("5            全部配置(七卡铺开,专家视图)");
                ui.monospace("Ctrl+1 ~ 5   任意页面直达对应场景");
                ui.monospace("Ctrl+0       回工作台");
                ui.add_space(6.0);
                ui.label(egui::RichText::new("工作台").size(12.0).strong());
                ui.monospace("Space        跟随最新帧");
                ui.monospace("F            复位视图");
                ui.monospace("+ / −        缩放");
                ui.monospace("← / →        平移");
                ui.monospace("图内:点击选帧 / Shift+点击测量 / 右键拖拽框选 / 双击复位");
                ui.add_space(6.0);
                ui.label(egui::RichText::new("通用").size(12.0).strong());
                ui.monospace("F1           本帮助");
                ui.monospace("文本框聚焦时以上键位自动失效");
            });
            self.help_open = open;
        }

        // ---------- 底部帧表(仅工作台页) ----------
        if self.page == 0 {
            egui::TopBottomPanel::bottom("table")
                .resizable(true)
                .default_height(280.0)
                .min_height(120.0)
                .show(ctx, |ui| {
                    let ds = self.ds.clone();
                    // 底部视图 tab:帧表 / 通道统计 / 聚合(同一数据的三种列表形态)
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.bottom_view, 0, "帧表");
                        ui.selectable_value(&mut self.bottom_view, 1, "通道");
                        ui.selectable_value(&mut self.bottom_view, 2, "聚合");
                        ui.separator();
                    });
                    if self.bottom_view == 1 {
                        if let Some(ds) = &ds {
                            views::channels_panel(ui, ds);
                        }
                        return;
                    }
                    if self.bottom_view == 2 {
                        self.agg_tab(ui);
                        return;
                    }
                    if let Some(ds) = &ds {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("帧 {} / {}", self.shown.len(), ds.frames.len()))
                                    .size(11.5)
                                    .color(Color32::from_rgb(140, 148, 160)),
                            );
                            // 过滤框(自顶栏移入,作用于帧表)
                            let mut f = self.filter.clone();
                            let resp = ui.add(
                                TextEdit::singleline(&mut f)
                                    .hint_text("过滤:文本/协议/通道…")
                                    .desired_width(180.0)
                                    .font(egui::TextStyle::Small),
                            );
                            if resp.changed() {
                                self.filter = f;
                                self.rebuild_shown();
                            }
                            if self.sel.is_some() {
                                if ui.button("跳到选中帧").clicked() {
                                    self.want_scroll = self.sel;
                                }
                            }
                        });
                        let mut sel = self.sel;
                        let mut want = self.want_scroll.take();
                        let mut out_filter: Option<String> = None;
                        let mut hover_frame: Option<u32> = None;
                        let sort_before = self.sort;
                        views::frame_table(ui, ds, &self.shown, sel, &mut sel, &mut want, &mut self.sort, &mut out_filter, &mut hover_frame);
                        self.hover_frame = hover_frame;
                        if sel != self.sel {
                            self.sel = sel;
                            self.sel_path.clear();
                            self.sync_plot_cursor();
                        }
                        self.want_scroll = want;
                        if self.sort != sort_before {
                            self.rebuild_shown();
                        }
                        if let Some(tok) = out_filter.take() {
                            self.filter = tok.clone();
                            self.rebuild_shown();
                            self.status = format!("已过滤: {tok}(右键帧可快速过滤)");
                        }
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                egui::RichText::new("打开日志文件开始分析(hex 日志 / candump / pcap / pcapng)")
                                    .color(dim(ui)),
                            );
                        });
                    }
                });
        }

        // ---------- 中央区:工作台=时序图;配置中心=整页卡片 ----------
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.page == 1 {
                self.config_page(ui);
                return;
            }
            let Some(ds) = self.ds.clone() else {
                // 空状态三步卡:新用户 30 秒上手路径
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() * 0.18);
                    ui.label(egui::RichText::new("IoTProbe — 总线报文分析").size(22.0).color(Color32::from_rgb(120, 180, 230)).strong());
                    ui.add_space(18.0);
                    let step = |ui: &mut egui::Ui, n: &str, title: &str, desc: &str| {
                        ui.horizontal(|ui| {
                            ui.add_space(ui.available_width() * 0.28);
                            ui.label(egui::RichText::new(n).size(16.0).color(Color32::from_rgb(120, 180, 230)).strong());
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(title).size(13.5).color(txt(ui)).strong());
                                ui.label(egui::RichText::new(desc).size(11.0).color(dim(ui)));
                            });
                        });
                        ui.add_space(6.0);
                    };
                    step(ui, "①", "打开数据文件", ".asc / .log / .candump / .pcap / .blf / .ndjson");
                    if ui.button("📂 打开文件…").clicked() {
                        self.open_files();
                    }
                    ui.add_space(10.0);
                    step(ui, "②", "自动匹配协议", "内置多个 DBC,CAN 数据自动选最优;也可在「配置中心 → 协议解析」手动勾选");
                    if ui.button("⚙ 打开配置中心…").clicked() {
                        self.page = 1;
                    }
                    ui.add_space(10.0);
                    step(ui, "③", "勾选信号画曲线", "左侧信号按报文分组;点组头◉整组画,点行画单变量;★ 收藏常用");
                    ui.add_space(14.0);
                    ui.label(
                        egui::RichText::new("图内手势:点击选帧 · Shift+点击测量 · 右键拖拽框选放大 · 滚轮缩放 · 双击复位")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    if ui.button("📖 查看使用指南(完整说明)").clicked() {
                        let p = session_path()
                            .parent()
                            .map(|d| d.join("IoTProbe使用指南.txt"))
                            .unwrap_or_else(|| PathBuf::from("IoTProbe使用指南.txt"));
                        if let Some(dir) = p.parent() {
                            let _ = std::process::Command::new("cmd")
                                .args(["/C", "start", "", &p.display().to_string()])
                                .current_dir(dir)
                                .spawn();
                        }
                    }
                });
                return;
            };
            // 绘图控制行(自顶栏移入,贴近图)
            ui.horizontal(|ui| {
                if ui.selectable_label(self.follow, "跟随").clicked() {
                    self.follow = !self.follow;
                }
                // 归一化:多系列量程差 3 倍以上时各自缩放,小波动也能看清
                if ui.selectable_label(self.plot_state.normalized, "归一化").clicked() {
                    self.plot_state.normalized = !self.plot_state.normalized;
                }
                if ui.button("复位视图").clicked() {
                    self.reset_plot = true;
                }
                if self.plot_state.cursor_a.is_some() || self.plot_state.cursor_b.is_some() {
                    if ui.button("清除游标").clicked() {
                        self.plot_state.cursor_a = None;
                        self.plot_state.cursor_b = None;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.label(egui::RichText::new("点击选帧/设游标A · Shift+点击设B · 右键拖拽框选 · 图内右上\"?\"看全部手势").size(10.0).color(dim(ui)));
                });
            });
            // 图例 chips:● 信号名[单位] 最新值;点击隐藏,右键改色/移除
            let chips: Vec<(String, usize, Color32, String)> = ds
                .signals
                .iter()
                .enumerate()
                .filter(|(_, s)| self.sig_sel.contains(&s.key))
                .map(|(si, s)| {
                    let c = self
                        .color_ov
                        .get(&s.key)
                        .map(|c| Color32::from_rgb(c[0], c[1], c[2]))
                        .unwrap_or_else(|| views::series_color(si));
                    let name = s.key.split('·').next_back().unwrap_or(&s.key);
                    let last = s.pts.last().map(|p| format!(" {}", plot::fmt_val(p.1))).unwrap_or_default();
                    let label = if s.unit.is_empty() { format!("{name}{last}") } else { format!("{name}[{}] {last}", s.unit) };
                    (s.key.clone(), si, c, label)
                })
                .collect();
            if !chips.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    for (key, si, c, label) in &chips {
                        let btn = egui::Button::new(egui::RichText::new(format!("● {label}")).size(11.5).color(*c))
                            .small()
                            .fill(Color32::from_rgba_unmultiplied(38, 42, 52, 160));
                        let resp = ui.add(btn).on_hover_text(key);
                        if resp.clicked() {
                            self.sig_sel.remove(key);
                            self.save_session();
                        }
                        resp.context_menu(|ui| {
                            ui.menu_button("颜色", |ui| {
                                for pc in views::palette() {
                                    let mark = if [pc.r(), pc.g(), pc.b()] == self.color_ov.get(key).copied().unwrap_or_default() { " ✔" } else { " ●" };
                                    if ui.button(egui::RichText::new(mark).color(pc).size(12.0)).clicked() {
                                        self.color_ov.insert(key.clone(), [pc.r(), pc.g(), pc.b()]);
                                        ui.close();
                                    }
                                }
                            });
                            if ui.button("恢复默认色").clicked() {
                                self.color_ov.remove(key);
                                ui.close();
                            }
                            if ui.button("移除曲线").clicked() {
                                self.sig_sel.remove(key);
                                let _ = si;
                                self.save_session();
                                ui.close();
                            }
                        });
                    }
                });
            }
            let series: Vec<plot::PlotSeries<'_>> = chips
                .iter()
                .map(|(_, si, c, _)| plot::PlotSeries { series: &ds.signals[*si], color: *c })
                .collect();
            let sel_t = self.sel.map(|s| ds.frames[s as usize].t_ns);
            let preview_t = self.hover_frame.map(|h| ds.frames[h as usize].t_ns);
            let out = plot::draw(ui, &ds, &series, &ds.events, sel_t, &mut self.plot_state, self.reset_plot, self.follow, preview_t);
            self.reset_plot = false;
            if let Some(f) = out.clicked_frame {
                if Some(f) != self.sel {
                    self.sel = Some(f);
                    self.sel_path.clear();
                    self.want_scroll = Some(f);
                }
            }
            if series.is_empty() {
                ui.painter().text(
                    ui.available_rect_before_wrap().center(),
                    Align2::CENTER_CENTER,
                    "在左侧「信号」列表勾选要观察的参数曲线\n点击曲线上的点可跳到对应帧",
                    FontId::proportional(13.0),
                    Color32::from_rgb(110, 118, 130),
                );
            }

            // ---- 选中帧横条:一行摘要;展开才显示字段树+hex(横向铺满中央) ----
            if let Some(fi) = self.sel {
                let f = &ds.frames[fi as usize];
                ui.separator();
                let expand_ch = if self.sel_expanded { "▾" } else { "▸" };
                ui.horizontal(|ui| {
                    let bg = if ui.visuals().dark_mode { Color32::from_rgb(34, 40, 52) } else { Color32::from_rgb(226, 234, 248) };
                    let r = ui.available_rect_before_wrap();
                    ui.painter().rect_filled(r, 4.0, bg);
                    ui.add_space(6.0);
                    if ui.add(egui::Button::new(egui::RichText::new(expand_ch).size(12.0)).small().frame(false)).clicked() {
                        self.sel_expanded = !self.sel_expanded;
                    }
                    // 修复(Win11 高 DPI 溢出):summary 可达数百字符,horizontal 布局不换行
                    // → 最小宽度撑爆中央区,右侧按钮被推出屏幕。横向 ScrollArea 裁剪+可拖动查看。
                    egui::ScrollArea::horizontal()
                        .id_salt("sel_frame_bar")
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.set_min_height(20.0);
                            ui.label(
                                egui::RichText::new(format!("#{fi}  {}", f.summary))
                                    .monospace()
                                    .size(12.0)
                                    .color(txt(ui)),
                            );
                        });
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("取消选中").clicked() {
                            self.sel = None;
                            self.sel_path.clear();
                        }
                        if !self.sel_expanded && ui.small_button("展开字段").clicked() {
                            self.sel_expanded = true;
                        }
                    });
                });
                if self.sel_expanded {
                    let dec = self.resolve_decoded(fi);
                    let active = self.frame_active_sig_names(&ds, fi);
                    let mut rclick: Option<String> = None;
                    let toggled = views::detail_pane(ui, &ds, fi, dec.as_deref(), &mut self.sel_path, &active, &mut rclick);
                    if let Some(bare) = toggled {
                        self.toggle_frame_signal(&ds, fi, &bare);
                    }
                    if let Some(bare) = rclick {
                        self.locate_point_in_sim(&bare, fi);
                    }
                }
            }
        });
    }
}

impl App {
    /// 回放并入当前实时会话:把所选文件重映射为目标设备的实时流量(模拟现场)
    fn start_replay_into(&mut self) {
        let Some(p) = self.live_form.replay_path.clone() else {
            self.status = "请先选择回放文件(.ndjson 录制 或 .asc 抓包)".into();
            return;
        };
        let tx = match self.live_tx_any() {
            Some(tx) => tx,
            None => {
                self.status = "并入需先连接实时源".into();
                return;
            }
        };
        let target = self.live_form.replay_target_ch;
        let speed = [1.0f64, 5.0, 20.0, 0.0][self.live_form.replay_speed_idx];
        // 并入点 = 主会话时间轴当前位置(epoch 为绝对墙钟锚;单调时基源无锚则从 0 起)
        let t_offset = self.live_epoch.map_or(0, |e| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            now.saturating_sub(e)
        });
        match live::spawn_replay_into(&p, target, speed, t_offset, tx) {
            Ok(hd) => {
                self.replay_into = Some(hd);
                let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                let dev = self.live_labels.get(&target).cloned().unwrap_or_else(|| format!("ch{target}"));
                let sp = ["原速 ×1", "×5", "×20", "极速"][self.live_form.replay_speed_idx];
                self.status = format!("回放并入:{name} → {dev}({sp})");
            }
            Err(e) => self.status = format!("并入启动失败: {e}"),
        }
    }

    /// 启动 DL/T 645 电表从机模拟(J1 顺带项)
    fn start_moddev645(&mut self) {
        let Some(y) = self.moddev645_yaml.clone() else { return };
        let record = if self.moddev645_record {
            match self.moddev645_record_path.clone() {
                Some(p) => Some(p),
                None => match rfd::FileDialog::new()
                    .set_file_name("sim645_session.ndjson")
                    .add_filter("NDJSON", &["ndjson"])
                    .save_file()
                {
                    Some(p) => {
                        self.moddev645_record_path = Some(p.clone());
                        Some(p)
                    }
                    None => return,
                },
            }
        } else {
            None
        };
        match crate::moddev645::spawn_645(&y, self.live_tx_for_moddev(), record) {
            Ok((rt, warns)) => {
                let _ = &warns;
                self.status = format!(
                    "645 电表从机已启动:{} 端口 {}·表号 {}·{} 点(EMS/采集终端按 645 over TCP 抄表)",
                    y.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                    rt.bound_port,
                    rt.addr_display,
                    rt.points.len()
                );
                self.moddev645_rt = Some(rt);
            }
            Err(e) => self.status = format!("645 从机启动失败: {e}"),
        }
    }

    /// 启动自定义协议从机模拟(A6)
    fn start_moddev_custom(&mut self) {
        let Some(y) = self.moddev_custom_yaml.clone() else { return };
        let record = if self.moddev_custom_record {
            match self.moddev_custom_record_path.clone() {
                Some(p) => Some(p),
                None => match rfd::FileDialog::new()
                    .set_file_name("simcustom_session.ndjson")
                    .add_filter("NDJSON", &["ndjson"])
                    .save_file()
                {
                    Some(p) => {
                        self.moddev_custom_record_path = Some(p.clone());
                        Some(p)
                    }
                    None => return,
                },
            }
        } else {
            None
        };
        match crate::moddev_custom::spawn_custom_slave(&y, self.live_tx_for_moddev(), record, Some(self.fwd_slot.clone())) {
            Ok((rt, warns)) => {
                self.status = format!(
                    "自定义从机已启动:{} 端口 {}·{} 字段·自轮询 {}ms{}{}",
                    y.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                    rt.bound_port,
                    rt.spec.fields.len(),
                    rt.poll_ms,
                    if rt.echo { "·回显开" } else { "" },
                    if warns.is_empty() { String::new() } else { format!(";⚠ {}", warns.join("; ")) }
                );
                self.moddev_custom_rt = Some(rt);
            }
            Err(e) => self.status = format!("自定义从机启动失败: {e}"),
        }
    }

    /// 启动 IEC 104 从机模拟(A5):录制路径解析 → spawn_104(与 Modbus 模拟器同款管线对接)
    fn start_moddev104(&mut self) {
        let Some(y) = self.moddev104_yaml.clone() else { return };
        let record = if self.moddev104_record {
            match self.moddev104_record_path.clone() {
                Some(p) => Some(p),
                None => match rfd::FileDialog::new()
                    .set_file_name("sim104_session.ndjson")
                    .add_filter("NDJSON", &["ndjson"])
                    .save_file()
                {
                    Some(p) => {
                        self.moddev104_record_path = Some(p.clone());
                        Some(p)
                    }
                    None => return,
                },
            }
        } else {
            None
        };
        match crate::moddev104::spawn_104(&y, self.live_tx_for_moddev(), record, Some(self.fwd_slot.clone())) {
            Ok((rt, warns)) => {
                self.moddev104_rt = Some(rt);
                let mut base = format!(
                    "104 从机已启动:{}(端口 {}·CA {}·{} 点;EMS 按 2404 连;STARTDT 后变位主动上送)",
                    y.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                    self.moddev104_rt.as_ref().map(|r| r.bound_port).unwrap_or(0),
                    self.moddev104_rt.as_ref().map(|r| r.dev.ca).unwrap_or(0),
                    self.moddev104_rt.as_ref().map(|r| r.dev.points.len()).unwrap_or(0)
                );
                if self.moddev104_record {
                    if let Some(rp) = &self.moddev104_record_path {
                        base.push_str(&format!(";录制→{}", rp.display()));
                    }
                }
                self.status = if warns.is_empty() { base } else { format!("{base};⚠ {}", warns.join("; ")) };
            }
            Err(e) => self.status = format!("104 从机启动失败: {e}"),
        }
    }

    /// 模拟器启动:有实时通道就借用其发送端;没有就先建一个空接收通道(纯 sink)
    fn live_tx_for_moddev(&mut self) -> std::sync::mpsc::Sender<live::LiveMsg> {
        if let Some(tx) = self.live_tx_any() {
            tx
        } else {
            self.start_live_sink();
            self.lives.last().expect("sink slot").h.tx.clone()
        }
    }

    /// 启动设备模拟器(实时接入表单与配置中心卡共用入口):
    /// 解析录制路径(勾选未选→保存对话框)→ 起服务 → 状态栏回报主机接入端点/unit/录制去向。
    fn start_moddev(&mut self) {
        let Some(y) = self.live_form.moddev_yaml.clone() else { return };
        let record = if self.live_form.sim_record {
            match self.live_form.sim_record_path.clone() {
                Some(p) => Some(p),
                None => match rfd::FileDialog::new()
                    .set_file_name("sim_session.ndjson")
                    .add_filter("NDJSON", &["ndjson"])
                    .save_file()
                {
                    Some(p) => {
                        self.live_form.sim_record_path = Some(p.clone());
                        Some(p)
                    }
                    None => return, // 取消对话框 = 放弃启动
                },
            }
        } else {
            None
        };
        match crate::moddev::spawn_standalone(&y, self.live_tx_for_moddev(), record.clone(), Some(self.fwd_slot.clone())) {
            Ok((rt, sim_warns)) => {
                // 实例名 = 点位表文件名去扩展;重名自动加序号(A3 多实例可并行)
                let mut name = y
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "模拟器".into());
                let mut k = 2;
                while self.moddev_rts.iter().any(|i| i.name == name) {
                    name = format!("{}-{k}", y.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "模拟器".into()));
                    k += 1;
                }
                self.moddev_rts.push(crate::moddev::ModDevInst { rt, name, yaml: y.clone(), record });
                self.moddev_inst_idx = self.moddev_rts.len() - 1;
                let inst = &self.moddev_rts[self.moddev_inst_idx];
                let eps: Vec<String> = inst.rt.devs.iter().map(|d| d.endpoint()).collect();
                let rec_s = if self.live_form.sim_record {
                    self.live_form
                        .sim_record_path
                        .as_ref()
                        .map(|rp| format!(";录制→{}", rp.display()))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let base = format!(
                    "模拟器已启动:实例 {} {} 台端点 {}{}(共 {} 个实例;自轮询发数中;主机按点位表 ip:端口 连,同端口多机 IP 填对应 127.0.0.N)",
                    inst.name,
                    inst.rt.devs.len(),
                    eps.join(" / "),
                    rec_s,
                    self.moddev_rts.len()
                );
                self.status = if sim_warns.is_empty() {
                    base
                } else {
                    format!("{base};⚠ {}", sim_warns.join("; "))
                };
            }
            Err(e) => self.status = format!("模拟器启动失败: {e}"),
        }
    }

    /// 无源接收通道:只承载模拟器泵线程的 Batch(界面照常节流重建)
    fn start_live_sink(&mut self) {
        let h = live::spawn_sink();
        self.push_live_slot(h, "模拟器·总线");
        self.last_rebuild = std::time::Instant::now();
    }

    /// C1:推送一路源进槽列表(首个源=新会话清空累积;后续源并入,按通道合并)
    fn push_live_slot(&mut self, h: live::LiveHandle, name: &str) {
        let first = self.lives.is_empty();
        if first {
            self.live_recs.clear();
            self.live_rolled = 0;
            self.live_labels.clear();
            self.live_warns.clear();
            self.live_stats = Default::default();
            self.live_epoch = None;
        }
        self.lives.push(LiveSlot { h, name: name.to_string(), stats: Default::default(), epoch: None });
        self.live_name = self.live_names_joined();
    }

    /// C1:全部源名的合并展示(数据源名/Dataset.name)
    fn live_names_joined(&self) -> String {
        if self.lives.is_empty() {
            String::new()
        } else {
            self.lives.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(" + ")
        }
    }

    /// C1:取一路源的发送端(并入回放/模拟器泵用;无源返回 None)
    fn live_tx_any(&self) -> Option<std::sync::mpsc::Sender<live::LiveMsg>> {
        self.lives.last().map(|s| s.h.tx.clone())
    }

    /// 该帧 CAN id 的已绘信号裸名集合(帧详情字段圆点高亮用)
    fn frame_active_sig_names(&self, ds: &iotprobe_core::model::Dataset, fi: u32) -> HashSet<String> {
        let Some(raw) = ds.records.get(ds.frames[fi as usize].record as usize).and_then(|r| r.can_id) else {
            return Default::default();
        };
        let id = raw & 0x1FFF_FFFF;
        let ext = raw & 0x8000_0000 != 0;
        let prefix = format!("CAN 0x{id:X}{}·", if ext { "x" } else { "" });
        ds.signals
            .iter()
            .filter(|s| self.sig_sel.contains(&s.key) && s.key.starts_with(&prefix))
            .map(|s| s.key[prefix.len()..].to_string())
            .collect()
    }

    /// 帧详情字段圆点点击:加/删该 CAN id 下名为 bare 的信号曲线
    fn toggle_frame_signal(&mut self, ds: &iotprobe_core::model::Dataset, fi: u32, bare: &str) {
        let Some(raw) = ds.records.get(ds.frames[fi as usize].record as usize).and_then(|r| r.can_id) else {
            self.status = "该帧不是 CAN 数据,无法绘制曲线".into();
            return;
        };
        let id = raw & 0x1FFF_FFFF;
        let ext = raw & 0x8000_0000 != 0;
        let key = format!("CAN 0x{id:X}{}·{}", if ext { "x" } else { "" }, bare);
        if ds.signals.iter().any(|s| s.key == key) {
            if self.sig_sel.contains(&key) {
                self.sig_sel.remove(&key);
                self.status = format!("已从绘图移除: {bare}");
            } else {
                self.sig_sel.insert(key);
                self.status = format!("已加入绘图: {bare}(点字段圆点可移除)");
            }
            self.save_session();
        } else {
            self.status = format!("未找到信号 {bare} —— 该帧可能未启用对应 DBC,去【配置中心】协议库勾选");
        }
    }

    fn sync_plot_cursor(&mut self) {
        if let (Some(ds), Some(sel)) = (self.ds.as_ref(), self.sel) {
            let t = ds.frames[sel as usize].t_ns as f64 / 1e9;
            let span = self.plot_state.t1 - self.plot_state.t0;
            if t < self.plot_state.t0 || t > self.plot_state.t1 {
                self.plot_state.t0 = (t - span * 0.1).max(0.0);
                self.plot_state.t1 = t + span * 0.9;
            }
        }
    }

    fn run_probe(&mut self) {
        use iotprobe_core::dissect::unknown;
        let Some(ds) = self.ds.clone() else { return };
        let mut out = vec![];
        for c in &ds.channels {
            if c.proto != Proto::Raw {
                continue;
            }
            let recs: Vec<&iotprobe_core::model::Record> = ds
                .records
                .iter()
                .filter(|r| r.source == c.source && r.channel == c.id)
                .collect();
            if recs.len() < 3 {
                continue;
            }
            out.push(unknown::probe(&c.label, &recs));
        }
        if out.is_empty() {
            self.status = "没有未识别协议的通道(全部已识别或样本过少)".into();
        } else {
            self.status = format!("试探完成:{} 个通道", out.len());
        }
        self.probe_results = out;
    }

    fn probe_tab(&mut self, ui: &mut Ui) {
        use iotprobe_core::dissect::unknown::Verdict;
        ui.horizontal(|ui| {
            if ui.button("运行试探").clicked() {
                self.run_probe();
            }
            if !self.inline_specs.is_empty() {
                ui.label(egui::RichText::new(format!("已采纳草案 {} 个", self.inline_specs.len())).size(10.5).color(dim(ui)));
            }
        });
        ui.separator();
        if self.probe_results.is_empty() {
            ui.label(
                egui::RichText::new(
                    "对未识别协议(RAW)的通道做结构试探:
同步头统计 → 长度域假设 → 校验算法网格试配 →
常量/计数器/载荷区域识别 → 生成协议草案。

草案经人工确认后可一键采纳(提议-确认式,不做黑盒自动化)。",
                )
                .size(11.0)
                .color(dim(ui)),
            );
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for i in 0..self.probe_results.len() {
                let rep = self.probe_results[i].clone();
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&rep.channel).size(11.5).monospace().color(txt(ui)));
                    let vcol = match rep.verdict {
                        Verdict::Framed => Color32::from_rgb(140, 200, 100),
                        Verdict::NDJson | Verdict::Text => Color32::from_rgb(98, 178, 235),
                        Verdict::Opaque => Color32::from_rgb(220, 120, 100),
                    };
                    ui.label(egui::RichText::new(format!("{:?}", rep.verdict)).size(11.0).color(vcol));
                    ui.add(
                        egui::ProgressBar::new(rep.confidence as f32)
                            .text(format!("置信度 {:.0}%", rep.confidence * 100.0))
                            .desired_width(140.0),
                    );
                });
                ui.label(egui::RichText::new(format!("{}记录 / {}B", rep.n_records, rep.total_bytes)).size(10.5).color(dim(ui)));
                for n in &rep.notes {
                    ui.label(egui::RichText::new(format!("· {n}")).size(10.5).color(dim(ui)));
                }
                if let Some(s) = &rep.sync {
                    ui.label(egui::RichText::new(format!("同步头 {s}")).size(11.0).monospace().color(Color32::from_rgb(235, 200, 90)));
                }
                if let Some((p, w, le, bias)) = rep.length {
                    ui.label(egui::RichText::new(format!("长度域 @{p} 宽{w} {} bias={bias}", if le { "LE" } else { "BE" })).size(11.0).monospace().color(Color32::from_rgb(98, 178, 235)));
                }
                if let Some(fl) = rep.fixed_len {
                    ui.label(egui::RichText::new(format!("固定帧长 {fl}")).size(11.0).monospace().color(Color32::from_rgb(98, 178, 235)));
                }
                if let Some((a, cs, el)) = &rep.checksum {
                    ui.label(egui::RichText::new(format!("校验 {a} cover从{cs} 尾部{el}B")).size(11.0).monospace().color(Color32::from_rgb(140, 200, 100)));
                }
                for h in &rep.hints {
                    ui.label(egui::RichText::new(format!("字段猜测: {} @{} ({})", h.kind, h.pos, h.detail)).size(10.5).color(dim(ui)));
                }
                if let Some(draft) = &rep.draft {
                    ui.horizontal(|ui| {
                        if ui.button("✔ 采纳并重新加载").clicked() {
                            let spec = draft.clone();
                            let files = self.last_files.clone();
                            let name = self.ds.as_ref().map(|d| d.name.clone()).unwrap_or_default();
                            self.inline_specs.push(spec);
                            self.start_load(files, name);
                        }
                        if ui.button("保存JSON…").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .set_file_name("probe_draft.json")
                                .add_filter("JSON", &["json"])
                                .save_file()
                            {
                                if let Ok(j) = serde_json::to_string_pretty(draft) {
                                    let _ = std::fs::write(&path, j);
                                    self.status = format!("草案已保存 {}", path.display());
                                }
                            }
                        }
                    });
                }
            }
        });
    }

    fn template_ui(&mut self, ui: &mut Ui) {
        use iotprobe_core::dissect::CustomSpec;
            ui.label(
                egui::RichText::new("模板 = 解析时使用的协议配置。增删后点底部「应用并重新加载」生效。")
                    .size(11.0)
                    .color(dim(ui)),
            );
            ui.add_space(4.0);

            // ---- 自定义协议(文件) ----
            ui.label(egui::RichText::new("自定义协议(文件)").size(11.5).color(Color32::from_rgb(235, 200, 90)));
            let paths = self.custom_paths.clone();
            if paths.is_empty() {
                ui.label(egui::RichText::new("(无)").size(11.0).color(dim(ui)));
            }
            let mut removed: Option<PathBuf> = None;
            for p in &paths {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default())
                            .monospace()
                            .size(11.0),
                    );
                    match iotprobe_core::textio::read_text_simple(p)
                        .map_err(|e| e.to_string())
                        .and_then(|t| serde_json::from_str::<CustomSpec>(&t).map_err(|e| e.to_string()))
                    {
                        Ok(spec) => {
                            ui.label(egui::RichText::new(spec_summary(&spec)).size(10.5).color(dim(ui)));
                        }
                        Err(e) => {
                            ui.label(egui::RichText::new(format!("解析失败: {e}")).size(10.5).color(Color32::from_rgb(235, 90, 80)));
                        }
                    }
                    if ui.small_button("移除").clicked() {
                        removed = Some(p.clone());
                    }
                });
            }
            if let Some(p) = removed {
                self.custom_paths.retain(|x| *x != p);
                self.status = "已移除模板,点「应用并重新加载」生效".into();
                self.save_session();
            }

            // ---- 试探采纳的内置草案 ----
            ui.add_space(4.0);
            ui.label(egui::RichText::new("试探采纳的草案(内置)").size(11.5).color(Color32::from_rgb(140, 200, 100)));
            if self.inline_specs.is_empty() {
                ui.label(egui::RichText::new("(无)").size(11.0).color(dim(ui)));
            }
            let mut removed_idx: Option<usize> = None;
            for (i, spec) in self.inline_specs.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&spec.name).monospace().size(11.0));
                    ui.label(egui::RichText::new(spec_summary(spec)).size(10.5).color(dim(ui)));
                    if ui.small_button("移除").clicked() {
                        removed_idx = Some(i);
                    }
                });
            }
            if let Some(i) = removed_idx {
                self.inline_specs.remove(i);
                self.status = "已移除草案,点「应用并重新加载」生效".into();
                self.save_session();
            }

            // ---- DBC 协议库(多选启用;导入即复制到协议目录) ----
            ui.add_space(4.0);
            ui.label(egui::RichText::new("CAN DBC 协议库").size(11.5).color(Color32::from_rgb(210, 160, 235)));
            ui.label(
                egui::RichText::new("勾选启用(可多选,自动合并解码);导入的文件复制到 protocols/ 目录随程序走。")
                    .size(10.5)
                    .color(dim(ui)),
            );
            ui.add_space(2.0);
            egui::ScrollArea::vertical()
                .id_salt("dbc_lib")
                .max_height(140.0)
                .show(ui, |ui| {
                    let mut to_import: Option<Vec<PathBuf>> = None;
                    if ui.small_button("＋ 导入 DBC…").clicked() {
                        if let Some(ps) = rfd::FileDialog::new()
                            .add_filter("DBC", &["dbc"])
                            .add_filter("全部", &["*"])
                            .pick_files()
                        {
                            to_import = Some(ps);
                        }
                    }
                    // 自动匹配:用当前数据的 CAN ID 对库内 DBC 打分(命中报文×信号数),启用最优
                    if ui.small_button("⚡ 自动匹配").clicked() {
                        let ds = self.ds.clone();
                        if let Some(ds) = ds {
                            if let Some((score, p)) = self.dbc_match_best(&ds) {
                                let name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                                if !self.dbc_paths.contains(&p) {
                                    self.dbc_paths.push(p);
                                }
                                self.status = format!("自动匹配: 启用 {name}(命中 {score} 个信号定义) —— 点「应用并重新加载」生效");
                            } else {
                                self.status = "自动匹配: 协议库中没有 DBC 与当前数据的 CAN ID 匹配".into();
                            }
                        } else {
                            self.status = "请先加载数据再自动匹配".into();
                        }
                    }
                    if let Some(ps) = to_import {
                        for p in ps {
                            match self.dbc_library_import(&p) {
                                Ok(true) => (),
                                Ok(false) => {}
                                Err(e) => self.status = format!("DBC 导入失败: {e}"),
                            }
                        }
                        self.dbc_library_save();
                        self.status = "DBC 已导入协议库,勾选后点「应用并重新加载」生效".into();
                    }
                    ui.add_space(2.0);
                    let lib = self.dbc_library.clone();
                    if lib.is_empty() {
                        ui.label(egui::RichText::new("(库为空;下方「+ DBC…」直接指定也仍然可用)").size(10.5).color(dim(ui)));
                    }
                    for entry in &lib {
                        let mut on = self.dbc_paths.contains(&entry.path);
                        ui.horizontal(|ui| {
                            if ui.checkbox(&mut on, &entry.name).changed() {
                                if on {
                                    self.dbc_paths.push(entry.path.clone());
                                } else {
                                    self.dbc_paths.retain(|x| *x != entry.path);
                                }
                                self.auto_match_done = true; // 手动选择优先,本次数据不再自动换
                                self.status = "DBC 启用集已变,点「应用并重新加载」生效".into();
                            }
                            ui.label(
                                egui::RichText::new(format!("{} 报文", entry.msgs))
                                    .size(10.0)
                                    .color(dim(ui)),
                            );
                            if entry.conflict {
                                ui.label(egui::RichText::new("⚠ID冲突").size(10.0).color(Color32::from_rgb(235, 170, 80)));
                            }
                            // 库内删除(不删启用集里的外部路径)
                            if ui.small_button("✕").clicked() {
                                self.dbc_library_remove = Some(entry.path.clone());
                            }
                        });
                    }
                    if let Some(p) = self.dbc_library_remove.take() {
                        self.dbc_library.retain(|e| e.path != p);
                        self.dbc_paths.retain(|x| *x != p);
                        let _ = std::fs::remove_file(&p);
                        self.dbc_library_save();
                        self.status = "已从协议库删除".into();
                    }
                });
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Modbus 寄存器映射").size(11.5).color(Color32::from_rgb(98, 178, 235)));
            if let Some(p) = self.map_path.clone() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(p.display().to_string()).monospace().size(11.0));
                    if ui.small_button("移除").clicked() {
                        self.map_path = None;
                        self.status = "已移除寄存器映射,点「应用并重新加载」生效".into();
                    }
                });
            } else {
                ui.label(egui::RichText::new("(无)").size(11.0).color(dim(ui)));
            }
            ui.add_space(4.0);
            // ---- IEC 104 点表(MVP ②)+ 编辑器 ----
            ui.label(egui::RichText::new("IEC 104 点表").size(11.5).color(Color32::from_rgb(230, 120, 180)));
            if let Some(p) = self.map104_path.clone() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(p.display().to_string()).monospace().size(11.0));
                    if let Ok(text) = iotprobe_core::textio::read_text_simple(&p) {
                        match iotprobe_core::dissect::Map104::parse(&text) {
                            Ok(m) => ui.label(egui::RichText::new(format!("{} 个信息体", m.points.len())).size(10.5).color(dim(ui))),
                            Err(e) => ui.label(egui::RichText::new(format!("解析失败: {e}")).size(10.5).color(Color32::from_rgb(235, 90, 80))),
                        };
                    }
                    if ui.small_button("编辑…").clicked() {
                        match iotprobe_core::textio::read_text_simple(&p)
                            .map_err(|e| e.to_string())
                            .and_then(|t| iotprobe_core::dissect::Map104::parse(&t))
                        {
                            Ok(m) => {
                                self.edit_map104 = Some(m);
                                self.edit_map104_path = Some(p.clone());
                                self.edit_map104_dirty = false;
                            }
                            Err(e) => self.status = format!("点表无法编辑: {e}"),
                        }
                    }
                    if ui.small_button("移除").clicked() {
                        self.map104_path = None;
                        self.status = "已移除 104 点表,点「应用并重新加载」生效".into();
                        self.save_session();
                    }
                });
            } else {
                ui.label(egui::RichText::new("(无)").size(11.0).color(dim(ui)));
            }

            ui.add_space(4.0);
            // ---- 储能拓扑(MVP ③) ----
            ui.label(egui::RichText::new("储能拓扑定义").size(11.5).color(Color32::from_rgb(150, 220, 130)));
            if let Some(p) = self.topo_path.clone() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(p.display().to_string()).monospace().size(11.0));
                    if let Some(t) = &self.topo {
                        ui.label(egui::RichText::new(format!("{} 台设备", t.devices.len())).size(10.5).color(dim(ui)));
                    }
                    if ui.small_button("移除").clicked() {
                        self.topo_path = None;
                        self.topo = None;
                        self.topo_state = None;
                        self.status = "已移除拓扑定义".into();
                        self.save_session();
                    }
                });
            } else {
                ui.label(egui::RichText::new("(无)").size(11.0).color(dim(ui)));
            }

            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("+ 自定义JSON…").clicked() {
                    self.load_config_of("custom");
                }
                if ui.button("+ DBC…").clicked() {
                    self.load_config_of("dbc");
                }
                if ui.button("+ 寄存器映射…").clicked() {
                    self.load_config_of("map");
                }
                if ui.button("+ 104 点表…").clicked() {
                    self.load_config_of("map104");
                }
                if ui.button("+ 拓扑…").clicked() {
                    self.load_config_of("topo");
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let can_apply = !self.last_files.is_empty();
                if ui.add_enabled(can_apply, egui::Button::new("✔ 应用并重新加载")).clicked() {
                    let files = self.last_files.clone();
                    let name = self
                        .ds
                        .as_ref()
                        .map(|d| d.name.clone())
                        .unwrap_or_default();
                    self.start_load(files, name);
                }
                if !can_apply {
                    ui.label(egui::RichText::new("尚未加载过文件").size(10.5).color(dim(ui)));
                }
            });
    }

    /// IEC 104 点表编辑器(MVP ②):工程名/变比/偏移/单位逐行编辑,保存 JSON/YAML。
    /// 编辑的是内存副本;「保存」写回原文件(盘点 YAML 会被转换为编辑器 JSON 形态保存)。
    /// 分析工具弹窗:事件/试探/任务/拓扑/发送(低频操作独立成窗,主界面只留查看主线)
    fn tool_windows(&mut self, ctx: &egui::Context) {
        // ---- 事件列表窗 ----
        if self.show_events {
            let mut open = self.show_events;
            let mut sel = self.sel;
            let mut sel_changed = false;
            egui::Window::new("异常事件")
                .open(&mut open)
                .default_width(560.0)
                .default_height(360.0)
                .show(ctx, |ui| {
                    let ds = self.ds.clone();
                    let Some(ds) = ds else {
                        ui.label(egui::RichText::new("未加载数据").color(dim(ui)));
                        return;
                    };
                    ui.horizontal(|ui| {
                        if ui.button("导出证据包(选中事件 ±10s)").clicked() {
                            self.export_evidence();
                        }
                        if ui.button("↻ 重跑规则(FR-3.7 热加载)").clicked() {
                            self.rerun_rules();
                        }
                        ui.label(
                            egui::RichText::new("点击事件行选中对应帧;无选中 = 全会话")
                                .size(10.5)
                                .color(dim(ui)),
                        );
                    });
                    ui.separator();
                    views::events_list(ui, &ds, sel, &mut sel);
                });
            self.show_events = open;
            if sel != self.sel {
                self.sel = sel;
                self.sel_path.clear();
                self.sync_plot_cursor();
                sel_changed = true;
            }
            let _ = sel_changed;
        }
        // ---- 试探窗 ----
        if self.show_probe {
            let mut open = self.show_probe;
            egui::Window::new("未知协议试探").open(&mut open).default_width(700.0).default_height(420.0).show(ctx, |ui| {
                self.probe_tab(ui);
            });
            self.show_probe = open;
        }
        // ---- 任务窗 ----
        if self.show_tasks {
            let mut open = self.show_tasks;
            egui::Window::new("规则任务").open(&mut open).default_width(620.0).default_height(380.0).show(ctx, |ui| {
                self.task_tab(ui);
            });
            self.show_tasks = open;
        }
        // ---- 拓扑窗 ----
        if self.show_topo {
            let mut open = self.show_topo;
            egui::Window::new("储能拓扑").open(&mut open).default_width(680.0).default_height(420.0).show(ctx, |ui| {
                self.topo_tab(ui);
            });
            self.show_topo = open;
        }
        // ---- 拓扑连线窗(A1):主机→模拟器设备链路健康;点设备节点 → 过滤到该设备的帧 ----
        if self.show_topolink {
            let mut open = self.show_topolink;
            let mut clicked: Option<usize> = None;
            // 跨实例展平全部设备(A3);dev_at 记录 (实例, 设备) 索引用于点击定位
            let mut devs: Vec<&crate::moddev::DevState> = vec![];
            let mut dev_at: Vec<(usize, usize)> = vec![];
            for (k, inst) in self.moddev_rts.iter().enumerate() {
                for (di, d) in inst.rt.devs.iter().enumerate() {
                    devs.push(d);
                    dev_at.push((k, di));
                }
            }
            egui::Window::new("拓扑连线(主机→模拟器)")
                .open(&mut open)
                .default_width(620.0)
                .default_height(320.0)
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new("连线颜色=链路健康:绿=主机已连/正常 · 红=断开或近期异常码 · 灰=无主机流量(自轮询不算);TCP 实线 / RTU 透传虚线。点设备节点 → 报文过滤到该设备")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    ui.separator();
                    views::topo_links(ui, "EMS/HMI", &devs, &mut clicked);
                });
            self.show_topolink = open;
            if let Some(i) = clicked {
                let name = dev_at
                    .get(i)
                    .and_then(|&(k, di)| self.moddev_rts.get(k).and_then(|inst| inst.rt.devs.get(di)))
                    .map(|d| d.meta.name.clone());
                if let Some(name) = name {
                    self.filter = format!("模拟·{name}");
                    self.rebuild_shown();
                    self.status = format!("已过滤到设备 {name}(通道别名 模拟·{name})");
                }
            }
        }
        // ---- 点位编辑窗(模拟联调主工位):全部点位就地改值 + 主机读到 + 临时点 + 回写点位表 ----
        if self.show_ptedit {
            let mut open = self.show_ptedit;
            let inst_i = self.moddev_inst_idx.min(self.moddev_rts.len().saturating_sub(1));
            let rt = self.moddev_rts.get(inst_i).map(|i| i.rt.clone());
            let label = self.moddev_rts.get(inst_i).map(|i| i.label()).unwrap_or_default();
            let yaml = self.moddev_rts.get(inst_i).map(|i| i.yaml.clone()).unwrap_or_default();
            egui::Window::new("点位编辑(模拟联调)")
                .open(&mut open)
                .default_width(940.0)
                .default_height(560.0)
                .show(ctx, |ui| {
                    if let Some(rt) = &rt {
                        self.ptedit_body(ui, rt, &label, &yaml);
                    } else {
                        ui.label(
                            egui::RichText::new("模拟器未运行——先在配置中心选「模拟联调」启动(或侧栏 kind=设备模拟器 → 选点位表并启动),再打开「点位编辑」")
                                .size(11.0)
                                .color(dim(ui)),
                        );
                    }
                });
            self.show_ptedit = open;
        }
        // ---- 单帧解码窗(W4):微信收到一帧 hex 秒解——同一 analyze 管线,语义层全可用 ----
        if self.show_single {
            let mut open = self.show_single;
            let mut decode_now = false;
            egui::Window::new("单帧解码")
                .open(&mut open)
                .default_width(680.0)
                .default_height(420.0)
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new("粘贴一帧立即解码(售后微信收帧/联调验帧):CAN 自动走 DBC+CANopen 语义层;UART 字节流走 Modbus/自定义识别。支持直接粘 candump 行(602#4017100...)")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.label("总线");
                        for (k, label) in [(0usize, "经典 CAN"), (1, "CAN FD"), (2, "UART 字节流")] {
                            if ui.selectable_label(self.single_kind == k, label).clicked() {
                                self.single_kind = k;
                            }
                        }
                    });
                    if self.single_kind <= 1 {
                        ui.horizontal(|ui| {
                            ui.label("ID(hex)");
                            ui.add(TextEdit::singleline(&mut self.single_id).desired_width(110.0).font(egui::TextStyle::Monospace));
                            ui.checkbox(&mut self.single_ext, "扩展帧(29bit)");
                            ui.checkbox(&mut self.single_dir_tx, "TX(本机发出)");
                        });
                    }
                    ui.horizontal(|ui| {
                        ui.label("数据(hex)");
                        ui.add(
                            TextEdit::singleline(&mut self.single_data)
                                .desired_width(ui.available_width() - 90.0)
                                .hint_text("11 22 33 44 55 66 77 88(空格/无空格均可;或直接粘 602#4017...)")
                                .font(egui::TextStyle::Monospace),
                        );
                        if ui.button("解码").clicked() {
                            decode_now = true;
                        }
                    });
                    ui.separator();
                    if decode_now {
                        self.decode_single_frame();
                    }
                    if let Some(ds) = &self.single_result {
                        // 解码结果:summary 内嵌解码语义(信号/OD/寄存器),事件单列
                        for f in &ds.frames {
                            ui.label(egui::RichText::new(format!("{} {}", f.dir.label(), f.summary)).monospace().size(12.0).color(txt(ui)));
                        }
                        for w in &ds.warnings {
                            ui.label(egui::RichText::new(format!("⚠ {w}")).size(10.0).color(Color32::from_rgb(235, 170, 80)));
                        }
                        if ds.events.is_empty() {
                            ui.label(egui::RichText::new("(无事件)").size(10.0).color(dim(ui)));
                        } else {
                            egui::ScrollArea::vertical().id_salt("single_events").max_height(160.0).auto_shrink([false, true]).show(ui, |ui| {
                                for e in &ds.events {
                                    ui.label(
                                        egui::RichText::new(format!("{:.3}s {:?} {}", e.t_ns as f64 / 1e9, e.kind, e.detail))
                                            .monospace()
                                            .size(11.0)
                                            .color(txt(ui)),
                                    );
                                }
                            });
                        }
                    }
                });
            self.show_single = open;
        }
        // ---- 串口终端窗(E1):设备 CLI/AT 命令交互;hex/文本双视图,单发/周期,同录 NDJSON 可回放 ----

        if self.show_terminal {
            let mut open = self.show_terminal;
            egui::Window::new("串口终端(设备 CLI/AT)")
                .open(&mut open)
                .default_width(700.0)
                .default_height(480.0)
                .show(ctx, |ui| {
                    // 连接栏
                    ui.horizontal(|ui| {
                        ui.label("串口");
                        let ports = terminal::list_ports();
                        if self.term_port.is_empty() {
                            if let Some(first) = ports.first() {
                                self.term_port = first.clone();
                            }
                        }
                        egui::ComboBox::from_id_salt("term_port")
                            .selected_text(self.term_port.clone())
                            .width(150.0)
                            .show_ui(ui, |ui| {
                                for p in &ports {
                                    ui.selectable_value(&mut self.term_port, p.clone(), p.clone());
                                }
                            });
                        ui.label("波特率");
                        egui::ComboBox::from_id_salt("term_baud")
                            .selected_text(format!("{}", self.term_baud))
                            .width(70.0)
                            .show_ui(ui, |ui| {
                                for b in [9600u32, 19200, 38400, 57600, 115200, 230400, 460800, 921600] {
                                    ui.selectable_value(&mut self.term_baud, b, format!("{b}"));
                                }
                            });
                        if self.term.is_some() {
                            if ui.button("⏹ 断开").clicked() {
                                if let Some(t) = self.term.take() {
                                    drop(t);
                                }
                                self.term_periodic = false;
                                self.status = "串口终端已断开".into();
                            }
                        } else if ui.button("▶ 连接").clicked() {
                            if self.term_port.is_empty() {
                                self.status = "串口终端:请选择端口".into();
                            } else {
                                let rp = if self.term_record {
                                    match self.term_record_path.clone() {
                                        Some(p) => Some(p),
                                        None => rfd::FileDialog::new()
                                            .set_file_name("term_session.ndjson")
                                            .add_filter("NDJSON", &["ndjson"])
                                            .save_file()
                                            .map(|p| {
                                                self.term_record_path = Some(p.clone());
                                                p
                                            }),
                                    }
                                } else {
                                    None
                                };
                                match terminal::open(&self.term_port, self.term_baud, rp) {
                                    Ok(h) => {
                                        self.term_err = None;
                                        self.status = format!("串口终端已连接 {}@{}(同录{})", self.term_port, self.term_baud, if self.term_record { "开" } else { "关" });
                                        self.term = Some(std::sync::Arc::new(h));
                                    }
                                    Err(e) => self.term_err = Some(e),
                                }
                            }
                        }
                        ui.checkbox(&mut self.term_hex, "HEX 视图");
                        ui.checkbox(&mut self.term_record, "同录 NDJSON");
                    });
                    if let Some(e) = &self.term_err {
                        ui.label(egui::RichText::new(format!("⚠ {e}")).size(10.5).color(Color32::from_rgb(235, 120, 100)));
                    }
                    ui.separator();
                    // 视图(贴底滚动;→=本机发出 ←=设备回)
                    ScrollArea::vertical()
                        .id_salt("term_view")
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            if let Some(t) = &self.term {
                                for l in t.snapshot() {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!("{:8.3}s", l.t_ms as f64 / 1000.0))
                                                .monospace()
                                                .size(10.0)
                                                .color(dim(ui)),
                                        );
                                        ui.label(egui::RichText::new(l.dir.mark()).size(10.5).color(if l.dir == terminal::TermDir::Tx {
                                            Color32::from_rgb(235, 170, 80)
                                        } else {
                                            dim(ui)
                                        }));
                                        let body = if self.term_hex {
                                            l.data.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
                                        } else {
                                            String::from_utf8_lossy(&l.data).replace('\r', "")
                                        };
                                        ui.label(egui::RichText::new(body).monospace().size(11.0).color(if l.dir == terminal::TermDir::Tx {
                                            Color32::from_rgb(235, 170, 80)
                                        } else {
                                            txt(ui)
                                        }));
                                    });
                                }
                            } else {
                                ui.label(egui::RichText::new("未连接:选端口/波特率后「▶ 连接」;发 AT 命令看回显(勾「同录 NDJSON」可离线回放进解析管线)").size(10.5).color(dim(ui)));
                            }
                        });
                    ui.separator();
                    // 发送区
                    ui.horizontal(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut self.term_input)
                                .hint_text("输入命令(AT/CLI);周期发送 = 按周期重复本框内容")
                                .desired_width(ui.available_width() * 0.55),
                        );
                        if let Some(t) = &self.term {
                            // 表单 → 线程共享态同步
                            *t.periodic_input.lock().unwrap_or_else(|e| e.into_inner()) = self.term_input.clone();
                            *t.interval_ms.lock().unwrap_or_else(|e| e.into_inner()) = self.term_interval_ms;
                            t.periodic.store(self.term_periodic && !self.term_input.is_empty(), Ordering::Relaxed);
                            if ui.button("发送").clicked() {
                                let mut bytes = self.term_input.clone().into_bytes();
                                if self.term_crlf && !bytes.is_empty() {
                                    bytes.extend_from_slice(b"\r\n");
                                }
                                match t.send_bytes(&bytes) {
                                    Ok(()) => self.term_err = None,
                                    Err(e) => self.term_err = Some(e),
                                }
                            }
                            ui.checkbox(&mut self.term_crlf, "追加CRLF");
                            ui.separator();
                            ui.checkbox(&mut self.term_periodic, "周期");
                            ui.add(egui::DragValue::new(&mut self.term_interval_ms).range(50..=60000).suffix("ms"));
                        } else {
                            ui.label(egui::RichText::new("连接后可发送").size(10.5).color(dim(ui)));
                        }
                    });
                });
            self.show_terminal = open;
        }
        // ---- 发送窗(安全敏感:独立窗口,锁定态显式解锁) ----
        if self.show_tx {
            let mut open = self.show_tx;
            egui::Window::new("CAN 发送(操作)")
                .open(&mut open)
                .default_width(520.0)
                .default_height(300.0)
                .show(ctx, |ui| {
                    self.tx_panel(ui);
                });
            self.show_tx = open;
        }
    }

    fn map104_editor_window(&mut self, ctx: &egui::Context) {
        if self.edit_map104.is_none() {
            return;
        }
        // 取出内存副本编辑(egui 闭包与 self 可变借用冲突的标准解法:窗口期间由局部变量持有)
        let mut map = self.edit_map104.take().unwrap();
        let path0 = self.edit_map104_path.clone();
        let mut open = true;
        let mut save_clicked = false;
        let mut save_as: Option<PathBuf> = None;
        egui::Window::new("IEC 104 点表编辑")
            .open(&mut open)
            .default_width(760.0)
            .default_height(480.0)
            .show(ctx, |ui| {
                let path_disp = path0
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(新建)".into());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(path_disp).monospace().size(11.0).color(dim(ui)));
                    if self.edit_map104_dirty {
                        ui.label(egui::RichText::new("●未保存").size(10.5).color(Color32::from_rgb(235, 170, 80)));
                    }
                    if ui.button("新增点").clicked() {
                        let ioa = map.points.iter().map(|p| p.ioa).max().unwrap_or(0) + 1;
                        map.points.push(iotprobe_core::dissect::map104::Pt104 {
                            ioa,
                            ty: 0,
                            ca: None,
                            name: String::new(),
                            factor: 1.0,
                            offset: 0.0,
                            unit: String::new(),
                            plot: true,
                        });
                        self.edit_map104_dirty = true;
                    }
                });
                ui.add_space(4.0);
                // 表头
                ui.horizontal(|ui| {
                    ui.set_min_width(700.0);
                    for (w, h) in [(52.0, "IOA"), (44.0, "类型"), (54.0, "CA"), (150.0, "工程名"), (70.0, "变比"), (66.0, "偏移"), (62.0, "单位"), (46.0, "曲线"), (40.0, "")] {
                        ui.set_min_width(w);
                        ui.label(egui::RichText::new(h).size(10.5).color(dim(ui)));
                    }
                });
                ui.separator();
                ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    let mut del: Option<usize> = None;
                    for (i, p) in map.points.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            // IOA/类型/CA 只读显示(改地址用删+增,避免键错乱)
                            ui.label(egui::RichText::new(format!("{}", p.ioa)).monospace().size(11.0));
                            ui.label(egui::RichText::new(if p.ty == 0 { "*".into() } else { format!("{}", p.ty) }).monospace().size(11.0).color(dim(ui)));
                            ui.label(egui::RichText::new(p.ca.map(|c| c.to_string()).unwrap_or_else(|| "*".into())).monospace().size(11.0).color(dim(ui)));
                            let resp = ui.add_sized([150.0, 18.0], egui::TextEdit::singleline(&mut p.name).hint_text("工程名"));
                            if resp.changed() { self.edit_map104_dirty = true; }
                            let mut fs = format!("{}", p.factor);
                            if ui.add_sized([70.0, 18.0], egui::TextEdit::singleline(&mut fs)).changed() {
                                if let Ok(v) = fs.trim().parse::<f64>() { p.factor = v; self.edit_map104_dirty = true; }
                            }
                            let mut os = format!("{}", p.offset);
                            if ui.add_sized([66.0, 18.0], egui::TextEdit::singleline(&mut os)).changed() {
                                if let Ok(v) = os.trim().parse::<f64>() { p.offset = v; self.edit_map104_dirty = true; }
                            }
                            let resp = ui.add_sized([62.0, 18.0], egui::TextEdit::singleline(&mut p.unit).hint_text("单位"));
                            if resp.changed() { self.edit_map104_dirty = true; }
                            if ui.checkbox(&mut p.plot, "").changed() { self.edit_map104_dirty = true; }
                            if ui.small_button("✕").clicked() { del = Some(i); }
                        });
                    }
                    if let Some(i) = del {
                        map.points.remove(i);
                        self.edit_map104_dirty = true;
                    }
                });
                ui.add_space(6.0);
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("保存").clicked() {
                        if path0.is_some() {
                            save_clicked = true;
                        } else {
                            save_as = rfd::FileDialog::new().add_filter("点表", &["yaml", "json"]).save_file();
                        }
                    }
                    if ui.button("另存为…").clicked() {
                        save_as = rfd::FileDialog::new().add_filter("点表", &["yaml", "json"]).save_file();
                    }
                    let can_apply = !self.last_files.is_empty();
                    if ui.add_enabled(can_apply, egui::Button::new("✔ 应用并重新加载")).clicked() {
                        // 先落盘(无路径则默认与数据集同名目录 points_104.yaml),再走标准重载
                        if path0.is_none() {
                            let def = self
                                .last_files
                                .first()
                                .and_then(|p| p.parent().map(|d| d.join("points_104.yaml")))
                                .unwrap_or_else(|| PathBuf::from("points_104.yaml"));
                            self.edit_map104_path = Some(def);
                        }
                        save_clicked = true;
                        let files = self.last_files.clone();
                        let name = self.ds.as_ref().map(|d| d.name.clone()).unwrap_or_default();
                        self.map104_path = self.edit_map104_path.clone();
                        self.start_load(files, name);
                    }
                    if !can_apply {
                        ui.label(egui::RichText::new("尚未加载过文件,改完先保存").size(10.5).color(dim(ui)));
                    }
                });
            });
        self.edit_map104 = Some(map); // 默认放回(未关闭/未保存都保留)
        if save_clicked {
            if let (Some(map), Some(p)) = (self.edit_map104.as_ref(), self.edit_map104_path.as_ref()) {
                match serde_json::to_string_pretty(map) {
                    Ok(json) => {
                        // 统一存 JSON(编辑器形态);YAML 生态由盘点脚本产出,GUI 保存 JSON 更稳
                        let path = if p.extension().map(|e| e != "json").unwrap_or(true) {
                            p.with_extension("json")
                        } else {
                            p.clone()
                        };
                        match std::fs::write(&path, json) {
                            Ok(_) => {
                                self.edit_map104_path = Some(path.clone());
                                self.edit_map104_dirty = false;
                                self.status = format!("点表已保存 {}", path.display());
                                self.save_session();
                            }
                            Err(e) => self.status = format!("保存失败: {e}"),
                        }
                    }
                    Err(e) => self.status = format!("序列化失败: {e}"),
                }
            }
        }
        if let Some(p) = save_as {
            if let Some(map) = self.edit_map104.as_ref() {
                if let Ok(json) = serde_json::to_string_pretty(map) {
                    let path = if p.extension().map(|e| e != "json").unwrap_or(true) { p.with_extension("json") } else { p.clone() };
                    if std::fs::write(&path, json).is_ok() {
                        self.edit_map104_path = Some(path);
                        self.edit_map104_dirty = false;
                        self.status = "点表已保存".into();
                        self.save_session();
                    }
                }
            }
        }
        if !open {
            if self.edit_map104_dirty {
                // 关闭时放弃未保存修改 —— 简单策略:直接丢,状态栏提示
                self.status = "点表编辑已关闭(未保存修改已丢弃)".into();
            }
            self.edit_map104 = None;
        }
    }

    /// 储能拓扑视图(MVP ③):设备卡片 + 异常高亮 + 点击信号跳帧。
    /// 无拓扑定义时提供「按信号前缀自动生成」——把 `unit1·` / `104 ` 等前缀归组为设备,
    /// 让首次使用不用手写 YAML 也能看到效果(之后可另存 YAML 细调)。
    fn topo_tab(&mut self, ui: &mut Ui) {
        let Some(ds) = self.ds.clone() else {
            ui.label(egui::RichText::new("未加载数据").color(dim(ui)));
            return;
        };
        if self.topo.is_none() {
            ui.label(egui::RichText::new("储能拓扑:把电池簇/PCS/电表等设备绑定到信号,一眼看出谁在告警。").size(11.5).color(dim(ui)));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("按信号前缀自动生成…").clicked() {
                    self.topo = Some(auto_topology(&ds));
                    self.topo_state = self
                        .topo
                        .as_ref()
                        .map(|topo| iotprobe_core::topology::evaluate(&ds, topo));
                    self.status = "已按信号前缀生成拓扑(可另存 YAML 细调)".into();
                }
                if ui.button("加载拓扑 YAML…").clicked() {
                    self.load_config_of("topo");
                }
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new("自动生成规则:信号键按 `unit{n}·`、`104 {名}·IOA{n}`、`CAN 0x…·` 前缀归组;阈值绑定留空,后续在 YAML 里补。").size(10.5).color(dim(ui)));
            return;
        }
        let topo = self.topo.clone().unwrap();
        let state = self.topo_state.clone().unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("{} — {} 台设备", topo.name, topo.devices.len())).size(11.5));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("保存 YAML…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().add_filter("拓扑", &["yaml"]).save_file() {
                        let yaml = iotprobe_core::topology::Topology::to_yaml(&topo);
                        match std::fs::write(&p, yaml) {
                            Ok(_) => {
                                self.topo_path = Some(p);
                                self.status = "拓扑已保存".into();
                                self.save_session();
                            }
                            Err(e) => self.status = format!("保存失败: {e}"),
                        }
                    }
                }
                if ui.small_button("重新评估").clicked() {
                    self.topo_state = Some(iotprobe_core::topology::evaluate(&ds, &topo));
                }
            });
        });
        ui.label(egui::RichText::new(format!("绑定覆盖:{} / {} 信号", ds.signals.len() - state.unbound, ds.signals.len())).size(10.5).color(dim(ui)));
        ui.add_space(4.0);
        ui.separator();

        // ---- 卡片网格 ----
        let card_w = 250.0;
        let mut jump: Option<u32> = None;
        let avail = ui.available_width();
        let cols = ((avail / card_w).floor() as usize).max(1);
        let health_color = |h: iotprobe_core::topology::Health| match h {
            iotprobe_core::topology::Health::NoData => Color32::from_rgb(120, 126, 136),
            iotprobe_core::topology::Health::Ok => Color32::from_rgb(110, 190, 120),
            iotprobe_core::topology::Health::Warn => Color32::from_rgb(235, 170, 80),
            iotprobe_core::topology::Health::Fault => Color32::from_rgb(230, 90, 80),
        };
        let kind_icon = |k: &str| match k {
            "cluster" => "🔋",
            "pcs" => "⚡",
            "meter" => "📊",
            _ => "📦",
        };
        egui::Grid::new("topo_cards").min_col_width(card_w).num_columns(cols).show(ui, |ui| {
            let mut cells = 0usize;
            for (d, st) in topo.devices.iter().zip(state.devices.iter()) {
                if cells % cols == 0 && cells > 0 {
                    ui.end_row();
                }
                cells += 1;
                let hc = health_color(st.health);
                egui::Frame::group(ui.style())
                    .fill(if st.health == iotprobe_core::topology::Health::Fault {
                        Color32::from_rgb(64, 30, 30)
                    } else if st.health == iotprobe_core::topology::Health::Warn {
                        Color32::from_rgb(62, 48, 26)
                    } else {
                        ui.style().visuals.panel_fill
                    })
                    .show(ui, |ui| {
                        ui.set_min_width(card_w - 12.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(kind_icon(&d.kind)).size(15.0));
                            ui.label(egui::RichText::new(&d.id).strong().size(12.5));
                            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                ui.label(egui::RichText::new(st.health.label()).size(10.5).color(hc).strong());
                                if st.event_n > 0 {
                                    ui.label(egui::RichText::new(format!("{} 异常", st.event_n)).size(10.5).color(Color32::from_rgb(230, 120, 100)));
                                }
                            });
                        });
                        if st.sigs.is_empty() {
                            ui.label(egui::RichText::new("(无绑定信号)").size(10.0).color(dim(ui)));
                        }
                        for s in &st.sigs {
                            ui.horizontal(|ui| {
                                let dot = match s.level {
                                    iotprobe_core::topology::Health::Fault => "●",
                                    iotprobe_core::topology::Health::Warn => "◐",
                                    _ => "·",
                                };
                                let sc = health_color(s.level);
                                if ui.button(egui::RichText::new(format!("{dot} {}: {}", s.bind_label, plot::fmt_val(s.last))).size(11.0).color(if s.level == iotprobe_core::topology::Health::Ok { dim(ui) } else { sc })).clicked() {
                                    jump = s.frame;
                                }
                                if !s.unit.is_empty() {
                                    ui.label(egui::RichText::new(&s.unit).size(10.0).color(dim(ui)));
                                }
                            });
                        }
                    });
            }
        });
        if let Some(fi) = jump {
            self.sel = Some(fi);
            self.sel_expanded = true;
            self.want_scroll = Some(fi);
            self.sync_plot_cursor();
        }
    }

    /// 绑定编辑器(简化:直接改 YAML 文本 + 应用,同时满足改阈值/改名/删设备)
    /// 完整表单化编辑留待 GUI 打磨;YAML 直改对工程师用户反而最快。
    fn agg_tab(&mut self, ui: &mut Ui) {
        let Some(ds) = self.ds.clone() else {
            ui.label(egui::RichText::new("未加载数据").color(dim(ui)));
            return;
        };
        if self.agg_cache.is_none() {
            self.agg_cache = Some(compute_agg(&ds));
        }
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("按 ID/单元聚合:最新值 · 频率 · 周期稳定性(FR-4.2 —— 一眼看出谁的周期抖了)").size(11.0).color(dim(ui)));
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let sort_lbl = if self.agg_sort == 0 { "排序:帧数" } else { "排序:抖动%" };
                if ui.button(sort_lbl).clicked() {
                    self.agg_sort = 1 - self.agg_sort;
                }
            });
        });
        ui.separator();
        let rows = self.agg_cache.as_ref().unwrap();
        if rows.is_empty() {
            ui.label(egui::RichText::new("无聚合目标").color(dim(ui)));
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            // 表头
            let mut sorted: Vec<&AggRow> = rows.iter().collect();
            if self.agg_sort == 1 {
                sorted.sort_by(|a, b| b.jitter_pct.total_cmp(&a.jitter_pct));
            } else {
                sorted.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
            }
            for r in sorted {
                let hot = r.jitter_pct > 25.0 && r.count >= 5;
                let kcol = if hot { Color32::from_rgb(255, 150, 60) } else { txt(ui) };
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&r.key).monospace().size(11.0).color(kcol));
                    ui.label(egui::RichText::new(&r.chan).monospace().size(10.5).color(dim(ui)));
                    ui.label(egui::RichText::new(format!("{}帧", r.count)).monospace().size(11.0).color(txt(ui)));
                    if r.mean_ms > 0.0 {
                        let dev_bad = r.dev_pct.map(|d| d.abs() > 20.0).unwrap_or(false);
                        let dcol = if dev_bad { Color32::from_rgb(255, 150, 60) } else { dim(ui) };
                        let per = match r.nominal_ms {
                            Some(nom) => format!("周期 {:.2}ms(标称 {nom}ms 偏差 {:+.0}%)", r.mean_ms, r.dev_pct.unwrap_or(0.0)),
                            None => format!("周期 {:.2}ms", r.mean_ms),
                        };
                        ui.label(egui::RichText::new(per).monospace().size(11.0).color(dcol));
                        let jcol = if hot { Color32::from_rgb(255, 150, 60) } else { dim(ui) };
                        ui.label(
                            egui::RichText::new(format!("抖动 σ {:.1}% (P95 {:.1}ms)", r.jitter_pct, r.p95_ms))
                                .monospace()
                                .size(11.0)
                                .color(jcol),
                        );
                    }
                    ui.label(egui::RichText::new(format!("末帧 {:.3}s", r.last_t as f64 / 1e9)).monospace().size(10.5).color(dim(ui)));
                });
                ui.label(egui::RichText::new(format!("   └ {}", r.last_summary)).monospace().size(10.5).color(dim(ui)));
            }
        });
    }

    fn task_tab(&mut self, ui: &mut Ui) {
        let Some(ds) = self.ds.clone() else {
            ui.label(egui::RichText::new("未加载数据").color(dim(ui)));
            return;
        };
        ui.label(
            egui::RichText::new(
                "轮询/重试类任务的关键指标:发出多少事务、几轮无响应、失败原因分布、每轮 RTT、最长连续失败段",
            )
            .size(11.0)
            .color(dim(ui)),
        );
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let mut shown_any = false;
            for c in &ds.channels {
                let is_modbus = matches!(
                    c.proto,
                    iotprobe_core::model::Proto::ModbusRtu | iotprobe_core::model::Proto::ModbusTcp
                );
                let st = task_stats(&ds, c);
                if !is_modbus && !st.both_dirs {
                    continue; // 无方向信息,无法配对
                }
                shown_any = true;
                ui.add_space(2.0);
                let pc = c.proto.color();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(c.proto.label()).size(11.0).color(Color32::from_rgb(pc[0], pc[1], pc[2])));
                    ui.label(egui::RichText::new(&c.label).size(11.5).monospace().color(txt(ui)));
                });
                egui::Grid::new(format!("task_{}_{}", c.source, c.id))
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("事务(请求帧)").size(11.0).color(dim(ui)));
                        ui.label(egui::RichText::new(format!("{}", st.tx)).monospace().size(11.5));
                        ui.end_row();
                        ui.label(egui::RichText::new("无响应(超时)").size(11.0).color(dim(ui)));
                        let tcol = if st.timeouts > 0 {
                            Color32::from_rgb(255, 90, 60)
                        } else {
                            Color32::from_rgb(140, 200, 100)
                        };
                        let pct = if st.tx > 0 { st.timeouts as f64 * 100.0 / st.tx as f64 } else { 0.0 };
                        ui.label(egui::RichText::new(format!("{} ({pct:.1}%)", st.timeouts)).monospace().size(11.5).color(tcol));
                        ui.end_row();
                        ui.label(egui::RichText::new("异常响应(协议码)").size(11.0).color(dim(ui)));
                        let ecol = if st.exceptions > 0 { Color32::from_rgb(255, 90, 60) } else { dim(ui) };
                        ui.label(egui::RichText::new(format!("{}", st.exceptions)).monospace().size(11.5).color(ecol));
                        ui.end_row();
                        if let Some((mn, md, p95, mx)) = st.rtt {
                            ui.label(egui::RichText::new("RTT min/中位/P95/max").size(11.0).color(dim(ui)));
                            ui.label(
                                egui::RichText::new(format!("{mn:.1} / {md:.1} / {p95:.1} / {mx:.1} ms"))
                                    .monospace()
                                    .size(11.5),
                            );
                            ui.end_row();
                        }
                        if let Some((n, t0, t1)) = st.worst_run {
                            if n >= 2 {
                                ui.label(egui::RichText::new("最长连续失败段").size(11.0).color(dim(ui)));
                                ui.label(
                                    egui::RichText::new(format!(
                                        "连续 {n} 次,{:.3}s ~ {:.3}s(跨度 {:.0}ms)",
                                        t0 as f64 / 1e9,
                                        t1 as f64 / 1e9,
                                        (t1 - t0) as f64 / 1e6
                                    ))
                                    .monospace()
                                    .size(11.5)
                                    .color(Color32::from_rgb(255, 120, 80)),
                                );
                                ui.end_row();
                            }
                        }
                        ui.label(egui::RichText::new("结果分布").size(11.0).color(dim(ui)));
                        let ok_n = st.tx.saturating_sub(st.timeouts + st.exceptions);
                        ui.label(
                            egui::RichText::new(format!("成功 {ok_n} · 超时 {} · 异常 {}", st.timeouts, st.exceptions))
                                .monospace()
                                .size(11.5),
                        );
                        ui.end_row();
                    });
                if !is_modbus {
                    ui.label(egui::RichText::new("按 RX/TX 交替估算(非 Modbus 协议,仅方向配对)").size(10.0).color(dim(ui)));
                }
                // ---- 写指令事务(A4):func5/6/15/16 请求-响应-RTT,EMS 下发的控制动作一目了然 ----
                if is_modbus {
                    let txns = write_txns(&ds, c);
                    let hdr = egui::CollapsingHeader::new(format!("写指令({}) — func5/6/15/16", txns.len()))
                        .default_open(false)
                        .show(ui, |ui| {
                            if txns.is_empty() {
                                ui.label(egui::RichText::new("(本通道无写指令:EMS 未下发 func5/6/15/16)").size(10.5).color(dim(ui)));
                                return;
                            }
                            let mut jump: Option<u32> = None;
                            egui::Grid::new(format!("wr_{}_{}", c.source, c.id))
                                .num_columns(6)
                                .striped(true)
                                .show(ui, |ui| {
                                    for t in &txns {
                                        ui.label(egui::RichText::new(format!("{:.3}s", t.t_ns as f64 / 1e9)).monospace().size(11.0).color(dim(ui)));
                                        ui.label(egui::RichText::new(format!("unit={}", t.unit)).monospace().size(11.0));
                                        let op = match t.func {
                                            5 => format!("写线圈 @{:#06x} = {}", t.addr, t.val),
                                            6 => format!("写寄存器 @{:#06x} = {}", t.addr, t.val),
                                            15 => format!("写多线圈 @{:#06x} × {}", t.addr, t.val),
                                            _ => format!("写多寄存器 @{:#06x} × {}", t.addr, t.val),
                                        };
                                        ui.label(egui::RichText::new(op).monospace().size(11.0));
                                        ui.label(
                                            egui::RichText::new(t.rtt_ms.map(|r| format!("{r:.1} ms")).unwrap_or_else(|| "-".into()))
                                                .monospace()
                                                .size(11.0)
                                                .color(dim(ui)),
                                        );
                                        let res = match (&t.resp_fi, t.exc) {
                                            (None, _) => ("无响应".to_string(), Color32::from_rgb(255, 90, 60)),
                                            (_, Some(code)) => (format!("异常码 {code:#04x}"), Color32::from_rgb(255, 90, 60)),
                                            (Some(_), None) => ("OK".to_string(), Color32::from_rgb(120, 200, 130)),
                                        };
                                        ui.label(egui::RichText::new(res.0).size(11.0).color(res.1));
                                        if ui.small_button("→帧").clicked() {
                                            jump = t.resp_fi.or(Some(t.req_fi));
                                        }
                                        ui.end_row();
                                    }
                                });
                            if let Some(fi) = jump {
                                self.sel = Some(fi);
                                self.want_scroll = Some(fi);
                                self.sel_path.clear();
                                self.sync_plot_cursor();
                                self.status = format!("已跳到写指令帧 #{fi}");
                            }
                        });
                    let _ = hdr;
                }
                ui.add_space(2.0);
                ui.separator();
            }
            if !shown_any {
                ui.label(egui::RichText::new("当前没有带方向信息(RX/TX)的通道,无法做事务配对。").size(11.0).color(dim(ui)));
            } else {
                ui.label(
                    egui::RichText::new(
                        "提示:无响应/异常事件可在「事件」页点击跳到对应时刻;RTT 已出现在左侧信号列表,勾选即画曲线。",
                    )
                    .size(10.5)
                    .color(dim(ui)),
                );
            }
        });
    }

    // ==================== 配置中心(整页) ====================
    // 设计:所有「要选的/要配的」收进本页,按功能分卡片;每张卡片上半=当前生效状态展示,下半=操作按钮。
    // 工作台页保持「看/分析」主线;展示类窗口(事件/试探/任务/拓扑/发送)仍是悬浮窗,入口在顶栏,两处开关同源联动。

    /// 配置中心整页:数据源 / 协议解析 / 规则引擎+设备模拟器(并排) / 实时接入 / 发送+界面诊断(并排)
    fn config_page(&mut self, ui: &mut Ui) {
        // ---- 任务卡阵(向导模式=主界面即向导:点击任务卡→进入该任务的每屏一步;专家视图=平铺) ----
        let step_totals = [3usize, 5, 3, 3, 0]; // 各场景步骤数(现场排故含产线抽测=5;全部配置=0)
        ui.horizontal(|ui| {
            let icons = ["📂", "🔧", "🤖", "🧪", "⚙"];
            // 进度口径(非技术状态):未开始 / 第N步 / 已完成
            let progress = |i: usize, s: &Self, dark: bool| -> (String, Color32) {
                let dim_c = if dark { Color32::from_rgb(120, 128, 140) } else { Color32::from_rgb(104, 112, 122) };
                let total = step_totals[i];
                if total == 0 {
                    return ("专家视图".into(), dim_c);
                }
                let any_sim = !s.moddev_rts.is_empty()
                    || s.moddev104_rt.is_some()
                    || s.moddev_custom_rt.is_some()
                    || s.moddev645_rt.is_some();
                let done_now = match i {
                    0 => s.ds.is_some(),
                    1 => !s.lives.is_empty(),
                    2 => s.ds.is_some(),
                    3 => any_sim,
                    _ => false,
                };
                let in_progress = match i {
                    1 => s.tx_unlocked, // 解锁了发送(抽测准备)但还没连源
                    _ => false,
                };
                if s.scene == i && s.wizard_mode {
                    (format!("第 {}/{} 步", s.wizard_step + 1, total), Color32::from_rgb(120, 180, 230))
                } else if done_now {
                    ("可继续".into(), Color32::from_rgb(120, 200, 130))
                } else if in_progress {
                    ("进行中".into(), Color32::from_rgb(235, 170, 80))
                } else {
                    ("未开始".into(), dim_c)
                }
            };

            for (i, (name, _desc)) in SCENES.iter().enumerate() {
                let sel = self.scene == i && (!self.wizard_mode || self.wizard_task == i);
                let border = if sel { Color32::from_rgb(120, 180, 230) } else { Color32::from_rgb(70, 76, 88) };
                let fill = if sel { Color32::from_rgb(38, 52, 72) } else { if ui.visuals().dark_mode { Color32::from_rgb(34, 38, 46) } else { Color32::from_rgb(238, 240, 244) } };
                let (ptxt, pcol) = progress(i, self, ui.visuals().dark_mode);
                let resp = egui::Frame::new()
                    .stroke(egui::Stroke::new(if sel { 2.0_f32 } else { 1.0_f32 }, border))
                    .fill(fill)
                    .corner_radius(6.0)
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width() / SCENES.len() as f32 - 10.0);
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(format!("{} {}", icons[i], name)).size(12.5).strong().color(if sel { txt(ui) } else { dim(ui) }));
                            ui.label(egui::RichText::new(ptxt).size(9.5).color(pcol));
                        });
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.clicked() {
                    // 向导模式:点任务卡=选定「这次做什么」,进入该任务的步骤(从头开始或继续)
                    if i < 4 {
                        self.wizard_mode = true;
                        self.wizard_task = i;
                        self.wizard_step = 0;
                    } else {
                        self.wizard_mode = false; // 全部配置=专家视图
                        self.wizard_task = usize::MAX;
                    }
                    self.scene = i;
                    self.save_session();
                }
                let _ = ptxt;
                let _ = pcol;
            }
        });
        ui.separator();

        // ---- 任务选择页(向导入口):未选任务 → 「这次想做什么?」用户语言任务卡(在下方滚动区渲染) ----
        let task_picking = self.wizard_mode && self.wizard_task == usize::MAX;
        if !self.wizard_mode {
            // 专家视图入口提示(向导可随时回来)
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🧭 返回向导模式(每屏一步)").size(10.5).color(dim(ui)));
                if ui.small_button("🧭 向导").clicked() {
                    self.wizard_mode = true;
                    self.wizard_task = usize::MAX;
                    self.wizard_step = 0;
                }
            });
        }

        // ---- 场景内容:任务选择页留白;全部配置=七卡铺开;其余=按任务步骤化(只显相关设置) ----
        ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if task_picking {
                self.task_picking_page(ui);
            } else if self.scene == 4 {
                self.expert_page(ui);
            } else if self.wizard_mode {
                // 向导模式:一屏一事(主界面即向导,不弹窗)
                self.wizard_screen(ui);
            } else {
                self.scene_steps(ui);
            }
        });
    }

    /// 场景步骤视图:每步复用既有卡片模块(不复制逻辑),步骤头带完成徽章(由状态推导)。
    fn scene_steps(&mut self, ui: &mut Ui) {
        match self.scene {
            0 => {
                // 离线分析(步骤合并 W2):打开+体检=一步(体检零点击自动出,单独成步是伪步骤)→ 挂协议(可跳过) → 工作台
                let done = self.ds.is_some();
                Self::step_card(ui, 1, "打开数据(打开即体检)", "ASC/pcap/candump/BLF/NDJSON 自动嗅探;体检随打开自动出结论(声明式阈值),一键 HTML 报告/批量回归", Some(done), |ui| {
                    self.card_data_source(ui);
                    ui.add_space(2.0);
                    self.card_checkup(ui);
                });
                let done = self.protocol_mounted();
                Self::step_card(ui, 2, "挂协议(可跳过)", "CAN 自动匹配 DBC;协议库多选合并解码(多 DBC 按 ID 命中);485/104/自定义在此挂载", Some(done), |ui| {
                    self.card_protocol(ui);
                });
                Self::step_card(ui, 3, "去工作台看曲线", "信号按报文分组,点组头 ◉ 整组上图", None, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("▶ 切到工作台(Ctrl+0)").clicked() {
                            self.page = 0;
                        }
                        ui.label(egui::RichText::new("图内:点击选帧 · Shift+点击测量 · 右键拖拽框选").size(10.5).color(dim(ui)));
                    });
                });
            }
            1 => {
                // 现场排故(S1,含产线抽测):连硬件 → 挂协议 → 挂规则 → 发送(可选) → 录制与证据包
                // B1 一键启动上次现场配置:源参数/录制路径/协议/规则包随会话持久化,第二次到现场单按钮恢复
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.lives.is_empty() && (self.live_form.kind != 3 || self.live_form.replay_path.is_some()),
                            egui::Button::new("▶ 一键启动上次现场配置"),
                        )
                        .on_hover_text("恢复上次源参数+开启录制+连接;协议与规则包随会话自动恢复;上次是模拟器则一键起模拟器")
                        .clicked()
                    {
                        self.quick_start_field();
                    }
                    ui.label(
                        egui::RichText::new(format!(
                            "上次配置:{} · 录制路径 {} · 规则包 {} 个",
                            live_kind_label(self.live_form.kind),
                            self.live_form
                                .record_path
                                .as_ref()
                                .map(|p| p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default())
                                .unwrap_or_else(|| "(未设)".into()),
                            self.rule_dirs.len()
                        ))
                        .size(10.5)
                        .color(dim(ui)),
                    );
                });
                ui.add_space(4.0);
                let done = !self.lives.is_empty();
                Self::step_card(ui, 1, "连接实时源", "六家 CAN 卡 / 串口 / TCP;只听默认开启", Some(done), |ui| {
                    self.card_live(ui);
                });
                let done = self.protocol_mounted();
                Self::step_card(ui, 2, "挂协议", "DBC 自动匹配;485 寄存器映射 / 104 点表", Some(done), |ui| {
                    self.card_protocol(ui);
                });
                let done = !self.rule_dirs.is_empty();
                Self::step_card(ui, 3, "挂规则与判定", "阈值 / 静默 / 变化率 → 事件;抽测判 PASS/FAIL 挂同一张卡;改 YAML 热加载", Some(done), |ui| {
                    self.card_rules(ui);
                });
                let done = self.tx_unlocked;
                Self::step_card(ui, 4, "发送激励(可选 · 产线抽测)", "白名单 + 显式解锁,窗口内操作;只看不发可跳过本步", Some(done), |ui| {
                    self.card_tx(ui);
                });
                Self::step_card(ui, 5, "录制与证据包", "录制开关在步骤1;故障复现/抽测留档一键证据包(全会话作测试记录)", None, |ui| {
                    self.evidence_actions(ui);
                });
            }
            2 => {
                // 数据喂 AI(S3):导出契约 JSONL → MCP 注册 → 对话
                let done = self.ds.is_some();
                Self::step_card(ui, 1, "导出契约 JSONL", "GUI 导出CSV 或 CLI dbg_analyze --export", Some(done), |ui| {
                    self.card_data_source(ui);
                });
                Self::step_card(ui, 2, "注册 MCP(ai-setup 打印即粘贴)", "ZCode/Trae/Cursor/Claude 片段一键生成", None, |ui| {
                    self.mcp_step_body(ui);
                });
                Self::step_card(ui, 3, "把这段话发给 AI", "实测:1169 帧回放 → 3 事件 → 证据帧号回跳", None, |ui| {
                    ui.label(
                        egui::RichText::new(
                            "「用 iot-probe 读回放文件 D:/data/sessions/modbus_rtu.frames.jsonl,列出全部事件;\n重点看 fault 级别,引用证据帧号;把上下文导出成 JSON 给我」",
                        )
                        .size(11.0)
                        .monospace(),
                    );
                });
            }
            3 => {
                // 模拟联调:启动模拟器 → 连源 → 挂规则
                // UX 摩擦修复:三种从机按协议折叠——标题带运行状态徽章,默认只展开未运行/正在用的那张
                // (四种从机折叠块抽成 simulators_folded,场景步骤与引导窗共用,零逻辑重复)
                let any_running = !self.moddev_rts.is_empty()
                    || self.moddev104_rt.is_some()
                    || self.moddev_custom_rt.is_some()
                    || self.moddev645_rt.is_some();
                Self::step_card(ui, 1, "启动设备模拟器(按协议折叠)", "本机扮演从机开端口:Modbus / IEC 104 / 自定义 DSL / DL/T 645;点位表驱动,可多类并行;Excel/文档→YAML 用 AI 转换指南", Some(any_running), |ui| {
                    self.simulators_folded(ui);
                });
                let done = !self.lives.is_empty();
                Self::step_card(ui, 2, "连接源", "模拟 CAN / TCP / 串口均可;模拟器数据自动入管线", Some(done), |ui| {
                    self.card_live(ui);
                });
                let done = !self.rule_dirs.is_empty();
                Self::step_card(ui, 3, "挂规则包", "对模拟寄存器值挂阈值/变化率规则", Some(done), |ui| {
                    self.card_rules(ui);
                });
            }
            _ => unreachable!("scene 4 = 全部配置,已在上方分支处理"),
        }
        // 模式确认摘要条:当前生效配置一览(全参数在上方卡片随时改,此处只汇总;与专家页头共用)
        ui.add_space(6.0);
        self.config_summary_line(ui);
        ui.add_space(10.0);
    }

    /// 当前生效配置摘要行(✅ 模式确认):场景步骤尾部与专家页头共用,同一口径。
    fn config_summary_line(&self, ui: &mut Ui) {
        let src_s = if !self.lives.is_empty() {
            format!("实时 {}", self.live_name)
        } else if self.ds.is_some() {
            format!("离线 {}", self.ds.as_ref().unwrap().name)
        } else {
            "未加载".into()
        };
        let proto_n = self.custom_paths.len() + self.dbc_paths.len() + self.map_path.iter().count() + self.map104_path.iter().count();
        let proto_s = if proto_n > 0 { format!("{} 项协议", proto_n) } else { "协议未挂".to_string() };
        let rules_s = if self.rule_dirs.is_empty() { "规则未挂".to_string() } else { format!("{} 规则包", self.rule_dirs.len()) };
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("✅ 模式确认:").size(10.5).color(dim(ui)));
            ui.label(egui::RichText::new(format!("数据源 {} · {} · {} · 转发 {}", src_s, proto_s, rules_s, if !self.lives.is_empty() && self.fwd_on { "开" } else { "关" })).size(10.5).color(txt(ui)));
            ui.label(egui::RichText::new("—— 全参数随时可改,改完重跑即生效").size(10.0).color(dim(ui)));
        });
    }

    /// 专家视图(全部配置):分组折叠 + 组头带生效摘要 —— 可售卖标准的页面结构:
    /// 页头即见当前生效配置;七卡按语义分三组(数据源与协议 / 实时接入与设备模拟 / 发送与界面),
    /// 组头右侧显示该组状态,默认全开、可收起(egui 按会话记忆开关);卡片内容与场景视图共用,零逻辑复制。
    fn expert_page(&mut self, ui: &mut Ui) {
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new(
                "全部配置(专家视图):按语义分三组;每张卡片上半是「当前生效状态」,下半是操作;改动后点「✔ 应用并重新加载」生效。",
            )
            .size(11.0)
            .color(dim(ui)),
        );
        ui.add_space(4.0);
        self.config_summary_line(ui);
        ui.add_space(6.0);
        let half = (ui.available_width() - 8.0) * 0.5;

        // ① 数据源与协议(离线分析的头两件事)
        let src_s = if self.ds.is_some() {
            format!("离线 {}", self.ds.as_ref().unwrap().name)
        } else if !self.lives.is_empty() {
            format!("实时 {}", self.live_name)
        } else {
            "未加载".into()
        };
        let proto_n = self.custom_paths.len() + self.dbc_paths.len() + self.map_path.iter().count() + self.map104_path.iter().count();
        let proto_s = if proto_n > 0 { format!("{proto_n} 项协议") } else { "协议未挂".to_string() };
        egui::CollapsingHeader::new(egui::RichText::new(format!("① 数据源与协议 —— {src_s} · {proto_s}")).size(13.0).strong())
            .default_open(true)
            .id_salt("expert_grp_data")
            .show(ui, |ui| {
                ui.add_space(2.0);
                self.card_data_source(ui);
                self.card_protocol(ui);
            });
        ui.add_space(6.0);

        // ② 实时接入与设备模拟(排故/联调的接入层)
        let live_s = if !self.lives.is_empty() { format!("已连 {}", self.live_name) } else { "未连接".to_string() };
        let sim_n = self.moddev_rts.len()
            + usize::from(self.moddev104_rt.is_some())
            + usize::from(self.moddev_custom_rt.is_some())
            + usize::from(self.moddev645_rt.is_some());
        let sim_s = if sim_n > 0 { format!("模拟器 {sim_n} 实例") } else { "模拟器未启动".to_string() };
        let rules_s = if self.rule_dirs.is_empty() { "规则未挂".to_string() } else { format!("{} 规则包", self.rule_dirs.len()) };
        egui::CollapsingHeader::new(egui::RichText::new(format!("② 实时接入与设备模拟 —— {live_s} · {sim_s} · {rules_s}")).size(13.0).strong())
            .default_open(true)
            .id_salt("expert_grp_live")
            .show(ui, |ui| {
                ui.add_space(2.0);
                self.card_live(ui);
                // 小卡并排:规则引擎 / 设备模拟器
                // allocate_ui 的子 UI 会继承 horizontal 的横向布局,必须显式 vertical,否则卡片内容挤成一行
                ui.horizontal(|ui| {
                    ui.allocate_ui(egui::vec2(half, 0.0), |ui| ui.vertical(|ui| self.card_rules(ui)));
                    ui.allocate_ui(egui::vec2(half, 0.0), |ui| ui.vertical(|ui| self.card_moddev(ui)));
                });
            });
        ui.add_space(6.0);

        // ③ 发送与界面(操作类收尾)
        let tx_s = if self.tx_unlocked { "发送已解锁" } else { "发送锁定" };
        egui::CollapsingHeader::new(egui::RichText::new(format!("③ 发送与界面 —— {tx_s}")).size(13.0).strong())
            .default_open(true)
            .id_salt("expert_grp_tx")
            .show(ui, |ui| {
                ui.add_space(2.0);
                // 小卡并排:发送 / 界面与诊断
                ui.horizontal(|ui| {
                    ui.allocate_ui(egui::vec2(half, 0.0), |ui| ui.vertical(|ui| self.card_tx(ui)));
                    ui.allocate_ui(egui::vec2(half, 0.0), |ui| ui.vertical(|ui| self.card_display(ui)));
                });
            });
        ui.add_space(10.0);
    }

    /// 步骤卡:编号 + 标题 + 完成徽章(由状态推导)+ 主体(复用卡片模块)。
    /// 关联函数(无 self 接收者):调用点的闭包要独占捕获 &mut self,与方法接收者借用冲突。
    fn step_card(ui: &mut Ui, no: usize, title: &str, hint: &str, done: Option<bool>, body: impl FnOnce(&mut Ui)) {
        egui::Frame::group(ui.style())
            .fill(if ui.visuals().dark_mode {
                Color32::from_rgb(30, 34, 42)
            } else {
                Color32::from_rgb(252, 253, 255)
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("步骤{no}")).size(11.0).strong().color(dim(ui)));
                    ui.label(egui::RichText::new(title).size(13.0).strong());
                    match done {
                        Some(true) => {
                            ui.label(egui::RichText::new("✓ 完成").size(11.0).color(Color32::from_rgb(120, 200, 130)));
                        }
                        Some(false) => {
                            ui.label(egui::RichText::new("○ 未完成").size(11.0).color(dim(ui)));
                        }
                        None => {}
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        ui.label(egui::RichText::new(hint).size(10.0).color(dim(ui)));
                    });
                });
                ui.separator();
                body(ui);
            });
        ui.add_space(2.0);
    }

    /// 协议配置是否有挂载(场景步骤完成徽章用)
    fn protocol_mounted(&self) -> bool {
        !self.dbc_paths.is_empty()
            || !self.custom_paths.is_empty()
            || !self.inline_specs.is_empty()
            || self.map_path.is_some()
            || self.map104_path.is_some()
            || self.topo_path.is_some()
    }

    /// 证据包/CSV 留档动作行(排故与抽测场景的收尾步骤)
    fn evidence_actions(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("🧾 导出证据包(选中事件 ±10s,无选中=全会话)").clicked() {
                self.export_evidence();
            }
            if ui
                .button("📋 复制为工单摘要(Markdown)")
                .on_hover_text("时间线+事件表+证据帧号;直接粘贴进售后工单/微信群,帧号可在 IoTProbe 回跳")
                .clicked()
            {
                self.copy_evidence_markdown(ui.ctx());
            }
            if ui.button("导出CSV").clicked() {
                self.export_csv();
            }
            if ui
                .button("📂 批量回归(选目录)")
                .on_hover_text("对目录内全部日志跑 解析+规则 → PASS/FAIL/WARN 汇总 HTML(带规则包与协议库);需同目录 batch_runner.exe")
                .clicked()
            {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    self.run_batch_regression(dir);
                }
            }
            ui.label(egui::RichText::new("先在事件窗口选中事件再导出=定向取证;无选中=全会话").size(10.5).color(dim(ui)));
        });
        let n = self.ds.as_ref().map(|d| d.events.len()).unwrap_or(0);
        ui.label(
            egui::RichText::new(if n > 0 {
                format!("当前数据集 {} 条事件(状态栏红色数字可点直达)", n)
            } else {
                "当前数据集 0 条事件;规则/诊断事件出现后在这里留档".into()
            })
            .size(10.5)
            .color(dim(ui)),
        );
    }

    /// 数据喂 AI 场景 · MCP 注册步骤体:ai-setup 片段 + 教程入口
    fn mcp_step_body(&mut self, ui: &mut Ui) {
        let exe = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().replace('\\', "\\\\"))
            .unwrap_or_else(|| "…\\target\\release\\iotprobe-mcp.exe".into());
        ui.label(
            egui::RichText::new(format!(
                "命令行执行: iotprobe-mcp ai-setup zcode   (或 trae | cursor | claude;ai-setup list 看清单)\n粘贴到 ZCode 全局 ~/.zcode/cli/mcp.json 或工作区 .zcode/mcp.json,重启客户端生效:"
            ))
            .size(10.5)
            .color(dim(ui)),
        );
        let snippet = format!(
            "{{\n  \"mcpServers\": {{\n    \"iot-probe\": {{\n      \"command\": \"{exe}\",\n      \"args\": [],\n      \"env\": {{}}\n    }}\n  }}\n}}"
        );
        ui.add(
            egui::TextEdit::multiline(&mut snippet.as_str())
                .desired_width(ui.available_width().min(560.0))
                .font(egui::TextStyle::Monospace),
        );
        ui.horizontal(|ui| {
            if ui.button("📖 打开 MCP 使用教程").clicked() {
                self.open_mcp_tutorial();
            }
            ui.label(
                egui::RichText::new("4 只读工具:list_devices / read_frames / query_events / export_context;prompt serbox-expert 内置专家打法")
                    .size(10.5)
                    .color(dim(ui)),
            );
        });
    }

    /// 用系统默认程序打开随包/仓库文档(发布包在 exe 同目录;开发态在 docs/)
    fn open_doc(&self, name: &str) {
        let mut candidates = vec![];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join(name));
                candidates.push(dir.join("docs").join(name));
                if let Some(up) = dir.parent() {
                    candidates.push(up.join("docs").join(name));
                }
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("docs").join(name));
            candidates.push(cwd.join(name));
            if let Some(up) = cwd.parent() {
                candidates.push(up.join("docs").join(name));
            }
        }
        if let Some(p) = candidates.into_iter().find(|p| p.exists()) {
            if let Some(dir) = p.parent() {
                let _ = std::process::Command::new("cmd")
                    .args(["/C", "start", "", &p.display().to_string()])
                    .current_dir(dir)
                    .spawn();
            }
        }
    }

    /// 用系统默认程序打开 MCP 教程
    fn open_mcp_tutorial(&self) {
        self.open_doc("MCP使用教程.md");
    }

    /// 卡片容器:圆角框 + 「标题 + 范围副标题」行;body 内自行组织「状态 → 操作」两段。
    /// 副标题 = 该卡职责边界一句话,卡与卡不重叠(功能纯粹一目了然)。
    fn config_card(title: &str, subtitle: &str, accent: Color32, ui: &mut Ui, body: impl FnOnce(&mut Ui)) {
        egui::Frame::group(ui.style())
            .fill(if ui.visuals().dark_mode {
                Color32::from_rgb(30, 34, 42)
            } else {
                Color32::from_rgb(252, 253, 255)
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(title).size(13.0).strong().color(accent));
                    ui.label(egui::RichText::new(subtitle).size(10.0).color(dim(ui)));
                });
                ui.separator();
                body(ui);
            });
        ui.add_space(2.0);
    }

    /// 「生效状态」段前缀
    fn state_prefix(ui: &mut Ui) {
        ui.label(egui::RichText::new("生效").size(10.5).color(dim(ui)));
    }

    /// 统一的「应用并重新加载」按钮(配置改动生效入口)
    fn apply_reload_btn(&mut self, ui: &mut Ui) {
        let can_apply = !self.last_files.is_empty();
        if ui
            .add_enabled(
                can_apply,
                egui::Button::new(egui::RichText::new("✔ 应用并重新加载").color(Color32::from_rgb(120, 200, 130))),
            )
            .clicked()
        {
            let files = self.last_files.clone();
            let name = self.ds.as_ref().map(|d| d.name.clone()).unwrap_or_default();
            self.start_load(files, name);
        }
        if !can_apply {
            ui.label(egui::RichText::new("尚未加载过文件(打开文件后可应用配置)").size(10.5).color(dim(ui)));
        }
    }

    /// 卡片:数据源(状态=当前数据集/实时源;操作=打开/示例/导出/重载)
    /// 单帧解码(W4):构造单帧 NDJSON → 同一 analyze 管线(当前 DBC/CANopen/自定义/Modbus 语义全可用)。
    /// 单帧解码(W4):多行粘贴(每行一帧)→ 同一 analyze 管线,同通道顺序进管线(配对/时序保留)。
    /// 每行 candump 嗅探(602#4017...)或使用 ID 框;UART 模式每行纯 hex 字节流。
    fn decode_single_frame(&mut self) {
        use iotprobe_core::ingest::live::{BusKind, LiveFrame};
        use iotprobe_core::model::{Dir, TsSrc};
        let mut records = vec![];
        let mut sess = iotprobe_core::ingest::live::LiveSession::new(None);
        let mut any = false;
        for (k, line_in) in self.single_data.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let mut ext = self.single_ext;
            let mut id: u32 = u32::from_str_radix(
                self.single_id.trim().trim_start_matches("0x").trim_start_matches("0X"),
                16,
            )
            .unwrap_or(0);
            let data_hex = line_in.replace(' ', "").replace('\t', "");
            let data_hex = if let Some(hash) = data_hex.find('#') {
                let id_s = data_hex[..hash].trim_start_matches(|c: char| !c.is_ascii_hexdigit()).to_string();
                if let Ok(v) = u32::from_str_radix(&id_s, 16) {
                    id = v;
                    ext = id > 0x7FF;
                }
                data_hex[hash + 1..].to_string()
            } else {
                data_hex
            };
            let data: Vec<u8> = (0..data_hex.len() / 2)
                .filter_map(|kk| u8::from_str_radix(&data_hex[kk * 2..kk * 2 + 2], 16).ok())
                .collect();
            if self.single_kind <= 1 && data.is_empty() {
                continue;
            }
            let (bus, id_v, id_ext) = match self.single_kind {
                0 => (BusKind::Can, id, ext),
                1 => (BusKind::CanFd, id, ext),
                _ => (BusKind::Uart, 0, false),
            };
            let f = LiveFrame {
                ts_ns: k as u64 * 1_000_000, // 行序=时序(1ms 间隔)
                ts_src: TsSrc::Wall,
                bus_type: bus,
                ch: 0,
                alias: Some("单帧解码".into()),
                dir: if self.single_dir_tx { Dir::Tx } else { Dir::Rx },
                id: id_v & 0x1FFF_FFFF,
                id_ext,
                dlc: data.len(),
                data,
                seq: None,
                meta_gap: None,
            };
            let line = crate::live::live_frame_to_jsonl(&f);
            if let Some(r) = sess.map_line(&line) {
                records.push(r);
                any = true;
            }
        }
        if !any {
            self.status = "单帧解码:无可解析的帧(检查格式:每行 602#4017... 或纯 hex)".into();
            return;
        }
        let sd = sess.into_source("单帧解码", records);
        let (mut cfg, _w) = load::build_cfg(&self.custom_paths, &self.inline_specs, &self.active_dbc_paths(), &self.map_path);
        if let Some(p) = &self.map104_path {
            let mut warns = vec![];
            load::load_map104(&mut cfg, p, &mut warns);
        }
        let mut ds = iotprobe_core::dissect::analyze(vec![sd], &cfg);
        let packs: Vec<_> = self
            .rule_dirs
            .iter()
            .filter_map(|p| iotprobe_core::rules::load_pack_dir(p).ok())
            .collect();
        if !packs.is_empty() {
            iotprobe_core::rules::reload_rules(&packs, &mut ds);
        }
        self.single_result = Some(Arc::new(ds));
    }

    /// 体检卡(MVP 离线分析):打开即出,零配置;阈值声明式透明

    fn card_checkup(&mut self, ui: &mut Ui) {
        let Some(ds) = self.ds.clone() else {
            ui.label(egui::RichText::new("未加载数据(体检随打开自动完成)").size(10.5).color(dim(ui)));
            return;
        };
        let ck = iotprobe_core::export::Checkup::from_dataset(&ds);
        let (verdict, why) = ck.verdict();
        let vcolor = match verdict {
            "PASS" => Color32::from_rgb(120, 200, 130),
            "WARN" => Color32::from_rgb(235, 170, 80),
            _ => Color32::from_rgb(235, 120, 100),
        };
        ui.label(
            egui::RichText::new(format!(
                "{} {} — {why}",
                match verdict {
                    "PASS" => "🟢",
                    "WARN" => "🟠",
                    _ => "🔴",
                },
                verdict
            ))
            .size(13.0)
            .color(vcolor),
        );
        let mut h = format!(
            "{} 帧 / {} 记录 / 跨度 {:.1}s / {} 通道 / fault {} · warn {} · info {} · 链路质量 {}",
            ck.frames, ck.records, ck.span_s, ck.channels, ck.faults, ck.warns, ck.infos, ck.gap_events
        );
        if let Some((hit, total)) = ck.dbc {
            let pct = if total > 0 { hit * 100 / total } else { 0 };
            h.push_str(&format!(" / DBC 覆盖 {}({}/{}){}", pct, hit, total, if total > hit { " ← 未命中可挂协议库" } else { "" }));
        }
        ui.label(egui::RichText::new(h).size(10.5).color(txt(ui)));
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui
                .button("📄 导出 HTML 报告")
                .on_hover_text("自包含可打印:体检结论+通道表+事件明细+信号统计;GUI/CLI/批量三入口同源")
                .clicked()
            {
                if let Some(p) = rfd::FileDialog::new()
                    .set_file_name(&format!("{}_report.html", ds.name.replace(' ', "_")))
                    .add_filter("HTML 报告", &["html"])
                    .save_file()
                {
                    match iotprobe_core::export::html_report(&ds, &ds.name, &p) {
                        Ok(n) => self.status = format!("HTML 报告已导出 {}({n} 字节)", p.display()),
                        Err(e) => self.status = format!("报告导出失败: {e}"),
                    }
                }
            }
            if ui
                .button("📂 批量回归(选目录)")
                .on_hover_text("对目录内全部日志跑 解析+规则 → PASS/FAIL/WARN 汇总 HTML(带规则包与协议库);需同目录 batch_runner.exe")
                .clicked()
            {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    self.run_batch_regression(dir);
                }
            }
            ui.label(egui::RichText::new("事件明细/帧号引用在事件窗与报告内").size(10.5).color(dim(ui)));
        });
        // verdict 下一步引导(体检卡不止"看",还指出去哪):
        ui.horizontal(|ui| {
            if ck.faults > 0 {
                if ui.button("🔴 打开事件窗看 fault 明细").clicked() {
                    self.show_events = true;
                }
            }
            if let Some((hit, total)) = ck.dbc {
                if total > hit {
                    ui.label(egui::RichText::new(format!("🟡 {} 帧 DBC 未命中 → 下一步「挂协议」(步骤 3)", total - hit)).size(10.5).color(dim(ui)));
                }
            }
            if ck.faults == 0 && ck.dbc.map(|(h, t)| t == 0 || h == t).unwrap_or(true) {
                ui.label(egui::RichText::new("数据健康 → 下一步「去工作台看曲线」(步骤 4)").size(10.5).color(dim(ui)));
            }
        });
    }

    /// 四种从机模拟器按协议折叠(场景步骤与引导窗共用,零逻辑重复)
    fn simulators_folded(&mut self, ui: &mut Ui) {
        let mb_st = if self.moddev_rts.is_empty() { "未运行".to_string() } else { format!("● 运行中 {} 实例", self.moddev_rts.len()) };
        let s104 = if self.moddev104_rt.is_some() { "● 运行中" } else { "未运行" };
        let sc = if self.moddev_custom_rt.is_some() { "● 运行中" } else { "未运行" };
        let s645 = if self.moddev645_rt.is_some() { "● 运行中" } else { "未运行" };
        egui::CollapsingHeader::new(egui::RichText::new(format!("Modbus 从机 —— {mb_st}")).color(if self.moddev_rts.is_empty() { dim(ui) } else { Color32::from_rgb(120, 200, 130) }))
            .default_open(self.moddev_rts.is_empty())
            .show(ui, |ui| self.card_moddev(ui));
        egui::CollapsingHeader::new(egui::RichText::new(format!("IEC 104 从机 —— {s104}")).color(if self.moddev104_rt.is_some() { Color32::from_rgb(120, 200, 130) } else { dim(ui) }))
            .default_open(false)
            .show(ui, |ui| self.card_moddev104(ui));
        egui::CollapsingHeader::new(egui::RichText::new(format!("自定义协议从机(JSON DSL) —— {sc}")).color(if self.moddev_custom_rt.is_some() { Color32::from_rgb(120, 200, 130) } else { dim(ui) }))
            .default_open(false)
            .show(ui, |ui| self.card_moddev_custom(ui));
        egui::CollapsingHeader::new(egui::RichText::new(format!("DL/T 645 电表从机 —— {s645}")).color(if self.moddev645_rt.is_some() { Color32::from_rgb(120, 200, 130) } else { dim(ui) }))
            .default_open(false)
            .show(ui, |ui| self.card_moddev645(ui));
        ui.horizontal(|ui| {
            if ui.button("📖 点位表格式与 AI 转换指南").clicked() {
                self.open_doc("点位表格式与AI转换指南.md");
            }
            ui.label(egui::RichText::new("厂商 Excel/文档 粘给 AI + 指南内提示词 → 得点位表 YAML").size(10.5).color(dim(ui)));
        });
    }

    /// 各场景步骤数(引导窗用;与 config_page 的 step_totals 及场景视图 step_card 数量保持同步)
    fn scene_step_count(&self, scene: usize) -> usize {
        match scene {
            0 => 3, // 打开+体检 / 挂协议 / 工作台
            1 => 5, // 连接 / 协议 / 规则 / 发送(可选·抽测) / 录制证据
            2 => 3, // 导出 / MCP / 喂 AI
            3 => 3, // 从机 / 连源 / 规则
            _ => 1,
        }
    }

    /// 任务选择页(用户语言):「这次想做什么?」——按用户处境措辞,不出现产品术语;熟手走「全部配置」。
    /// 选中 → wizard_task/step → config_page 渲染 wizard_screen(一屏一事)。
    fn task_picking_page(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        ui.label(egui::RichText::new("这次想做什么?").size(17.0).strong());
        ui.label(
            egui::RichText::new("选一个,只问这件事需要的参数;做完直接进工作台。随时可换(顶部任务卡 / 数字键 1~5 / 菜单「使用引导」)。")
                .size(10.5)
                .color(dim(ui)),
        );
        ui.add_space(8.0);
        // (图标, 用户的处境/问句, 会经过哪几步, 场景下标)
        let items: [(&str, &str, &str, usize); 5] = [
            ("📂", "我有一份日志/抓包,想知道里面发生了什么", "打开文件(自动体检) → 挂协议(可跳过) → 工作台看曲线与事件", 0),
            ("🔌", "设备就在手边,要抓实时数据排故(含产线抽测)", "连硬件 → 挂协议 → 挂规则 → 发激励(可选) → 留证据包", 1),
            ("🧪", "没有设备,想在本机模拟一台给上位机联调", "起模拟器 → 改点位值 → 盯规则", 3),
            ("🤖", "我想让 AI 帮我看数据", "导出契约 JSONL → 注册 MCP → 对话排障", 2),
            ("⚙", "我是熟手,直接改全部参数", "七张配置卡平铺(专家视图)", 4),
        ];
        let dark = ui.visuals().dark_mode;
        for (icon, q, steps, sc) in items {
            let resp = egui::Frame::new()
                .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(70, 76, 88)))
                .fill(if dark { Color32::from_rgb(34, 38, 46) } else { Color32::from_rgb(238, 240, 244) })
                .corner_radius(8.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(icon).size(24.0));
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(q).size(13.5).strong().color(txt(ui)));
                            ui.label(egui::RichText::new(steps).size(10.5).color(dim(ui)));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new(SCENES[sc].0).size(10.0).color(dim(ui)));
                        });
                    });
                })
                .response
                .interact(egui::Sense::click());
            let clicked = resp.clicked();
            if resp.hovered() {
                resp.highlight();
            }
            if clicked {
                // 向导任务(0~3)=选定「这次做什么」,从第一步开始;全部配置=专家视图
                if sc < 4 {
                    self.wizard_mode = true;
                    self.wizard_task = sc;
                    self.wizard_step = 0;
                } else {
                    self.wizard_mode = false;
                    self.wizard_task = usize::MAX;
                }
                self.scene = sc;
                self.save_session();
            }
            ui.add_space(6.0);
        }
        ui.label(
            egui::RichText::new("到过现场?选「设备就在手边」后,第一步可一键恢复上次现场配置。")
                .size(10.0)
                .color(dim(ui)),
        );
        ui.add_space(10.0);
    }

    /// 向导屏(主界面即向导,不弹窗):一屏一事 —— 问句标题 + 只露必填子块 + 就地结果 + 门控的下一步;
    /// 完成即进工作台(wizard_finish)。子块复用卡片的分块渲染(live_form_parts / card_data_source_parts),零逻辑重复。
    fn wizard_screen(&mut self, ui: &mut Ui) {
        let t = self.wizard_task.min(3);
        let total = self.scene_step_count(t);
        let step = self.wizard_step.min(total - 1);
        let (title, hint) = self.wizard_step_title(t, step);
        let icons = ["📂", "🔧", "🤖", "🧪"];
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("{} {}", icons[t], title)).size(15.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new(format!("第 {}/{} 步 · {}", step + 1, total, SCENES[t].0)).size(10.0).color(dim(ui)));
            });
        });
        ui.label(egui::RichText::new(hint).size(10.5).color(dim(ui)));
        ui.add_space(4.0);
        // 主体:只露本步必填子块
        egui::Frame::group(ui.style())
            .fill(if ui.visuals().dark_mode { Color32::from_rgb(30, 34, 42) } else { Color32::from_rgb(252, 253, 255) })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                self.wizard_step_body(ui, t, step);
            });
        // 就地结果:✓ 已就绪 / ○ 还差什么(由状态推导,不靠用户自觉);可选步直接说明
        ui.add_space(4.0);
        let gate = self.wizard_step_gate(t, step);
        let ready = match &gate {
            Some((true, txt)) => {
                ui.label(egui::RichText::new(format!("✓ {txt}")).size(11.0).color(Color32::from_rgb(120, 200, 130)));
                true
            }
            Some((false, txt)) => {
                ui.label(egui::RichText::new(format!("○ {txt}")).size(11.0).color(Color32::from_rgb(235, 170, 80)));
                false
            }
            None => {
                ui.label(egui::RichText::new("○ 本步可选(不改也能下一步)").size(10.0).color(dim(ui)));
                true
            }
        };
        // 导航:上一步 / 下一步(门控) / 完成 → 工作台
        ui.separator();
        ui.horizontal(|ui| {
            if ui.small_button("↩ 换个任务").clicked() {
                self.wizard_task = usize::MAX;
                self.wizard_step = 0;
            }
            if step > 0 && ui.button("← 上一步").clicked() {
                self.wizard_step = step - 1;
            }
            if step + 1 < total {
                let b = ui.add_enabled(ready, egui::Button::new(egui::RichText::new("下一步 →").strong()));
                if b.clicked() {
                    self.wizard_step = step + 1;
                }
            } else if ui.button(egui::RichText::new("✔ 完成,进入工作台").strong()).clicked() {
                self.wizard_finish(t);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .small_button("⚙ 全部参数(专家视图)")
                    .on_hover_text("七张配置卡平铺;向导随时可从菜单「使用引导」或顶部任务卡回来")
                    .clicked()
                {
                    self.wizard_mode = false;
                    self.wizard_task = usize::MAX;
                    self.scene = 4;
                }
            });
        });
        ui.add_space(10.0);
    }

    /// 向导屏标题:问句 + 一句提示(用户语言;不写内部状态名)
    fn wizard_step_title(&self, t: usize, step: usize) -> (&'static str, &'static str) {
        match (t, step) {
            (0, 0) => ("日志文件在哪?", "ASC / pcap / candump / BLF / NDJSON 自动识别;打开即体检,结论就在下面"),
            (0, 1) => ("用什么协议解码?(不确定可跳过)", "CAN 自动匹配 DBC;485 寄存器映射 / 104 点表 / 自定义协议在此挂载"),
            (0, 2) => ("开始看", "工作台:信号按报文分组,点组头 ◉ 整组上图;点击选帧 · Shift+点击测量 · 右键框选"),
            (1, 0) => ("设备接在哪?", "选源类型 → 填参数 → 点「连接」;要留档就勾录制。到过现场的可一键恢复上次配置"),
            (1, 1) => ("用什么协议解码?(不确定可跳过)", "DBC 自动匹配;485 寄存器映射 / 104 点表"),
            (1, 2) => ("要盯什么?(阈值 / 静默 / 变化率;可跳过)", "挂 YAML 规则包 → 事件;抽测判 PASS/FAIL 挂同一张卡;改 YAML 热加载"),
            (1, 3) => ("要发激励吗?(可选 · 产线抽测)", "白名单 + 显式解锁后在窗口内操作;只看不发直接下一步"),
            (1, 4) => ("留档:证据包 / CSV / 批量回归", "故障复现或抽测留档;证据包含时间线 + 事件表 + 证据帧号"),
            (2, 0) => ("数据从哪来?", "打开日志或示例;AI 读的是从这里导出的契约 JSONL"),
            (2, 1) => ("注册到你的 AI 工具", "ZCode / Trae / Cursor / Claude 片段一键生成,粘贴即用"),
            (2, 2) => ("把这段话发给 AI", "实测:1169 帧回放 → 3 事件 → 证据帧号回跳"),
            (3, 0) => ("模拟哪台设备?", "按协议展开 → 选点位表 → 启动;厂商 Excel/文档转 YAML 用 AI 转换指南"),
            (3, 1) => ("上位机或采集端怎么连?(可跳过)", "模拟器自轮询已把数据送进管线;只有要让 IoTProbe 当主机去读模拟器时才需要连源"),
            (3, 2) => ("盯哪些值?顺手改点位值", "规则对模拟值生效;改值 / 钉住 / 「主机读到」在点位编辑窗"),
            _ => ("", ""),
        }
    }

    /// 本步是否必须先有结果(下一步门控):Some((就绪, 提示)) / None=可选步。提示写用户的下一个动作,不写内部状态名
    fn wizard_step_gate(&self, t: usize, step: usize) -> Option<(bool, String)> {
        match (t, step) {
            (0, 0) | (2, 0) => match &self.ds {
                Some(ds) => Some((true, format!("已加载 {}:{} 帧 · {} 信号", ds.name, ds.frames.len(), ds.signals.len()))),
                None => Some((false, "还没有数据:点「📂 打开文件…」选日志,或点「示例」".into())),
            },
            (1, 0) => {
                if !self.lives.is_empty() {
                    Some((
                        true,
                        format!(
                            "已连接「{}」:收 {} 帧{}",
                            self.live_name,
                            self.live_stats.ok,
                            if self.live_form.record { " · 录制中" } else { "" }
                        ),
                    ))
                } else {
                    Some((false, "还没连上:选好源类型、填好参数后点「连接」".into()))
                }
            }
            (3, 0) => {
                let n = self.moddev_rts.len()
                    + usize::from(self.moddev104_rt.is_some())
                    + usize::from(self.moddev_custom_rt.is_some())
                    + usize::from(self.moddev645_rt.is_some());
                if n > 0 {
                    Some((true, format!("模拟器运行中:{n} 个实例,上位机可按端点连入;下一步改点位值或盯规则")))
                } else {
                    Some((false, "还没启动:展开协议 → 选点位表 → 点「启动」".into()))
                }
            }
            _ => None,
        }
    }

    /// 向导屏主体:按 (任务, 步) 渲染必填子块(复用卡片 / 分块渲染;专家卡片不被复制)
    fn wizard_step_body(&mut self, ui: &mut Ui, t: usize, step: usize) {
        match (t, step) {
            (0, 0) => {
                self.card_data_source_parts(ui, 3);
                ui.add_space(4.0);
                self.card_checkup(ui);
            }
            (0, 1) | (1, 1) => self.card_protocol(ui),
            (0, 2) => {
                ui.horizontal(|ui| {
                    if ui.button("▶ 现在就去工作台(Ctrl+0)").clicked() {
                        self.page = 0;
                    }
                    ui.label(egui::RichText::new("图内:点击选帧 · Shift+点击测量 · 右键拖拽框选;规则未挂也能看曲线").size(10.5).color(dim(ui)));
                });
            }
            (1, 0) => {
                // 一键恢复上次现场配置(未连接时可用;quick_start_field 已连接会拒绝)
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.lives.is_empty() && (self.live_form.kind != 3 || self.live_form.replay_path.is_some()),
                            egui::Button::new("▶ 一键恢复上次现场配置"),
                        )
                        .on_hover_text("恢复上次源参数 + 开启录制 + 连接;协议与规则包随会话自动恢复;上次是模拟器则一键起模拟器")
                        .clicked()
                    {
                        self.quick_start_field();
                    }
                    ui.label(
                        egui::RichText::new(format!("上次:{} · 规则包 {} 个", live_kind_label(self.live_form.kind), self.rule_dirs.len()))
                            .size(10.0)
                            .color(dim(ui)),
                    );
                });
                ui.separator();
                self.live_form_parts(ui, 1 | 2 | 4 | 16);
            }
            (1, 2) => self.card_rules(ui),
            (3, 2) => {
                self.card_rules(ui);
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button("⛶ 打开点位编辑(改值 · 钉住 · 主机读到 · 临时点)").clicked() {
                        self.show_ptedit = true;
                    }
                    ui.label(egui::RichText::new("改完立即生效;📌 钉住的点 Random 场景不动").size(10.0).color(dim(ui)));
                });
            }
            (1, 3) => self.card_tx(ui),
            (1, 4) => self.evidence_actions(ui),
            (2, 0) => self.card_data_source_parts(ui, 3),
            (2, 1) => self.mcp_step_body(ui),
            (2, 2) => {
                ui.label(
                    egui::RichText::new(
                        "「用 iot-probe 读回放文件 D:/data/sessions/modbus_rtu.frames.jsonl,列出全部事件;\n重点看 fault 级别,引用证据帧号;把上下文导出成 JSON 给我」",
                    )
                    .size(11.0)
                    .monospace(),
                );
            }
            (3, 0) => self.simulators_folded(ui),
            (3, 1) => self.card_live(ui),
            _ => {}
        }
    }

    /// 向导完成 → 工作区:工作台(曲线/事件);模拟联调同时打开点位编辑(改值 / 钉住 / 主机读到)
    fn wizard_finish(&mut self, t: usize) {
        self.page = 0;
        if t == 3 {
            self.show_ptedit = true;
        }
        self.status = format!("已进入「{}」:配置即生效,全参数随时可改", SCENES[t].0);
        self.save_session();
    }

    fn card_data_source(&mut self, ui: &mut Ui) {
        self.card_data_source_parts(ui, 3);
    }

    /// 数据源卡分块(向导一屏只露必填):位 1=当前状态 2=操作(打开/示例/导出/重载)
    fn card_data_source_parts(&mut self, ui: &mut Ui, parts: u8) {
        Self::config_card("数据源", "数据的进与出:打开日志 · 示例 · 导出CSV · 重载当前", Color32::from_rgb(120, 180, 230), ui, |ui| {
            Self::state_prefix(ui);
            if parts & 1 != 0 {
            match self.ds.clone() {
                Some(ds) => {
                    let mut protos: Vec<&str> = vec![];
                    for f in &ds.frames {
                        let l = f.proto.label();
                        if !protos.contains(&l) {
                            protos.push(l);
                        }
                    }
                    ui.label(
                        egui::RichText::new(format!(
                            "{} · {}帧 · {}信号 · 0~{:.1}s",
                            ds.name,
                            ds.frames.len(),
                            ds.signals.len(),
                            ds.t_max_ns() as f64 / 1e9
                        ))
                        .size(11.5)
                        .strong(),
                    );
                    ui.label(egui::RichText::new(protos.join(" + ")).size(10.5).color(dim(ui)));
                }
                None => {
                    ui.label(
                        egui::RichText::new("未加载数据(点下方「📂 打开文件…」或「示例」)")
                            .size(11.0)
                            .color(dim(ui)),
                    );
                }
            }
            if !self.lives.is_empty() {
                ui.label(
                    egui::RichText::new(format!(
                        "● 实时「{}」: 收 {} 帧 · 坏 {} · 丢 {}",
                        self.live_name, self.live_stats.ok, self.live_stats.bad, self.live_stats.gaps
                    ))
                    .size(10.5)
                    .color(Color32::from_rgb(120, 200, 130)),
                );
            }
            }
            if parts & 2 != 0 {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("📂 打开文件…").clicked() {
                    self.open_files();
                }
                if ui.button("示例").clicked() {
                    self.try_load_demo();
                }
                if ui.button("导出CSV").clicked() {
                    self.export_csv();
                }
                if ui.button("↻ 重新加载").clicked() {
                    let files = self.last_files.clone();
                    if !files.is_empty() {
                        let name = self.ds.as_ref().map(|d| d.name.clone()).unwrap_or_default();
                        self.start_load(files, name);
                    } else {
                        self.status = "尚无已加载文件可重载".into();
                    }
                }
            });
            }
        });
    }

    /// 卡片:协议解析(自定义 JSON / DBC 库 / 寄存器映射 / 104 点表 / 拓扑;原「模板管理」收编于此)
    fn card_protocol(&mut self, ui: &mut Ui) {
        Self::config_card(
            "协议解析(模板)",
            "解码规则从哪来:自定义 JSON · DBC 库 · 寄存器映射 · 104 点表 · 拓扑定义",
            Color32::from_rgb(210, 160, 235),
            ui,
            |ui| {
            self.template_ui(ui);
        });
    }

    /// 规则包挂载/热加载(自模板管理拆出,独立卡片)
    fn rules_ui(&mut self, ui: &mut Ui) {
        if self.rule_dirs.is_empty() {
            ui.label(egui::RichText::new("(无)").size(11.0).color(dim(ui)));
        }
        let mut removed_rule: Option<PathBuf> = None;
        for p in &self.rule_dirs {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default())
                        .monospace()
                        .size(11.0),
                );
                if ui.small_button("移除").clicked() {
                    removed_rule = Some(p.clone());
                }
            });
        }
        if let Some(p) = removed_rule {
            self.rule_dirs.retain(|x| *x != p);
            self.status = "已移除规则包,点「✔ 应用并重新加载」生效".into();
            self.save_session();
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("+ 挂载规则包…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    self.rule_dirs.push(p);
                    self.save_session();
                    self.status = "规则包已添加,点「✔ 应用并重新加载」生效".into();
                }
            }
            if ui.button("↻ 重跑规则(热加载)").clicked() {
                self.rerun_rules();
            }
        });
        self.apply_reload_btn(ui);
    }

    fn card_rules(&mut self, ui: &mut Ui) {
        Self::config_card("规则引擎(ADR-6)", "何时报事件:挂 YAML 规则包(阈值/静默/变化率)→ 事件,热加载", Color32::from_rgb(80, 150, 240), ui, |ui| {
            Self::state_prefix(ui);
            ui.label(
                egui::RichText::new("YAML 规则包:on_signal 阈值/持续 · on_timeout 静默 · on_frame 匹配 · on_rate 变化率")
                    .size(10.5)
                    .color(dim(ui)),
            );
            self.rules_ui(ui);
        });
    }

    /// 卡片:设备模拟器(Modbus 从机,独立启停;原顶栏快捷键收编)
    /// 点位编辑窗体(模拟联调主工位):就地改值/过滤/分组/主机读到/临时点/回写
    fn ptedit_body(&mut self, ui: &mut Ui, rt: &std::sync::Arc<crate::moddev::ModDevRuntime>, label: &str, yaml: &std::path::Path) {
        // 顶行:实例 + 设备选择 + 场景 + 释放全部
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(label).size(11.0).color(Color32::from_rgb(120, 200, 130)));
            if rt.devs.len() > 1 {
                let dev_i = self.moddev_dev_idx.min(rt.devs.len() - 1);
                let sel = rt.devs.get(dev_i).map(|d| format!("dev{} {}", d.meta.id, d.meta.name)).unwrap_or_default();
                egui::ComboBox::from_id_salt("ptedit_dev").selected_text(sel).show_ui(ui, |ui| {
                    for (i, d) in rt.devs.iter().enumerate() {
                        ui.selectable_value(&mut self.moddev_dev_idx, i, format!("dev{} {}({}点)", d.meta.id, d.meta.name, d.meta.points.len()));
                    }
                });
            }
            ui.separator();
            ui.label("场景");
            let sc = { *rt.scene.lock().unwrap_or_else(|e| e.into_inner()) };
            for (sc_i, lb) in [
                (crate::moddev::Scene::Normal, "Normal 静止"),
                (crate::moddev::Scene::Random, "Random 随机"),
                (crate::moddev::Scene::Fault, "Fault 故障"),
            ] {
                if ui.selectable_label(sc == sc_i, lb).clicked() {
                    *rt.scene.lock().unwrap_or_else(|e| e.into_inner()) = sc_i;
                    self.status = format!("模拟器场景 → {lb}(📌 已置点位不受影响)");
                }
            }
            if ui
                .small_button("释放全部钉住")
                .on_hover_text("释放全部 📌 已置点位(它们此前不被 Normal/Random/Fault 改动)")
                .clicked()
            {
                let n = rt.release_all_pins(self.moddev_dev_idx);
                self.status = format!("已释放 {n} 个钉住点位");
            }
        });
        // 工具行:搜索 + 过滤
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            ui.add(TextEdit::singleline(&mut self.moddev_filter).hint_text("搜索点位名/分组…").desired_width(160.0).font(egui::TextStyle::Small));
            ui.checkbox(&mut self.moddev_only_rw, "只看主机可写").on_hover_text("点位表 rw:1 的点位;其余点(如遥测)模拟器侧也能改——那是在\"设定被测量\"");
            ui.checkbox(&mut self.moddev_only_pinned, "只看已置");
            ui.checkbox(&mut self.moddev_only_host, "只看主机读过");
        });
        let dev_i = self.moddev_dev_idx.min(rt.devs.len().saturating_sub(1));
        // 采样一拍(500ms 节流):sparkline 列数据源
        if let Some(d) = rt.devs.get(dev_i) {
            d.sample_if_due();
        }
        let all = rt.points_view(dev_i, &self.moddev_filter);
        let rows: Vec<crate::moddev::PointRow> = all
            .into_iter()
            .filter(|r| (!self.moddev_only_rw || r.rw) && (!self.moddev_only_pinned || r.pinned) && (!self.moddev_only_host || r.host.is_some()))
            .collect();
        let shown = rows.len();
        let total = rt.devs.get(dev_i).map(|d| d.meta.points.len()).unwrap_or(0);
        // 表头
        ui.horizontal(|ui| {
            for (w, t) in [(150.0, "点位"), (115.0, "值(就地改)"), (132.0, "近 32 拍"), (88.0, "类型·RW"), (168.0, "主机读到"), (72.0, "钉住")] {
                ui.add_sized([w, 15.0], egui::Label::new(egui::RichText::new(t).size(9.5).color(dim(ui))).truncate());
            }
        });
        ui.separator();
        // 分组(保序合并同名分组)
        let mut groups: Vec<(String, Vec<crate::moddev::PointRow>)> = vec![];
        for r in rows {
            if let Some((_, v)) = groups.iter_mut().find(|(g, _)| *g == r.grp) {
                v.push(r);
            } else {
                groups.push((r.grp.clone(), vec![r]));
            }
        }
        egui::ScrollArea::vertical().id_salt("ptedit_rows").max_height(300.0).show(ui, |ui| {
            for (grp, grs) in &groups {
                egui::CollapsingHeader::new(egui::RichText::new(format!("{grp} · {} 点", grs.len())).size(10.5))
                    .default_open(true)
                    .id_salt(("ptgrp", dev_i, grp.as_str()))
                    .show(ui, |ui| {
                        for r in grs {
                            self.ptedit_row(ui, rt, dev_i, r);
                        }
                    });
            }
            if groups.is_empty() {
                ui.label(egui::RichText::new("(无匹配点位)").size(10.5).color(dim(ui)));
            }
        });
        ui.label(
            egui::RichText::new(format!("显示 {shown}/{total} 点位 · 值改完立即写入并 📌 钉住(场景不再改动;释放回到场景驱动)"))
                .size(9.5)
                .color(dim(ui)),
        );
        // ---- 临时点:点位表没定义、现在就要试的寄存器 ----
        ui.separator();
        ui.horizontal(|ui| {
            let t = if self.moddev_temp_open { "▾ 临时点:点位表没定义、现在就要试的寄存器" } else { "▸ 临时点:点位表没定义、现在就要试的寄存器" };
            if ui.selectable_label(self.moddev_temp_open, t).clicked() {
                self.moddev_temp_open = !self.moddev_temp_open;
            }
            if !self.moddev_temp.is_empty() {
                ui.label(egui::RichText::new(format!("本会话 {} 个", self.moddev_temp.len())).size(10.0).color(dim(ui)));
                if ui
                    .button("回写点位表")
                    .on_hover_text(format!("追加 dev{{N}}_临时点位 分节到 {}(重启模拟器后生效;已存在同名分节会拒绝,避免重复键)", yaml.display()))
                    .clicked()
                {
                    match moddev_writeback(yaml, &self.moddev_temp) {
                        Ok(n) => {
                            self.status = format!("已回写 {n} 个临时点到 {}(重启模拟器生效)", yaml.display());
                            self.moddev_temp.clear();
                        }
                        Err(e) => self.status = format!("回写失败:{e}"),
                    }
                }
            }
        });
        if self.moddev_temp_open {
            ui.horizontal(|ui| {
                ui.label("名称");
                ui.add_sized([110.0, 17.0], egui::TextEdit::singleline(&mut self.tmp_name).hint_text("如 临时电压"));
                ui.label("地址");
                ui.add_sized([76.0, 17.0], egui::TextEdit::singleline(&mut self.tmp_addr).hint_text("0x0100/256"));
                ui.label("区");
                let fs = if self.tmp_func == 3 { "3 保持" } else { "4 输入" };
                egui::ComboBox::from_id_salt("tmp_func").selected_text(fs).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.tmp_func, 3, "3 保持");
                    ui.selectable_value(&mut self.tmp_func, 4, "4 输入");
                });
                ui.label("类型");
                egui::ComboBox::from_id_salt("tmp_ty").selected_text(self.tmp_ty.clone()).show_ui(ui, |ui| {
                    for t in ["u16", "i16", "u32", "i32", "str"] {
                        ui.selectable_value(&mut self.tmp_ty, t.to_string(), t);
                    }
                });
                if self.tmp_ty == "str" || self.tmp_ty == "u32" || self.tmp_ty == "i32" {
                    ui.label("regs");
                    ui.add(egui::DragValue::new(&mut self.tmp_regs).range(1..=16));
                }
                ui.label("scale");
                ui.add(egui::DragValue::new(&mut self.tmp_scale).range(0.0001..=10000.0).speed(0.1));
                ui.label("单位");
                ui.add_sized([44.0, 17.0], egui::TextEdit::singleline(&mut self.tmp_unit));
            });
            ui.horizontal(|ui| {
                ui.label("初值");
                ui.add(egui::DragValue::new(&mut self.tmp_val).speed(1.0));
                if ui.button("添加并置值 📌").clicked() {
                    let dev_id = rt.devs.get(dev_i).map(|d| d.meta.id).unwrap_or(1);
                    match self.add_temp_point(rt, dev_i, dev_id) {
                        Ok(name) => self.status = format!("临时点 {name} 已添加并置值 📌(可回写点位表)"),
                        Err(e) => self.status = format!("临时点添加失败:{e}"),
                    }
                }
            });
        }
    }

    /// 点位编辑窗一行(值控件 / 近拍 / 类型 / 主机读到 / 钉住释放)
    fn ptedit_row(&mut self, ui: &mut Ui, rt: &std::sync::Arc<crate::moddev::ModDevRuntime>, dev_i: usize, r: &crate::moddev::PointRow) {
        let mut released = false;
        ui.horizontal(|ui| {
            ui.add_sized(
                [150.0, 17.0],
                egui::Label::new(
                    egui::RichText::new(r.name.as_str()).size(10.5).monospace().color(if r.pinned { Color32::from_rgb(235, 200, 90) } else { txt(ui) }),
                )
                .truncate(),
            );
            if let Some(msg) = Self::ptedit_value_ui(ui, rt, dev_i, r) {
                self.status = msg;
            }
            match rt.devs.get(dev_i).and_then(|d| d.point_stats(&r.name)) {
                Some((mn, mx, _cur, series)) => {
                    ui.add_sized(
                        [96.0, 15.0],
                        egui::Label::new(egui::RichText::new(format!("{mn:.3}~{mx:.3}")).size(9.0).monospace().color(dim(ui))).truncate(),
                    );
                    spark(ui, &series, mn, mx);
                }
                None => {
                    ui.label(egui::RichText::new("(采样中…)").size(9.0).color(dim(ui)));
                }
            }
            ui.add_sized(
                [88.0, 15.0],
                egui::Label::new(egui::RichText::new(format!("{}·{}", r.ty, if r.rw { "RW" } else { "RO" })).size(9.5).color(dim(ui))).truncate(),
            );
            match r.host {
                Some((v, n, ago)) => {
                    ui.add_sized(
                        [168.0, 15.0],
                        egui::Label::new(
                            egui::RichText::new(format!("读到 {v:.3} ×{n} · {:.0}s 前", ago.as_secs_f32()))
                                .size(9.5)
                                .color(Color32::from_rgb(120, 200, 130)),
                        )
                        .truncate(),
                    )
                    .on_hover_text("真实主机 func3/4 读到的值(自轮询不计)——对不上就查 scale/字节序");
                }
                None => {
                    ui.add_sized(
                        [168.0, 15.0],
                        egui::Label::new(egui::RichText::new("— 未被主机读").size(9.5).color(dim(ui))).truncate(),
                    );
                }
            }
            if r.pinned {
                if ui.small_button("📌 释放").clicked() {
                    released = true;
                }
            } else {
                ui.label(egui::RichText::new("·").size(9.5).color(dim(ui)));
            }
        });
        if released {
            rt.release_point(dev_i, &r.name);
            self.status = format!("已释放 {}(回到场景驱动)", r.name);
        }
    }

    /// 点位值控件(类型自适应:枚举下拉/位开关/数值拖拽/文本);改即写入并钉住,返回状态文案
    fn ptedit_value_ui(ui: &mut Ui, rt: &std::sync::Arc<crate::moddev::ModDevRuntime>, dev_i: usize, r: &crate::moddev::PointRow) -> Option<String> {
        // 枚举点:下拉选含义(显示当前含义;选中即置值)
        if let Some(en) = &r.enum_ {
            let cur = en.iter().find(|(v, _)| (v - r.phys).abs() < 1e-9).map(|(_, l)| l.clone());
            let sel = cur.unwrap_or_else(|| format!("{:.3}", r.phys));
            let mut picked: Option<(f64, String)> = None;
            egui::ComboBox::from_id_salt(format!("pe_{}", r.name))
                .selected_text(sel)
                .width(112.0)
                .show_ui(ui, |ui| {
                    for (v, l) in en {
                        if ui.selectable_label((v - r.phys).abs() < 1e-9, format!("{l} ({v})")).clicked() {
                            picked = Some((*v, l.clone()));
                        }
                    }
                });
            if let Some((v, l)) = picked {
                if rt.set_point(dev_i, &r.name, v) {
                    return Some(format!("已置 {} = {v}({l}) 📌", r.name));
                }
            }
            return None;
        }
        match r.ty.as_str() {
            "bit" => {
                let mut b = r.phys != 0.0;
                let label = if b { "开" } else { "关" };
                if ui.add_sized([60.0, 17.0], egui::Checkbox::new(&mut b, label)).changed() {
                    let v = if b { 1.0 } else { 0.0 };
                    if rt.set_point(dev_i, &r.name, v) {
                        return Some(format!("已置 {} = {} 📌", r.name, if b { "1" } else { "0" }));
                    }
                }
                None
            }
            "str" | "mac" => {
                let mut s = r.str_val.clone().unwrap_or_default();
                if ui.add_sized([130.0, 17.0], egui::TextEdit::singleline(&mut s).hint_text("(文本)")).changed() {
                    if rt.set_point_str(dev_i, &r.name, &s) {
                        return Some(format!("已置 {} = \"{s}\" 📌", r.name));
                    }
                }
                None
            }
            _ => {
                let mut v = r.phys;
                let mut dv = egui::DragValue::new(&mut v).speed(if r.scale.abs() >= 1.0 { 1.0 } else { 0.1 });
                if let (Some(lo), Some(hi)) = (r.min, r.max) {
                    dv = dv.range(lo..=hi);
                }
                if !r.unit.is_empty() {
                    dv = dv.suffix(r.unit.as_str());
                }
                if ui.add_sized([112.0, 17.0], dv).changed() {
                    if rt.set_point(dev_i, &r.name, v) {
                        return Some(format!("已置 {} = {v}{} 📌", r.name, if r.unit.is_empty() { String::new() } else { format!(" {}", r.unit) }));
                    }
                }
                None
            }
        }
    }

    /// 从表单字段构造临时点并加入模拟器(成功返回点名)
    fn add_temp_point(&mut self, rt: &std::sync::Arc<crate::moddev::ModDevRuntime>, dev_i: usize, dev_id: u32) -> Result<String, String> {
        let addr_s = self.tmp_addr.trim();
        if addr_s.is_empty() {
            return Err("地址不能为空".into());
        }
        let addr = if let Some(h) = addr_s.strip_prefix("0x").or_else(|| addr_s.strip_prefix("0X")) {
            u16::from_str_radix(h, 16).map_err(|_| format!("地址「{addr_s}」不是合法十六进制"))?
        } else {
            addr_s.parse::<u16>().map_err(|_| format!("地址「{addr_s}」不是合法十进制(十六进制请写 0x 前缀)"))?
        };
        let scale = self.tmp_scale;
        if scale == 0.0 {
            return Err("scale 不能为 0".into());
        }
        let name = if self.tmp_name.trim().is_empty() { format!("临时_{addr}") } else { self.tmp_name.trim().to_string() };
        let (regs, init_raw) = match self.tmp_ty.as_str() {
            "u32" | "i32" => (2, self.tmp_val / scale),
            "str" => (self.tmp_regs, 0.0),
            _ => (1, self.tmp_val / scale),
        };
        let key = format!("tmp_0x{addr:04X}");
        let p = iotprobe_core::moddev::MbPoint {
            key: key.clone(),
            name: name.clone(),
            addr,
            func: self.tmp_func,
            ty: self.tmp_ty.clone(),
            regs,
            scale,
            bit: None,
            grp: "临时".into(),
            rw: true,
            min: None,
            max: None,
            init: Some(init_raw.round()),
            init_str: None,
            unit: if self.tmp_unit.trim().is_empty() { None } else { Some(self.tmp_unit.trim().to_string()) },
            enum_: None,
        };
        rt.add_temp_point(dev_i, p)?;
        if self.tmp_ty != "str" {
            rt.set_point(dev_i, &name, self.tmp_val);
        }
        self.moddev_temp.push(ModTempPoint {
            dev_id,
            key,
            name: name.clone(),
            addr,
            func: self.tmp_func,
            ty: self.tmp_ty.clone(),
            regs,
            scale,
            unit: self.tmp_unit.trim().to_string(),
            init_raw: init_raw.round(),
        });
        self.tmp_name.clear();
        self.tmp_addr.clear();
        Ok(name)
    }

    fn card_moddev(&mut self, ui: &mut Ui) {
        // 逐实例停止在闭包内收集(闭包里同时遍历实例列表,移除放到闭包外)
        let mut stop_i: Option<usize> = None;
        Self::config_card("设备模拟器(Modbus 从机)", "本机扮演从机给上位机当被测对象;每台设备独立端点(按点位表),自轮询持续发数;多实例独立启停,与实时接入互不依赖", Color32::from_rgb(235, 170, 80), ui, |ui| {
            Self::state_prefix(ui);
            if !self.moddev_rts.is_empty() {
                // A3:逐实例列出(实例名/端点/录制/独立停止)
                for (i, inst) in self.moddev_rts.iter().enumerate() {
                    let all_bound = inst.rt.devs.iter().all(|d| d.port_bound);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "● {}:{} 台从机 —— 主机(HMI/EMS)按端点连接(端口唯一=0.0.0.0 跨机可达;同端口多机=127.0.0.<N> 按设备区分):",
                                inst.label(),
                                inst.rt.devs.len()
                            ))
                            .size(11.0)
                            .color(if all_bound { Color32::from_rgb(120, 200, 130) } else { Color32::from_rgb(235, 170, 80) }),
                        );
                        if ui.small_button("⏹ 停止此实例").clicked() {
                            stop_i = Some(i);
                        }
                    });
                    for d in &inst.rt.devs {
                        ui.label(
                            egui::RichText::new(format!("dev{} {} → {} unit={} · {}", d.meta.id, d.meta.name, d.endpoint(), d.meta.slave, d.link_label()))
                                .size(10.5)
                                .monospace()
                                .color(if d.port_bound { dim(ui) } else { Color32::from_rgb(235, 120, 100) }),
                        );
                    }
                    if let Some(rp) = &inst.record {
                        ui.label(
                            egui::RichText::new(format!("录制→{}", rp.display()))
                                .size(10.0)
                                .monospace()
                                .color(dim(ui)),
                        );
                    }
                }
                ui.label(
                    egui::RichText::new("自轮询发数中(点位表 poll_ms 周期,0=关) —— 无主机连入曲线也滚动")
                        .size(10.5)
                        .color(dim(ui)),
                );
                if ui
                    .button("拓扑连线图(主机→设备链路健康)")
                    .on_hover_text("左=主机节点,右=设备端点;绿=已连/红=断开或异常码/灰=无流量;点设备节点过滤到该设备的帧")
                    .clicked()
                {
                    self.show_topolink = true;
                }
            } else {
                ui.label(egui::RichText::new("未运行").size(11.0).color(dim(ui)));
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("选择点位表 .yaml…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("点位表 YAML", &["yaml", "yml"])
                        .pick_file()
                    {
                        self.live_form.moddev_yaml = Some(p);
                    }
                }
                if let Some(p) = &self.live_form.moddev_yaml {
                    ui.label(
                        egui::RichText::new(p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default())
                            .size(10.5)
                            .monospace()
                            .color(dim(ui)),
                    );
                }
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.live_form.sim_record, "录制 .ndjson(原始帧落盘,可离线回放)");
                if self.live_form.sim_record {
                    if let Some(p) = &self.live_form.sim_record_path {
                        ui.label(
                            egui::RichText::new(p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default())
                                .size(10.0)
                                .monospace()
                                .color(dim(ui)),
                        );
                    } else {
                        ui.label(egui::RichText::new("启动时选保存位置").size(10.0).color(dim(ui)));
                    }
                }
            });
            ui.horizontal(|ui| {
                if !self.moddev_rts.is_empty() {
                    if ui.button("⏹ 全部停止").clicked() {
                        for inst in self.moddev_rts.drain(..) {
                            inst.rt.stop_all();
                        }
                        self.moddev_inst_idx = 0;
                        self.status = "模拟器全部停止(端口关闭)".into();
                    }
                }
                if self.live_form.moddev_yaml.is_some() {
                    if ui.button("▶ 启动模拟器(单端口·按 unit 路由)").clicked() {
                        self.start_moddev();
                    }
                }
                if self.moddev_rts.is_empty() && self.live_form.moddev_yaml.is_none() {
                    ui.label(
                        egui::RichText::new("先选点位表 YAML(devN 驱动):link: tcp=Modbus TCP / rtu_tcp=RTU·串口服务器透传;端口唯一绑 0.0.0.0,同端口多机自动 127.0.0.N;格式见「AI 转换指南」")
                            .size(10.5)
                            .color(dim(ui)),
                    );
                }
            });
        });
        // 逐实例停止(闭包内只收集,移除放闭包外避免借用冲突)
        if let Some(i) = stop_i {
            let inst = self.moddev_rts.remove(i);
            inst.rt.stop_all();
            self.moddev_inst_idx = self.moddev_inst_idx.min(self.moddev_rts.len().saturating_sub(1));
            self.status = format!("模拟器实例 {} 已停止(端口关闭)", inst.name);
        }
    }
    /// 卡片:自定义协议从机模拟(A6)
    fn card_moddev_custom(&mut self, ui: &mut Ui) {
        let mut stop = false;
        Self::config_card("自定义协议从机(JSON DSL)", "本机按 CustomSpec 扮演从机:deframe 定界收帧→字段解码→原帧回显;自轮询按 spec 编码周期发数(长度域/校验重算)", Color32::from_rgb(180, 150, 235), ui, |ui| {
            Self::state_prefix(ui);
            if let Some(rt) = &self.moddev_custom_rt {
                ui.label(
                    egui::RichText::new(format!(
                        "● 运行中:{} 端口 {} · {} 字段 · 自轮询 {}ms · 回显{}",
                        rt.spec.name,
                        rt.bound_port,
                        rt.spec.fields.len(),
                        rt.poll_ms,
                        if rt.echo { "开" } else { "关" }
                    ))
                    .size(11.0)
                    .color(Color32::from_rgb(120, 200, 130)),
                );
                egui::ScrollArea::vertical().id_salt("moddev_custom_fields").max_height(110.0).auto_shrink([false, true]).show(ui, |ui| {
                    for (name, ty, val) in rt.fields_view().iter().take(64) {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("{name} [{ty}]")).monospace().size(10.5).color(txt(ui)));
                            // 行内 DragValue 直接改值(联调最短路径:改值→下个自轮询拍带出新值)
                            let mut v = *val;
                            if ui.add(egui::DragValue::new(&mut v).speed(0.1)).changed() {
                                rt.set_field(name, v);
                                self.status = format!("已置 {name} = {v}(下个自轮询拍生效)");
                            }
                        });
                    }
                });
            } else {
                ui.label(egui::RichText::new("未运行").size(11.0).color(dim(ui)));
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("选择从机配置 .yaml…").on_hover_text("格式: spec/spec_file(CustomSpec JSON)+ port + poll_ms + echo + init").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("自定义从机 YAML", &["yaml", "yml"])
                        .pick_file()
                    {
                        self.moddev_custom_yaml = Some(p);
                    }
                }
                if let Some(p) = &self.moddev_custom_yaml {
                    ui.label(egui::RichText::new(p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default()).size(10.5).monospace().color(dim(ui)));
                }
            });
            ui.checkbox(&mut self.moddev_custom_record, "录制 .ndjson(可离线回放)");
            ui.horizontal(|ui| {
                if self.moddev_custom_rt.is_some() {
                    if ui.button("⏹ 停止自定义从机").clicked() {
                        stop = true;
                    }
                } else if self.moddev_custom_yaml.is_some() {
                    if ui.button("▶ 启动自定义从机").clicked() {
                        self.start_moddev_custom();
                    }
                } else {
                    ui.label(egui::RichText::new("先选配置 YAML:spec 用 CustomSpec JSON(试探引擎产出的草案可直接用);echo=true 时主机帧原样回显").size(10.5).color(dim(ui)));
                }
            });
        });
        if stop {
            if let Some(rt) = self.moddev_custom_rt.take() {
                rt.stop_all();
            }
            self.status = "自定义从机已停止".into();
        }
    }

    /// 卡片:IEC 104 从机模拟(A5)
    /// 卡片:DL/T 645 电表从机模拟(J1)
    fn card_moddev645(&mut self, ui: &mut Ui) {
        let mut stop = false;
        Self::config_card("DL/T 645 电表从机(2007)", "本机扮演一块 645 电表:EMS/采集终端经 TCP 透明透传来抄表(读数据 0x11);点表 YAML 驱动,串口现场建议串口服务器转 TCP", Color32::from_rgb(120, 210, 200), ui, |ui| {
            Self::state_prefix(ui);
            if let Some(rt) = &self.moddev645_rt {
                ui.label(
                    egui::RichText::new(format!(
                        "● 运行中:{} 端口 {}·表号 {}·{} 点",
                        rt.name,
                        rt.bound_port,
                        rt.addr_display,
                        rt.points.len()
                    ))
                    .size(11.0)
                    .color(Color32::from_rgb(120, 200, 130)),
                );
                egui::ScrollArea::vertical().id_salt("moddev645_points").max_height(110.0).auto_shrink([false, true]).show(ui, |ui| {
                    for (di, name, val) in rt.points_view().iter().take(64) {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("DI {di:08x} {name} = {val:.4}")).monospace().size(10.5).color(txt(ui)));
                        });
                    }
                });
            } else {
                ui.label(egui::RichText::new("未运行").size(11.0).color(dim(ui)));
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("选择 645 点表 .yaml…").on_hover_text("格式: name/port/addr/poll_ms + points: <DI>: {name, init, min, max}").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("645 点表 YAML", &["yaml", "yml"])
                        .pick_file()
                    {
                        self.moddev645_yaml = Some(p);
                    }
                }
                if let Some(p) = &self.moddev645_yaml {
                    ui.label(egui::RichText::new(p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default()).size(10.5).monospace().color(dim(ui)));
                }
            });
            ui.checkbox(&mut self.moddev645_record, "录制 .ndjson(可离线回放)");
            ui.horizontal(|ui| {
                if self.moddev645_rt.is_some() {
                    if ui.button("⏹ 停止 645 从机").clicked() {
                        stop = true;
                    }
                } else if self.moddev645_yaml.is_some() {
                    if ui.button("▶ 启动 645 从机").clicked() {
                        self.start_moddev645();
                    }
                } else {
                    ui.label(egui::RichText::new("先选 645 点表 YAML;串口 2400/Even/8/1 由串口服务器转 TCP;真表 golden 验证待真表到手后执行").size(10.5).color(dim(ui)));
                }
            });
        });
        if stop {
            if let Some(rt) = self.moddev645_rt.take() {
                rt.stop_all();
            }
            self.status = "645 从机已停止".into();
        }
    }

    fn card_moddev104(&mut self, ui: &mut Ui) {
        let mut stop = false;
        Self::config_card("104 从机模拟(IEC 104)", "本机扮演 104 从机:总召唤/时钟同步/遥控应答,STARTDT 后变位主动上送;点表 YAML 驱动,帧进同一管线", Color32::from_rgb(120, 180, 240), ui, |ui| {
            Self::state_prefix(ui);
            if let Some(rt) = &self.moddev104_rt {
                let st = match rt.link_state() {
                    crate::moddev104::LinkState::Green => ("● 主站已连", Color32::from_rgb(120, 200, 130)),
                    crate::moddev104::LinkState::Red(_r) => ("● 断开/异常", Color32::from_rgb(229, 90, 90)),
                    crate::moddev104::LinkState::Gray => ("○ 无主机流量", dim(ui)),
                };
                ui.label(
                    egui::RichText::new(format!(
                        "{}:{} 端口 {}·CA {} · {} 点 —— 主机侧连接 127.0.0.1:{}",
                        st.0,
                        rt.dev.name,
                        rt.bound_port,
                        rt.dev.ca,
                        rt.dev.points.len(),
                        rt.bound_port
                    ))
                    .size(11.0)
                    .color(st.1),
                );
                let mut set_val: Option<(u16, f64)> = None;
                egui::ScrollArea::vertical().id_salt("moddev104_points").max_height(120.0).auto_shrink([false, true]).show(ui, |ui| {
                    for (ioa, name, ty, val) in rt.points_view().iter().take(64) {
                        let rw = rt.dev.points.iter().any(|p| p.ioa == *ioa && p.rw);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("IOA {ioa} [{ty}] {name} = {val:.3}")).monospace().size(10.5).color(txt(ui)));
                            if rw && (*ty == "单点" || *ty == "双点") {
                                if ui.small_button("置0").on_hover_text("变位即触发 COT=3 突发上送").clicked() {
                                    set_val = Some((*ioa, 0.0));
                                }
                                if ui.small_button("置1").clicked() {
                                    set_val = Some((*ioa, 1.0));
                                }
                            }
                        });
                    }
                });
                if let Some((ioa, v)) = set_val {
                    if rt.set_ioa(ioa, v) {
                        self.status = format!("已置 IOA {ioa} = {v}(下个上送节拍触发 COT=3)");
                    }
                }
            } else {
                ui.label(egui::RichText::new("未运行").size(11.0).color(dim(ui)));
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("选择 104 点表 .yaml…").on_hover_text("格式: dev104: {name, port, ca, poll_ms} + points: <IOA>: {name, ty: sp/dp/na/nb/nc, init, rw, min, max}").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("104 点表 YAML", &["yaml", "yml"])
                        .pick_file()
                    {
                        self.moddev104_yaml = Some(p);
                    }
                }
                if let Some(p) = &self.moddev104_yaml {
                    ui.label(egui::RichText::new(p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default()).size(10.5).monospace().color(dim(ui)));
                }
            });
            ui.checkbox(&mut self.moddev104_record, "录制 .ndjson(可离线回放进 104 解析)");
            ui.horizontal(|ui| {
                if self.moddev104_rt.is_some() {
                    if ui.button("⏹ 停止 104 从机").clicked() {
                        stop = true;
                    }
                } else if self.moddev104_yaml.is_some() {
                    if ui.button("▶ 启动 104 从机(2404)").clicked() {
                        self.start_moddev104();
                    }
                } else {
                    ui.label(egui::RichText::new("先选 104 点表 YAML;ty=sp 单点/dp 双点/nc 短浮点;Fault 场景每拍翻转遥信演示变位上送").size(10.5).color(dim(ui)));
                }
            });
        });
        if stop {
            if let Some(rt) = self.moddev104_rt.take() {
                rt.stop_all();
            }
            self.status = "104 从机已停止(端口关闭)".into();
        }
    }

    /// 卡片:实时接入与录制(FR-S1/S2;源类型/地址/波特率/录制/回放并入,原悬浮窗表单收编)
    fn card_live(&mut self, ui: &mut Ui) {
        Self::config_card("实时接入与录制(FR-S1)", "连总线/网络/回放源进同一管线;原始行落盘 .ndjson 可回放", Color32::from_rgb(140, 200, 110), ui, |ui| {
            Self::state_prefix(ui);
            if !self.lives.is_empty() {
                let rec = if self.live_form.record {
                    format!(
                        " · 录制→{}",
                        self.live_form
                            .record_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    )
                } else {
                    String::new()
                };
                ui.label(
                    egui::RichText::new(format!(
                        "● 已连接「{}」 收 {} 帧 · 坏 {} · 丢 {}{}{}",
                        self.live_name,
                        self.live_stats.ok,
                        self.live_stats.bad,
                        self.live_stats.gaps,
                        rec,
                        // C4 内存护栏诚实标注:滚动丢弃只影响内存视图,源头录制不受影响
                        if self.live_rolled > 0 {
                            format!(" · ⚠ 内存护栏已滚动丢弃最旧 {} 条(开录制保完整)", self.live_rolled)
                        } else {
                            String::new()
                        }
                    ))
                    .size(11.0)
                    .color(if self.live_rolled > 0 { Color32::from_rgb(235, 170, 80) } else { Color32::from_rgb(120, 200, 130) }),
                );
            } else {
                ui.label(
                    egui::RichText::new("未连接(下方选源类型后点「连接」;顶栏绿色 ● 同步显示)")
                        .size(11.0)
                        .color(dim(ui)),
                );
            }
            // 帧流转发(W:指向其他端口):契约帧 NDJSON → TCP 端口(现场 A 机采集,远端脚本/B 机实时消费)
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let rebind = ui.checkbox(&mut self.fwd_on, "转发帧流到 TCP 端口").changed();
                let port_changed = ui
                    .add(egui::DragValue::new(&mut self.fwd_port).range(1024..=65535))
                    .changed();
                if (rebind || port_changed) && self.fwd_on {
                    if let Some(old) = self.fwd.take() {
                        drop(old);
                    }
                    *self.fwd_slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    match crate::live::spawn_forwarder(self.fwd_port) {
                        Ok((f, bound)) => {
                            *self.fwd_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(f.tx.clone());
                            self.fwd = Some(f);
                            self.status = format!("帧流转发已开启:0.0.0.0:{bound}(契约 NDJSON,可连任意脚本/第二实例)");
                        }
                        Err(e) => {
                            self.fwd_on = false;
                            self.status = e;
                        }
                    }
                }
                if !self.fwd_on && self.fwd.is_some() {
                    *self.fwd_slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    if let Some(old) = self.fwd.take() {
                        drop(old);
                    }
                }
                if let Some(f) = &self.fwd {
                    ui.label(
                        egui::RichText::new(format!("● {} 客户端", f.client_count()))
                            .size(10.5)
                            .color(Color32::from_rgb(120, 200, 130)),
                    );
                }
            });
            ui.add_space(4.0);
            self.live_form_parts(ui, u8::MAX);
        });
    }

    /// 卡片:CAN 发送(操作类保持独立窗口;状态在此可见)
    fn card_tx(&mut self, ui: &mut Ui) {
        Self::config_card("CAN 发送(操作·FR-4.7)", "唯一主动发帧入口;解锁/白名单/收发都在独立窗口,锁定态在此可见", Color32::from_rgb(240, 150, 80), ui, |ui| {
            Self::state_prefix(ui);
            let wl = if self.tx_whitelist.trim().is_empty() { "未设置" } else { self.tx_whitelist.trim() };
            ui.label(
                egui::RichText::new(format!(
                    "{} · ID 白名单: {}",
                    if self.tx_unlocked {
                        "🔓已解锁(危险:可主动发帧)"
                    } else {
                        "🔒锁定(默认,显式解锁后才可发)"
                    },
                    wl
                ))
                .size(11.0),
            );
            ui.label(
                egui::RichText::new(if self.tx_hub.is_some() {
                    "发送通道已接入(实时 CAN 卡 / 模拟总线)"
                } else {
                    "无发送通道:连接实时 CAN 卡或模拟总线后可用"
                })
                .size(10.5)
                .color(dim(ui)),
            );
            ui.add_space(4.0);
            let open_btn = if self.show_tx { "打开发送窗口(已开,点置前台)" } else { "打开发送窗口" };
            if ui.button(open_btn).clicked() {
                self.show_tx = true;
            }
        });
    }

    /// 卡片:界面与诊断(主题/告警/展示窗口开关/使用指南;会话持久化说明)
    fn card_display(&mut self, ui: &mut Ui) {
        Self::config_card("界面与诊断", "外观主题 · 告警列表 · 展示类窗口开关 · 使用指南;不碰数据与硬件", Color32::from_rgb(150, 155, 165), ui, |ui| {
            Self::state_prefix(ui);
            let warns = self.ds.as_ref().map(|d| d.warnings.len()).unwrap_or(0);
            ui.label(
                egui::RichText::new(format!(
                    "主题 {} · 告警 {} 条 · 会话自动保存 iotprobe_session.json(exe 目录,重启恢复文件/模板/勾选)",
                    if self.dark { "暗色" } else { "亮色" },
                    warns
                ))
                .size(10.5)
                .color(dim(ui)),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let theme_btn = if self.dark { "☀ 切亮色" } else { "🌙 切暗色" };
                if ui.button(theme_btn).clicked() {
                    self.dark = !self.dark;
                    apply_theme(ui.ctx(), self.dark);
                    self.save_session();
                }
                if warns > 0 && ui.button(format!("⚠ 告警列表({warns})")).clicked() {
                    self.warn_open = true;
                }
                if ui.button("📖 使用指南").clicked() {
                    let p = session_path()
                        .parent()
                        .map(|d| d.join("IoTProbe使用指南.txt"))
                        .unwrap_or_else(|| PathBuf::from("IoTProbe使用指南.txt"));
                    if let Some(dir) = p.parent() {
                        let _ = std::process::Command::new("cmd")
                            .args(["/C", "start", "", &p.display().to_string()])
                            .current_dir(dir)
                            .spawn();
                    }
                }
            });
            // 与顶栏「分析工具」菜单同一状态源,两处联动(打开的窗口数在菜单名上)
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("展示窗口(悬浮,两页通用)").size(10.5).color(dim(ui)));
                ui.checkbox(&mut self.show_events, "异常事件");
                ui.checkbox(&mut self.show_probe, "未知协议试探");
                ui.checkbox(&mut self.show_tasks, "规则任务");
                ui.checkbox(&mut self.show_topo, "储能拓扑");
                ui.checkbox(&mut self.show_topolink, "拓扑连线");
            });
        });
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(egui::RichText::new("协议配置").size(11.0).color(dim(ui)));
            ui.horizontal(|ui| {
                if ui.small_button("+自定义").clicked() {
                    self.load_config_of("custom");
                }
                if ui.small_button("+DBC").clicked() {
                    self.load_config_of("dbc");
                }
                if ui.small_button("+寄存器").clicked() {
                    self.load_config_of("map");
                }
                if ui.small_button("+104点表").clicked() {
                    self.load_config_of("map104");
                }
                if ui.small_button("配置中心…").clicked() {
                    self.page = 1;
                }
            });
            for (label, p) in self
                .custom_paths
                .iter()
                .map(|p| ("custom", p))
                .chain(self.dbc_path.iter().map(|p| ("dbc", p)))
                .chain(self.map_path.iter().map(|p| ("map", p)))
                .chain(self.map104_path.iter().map(|p| ("map104", p)))
            {
                let color = match label {
                    "custom" => Color32::from_rgb(235, 200, 90),
                    "dbc" => Color32::from_rgb(210, 160, 235),
                    "map104" => Color32::from_rgb(230, 120, 180),
                    _ => Color32::from_rgb(98, 178, 235),
                };
                ui.label(
                    egui::RichText::new(format!(
                        "· {}",
                        p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
                    ))
                    .size(10.5)
                    .monospace()
                    .color(color),
                );
            }
            ui.add_space(6.0);
            ui.separator();

            let ds = self.ds.clone();
            if let Some(ds) = ds {
                // 信号列表(按报文分组:组头折叠/圆点全选,过滤框匹配报文名/信号名)
                ui.label(
                    egui::RichText::new(format!("信号 ({})", ds.signals.len()))
                        .size(11.0)
                        .color(dim(ui)),
                );
                ui.horizontal(|ui| {
                    let w = (ui.available_width() - 58.0).max(60.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.sig_filter)
                            .desired_width(w)
                            .hint_text("过滤: 报文名/信号名/ID")
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.small_button("⊟").on_hover_text("全部折叠(节+组)").clicked() {
                        let mut gkeys: HashSet<String> = HashSet::new();
                        for s in &ds.signals {
                            if let Some((g, _)) = s.key.split_once('·') {
                                gkeys.insert(g.to_string());
                            }
                        }
                        for g in gkeys {
                            self.sig_group_closed.insert(g);
                        }
                        self.sig_group_closed.insert("sec:未匹配报文".into());
                        self.sig_group_closed.insert("sec:其他".into());
                        let names: HashSet<String> = self.dbc_attr.values().cloned().collect();
                        for n in names {
                            self.sig_group_closed.insert(format!("sec:{n}"));
                        }
                    }
                    if ui.small_button("⊞").on_hover_text("全部展开").clicked() {
                        self.sig_group_closed.clear();
                    }
                });
                ui.add_space(3.0);

                let q = self.sig_filter.trim().to_lowercase();
                // 组键 = '·' 前缀(如 CAN 0x18FF2DF3x / RTT / unit0 / Δt);保序去重
                let mut groups: Vec<(String, Vec<usize>)> = vec![];
                for (i, s) in ds.signals.iter().enumerate() {
                    let (g, name) = s.key.split_once('·').unwrap_or((s.key.as_str(), s.key.as_str()));
                    if !q.is_empty() {
                        let glabel = self.group_label(g).to_lowercase();
                        let id_hit = g.to_lowercase().contains(&q);
                        if !glabel.contains(&q) && !id_hit && !name.to_lowercase().contains(&q) {
                            continue;
                        }
                    }
                    match groups.iter_mut().find(|(k, _)| k == g) {
                        Some((_, v)) => v.push(i),
                        None => groups.push((g.to_string(), vec![i])),
                    }
                }
                // 「★ 常用」置顶:跨报文的收藏信号(无过滤时)
                if q.is_empty() {
                    let fav_idx: Vec<usize> = ds
                        .signals
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| self.fav_sigs.contains(&s.key) && !s.key.starts_with("Δt"))
                        .map(|(i, _)| i)
                        .collect();
                    if !fav_idx.is_empty() {
                        groups.insert(0, ("★ 常用".to_string(), fav_idx));
                    }
                }

                let mut toggles: Vec<String> = vec![];
                let mut group_toggles: Vec<Vec<String>> = vec![];
                // 分节:每个匹配到的 DBC 一节(节名=DBC 文件名),未命中报文归「未匹配」,非 CAN 归「其他」
                let mut sections: Vec<(String, Vec<(String, Vec<usize>)>)> = vec![];
                for (g, idxs) in groups {
                    let sec = dbc_section_of(&g, &self.dbc_attr);
                    match sections.iter_mut().find(|(k, _)| *k == sec) {
                        Some((_, v)) => v.push((g, idxs)),
                        None => sections.push((sec, vec![(g, idxs)])),
                    }
                }
                for (sec, sec_groups) in &sections {
                    // 节头:▸/▾ + "DBC名 (N信号)" —— 匹配成功的 DBC 在此对应显示,可自由折叠
                    let sec_key = format!("sec:{sec}");
                    let sec_closed = self.sig_group_closed.contains(&sec_key) && q.is_empty();
                    let total = sec_groups.iter().map(|(_, v)| v.len()).sum::<usize>();
                    let sr = ui
                        .allocate_ui(egui::vec2(ui.available_width(), 18.0), |ui| {
                            let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 17.0), Sense::click());
                            let p = ui.painter();
                            p.rect_filled(
                                Rect_::from_min_max(Pos2::new(r.left(), r.top()), Pos2::new(r.right(), r.bottom())),
                                3.0,
                                if ui.visuals().dark_mode { Color32::from_rgb(30, 34, 42) } else { Color32::from_rgb(233, 237, 244) },
                            );
                            p.text(Pos2::new(r.left() + 6.0, r.center().y), Align2::LEFT_CENTER, if sec_closed { "▸" } else { "▾" }, FontId::monospace(10.0), dim(ui));
                            p.text(
                                Pos2::new(r.left() + 20.0, r.center().y),
                                Align2::LEFT_CENTER,
                                format!("{sec} · {total} 信号"),
                                FontId::monospace(11.5),
                                Color32::from_rgb(210, 160, 235),
                            );
                            resp
                        })
                        .inner;
                    let sr = sr.on_hover_text("匹配到的 DBC 协议分节:点击折叠/展开其下全部报文");
                    if sr.clicked() && q.is_empty() {

                        if self.sig_group_closed.contains(&sec_key) {
                            self.sig_group_closed.remove(&sec_key);
                        } else {
                            self.sig_group_closed.insert(sec_key);
                        }
                    }
                    if sec_closed {
                        continue;
                    }
                for (g, idxs) in sec_groups {
                    let on_cnt = idxs.iter().filter(|i| self.sig_sel.contains(&ds.signals[**i].key)).count();
                    let all_on = on_cnt == idxs.len() && on_cnt > 0;
                    let closed = self.sig_group_closed.contains(g) && q.is_empty();
                    let glabel = self.group_label(g);
                    let gcolor = views::series_color(*idxs.first().unwrap());
                    // 组头:▸/▾ + ◉全选点 + "报文名 · ID (n)"
                    let hr = ui
                        .allocate_ui(egui::vec2(ui.available_width(), 16.0), |ui| {
                            let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 15.0), Sense::click());
                            ui.painter().circle(
                                Pos2::new(r.left() + 8.0, r.center().y),
                                4.5,
                                if all_on { gcolor } else { Color32::from_rgb(60, 64, 72) },
                                egui::Stroke::NONE,
                            );
                            ui.painter().text(
                                Pos2::new(r.left() + 18.0, r.center().y),
                                Align2::LEFT_CENTER,
                                if closed { "▸" } else { "▾" },
                                FontId::monospace(9.0),
                                dim(ui),
                            );
                            ui.painter().text(
                                Pos2::new(r.left() + 30.0, r.center().y),
                                Align2::LEFT_CENTER,
                                format!("{glabel} ({})", idxs.len()),
                                FontId::monospace(11.5),
                                if on_cnt > 0 { txt(ui) } else { dim(ui) },
                            );
                            resp
                        })
                        .inner;
                    if hr.clicked() {
                        if let Some(pos) = hr.interact_pointer_pos() {
                            if pos.x < hr.rect.left() + 16.0 {
                                // 点 ◉ 区域:组内全选/全不选
                                group_toggles.push(idxs.iter().map(|i| ds.signals[*i].key.clone()).collect());
                            } else if q.is_empty() {
                                if self.sig_group_closed.contains(g) {
                                    self.sig_group_closed.remove(g);
                                } else {
                                    self.sig_group_closed.insert(g.clone());
                                }
                            }
                        }
                    }
                    // 组头右键:整组收藏
                    hr.context_menu(|ui| {
                        let all_fav = idxs.iter().all(|i| self.fav_sigs.contains(&ds.signals[*i].key));
                        let label = if all_fav { "☆ 取消收藏整组" } else { "★ 收藏整组" };
                        if ui.button(label).clicked() {
                            if all_fav {
                                for i in idxs {
                                    self.fav_sigs.remove(&ds.signals[*i].key);
                                }
                            } else {
                                for i in idxs {
                                    self.fav_sigs.insert(ds.signals[*i].key.clone());
                                }
                            }
                            ui.close();
                            self.save_session();
                        }
                    });
                    if closed {
                        continue;
                    }
                    for &i in idxs {
                        let s = &ds.signals[i];
                        let on = self.sig_sel.contains(&s.key);
                        let fav = self.fav_sigs.contains(&s.key);
                        let color = self
                            .color_ov
                            .get(&s.key)
                            .map(|c| Color32::from_rgb(c[0], c[1], c[2]))
                            .unwrap_or_else(|| views::series_color(i));
                        let name = s.key.split_once('·').map(|(_, n)| n).unwrap_or(s.key.as_str());
                        let resp = ui.allocate_ui(egui::vec2(ui.available_width(), 15.0), |ui| {
                            let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 15.0), Sense::click());
                            ui.painter().rect_filled(
                                Rect_::from_min_size(Pos2::new(r.left() + 8.0, r.center().y - 4.0), egui::vec2(10.0, 8.0)),
                                3.0,
                                if on { color } else { Color32::from_rgb(60, 64, 72) },
                            );
                            let text = if s.unit.is_empty() {
                                name.to_string()
                            } else {
                                format!("{name} [{}]", s.unit)
                            };
                            ui.painter().text(
                                Pos2::new(r.left() + 24.0, r.center().y),
                                Align2::LEFT_CENTER,
                                &text,
                                FontId::monospace(11.5),
                                if on { txt(ui) } else { dim(ui) },
                            );
                            // 右端收藏星标
                            ui.painter().text(
                                Pos2::new(r.right() - 9.0, r.center().y),
                                Align2::CENTER_CENTER,
                                if fav { "★" } else { "☆" },
                                FontId::proportional(11.0),
                                if fav { Color32::from_rgb(240, 200, 90) } else { dim(ui) },
                            );
                            resp
                        });
                        if resp.inner.clicked() {
                            if let Some(pos) = resp.inner.interact_pointer_pos() {
                                if pos.x > resp.inner.rect.right() - 18.0 {
                                    // 星标区:切换收藏
                                    if fav {
                                        self.fav_sigs.remove(&s.key);
                                    } else {
                                        self.fav_sigs.insert(s.key.clone());
                                    }
                                    self.save_session();
                                } else {
                                    toggles.push(s.key.clone());
                                }
                            }
                        }
                        resp.inner.on_hover_text(&s.key);
                    }
                    ui.add_space(2.0);
                }
                }
                let toggled_any = !toggles.is_empty() || !group_toggles.is_empty();
                for k in toggles {
                    if self.sig_sel.contains(&k) {
                        self.sig_sel.remove(&k);
                    } else {
                        self.sig_sel.insert(k);
                    }
                }
                for keys in group_toggles {
                    if keys.iter().all(|k| self.sig_sel.contains(k)) {
                        for k in keys {
                            self.sig_sel.remove(&k);
                        }
                    } else {
                        for k in keys {
                            self.sig_sel.insert(k);
                        }
                    }
                }
                if toggled_any {
                    self.save_session();
                }
                ui.add_space(6.0);
                ui.separator();
                // 协议过滤
                ui.label(egui::RichText::new("协议过滤").size(11.0).color(dim(ui)));
                let mut seen: Vec<Proto> = vec![];
                for f in &ds.frames {
                    if !seen.contains(&f.proto) {
                        seen.push(f.proto);
                    }
                }
                let mut changed = false;
                for p in seen {
                    let mut on = self.proto_filter.get(&p).copied().unwrap_or(true);
                    if ui.checkbox(&mut on, p.label()).changed() {
                        self.proto_filter.insert(p, on);
                        changed = true;
                    }
                }
                if changed {
                    self.rebuild_shown();
                }
                ui.add_space(6.0);
                ui.separator();
                // 分析参数
                ui.label(egui::RichText::new("分析参数").size(11.0).color(dim(ui)));
                let gap_resp = ui.add(
                    egui::Slider::new(&mut self.gap_ms, 0.0..=2000.0)
                        .text("间隔阈值ms (0=自动)")
                        .logarithmic(true),
                );
                if gap_resp.drag_stopped() {
                    self.save_session();
                }
                ui.add_space(4.0);
                ui.separator();
                ui.label(egui::RichText::new("通道").size(11.0).color(dim(ui)));
                views::channels_panel(ui, &ds);
            } else {
                ui.label(egui::RichText::new("未加载数据").size(11.0).color(dim(ui)));
            }
        });
    }
}

use egui::Rect as Rect_;

#[derive(Clone, Debug)]
pub struct AggRow {
    pub key: String,
    pub chan: String,
    pub count: usize,
    pub last_t: u64,
    pub last_summary: String,
    pub mean_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub jitter_pct: f64,
    /// DBC 标称周期(BA_ GenMsgCycleTime);有值时显示偏差%
    pub nominal_ms: Option<u32>,
    pub dev_pct: Option<f64>,
}

/// FR-4.2:按 ID(Modbus 按 unit·方向)聚合,统计周期稳定性
fn compute_agg(ds: &Dataset) -> Vec<AggRow> {
    let dbc = ds.decode_ctx.dbc.clone();
    use std::collections::HashMap;
    #[derive(Default)]
    struct Acc {
        count: usize,
        last_t: u64,
        last_summary: String,
        dts: Vec<f64>,
    }
    let mut map: HashMap<(u16, u16, String), Acc> = HashMap::new();
    for f in &ds.frames {
        let key = match f.proto {
            Proto::Can | Proto::CanFd => f.summary.split_whitespace().next().unwrap_or("?").to_string(),
            Proto::ModbusRtu | Proto::ModbusTcp => {
                let unit = f.summary.split(' ').find(|w| w.starts_with("unit")).unwrap_or("unit?");
                format!("{unit}·{}", f.dir.label())
            }
            _ => f.proto.label().to_string(),
        };
        let e = map.entry((f.source, f.channel, key)).or_default();
        if e.count > 0 {
            e.dts.push(f.t_ns.saturating_sub(e.last_t) as f64 / 1e6);
        }
        e.count += 1;
        e.last_t = f.t_ns;
        e.last_summary = f.summary.clone();
    }
    let mut rows: Vec<AggRow> = vec![];
    for ((src, ch, key), a) in map {
        if a.dts.is_empty() {
            continue;
        }
        let mut d = a.dts.clone();
        d.sort_by(|x, y| x.total_cmp(y));
        let n = d.len();
        let mean = d.iter().sum::<f64>() / n as f64;
        let var = d.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n as f64;
        let std = var.sqrt();
        let p95 = d[((n as f64) * 0.95) as usize % n];
        // DBC 标称周期比对:聚合键形如 "0x1A0"/"0x18FF0102x"(CAN),按 29bit+扩展位查表
        let nominal = dbc.as_ref().and_then(|dbc| {
            let t = key.trim().to_lowercase();
            let t = t.strip_prefix("0x")?;
            let ext = t.ends_with('x');
            let id = u32::from_str_radix(t.trim_end_matches('x'), 16).ok()?;
            dbc.msgs.get(&iotprobe_core::dbc::msg_key(id, ext)).and_then(|m| m.cycle_ms)
        });
        let dev = nominal.map(|nom| (mean - nom as f64) / nom as f64 * 100.0);
        rows.push(AggRow {
            key,
            chan: ds.channel_label(src, ch),
            count: a.count,
            last_t: a.last_t,
            last_summary: a.last_summary,
            mean_ms: mean,
            p95_ms: p95,
            max_ms: d[n - 1],
            jitter_pct: if mean > 0.0 { std / mean * 100.0 } else { 0.0 },
            nominal_ms: nominal,
            dev_pct: dev,
        });
    }
    rows
}

fn spec_summary(spec: &iotprobe_core::dissect::CustomSpec) -> String {
    use iotprobe_core::dissect::custom::Off;
    let sync = spec.sync.clone().unwrap_or_else(|| "无同步头".into());
    let len = match (&spec.length, spec.frame_len) {
        (Some(l), _) => {
            let pos = match l.at {
                Off::Abs(p) => format!("@{p}"),
                Off::EndMinus(n) => format!("end-{n}"),
            };
            format!("长度域{pos}×{} bias{}", l.size, l.bias)
        }
        (None, Some(fl)) => format!("固定长{fl}"),
        (None, None) => "无长度域".into(),
    };
    let cks = match &spec.checksum {
        Some(c) => format!("校验 {}", c.algo),
        None => "无校验".into(),
    };
    format!("sync={sync} · {len} · {cks} · 字段{}", spec.fields.len())
}

/// 按信号前缀自动生成拓扑(首次使用的零配置入口):
/// `unit{n}·X` → 设备 unit{n}(meter 类);`104 {名}·IOA…` → 设备 `{名}` 分组不适用,
/// 104 键是 `104 名` 单键形态,按 · 前无内容处理 → 归到 `104设备`;CAN `0x…·sig` → 0x… 设备。
/// 每设备绑定其组内信号(不带阈值),另存 YAML 后可补 warn/fault。
fn auto_topology(ds: &Dataset) -> iotprobe_core::topology::Topology {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in &ds.signals {
        if s.key.starts_with("Δt") || s.key.starts_with("RTT") {
            continue;
        }
        // 组名 = 第一个 · 前的部分(无 · 用整键,但 104 {名} 键 · 常缺失 → 整键作组)
        let group = s.key.split('·').next().unwrap_or(&s.key).to_string();
        let sig_name = s.key.rsplit('·').next().unwrap_or(&s.key).to_string();
        groups.entry(group).or_default().push(sig_name);
    }
    let devices = groups
        .into_iter()
        .take(64) // 保险:超大信号集不铺满
        .map(|(g, sigs)| {
            let kind = if g.starts_with("unit") || g.contains("SDM") || g.contains("电") {
                "meter"
            } else if g.contains("104") || g.contains("PCS") || g.contains("簇") {
                "cluster"
            } else {
                "other"
            };
            iotprobe_core::topology::Device {
                id: g,
                kind: kind.into(),
                binds: sigs
                    .into_iter()
                    .take(32)
                    .map(|s| iotprobe_core::topology::Bind {
                        signal: s,
                        label: String::new(),
                        warn: None,
                        fault: None,
                    })
                    .collect(),
            }
        })
        .collect();
    iotprobe_core::topology::Topology { name: "自动生成".into(), devices }
}

struct TaskStats {
    tx: usize,
    timeouts: usize,
    exceptions: usize,
    rtt: Option<(f64, f64, f64, f64)>,
    worst_run: Option<(usize, u64, u64)>,
    both_dirs: bool,
}

/// 写指令事务(任务卡 A4):一条 func5/6/15/16 请求及其配对响应
#[derive(Debug)]
struct WriteTxn {
    req_fi: u32,
    resp_fi: Option<u32>,
    t_ns: u64,
    unit: u8,
    func: u8,
    addr: u16,
    /// func5: 0/1;func6: 寄存器值;func15/16: 数量
    val: u32,
    rtt_ms: Option<f64>,
    /// 响应为异常(func|0x80)时的子码
    exc: Option<u8>,
}

/// 从帧流识别某 Modbus 通道的写指令事务:请求(dir=Tx,func5/6/15/16)→ 下一帧 Rx 配对。
/// RTU PDU 从字节 1 起,TCP ADU 从字节 7 起;响应异常 = func|0x80。
fn write_txns(ds: &Dataset, c: &iotprobe_core::model::ChannelMeta) -> Vec<WriteTxn> {
    use iotprobe_core::model::{Dir, Proto};
    let pdu_off = match c.proto {
        Proto::ModbusRtu => 1usize,
        Proto::ModbusTcp => 7usize,
        _ => return vec![],
    };
    let is_write = |func: u8| matches!(func, 5 | 6 | 15 | 16);
    let mut out = vec![];
    let mut pending: Option<WriteTxn> = None;
    for (fi, f) in ds.frames.iter().enumerate() {
        if f.source != c.source || f.channel != c.id {
            continue;
        }
        let rec = &ds.records[f.record as usize];
        let data = &rec.data[f.off as usize..(f.off + f.len) as usize];
        if data.len() < pdu_off + 1 {
            continue;
        }
        let unit = data[pdu_off - 1];
        let func = data[pdu_off];
        match f.dir {
            Dir::Tx if is_write(func) && data.len() >= pdu_off + 5 => {
                // 请求:地址 = PDU[1..3];func5 值 0xFF00/0x0000 → 1/0,func6 值 PDU[3..5],15/16 数量 PDU[3..5]
                let addr = ((data[pdu_off + 1] as u16) << 8) | data[pdu_off + 2] as u16;
                let raw = ((data[pdu_off + 3] as u32) << 8) | data[pdu_off + 4] as u32;
                let val = match func {
                    5 => u32::from(raw == 0xFF00),
                    _ => raw,
                };
                pending = Some(WriteTxn { req_fi: fi as u32, resp_fi: None, t_ns: f.t_ns, unit, func, addr, val, rtt_ms: None, exc: None });
            }
            Dir::Rx => {
                // 响应:配最近一条未应答写请求
                if let Some(mut p) = pending.take() {
                    p.resp_fi = Some(fi as u32);
                    p.rtt_ms = Some((f.t_ns.saturating_sub(p.t_ns)) as f64 / 1e6);
                    if func == p.func | 0x80 {
                        p.exc = data.get(pdu_off + 1).copied();
                    }
                    out.push(p);
                }
            }
            _ => {}
        }
    }
    if let Some(p) = pending.take() {
        out.push(p); // 日志结束仍无响应的写指令
    }
    out
}

fn task_stats(ds: &Dataset, c: &iotprobe_core::model::ChannelMeta) -> TaskStats {
    use iotprobe_core::model::{Dir, EventKind};
    let mut tx = 0usize;
    let mut seen_rx = false;
    let mut seen_tx = false;
    for f in &ds.frames {
        if f.source == c.source && f.channel == c.id {
            match f.dir {
                Dir::Tx => {
                    tx += 1;
                    seen_tx = true;
                }
                Dir::Rx => seen_rx = true,
                _ => {}
            }
        }
    }
    let mut timeouts = 0usize;
    let mut exceptions = 0usize;
    let mut worst: Option<(usize, u64, u64)> = None;
    let mut cur = 0usize;
    let mut cur_t0 = 0u64;
    for e in &ds.events {
        if e.source != c.source || e.channel != c.id {
            continue;
        }
        match e.kind {
            EventKind::Timeout => timeouts += 1,
            EventKind::Exception => exceptions += 1,
            _ => {}
        }
        if matches!(e.kind, EventKind::Timeout | EventKind::Exception) {
            if cur == 0 {
                cur_t0 = e.t_ns;
            }
            cur += 1;
            if worst.map(|(n, _, _)| cur > n).unwrap_or(true) {
                worst = Some((cur, cur_t0, e.t_ns));
            }
        } else {
            cur = 0;
        }
    }
    let rtt_key = format!("RTT·{}", ds.channel_label(c.source, c.id));
    let rtt = ds.signals.iter().find(|s| s.key == rtt_key).map(|s| {
        let mut vals: Vec<f64> = s.pts.iter().map(|p| p.1).collect();
        vals.sort_by(|a, b| a.total_cmp(b));
        let n = vals.len();
        if n == 0 {
            (0.0, 0.0, 0.0, 0.0)
        } else {
            (vals[0], vals[n / 2], vals[((n as f64) * 0.95) as usize % n], vals[n - 1])
        }
    });
    TaskStats { tx, timeouts, exceptions, rtt, worst_run: worst, both_dirs: seen_rx && seen_tx }
}

/// D2 崩溃报告:当前会话标签(数据源名/实时名),panic hook 写入 crash 日志时带上
static SESSION_TAG: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// D1 增量更新:exe 同目录 update/manifest.json → {"version":"x.y.z","notes":"…"}
/// 版本更大则启动提示;不自动下载不自动替换(现场无网是常态,替换包由使用者手动放)。
fn check_update_manifest() -> Option<(String, String)> {
    let exe = std::env::current_exe().ok()?;
    let mf = exe.parent()?.join("update").join("manifest.json");
    let txt = std::fs::read_to_string(mf).ok()?;
    let v: serde_json::Value = serde_json::from_str(&txt).ok()?;
    let ver = v.get("version")?.as_str()?.to_string();
    let notes = v.get("notes").and_then(|n| n.as_str()).unwrap_or_default().to_string();
    let newer = |s: &str| -> Vec<u64> { s.split('.').map(|x| x.trim().parse().unwrap_or(0)).collect() };
    let (cur, new) = (newer(env!("CARGO_PKG_VERSION")), newer(&ver));
    let is_newer = (0..3).any(|i| new.get(i).unwrap_or(&0) > cur.get(i).unwrap_or(&0));
    is_newer.then_some((ver, notes))
}

fn set_session_tag(tag: &str) {
    if let Ok(mut g) = SESSION_TAG.lock() {
        *g = Some(tag.to_string());
    }
}

/// D2:crash 日志目录(exe 同目录;写入失败时静默放弃,不影响默认 panic 行为)
fn crash_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// D2 崩溃报告:panic hook 写 crash-<epoch_ms>.log(panic 信息+线程+会话标签+回溯栈),
/// 保留默认 hook 的 stderr 输出;下次启动 App::new 扫描 crash 日志给出提示。
fn install_crash_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let tag = SESSION_TAG.lock().ok().and_then(|g| g.clone()).unwrap_or_else(|| "(未加载会话)".into());
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>").to_string();
        let bt = std::backtrace::Backtrace::force_capture();
        let body = format!(
            "IoTProbe crash @ {} ms\n会话: {tag}\n线程: {thread_name}\npanic: {info}\n\nbacktrace:\n{bt}\n",
            ts
        );
        let path = crash_dir().join(format!("crash-{ts}.log"));
        let _ = std::fs::write(&path, body.as_bytes());
        default_hook(info);
    }));
}

/// D2:扫描 crash 日志,返回最新一条(启动提示"上次异常退出")
fn latest_crash_log() -> Option<PathBuf> {
    let dir = crash_dir();
    let rd = std::fs::read_dir(&dir).ok()?;
    let mut best: Option<(u64, PathBuf)> = None;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(ts) = name.strip_prefix("crash-").and_then(|s| s.strip_suffix(".log")).and_then(|s| s.parse::<u64>().ok()) {
            if best.as_ref().map(|(t, _)| ts > *t).unwrap_or(true) {
                best = Some((ts, e.path()));
            }
        }
    }
    best.map(|(_, p)| p)
}

fn main() -> eframe::Result<()> {
    install_crash_hook();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1500.0, 920.0])
            .with_min_inner_size([1000.0, 600.0])
            .with_title(format!("IoTProbe v{} — IoT 日志多协议解析与时序分析", env!("CARGO_PKG_VERSION"))),
        ..Default::default()
    };
    eframe::run_native("IoTProbe", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

#[cfg(test)]
mod moddev_e2e {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    const YAML: &str = r#"
dev1: {enable: 1, name: 测试PCS, link: tcp, port: 15022, slave: 1, poll_ms: 1000}
dev1_状态:
  a30: {name: 电网电压, addr: 0x001E, func: 3, type: u16, scale: 0.1, grp: 状态, init: 4000}
  a33: {name: 系统启停状态, addr: 0x0021, func: 3, type: bit, bit: 0, grp: 状态}
  a40: {name: 母线功率, addr: 0x0028, func: 3, type: i32, regs: 2, grp: 状态, init: -100}
dev1_控制:
  a1001: {name: 总开机, addr: 0x03E9, func: 3, type: u16, rw: 1, wfunc: 6, grp: 控制}
"#;

    fn mbap(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
        let mut f = vec![(tid >> 8) as u8, tid as u8, 0, 0, ((pdu.len() + 1) >> 8) as u8, (pdu.len() + 1) as u8, unit];
        f.extend_from_slice(pdu);
        f
    }

    fn transact(c: &mut TcpStream, tid: u16, pdu: &[u8]) -> Vec<u8> {
        c.write_all(&mbap(tid, 1, pdu)).unwrap();
        let mut hdr = [0u8; 7];
        c.read_exact(&mut hdr).unwrap();
        let len = (((hdr[4] as usize) << 8) | hdr[5] as usize) - 1;
        let mut rest = vec![0u8; len];
        c.read_exact(&mut rest).unwrap();
        rest
    }

    #[test]
    fn rw_loop_e2e() {
        let (rt, warns, _h) = crate::moddev::ModDevRuntime::start(YAML).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        assert!(rt.devs[0].port_bound);

        let mut c = TcpStream::connect("127.0.0.1:15022").expect("客户端连接");
        std::thread::sleep(std::time::Duration::from_millis(100));

        // func3 读 init
        let resp = transact(&mut c, 1, &[3, 0x00, 0x1E, 0x00, 0x01]);
        assert_eq!(resp[0], 3);
        assert_eq!(((resp[2] as u16) << 8) | resp[3] as u16, 4000, "init raw 直读");
        // func6 写 → 回读(控制闭环)
        transact(&mut c, 2, &[6, 0x03, 0xE9, 0x00, 0x01]);
        let resp = transact(&mut c, 3, &[3, 0x03, 0xE9, 0x00, 0x01]);
        assert_eq!(((resp[2] as u16) << 8) | resp[3] as u16, 1, "写后回读 = 1");
        // func16 多写
        transact(&mut c, 4, &[16, 0x00, 0x30, 0x00, 0x02, 0x04, 0x12, 0x34, 0xAB, 0xCD]);
        let resp = transact(&mut c, 5, &[3, 0x00, 0x30, 0x00, 0x02]);
        assert_eq!(resp[2], 0x12);
        assert_eq!(resp[4], 0xAB);
        // 异常码
        let resp = transact(&mut c, 6, &[3, 0x70, 0x00, 0x00, 0x01]);
        assert_eq!(resp[0], 0x83);
        assert_eq!(resp[1], 0x02);
        // NDJSON 快照
        std::thread::sleep(std::time::Duration::from_millis(150));
        let lines = rt.drain();
        assert!(lines.len() >= 12, "6 事务 × 2 = 12 行,实际 {}", lines.len());
        assert!(lines.iter().any(|l| l.contains("rx")));
        rt.stop_all();
    }

    #[test]
    fn setpoint_and_scene() {
        // 与 rw_loop_e2e 并行执行:用不同端口避免 bind 冲突
        let yaml2 = YAML.replace("15022", "15023");
        let (rt, _w, _h) = crate::moddev::ModDevRuntime::start(&yaml2).unwrap();
        assert!(rt.set_point(0, "系统启停状态", 1.0));
        let sp = rt.devs[0].space.lock().unwrap();
        assert_eq!(sp.read(3, 0x0021, 1).unwrap()[0] & 1, 1);
        assert!(sp.writes >= 1);
        drop(sp);
        *rt.scene.lock().unwrap() = crate::moddev::Scene::Fault;
        std::thread::sleep(std::time::Duration::from_millis(700));
        rt.stop_all();
    }

    #[test]
    fn ptedit_host_reads_pinned_and_temp_point_e2e() {
        // 端口 0 = 系统分配(与并行测试互不冲突);从 bound_port 取实际端口
        let (rt, warns, _h) = crate::moddev::ModDevRuntime::start(&YAML.replace("15022", "0")).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        assert!(rt.devs[0].port_bound);
        // 初始:无钉住、主机未读
        let rows = rt.points_view(0, "电网");
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].pinned);
        assert!(rows[0].host.is_none(), "自轮询不算主机读");
        assert_eq!(rows[0].unit, ""); // 测试表未写 unit
        // 真实主机读(同 rw_loop_e2e 的 MBAP 封装)
        let mut c = TcpStream::connect(("127.0.0.1", rt.devs[0].bound_port)).expect("客户端连接");
        let resp = transact(&mut c, 1, &[3, 0x00, 0x1E, 0x00, 0x01]);
        assert_eq!(resp[0], 3);
        let rows = rt.points_view(0, "电网");
        let (v, n, _ago) = rows[0].host.expect("主机读到电网电压");
        assert!((v - 400.0).abs() < 1e-9, "phys = raw 4000 × scale 0.1");
        assert_eq!(n, 1);
        // 再读一次(0x0028 两个寄存器 = 母线功率 i32)→ 次数累加、第二个点也被记
        let resp = transact(&mut c, 2, &[3, 0x00, 0x28, 0x00, 0x02]);
        assert_eq!(resp[0], 3);
        let bus = rt.points_view(0, "母线").remove(0);
        assert_eq!(bus.host.map(|h| h.0), Some(-100.0));
        // 异常码不记(读未定义地址 0x7000)
        let resp = transact(&mut c, 3, &[3, 0x70, 0x00, 0x00, 0x01]);
        assert_eq!(resp[0], 0x83);
        // 置值 → 钉住 → Random 不动它 → 释放后可动
        assert!(rt.set_point(0, "电网电压", 410.0));
        assert!(rt.points_view(0, "电网")[0].pinned);
        *rt.scene.lock().unwrap() = crate::moddev::Scene::Random;
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let v = rt.points_view(0, "电网")[0].phys;
        assert!((v - 410.0).abs() < 1e-9, "钉住的点 Random 场景不动(实际 {v})");
        assert_eq!(rt.release_all_pins(0), 1);
        assert!(!rt.points_view(0, "电网")[0].pinned);
        // 临时点:加完即可被主机读到、表格里可见(分组「临时」)
        let tmp = iotprobe_core::moddev::MbPoint {
            key: "tmp_0x0040".into(),
            name: "临时功率".into(),
            addr: 0x0040,
            func: 3,
            ty: "i32".into(),
            regs: 2,
            scale: 1.0,
            bit: None,
            grp: "临时".into(),
            rw: true,
            min: None,
            max: None,
            init: Some(7.0),
            init_str: None,
            unit: Some("kW".into()),
            enum_: None,
        };
        rt.add_temp_point(0, tmp).unwrap();
        assert!(rt.add_temp_point(0, rt.devs[0].meta.points[0].clone()).is_err(), "同名/同键重复拒绝");
        assert!(rt.set_point(0, "临时功率", 123.0));
        let rows = rt.points_view(0, "临时");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].phys, 123.0);
        assert_eq!(rows[0].unit, "kW");
        let resp = transact(&mut c, 4, &[3, 0x00, 0x40, 0x00, 0x02]);
        assert_eq!(resp[0], 3);
        // i32 两寄存器:高字在前(0x0000 0x007B = 123)
        let hi = (((resp[2] as u16) << 8) | resp[3] as u16) as u32;
        let lo = (((resp[4] as u16) << 8) | resp[5] as u16) as u32;
        assert_eq!(((hi << 16) | lo) as i32, 123, "主机读到临时点的值");
        let rows = rt.points_view(0, "临时功率");
        assert_eq!(rows[0].host.map(|h| h.0), Some(123.0));
        // 只看已置/只看主机可写 过滤语义由 UI 做;这里验证 PointRow 字段齐备
        assert!(rows[0].rw);
        rt.stop_all();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod ptedit_test {
    // 点位编辑窗:临时点回写为 devN_临时点位 分节 → 解析往返;二次回写拒绝(避免 YAML 重复键)
    use super::*;

    #[test]
    fn temp_point_writeback_round_trip() {
        let pts = vec![ModTempPoint {
            dev_id: 1,
            key: "tmp_0x0100".into(),
            name: "临时电压".into(),
            addr: 0x0100,
            func: 3,
            ty: "u16".into(),
            regs: 1,
            scale: 0.1,
            unit: "V".into(),
            init_raw: 500.0,
        }];
        // 分节文本 → 解析器往返
        let yaml = format!("dev1: {{enable: 1, name: PCS-1号, port: 502}}{}", moddev_temp_section(1, &pts));
        let (devs, warns) = iotprobe_core::moddev::parse_points_yaml(&yaml).unwrap();
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].points.len(), 1);
        let p = &devs[0].points[0];
        assert_eq!(p.name, "临时电压");
        assert_eq!(p.addr, 0x0100);
        assert_eq!(p.func, 3);
        assert_eq!(p.ty, "u16");
        assert_eq!(p.unit.as_deref(), Some("V"));
        assert_eq!(p.init, Some(500.0));
        assert!(p.rw);
        assert_eq!(p.grp, "临时");
        // 写文件:无尾换行的原文件也能正确追加;二次回写拒绝
        let dir = std::env::temp_dir().join("iotprobe_ptedit_test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pts.yaml");
        std::fs::write(&f, "dev1: {enable: 1, name: PCS, port: 502}").unwrap();
        assert_eq!(moddev_writeback(&f, &pts).unwrap(), 1);
        let txt = std::fs::read_to_string(&f).unwrap();
        assert!(txt.contains("dev1_临时点位:"), "分节已追加");
        let (devs, _) = iotprobe_core::moddev::parse_points_yaml(&txt).unwrap();
        assert_eq!(devs[0].points.len(), 1, "追加后的文件能解析出临时点");
        assert!(moddev_writeback(&f, &pts).is_err(), "分节已存在 → 拒绝(避免重复键)");
        assert!(moddev_writeback(std::path::Path::new(""), &pts).is_err(), "空路径 → 报错");
        std::fs::remove_file(&f).ok();
    }

    #[test]
    fn yaml_escape_handles_quotes() {
        assert_eq!(yaml_escape("a\"b\\c"), "a\\\"b\\\\c");
    }
}

#[cfg(test)]
mod write_txn_test {
    // 任务卡 A4:写指令事务识别与配对(func5/6/15/16 → 请求+响应+RTT;func3 读不进写视图)
    use iotprobe_core::crc;
    use iotprobe_core::dissect::{analyze, AnalyzeCfg};
    use iotprobe_core::ingest::live::{BusKind, LiveFrame};
    use iotprobe_core::model::{Dir, Proto, TsSrc};

    fn rtu_line(unit: u8, pdu_core: &[u8], dir: Dir, ts_ns: u64) -> String {
        // RTU ADU = unit + PDU(func 起) + CRC16(低位在前)
        let mut adu = vec![unit];
        adu.extend_from_slice(pdu_core);
        let c = crc::crc16_modbus(&adu);
        adu.push(c as u8);
        adu.push((c >> 8) as u8);
        let f = LiveFrame {
            ts_ns,
            ts_src: TsSrc::Sw,
            bus_type: BusKind::Uart,
            ch: 1,
            alias: Some("写指令测试·485".into()),
            dir,
            id: 0,
            id_ext: false,
            dlc: adu.len(),
            data: adu,
            seq: None,
            meta_gap: None,
        };
        crate::live::live_frame_to_jsonl(&f)
    }

    #[test]
    fn write_txn_pairing() {
        let dir = std::env::temp_dir().join(format!("iotprobe_wrtest_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("wr.ndjson");
        let base: u64 = 1000;
        // func6 写 0x03E9=1(Tx) → 1.5ms 后响应(Rx);再来一对 func3 读(不进写视图)
        let mut lines = vec![
            rtu_line(1, &[6, 0x03, 0xE9, 0x00, 0x01], Dir::Tx, base),
            rtu_line(1, &[6, 0x03, 0xE9, 0x00, 0x01], Dir::Rx, base + 1_500_000),
            rtu_line(1, &[3, 0x00, 0x1E, 0x00, 0x01], Dir::Tx, base + 3_000_000),
            rtu_line(1, &[3, 0x02, 0x01, 0x0F, 0xA0], Dir::Rx, base + 4_000_000),
        ];
        // func6 异常响应(0x86 / 0x02):应标 exc,RTT 有值
        lines.push(rtu_line(2, &[6, 0x10, 0x00, 0x00, 0x01], Dir::Tx, base + 6_000_000));
        lines.push(rtu_line(2, &[0x86, 0x02], Dir::Rx, base + 6_500_000));
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();

        let sd = iotprobe_core::ingest::read_file(&p).unwrap();
        let ds = analyze(vec![sd], &AnalyzeCfg::default());
        let ch = ds
            .channels
            .iter()
            .find(|c| matches!(c.proto, Proto::ModbusRtu))
            .expect("NDJSON 重放的 RTU 帧应识别出 Modbus RTU 通道");
        let txns = crate::write_txns(&ds, ch);
        assert_eq!(txns.len(), 2, "func6 ×2(正常+异常),func3 读不进写视图: {txns:?}");
        let t0 = &txns[0];
        assert_eq!(t0.func, 6);
        assert_eq!(t0.addr, 0x03E9);
        assert_eq!(t0.val, 1);
        assert_eq!(t0.unit, 1);
        assert!(t0.exc.is_none(), "第一笔应答正常");
        assert_eq!(t0.resp_fi, Some(t0.req_fi + 1));
        assert!(t0.rtt_ms.unwrap() >= 1.4, "RTT≈1.5ms,实际 {}", t0.rtt_ms.unwrap());
        let t1 = &txns[1];
        assert_eq!(t1.unit, 2);
        assert_eq!(t1.exc, Some(0x02), "异常应答应带子码 0x02");
        std::fs::remove_dir_all(&dir).ok();
    }
}
