//! 视图组件:虚拟化帧表、hex+字段树详情、事件列表、通道统计。

use egui::{Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, Vec2};
use iotprobe_core::model::{Dataset, Decoded, Field, Frame, Proto, Value};

// ---- Design tokens(主题感知):文字/弱文字/选中底/悬停底,亮暗两套 ----
fn txt(u: &egui::Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(205, 210, 218) } else { Color32::from_rgb(38, 43, 52) }
}
fn txt_dim(u: &egui::Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(120, 128, 140) } else { Color32::from_rgb(104, 112, 122) }
}
fn sel_bg(u: &egui::Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(46, 60, 82) } else { Color32::from_rgb(212, 228, 250) }
}
fn hover_bg(u: &egui::Ui) -> Color32 {
    if u.visuals().dark_mode { Color32::from_rgb(36, 40, 48) } else { Color32::from_rgb(230, 234, 240) }
}

pub const ROW_H: f32 = 20.0;

fn col(c: [u8; 3]) -> Color32 {
    Color32::from_rgb(c[0], c[1], c[2])
}

pub fn series_color(i: usize) -> Color32 {
    // 高饱和度调色板循环
    const PALETTE: [[u8; 3]; 12] = [
        [86, 182, 224], [255, 166, 61], [155, 205, 90], [229, 90, 90],
        [171, 130, 255], [240, 200, 90], [80, 220, 180], [235, 130, 180],
        [130, 160, 235], [190, 140, 100], [110, 200, 120], [220, 220, 120],
    ];
    col(PALETTE[i % PALETTE.len()])
}

/// 完整调色板(图例 chips 右键改色用)
pub fn palette() -> Vec<Color32> {
    const PALETTE: [[u8; 3]; 12] = [
        [86, 182, 224], [255, 166, 61], [155, 205, 90], [229, 90, 90],
        [171, 130, 255], [240, 200, 90], [80, 220, 180], [235, 130, 180],
        [130, 160, 235], [190, 140, 100], [110, 200, 120], [220, 220, 120],
    ];
    PALETTE.iter().map(|c| col(*c)).collect()
}

// ================= 帧表 =================

/// 可排序列
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SortKey {
    Idx,
    Time,
    Dt,
    Dir,
    Proto,
    Chan,
    Len,
}

const COLS: &[(f32, &str, Option<SortKey>)] = &[
    (50.0, "#", Some(SortKey::Idx)),
    (92.0, "时间", Some(SortKey::Time)),
    (86.0, "Δt", Some(SortKey::Dt)),
    (30.0, "向", Some(SortKey::Dir)),
    (84.0, "协议", Some(SortKey::Proto)),
    (110.0, "通道", Some(SortKey::Chan)),
    (44.0, "长", Some(SortKey::Len)),
];

pub fn frame_table(
    ui: &mut egui::Ui,
    ds: &Dataset,
    shown: &[u32],
    sel: Option<u32>,
    out_sel: &mut Option<u32>,
    want_scroll: &mut Option<u32>,
    sort: &mut (SortKey, bool),
    out_filter: &mut Option<String>,
    out_hover: &mut Option<u32>,
) {
    let text_h = 14.0;
    // 表头(可点击排序)
    let (hr, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_H), Sense::hover());
    let mut x = hr.left();
    for (w, name, key) in COLS {
        let cr = Rect::from_min_size(Pos2::new(x, hr.top()), Vec2::new(*w, ROW_H));
        let resp = ui
            .allocate_rect(cr, Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        let arrow = if *key == Some(sort.0) {
            if sort.1 { " ▼" } else { " ▲" }
        } else {
            ""
        };
        let hc = if *key == Some(sort.0) { txt(ui) } else { txt_dim(ui) };
        ui.painter().text(Pos2::new(x + 4.0, hr.center().y), Align2::LEFT_CENTER, &format!("{name}{arrow}"), FontId::proportional(11.5), hc);
        if let Some(k) = key {
            if resp.clicked() {
                if sort.0 == *k {
                    sort.1 = !sort.1;
                } else {
                    sort.0 = *k;
                    sort.1 = false;
                }
            }
        }
        x += w;
    }
    ui.painter().text(Pos2::new(x + 4.0, hr.center().y), Align2::LEFT_CENTER, "摘要", FontId::proportional(11.5), txt_dim(ui));
    ui.add_space(2.0);
    let _avail = ui.available_height().max(ROW_H);
    let mut scroll_target = want_scroll.take().and_then(|w| shown.iter().position(|&x| x == w));
    let out = egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, ROW_H, shown.len(), |ui, range| {
            for row in range {
                let fi = shown[row] as usize;
                let f = &ds.frames[fi];
                let (r, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_H), Sense::click());
                let p = ui.painter();
                let hovered = resp.hovered();
                if hovered {
                    *out_hover = Some(fi as u32);
                }
                if Some(fi as u32) == sel {
                    p.rect_filled(r, 1.0, sel_bg(ui));
                } else if hovered {
                    p.rect_filled(r, 1.0, hover_bg(ui));
                }
                // Δt(同通道与前帧间隔)
                let dt_s = if fi > 0 && ds.frames[fi - 1].channel == f.channel && ds.frames[fi - 1].source == f.source {
                    (f.t_ns.saturating_sub(ds.frames[fi - 1].t_ns)) as f64 / 1e6
                } else {
                    0.0
                };
                let mut x = r.left();
                let cells: Vec<(String, Color32)> = vec![
                    (fi.to_string(), txt_dim(ui)),
                    (iotprobe_core::timeutil::fmt_rel_ns(f.t_ns), txt(ui)),
                    (if dt_s > 0.0 { iotprobe_core::timeutil::fmt_dt_ns((dt_s * 1e6) as i64) } else { "-".into() }, if dt_s > 1000.0 { Color32::from_rgb(240, 150, 60) } else { txt_dim(ui) }),
                    (f.dir.label().to_string(), col(f.dir.color())),
                    (f.proto.label().to_string(), col(f.proto.color())),
                    (ds.channel_label(f.source, f.channel), txt_dim(ui)),
                    (f.len.to_string(), txt_dim(ui)),
                ];
                for ((w, _, _), (s, c)) in COLS.iter().zip(cells) {
                    let cr = Rect::from_min_size(Pos2::new(x, r.top()), Vec2::new(*w, ROW_H));
                    p.with_clip_rect(cr).text(Pos2::new(x + 4.0, r.center().y), Align2::LEFT_CENTER, &s, FontId::monospace(text_h), c);
                    x += w;
                }
                let sr = Rect::from_min_size(Pos2::new(x, r.top()), Vec2::new(r.right() - x, ROW_H));
                p.with_clip_rect(sr).text(Pos2::new(x + 4.0, r.center().y), Align2::LEFT_CENTER, &f.summary, FontId::monospace(text_h), txt(ui));
                if resp.clicked() {
                    *out_sel = Some(fi as u32);
                }
                if resp.secondary_clicked() {
                    // 右键:按 ID / 协议快速过滤
                    let tok = match f.proto {
                        Proto::Can | Proto::CanFd => f.summary.split_whitespace().next().unwrap_or("CAN").to_string(),
                        Proto::ModbusRtu | Proto::ModbusTcp => f.summary.split(' ').nth(1).map(|w| w.to_string()).unwrap_or_else(|| f.proto.label().to_string()),
                        _ => f.proto.label().to_string(),
                    };
                    *out_filter = Some(tok);
                }
            }
        });
    // 联动滚动定位
    if let Some(row) = scroll_target.take() {
        let view_h = out.inner_rect.height().max(ROW_H);
        let mut st = out.state;
        st.offset.y = ((row as f32 * ROW_H) - view_h * 0.5).max(0.0);
        st.store(ui.ctx(), out.id);
    }
}

// ================= 详情(hex + 字段树) =================

fn field_by_path<'a>(root: &'a [Field], path: &[usize]) -> Option<&'a Field> {
    let mut cur_list = root;
    let mut cur: Option<&Field> = None;
    for (k, &i) in path.iter().enumerate() {
        if k == 0 {
            cur = cur_list.get(i);
            if cur.is_none() {
                return None;
            }
        } else {
            cur = cur.and_then(|c| c.children.get(i));
            if cur.is_none() {
                return None;
            }
        }
        if let Some(c) = cur {
            if k + 1 < path.len() {
                cur_list = &c.children;
            }
        }
    }
    cur
}

fn field_color(i: usize) -> Color32 {
    let c = series_color(i);
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 55)
}

/// 帧详情:字段树(可画曲线字段点圆点即加/删曲线,返回被切换的信号名)+ hex 并排。
/// `out_rclick`:右键点中的字段显示名(B2「在模拟器中定位该点位」用)。
pub fn detail_pane(
    ui: &mut egui::Ui,
    ds: &Dataset,
    fi: u32,
    dec: Option<&Decoded>,
    sel_path: &mut Vec<usize>,
    active: &std::collections::HashSet<String>,
    out_rclick: &mut Option<String>,
) -> Option<String> {
    let f = &ds.frames[fi as usize];
    let mut toggled: Option<String> = None;
    // 修复(同 Win11 高 DPI 溢出):summary 在 horizontal 里不换行会撑爆宽度 → 横向滚动裁剪
    egui::ScrollArea::horizontal()
        .id_salt("detail_head")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.set_min_height(18.0);
            ui.label(egui::RichText::new(format!("#{} {}", fi, f.summary)).monospace().size(12.0).color(txt(ui)));
        });
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("提示: 点字段左侧圆点 = 加/删曲线;点字段名 = 选中查看;右键字段 = 在模拟器中定位该点位")
            .size(10.0)
            .color(txt_dim(ui)),
    );
    // 字段树 + hex 并排
    ui.horizontal(|ui| {
        // ---- 字段树 ----
        egui::ScrollArea::vertical()
            .id_salt("tree")
            .max_height(400.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                match dec {
                    Some(dec) => {
                        if dec.root.is_empty() {
                            ui.label(egui::RichText::new("(无字段)").size(11.0).color(txt_dim(ui)));
                        }
                        toggled = draw_tree(ui, ds, &dec.root, &[], 0, sel_path, fi, active, out_rclick);
                    }
                    None => {
                        ui.label(egui::RichText::new("(解码失败)").size(11.0).color(txt_dim(ui)));
                    }
                }
            });
        ui.separator();
        // ---- hex ----
        let rec = &ds.records[f.record as usize];
        let data = &rec.data[f.off as usize..(f.off + f.len) as usize];
        // 选中字节的字段路径
        let root_fields: &[Field] = dec.map(|d| d.root.as_slice()).unwrap_or(&[]);
        egui::ScrollArea::both()
            .id_salt("hex")
            .max_height(400.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                draw_hex(ui, data, root_fields, sel_path, fi);
            });
    });
    toggled
}

#[allow(clippy::too_many_arguments)]
/// 字段显示名 → 信号裸名(DBC 字段形如 "name = value (label)")
fn bare_sig_name(disp: &str) -> String {
    disp.split_once(" = ").map(|(a, _)| a.trim().to_string()).unwrap_or_else(|| disp.trim().to_string())
}

#[allow(clippy::too_many_arguments)]
fn draw_tree(
    ui: &mut egui::Ui,
    ds: &Dataset,
    fields: &[Field],
    path: &[usize],
    depth: usize,
    sel_path: &mut Vec<usize>,
    fi: u32,
    active: &std::collections::HashSet<String>,
    out_rclick: &mut Option<String>,
) -> Option<String> {
    for (i, fld) in fields.iter().enumerate() {
        let mut p = path.to_vec();
        p.push(i);
        let name = ds.strings.get(fld.name).to_string();
        let unit = fld.unit.map(|u| ds.strings.get(u).to_string()).unwrap_or_default();
        let val_s = match &fld.val {
            Value::Hex(b) if b.len() > 16 => format!("{}B [{} …]", b.len(), b.iter().take(8).map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")),
            v => v.display(),
        };
        let sel = *sel_path == p;
        let row_h = 17.0;
        let (r, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), row_h), Sense::click());
        let pp = ui.painter();
        if sel {
            pp.rect_filled(r, 1.0, sel_bg(ui));
        } else if resp.hovered() {
            pp.rect_filled(r, 1.0, hover_bg(ui));
        }
        let indent = 8.0 + depth as f32 * 14.0;
        let x = r.left() + indent;
        // 可绘曲线字段:圆点实心=已在图中;点圆点即加/删曲线
        let bare = bare_sig_name(&name);
        let plotted = active.contains(&bare);
        if fld.plot {
            if plotted {
                pp.circle_filled(Pos2::new(r.left() + 5.0, r.center().y), 3.0, Color32::from_rgb(240, 200, 90));
            } else {
                pp.circle(Pos2::new(r.left() + 5.0, r.center().y), 3.0, Color32::TRANSPARENT, Stroke::new(1.2_f32, Color32::from_rgb(110, 118, 130)));
            }
        }
        if !fld.children.is_empty() {
            pp.text(Pos2::new(x, r.center().y), Align2::LEFT_CENTER, "▾", FontId::proportional(10.0), txt_dim(ui));
        }
        pp.text(Pos2::new(x + 10.0, r.center().y), Align2::LEFT_CENTER, &name, FontId::monospace(12.0), Color32::from_rgb(150, 190, 230));
        let val_x = r.left() + 175.0;
        let vr = Rect::from_min_size(Pos2::new(val_x, r.top()), Vec2::new(r.right() - val_x - 40.0, ROW_H));
        pp.with_clip_rect(vr).text(Pos2::new(val_x, r.center().y), Align2::LEFT_CENTER, &val_s, FontId::monospace(12.0), txt(ui));
        if !unit.is_empty() {
            pp.text(Pos2::new(r.right() - 36.0, r.center().y), Align2::RIGHT_CENTER, &unit, FontId::proportional(10.5), txt_dim(ui));
        }
        let mut toggled: Option<String> = None;
        if resp.clicked() {
            let dot_click = fld.plot && resp.interact_pointer_pos().map(|pt| pt.x < r.left() + 14.0).unwrap_or(false);
            if dot_click {
                toggled = Some(bare.clone());
            }
            *sel_path = p.clone();
        }
        if resp.secondary_clicked() {
            // B2:右键字段 → 在模拟器中定位该点位(main.rs 按名称/寄存器地址反查)
            *out_rclick = Some(bare.clone());
        }
        if !fld.children.is_empty() {
            if let Some(t) = draw_tree(ui, ds, &fld.children, &p, depth + 1, sel_path, fi, active, out_rclick) {
                toggled = Some(t);
            }
        }
        if toggled.is_some() {
            return toggled;
        }
    }
    None
}

fn draw_hex(ui: &mut egui::Ui, data: &[u8], root: &[Field], sel_path: &mut Vec<usize>, fi: u32) {
    let mono = FontId::monospace(12.0);
    let cw = 17.0f32;
    let bytes_per_row = 16usize;
    // 每个字节所属的顶层字段
    let field_of = |off: usize| -> Option<usize> {
        root.iter().position(|f| f.len > 0 && off >= f.start as usize && off < (f.start + f.len) as usize)
    };
    let sel_field: Option<&Field> = field_by_path(root, sel_path);
    let rows = data.len().div_ceil(bytes_per_row);
    for r in 0..rows {
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 18.0), Sense::click());
        let p = ui.painter();
        let base = r * bytes_per_row;
        // 偏移
        p.text(Pos2::new(rect.left(), rect.center().y), Align2::LEFT_CENTER, &format!("{base:04X}"), mono.clone(), txt_dim(ui));
        let mut bx = rect.left() + 42.0;
        for k in 0..bytes_per_row {
            let off = base + k;
            if off >= data.len() {
                break;
            }
            let fx = field_of(off);
            let is_sel = sel_field
                .map(|f| off >= f.start as usize && off < (f.start + f.len) as usize)
                .unwrap_or(false);
            if is_sel {
                p.rect_filled(Rect::from_min_size(Pos2::new(bx - 2.0, rect.top() + 1.0), Vec2::new(cw, 16.0)), 2.0, sel_bg(ui));
            } else if let Some(fi2) = fx {
                p.rect_filled(Rect::from_min_size(Pos2::new(bx - 2.0, rect.top() + 1.0), Vec2::new(cw, 16.0)), 2.0, field_color(fi2));
            }
            p.text(Pos2::new(bx, rect.center().y), Align2::LEFT_CENTER, &format!("{:02X}", data[off]), mono.clone(), txt(ui));
            bx += cw;
        }
        // ASCII
        let mut ax = bx + 10.0;
        for k in 0..bytes_per_row {
            let off = base + k;
            if off >= data.len() {
                break;
            }
            let ch = data[off];
            let s = if (0x20..0x7F).contains(&ch) { (ch as char).to_string() } else { "·".into() };
            p.text(Pos2::new(ax, rect.center().y), Align2::LEFT_CENTER, &s, mono.clone(), txt_dim(ui));
            ax += 9.0;
        }
        if resp.clicked() {
            if let Some(p2) = resp.interact_pointer_pos() {
                let k = ((p2.x - (rect.left() + 42.0)) / cw) as usize;
                let off = base + k;
                if off < data.len() {
                    if let Some(path) = deepest_field_path(root, off, 0, vec![]) {
                        *sel_path = path;
                    }
                }
                let _ = fi;
            }
        }
    }
}

fn deepest_field_path(root: &[Field], off: usize, depth: usize, mut path: Vec<usize>) -> Option<Vec<usize>> {
    let mut best: Option<Vec<usize>> = None;
    for (i, f) in root.iter().enumerate() {
        let start = f.start as usize;
        let end = start + f.len as usize;
        if f.len > 0 && off >= start && off < end {
            let mut p = path.clone();
            p.push(i);
            let deeper = if !f.children.is_empty() {
                deepest_field_path(&f.children, off, depth + 1, p.clone())
            } else {
                None
            };
            best = Some(deeper.unwrap_or(p));
        }
        let _ = &mut path;
    }
    let _ = depth;
    best
}

// ================= 事件列表 =================

pub fn events_list(ui: &mut egui::Ui, ds: &Dataset, sel: Option<u32>, out_sel: &mut Option<u32>) {
    egui::ScrollArea::vertical()
        .id_salt("events")
        .auto_shrink([false, false])
        .show_rows(ui, ROW_H, ds.events.len(), |ui, range| {
            for row in range {
                let e = &ds.events[row];
                let (r, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_H), Sense::click());
                let p = ui.painter();
                if e.frame.is_some() && Some(e.frame.unwrap()) == sel {
                    p.rect_filled(r, 1.0, sel_bg(ui));
                } else if resp.hovered() {
                    p.rect_filled(r, 1.0, hover_bg(ui));
                }
                let c = col(e.kind.color());
                p.circle_filled(Pos2::new(r.left() + 8.0, r.center().y), 3.0, c);
                p.text(Pos2::new(r.left() + 18.0, r.center().y), Align2::LEFT_CENTER, &format!("{:.3}s", e.t_ns as f64 / 1e9), FontId::monospace(12.0), txt_dim(ui));
                let kind_txt = match &e.rule {
                    Some(r) => format!("{} ({})", e.kind.label(), r.rule_id),
                    None => e.kind.label().to_string(),
                };
                p.text(Pos2::new(r.left() + 76.0, r.center().y), Align2::LEFT_CENTER, &kind_txt, FontId::proportional(11.5), c);
                let dr = Rect::from_min_size(Pos2::new(r.left() + 150.0, r.top()), Vec2::new(r.right() - r.left() - 150.0, ROW_H));
                p.with_clip_rect(dr).text(Pos2::new(r.left() + 154.0, r.center().y), Align2::LEFT_CENTER, &e.detail, FontId::monospace(11.5), txt(ui));
                if resp.clicked() {
                    if let Some(f) = e.frame {
                        *out_sel = Some(f);
                    }
                }
            }
        });
}

// ================= 拓扑连线图(任务卡 A1) =================

/// 拓扑连线图:左=主机(EMS/HMI)节点,右=各模拟器设备端点,连线颜色=链路健康。
/// 绿=有主机连接且无近期异常;红=连接断开/近 5s 异常码;灰=从未有主机连入(自轮询不算)。
/// 线型:Modbus TCP 实线 / RTU-over-TCP 虚线。点设备节点 → 跳转对应帧过滤。
pub fn topo_links(
    ui: &mut egui::Ui,
    host_label: &str,
    devs: &[&crate::moddev::DevState],
    clicked: &mut Option<usize>,
) {
    use crate::moddev::LinkState;
    use egui::StrokeKind;
    let n = devs.len();
    let row_h = 64.0;
    let h = (n as f32 * row_h + 24.0).max(140.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), h), Sense::hover());
    // 主机节点(垂直居中)——painter 只在块内借用,设备循环里要 allocate_rect(可变借用 ui)
    let host_w = 130.0;
    let host_rect = Rect::from_min_size(
        Pos2::new(rect.left() + 8.0, rect.center().y - 26.0),
        Vec2::new(host_w, 52.0),
    );
    {
        let p = ui.painter();
        p.rect_filled(host_rect, 4.0, sel_bg(ui));
        p.rect(host_rect, 4.0, Color32::TRANSPARENT, Stroke::new(1.0_f32, txt_dim(ui)), StrokeKind::Middle);
        p.text(Pos2::new(host_rect.center().x, host_rect.center().y - 9.0), Align2::CENTER_CENTER, host_label, FontId::proportional(13.0), txt(ui));
        p.text(Pos2::new(host_rect.center().x, host_rect.center().y + 11.0), Align2::CENTER_CENTER, "主机侧连接各设备端点", FontId::proportional(9.5), txt_dim(ui));
    }
    // 设备节点(右侧堆叠)
    let dev_w = 250.0;
    let dev_x = rect.right() - dev_w - 8.0;
    for (i, d) in devs.iter().enumerate() {
        let cy = rect.top() + 12.0 + i as f32 * row_h + row_h / 2.0;
        let dr = Rect::from_min_size(Pos2::new(dev_x, cy - 24.0), Vec2::new(dev_w, 48.0));
        let resp = ui.allocate_rect(dr, Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
        let (stroke_c, state_txt) = match d.link_state() {
            LinkState::Green => (Color32::from_rgb(120, 200, 130), "正常".to_string()),
            LinkState::Red(r) => (Color32::from_rgb(229, 90, 90), r),
            LinkState::Gray => (txt_dim(ui), "无流量".to_string()),
        };
        let p = ui.painter();
        if resp.hovered() {
            p.rect_filled(dr, 4.0, hover_bg(ui));
        }
        p.rect(dr, 4.0, Color32::TRANSPARENT, Stroke::new(1.2_f32, stroke_c), StrokeKind::Middle);
        p.text(Pos2::new(dr.left() + 10.0, dr.top() + 12.0), Align2::LEFT_CENTER, &d.meta.name, FontId::proportional(12.0), txt(ui));
        p.text(Pos2::new(dr.left() + 10.0, dr.top() + 32.0), Align2::LEFT_CENTER, &format!("unit={} {}", d.meta.slave, d.endpoint()), FontId::monospace(10.0), txt_dim(ui));
        // 状态徽章(右上)
        p.text(Pos2::new(dr.right() - 8.0, dr.top() + 12.0), Align2::RIGHT_CENTER, state_txt, FontId::proportional(10.0), stroke_c);
        // 未绑定端口告警
        if !d.port_bound {
            p.text(Pos2::new(dr.right() - 8.0, dr.top() + 32.0), Align2::RIGHT_CENTER, "未绑定", FontId::proportional(9.5), Color32::from_rgb(235, 120, 100));
        }
        // 连线:主机右缘 → 设备左缘;RTU 虚线
        let a = Pos2::new(host_rect.right(), host_rect.center().y);
        let b = Pos2::new(dr.left(), cy);
        let stroke = Stroke::new(if matches!(d.link_state(), LinkState::Red(_)) { 2.2_f32 } else { 1.6_f32 }, stroke_c);
        if d.link_label().contains("RTU") {
            let mid1 = Pos2::new((a.x + b.x) / 2.0, a.y);
            let mid2 = Pos2::new((a.x + b.x) / 2.0, b.y);
            for seg in egui::Shape::dashed_line(&[a, mid1, mid2, b], stroke, 6.0, 4.0) {
                p.add(seg);
            }
        } else {
            // 直线+水平肘:主机右缘水平引出后接设备左缘(经典拓扑连线)
            let elbow = Pos2::new(b.x - 40.0, a.y);
            p.add(egui::Shape::line_segment([a, elbow], stroke));
            p.add(egui::Shape::line_segment([elbow, b], stroke));
        }
        // 线中点:链路形态标签
        p.text(
            Pos2::new((a.x + b.x) / 2.0, (a.y + b.y) / 2.0 - 8.0),
            Align2::CENTER_CENTER,
            if d.link_label().contains("RTU") { "RTU透传" } else { "TCP" },
            FontId::proportional(9.5),
            txt_dim(ui),
        );
        if resp.clicked() {
            *clicked = Some(i);
        }
    }
    if n == 0 {
        ui.painter().text(rect.center(), Align2::CENTER_CENTER, "(模拟器未运行:启动后此处显示 主机→设备 链路)", FontId::proportional(11.5), txt_dim(ui));
    }
}

// ================= 通道统计 =================

pub fn channels_panel(ui: &mut egui::Ui, ds: &Dataset) {
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        for (ci, c) in ds.channels.iter().enumerate() {
            let idxs: Vec<&Frame> = ds.frames.iter().filter(|f| f.source == c.source && f.channel == c.id).collect();
            if idxs.is_empty() {
                continue;
            }
            let span = (idxs.last().unwrap().t_ns.saturating_sub(idxs[0].t_ns)) as f64 / 1e9;
            let rate = if span > 0.001 { idxs.len() as f64 / span } else { 0.0 };
            let ev_n = ds.events.iter().filter(|e| e.source == c.source && e.channel == c.id).count();
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("{} ", c.proto.label())).monospace().size(11.5).color(col(c.proto.color())));
                ui.label(egui::RichText::new(&c.label).monospace().size(11.5).color(txt(ui)));
            });
            let ts = c.ts_src;
            ui.label(
                egui::RichText::new(format!(
                    "   {}帧 · 跨度{:.2}s · {:.1}帧/s · 事件{} · 时基 {}({})",
                    idxs.len(),
                    span,
                    rate,
                    ev_n,
                    ts.label(),
                    ts.level()
                ))
                .size(10.5)
                .color(txt_dim(ui)),
            );
            if ci + 1 < ds.channels.len() {
                ui.separator();
            }
        }
    });
}
