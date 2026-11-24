//! 自绘时序图:曲线 + 事件泳道 + 十字光标 + 点击选帧 + 滚轮缩放/拖拽平移。
//! 自绘而非用 egui_plot:交互(联动选帧、事件道、hover 读数)完全可控,零版本耦合。

use egui::{Align2, Color32, FontId, Pos2, Rect, Sense, Shape, Stroke, Vec2};
use iotprobe_core::model::{Dataset, Event};

pub struct PlotState {
    /// 可视时间范围(秒)
    pub t0: f64,
    pub t1: f64,
    /// true = 多系列各自归一化(0-1 带独立标签);false = 共用一个 Y 轴
    pub normalized: bool,
    /// 测量游标 A/B(秒;None=未设)。左键点击设 A,Shift+点击设 B,右键点击清除
    pub cursor_a: Option<f64>,
    pub cursor_b: Option<f64>,
    /// 右键框选中(起点,当前点);松手按框缩放
    pub box_drag: Option<(egui::Pos2, egui::Pos2)>,
}

pub struct PlotOut {
    pub clicked_frame: Option<u32>,
    pub hover_t: Option<f64>,
}

const EVENT_LANE: f32 = 34.0;

fn nice_step(range: f64) -> f64 {
    let raw = range / 8.0;
    let mag = 10f64.powf(raw.abs().max(1e-12).log10().floor());
    for m in [1.0, 2.0, 5.0, 10.0] {
        if raw <= m * mag {
            return m * mag;
        }
    }
    10.0 * mag
}

fn fmt_time(s: f64) -> String {
    if s.abs() < 1.0 {
        format!("{:.0}ms", s * 1e3)
    } else if s.abs() < 60.0 {
        format!("{:.3}s", s)
    } else {
        format!("{}m{:.1}s", (s as i64) / 60, s % 60.0)
    }
}

pub fn fmt_val(v: f64) -> String {
    if v.abs() >= 1e6 || (v.abs() < 1e-3 && v != 0.0) {
        format!("{:.2e}", v)
    } else if v.abs() >= 100.0 {
        format!("{:.1}", v)
    } else {
        format!("{:.3}", v)
    }
}

pub struct PlotSeries<'a> {
    pub series: &'a iotprobe_core::model::Series,
    pub color: Color32,
}

#[allow(clippy::too_many_arguments)]
pub fn draw(
    ui: &mut egui::Ui,
    ds: &Dataset,
    series: &[PlotSeries<'_>],
    events: &[Event],
    sel_t: Option<u64>,
    state: &mut PlotState,
    reset: bool,
    follow: bool,
    preview_t: Option<u64>,
) -> PlotOut {
    let rect = ui.available_rect_before_wrap();
    let (rect, resp) = ui.allocate_exact_size(rect.size(), Sense::click_and_drag());
    let painter = ui.painter().with_clip_rect(rect);

    let t_max_ds = ds.t_max_ns() as f64 / 1e9;
    if reset || state.t1 <= state.t0 {
        state.t0 = 0.0;
        state.t1 = (t_max_ds * 1.1).max(1.0);
    }
    if follow {
        // 加法窗口:右缘 = 最新点 + 0.5s,左缘 = 右缘 − 窗宽。
        // 旧实现 t1 = t_max×1.02 是乘法余量:t_max 一大(模拟器跑久/换机时间基准不同),
        // 2% 间隙远超 10s 窗宽,最新数据被甩出窗口左侧 —— 曲线整体右移缩小到看不见(用户实测)
        const FOLLOW_PAD_S: f64 = 0.5;
        const FOLLOW_SPAN_S: f64 = 10.0;
        state.t1 = t_max_ds + FOLLOW_PAD_S;
        state.t0 = (state.t1 - FOLLOW_SPAN_S).max(0.0);
    }

    let plot_rect = Rect::from_min_max(rect.left_top(), Pos2::new(rect.right(), rect.bottom() - EVENT_LANE));
    let lane_rect = Rect::from_min_max(Pos2::new(rect.left(), plot_rect.bottom()), rect.right_bottom());
    let label_w = 62.0;
    let plot = Rect::from_min_max(Pos2::new(plot_rect.left() + label_w, plot_rect.top()), Pos2::new(plot_rect.right() - 6.0, plot_rect.bottom() - 16.0));

    // ---- 视口内的 y 范围 ----
    let (t0, t1) = (state.t0, state.t1);
    // 每系列的独立量程(归一化模式用;每帧重算代价 O(视口内点数),与曲线抽稀同量级)
    let per_range: Vec<(f64, f64)> = series
        .iter()
        .map(|ps| {
            let (mut lo, mut hi) = (f64::INFINITY, f64::NEG_INFINITY);
            for &(t, v, _) in &ps.series.pts {
                let ts = t as f64 / 1e9;
                if ts >= t0 && ts <= t1 {
                    lo = lo.min(v);
                    hi = hi.max(v);
                }
            }
            if !lo.is_finite() {
                lo = 0.0;
                hi = 1.0;
            }
            if (hi - lo).abs() < 1e-12 {
                hi = lo + 1.0;
            }
            let pad = (hi - lo) * 0.08;
            (lo - pad, hi + pad)
        })
        .collect();
    let mut y_min = f64::INFINITY;
    let mut y_max = f64::NEG_INFINITY;
    for ps in series {
        for &(t, v, _) in &ps.series.pts {
            let ts = t as f64 / 1e9;
            if ts >= t0 && ts <= t1 {
                y_min = y_min.min(v);
                y_max = y_max.max(v);
            }
        }
    }
    if !y_min.is_finite() {
        y_min = 0.0;
        y_max = 1.0;
    }
    if (y_max - y_min).abs() < 1e-12 {
        y_max = y_min + 1.0;
    }
    let pad = (y_max - y_min) * 0.08;
    y_min -= pad;
    y_max += pad;
    // 归一化:量程跨度差 3 倍以上才启用(同量纲系列共用轴更直观)
    let normalize = state.normalized && {
        let spans: Vec<f64> = per_range.iter().map(|(a, b)| b - a).collect();
        let max_s = spans.iter().cloned().fold(0.0, f64::max);
        let min_s = spans.iter().cloned().fold(f64::INFINITY, f64::min);
        max_s / min_s.max(1e-12) > 3.0
    };
    // v_to_y:按模式选全局或按系列归一
    let v_to_y_global = |v: f64| (plot.bottom() as f64 - ((v - y_min) / (y_max - y_min)) * plot.height() as f64) as f32;
    let v_to_y = |v: f64, si: usize| -> f32 {
        if normalize {
            let (lo, hi) = per_range[si];
            (plot.bottom() as f64 - ((v - lo) / (hi - lo)) * plot.height() as f64) as f32
        } else {
            v_to_y_global(v)
        }
    };

    let t_to_x = |t: f64| (plot.left() as f64 + ((t - t0) / (t1 - t0).max(1e-9)) * plot.width() as f64) as f32;
    let x_to_t = |x: f64| t0 + ((x - plot.left() as f64) / plot.width() as f64) * (t1 - t0);

    // ---- 背景 & 网格(主题感知) ----
    let dark = ui.visuals().dark_mode;
    let (bg_col, grid_col, txt_col, frame_col, panel_col, panel_txt_col) = if dark {
        (
            Color32::from_rgb(17, 19, 23),
            Color32::from_rgb(38, 42, 50),
            Color32::from_rgb(130, 138, 150),
            Color32::from_rgb(55, 60, 70),
            Color32::from_rgba_unmultiplied(24, 28, 34, 235),
            Color32::from_rgb(190, 198, 210),
        )
    } else {
        (
            Color32::from_rgb(252, 252, 254),
            Color32::from_rgb(228, 231, 238),
            Color32::from_rgb(110, 118, 130),
            Color32::from_rgb(195, 200, 210),
            Color32::from_rgba_unmultiplied(255, 255, 255, 238),
            Color32::from_rgb(60, 68, 80),
        )
    };
    painter.rect_filled(rect, 2.0, bg_col);
    let mono = FontId::monospace(10.0);

    let xstep = nice_step((t1 - t0) as f64);
    let mut t = (t0 / xstep).floor() * xstep;
    while t <= t1 {
        let x = t_to_x(t) as f32;
        if x >= plot.left() && x <= plot.right() {
            painter.line_segment([Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom())], Stroke::new(1.0_f32, grid_col));
            painter.text(Pos2::new(x, plot.bottom() + 3.0), Align2::CENTER_TOP, &fmt_time(t), mono.clone(), txt_col);
        }
        t += xstep;
    }
    let ystep = nice_step(y_max - y_min);
    let mut v = (y_min / ystep).floor() * ystep;
    while v <= y_max {
        let y = v_to_y_global(v) as f32;
        if y >= plot.top() && y <= plot.bottom() {
            painter.line_segment([Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)], Stroke::new(1.0_f32, grid_col));
            if !normalize {
                painter.text(Pos2::new(plot.left() - 3.0, y), Align2::RIGHT_CENTER, &fmt_val(v), mono.clone(), txt_col);
            }
        }
        v += ystep;
    }
    painter.rect_stroke(plot, 0.0, Stroke::new(1.0_f32, frame_col), egui::StrokeKind::Outside);

    // ---- 归一化模式:左侧画全局刻度淡化;每系列在右侧画自己的 min/max 标签 ----
    if normalize {
        for (si, ps) in series.iter().enumerate() {
            let (lo, hi) = per_range[si];
            let y_lo = v_to_y(lo, si);
            let y_hi = v_to_y(hi, si);
            let xr = plot.right() + 3.0;
            painter.text(Pos2::new(xr, (y_hi + 6.0).max(plot.top() + 6.0)), Align2::LEFT_TOP, &fmt_val(hi), FontId::monospace(9.5), ps.color);
            painter.text(Pos2::new(xr, (y_lo - 6.0).min(plot.bottom() - 6.0)), Align2::LEFT_BOTTOM, &fmt_val(lo), FontId::monospace(9.5), ps.color);
        }
    }

    // ---- 曲线(像素列 min/max 抽稀) ----
    for (si, ps) in series.iter().enumerate() {
        let mut pts: Vec<Pos2> = Vec::new();
        let w = plot.width().max(2.0) as usize;
        // 按像素列分桶
        let mut buckets: Vec<(f64, f64, u64, u64)> = vec![(f64::INFINITY, f64::NEG_INFINITY, u64::MAX, 0); w + 1];
        let mut in_view = 0usize;
        for &(t, v, _fi) in &ps.series.pts {
            let ts = t as f64 / 1e9;
            if ts < t0 || ts > t1 {
                continue;
            }
            in_view += 1;
            let col = (((ts - t0) / (t1 - t0)) * w as f64) as usize;
            let b = &mut buckets[col.min(w)];
            if v < b.0 {
                b.0 = v;
                b.2 = t;
            }
            if v > b.1 {
                b.1 = v;
                b.3 = t;
            }
        }
        if in_view <= w * 2 {
            // 数据少:直接画所有点
            for &(t, v, _) in &ps.series.pts {
                let ts = t as f64 / 1e9;
                if ts >= t0 && ts <= t1 {
                    pts.push(Pos2::new(t_to_x(ts) as f32, v_to_y(v, si)));
                }
            }
        } else {
            for (col, b) in buckets.iter().enumerate() {
                if b.0.is_finite() {
                    let x = plot.left() + col as f32;
                    pts.push(Pos2::new(x, v_to_y(b.0, si)));
                    if b.1 > b.0 {
                        pts.push(Pos2::new(x, v_to_y(b.1, si)));
                    }
                }
            }
        }
        if pts.len() >= 2 {
            painter.add(Shape::line(pts, Stroke::new(1.4_f32, ps.color)));
        } else if pts.len() == 1 {
            painter.circle_filled(pts[0], 2.0, ps.color);
        }
        let _ = &ps.color;
    }

    // ---- 事件泳道 ----
    painter.line_segment(
        [Pos2::new(rect.left(), lane_rect.top()), Pos2::new(rect.right(), lane_rect.top())],
        Stroke::new(1.0_f32, frame_col),
    );
    painter.text(
        Pos2::new(rect.left() + 6.0, lane_rect.top() + 2.0),
        Align2::LEFT_TOP,
        "异常",
        FontId::proportional(10.0),
        Color32::from_rgb(170, 100, 100),
    );
    for e in events {
        let ts = e.t_ns as f64 / 1e9;
        if ts < t0 || ts > t1 {
            continue;
        }
        let x = t_to_x(ts) as f32;
        let y = lane_rect.center().y + 6.0;
        let c = Color32::from_rgb(e.kind.color()[0], e.kind.color()[1], e.kind.color()[2]);
        painter.circle_filled(Pos2::new(x, y), 3.5, c);
    }

    // ---- 选中帧游标 ----
    if let Some(st) = sel_t {
        let ts = st as f64 / 1e9;
        if ts >= t0 && ts <= t1 {
            let x = t_to_x(ts) as f32;
            painter.line_segment(
                [Pos2::new(x, plot.top()), Pos2::new(x, lane_rect.bottom())],
                Stroke::new(1.0_f32, Color32::from_rgb(250, 200, 90)),
            );
        }
    }

    // ---- 帧表 hover 预览线(淡色,不抢选中) ----
    if let Some(pt) = preview_t {
        let ts = pt as f64 / 1e9;
        if ts >= t0 && ts <= t1 && sel_t != Some(pt) {
            let x = t_to_x(ts) as f32;
            painter.line_segment(
                [Pos2::new(x, plot.top()), Pos2::new(x, lane_rect.bottom())],
                Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(250, 200, 90, 70)),
            );
        }
    }

    // ---- 测量游标 A/B + 读数 ----
    let cursor_col_a = Color32::from_rgb(90, 210, 250);
    let cursor_col_b = Color32::from_rgb(240, 130, 220);
    for (t_opt, col) in [(state.cursor_a, cursor_col_a), (state.cursor_b, cursor_col_b)] {
        if let Some(ts) = t_opt {
            if ts >= t0 && ts <= t1 {
                let x = t_to_x(ts) as f32;
                painter.line_segment([Pos2::new(x, plot.top()), Pos2::new(x, lane_rect.bottom())], Stroke::new(1.2_f32, col));
                painter.text(Pos2::new(x + 4.0, plot.top() + 2.0), Align2::LEFT_TOP, if t_opt == state.cursor_a { "A" } else { "B" }, FontId::monospace(10.0), col);
            }
        }
    }
    if let (Some(a), Some(b)) = (state.cursor_a, state.cursor_b) {
        if b > a {
            // A/B 之间浅色带
            let (xa, xb) = (t_to_x(a) as f32, t_to_x(b) as f32);
            if xb > plot.left() && xa < plot.right() {
                painter.rect_filled(
                    Rect::from_min_max(Pos2::new(xa.max(plot.left()), plot.top()), Pos2::new(xb.min(plot.right()), lane_rect.bottom())),
                    0.0,
                    Color32::from_rgba_unmultiplied(120, 170, 220, 22),
                );
            }
        }
        // 读数框(顶部居中):Δt + 每系列 Δv/速率
        let dt = (b - a).abs();
        let mut lines = vec![format!("Δt = {}", fmt_time(dt))];
        for (si, ps) in series.iter().enumerate().take(8) {
            if let (Some(va), Some(vb)) = (value_at(ps.series, (a * 1e9) as u64), value_at(ps.series, (b * 1e9) as u64)) {
                let dv = vb - va;
                let rate = if dt > 1e-9 { dv / dt } else { 0.0 };
                let name: String = ps.series.key.split('·').next_back().unwrap_or(&ps.series.key).chars().take(22).collect();
                let sign = if dv < 0.0 { "-" } else { "" };
                let rsign = if rate < 0.0 { "-" } else { "" };
                lines.push(format!("{name}  Δv={sign}{}  {rsign}{}/s", fmt_val(dv.abs()), fmt_val(rate.abs())));
            }
            let _ = si;
        }
        if lines.len() > 1 {
            let w = lines.iter().map(|l| l.chars().count()).max().unwrap_or(10) as f32 * 6.4 + 14.0;
            let h = lines.len() as f32 * 14.0 + 8.0;
            let bx = plot.left() + (plot.width() - w) / 2.0;
            painter.rect_filled(Rect::from_min_size(Pos2::new(bx, plot.top() + 4.0), Vec2::new(w, h)), 4.0, panel_col);
            painter.rect_stroke(Rect::from_min_size(Pos2::new(bx, plot.top() + 4.0), Vec2::new(w, h)), 4.0, Stroke::new(1.0_f32, cursor_col_a), egui::StrokeKind::Outside);
            let mut y = plot.top() + 11.0;
            for (k, l) in lines.iter().enumerate() {
                let col = if k == 0 { cursor_col_a } else { series.get(k - 1).map(|s| s.color).unwrap_or(txt_col) };
                painter.text(Pos2::new(bx + 7.0, y), Align2::LEFT_CENTER, l, FontId::monospace(10.0), col);
                y += 14.0;
            }
        }
    }

    // ---- 右键框选矩形(进行中) ----
    if let Some((a, b)) = state.box_drag {
        let r = Rect::from_min_max(a, b);
        painter.rect_filled(r, 0.0, Color32::from_rgba_unmultiplied(120, 170, 220, 40));
        painter.rect_stroke(r, 0.0, Stroke::new(1.0_f32, Color32::from_rgb(120, 170, 220)), egui::StrokeKind::Middle);
    }

    // ---- 手势提示 "?" ----
    let hint_r = Rect::from_min_size(Pos2::new(plot.right() - 20.0, plot.top() + 4.0), Vec2::new(16.0, 16.0));
    painter.rect_filled(hint_r, 3.0, panel_col);
    painter.text(hint_r.center(), Align2::CENTER_CENTER, "?", FontId::monospace(11.0), txt_col);

    // ---- 交互 ----
    let mut out = PlotOut { clicked_frame: None, hover_t: None };

    // 平移:仅左键拖拽
    if resp.dragged_by(egui::PointerButton::Primary) {
        let d = resp.drag_delta();
        let dt = d.x as f64 / plot.width() as f64 * (t1 - t0);
        state.t0 -= dt;
        state.t1 -= dt;
        ui.ctx().request_repaint();
    }
    // 框选:右键拖拽
    if resp.drag_started_by(egui::PointerButton::Secondary) {
        if let Some(p) = resp.interact_pointer_pos() {
            state.box_drag = Some((p, p));
        }
    }
    if state.box_drag.is_some() && resp.dragged_by(egui::PointerButton::Secondary) {
        if let Some(p) = resp.interact_pointer_pos() {
            if let Some((a, _)) = state.box_drag {
                state.box_drag = Some((a, p));
            }
        }
    }
    if resp.drag_stopped_by(egui::PointerButton::Secondary) {
        if let Some((a, b)) = state.box_drag.take() {
            let (xa, xb) = (a.x.min(b.x), a.x.max(b.x));
            if xb - xa < 4.0 {
                // 无位移的右键点击:清除游标
                state.cursor_a = None;
                state.cursor_b = None;
            } else {
                let (nt0, nt1) = (x_to_t(xa as f64), x_to_t(xb as f64));
                state.t0 = nt0.min(nt1);
                state.t1 = nt1.max(nt0);
            }
        }
    }
    let wheel = ui.input(|i| i.smooth_scroll_delta.y);
    if wheel != 0.0 && resp.hovered() && state.box_drag.is_none() {
        let f = if wheel > 0.0 { 0.85 } else { 1.18 };
        let center = resp.hover_pos().map(|p| x_to_t(p.x as f64)).unwrap_or((t0 + t1) / 2.0);
        state.t0 = center - (center - state.t0) * f;
        state.t1 = center + (state.t1 - center) * f;
        ui.ctx().request_repaint();
    }
    if resp.double_clicked() {
        state.t0 = 0.0;
        state.t1 = (t_max_ds * 1.1).max(1.0);
    }

    if let Some(p) = resp.interact_pointer_pos() {
        // "?" 悬停浮层
        if hint_r.contains(p) {
            let hint_lines = [
                "左键点击   选帧 / 设游标A",
                "Shift+点击 设游标B(与A测Δt/Δv)",
                "右键拖拽   框选放大",
                "右键点击   清除游标",
                "左键拖拽   平移    滚轮 缩放",
                "双击       复位视图",
                "Space 跟随  F 复位  +/− 缩放",
                "← / →      左右平移",
            ];
            let w = hint_lines.iter().map(|l| l.chars().count()).max().unwrap_or(20) as f32 * 7.0 + 16.0;
            let h = hint_lines.len() as f32 * 15.0 + 10.0;
            let px = (hint_r.right() - w).max(plot.left());
            painter.rect_filled(Rect::from_min_size(Pos2::new(px, hint_r.bottom() + 4.0), Vec2::new(w, h)), 4.0, panel_col);
            painter.rect_stroke(Rect::from_min_size(Pos2::new(px, hint_r.bottom() + 4.0), Vec2::new(w, h)), 4.0, Stroke::new(1.0_f32, Color32::from_rgb(80, 90, 105)), egui::StrokeKind::Outside);
            let mut y = hint_r.bottom() + 12.0;
            for l in hint_lines {
                painter.text(Pos2::new(px + 8.0, y), Align2::LEFT_CENTER, l, FontId::monospace(10.0), panel_txt_col);
                y += 15.0;
            }
        } else if plot.contains(p) && state.box_drag.is_none() {
            let ht = x_to_t(p.x as f64);
            out.hover_t = Some(ht);
            // hover 读数框
            let mut lines = vec![format!("t = {:.4}s", ht)];
            for (si, ps) in series.iter().enumerate() {
                if let Some(v) = value_at(ps.series, (ht * 1e9) as u64) {
                    lines.push(format!("{} = {}", ps.series.key, fmt_val(v)));
                }
                let _ = si;
            }
            let mut y = plot.top() + 6.0;
            for (k, l) in lines.iter().enumerate() {
                let col = if k == 0 { txt_col } else { series.get(k - 1).map(|s| s.color).unwrap_or(txt_col) };
                let galley_rect = Rect::from_min_size(Pos2::new(plot.left() + 8.0, y), Vec2::new(10.0, 13.0));
                painter.rect_filled(galley_rect.expand2(Vec2::new(4.0, 1.0)), 3.0, panel_col);
                painter.text(Pos2::new(plot.left() + 12.0, y + 6.5), Align2::LEFT_CENTER, l, FontId::monospace(10.0), col);
                y += 15.0;
            }
        }
    }

    // 点击 → 最近点选帧 + 游标(Shift=游标B)
    if resp.clicked_by(egui::PointerButton::Primary) {
        if let Some(p) = resp.interact_pointer_pos() {
            let ht = x_to_t(p.x as f64);
            let shift = ui.input(|i| i.modifiers.shift);
            if shift {
                state.cursor_b = Some(ht);
            } else {
                state.cursor_a = Some(ht);
            }
            let mut best: Option<(f64, u32)> = None;
            for ps in series {
                for &(t, _, fi) in &ps.series.pts {
                    let ts = t as f64 / 1e9;
                    if ts < t0 || ts > t1 {
                        continue;
                    }
                    let px = (t_to_x(ts) - p.x).abs() as f64;
                    if px < 8.0 && best.map(|(d, _)| px < d).unwrap_or(true) {
                        best = Some((px, fi));
                    }
                }
            }
            if !shift {
                out.clicked_frame = best.map(|(_, f)| f);
            }
        }
    }
    out
}

/// 二分查找 t 附近(±半采样周期)的值
fn value_at(s: &iotprobe_core::model::Series, t_ns: u64) -> Option<f64> {
    if s.pts.is_empty() {
        return None;
    }
    let idx = s.pts.partition_point(|p| p.0 < t_ns);
    for k in [idx.saturating_sub(1), idx.min(s.pts.len() - 1)] {
        let dt = (s.pts[k].0 as i64 - t_ns as i64).abs();
        if dt < 200_000_000 {
            // 200ms 内视为对齐
            return Some(s.pts[k].1);
        }
    }
    None
}
