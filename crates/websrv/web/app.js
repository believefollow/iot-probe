"use strict";
/* IoTProbe Web 实时台演示前端(零构建,vanilla JS;ADR-0012)。
   数据面:WS 信封 {"type":"frame"|"signal"|"event", seq, payload} — payload 符合冻结契约。 */

const $ = (id) => document.getElementById(id);
const LANES = [
  { key: "CAN 0x1A0·Speed", label: "Speed · kph", color: "#4fc3f7" },
  { key: "CAN 0x1A0·Torque", label: "Torque · Nm", color: "#ffb74d" },
  { key: "CAN 0x1A0·Temp", label: "Temp · °C", color: "#ef5350" },
];

function idName(id, ext) {
  if (ext) return id === 0x18FF0102 ? "FD_CALIB" : "EXT_" + id.toString(16).toUpperCase();
  return { 0x1a0: "MOTOR_STATUS", 0x100: "HEARTBEAT" }[id] || "0x" + id.toString(16).toUpperCase();
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function parseIdTok(tok) {
  tok = tok.trim().toLowerCase();
  if (!tok) return null;
  if (tok.startsWith("0x")) return parseInt(tok.slice(2), 16) || null;
  const n = parseInt(tok, 10);
  return isNaN(n) ? null : n;
}

const state = {
  paused: false, pausedFrames: 0,
  series: new Map(),   // key → {unit, pts:[{t,v}]}
  agg: new Map(),      // id → {count, lastT, periods[], ext}
  evByCode: new Map(), // code → {el, n, lastTs}
  rowRefs: [],         // {t, el}
  sigCount: 0,
};

/* ---------- WebSocket ---------- */
let ws = null;
function connect() {
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
  ws.onopen = () => { $("ws-state").textContent = "实时接收中"; $("ws-state").className = "badge on"; };
  ws.onclose = () => { $("ws-state").textContent = "已断开,2s 后重连…"; $("ws-state").className = "badge off"; setTimeout(connect, 2000); };
  ws.onerror = () => { try { ws.close(); } catch (_) {} };
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.type === "frame") onFrame(m.payload);
    else if (m.type === "signal") onSignal(m.payload);
    else if (m.type === "event") onEvent(m.payload);
  };
}

/* ---------- 报文表 ---------- */
function addRow(r) {
  const tb = $("fbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `<td>${r.t.toFixed(3)}</td><td class="dir">${r.dir.toUpperCase()}</td><td>${r.proto}</td>` +
    `<td class="id">0x${r.id.toString(16).toUpperCase()}${r.ext ? "x" : ""}</td><td>${r.name}</td>` +
    `<td>${r.dlc}</td><td class="hex">${r.hex}</td>`;
  tb.prepend(tr);
  state.rowRefs.unshift({ t: r.t, el: tr });
  while (tb.children.length > 400) {
    tb.lastChild.remove();
    state.rowRefs.pop();
  }
}

function onFrame(f) {
  // 聚合
  let a = state.agg.get(f.id);
  if (!a) { a = { count: 0, lastT: null, periods: [], ext: f.id_type === "ext" }; state.agg.set(f.id, a); }
  if (a.lastT != null) {
    const p = (f.ts_ns - a.lastT) / 1e6;
    if (p > 0 && p < 5000) { a.periods.push(p); if (a.periods.length > 30) a.periods.shift(); }
  }
  a.count++; a.lastT = f.ts_ns;

  if (state.paused) { state.pausedFrames++; $("paused-hint").textContent = `已暂停 · 积压 ${state.pausedFrames} 帧未显示`; return; }
  addRow({
    t: f.ts_ns / 1e9, dir: f.dir, proto: f.bus.type === "canfd" ? "CAN FD" : "CAN",
    id: f.id, ext: f.id_type === "ext", dlc: f.dlc,
    hex: f.data.map((b) => b.toString(16).padStart(2, "0")).join(" "),
    name: idName(f.id, f.id_type === "ext"),
  });
}

/* ---------- 信号 ---------- */
function onSignal(s) {
  let ser = state.series.get(s.name);
  if (!ser) { ser = { unit: s.unit || "", pts: [] }; state.series.set(s.name, ser); }
  ser.pts.push({ t: s.t_ns / 1e9, v: s.value });
  if (ser.pts.length > 24000) ser.pts.splice(0, 2000);
  state.sigCount++;
}

/* ---------- 事件(按 code 15s 窗口折叠 ×N) ---------- */
function trimEvents() {
  const list = $("events");
  while (list.children.length > 200) list.lastChild.remove();
}

function onEvent(ev) {
  const prev = state.evByCode.get(ev.code);
  if (prev && (ev.ts_ns - prev.lastTs) / 1e9 < 15) {
    prev.n++; prev.lastTs = ev.ts_ns;
    const nEl = prev.el.querySelector(".ev-n");
    if (nEl) nEl.textContent = "×" + prev.n;
    if (!state.paused) { $("events").prepend(prev.el); trimEvents(); }
    return;
  }
  const el = document.createElement("div");
  el.className = "ev " + ev.level;
  const sigs = (ev.evidence && ev.evidence.signals || [])
    .map((s) => `${escapeHtml(s.name)} = <b>${escapeHtml(String(s.value))}</b>${s.unit ? escapeHtml(s.unit) : ""}`)
    .join(" · ");
  el.innerHTML =
    `<div class="ev-head"><span class="ev-code">${escapeHtml(ev.code)}</span>` +
    `<span class="ev-n"></span><span class="ev-lv ${ev.level}">${ev.level}</span>` +
    `<span class="ev-t">${(ev.ts_ns / 1e9).toFixed(2)}s</span></div>` +
    `<div class="ev-msg">${escapeHtml(ev.message || "")}</div>` +
    (sigs ? `<div class="ev-evi">证据: ${sigs}</div>` : "");
  el.addEventListener("click", () => jumpToT(ev.ts_ns / 1e9));
  state.evByCode.set(ev.code, { el, n: 1, lastTs: ev.ts_ns });
  if (state.paused) return;
  $("events").prepend(el);
  trimEvents();
}

/* ---------- 三联动:按时间跳帧 ---------- */
function jumpToT(t) {
  let best = null, bestD = Infinity;
  for (const r of state.rowRefs) {
    const d = Math.abs(r.t - t);
    if (d < bestD) { bestD = d; best = r; }
  }
  if (!best) return;
  for (const r of state.rowRefs) r.el.classList.remove("flash");
  best.el.classList.add("flash");
  best.el.scrollIntoView({ block: "center" });
  setTimeout(() => best.el.classList.remove("flash"), 1600);
}

/* ---------- 曲线(3 通道,60s 窗口,像素 min/max 抽稀) ---------- */
function draw() {
  const cv = $("chart");
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight;
  if (!w || !h) return;
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
  }
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  let tMax = 0;
  for (const l of LANES) {
    const s = state.series.get(l.key);
    if (s && s.pts.length && s.pts[s.pts.length - 1].t > tMax) tMax = s.pts[s.pts.length - 1].t;
  }
  if (!tMax) return;
  const tMin = tMax - 60;
  const laneH = h / LANES.length;
  LANES.forEach((lane, li) => {
    const s = state.series.get(lane.key);
    if (!s) return;
    const pts = s.pts.filter((p) => p.t >= tMin);
    const y0 = li * laneH;
    ctx.fillStyle = "rgba(255,255,255,0.03)";
    ctx.fillRect(0, y0, w, laneH);
    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.lineWidth = 1;
    for (let g = 1; g < 4; g++) {
      const y = y0 + (laneH * g) / 4;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }
    if (pts.length < 2) return;
    let mn = Infinity, mx = -Infinity;
    for (const p of pts) { if (p.v < mn) mn = p.v; if (p.v > mx) mx = p.v; }
    if (mx - mn < 1e-9) mx = mn + 1;
    const pad = (mx - mn) * 0.18; mn -= pad; mx += pad;
    // 像素列 min/max
    const col = new Map();
    for (const p of pts) {
      const x = Math.floor(((p.t - tMin) / 60) * w);
      let c = col.get(x);
      if (!c) col.set(x, { mn: p.v, mx: p.v });
      else { if (p.v < c.mn) c.mn = p.v; if (p.v > c.mx) c.mx = p.v; }
    }
    ctx.strokeStyle = lane.color; ctx.lineWidth = 1.2;
    ctx.beginPath();
    let started = false;
    for (const [x, c] of [...col.entries()].sort((a, b) => a[0] - b[0])) {
      const y1 = y0 + laneH - ((c.mx - mn) / (mx - mn)) * (laneH - 10) - 5;
      const y2 = y0 + laneH - ((c.mn - mn) / (mx - mn)) * (laneH - 10) - 5;
      if (!started) { ctx.moveTo(x + 0.5, y2); started = true; } else { ctx.lineTo(x + 0.5, y2); }
      ctx.lineTo(x + 0.5, y1);
    }
    ctx.stroke();
    ctx.fillStyle = lane.color; ctx.font = "11px system-ui, sans-serif";
    ctx.fillText(lane.label, 8, y0 + 14);
    ctx.fillStyle = "rgba(255,255,255,0.45)";
    ctx.fillText(mx.toFixed(1), 90, y0 + 14);
    ctx.fillText(mn.toFixed(1), 90, y0 + laneH - 5);
  });
}

/* 曲线 hover/click(最近点 + 跳帧) */
function chartPick(ev) {
  const cv = $("chart");
  const rect = cv.getBoundingClientRect();
  const x = ev.clientX - rect.left, y = ev.clientY - rect.top;
  const ref = state.chartRef;
  if (!ref) return null;
  const li = Math.min(2, Math.max(0, Math.floor(y / (rect.height / 3))));
  const lane = LANES[li];
  const s = state.series.get(lane.key);
  if (!s) return null;
  const t = ref.tMin + (x / rect.width) * 60;
  let best = null, bestD = Infinity;
  for (const p of s.pts) {
    if (p.t < ref.tMin) continue;
    const d = Math.abs(p.t - t);
    if (d < bestD) { bestD = d; best = p; }
  }
  return best ? { lane, pt: best } : null;
}
function initChartEvents() {
  const cv = $("chart");
  const tip = $("tooltip");
  cv.addEventListener("mousemove", (ev) => {
    const hit = chartPick(ev);
    if (!hit) { tip.hidden = true; return; }
    tip.hidden = false;
    tip.style.left = Math.min(ev.offsetX + 12, cv.clientWidth - 150) + "px";
    tip.style.top = (ev.clientY - rectTop()) + "px";
    tip.innerHTML = `<b>${escapeHtml(hit.lane.label)}</b><br>t=${hit.pt.t.toFixed(3)}s · ${hit.pt.v.toFixed(2)}`;
  });
  cv.addEventListener("mouseleave", () => { tip.hidden = true; });
  cv.addEventListener("click", (ev) => {
    const hit = chartPick(ev);
    if (hit) jumpToT(hit.pt.t);
  });
}
let rectTop = () => 0;

/* ---------- 聚合表 ---------- */
function renderAgg() {
  const rows = [];
  for (const [id, a] of state.agg) {
    if (!a.periods.length) continue;
    const mean = a.periods.reduce((x, y) => x + y, 0) / a.periods.length;
    const sd = Math.sqrt(a.periods.reduce((x, y) => x + (y - mean) ** 2, 0) / a.periods.length);
    rows.push({ id, ext: a.ext, name: idName(id, a.ext), count: a.count, mean, jitter: mean ? (sd / mean) * 100 : 0 });
  }
  rows.sort((a, b) => b.count - a.count);
  $("aggbody").innerHTML = rows.slice(0, 8).map((r) =>
    `<tr class="${r.jitter > 25 ? "jit" : ""}"><td>0x${r.id.toString(16).toUpperCase()}${r.ext ? "x" : ""}</td>` +
    `<td>${r.name}</td><td>${r.count.toLocaleString()}</td><td>${r.mean.toFixed(1)} ms</td><td>${r.jitter.toFixed(1)}%</td></tr>`
  ).join("");
}

/* ---------- 控件 ---------- */
function initControls() {
  $("btn-fault").addEventListener("click", async () => {
    const r = await fetch("/api/inject", { method: "POST", body: JSON.stringify({ kind: "temp_fault" }) }).then((x) => x.json());
    $("btn-fault").textContent = r.temp_fault ? "停止温度故障" : "注入温度故障";
    $("btn-fault").classList.toggle("active", !!r.temp_fault);
  });
  $("btn-stall").addEventListener("click", () => {
    fetch("/api/inject", { method: "POST", body: JSON.stringify({ kind: "hb_stall" }) });
    $("btn-stall").textContent = "心跳已停发 3s";
    setTimeout(() => { $("btn-stall").textContent = "心跳停发 3s"; }, 3200);
  });
  $("btn-pause").addEventListener("click", () => {
    state.paused = !state.paused;
    $("btn-pause").textContent = state.paused ? "▶ 恢复滚动" : "⏸ 暂停滚动";
    if (!state.paused) { state.pausedFrames = 0; $("paused-hint").textContent = ""; }
  });
  $("f-apply").addEventListener("click", () => {
    if (!ws || ws.readyState !== 1) return;
    const raw = $("f-ids").value.trim();
    const ids = raw ? raw.split(/[,;\s]+/).map(parseIdTok).filter((x) => x !== null) : [];
    const dir = $("f-dir").value;
    ws.send(JSON.stringify({ type: "set_filter", ids, dir }));
    const parts = [];
    if (raw) parts.push("ID " + raw);
    if (dir) parts.push(dir.toUpperCase());
    $("f-active").textContent = parts.length ? "已生效: " + parts.join(" · ") + "(服务端)" : "";
  });
  $("f-clear").addEventListener("click", () => {
    $("f-ids").value = ""; $("f-dir").value = ""; $("f-active").textContent = "";
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "set_filter", ids: [], dir: "" }));
  });
}

/* ---------- 周期渲染 ---------- */
function initLoops() {
  setInterval(draw, 200);
  setInterval(renderAgg, 1000);
  setInterval(async () => {
    try {
      const st = await fetch("/api/stats").then((x) => x.json());
      $("st-frames").textContent = st.frames.toLocaleString();
      $("st-sig").textContent = st.signal_pts.toLocaleString();
      $("st-ev").textContent = st.events.toLocaleString();
    } catch (_) {}
  }, 1000);
  window.addEventListener("resize", draw);
  rectTop = () => $("chart").getBoundingClientRect().top;
}

initControls();
initChartEvents();
initLoops();
connect();
draw();
