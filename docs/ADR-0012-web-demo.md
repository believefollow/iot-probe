# ADR-0012 Web 实时台·可演示版本（无构建前端 + 内嵌模拟源）

状态：已采纳（2026-11-15，执行：AI 代理，决策人：项目所有者默认）　关联：ADR-0008 / 主 spec 4.5 / 任务卡 T-1.9、T-1.10、T-1.11

## 背景

PH-2 功能面已收齐（G2 离线预演全通），但对外演示只有 egui 桌面台与 CLI。
ADR-0008 规划的 **Web 实时台**（T-1.9 报文滚动表 / T-1.10 Canvas 曲线 / T-1.11 服务端过滤器）尚未新建。
需要一个"打开浏览器就能看"的可演示版本，用于客户演示、G2 预演与 AI 验收。

## 决策

1. 新建 `crates/websrv`（bin `iotprobe-web`）：std 线程 + 手写最小 HTTP/RFC6455 WebSocket，
   **不引入任何新第三方依赖**（tokio/rmcp 只属于 aimcp；core 保持 std-only 不动）。
2. 数据面完全复用既有管线：模拟 CAN 源（移植 app/sim.rs 同构实现）→ NDJSON 契约流 →
   core `ingest::live::Pipeline` → 周期性 `dissect::analyze`（DBC+规则包）→ 信号/事件增量。
   帧广播直接按 `frame.schema.json` 出，事件按 `event.schema.json` 出，信封
   `{"type","seq","payload"}`（主 spec 10.3）；`contracts/` 只读不动。
3. 前端为 **零构建静态页**（vanilla JS + Canvas，`include_str!` 内嵌）：
   报文滚动表、ID 聚合条、三通道信号曲线（像素 min/max 抽稀）、事件列表、三联动、
   服务端过滤器（T-1.11）、故障注入按钮（温度故障/心跳停发）。
   生产框架（Svelte/React）选择推迟到 G2 之后，届时若引入构建链另立 ADR。
4. 模拟源内嵌 **demo-bms 规则包**（Temp 阈值 warn/fault + rate 骤降），时基如实标注
   `sw/L0`（ADR-5 诚实原则，UI 徽章展示）。
5. 会话策略：记录全量累积（保证 `for` 持续时长与速率窗口语义稳定），默认软上限
   15 万条记录（约 20 分钟演示），超限停止采集并在 UI 提示重启会话。

## 后果

- 演示即产品叙事：浏览器打开 → 报文流动 → 注入故障 → 规则事件带证据链 → 三联动跳帧 → 服务端过滤。
- 不改变 egui 台与 CLI 的任何行为；`crates/core`、`contracts/` 零改动。
- 已知限制：客户端加入后曲线只向前填充（不做历史回放）；多客户端各自独立过滤器。
