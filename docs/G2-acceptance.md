# G2 三场景手跑清单(PH-2 出货验收)

> 对齐 ADR-0011 附录表,展开为可直接照做的步骤。每个场景分
> **离线预演**(本机零硬件,已验证 ✅)与 **现场实跑**(需硬件)两段;
> 预演通过即可确认软件链路,实跑只多出"换数据源"这一步。
> 勾选框供手跑时逐项打勾;发现步骤与实际 UI 不符请改本文件。

约定:二进制在 `target/release/`(未 build 时先 `cargo build --release`);
测试语料在 `D:\dev\tools\test-corpus\`,示例数据在 `samples/`。

---

## S1 现场排故(储能站:CAN BMS + 485 电表)

**目标**:两路实时源同屏 → 聚合视图看周期 → 规则包抓异常 → 录制 → 证据包。

### 硬件/环境清单(现场)

- [ ] ZLG USBCANFD-200U + 驱动(`zlgcan.dll` 在程序目录或 PATH)
- [ ] 串口服务器(有人/周立功)把 485 电表透传成 TCP,拿到 `IP:端口`
- [ ] BMS CAN 终端电阻/分线盒就位

### 现场实跑步骤

1. [ ] 启动 `iotprobe.exe` → 顶栏切「配置中心」→「实时接入与录制」卡
2. [ ] **源 1(BMS CAN)**:源类型选 `ZLG USBCANFD`;设备类型 `USBCANFD-200U`、通道数、
       波特率 kbps(经典段 500 / 数据段按车厂)、时戳单位;勾**只听(不干扰现场)**;
       通道别名填 `BMS-CAN`
3. [ ] **源 2(485 电表)**:再开一个 iotprobe 实例(多会话并行待 FR-1.4,当前一实例一源),
       源类型选 `Modbus RTU(TCP)`;服务器地址填串口服务器 `IP:8899`;
       RTU 静默间隙按默认(电表响应慢可调大到 100ms+);别名填 `485-METER`
4. [ ] **两源都勾「会话录制(原始 NDJSON 落盘)」** 并选好文件——先开录再等故障,证据从原始流出
5. [ ] 连接后看状态行「接收中:N 帧 · 坏行 x · 丢帧 y」;坏行持续增长说明波特率/间隙不对
6. [ ] 右侧「聚合」页:按 unit·方向看 485 电表的周期均值/P95/抖动σ%;
       按 ID 看 CAN 报文周期,抖动 >25% 高亮;挂 DBC 时与标称周期比对(偏差 >20% 标橙)
7. [ ] 「配置中心 → 规则引擎」→「+ 挂载规则包…」挂规则包目录;BMS 压差示例(见下方模板);
       「✔ 应用并重新加载」生效;改 YAML 后事件页「↻ 重跑规则」秒级热加载
8. [ ] 故障复现时:事件页看到规则事件 → 选中事件 → 「导出证据包(选中事件 ±10s)」
9. [ ] 验收口径:证据包 JSON 含事件 + 信号 + 原始帧字节 + 规则出处,≤10MB

### BMS 压差规则包模板(存为 `<目录>/rules.yaml`)

```yaml
pack: bms-celldiff
meta: { vendor: <厂商>, model: <机型>, version: "1.0" }
rules:
  - id: CELL_VOLT_DIFF
    level: warn
    on: signal
    signal: cell_volt_diff      # 换成实际 DBC/寄存器映射出的压差信号键
    when: "$ > 0.10"
    for: 2s
    message: "单体压差 {value} V 持续 2s"
  - id: CELL_VOLT_DIFF_HIGH
    level: fault
    on: signal
    signal: cell_volt_diff
    when: "$ > 0.20"
    message: "单体压差 {value} V 越限"
  # 压差信号不存在时用变化率兜底:单体最高电压骤降
  - id: CELL_VOLT_DROP
    level: warn
    on: rate
    signal: max_cell_voltage_v
    window: 5s
    rate: "rate < -0.05"
    message: "最高单体电压 5s 内骤降 {delta} V(rate={rate} V/s)"
```

### 离线预演(零硬件,✅ 2026-11 已验证)

- [ ] CLI 穿堂(规则→事件,需挂寄存器映射才有命名信号):

  ```bash
  target/release/dbg_analyze.exe samples/modbus_rtu.log --map samples/configs/modbus_map.json --rules samples/rules-pack/generic-bms
  # 期望:Rule 事件 TEMP_OVER_LIMIT/TEMP_HIGH/MOTOR_IDLE(带证据信号值)
  ```

- [ ] 变化率规则阈值边界:`cargo test -p iotprobe-core --test e2e rules_rate`(真实日志,阈值 8 触发 / 150 零误报)
- [ ] 无硬件 CAN 演示:源类型选 **模拟 CAN**(0x1A0 速度/扭矩/温度正弦 + 心跳 + CAN FD),
       挂 `samples/motor.dbc` → 聚合视图周期、规则包、证据包全链路同真实源
- [ ] 离线重放闭环:步骤 4 录下的 `.ndjson` 用「打开文件」直接回放(同一解析器),
       或源类型选「回放 .ndjson」重跑
- [ ] 无硬件 CAN 演示(备选):装 Kvaser 驱动后用 **Virtual CAN**(「CAN卡·Kvaser」,通道 0 起)跑同样链路

---

## S1-H CAN 硬件后端逐家 bench 清单(ADR-0014,2026-11-20 适配)

> 六家后端已接入同一管线;**均未经真机验证**——每家插真盒跑一遍本节即完成 bench,
> 通过后在 canlib/README.md 注册表把状态改为"已 bench"。
> 通用口径:只听默认开 → 收帧数增长 → 帧内容与厂商上位机一致 → 时戳单调(硬件源应为 hw/L1) →
> 解锁发送后对回环(对端 ACK)能收到自发自收帧 → 断开无残留(端口释放/无 panic)。

- [ ] **ZLG USBCANFD**(kind 4,ADR-0010):USBCANFD-200U 双通道;核对 ReceiveMsg 时戳单位
       (0.1ms/10µs/1µs 三档下拉与实测对齐);FD 帧走 ReceiveFDData
- [ ] **VCI 兼容卡·创芯老版**(kind 8):32 位 ControlCAN.dll 经 vci-bridge.exe 桥接;
       桥接状态行显示"就绪(桥接进程)";收发各验一次
- [ ] **VCI·创芯新 SDK x64**(kind 8 同入口):DLL 状态行应显示 cxcan x64 路径且"进程内加载"(免桥接);
       DeviceType 与老版是否一致需核对(不一致就改型号下拉/数字直传)
- [ ] **PEAK PCAN-Basic**(kind 11):USB1 起;经典 500k 收发;勾 FD 后 InitializeFD
       (数据段 2M@80% 缺省)与 PCAN-View 收到帧一致;LISTEN_ONLY 生效(对端不见我们的帧)
- [ ] **Kvaser CANlib**(kind 12):装驱动后通道号以 Kvaser Device Guide 为准;Virtual CAN 可先过软件链路;
       时戳粒度 10µs(SET_TIMER_SCALE)与实际帧间隔核对;SILENT 只听连 ACK 都不发(对端单节点应无 ACK)
- [ ] **GCAN ECanVci**(kind 13):DeviceType 按手册数字(例程 16);CHUSBDLL 同目录预载生效
       (不报依赖缺失);Receive 批量与 TimeStamp 口径核对(当前用软件时戳,确认后可升级 hw)
- [ ] **SLCAN**(kind 9):CANable 串口 115200,S 波特率索引;收发 + 只听(S 命令无只听,发侧靠白名单)

---

## S2 产线抽测(整机下线:发激励 → 看响应)

**目标**:对被测板发送固定激励,人眼/规则判断响应正确。
**状态 🟡**:单次/周期发送可用;**预设序列脚本(FR-4.9)未做**,当前按"周期发送当激励源"降级跑。

### 已可用流程(降级版)

1. [ ] 实时接入 ZLG 源(同 S1 步骤 2),接被测板 CAN
2. [ ] 顶栏「📤 发送」开「CAN 发送」窗口 →「🔒 解锁发送(FR-10.4 显式解锁)」
       ——默认锁定是刻意设计,解锁前确认现场安全;连接任一 CAN 硬件源(或回放/模拟)即有发送通道
3. [ ] 填白名单(允许发送的 id 区间,hex/十进制均可)→「应用」;
       入队/出队双重校验,越界发送会计入「白名单已拒绝」
4. [ ] 填 id + 数据字节,「周期 ms(0=单次)」填 1000 →「发送」→ 状态栏「已入队发送」
5. [ ] 看响应:帧详情过滤该 id;「规则任务」窗口(分析工具菜单)看请求-响应配对与 RTT(Modbus 通道);
       或挂规则包对响应信号判 PASS/FAIL 阈值
6. [ ] 抽测记录:导出证据包(全会话模式,不选事件)作为该板测试留档

### FR-4.9 待补(序列脚本)

- [ ] 预设序列 YAML:多步(发激励 → 等响应超时 → 判 PASS/FAIL → 下一依赖步)
- [ ] 批量执行 + 汇总报表(通过率/失败步)

---

## S3 数据喂 AI(MCP 排障助手)

**目标**:Claude/Cursor/ZCode 直连会话数据,自然语言查询 + 导出证据包回喂。
**入口文档**:[MCP使用教程.md](MCP使用教程.md)(双 server 定位/参数/实测记录,2026-11-20 定稿)。
**两条路径**:现场直播式排故走 **ai-gate**(`iotprobe-mcp.exe`,serbox/回放/契约 JSONL 直接喂);
离线批量查询走 **离线 JSONL server**(`mcp_server.exe + --export 目录`,下述步骤)。

### 准备会话数据(二选一)

- **GUI**:打开日志 → 「导出CSV」(同目录产出 `*_frames_schema.jsonl` / `*_events_schema.jsonl` / `*_signals_schema.jsonl`)
- **CLI**(✅ 已验证,推荐批量):

  ```bash
  target/release/dbg_analyze.exe samples/modbus_rtu.log --rules samples/rules-pack/generic-bms --export D:/data/sessions
  # 产出 D:/data/sessions/modbus_rtu.{frames,events,signals}.jsonl
  ```

### 注册 MCP(Claude Desktop / Cursor)

```json
{ "mcpServers": { "iotprobe": {
    "command": "D:/dev/tools/iot-probe/target/release/mcp_server.exe",
    "args": ["D:/data/sessions"]
} } }
```

> 或直接用 ai-gate(`iotprobe-mcp.exe`,无 args):`iotprobe-mcp ai-setup <client>` 打印即粘贴;
> 也可把契约 JSONL 直接作为 `read_frames(file=…)` 数据源喂给它(实测 1169 帧→3 事件)。

重启客户端后验证:

1. [ ] 「列出会话」→ `list_sessions` 返回会话名/帧数/事件数/时间范围
2. [ ] 「查 fault 事件」→ `query_events {level: fault}` 返回规则/诊断事件
3. [ ] 「TempSensor 曲线」→ `get_signal_series {name_contains: "TempSensor"}`
4. [ ] 「取 OVER_TEMP 前后的帧」→ `query_frames {t_from_s, t_to_s}`
5. [ ] 「导出证据包」→ `export_session {event_id}` 产出
       `<sessions_root>/<会话>_evidence.json`(含事件+信号+原始帧+规则出处,≤10MB)
       注意 `event_id` 用事件 JSONL 里的完整 id(如 `modbus_rtu.log:1`,带文件扩展名)
6. [ ] 验收口径:把证据包 JSON 直接发给 AI,能复述故障时间线(事件→信号→帧字节)

### 离线预演(✅ 2026-11 已验证,实测记录)

```bash
# 1. 导出契约 JSONL(带规则包,事件含 TEMP_OVER_LIMIT 等)
target/release/dbg_analyze.exe samples/modbus_rtu.log --map samples/configs/modbus_map.json \
    --rules samples/rules-pack/generic-bms --export D:/data/sessions
# 2. stdio 直发 JSON-RPC 驱动 mcp_server.exe 五工具
```

| 工具 | 实测(sessions=modbus_rtu) |
|---|---|
| `list_sessions` | frames 1169 / events 244 / t_range 0~59.9s |
| `query_events level=fault` | total 94(TEMP_OVER_LIMIT×91 + 诊断 3) |
| `get_signal_series TempSensor` | unit1·TempSensor °C 583 点 |
| `query_frames` | total 1169,首帧含原始 data 字节 |
| `export_session`(全会话) | 证据包 1 个,窗口摘要 0~59.9s,无截断 |
| `export_session`(focus `modbus_rtu.log:1` ±10s) | 42 事件 / 208 帧 / 727 信号点,摘要含 `fault: TEMP_OVER_LIMIT×17` |

---

## 附:预演记录(2026-11)

| 项 | 命令 | 结果 |
|---|---|---|
| S1 CLI 穿堂 | `dbg_analyze samples/modbus_rtu.log --map samples/configs/modbus_map.json --rules samples/rules-pack/generic-bms` | Rule 事件带证据信号(TempSensor 32.6°C 等) |
| S3 JSONL 导出 | 同上 + `--export D:/data/sessions` | frames/events/signals 三份 JSONL(246KB/96KB/381KB) |
| S3 MCP 查询 | stdio JSON-RPC 五工具逐一调用 | list/query/series/export 全通(实测见 S3 表) |
| S1 变化率边界 | `cargo test -p iotprobe-core --test e2e` | 81 项全绿(含 rate 阈值边界) |

> 预演顺带修复:证据包摘要对全会话导出(窗口哨兵 f64::MAX/2)会打印 1.8e308 的荒谬
> 数字 → 已收敛到数据实际末帧时间(export.rs `t_to_display`)。
