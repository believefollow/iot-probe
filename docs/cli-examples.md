# CLI 命令示例手册(全部命令实测通过,2026-11)

> 二进制在 `target/release/`(若没有,先 `cargo build --release`)。
> 本文所有命令在仓库根目录(`D:\dev\tools\iot-probe`)、Git Bash 下验证;
> PowerShell/CMD 下路径分隔符换成 `\` 即可。测试语料在 `D:\dev\tools\test-corpus\`。

---

## 0. 构建 & 准备示例数据

```bash
cargo build --release                      # 全量构建(iotprobe GUI / dbg_analyze / mcp_server)
cargo run -p iotprobe-core --bin gen_samples   # 生成 samples/ 示例数据(仓库已带,可跳过)
cargo run --release -p iotprobe            # 启动 GUI(存在 samples/ 时启动即演示)
```

## 1. dbg_analyze:无 GUI 快速解析

基本形态:文件可传多个(同数据集聚合),参数可任意组合。

```bash
./target/release/dbg_analyze.exe <文件.log|pcap|asc|ndjson> [其它文件...]
    [--map map.json] [--dbc x.dbc] [--map104 points.yaml] [--custom spec.json]
    [--rules 规则包目录] [--probe] [--export 输出目录]
```

输出:数据集统计(records/frames/signals/events)→ 通道协议识别 → 信号列表 → 事件(前 20)→ 帧样例(前 8)→ 警告。

### 1.1 Modbus RTU + 寄存器映射

```bash
./target/release/dbg_analyze.exe samples/modbus_rtu.log --map samples/configs/modbus_map.json
```

实测:1169 帧,信号出现 `unit1·TempSensor [°C]`、`unit1·Energy [kWh]`(CDAB 32bit)等命名信号。
不挂 `--map` 时信号是原始寄存器名 `unit1·HR0..HR4`。

### 1.2 电表日志(真实设备)

```bash
./target/release/dbg_analyze.exe ../test-corpus/06-modbus/sdm120_rtu.log --map ../test-corpus/06-modbus/sdm120_modbus_map.json
```

实测:`unit1·ActivePower [W] 1035.6`、`unit1·Frequency [Hz] 50.04` 等 8 信号。

### 1.3 CAN 日志 + DBC

```bash
./target/release/dbg_analyze.exe ../test-corpus/05-can-logs/pycan_logfile.asc --dbc samples/motor.dbc
```

ASC/CANoe、candump、SocketCAN pcap 同理;DBC 给 Intel/Motorola 字节序、复用帧、VAL_ 枚举名。

### 1.4 IEC 104 + 点表

```bash
./target/release/dbg_analyze.exe ../test-corpus/07-iec104/iec104_wireshark.pcap --map104 samples/configs/points104_example.yaml
```

点表格式(`samples/configs/points104_example.yaml` 是最小样例):

```yaml
points:
  - {ty: 13, ioa: 256, name: 直流电压, factor: 0.1, unit: V, plot: true}
```

- 命中 `(类型,IOA,CA)` 后信号键改为 `104 <工程名>·IOA<n>` 并按 `factor·offset` 换算
- `ty: 0` 或省略 = 类型通配
- **注意**:抓包自动盘点生成的 YAML(`points_104_*.yaml`,只有 type_id/ioa/hits)
  没有 name/factor,直接喂 `--map104` 会解析失败 —— 先在 GUI 配置中心 → 协议解析里
  「编辑…」开点表编辑器补语义名再保存,或照上面最小样例手写

### 1.5 自定义协议 JSON DSL

```bash
./target/release/dbg_analyze.exe samples/custom_485.log --custom samples/configs/custom_example.json
```

实测:298 帧识别为 `Custom`,信号 `ACME-485·temp [°C]` 等;无法定界的行计入 Malformed 事件,不中断。

### 1.6 未知协议试探(逆向草案)

```bash
./target/release/dbg_analyze.exe samples/custom_485.log --probe
# 换成任何 RAW 日志:./target/release/dbg_analyze.exe 你的日志.log --probe
```

输出同步头/长度域/校验算法/置信度/字段区域猜测 + CustomSpec 草案(JSON 可直接存成 spec 文件)。
试探是统计启发式:CRC 命中是最强证据,置信度低时勿盲信。

### 1.7 挂规则包(语义事件)

```bash
./target/release/dbg_analyze.exe samples/modbus_rtu.log --map samples/configs/modbus_map.json --rules samples/rules-pack/generic-bms
```

实测事件:`Rule 温度越限 32.600 °C(阈值 32.0)` 等。规则包目录结构 `<目录>/rules.yaml`,
四种触发 `on: signal / timeout / frame / rate` 详见 `samples/rules-pack/` 与 README 规则引擎一节。

### 1.8 导出契约 JSONL(MCP 数据源)

```bash
./target/release/dbg_analyze.exe samples/modbus_rtu.log \
    --map samples/configs/modbus_map.json \
    --rules samples/rules-pack/generic-bms \
    --export D:/data/sessions
```

产出 `D:/data/sessions/modbus_rtu.{frames,events,signals}.jsonl`
(实测 246KB/96KB/381KB;数据集名取文件 stem,MCP 里就是会话名 `modbus_rtu`)。

## 2. mcp_server:AI 直连查询

### 2.1 注册到 Claude Desktop / Cursor

```json
{ "mcpServers": { "iotprobe": {
    "command": "D:/dev/tools/iot-probe/target/release/mcp_server.exe",
    "args": ["D:/data/sessions"]
} } }
```

重启客户端后直接对 AI 说:
「列出会话;查 modbus_rtu 的 fault 事件;TempSensor 曲线;导出证据包」。
工具:`list_sessions / query_events / query_frames / get_signal_series / export_session`。

### 2.2 不装客户端,stdio 手动测(JSON-RPC 直发)

```bash
cd /d/data/sessions && {
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_sessions","arguments":{}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_events","arguments":{"session":"modbus_rtu","level":"fault","limit":5}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_signal_series","arguments":{"session":"modbus_rtu","name_contains":"TempSensor"}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"query_frames","arguments":{"session":"modbus_rtu","limit":3}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"export_session","arguments":{"session":"modbus_rtu","event_id":"modbus_rtu.log:1"}}}'
} | /d/dev/tools/iot-probe/target/release/mcp_server.exe .
```

要点(实测踩过的坑):

- `session` = JSONL 文件 stem(如 `modbus_rtu`,不带扩展名)
- `export_session` 的 `event_id` 用事件 JSONL 里的完整 `id` 字段:
  格式是 **`<文件名含扩展名>:<序号>`**,如 `modbus_rtu.log:1`(写错会返回"事件不存在")
- 省略 `t_to_s` = 全会话;给 `event_id` = 该事件 ±10s 窗口
- 证据包落在 `<sessions_root>/<会话>_evidence.json`,单文件 ≤10MB,可直接回喂 AI

## 3. 协议识别回测矩阵

```bash
# 在 test-corpus-tools 目录跑(脚本按 ../test-corpus 相对找语料,也可显式传目录)
cd /d/dev/tools/test-corpus-tools
python -I run_matrix.py /d/dev/tools/iot-probe/target/release/dbg_analyze.exe
python -I run_matrix.py /d/dev/tools/iot-probe/target/release/dbg_analyze.exe ../test-corpus
```

逐条跑 `dbg_analyze` 断言识别结果(期望协议/最小信号数登记在脚本 `EXPECT` 表),
输出 PASS/FAIL 矩阵 + `matrix_result.json`(供 CI diff)。当前基线 **10/10 PASS**。

104 抓包盘点(生成点表草案的辅助脚本):

```bash
python -I dbg_scan104.py <104 抓包.pcap>     # 输出每 TCP 流的 APDU 定界/类型分布
```

## 4. 测试

```bash
cargo test --workspace                                  # 全量(101 项)
cargo test -p iotprobe-core --test e2e                  # 20 项端到端
cargo test -p iotprobe-core --test e2e rules_rate       # 只跑变化率规则阈值边界
cargo test -p iotprobe-mcp                              # MCP 协议纯函数测试
```

## 5. 常见问题

| 现象 | 原因/处理 |
|---|---|
| `没有可解析的文件` | 文件路径不存在或格式不认识;不带参数运行也报这个 |
| `--map104` 报"YAML/JSON 均不识别" | 盘点表缺 name 字段;用点表编辑器补全或手写最小样例(见 1.4) |
| 规则事件 0 条 | 信号没命名(规则匹配 `unit1·TempSensor` 这类键):确认挂了 `--map`/`--dbc`/`--map104` |
| Modbus RTU 时间轴不可用 | 日志无时间戳;换带时间戳的记录(SSCOM 风格或 serbox NDJSON) |
| MCP `事件不存在: modbus_rtu:1` | event_id 少了文件扩展名,应为 `modbus_rtu.log:1`(见 2.2) |
