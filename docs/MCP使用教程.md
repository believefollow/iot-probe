# MCP 使用教程(定稿,2026-11-20 实测确认)

> 本文所有命令与响应摘录均来自当次实测;代码改动后请重跑「自测」一节核对。
> IoTProbe 有**两个 MCP server**,按数据形态选;AI 客户端日常接入用 **ai-gate**(推荐入口)。

## 0. 两个 server 怎么选

| | **ai-gate**(推荐) | **离线 JSONL server** |
|---|---|---|
| 可执行文件 | `target/release/iotprobe-mcp.exe` | `target/release/mcp_server.exe` |
| 实现 | `crates/aimcp`(rmcp 官方 Rust SDK,stdio) | `crates/core/src/bin/mcp_server.rs`(手写 JSON-RPC) |
| 数据源 | ① serbox 设备表(ai-gate.json) ② 直连 `host:3333` 帧流 ③ **录制 .ndjson / 契约 JSONL 文件** | `dbg_analyze --export` 产出的契约 JSONL **目录** |
| 工具 | `list_devices` / `read_frames` / `query_events` / `export_context`(全只读) | `list_sessions` / `query_events` / `query_frames` / `get_signal_series` / `export_session` |
| 附加 | prompt `serbox-expert`(内置总线专家打法) + `ai-setup` 注册片段生成 | — |
| 适用 | 现场排故:AI 直连总线/回放,顺序 query_events → read_frames → 假设 → 验证 | 离线日志已导出成 JSONL,按会话批量查询/取曲线 |

两 server 都是**只读**(第一版权限模型;写类工具待 serbox 控制面就绪后解锁)。

## 1. 30 秒接入(打印即粘贴)

```bash
iotprobe-mcp ai-setup zcode     # 或 trae | cursor | claude;ai-setup list 看清单
```

stdout 输出该客户端的配置 JSON 片段(command 用 exe 绝对路径,不依赖 PATH),说明走 stderr。实测输出:

```json
{
  "mcpServers": {
    "iot-probe": {
      "command": "D:\\dev\\tools\\iot-probe\\target\\release\\iotprobe-mcp.exe",
      "args": [],
      "env": {}
    }
  }
}
```

粘贴位置(stderr 会同步提示):ZCode `~/.zcode/cli/mcp.json` 或工作区 `.zcode/mcp.json`;Cursor `~/.cursor/mcp.json`;Claude 项目根 `.mcp.json`;Trae 的 MCP 手动添加框。粘贴后重启客户端,确认 `iot-probe` 已连接。

> 提示词包已编译进二进制:客户端里调用 **prompt `serbox-expert`** 即注入总线专家打法;原文在 `crates/aimcp/prompts/serbox-expert.md`。

## 2. 数据从哪来(ai-gate 三种寻址,`file > tcp > device` 优先级)

1. **回放文件(零硬件,推荐先走通)**:录制 `.ndjson` / 契约 JSONL 都行
   - 契约 JSONL 现场生成:GUI「导出CSV」或 CLI `dbg_analyze`:
     ```bash
     target/release/dbg_analyze.exe samples/modbus_rtu.log --map samples/configs/modbus_map.json \
       --rules samples/rules-pack/generic-bms --export D:/data/sessions
     # 产出 D:/data/sessions/modbus_rtu.{frames,events,signals}.jsonl
     ```
2. **serbox 设备表**:iot-probe 同目录放 `ai-gate.json`:
   ```json
   { "devices": [ { "name": "serbox-1", "tcp": "192.168.1.50:3333" } ] }
   ```
3. **直连**:`tcp = "192.168.1.50:3333"`(serbox NDJSON 帧流固定 3333)。

## 3. 工具详解(参数与语义)

| 工具 | 关键参数 | 说明(实测口径) |
|---|---|---|
| `list_devices` | — | 列 ai-gate.json 设备表;无配置时返回带 `hint` 的空表(不报错) |
| `read_frames` | `file`/`tcp`/`device` 三选一;`max_frames`(默认 200,上限 100000);`seconds`(TCP 默认 10s,空闲 3s 提前收口;文件源忽略) | 收集帧 → 结构化列表(frame_no/t_rel/t_wall/channel/dir/proto/hex);**收集结果整体替换当前会话** |
| `query_events` | 同上数据源;`kind` 子串过滤(如 Timeout/校验/丢帧/协议异常码);`max_events`(默认 200) | 跑完整分析管线(协议识别/CRC/请求-响应配对/丢帧/间隔);`events[].frame` = 证据帧号 = read_frames 的 `frames[]` 下标,可直接引用回跳;`by_kind` 给分型统计 |
| `export_context` | `path`(缺省 `ai-gate-export/context-<时间戳>.json`) | 当前会话导出单文件上下文包(schema/generated_at/source/meta/frames/events);≤10MB,超限自动抽稀帧 |

**会话语义**:`read_frames` 换源会整体替换会话;`query_events`/`export_context` 缺省分析当前会话——先 read_frames 再追问,不用每轮重传数据源参数。

## 4. 实测记录(2026-11-20,命令与真实输出)

```text
read_frames  file=modbus_rtu.frames.jsonl (dbg_analyze 导出)
→ collected 1169 | parsed_ok 1169 | bad_lines 0 | channels 1(UART1)

query_events {}   (分析当前会话)
→ total_matched 3 | by_kind {"协议异常码":1, "请求无响应":1, "间隔异常":1}
→ 首事件 {kind:"请求无响应", level:"fault", frame_no:401}

export_context path=ctx-modbus.json
→ 1169 帧 + 3 事件, 473KB 单文件 JSON
```

另用 5 行小样本(含 1 行故意坏行)验证容错:`bad_lines=1` 计数、其余 4 帧照常解析——**坏行不中断**。

## 5. 典型对话(把这段直接发给 AI)

> 「用 iot-probe 读回放文件 D:/data/sessions/modbus_rtu.frames.jsonl,列出全部事件;
> 重点看 fault 级别,引用证据帧号;把上下文导出成 JSON 给我」

AI 会依次调 `read_frames(file=…)` → `query_events({})` → `export_context({path:…})`,
回答里每个结论都带 `frame_no`(可回 GUI 跳帧核对——帧号与 GUI 帧表序号同源)。

## 6. 离线 JSONL server(mcp_server.exe)

```json
{ "mcpServers": { "iotprobe": {
    "command": "D:/dev/tools/iot-probe/target/release/mcp_server.exe",
    "args": ["D:/data/sessions"]
} } }
```

- 数据源 = `--export` 目录(`<会话名>.{frames,events,signals}.jsonl`);`args[0]` 或环境变量 `IOTPROBE_SESSIONS` 指根目录
- 五工具:`list_sessions` / `query_events`(可按 level/kind 过滤) / `query_frames`(按时间窗) / `get_signal_series`(按信号名取曲线点,可直接画图) / `export_session`(按事件导出证据包,`event_id` 用事件 JSONL 里的完整 id,如 `modbus_rtu.log:1`)
- 实测:`query_events(level=fault)` 返回 `TEMP_OVER_LIMIT`(带 evidence.frames_ref + rule_ref);
  `get_signal_series(name_contains=TempSensor)` 返回 °C 曲线点
- 定位差异:它**没有会话概念**(每工具独立查询),适合"导出完毕后批量问答";现场直播式排故用 ai-gate

## 7. 自测(改代码后重跑这几条)

```bash
# 1) 注册片段可生成
target/release/iotprobe-mcp.exe ai-setup zcode
# 2) stdio 全链路(initialize → tools/list → read_frames → query_events → export_context)
#    见本文 §4,或直接把本文 fixture 流程再跑一遍
# 3) 契约 JSONL 数据源(先导出再喂):
target/release/dbg_analyze.exe samples/modbus_rtu.log --map samples/configs/modbus_map.json \
  --rules samples/rules-pack/generic-bms --export D:/tmp/mcp-test
# 4) 离线 server 五工具
echo {"jsonrpc":"2.0","id":1,"method":"tools/list"} | target/release/mcp_server.exe D:/tmp/mcp-test
```

## 8. 常见坑

| 现象 | 原因与处理 |
|---|---|
| `read_frames(device=…)` 报"未找到 ai-gate.json" | 设备名寻址依赖 ai-gate.json(exe 同目录/cwd);或改用 `tcp` 直连 |
| 契约 JSONL 喂进去 `parsed_ok=0` | 喂的是 events/signals JSONL——`read_frames`/`query_events` 只吃 **frames** 帧流(.ndjson / frames.jsonl) |
| 事件里 `kind` 跟 G2 说的对不上 | kind 是中文标签(协议异常码/请求无响应/间隔异常/校验错误…),`kind` 参数子串匹配即可 |
| 证据包 >10MB | export_context 自动抽稀帧(事件不抽),`frames_sampled=true` 即发生了抽稀 |
| 客户端里看不到 prompt | serbox-expert 是 **prompt 能力**,部分客户端 UI 不展示 prompts——可用 `prompts/list` 确认,或直接读 md 原文 |
