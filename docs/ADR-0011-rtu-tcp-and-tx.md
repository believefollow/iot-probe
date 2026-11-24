# ADR-0011 live Modbus 485(RTU-over-TCP)与发送面板

状态:已采纳(2026-11-10,Q4 顺序:CAN FD P0 → 485 P1) 关联:ADR-0010 / FR-4.7 / FR-10.4 / FR-10.5

## 决策

1. **RTU-over-TCP 适配器**(`rtu_tcp.rs`):串口服务器(有人/周立功)把 485 透传成 TCP
   裸字节。定帧 = 字节到达静默间隙(默认 30ms,5-200 可调)+ CRC16 扫描双重启发;
   与 dissect::modbus::scan 同一套 CRC 规则。帧以 uart/L0 契约入管线
   (ts_src=sw 如实标注;监听无方向 → ADR-0007 assumed_dir)。
   无法定界的尾字节保留 500ms 后丢弃并计数(不产噪声帧)。
2. **发送面板**(仅 ZLG 硬件源):`TxHub` 队列(UI ↔ live 线程),
   poll 前排空 → ZCAN_Transmit。
   - FR-10.4:`enabled` 原子门控,UI 显式「解锁发送」;断开连接自动回收 hub(重锁)。
   - FR-10.5:白名单文本(单 id/区间,hex/十进制混排),入队 + 出队双重校验,
     越界拒绝并计数展示。
   - 单次/周期(0=单次);BRS 仅 FD 生效。
3. TX 布局:TransmitData 24B / TransmitFdData 80B / TransmitMsg 88B(static assert);
   BRS 位与发送回执语义属 T-1.3 bench 核对项。
4. 录制:TX 帧暂不入 NDJSON 录制(记录仪只截获接收行)——需要 TX 审计时在
   TxHub 落盘,列为后续任务。

## 后果

- 485 live 与 CAN live 同管线:485 现场数据同样获得规则引擎/聚合视图/证据包能力。
- ZLG 转发场景:用 ZLG 收 CAN、用串口服务器收 485,两个实时会话各开一个实例即可
  (多会话并行留待 FR-1.4 验收阶段)。

## 附:G2 三场景验收清单(准备事项)

> 步骤级手跑清单已展开到 **`docs/G2-acceptance.md`**(含离线预演记录,2026-11)。

| 场景 | 就绪状态 | 手跑步骤 |
|---|---|---|
| S1 现场排故 | ✅ 流程就绪 | ZLG 源接 BMS-CAN + RTU-TCP 源接 485 电表 → 聚合视图看周期 → 规则包挂 BMS 压差 → 触发即录 → 导出证据包 |
| S2 产线抽测 | 🟡 需序列脚本 | 发送面板单次/周期已可用;预设序列(发激励→采响应→PASS/FAIL)待 FR-4.9 |
| S3 数据喂 AI | ✅ MCP 就绪 | Claude/Cursor 挂 mcp_server.exe → 自然语言查询 → export_session 证据包 |
