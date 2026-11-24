# ADR-0007 离线工具的 Frame/Event 契约映射与偏差

状态:已采纳(2026-11-10) 关联:contracts/frame.schema.json、contracts/event.schema.json

## 背景

`contracts/` 下的 Frame/Event schema 按 spec 第 4/10 章冻结,面向**网关实时采集**形态
(bus.type 四值、data ≤64B、dir 仅 rx/tx)。iotprobe 离线分析台处理的是文件日志与抓包,
存在三类无法直接落入冻结枚举的数据。按 spec 第 10.5 条,任何接口偏差必须走 ADR,本文
即该偏差记录。

## 决策

1. **bus.type 映射(不改枚举)**:非 CAN/EtherCAT 的字节流一律映射 `uart`,
   真实传输载体写入扩展键 `meta.transport`(tcp/udp/serial-log)。
   schema 的 `meta.additionalProperties: true` 允许此扩展,且传输载体属采集元数据,
   不违反"meta 不得承载业务语义"约束。
2. **dir unknown(不改枚举)**:candump/ASC 等无方向标记的帧映射 `rx`,
   并写 `meta.assumed_dir: true` 如实标注"方向为假定值"。
3. **data.maxItems 64 → 512(唯一 schema 数值变更)**:UART 字节流帧
   (Modbus RTU 最长 256B、自定义协议常见 >64B)超出 64B 上限。
   CAN/CAN FD 帧不受影响。冻结 schema 本体不改动;校验时以"冻结 schema +
   本 ADR 补丁"执行(见 tests/schema_conformance.rs 中的 patch 函数)。
4. **诊断事件的契约桥接**:iotprobe 的解析层诊断事件(CRC 错/超时/间隔等)
   不是 spec 定义的"厂商语义事件"(后者必须由 rules-pack 产出,见 ADR-0006 计划)。
   导出时以 `rule_ref.pack = "builtin-diag"` 标注,`code` 采用 `DIAG_*` 前缀,
   明确与规则引擎事件区分。rules 引擎落地后(T-2.1),语义事件走正规路径,
   诊断事件保留 builtin 归属。

## 后果

- 离线工具可输出严格通过 schema 校验的 JSONL(帧/事件),可充当 golden 采集器,
  支撑 T-0.2 基线采集与 FR-7.2 证据链导出。
- 实时采集落地时(crates/ingest),ts_src 将来自真实适配器能力(hw/mcu);
  离线文件按来源标注(sw=抓包/内核时间戳,wall=日志墙钟)。
- spec 4.2 提到的 signal.schema.json 在 contracts/ 中缺失(T-0.3 冻结评审项),
  信号导出暂维持 CSV,待 schema 补齐后增加 JSONL 信号导出。
