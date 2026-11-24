# ADR-0009 规则包引入 serde_yaml_ng(唯一 YAML 依赖)

状态:已采纳(2026-11-10) 关联:主 spec ADR-6 / T-2.1 / FR-3.5

## 背景

ADR-6 规定"规则外部化,代码不认识任何厂商",spec 4.4 规定规则包为 YAML。
core 此前零第三方依赖;YAML 解析是规则外部化的必要前提。

## 决策

- core 引入 `serde_yaml_ng`(serde_yaml 的维护 fork,轻量、纯 Rust),
  **仅用于解析 rules-pack**;core 其余模块保持零依赖不变(jsonschema 仍为 dev-dep)。
- 表达式求值器**自研**(约 150 行递归下降),不引入表达式引擎:
  支持 阈值比较、四则、位运算、&&/||/!、括号、`$`(当前值)/`prev`(上一值)、
  `for <n>s|ms` 持续时长。明确**不做**函数定义、循环、字符串运算(T-2.1 禁区)。
- 首版触发类型:`on_signal`(阈值/状态/持续)、`on_timeout`(通道静默)、
  `on_frame`(帧匹配);变化率(rate)留待下一版(需滑动窗口状态)。
- 热加载(FR-3.7)首版不做:离线分析在加载时解析规则包,改 YAML 重新加载即可。
- 事件产出:`EventKind::Rule` + `code`(来自规则 id)+ `rule_ref{pack,file,rule_id}`
  + `signal_evidence`,events_jsonl 导出时映射到 event.schema.json
  (evidence.signals ≥1、frames_ref ≥1 的契约约束由运行器保证)。

## 后果

- 依赖面:core 从零依赖变为一个运行时依赖(serde + serde_yaml_ng + serde_json)。
- 坏 YAML 报错含 serde_yaml_ng 的行列信息;规则 id 重复/信号不存在时以 warning 呈现。
- 后续 signal.schema.json 冻结后,证据 signals 结构随之对齐(T-0.3)。
