# 规则包目录(rules-catalog,任务卡 B4)

> 登记在册的规则包:来源、适用对象、每条规则的含义与触发样例。
> 规则包是**数据不是代码**(ADR-6):YAML 放进任意目录,配置中心「规则引擎」卡挂载即生效,改完「↻ 重跑规则」秒级热加载。
> 生成新厂商规则包:把协议文档/阈值表粘给 AI + [点位表格式与AI转换指南.md](点位表格式与AI转换指南.md) 同样的提示词思路,产出本目录格式的 YAML 后人工校对一轮。

## 内置包(随软件分发)

| 包 | 位置 | 适用 | 事件码 |
|---|---|---|---|
| generic-bms | `samples/rules-pack/generic-bms/`(生成器:`gen_samples`) | 通用 BMS 温度/运行状态演示 | TEMP_OVER_LIMIT / TEMP_HIGH / MOTOR_IDLE |
| generic-heartbeat | `samples/rules-pack/generic-heartbeat/` | 通道静默(心跳丢失) | BUS_SILENCE |
| demo-bms | `crates/websrv/assets/demo-bms.rules.yaml`(Web 演示数据) | Web 实时台演示:电机温度带持续时长+变化率 | MOTOR_TEMP_WARN / MOTOR_TEMP_FAULT / MOTOR_TEMP_DROP |

### generic-bms

| 规则 | 级别 | 触发条件 | 说明 |
|---|---|---|---|
| TEMP_OVER_LIMIT | fault | 信号 TempSensor > 32.0(瞬时) | 温度越限,消息含实测值 |
| TEMP_HIGH | warn | 30.0 < TempSensor ≤ 32.0 | 温度偏高预警 |
| MOTOR_IDLE | info | RunState == 2,`once: true` 只报一次 | 电机怠速状态提示 |

### generic-heartbeat

| 规则 | 级别 | 触发条件 | 说明 |
|---|---|---|---|
| BUS_SILENCE | warn | 通道 `candump` 静默 > 80ms | 心跳/周期帧丢失;消息含实际静默时长 |

### demo-bms(持续时长 + 变化率示范)

| 规则 | 级别 | 触发条件 | 说明 |
|---|---|---|---|
| MOTOR_TEMP_WARN | warn | Temp > 50 持续 1s(`for`) | 不到 1s 的尖峰不报,压掉抖动误报 |
| MOTOR_TEMP_FAULT | fault | Temp > 60 持续 1s | 越限告警 |
| MOTOR_TEMP_DROP | warn | Temp 变化率超阈(`on_rate` 滑动窗口) | 温度骤降/骤升爬坡异常 |

## 规则语法速查(详见 ADR-9 与 rules.rs)

```yaml
pack: <厂商-机型>            # 包名,事件 rule_ref.pack 引用它
meta: { vendor: x, model: y, version: "1.0" }
rules:
  - id: <事件码>             # 进事件 evidence.rule_ref.rule_id
    level: info|warn|fault
    on: signal               # 四类触发:signal / timeout / frame / rate
    signal: <信号名>          # 解码出的信号键(DBC 裸名/寄存器工程名)
    when: "$ > 32.0"         # 表达式:$=当前值 prev=上一拍;支持位运算/hex
    for: 1s                  # 可选:持续时长(压抖动)
    once: true               # 可选:只报一次
    message: "…{value}…"      # 模板:{value} {timeout} {silence} 等
  - id: BUS_SILENCE
    on: timeout
    channel: "candump"       # 通道别名匹配
    timeout: 80ms
```

## 行业包(可选付费内容:有付费信号才开工)

> 以下为预留登记位——用户/AI 按协议文档生成后放 `rules-pack/<厂商>/<机型>/` 即生效;
> 软件不内置不爬取厂商阈值。

| 包(预留) | 适用 | 状态 |
|---|---|---|
| pcs-<品牌> | 储能 PCS 阈值(电网电压/母线功率/绝缘) | 待真实样本 |
| bms-<品牌> | 电池簇(温度梯度/压差/SOC 突跳) | 待真实样本 |
| canopen-robot | 机器人 CANopen(EMCY 错误码/NMT 状态跳变) | 待真实样本 |
| gb27930-charge | 充电流程(BHM/BRM 超时、BCP 异常) | 待真实样本 |

## AI 生成规则包的最小提示词

```
你是协议/现场工程师。把下面的协议文档段落转成 IoTProbe 规则包 YAML:
- 只输出 YAML,pack=<厂商>-<机型>;规则 id 用大写蛇形
- 每条规则:level/on/trigger/message 四要素;瞬时阈值不写 for,防抖动写 for
- 值域/阈值必须来自文档原文,不得编造;文档没给的不要造规则
- message 模板使用 {value} 等占位符,中文可读
协议文档:<粘贴>
```
