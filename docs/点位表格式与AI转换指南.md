# 点位表格式与 AI 转换指南

> 目标：把任意厂商的 Excel/Word/PDF 协议点表，交给 AI 转成 IoTProbe 设备模拟器可直接加载的
> 点位表 YAML。本文 = 目标格式规范 + 完整示例 + 常见列名映射 + 可直接复制的转换提示词 + 自检清单。
> 使用方式：把本文的「转换提示词」整段复制给 AI，再附上你的 Excel 内容/协议文档文本即可。
> 配置中心「模拟联调」场景有「打开本指南」按钮；转换结果保存为 .yaml 后在模拟器卡选择加载。

---

## 1. 目标格式规范（设备模拟器点位表 YAML）

```yaml
# 顶层键:
#   devN        设备定义(N=1,2,3…;enable:0 跳过该台)
#   devN_分节名 点位分节(一个设备可有多节,按键顺序合并;分节名随意)
#   global      预留(可省略)

dev1: {enable: 1, name: PCS-1号, link: tcp, ip: 192.168.1.117, port: 1502, slave: 1, poll_ms: 1000}

dev1_状态数据:
  系统故障状态: {addr: 0x0020, func: 3, type: bit, bit: 0, rw: 1}
  电网电压:     {addr: 0x001E, func: 3, type: u16, scale: 0.1, unit: V, init: 4000, grp: 状态数据}
```

### 设备头（devN 行）字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enable` | 0/1 | 1 | 0 = 跳过该台 |
| `name` | 文本 | 未命名 | 设备名（进通道别名"模拟·name"） |
| `link` | tcp / rtu_tcp | tcp | **tcp**=Modbus TCP(MBAP 头)；**rtu_tcp**=RTU-over-TCP(串口服务器透传，slave+CRC 定帧) |
| `ip` | 文本 | — | 设备原 IP（模拟器仅记录展示；实际绑定见下） |
| `port` | 0~65535 | 502 | 监听端口。**端口唯一 → 绑 0.0.0.0（按表里 ip:端口 原样连，局域网可达）**；**同端口多台 → 自动改绑 127.0.0.N 按设备区分**；0=系统分配 |
| `slave` | 1~247 | 1 | unit/slave 站号（真实表常全为 1，直接保留） |
| `poll_ms` | ≥50 毫秒 | 1000 | **自轮询周期**：模拟器以此节奏自己读自己并进管线（无主机连入曲线也滚动）；0=关闭 |

### 点位（devN_分节 下每行）字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| 键 | 文本 | — | 行键（设备内唯一即可，常用 `a<地址>` 或寄存器名） |
| `name` | 文本 | 键名 | 点位工程名（进信号键，建议中文原文） |
| `addr` | int / 0xHEX | 必填 | 寄存器地址（支持十进制与 0x 十六进制） |
| `func` | 1~4 | 3 | Modbus 功能码：3=保持寄存器(读/写) 4=输入寄存器(只读) 1/2=线圈/离散量(按 bit) |
| `type` | 见下 | u16 | u16/i16/u32/i32/f32(=2 寄存器浮点)/str/mac(需 `regs`)/bit(需 `bit` 位号) |
| `regs` | ≥1 | 1 | 占用寄存器数（str/mac 必填：字符数÷2 向上取整） |
| `scale` | 数 | 1.0 | 物理值 = raw × scale（显示/曲线用） |
| `unit` | 文本 | — | 单位（显示在点位值后；点位编辑表拖拽框后缀） |
| `enum` | 映射 | — | 枚举表（物理值 → 含义），如 `{0: 停机, 1: 运行, 2: 待机}`；写了之后点位编辑表改为下拉选含义，选中即按该物理值置位 |
| `bit` | 0~15 | — | bit 点位在寄存器内的位号（同地址可挂多个 bit） |
| `rw` | 0/1 | 0 | 1=可写（模拟器接受 func6/16 写该点）；未写 rw 的点在点位编辑表里标 🔒（主机不可写），但模拟器侧（你）仍可改——那是在"设定被测量" |
| `min` | 数 | — | **Random 场景随机下限（物理值）**；与 max 成对出现 |
| `max` | 数 | — | **Random 场景随机上限（物理值）**；有 min/max 的点在范围内随机波动，模拟真实运行 |
| `grp` | 文本 | 分节名 | 分组（GUI 点位表按此分组展示） |
| `init` | 数 | 0 | 初始值：数值型=raw 寄存器值（**不经 scale**，与 Excel 导出一致）；str=字符串内容 |

**约束**：bit 点不占寄存器（宿主寄存器由同地址任意点创建，模拟器会自动注册）；u32/i32/f32 占 2 寄存器；str 占 `regs` 个。

---

## 2. 三个完整示例

### 示例 A：最小可用（1 台 2 点）

```yaml
dev1: {enable: 1, name: 温控器, port: 502, slave: 1, poll_ms: 1000}

dev1_数据:
  温度: {addr: 0, func: 3, type: i16, scale: 0.1, unit: "°C", init: 250, min: 15.0, max: 85.0, grp: 数据}
  开关: {addr: 1, func: 3, type: bit, bit: 0, rw: 1}
```

> `min/max` 是 Random 扰动场景的物理值域：模拟器"Random 随机扰动"模式下，
> 带 min/max 的点位在区间内随机取值（模拟真实运行波动）；无 min/max 的点只做 ±2% 微抖。

### 示例 B：真实储能 PCS（多设备多端口 + bit 状态 + 字符串）

```yaml
dev1: {enable: 1, role: 1, name: PCS-1号, link: tcp, ip: 192.168.1.117, port: 1502, slave: 1, poll_ms: 1000}
dev2: {enable: 1, role: 1, name: PCS-2号, link: tcp, ip: 192.168.1.117, port: 2502, slave: 1, poll_ms: 1000}
dev6: {enable: 1, role: 3, name: 消防主机, link: tcp, ip: 192.168.1.117, port: 6502, slave: 80, poll_ms: 1000}

dev1_状态数据:
  序号:       {name: 序列号, addr: 0x0000, func: 3, type: str, regs: 11, init: "ZX0P600443411907030001", grp: 状态数据}
  系统故障状态: {addr: 0x0020, func: 3, type: bit, bit: 0, grp: 状态数据}
  系统并网状态: {addr: 0x0020, func: 3, type: bit, bit: 4, grp: 状态数据}
  电网电压:    {addr: 0x0032, func: 3, type: u16, scale: 0.1, unit: V, init: 4000, grp: 状态数据}
dev1_控制与定值:
  系统启停:    {addr: 0x03E9, func: 3, type: bit, bit: 0, rw: 1, grp: 控制}
  有功功率定值: {addr: 0x03EA, func: 3, type: i32, scale: 1.0, unit: kW, rw: 1, grp: 控制}
```

### 示例 C：RTU-over-TCP（串口服务器透传 485 设备）

```yaml
dev1: {enable: 1, name: 电表, link: rtu_tcp, ip: 192.168.1.50, port: 8899, slave: 12, poll_ms: 2000}

dev1_遥测:
  有功总功: {addr: 0x0000, func: 4, type: u32, scale: 0.01, unit: kWh, init: 123456, grp: 遥测}
  A相电压:  {addr: 0x0002, func: 4, type: u16, scale: 0.1, unit: V, init: 2200, grp: 遥测}
```

---

## 3. 常见厂商列名 → 字段映射

| Excel/文档常见列名 | 映射到 | 备注 |
|---|---|---|
| 寄存器地址 / 地址 / Address / Addr / Modbus 地址 | `addr` | 保持原文（0x 或十进制均可） |
| 功能码 / FC / Function Code / 读指令 | `func` | "03/0x03/保持寄存器"→3；"04/输入寄存器"→4；"01/线圈"→1；"02/离散量"→2 |
| 数据类型 / 类型 / Type / 长度 | `type` + `regs` | "U16/UINT16"→u16；"I16/INT16"→i16；"U32/UINT32/Long"→u32；"I32"→i32；"Float/F32"→f32；"String/n 字符"→str+regs=n÷2 向上取整；"Bit/位/BOOL"→bit+bit 位号 |
| 位号 / Bit / 位 | `bit` | 0~15；同地址多个 bit 拆多行 |
| 系数 / 变比 / 缩放 / Scale / 分辨率 | `scale` | 物理=raw×scale；"0.1V/字节"即 0.1 |
| 单位 / Unit | `unit` | 原文 |
| 读写 / R/W / 权限 / Access | `rw` | 含"写/W/可写"→1，只读→0 |
| 工程名 / 点名 / 名称 / 描述 / Description | `name` | 中文原文保留（信号键用它） |
| 初始值 / 默认值 / Init | `init` | 数值型填 raw（除以 scale 前的寄存器值）；字符串原样 |
| 分组 / 组 / Group / 分节 | `grp` 或分节名 | 建议按 Excel 的 sheet/大标题拆 `devN_分节` |
| 设备名 / 从机 / Slave / 站号 | `name` / `slave` | 每台设备一个 devN 头；站号填 `slave` |
| IP / 端口 / Port | `ip` / `port` | 原样填；模拟器绑定策略见设备头 `port` 说明 |

---

## 4. 转换提示词（整段复制给 AI）

```text
你是工业协议点表转换专家。请把我提供的厂商点位表(Excel/文档内容附后)转换为 IoTProbe
设备模拟器的点位表 YAML。严格遵守以下规范：

【顶层结构】每台设备一个 `devN:` 头(N 从 1 递增)，点位放 `devN_分节名:` 下(分节按原文
大标题/sheet 拆)；只输出 YAML 代码块，不要解释。

【设备头字段】enable:1, name:设备名(原文), link:tcp(默认;文档明确说"串口服务器/485透传/
RTU over TCP"才用 rtu_tcp), ip:原文, port:原文(数字), slave:站号(原文,常为1), poll_ms:1000。

【每行点位】键 = a<地址十六进制去0x前缀><位号可选>(如 a32b0)；字段：
name(工程名中文原文) / addr(原样) / func(数字) / type(u16|i16|u32|i32|f32|str|mac|bit) /
regs(str/mac 必填=字符数÷2向上取整) / bit(bit 必填=位号) / scale(默认 1.0,有系数才写) /
unit(原文) / rw(原文含"写"才 1) / grp(原分组名) / init(数值=raw 寄存器值,即原文除以 scale
之前;字符串加引号)。

【硬性规则】
1. 每行 addr/func/type 必须完整,缺失处从上下文推断并加注释 #推
2. bit 点:同一寄存器地址的多个位拆成多行,键带位号(a32b0/a32b4)
3. str:regs 按 desc 里示例字符长度算;init 用 desc 示例字符串
4. 不确定 scale 时:文档写"分辨率 0.1"→scale:0.1;没有就省略(默认 1.0)
5. 全部点位保留,不要省略"看起来重复"的行
6. 数值点尽量给 min/max:从文档"量程/范围/Max/Min"列提取(物理值);
   文档没有时按 type 合理估计(u16+scale 可到 65535×scale,取常见运行段的 1.5 倍)
7. 输出后附 3 行自检:总设备数/总点位数/你不确定的字段清单

【我的点表】(粘贴 Excel 内容或文档文本)
```

---

## 5. 自检清单（AI 输出后人工核对）

- [ ] `devN` 编号连续、每台都有 `port`（同端口多台时确认理解了 127.0.0.N 策略）
- [ ] **`init` 是 raw 寄存器值**（原文物理值 ×  ÷scale 的那一步有没有做反？）
- [ ] bit 点 `bit` 位号与原文一致；str 点 `regs` 与示例长度匹配
- [ ] `func` 3/4 没有混淆（保持寄存器=3，输入寄存器=4，**bit 状态点通常也在 func3**）
- [ ] 可写控制点（定值/启停）标了 `rw: 1`——模拟器才会接受 EMS 下发
- [ ] 加载验证：配置中心 → 设备模拟器选该 YAML → 启动无告警 → 卡片逐台显示端点 →
      主机连入读任意已定义地址有应答（异常码 0x02 = 地址未注册，回来报 bug）
- [ ] 联调留档：勾「录制 .ndjson」，EMS 轮询+模拟器自轮询全落盘可回放

## 6. 已知边界

- 线圈(01)/离散量(02) 功能码：当前模拟器按 func3/4 语义应答（bit 读写覆盖大部分场景），
  独立线圈空间待后续版本
- 模拟器当前支持 Modbus TCP / Modbus RTU-over-TCP 两种链路；IEC 104 与自定义 DSL 设备模拟
  在路线图（ADR-0016 预留接口），自定义协议设备可先用「设备模拟器(Modbus) + 试探/CustomSpec」
  组合覆盖分析侧
- 点位表键（行键）设备内必须唯一，重复键后者覆盖前者
```
