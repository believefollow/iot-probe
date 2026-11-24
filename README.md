# IoTProbe — IoT 日志多协议解析与时序分析台

Rust 编写的 PC 桌面工具,定位是 **"拿到日志之后"** 的分析:
把 Wireshark 的解析深度、SavvyCAN 的信号时序曲线、三联动交互合并到一起,面向 IoT 混合总线(RS485/CAN/EtherCAT/TCP)。

核心仍以离线日志分析为主;v0.1 起新增**实时接入**(FR-S1:serbox NDJSON 帧流经 TCP/串口进入现有管线,core 不引驱动)与**会话录制**(FR-S2:原始行落盘 `.ndjson`,离线可重放)。

> **定位一句话:IoTProbe 不生成代码、不建工程、不做平台——它把现场的总线字节变成 5 分钟能看懂的事实与证据,逻辑交给 YAML 数据和 AI。**
> **目标场景:储能/能源与工业集成商的协议验收与诊断伴侣**——电网侧 IEC 104 / 设备侧 Modbus / CAN(EtherCAT/PROFINET) / 聚合平台 MQTT,出厂到查错全流程(模拟→单测→实时→回放→灌入→批量回归)。不涉及 EMS 调度/控制本体。

## 开源与授权

核心(MIT/Apache-2.0 双许可,见 [LICENSE](LICENSE))开源:接入、解析、可视化、事件、MCP 全部能力。
**不做代码生成、不做节点仿真、不做标定栈**——逻辑层一律走 AI 可生成的数据(YAML 点表 / rules-pack / CustomSpec)。
后续按需提供付费行业内容包(厂商 rules-pack / DTC 数据包)与协议转换服务;基础 generic 包永久开源,当前无任何付费项。

## 功能(v0.1)

| 能力 | 说明 |
|---|---|
| **配置中心(ADR-0013/0015)** | 顶栏「工作台 \| 配置中心」整页切换;**场景视图**(ADR-0015):1 离线分析 / 2 现场排故 / 3 产线抽测 / 4 数据喂AI / 5 模拟联调 / 6 全部配置——按任务只显相关设置,步骤化排布,步骤头自动打 ✓ 完成徽章;卡片模块跨场景复用(状态在上、操作在下);快捷键 1~6 切场景 · Ctrl+0 工作台 · F1 帮助;展示类窗口(事件/试探/任务/拓扑)保留悬浮窗但入口统一、打开数在菜单名 |
| 实时接入 | serbox NDJSON 帧流(frame.schema.json):**源类型分类下拉**(文件/网络/串口·CAN卡/模拟,默认=回放文件导入);TCP 客户端 / TCP 服务端 / 串口(COM)/ 回放录制文件;坏行计数不中断,meta.seq 丢帧检测;**回放可并入当前实时会话**(重映射到指定设备通道,原速/×5/×20/极速,模拟现场);报文表/曲线/事件/三联动零改动复用 |
| 会话录制 | 实时流原始 NDJSON 行追加落盘为 `.ndjson`;「打开文件」可直接离线重放(同一解析器) |
| 文件摄入 | 通用 hex 串口日志(SSCOM 风格,带时间戳/方向/裸hex均可)、candump(SocketCAN)、**Vector ASC**(CANoe/ZCANPro 导出)、pcap / pcapng(自动 TCP 重组)、**SocketCAN 抓包(pcap linktype 204,含 CAN FD)**、**.ndjson 帧流录制** |
| 协议解析 | Modbus RTU(无同步头的启发式定界 + CRC)、Modbus TCP、**IEC 60870-5-104**(APCI 定界/纠错 + ASDU:遥信/双点/步位置/遥测 NVA·BVA·短浮点/累计量/带时标 CP56/遥控/设定值/总召唤/时钟同步;通道识别先于 MQTT 判定,修复 2404 端口流量被误判为 MQTT)、MQTT(3.1.x/5.0 基础报文)、EtherCAT(报文+CoE SDO 简析+WKC)、CAN/CAN FD + DBC、UDP/ARP |
| DBC | Intel/Motorola 双字节序、**多路复用(M / mN)+ SG_MUL_VAL_ 扩展复用**、**扩展帧 ID(bit31)**、**VAL_ 值表(枚举显示名)**、**SIG_VALTYPE_ 浮点**、factor/offset、**GenMsgCycleTime 标称周期(供聚合视图比对)** |
| **多帧重组(FR-3.4)** | **J1939 TP.BAM**:BAM 宣告(总长/包数/PGN)→ 分片缓存按序号回填 → 齐包后按 PGN+SA+对端 PS 掩码匹配 DBC 解码(容忍任意优先级);产出重组信号 + Info 事件(证据链=参与碎片帧);会话被新会话替换即报丢帧(GB/T 27930 BRM 49B/BCP 13B/BCS 9B 实测) |
| **Modbus** | RTU ✓ / **ASCII ✓(LRC)** / TCP ✓;**6 种字节序(AB/BA/ABCD/BADC/CDAB/DCBA,FR-3.2)**、16/32bit 宽度、有符号、**枚举表(FR-3.3)**、缩放/单位;读写寄存器值均入时序 |
| **104 点表 + 配置编辑器(MVP ②)** | **IEC 104 信息体点表**:(类型,IOA,CA)→ 工程名/变比/偏移/单位,命中即改信号键并按 factor·offset 换算(ty=0/CA 缺省为通配,精确→通配两级命中);YAML(盘点脚本生态)/JSON(GUI 编辑形态)双格式,**配置中心 → 协议解析一键「编辑…」开点表编辑器**:逐行改工程名/变比/偏移/单位/曲线勾选,增删点、保存、应用并重新加载;会话持久化,CLI `--map104` 同管道 |
| **储能拓扑视图(MVP ③)** | **设备卡片总览**:拓扑 YAML(设备 id/类型 电池簇·PCS·电表/信号绑定+越限表达式)或**零配置「按信号前缀自动生成」**(unit1·TempSensor → 设备 unit1);评估把匹配到的信号最新值/单位/帧号归到卡片,健康级 = 绑定越限(fault>warn)∪ 归属诊断事件数;**异常卡片红/橙高亮**,信号值点击直接跳帧(三联动);未绑定信号计数显示覆盖度;「保存 YAML…」把自动生成的拓扑落盘再手工精修 |
| **FR-4.2 聚合视图** | 按 ID/CAN、按 unit·方向(Modbus)聚合:帧数/周期均值/P95/最大/抖动σ%,抖动 >25% 高亮;**DBC 标称周期比对(偏差>20% 标橙)** — 一眼看出谁的周期抖了 |
| **规则引擎(ADR-6)** | YAML 规则包(rules-pack/<厂商>/<机型>):`on_signal`(阈值/布尔/**for 持续时长**)/`on_timeout`(通道静默)/`on_frame`(帧匹配)/**on_rate(变化率滑动窗口)** → 契约语义事件(level/code/**evidence{signals,frames_ref,rule_ref}**);表达式支持位运算/hex 字面量/$与prev;**变化率规则**:窗口内 Δ值/Δ秒(变量 rate/delta/$),触发后冷却一个窗口防连报,检测 SOC 突跳、温度骤升等爬坡异常;**内置 generic-bms / generic-heartbeat 两包**;CLI `--rules`、配置中心规则引擎卡挂载;**FR-3.7 热加载**:事件页「↻ 重跑规则」改完 YAML 秒级生效(剔除旧规则事件→重跑→重排序,不动报文解码/信号/诊断事件) |
| **MCP server(FR-7.1)** | stdio JSON-RPC 五工具:`list_sessions / query_events / query_frames / get_signal_series / export_session` — Claude/Cursor 直连查询报文与事件;数据源 = 契约 JSONL 导出目录 |
| **live 采集(FR-S1,CAN FD P0)** | **六家硬件后端统一管线**:ZLG USBCANFD(ADR-0010)、VCI 兼容卡(创芯老版 32 位经桥接 / **新 SDK x64 免桥接**)、SLCAN(CANable)、**PEAK PCAN-Basic(经典+FD)**、**Kvaser CANlib(Virtual CAN 可无硬件)**、**GCAN ECanVci(CHUSBDLL 预载)**(ADR-0014,均未经真机 bench);硬件时戳(hw/L1),只听默认开启(FR-10.4);帧 → 契约 NDJSON → 同一管线(录制/回放/解析/曲线/规则全复用);另含 TCP 客户端/服务端/串口 NDJSON 源与**模拟 CAN 总线**(无硬件演示) |
| **live Modbus 485(P1)** | **RTU-over-TCP**(有人/周立功串口服务器):静默间隙+CRC16 定帧 → uart/L0 契约入管线;间隙 5-200ms 可调 |
| **Modbus 设备模拟器(P1)** | 本机扮演多台从机(点位表 devN 驱动,**拓扑对齐真实采集表**):**每台设备独立监听**——端口唯一绑 0.0.0.0(主机按表里 ip:端口 原样连,局域网可达),同端口多机自动改 127.0.0.<N> 按设备区分(unit 保持表里原值,无 init 的 bit 点位所在寄存器也注册,主机逐点位读不再踩 0x02);**自轮询发数**(poll_ms 周期按已定义地址连续段读自己,无主机连入曲线也滚动,poll_ms=0 关);**点位 min/max 随机域**(Random 场景在物理值范围内波动,模拟真实运行;无域 ±2% 微抖);**双链路** link: tcp=Modbus TCP / rtu_tcp=RTU-over-TCP(串口服务器透传,slave+CRC 定帧,未知 slave 回 0x0B);厂商 Excel/文档→YAML 用 **AI 转换指南**(docs/点位表格式与AI转换指南.md,含提示词);**NDJSON 录制落盘**(原始帧可离线回放);MBAP 组帧(粘包一次全应答/拆包跨轮续传/非法流断连)、func3/4 读·func6/16 写、越界回异常码、未知 unit 回网关码 0x0B;每实例独立收集器,多模拟器不串流 |
| **发送面板(FR-4.7/10.4/10.5)** | 单次/周期发送(经典 CAN + CAN FD/BRS);**默认锁定,显式解锁**;**id 白名单**(单 id/区间,hex/十进制)入队出队双重校验,越界拒绝计数;**RTU 静默间隙 + CRC16 双启发定帧**,帧前未定界字节计入丢弃 |
| **证据包(FR-7.2/7.3)** | 事件页一键导出(选中事件 ±10s 或全会话):事件+信号+原始帧字节+规则出处,单文件 ≤10MB(超限自动抽稀),人类可读摘要,给 AI 排障 |
| 自定义协议 | JSON DSL:**串口行 / TCP 字节流 / UDP 数据报** 三种形态自动识别与定界;同步头 + 长度域 + 校验(crc16_modbus/ccitt/xmodem/sum8/xor8/lrc)+ 字段(整型/浮点/缩放/位域),加载即用,自动探测打分 |
| **HTTP(轻量)** | socket 通道自动识别:请求/状态行 + Content-Length,设备 Web API 排障 |
| **未知协议试探** | 对 RAW 通道自动逆向:同步头统计 → 长度域假设验证 → 校验算法网格试配 → 常量/计数器/载荷区域识别 → 生成 CustomSpec 草案,**一键采纳闭环**(提议-确认式,非黑盒自动化);文本/NDJSON 自动判定 |
| **协议解析(模板)** | 配置中心 → 协议解析卡集中管理:自定义 JSON / 试探草案 / **CAN DBC 协议库**(导入进 protocols/ 目录,多选合并解码)/ 寄存器映射 / 104 点表 / 储能拓扑定义,列表+摘要+移除,一键「应用并重新加载」 |
| **任务分析** | 轮询/重试类事务:请求-响应自动配对,统计事务数/无响应(超时)/异常码/RTT(min·中位·P95·max)/最长连续失败段;**RTT 直接成为时序信号**;丢失响应的轮次自动报"请求被后续请求覆盖" |
| 时序曲线 | 解码出的参数自动成列:寄存器值、DBC 信号、自定义字段、WKC、Δt、**RTT**;像素列 min/max 抽稀,百万点可交互 |
| 异常事件 | CRC 错误、无法定界、Modbus 异常码、MQTT 残包、EtherCAT WKC=0、抓包缺段、间隔异常(P95×2 自动阈值)、**请求无响应(被覆盖/日志结束)** |
| 三联动 | 曲线上点选 → 帧表定位;事件列表点选 → 跳帧;选帧 → hex 高亮 + 字段树 + 曲线游标 |
| 其他 | 文本过滤、协议过滤、**表头点击排序、右键帧快速过滤**、**会话持久化(文件/模板/信号勾选,重启自动恢复)**、大文件懒解码护栏(字段树预算 30 万帧,超出自动按需解码)、CSV 导出(帧/信号/事件)、**契约 JSONL 导出(过 frame/event.schema 校验)**、**时基等级标注(FR-2.2:通道面板显示 sw/L0~wall)** |
| **拓扑连线图(A1)** | 主机(EMS/HMI)→模拟器设备连线图:绿=已连/红=断开或近 5s 异常码/灰=无主机流量(自轮询不算);TCP 实线/RTU 透传虚线;点设备节点→报文过滤到该设备;多实例展平 |
| **点位实时值列+sparkline(A2)** | 模拟器点位行内"当前/近拍 min~max"+ 34×12px 微曲线(500ms 节流×32 拍环形);Random/Fault 场景波动一眼可见 |
| **多模拟器实例(A3)** | `Vec<ModDevInst>` 并行运行(如同时模拟 Modbus+104),逐实例启停/录制,重名自动加序号;点位表视图实例下拉 |
| **写指令视图(A4)** | 规则任务窗按 Modbus 通道列出 func5/6/15/16 事务:时间/unit/地址/值/RTT/结果(OK·异常码·无响应),→帧 跳转;EMS 下发动作一目了然 |
| **一键现场配置(B1)** | 现场排故场景单按钮恢复上次源参数+开启录制+连接;协议/规则包随会话自动恢复;上次是模拟器则一键起模拟器 |
| **右键定位点位(B2)** | 帧详情字段右键→在运行中的模拟器按点位名/寄存器地址(HR/IR+地址)反查,命中即切场景+选实例+过滤定位 |
| **工单摘要(B3)** | 证据一键复制为 Markdown(时间线+事件表+证据帧号+规则包),直接贴售后工单/微信群;口径与证据包一致(选中事件 ±10s/全会话) |
| **串口终端(E1)** | 设备 CLI/AT 交互窗:hex/文本双视图、时间戳行、单发/周期发送(可追加 CRLF)、同录 NDJSON 可离线回放进解析管线 |
| **多通道并行接入(C1)** | `Vec<LiveSlot>` 多实时源同会话并行(第二路 485/第二张 CAN 卡不再开第二个实例);记录按通道合并,统计逐槽累计,逐源结束提示 |
| **内存护栏(C4)** | 实时累积超 200 万条滚动丢弃最旧,状态栏诚实标注(完整数据靠源头录制,不受影响) |
| **崩溃报告(D2)** | panic hook 写 crash-<时间戳>.log(信息+线程+会话标签+回溯)到 exe 目录;下次启动提示"上次异常退出" |
| **增量更新提示(D1)** | exe 同目录 update/manifest.json 版本更大则启动提示(离线口,不自动下载不自动替换) |
| **解析正确性基线(C3)** | scripts/gen_golden.py 用 cantools(独立参照实现)对语料逐帧解码 → 7510 帧/65842 个信号值,golden_decode 测试逐信号比对 **100% 一致**(1e-6 相对误差);GBK DBC 兼容 |
| **104 从机模拟(A5)** | IEC 60870-5-104 从机:STARTDT/STOPDT/TESTFR、总召唤(激活确认→逐点 COT=20→激活结束)、时钟同步、遥控(激活确认→写点位→激活结束)、变位主动上送(COT=3);点表 YAML 驱动+GUI 置值;帧进同一管线(104 解析器直接可用) |
| **自定义协议从机(A6)** | CustomSpec 扮演从机:deframe 收帧→字段解码→原帧回显(RTT/校验联调);自轮询按 spec 反向编码发数(长度域/校验重算);试探引擎草案可直接用 |
| **CANopen 解析(F1)** | DBC 之上的语义层:NMT 状态机事件、EMCY 错误码分段可读、心跳状态、**SDO 请求/响应配对事件**(读/写+RTT+帧号引用,abort/无响应单列)、PDO 节点标注;严格帧结构校验防误标;PDO 信号命名等真实 EDS 样本 |
| **打开即体检(MVP 离线②)** | 离线分析场景第二步"体检(打开即出)":结论 PASS/WARN/FAIL(声明式阈值:fault>0/Warn 或链路质量>0)+ 帧分布/DBC 覆盖率/事件分级/链路质量;挂协议前也能先看事实 |
| **HTML 报告导出(MVP 离线④)** | 自包含可打印 HTML(体检结论+通道表+事件明细+信号统计,内联 CSS 零依赖);GUI 体检卡一键 / CLI `--report` / 批量汇总共用同一生成器 |
| **批量回归 CLI** | `batch_runner --dir <日志目录> [--rules --dbc --map104 --out report.html]`:目录扫描→逐文件解析+规则→PASS/FAIL/WARN 汇总表+HTML;CI 语义(fail 即非零退出);"日志的 CI" |
| **BLF 导入(Vector)** | LOGG/LOBJ/LOG 容器(zlib+未压缩),CAN/CANFD(type 1/2/100/101)/错误帧(73)/GLOBAL_MARKER;真实文件锚点 issue_1905(22 FD64 对象)专测 + 6 语料夹具结构回归 |
| **UX 摩擦修复(2026-11-21 审计)** | ① 模拟联调三种从机卡按协议折叠(标题带运行状态徽章,只展开在用的);② 体检卡 verdict 下一步引导(fault→一键事件窗/DBC 未命中→挂协议/健康→工作台);③ 首启分流(无数据无 samples 默认进离线分析场景);④ 顶栏常驻体检 chip(工作台直接看健康,点击直达);⑤ 批量回归 GUI 入口(体检卡+证据包动作,透传规则包/多 DBC);⑥ 自定义从机字段行内 DragValue 改值
| **场景步骤合并(使用体验审计)** | 离线分析 4 步→3 步:打开+体检合一(体检零点击,单独成步是伪步骤);模拟联调三种从机卡按协议折叠;每步 done 徽章自动判定 |
| **多 DBC 合并解码** | 全链路:GUI 协议库多选(dbc_all 合并,按 ID 命中)/CLI 重复 --dbc/batch_runner 多 --dbc 合并——CAN 总线多厂商报文同挂一库 |
| **单帧解码(W4)** | 粘一帧 hex 秒解(售后微信收帧/联调验帧):GUI 工具窗多行粘贴(每行一帧,candump 602#4017... 嗅探)+CLI --frame;同一 analyze 管线——DBC/CANopen SDO 配对/Modbus/自定义语义全可用,零新解析代码 || **帧流转发到 TCP 端口(W:指向其他端口)** | 实时接入卡勾选「转发帧流」:契约帧 NDJSON 实时广播到 TCP 端口(默认 9101,可热插拔不重连)——现场 A 机采集,远端脚本/第二台 iotprobe/BI 工具实时消费;主源+三模拟器泵全部接入;loopback 测试 |
| **回放注入 FD 修复** | 现场报文灌入手上设备:录制/抓包按时间轴经硬件 TX 发出;>8B 载荷自动判 CAN FD(此前 FD 帧注入 0 发出) || **S7comm 解析** | TPKT/COTP 定界 → ROSCTR(Job/Ack/Ack_Data/Userdata)→ 功能码(Setup/Read Var/Write Var/Upload/Download)→ S7ANY 变量项(存储区/DB/地址/数量)→ Ack_Data 返回码分级;Job/Ack 按 pdu_ref 配对(事务+RTT+帧号,失败=fault);**真实样本验证**(wiki 220 帧全解) || **PROFINET 解析(DCP)** | EtherType 0x8892 家族接入:DCP(Get/Set/Identify/Hello,ServiceType req/resp 厂商变体兼容)+PTCP 同步帧+RT 数据标注;**DCP Set 事件**(设备名/改 IP 现场误配立即可见);IP 块点分显示;**真实样本验证**(ChangeIPUsingDCP.pcap 6 帧全解);RT 循环数据语义化等 GSDML 样本 || **DL/T 645-2007 读表** | 帧定界(CS 校验+**L 字段长度自纠**——厂家普遍不守 L)/FE 唤醒吃掉/失步重扫/读数据 0x11+常用 DI(电压电流功率电量)/出错响应;**645 从机模拟**(TCP 透传形态,EMS 抄表验证);串口 2400/Even/8/1 由串口服务器转 TCP;真表 golden 采购中 || **协议正确性回归** | cargo test:app 59 + core 22(golden/canopen/e2e/契约)——新增功能全带测试落地 |


## 构建 & 运行

```bash
cargo build --release
# 生成示例数据(可选,demo 会在启动时自动加载 ./samples)
cargo run -p iotprobe-core --bin gen_samples
# 运行
cargo run --release -p iotprobe
# 32 位 VCI 桥接(老设备 32 位 ControlCAN.dll 专用;先 rustup target add i686-pc-windows-msvc)
cargo build --release --target i686-pc-windows-msvc -p vci-bridge
```

Windows 下自动加载微软雅黑(中文字体);目录 `samples/` 存在时启动即演示。

## 发布打包(Windows)

```bash
cargo build --release -p iotprobe
cargo build --release --target i686-pc-windows-msvc -p vcibridge   # 32 位老 VCI 桥接
python -I scripts/package_release.py --variant clean   # 干净版(运行时精简)
python -I scripts/package_release.py --variant full    # 全带版(全部原料)
python -I scripts/package_release.py --variant both    # 两个都打
```

- **clean 干净版**:主程序 + 32 位桥接 + ControlCAN.dll + 各家**运行时 DLL**(zlgcan+kerneldlls / cxcan sdk x64 / gcan / peak / kvaser)+ protocols/ DBC 库(6 份)+ samples/ 示例报文 + 使用说明 —— 现场直接用。
- **full 全带版**:clean 全部内容 + **IXXAT/来可运行时 DLL(待接入)** + 各家 SDK 头文件与库 + PEAK 全套(Samples/NuGet/ARM64/Include) + 厂商手册 PDF + 来可内核驱动 —— 现场开发/调试硬件时用。
- 两个版本都不含原始压缩包与安装器解包树(可再生内容);硬件厂商 USB 驱动需按 canlib/README.md 装厂商驱动。

**VCI 兼容卡 32 位老设备**:创芯 CANalyst-II/USBCAN 系及国产兼容卡用厂商 ControlCAN.dll。DLL 与程序位数一致时进程内直接加载;DLL 是 32 位而程序是 64 位时,把 32 位构建的 `vci-bridge.exe` 放到主程序目录即可自动桥接(位数不匹配且无桥接时给出明确指引)。DLL/桥接搜索顺序:主程序目录 → 主程序目录\canlib\ → 当前目录。

## CLI 快速验证(无 GUI)

逐条命令的实测示例见 **[docs/cli-examples.md](docs/cli-examples.md)**；AI 接入教程见 **[docs/MCP使用教程.md](docs/MCP使用教程.md)**；三场景出货验收手跑清单见 **[docs/G2-acceptance.md](docs/G2-acceptance.md)**。

```bash
cargo run -p iotprobe-core --bin dbg_analyze -- 文件.log [其它文件...]
   [--custom spec.json] [--dbc x.dbc] [--map map.json] [--map104 points.yaml] [--rules dir] [--probe]
   [--export 输出目录]   # 导出 <文件名>.frames/events/signals.jsonl 契约(MCP server 数据源,S3)
```

打印:通道协议识别结果、信号列表、事件、帧样例。`--probe` 对未识别协议通道做试探并输出草案。

打印:通道协议识别结果、信号列表、事件、帧样例。`--probe` 对未识别协议通道做试探并输出草案。

## 多协议识别回测矩阵

`D:\dev\tools\test-corpus-tools\run_matrix.py` 对测试语料库(`../test-corpus/`,公开标准/开源/自合成样本)一键回归:

```bash
python -I run_matrix.py <dbg_analyze.exe> [语料库目录]
```

期望协议/最小信号数/参数配置登记在脚本 `EXPECT` 表(新增语料加一行),逐条跑 `dbg_analyze` 断言识别结果,输出 PASS/FAIL 矩阵 + `matrix_result.json`(供 CI diff)。当前基线 **35/35 PASS**:GB27930(CAN+TP 重组)、python-can ASC、Modbus TCP/RTU(+点位表)、IEC 104 ×5(含 200 RTU 合成大包)、**真实世界抓包 24 份(Wireshark wiki/EtherCAT/S7/MQTT/J1939 卡车 CAN/DNP3 多会话+坏帧/MQTT 短会话(含愈合)/CAN FD ASC/BLF ×6,`test-corpus/08-real-captures/`)**。

## 未知协议试探工作流

拿到一段不知道格式的 485 日志时:

1. 直接加载(识别为 RAW 通道)→ 「未知协议试探」窗口(顶栏「分析工具」菜单)→ **运行试探**
2. 看报告:同步头 / 长度域 / 校验算法 / 置信度 / 字段区域猜测(常量、计数器、载荷)
3. 「保存JSON…」导出草案,人工核对字段含义(改名字、加 scale/单位、勾 plot)
4. 或直接「✔ 采纳并重新加载」—— 立即按草案定界解码,不对劲随时撤

试探是统计启发式(CRC/校验和命中是最强证据),置信度低时请勿盲信;字段语义永远需要人来确认。

## "循环 N 次直到获取结果"的任务怎么看

典型场景:主站轮询/重试直到设备给出有效应答。「规则任务」窗口(顶栏「分析工具」菜单)给出答案,关注优先级:

1. **无响应(超时)次数与位置** —— 哪几轮请求石沉大海?是连续成段(设备离线/总线堵死)还是零星(偶发丢帧)?
2. **失败原因分布** —— 超时 vs 异常码(非法地址/忙/设备故障)vs CRC 错,三类对应完全不同的根因方向
3. **RTT 曲线** —— 重试期间 RTT 是否抬升(设备在忙/网络拥塞);P95 与 max 的差距暴露长尾
4. **最长连续失败段** —— 跨度多少毫秒,期间设备其余寄存器/心跳是否还在动
5. **结果收敛** —— 目标寄存器值曲线在哪一帧终于变成期望值(曲线点选直接跳帧)

事务配对规则:Modbus 按 unit(RTU)/事务 ID(TCP)自动配对并算 RTT;响应到达(含异常响应)即完成事务;请求未等到响应就被下一轮请求覆盖 → 记「无响应(被覆盖)」,日志结束仍未响应 → 记「无响应(日志结束)」。非 Modbus 通道若有 RX/TX 方向信息,按方向交替估算。

## 自定义协议 JSON 示例

```json
{
  "name": "ACME-485",
  "sync": "AA55",
  "min_len": 11,
  "length": {"at": 3, "size": 1, "bias": 7},
  "checksum": {"algo": "crc16_modbus", "cover": [0, "end-2"]},
  "fields": [
    {"name": "cmd",  "at": 2, "ty": "u8"},
    {"name": "temp", "at": 4, "ty": "i16", "scale": 0.1, "unit": "°C", "plot": true},
    {"name": "rpm",  "at": 6, "ty": "u16", "endian": "big", "plot": true},
    {"name": "flags","at": 8, "ty": "u8", "bits": [{"name": "running", "bit": 0}]}
  ]
}
```

- `sync`:hex 字符串;无同步头则留空(按长度域顺序定界)
- `length.at` 相对帧起始;`bias` = 总帧长 − 长度域值
- `checksum.cover` 支持 `"end-2"` 相对帧尾;校验字节位置默认取 cover 结束处
- Modbus 寄存器映射 JSON:`{"regs":[{"addr":0,"name":"TempSensor","scale":0.1,"unit":"°C"}]}`

## 已知边界(v0.1 诚实声明)

- 大文件:字段树预算 30 万帧(约对应内存峰值 <500MB @ 200 万帧实测);超限通道的详情页点击时才解码,寄存器命名通过向后扫描请求恢复
- Modbus RTU 定界依赖 CRC/方向/记录边界;无时间戳日志时间轴不可用(会提示)
- TCP 重组假设无乱序重传洪泛;缺段会标注但不重传
- EtherCAT 只到报文级 + CoE SDO 简析,未解析 ESC 寄存器/状态机
- ASC 支持经典 CAN(含扩展帧)与 CANoe v8.5+ `CANFD` 行;旧式 `Type: 2/3` FD 行跳过并提示;
  BLF 支持 python-can/CANoe 写出的经典 CAN/FD/FD64/错误帧对象与 zlib 压缩容器(自研 inflate);
  其余 BLF 对象类型(全局标记等)跳过并计数
- 一个通道一种主协议(探测打分取最优);混合协议通道后续支持多选
- 试探引擎对"整行一帧"日志最可靠;流式数据依赖同步头间隙分析,弱结构会标 Opaque

## 架构

```
contracts/   冻结契约(与主 spec 同源,只读;变更走 ADR)
docs/        ADR-0007 契约映射偏差 / ADR-0008 双UI策略(egui 离线台 + Web 实时台)
crates/core (零第三方依赖,jsonschema 仅 dev-dep 用于契约校验)
  ingest/    hexlog / candump / ASC(含 CANFD 行) / BLF(+自研 inflate) / pcap / pcapng(含 SocketCAN) / TCP重组 / live(NDJSON 契约流,FR-S1 实时接入地基)
  dissect/   modbus / mqtt / iec104 / map104(104 点表) / dnp3 / ethercat / custom(DSL) / unknown(试探) / 编排+时序+事件(含 J1939 TP.BAM 重组)
  dbc.rs     DBC 解析(Intel/Motorola/复用/扩展帧/VAL_/float)
  crc.rs     CRC/LRC/校验和集合
  topology.rs 储能拓扑(MVP ③):YAML 设备/绑定定义 + 纯函数 evaluate(信号归属/健康级/覆盖度)
  export.rs  CSV + 契约 JSONL(frame.schema / event.schema)
crates/app   eframe 离线分析台(自绘时序图;实时台按 ADR-0008 走 Web/WS,并行新建)
tests/       81 项:单测(字节序向量/表达式求值器/规则包/104 点表/规则热加载/变化率窗口) + e2e(20,含 IEC104 误判回归、GB27930 TP.BAM 重组、104 点表改名/变比、拓扑评估回测×2、规则热加载真实日志回测、变化率真实日志阈值边界) + schema_conformance(jsonschema)
```

## MCP:AI 客户端接入(定稿教程 → [docs/MCP使用教程.md](docs/MCP使用教程.md))

两个只读 MCP server,按数据形态选(参数/响应均实测确认):

| | **ai-gate**(推荐入口) | **离线 JSONL server** |
|---|---|---|
| exe | `iotprobe-mcp.exe`(rmcp 官方 SDK) | `mcp_server.exe` |
| 数据源 | serbox 设备表 / 直连 host:3333 / 录制 .ndjson / **契约 JSONL** | `--export` 导出目录 |
| 工具 | `list_devices` / `read_frames` / `query_events` / `export_context` + prompt `serbox-expert` | `list_sessions` / `query_events` / `query_frames` / `get_signal_series` / `export_session` |

30 秒注册:`iotprobe-mcp ai-setup zcode`(或 trae/cursor/claude)→ stdout 打印即粘贴的配置片段。
实测(契约 JSONL 喂 ai-gate):1169 帧全解析 → 3 事件(协议异常码/请求无响应/间隔异常)→ 证据帧号可直接回跳 GUI。
对 AI 说:「读回放文件 X,列出事件,重点 fault,引用证据帧号,导出上下文给我」。

## G2 三场景验收清单

PH-2 功能面收齐后的出货验收手跑清单在 **[docs/G2-acceptance.md](docs/G2-acceptance.md)**:
S1 现场排故(CAN+485 双源/规则/录制/证据包)、S2 产线抽测(发送面板,FR-4.9 序列待补)、
S3 数据喂 AI(MCP 五工具)。含零硬件离线预演路径与 2026-11 实测记录。

## Roadmap(对齐主 spec 收敛路径)

- ~~模型对齐冻结契约 + JSONL 导出~~ ✅(ADR-0007,34 测试含 schema 符合性)
- ~~Modbus 6 字节序 + 枚举表~~ ✅ / ~~FR-4.2 聚合视图~~ ✅
- ~~NDJSON 契约流接入(live.rs)~~ ✅(并行会话交付,含丢帧检测;修复其上电单调时基 bug)
- ~~大类解析补缺~~ ✅:Modbus ASCII、MQTT 5.0 属性、SG_MUL_VAL_、GenMsgCycleTime→聚合比对、TCP/UDP 私有 DSL、HTTP 简析(58 测试)
- ~~rules-pack 最小版~~ ✅ / ~~MCP server~~ ✅ / ~~证据包导出~~ ✅ (验收手跑清单见 [docs/G2-acceptance.md](docs/G2-acceptance.md))
- ~~IEC 60870-5-104 报文级解析(P0-A)~~ ✅ / ~~J1939 TP.BAM 多帧重组(FR-3.4)~~ ✅(2026-11,含真实抓包回归:测试语料库 `../test-corpus/`)
- ~~104 点表 + 配置编辑器(MVP ②)~~ ✅(2026-11:map104 模块 + 编辑器窗口,e2e map104_e2e)
- ~~P0-C 拓扑视图(电池簇/PCS/电表卡片 + 异常高亮)~~ ✅(2026-11:topology.rs 纯函数评估 + GUI 卡片 Tab + 零配置自动生成;e2e 拓扑回测×2;多协议回测矩阵 run_matrix.py 10/10 PASS)
- ~~rules 热加载(FR-3.7)~~ ✅(2026-11:reload_rules 按包名热替换 + 事件页「重跑规则」按钮;单测 + 真实 modbus 日志 e2e 回测)
- ~~live 采集接线(serial/USB-CAN 设备侧,FR-S1)~~ ✅(2026-11-20:六家硬件后端统一管线 ZLG/VCI新老/SLCAN/PEAK/Kvaser/GCAN,ADR-0010/0014;发送面板 hub 全硬件源启用;真机 bench 见 docs/G2-acceptance.md S1-H)
- ~~变化率规则(滑动窗口)~~ ✅(2026-11:on_rate 窗口 Δ值/Δ秒 + 冷却防抖;单测 + 真实日志阈值边界 e2e)
- ~~真实世界抓包回归~~ ✅(2026-11:`test-corpus/08-real-captures/` 公开抓包入矩阵;抓出并修复 MQTT SUBACK 越界 panic、S7/TPKT 被 MQTT 误判两个真 bug;2026-11-14 扩 DNP3 七份(含 198 帧坏帧负样本)、CAN FD ASC ×2、BLF ×6、MQTT 短会话 ×3、104 遥控/总召唤生成器样本;新暴露缺口 B1-B5 记在 08 README)
- ~~08 缺口 B1–B5 闭环~~ ✅(2026-11-15:**DNP3 解析器**落地(链路 CRC 定界 + 应用功能/对象组,7 份全识别,
  part1 93 帧 / malformed 197 帧 + 坏帧事件);**单向 104 + 控制 ASDU 45/46/48/100/102**(threat 3422 帧/3936 信号);
  **损坏 pcap 宽松重同步愈合**(mqtt_redhat 写盘器 8B 垫字节,全文件恰好走完才接受,19 记录/20 帧);
  **ASC CANFD 行 + BLF 摄入器**(自研 inflate:RFC 1950/1951 三种块型 + Adler-32;LOG 容器/对象流/
  经典 CAN/FD/FD64/错误帧,#1905 截断补零,6 份全出帧);**XCP 私有封装明确拒识**。矩阵 35/35 PASS)
- 信号 schema 冻结(T-0.3)
- 待真实数据:G1 基线(SavvyCAN 逐信号比对)
