# ADR-0010 live 采集适配层:ZLG USBCANFD 动态加载 + 模拟源

状态:已采纳(2026-11-10,Q3/Q4 已确认) 关联:Q3/ZLG USBCAN-FD2 选型、Q4 总线配比、FR-10.4

## 背景

Q3 选定周立功 USBCAN-FD2(设备类型串 USBCANFD-200U);Q4 确认 live 顺序 CAN FD(P0)→
Modbus 485(P1,经 TCP 串口服务器)→ RS232(P2);EtherCAT 维持后置。风险备注 #2 要求
适配器抽象,后续换 TCP 网关不改上层;#3 要求离线/实时共用同一时基对齐代码。

## 决策

1. **适配层 = 契约 NDJSON 字节流**。ZLG 适配器把硬件帧转成 frame.schema.json 形态的
   NDJSON 行(实现 std::io::Read),接入 core 现有 live::Pipeline —— 录制(FR-S2)、
   回放、相对化、丢帧检测、解析/曲线/规则全部复用,零新增解析路径。
2. **动态加载 zlgcan.dll**(libloading,无链接期依赖):只调用五个长期稳定入口
   OpenDevice / CloseDevice / InitCAN / StartCAN / Receive(+ResetCAN 清理)。
   结构体布局按官方 zlgcan.h(ReceiveData 24B / ReceiveFDData 80B / ReceiveMsg 96B,
   含 static assert);FD 初始化配置以"常用字段前置 + 512B 零填充尾"传递,
   吸收版本差异;布局核对属 T-1.3 真机 bench 任务。
3. **硬件时戳**:ts_src = hw(ADR-5 L1);单位默认 0.1ms(ZLG 通用函数库文档),
   表单可切 10µs/1µs。真机核对后固化默认值。
4. **只听模式默认开启**(FR-10.4):mode=1(listen-only),防误发干扰现场;
   发送面板后置,届时走 FR-10.5 白名单。
5. **模拟 CAN 总线源**(SimSource):与 motor.dbc 同构的速度/扭矩/温度曲线 +
   心跳 + 64B FD 扩展帧,墙钟实时推进 —— 无硬件完成全管线开发/UI 验证/回归。
6. 依赖:app crate 新增 libloading(FFI 动态加载,~零体积);core 保持不变。

## 后果

- 真机 bench 任务(T-1.3):核对结构体布局、时戳单位、波特率配置口径;
  若 ZLG 驱动版本结构有出入,只需调整本适配层,上层零改动。
- Modbus 485(live 二期)= 新增一个 SourceKind + 适配器(串口服务器 TCP→RTU 帧),
  沿用同一管线。
- SimSource 保留为演示与 CI 回归数据源。
