# ADR-0014 CAN 硬件后端第二批（PEAK / Kvaser / GCAN + 创芯新 SDK 免桥接）

状态：已采纳（2026-11-20）　关联：ADR-0010（ZLG）/ ADR-0008 / FR-S1 / FR-10.4

## 背景

canlib 原料库在 2026-11-19/20 补齐了 PEAK（x64/x86/ARM64 PCANBasic.dll）、Kvaser（SDK+安装器）、GCAN
（ECanVci 双位 + CHUSBDLL）、创芯新 SDK（cxcan，含 **x64** ControlCAN.dll）四家原料；此前实时接入
只有 ZLG / 老版 VCI（32 位必经桥接）/ SLCAN。用户要求"依次整理适配"。

## 决策

1. **模式零新意**（这是特性）：三家新后端全部走既有骨架 —— `CanBackend::poll()` 产契约 NDJSON →
   `CanHwSource` → `live::pump`；发送 `TxHub::pop_due`；结构体/常量以随包官方头文件为准
   （PCANBasic.h 2025-10-24 版 / canlib.h 5.53 / ECanVci.h），并附尺寸静态断言。
2. **厂商定位统一走 `find_vendor_dll_checked`**（canhw.rs 新基建）：厂商分目录候选（`peak/x64/`、
   `cxcan/sdk/x64/`、`gcan/win64/`…）按 PE machine 选位数一致的候选；裸文件名候选走系统搜索链
   （随驱动安装）；只有位数不符的副本时报"装驱动"指引。
3. **VCI 多候选**：老版根目录 32 位 → 创芯新 SDK x64（**免桥接直连**）→ GCAN 的 VCI_ 前缀版；
   位数一致者优先，否则沿用 vci-bridge。`vci_device_type` 支持纯数字直传（GCAN 等厂商 DeviceType）。
4. **GCAN 依赖预载**：libloading 的 LoadLibraryExW(flags=0) 不搜 DLL 自身目录，加载 ECanVci[64].dll
   前先按全路径预载同目录 CHUSBDLL[64].dll（依赖按模块名命中已载入副本）。
5. **诚实边界**（FR-10.4/ADR-5 延续）：
   - 三家均**未经真机 bench**：UI 表单、错误信息、README 均如实标注；FD 位时序取官方推荐缺省
     （PEAK 数据段 2M@80%、Kvaser canFD_BITRATE_2M_80P），待硬件核对。
   - Kvaser 时戳经 `canIoctl(SET_TIMER_SCALE)` 显式设 10µs/格（默认 1ms 粒度不适合抖动分析）。
   - GCAN 的 CAN_OBJ.TimeStamp 口径文档未标注 → 一律软件时戳 `ts_src=sw`，bench 确认后再升级 hw。
   - Kvaser SDK 包内 canlib32.dll 为 32 位；64 位进程必须装驱动（System32 副本），错误信息直接说清。
6. **发送面板 hub 补齐**：`connect_live` 此前只给 ZLG 建 TxHub，VCI 源的发送面板实际拿不到队列 ——
   本轮起全部 CAN 硬件源（Zlg + CanHw 全部 vendor）统一建 hub，锁定默认不变。
7. UI：源类型「串口 / CAN 卡」组新增 CAN卡·PEAK / Kvaser / GCAN（kind 11/12/13），
   通用行复用（通道号/波特率/只听/FD 勾选 + DLL 状态行绿/灰/红）。

## 后果

- 实时接入硬件面从 3 家扩到 6 家（ZLG/VCI/SLCAN/PEAK/Kvaser/GCAN），均可进录制/回放/解析/曲线/规则全管线。
- canlib/README.md 成为厂商注册表（PE 实测位数 + API 族 + 接入状态 + 待接入清单）。
- 新增单测 12 项（波特率表/结构体尺寸/时戳公式/哨兵常量/候选搜索），无硬件即可回归。
- 发布包新增 cxcan\sdk（双位）、kvaser\sdk；peak\x64、gcan 全套原有。
- 待办：真机 bench 六家（docs/G2-acceptance.md **S1-H 逐家清单**：核对收发/时戳口径/FD 位时序/只听生效），通过后在 canlib/README.md 注册表标"已 bench"；IXXAT vcinpl2（SDK 已解包）与来可 CanCmd 另立 ADR 适配。
