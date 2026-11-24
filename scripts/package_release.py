# -*- coding: utf-8 -*-
"""IoTProbe Windows 发布包打包脚本(双版本)。

- clean(干净版):运行时所需 —— 主程序/桥接/各家运行时 DLL/协议库/示例报文/使用说明。
- full(全带版):clean 之上再加 canlib 全部原料 —— 未接入厂商(IXXAT/来可)运行时 DLL、
  各家 SDK 头文件与库、PEAK 全套(Samples/NuGet/ARM64)、厂商手册文档、来可内核驱动。
  原始压缩包与安装器解包树(可再生的重复内容)仍不进包。

产物: dist/IoTProbe-v{VERSION}-win64-{clean|full}-{日期}.zip

用法:
  python scripts/package_release.py --variant clean   # 只打干净版
  python scripts/package_release.py --variant full    # 只打全带版
  python scripts/package_release.py --variant both    # 两个都打
前置构建:
  cargo build --release -p iotprobe
  cargo build --release --target i686-pc-windows-msvc -p vcibridge   # 32 位老 VCI 桥接
"""
import argparse
import re
import shutil
import sys
import zipfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # iot-probe/
VERSION = "0.1.0"
CANLIB_SRC = Path("D:/dev/tools/canlib")       # 硬件库原料库(开发机路径)

# 运行时 DLL(两个版本都带;位数按目录区分)
CANLIB_RUNTIME = [
    ("gcan", "gcan"),                     # GCAN 全套(ECanVci + CHUSBDLL,小)
    ("peak/x64", "peak/x64"),             # PEAK 64 位运行时
    ("peak/x86", "peak/x86"),             # PEAK 32 位(32 位程序备用)
    ("kvaser/x64", "kvaser/x64"),         # Kvaser 64 位 canlib32.dll(PE=x64,免装驱动即可加载)
    ("kvaser/x86", "kvaser/x86"),         # Kvaser 32 位
    ("cxcan/sdk", "cxcan/sdk"),           # 创芯新 SDK(x64 免桥接 + win32)
    ("zlg/zlgcan_x64", "zlg/zlgcan_x64"), # ZLG 64 位运行时(含 kerneldlls)
    ("zlg/zlgcan_x86", "zlg/zlgcan_x86"), # ZLG 32 位运行时
    ("zlg/zlgcan License.txt", "zlg/zlgcan License.txt"),
]
# 全带版追加:未接入厂商运行时 + SDK/头文件/文档/驱动
CANLIB_FULL_EXTRA = [
    ("peak", "peak"),                     # PEAK 全套(Samples/NuGet/ARM64/Include)
    ("kvaser/sdk", "kvaser/sdk"),         # Kvaser 头文件(canlib.h)
    ("kvaser/lib", "kvaser/lib"),         # Kvaser 链接库
    ("kvaser/include", "kvaser/include"),
    ("ixxat/x64", "ixxat/x64"),           # IXXAT vcinpl2/vcinpl(待接入)
    ("ixxat/x86", "ixxat/x86"),
    ("ixxat/sdk", "ixxat/sdk"),           # GUID 头
    ("ixxat/docs", "ixxat/docs"),         # 设计指南/安装手册 PDF
    ("laike/driver", "laike/driver"),     # 来可内核驱动 lk_usbcan.sys
    ("laike/x64", "laike/x64"),           # 来可 CanCmd.dll(待接入)
    ("laike/x86", "laike/x86"),
    ("laike/include", "laike/include"),
]

README_TXT = """# IoTProbe v{version}({arch})发布包 —— {variant_title}

## 快速开始(30 秒)
1. 解压到任意目录,双击 `iotprobe.exe` —— 启动即自动加载 `samples/` 示例报文,直接看到解析/曲线/事件/聚合效果
2. 分析自己的日志:顶栏「打开文件」(.asc / .log / .candump / .pcap / .pcapng / .blf / .ndjson)
3. 所有配置在顶栏「配置中心」一页:按功能分卡片,每张卡片上半是**当前生效状态**,下半是操作
   (数据源 / 协议解析 / 规则引擎 / 设备模拟器 / 实时接入 / 发送 / 界面与诊断);改完点「✔ 应用并重新加载」

## 目录说明
| 路径 | 用途 |
|---|---|
| `iotprobe.exe` | 主程序(64 位) |
| `vci-bridge.exe` | 32 位老 VCI DLL 桥接器(检测到位数不匹配时自动调用,无需手动运行) |
| `iotprobe-mcp.exe` | ai-gate MCP server:AI 客户端(ZCode/Cursor/Claude…)接入总线能力的统一入口;`iotprobe-mcp ai-setup zcode` 打印即贴配置 |
| `batch_runner.exe` | 批量回归 CLI("日志的 CI"):目录扫描→逐文件解析+规则→PASS/FAIL/WARN 汇总 HTML;GUI 体检卡可一键调用 |
| `ControlCAN.dll` | 创芯/USBCAN 兼容卡 SDK(32 位,供桥接用;放主程序目录) |
| `canlib/` | CAN 硬件库:{canlib_desc} |
| `protocols/` | DBC 协议库:把 .dbc 放进此目录重启即可识别(已内置 6 份常用协议) |
| `samples/` | 示例报文与配置(Modbus RTU/自定义 485/candump/Vector ASC/pcap/未知协议 + 规则包) |
| `IoTProbe使用指南.txt` | 完整使用说明(与程序内置一致;删除后下次启动重新生成) |
| `MCP使用教程.md` | AI 客户端接入教程(ai-gate / 离线 JSONL 双 server;配置中心「数据喂AI」场景一键打开) |
| `点位表格式与AI转换指南.md` | 厂商 Excel/协议文档→模拟器点位表 YAML 的格式规范+转换提示词(「模拟联调」场景一键打开) |

## 实时硬件接入(可选)
- **ZLG USBCANFD-200U**:装厂商驱动后,「配置中心 → 实时接入」选「ZLG USBCANFD」(canlib/zlgcan.dll 已随包,含 kerneldlls)
- **创芯 CANalyst-II / USBCAN 系**:32 位老 DLL 经 vci-bridge.exe 桥接(已随包);canlib/cxcan/sdk/x64/ControlCAN.dll 为新 SDK,64 位程序免桥接(设备 USB 驱动需用厂商安装器,未随包)
- **PEAK PCAN-Basic**:选「CAN卡·PEAK」(canlib/peak/x64/PCANBasic.dll 已随包;支持 CAN FD 勾选;PCAN 设备驱动需装 PEAK Drivers)
- **Kvaser CANlib**:canlib/kvaser/x64/canlib32.dll 已随包(64 位免装驱动加载 DLL);用真机/Virtual CAN 需装 Kvaser Drivers for Windows
- **GCAN 广成**:选「CAN卡·GCAN」,DeviceType 按厂商手册填数字(例程 16;canlib/gcan/ 全套已随包)
- **SLCAN(CANable 等)**:选「CAN卡·SLCAN」,串口直连,无需 DLL
- IXXAT / 来可:DLL 与资料在 canlib/(全带版),适配器待接入(见 canlib/README.md)
- 以上均默认**只听模式**;发送面板默认锁定,显式解锁后才可发帧(FR-10.4);PEAK/Kvaser/GCAN 未经真机验证,遇到问题先看状态栏与 stderr

## 已知边界(v0.1 诚实声明)
- 大文件字段树预算 30 万帧;超限通道详情页点击时才解码
- 无时间戳日志时间轴不可用(界面会提示)
- Modbus RTU 定界依赖 CRC/方向/记录边界;TCP 重组假设无乱序洪泛
- 完整说明见 `IoTProbe使用指南.txt`
"""


def guide_text() -> str:
    """从 main.rs 提取内置 GUIDE 常量,保证包内指南与程序生成的一致。"""
    src = (ROOT / "crates/app/src/main.rs").read_text(encoding="utf-8")
    m = re.search(r'const GUIDE: &str = r#"(.*?)"#;', src, re.S)
    if not m:
        sys.exit("未能从 main.rs 提取 GUIDE 常量")
    return m.group(1)


def copy_canlib(cl: Path, variant: str) -> None:
    cl.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CANLIB_SRC / "ControlCAN.dll", cl / "ControlCAN.dll")
    shutil.copy2(CANLIB_SRC / "README.md", cl / "README.md")
    entries = list(CANLIB_RUNTIME)
    if variant == "full":
        entries += CANLIB_FULL_EXTRA
    for src_rel, dst_rel in entries:
        src = CANLIB_SRC / src_rel
        if not src.exists():
            print(f"   跳过(原料缺失): {src_rel}")
            continue
        dst = cl / dst_rel
        if src.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        else:
            # 干净版排除 linux 目录;全带版保留(原料完整)
            ignore = None if variant == "full" else shutil.ignore_patterns("linux32", "linux64")
            shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore)


def package(variant: str, out_dir: Path, skip_zip: bool) -> None:
    exe = ROOT / "target/release/iotprobe.exe"
    bridge = ROOT / "target/i686-pc-windows-msvc/release/vci-bridge.exe"
    mcp = ROOT / "target/release/iotprobe-mcp.exe"
    batch = ROOT / "target/release/batch_runner.exe"
    missing = [str(p) for p in (exe, bridge, mcp, batch) if not p.exists()]
    if missing:
        sys.exit("缺少构建产物: " + ", ".join(missing) + "\n先执行: cargo build --release -p iotprobe -p iotprobe-core && "
                 "cargo build --release --target i686-pc-windows-msvc -p vcibridge\n"
                 "(iotprobe-mcp = ai-gate MCP server;batch_runner = 批量回归 CLI)")

    suffix = "clean" if variant == "clean" else "full"
    name = f"IoTProbe-v{VERSION}-win64-{suffix}"
    stage = out_dir / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    print(f"== 组装[{variant}] {stage}")

    # ---- 主程序与桥接 + CLI 工具(MCP/批量回归) ----
    shutil.copy2(exe, stage / "iotprobe.exe")
    shutil.copy2(bridge, stage / "vci-bridge.exe")
    shutil.copy2(mcp, stage / "iotprobe-mcp.exe")
    shutil.copy2(batch, stage / "batch_runner.exe")

    # ---- canlib:干净版=运行时;全带版=运行时+全部原料 ----
    copy_canlib(stage / "canlib", variant)

    # ---- 协议库(exe 同级 protocols/,启动播种即可用) ----
    prot = stage / "protocols"
    prot.mkdir()
    for f in sorted((ROOT / "dbc").glob("*.dbc")):
        shutil.copy2(f, prot / f.name)
    print(f"   protocols/: {len(list(prot.glob('*.dbc')))} 个 DBC")

    # ---- 示例报文(启动即演示) ----
    shutil.copytree(ROOT / "samples", stage / "samples")

    # ---- 使用说明:内置指南 + MCP 教程 + 发布包 README ----
    (stage / "IoTProbe使用指南.txt").write_text(guide_text(), encoding="utf-8")
    for doc in ("MCP使用教程.md", "点位表格式与AI转换指南.md"):
        src = ROOT / "docs" / doc
        if src.exists():
            shutil.copy2(src, stage / doc)
    if variant == "clean":
        canlib_desc = "zlgcan.dll(+kerneldlls)、ControlCAN(32位桥接)、cxcan/sdk(x64 新 SDK)、gcan、peak/x64+x86、kvaser/x64+x86"
        variant_title = "干净版(运行时)"
    else:
        canlib_desc = "干净版全部内容 + IXXAT/来可运行时 DLL(待接入)+ 各家 SDK 头文件与库 + PEAK 全套 + 厂商手册 + 来可内核驱动"
        variant_title = "全带版(全部原料)"
    (stage / "使用说明.md").write_text(
        README_TXT.format(version=VERSION, arch="win64", variant_title=variant_title, canlib_desc=canlib_desc),
        encoding="utf-8")

    n_files = sum(1 for _ in stage.rglob("*") if _.is_file())
    size_mb = sum(f.stat().st_size for f in stage.rglob("*") if f.is_file()) / 1e6
    print(f"   共 {n_files} 个文件, {size_mb:.1f} MB")

    if skip_zip:
        print(f"== [{variant}] --skip-zip:未打压缩包")
        return
    zpath = out_dir / f"{name}-{date.today():%Y%m%d}.zip"
    if zpath.exists():
        zpath.unlink()
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for f in sorted(stage.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(stage.parent))
    print(f"== 完成[{variant}]: {zpath}({zpath.stat().st_size / 1e6:.1f} MB)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist"))
    ap.add_argument("--variant", choices=["clean", "full", "both"], default="clean",
                    help="clean=运行时精简;full=全部原料;both=两个都打")
    ap.add_argument("--skip-zip", action="store_true")
    args = ap.parse_args()
    out_dir = Path(args.out)
    variants = ["clean", "full"] if args.variant == "both" else [args.variant]
    for v in variants:
        package(v, out_dir, args.skip_zip)


if __name__ == "__main__":
    main()
