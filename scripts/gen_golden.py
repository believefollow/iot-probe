#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成解析正确性基线(任务卡 C3):用 cantools(独立参照实现)对语料 ASC 逐帧解码,
输出 test-corpus/golden/<名>.expected.jsonl —— 每帧一行 {i, id, ext, signals}。
Rust 侧 crates/core/tests/golden_decode.rs 逐信号比对(浮点 1e-6 相对误差)。
参照实现只读:本脚本不改任何日志/DBC;预期值人工可复核(cantools 是 cantools 的实现,不是我们的)。

用法: python scripts/gen_golden.py [test-corpus 目录](默认 ../test-corpus)
依赖: pip install cantools
"""
import json
import re
import sys
from pathlib import Path

try:
    import cantools
except ImportError:
    sys.exit("需要 cantools: pip install cantools")

# (log 相对路径, dbc 相对路径, 输出名)
PAIRS = [
    ("jxdcdc.asc", "JXDCDC_CAN通讯协议_V0.2 20261008.dbc", "jxdcdc"),
    ("04-gb27930/test_27930.asc", "04-gb27930/gbt27930.dbc", "gb27930"),
]

HEX_ID = re.compile(r"^[0-9A-Fa-f]{1,8}x?$")


def parse_asc_line(line: str):
    """容忍 CANoe/简易导出:[t, 通道, ID(Rx/Tx 前), Rx/Tx, d, len, 字节...]。
    定位 'd' 数据标记,其前是方向,再前是 ID。返回 (t, id, ext, data) 或 None。"""
    toks = line.split()
    if len(toks) < 6:
        return None
    try:
        t = float(toks[0])
    except ValueError:
        return None
    p = next((i for i in range(1, len(toks)) if toks[i].lower() == "d"), None)
    if p is None or p < 2:
        return None
    id_tok = toks[p - 2]
    if not HEX_ID.match(id_tok):
        return None
    rest = toks[p + 1:]
    try:
        n = int(rest[0])
    except (ValueError, IndexError):
        return None
    data = []
    for b in rest[1:1 + n]:
        try:
            data.append(int(b, 16))
        except ValueError:
            return None
    if len(data) != n:
        return None
    ext = id_tok.lower().endswith("x")
    cid = int(id_tok.rstrip("xX"), 16)
    return (t, cid, ext, bytes(data))


def main():
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent.parent / "test-corpus"
    out_dir = corpus / "golden"
    out_dir.mkdir(exist_ok=True)
    total_msgs = 0
    for log_rel, dbc_rel, name in PAIRS:
        log_p, dbc_p = corpus / log_rel, corpus / dbc_rel
        if not log_p.exists() or not dbc_p.exists():
            print(f"[skip] {log_rel} 或 {dbc_rel} 不存在")
            continue
        try:
            raw = dbc_p.read_bytes()
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("gbk", errors="replace")  # 国内厂商 DBC 注释常见 GBK
        # 损坏注释行剥离(CM_ 只影响可读性,不影响信号定义;gb27930 官方样例有混编码坏行)
        text = "\n".join(l for l in text.splitlines() if not l.startswith("CM_"))
        db = cantools.database.load_string(text, "dbc", strict=False)
        known = {m.frame_id for m in db.messages}
        n_dec, n_skip = 0, 0
        with open(log_p, "r", encoding="utf-8", errors="replace") as f, open(out_dir / f"{name}.expected.jsonl", "w", encoding="utf-8") as out:
            i = 0  # CAN 帧序号(与 Rust 侧过滤 Can/CanFd 后一致)
            for line in f:
                parsed = parse_asc_line(line)
                if parsed is None:
                    continue
                _, cid, ext, data = parsed
                i += 1
                if cid not in known:
                    n_skip += 1
                    continue
                try:
                    msg = db.get_message_by_frame_id(cid)
                    # 本版 cantools 无 allow_truncated:残帧由异常捕获跳过(如实计入 skip)
                    sigs = msg.decode(data, decode_choices=False)
                except Exception:
                    n_skip += 1
                    continue
                out.write(json.dumps({"i": i, "id": cid, "ext": ext,
                                      "signals": {k: float(v) for k, v in sigs.items() if isinstance(v, (int, float))}},
                                     ensure_ascii=False) + "\n")
                n_dec += 1
        print(f"[ok] {name}: {n_dec} 帧解码, {n_skip} 帧跳过(不在 DBC/解不了) → {out_dir / (name + '.expected.jsonl')}")
        total_msgs += n_dec
    print(f"共 {total_msgs} 帧期望值")


if __name__ == "__main__":
    main()
