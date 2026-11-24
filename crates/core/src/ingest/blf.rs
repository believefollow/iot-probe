//! BLF(Vector Binary Logging Format)摄入器 v1:python-can / CANoe / binlog.dll 写出的 CAN 日志。
//! 布局与 python-can `can/io/blf.py` 对齐:
//!   文件头 144B:魔法数 "LOGG",头部总长 u32@4;起始时刻 SYSTEMTIME(8×u16)@40。
//!   其后是顶层对象流,每对象 = 基础头 16B(sig"LOBJ"/头大小u16/版本u16/对象大小u32/类型u32),
//!   对象后按 4 字节对齐补垫(对象大小 % 4):
//!     类型 10 = LOG 容器:压缩方法 u16@16(0=裸 / 2=zlib)+ 解压后大小 u32@24 + 内容@32..;
//!       容器内容拼接后仍是对象流,对象可跨容器。
//!     类型 1/86 = 经典 CAN(成员@32:通道u16/标志u8/DLCu8/IDu32/数据8B)
//!     类型 73 = CAN 错误帧(成员@32:…DLC u8@42/ID u32@48/数据8B@56)
//!     类型 100 = CAN FD(成员 80B:FD标志u8@44/有效字节u8@45/数据64B@48)
//!     类型 101 = CAN FD 64(ext_data_offset=0 时按对象大小截断数据并补零——#1905 语义)
//!     正确性锚点:issue_1905.blf(真实 Vector 写入,zlib 容器,22 个 FD64 对象)专测通过;
//!     语料 test_CanFdMessage64.blf 为合成 dummy 夹具(纯模式字节),其载荷字段语义不可自证
//!     (实测 id=0x15555555/0B 数据)——只作结构回归锁定,不作语义 golden
//!   对象头 v1:标志 u32@16(bit0=10µs 单位,其余=ns 单位)+ 时间戳 u64@24;v2 头 24B(成员@40)。
//! 未知对象类型跳过并计数;损坏容器流不猜测、明确报错。

use super::rec;
use crate::model::{Dir, Proto, Record};
use std::collections::HashMap;

const OBJ_CONTAINER: u32 = 10;
const OBJ_CAN: u32 = 1;
const OBJ_CAN_ERR_EXT: u32 = 73;
const OBJ_CAN2: u32 = 86;
const OBJ_CAN_FD: u32 = 100;
const OBJ_CAN_FD64: u32 = 101;
/// 对象头标志 bit0:时间戳以 10µs 为单位;其余按 ns
const TIME_TEN_MICS: u32 = 1;
const FLAG_EXT_ID: u32 = 0x8000_0000;
const FLAG_TX: u8 = 0x1; // 经典 CAN / FD100 标志 bit0 = 发送方向
const FLAG_REMOTE: u8 = 0x80;
/// FD64 的 fd_flags 位定义
const FD64_REMOTE: u32 = 0x0010;

fn u16le(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn u64le(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3], d[o + 4], d[o + 5], d[o + 6], d[o + 7]])
}

/// SYSTEMTIME(8×u16:年月星期日时分秒毫秒)→ Unix 纳秒;年份不合理按相对 0 处理
fn systemtime_to_ns(d: &[u8]) -> u64 {
    let (y, mo, _dow, da, h, mi, s, ms) = (
        u16le(d, 0) as i64,
        u16le(d, 2) as u32,
        u16le(d, 4),
        u16le(d, 6) as u32,
        u16le(d, 8) as u64,
        u16le(d, 10) as u64,
        u16le(d, 12) as u64,
        u16le(d, 14) as u64,
    );
    if !(1990..=2999).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return 0;
    }
    // days_from_civil(Hinnant):公历日期 → 自 1970-01-01 的天数
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = ((mo + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + da as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    ((days as u64) * 86_400 + h * 3600 + mi * 60 + s) * 1_000_000_000 + ms * 1_000_000
}

/// 读取 BLF;返回记录 / 通道标签 / 历元 / 警告
pub fn read(
    data: &[u8],
    name: &str,
) -> Result<(Vec<Record>, HashMap<u16, String>, Option<u64>, Vec<String>), String> {
    let _ = name;
    if data.len() < 144 || &data[..4] != b"LOGG" {
        return Err("不是 BLF 文件(缺少 LOGG 头)".into());
    }
    let hdr_size = u32le(data, 4) as usize;
    if !(64..=4096).contains(&hdr_size) || hdr_size > data.len() {
        return Err(format!("BLF 文件头长度异常: {hdr_size}"));
    }
    let start_ns = systemtime_to_ns(&data[40..56]);
    let epoch_ns = (start_ns > 1_000_000_000_000).then_some(start_ns);
    let mut records = Vec::new();
    let mut labels = HashMap::new();
    let mut warns = Vec::new();
    let mut skipped = 0usize;
    let mut containers = 0usize;
    // 容器内容拼接缓冲:对象可跨容器
    let mut buf: Vec<u8> = Vec::new();
    let mut off = hdr_size;
    while off + 16 <= data.len() {
        if &data[off..off + 4] != b"LOBJ" {
            return Err(format!("BLF 顶层对象流在 {off:#x} 处失去 LOBJ 签名"));
        }
        let obj_size = u32le(data, off + 8) as usize;
        let obj_type = u32le(data, off + 12);
        if obj_size < 16 || off + obj_size > data.len() {
            return Err(format!("BLF 容器长度异常 @{off:#x}: size={obj_size}"));
        }
        if obj_type == OBJ_CONTAINER {
            let method = u16le(data, off + 16) as u32;
            let content = &data[off + 32..off + obj_size];
            match method {
                0 => buf.extend_from_slice(content),
                2 => match super::inflate::zlib_decompress(content) {
                    Ok(dec) => buf.extend_from_slice(&dec),
                    Err(e) => warns.push(format!("BLF 容器 @{off:#x} zlib 解压失败,已跳过: {e}")),
                },
                m => warns.push(format!("BLF 容器 @{off:#x} 未知压缩方法 {m},已跳过")),
            }
            containers += 1;
        } else {
            skipped += 1; // 顶层非容器对象(罕见),跳过
        }
        off += obj_size + obj_size % 4; // 4 字节对齐补垫
    }
    if containers == 0 {
        return Err("BLF 中没有 LOG 容器".into());
    }
    let consumed = parse_objects(&buf, start_ns, &mut records, &mut labels, &mut skipped, &mut warns);
    if consumed < buf.len() {
        warns.push(format!("BLF 对象流尾部残留 {} 字节(截断/损坏),已丢弃", buf.len() - consumed));
    }
    if skipped > 0 {
        warns.push(format!("BLF 跳过 {skipped} 个非 CAN 报文对象"));
    }
    Ok((records, labels, epoch_ns, warns))
}

/// 解析容器拼接出的对象流,返回已消费字节数。
/// 残尾(不足一个完整对象)不计入消费 —— 由调用方作为截断告警。
fn parse_objects(
    buf: &[u8],
    start_ns: u64,
    out: &mut Vec<Record>,
    labels: &mut HashMap<u16, String>,
    skipped: &mut usize,
    warns: &mut Vec<String>,
) -> usize {
    let mut pos = 0usize;
    while pos + 16 <= buf.len() {
        // 8 字节窗口内找 LOBJ(容忍对象间少量填充);窗口耗尽则视为损坏
        let found = (pos..buf.len().min(pos + 8)).find(|&p| p + 4 <= buf.len() && &buf[p..p + 4] == b"LOBJ");
        let Some(p) = found else {
            warns.push(format!("BLF 对象流 @{pos:#x} 处找不到 LOBJ 签名,停止解析"));
            return pos;
        };
        pos = p;
        let hver = u16le(buf, pos + 6) as usize;
        let obj_size = u32le(buf, pos + 8) as usize;
        let obj_type = u32le(buf, pos + 12);
        if obj_size < 32 || pos + obj_size > buf.len() {
            warns.push(format!("BLF 对象长度异常 @{pos:#x}: size={obj_size},停止解析"));
            return pos;
        }
        // 对象头 v1:标志 u32@16 + 时间戳 u64@24(成员@32);v2 头 24B(成员@40)
        let (flags, ts, member) = match hver {
            1 => (u32le(buf, pos + 16), u64le(buf, pos + 24), 32usize),
            2 => (u32le(buf, pos + 16), u64le(buf, pos + 24), 40usize),
            _ => {
                *skipped += 1;
                pos += obj_size;
                continue;
            }
        };
        let ts_ns = if flags == TIME_TEN_MICS { ts.saturating_mul(10_000) } else { ts };
        let t_ns = start_ns.saturating_add(ts_ns);
        let m = &buf[pos + member..pos + obj_size]; // 成员数据(相对成员起点寻址)
        match obj_type {
            OBJ_CAN | OBJ_CAN2 => push_classic(m, t_ns, out, labels),
            OBJ_CAN_ERR_EXT => push_err_ext(m, t_ns, out, labels),
            OBJ_CAN_FD => push_fd(m, t_ns, out, labels),
            OBJ_CAN_FD64 => push_fd64(m, obj_size - member, t_ns, out, labels),
            _ => *skipped += 1,
        }
        pos += obj_size;
    }
    pos
}

fn note_channel(ch: u16, labels: &mut HashMap<u16, String>) {
    labels.entry(ch).or_insert_with(|| format!("BLF ch{ch}"));
}

/// 经典 CAN(类型 1/86):通道u16/标志u8/DLCu8/IDu32/数据8B(相对成员起点)
fn push_classic(m: &[u8], t_ns: u64, out: &mut Vec<Record>, labels: &mut HashMap<u16, String>) {
    if m.len() < 16 {
        return;
    }
    let ch = u16le(m, 0);
    let flags = m[2];
    let dlc = m[3] as usize;
    let id = u32le(m, 4);
    let mut data = m[8..16].to_vec();
    data.truncate(dlc.min(8));
    if flags & FLAG_REMOTE != 0 {
        data.clear();
    }
    note_channel(ch, labels);
    let dir = if flags & FLAG_TX != 0 { Dir::Tx } else { Dir::Rx };
    let mut r = rec(t_ns, dir, Proto::Can, data);
    r.channel = ch;
    r.can_id = Some((id & 0x1FFF_FFFF) | (((id & FLAG_EXT_ID) != 0) as u32) << 31);
    out.push(r);
}

/// CAN 错误帧(类型 73):…DLC u8@10 / ID u32@16 / 数据 8B@24(相对成员起点)
fn push_err_ext(m: &[u8], t_ns: u64, out: &mut Vec<Record>, labels: &mut HashMap<u16, String>) {
    if m.len() < 32 {
        return;
    }
    let ch = u16le(m, 0);
    let dlc = m[10] as usize;
    let id = u32le(m, 16);
    let mut data = m[24..32].to_vec();
    data.truncate(dlc.min(8));
    note_channel(ch, labels);
    let mut r = rec(t_ns, Dir::Unknown, Proto::Can, data);
    r.channel = ch;
    r.can_id = Some(id & 0x1FFF_FFFF);
    out.push(r);
}

/// CAN FD(类型 100):通道u16/标志u8/DLCu8/IDu32/帧长u32/FD标志u8/有效字节u8/数据64B(相对成员起点)
fn push_fd(m: &[u8], t_ns: u64, out: &mut Vec<Record>, labels: &mut HashMap<u16, String>) {
    if m.len() < 80 {
        return;
    }
    let ch = u16le(m, 0);
    let flags = m[2];
    let id = u32le(m, 4);
    let valid = m[13] as usize;
    let mut data = m[16..80].to_vec();
    data.truncate(valid.min(64));
    if flags & FLAG_REMOTE != 0 {
        data.clear();
    }
    note_channel(ch, labels);
    let dir = if flags & FLAG_TX != 0 { Dir::Tx } else { Dir::Rx };
    let mut r = rec(t_ns, dir, Proto::CanFd, data);
    r.channel = ch;
    r.can_id = Some((id & 0x1FFF_FFFF) | (((id & FLAG_EXT_ID) != 0) as u32) << 31);
    out.push(r);
}

/// CAN FD 64(类型 101):成员 40B + 数据区;ext_data_offset=0 时按对象大小截断并补零(#1905)
fn push_fd64(
    m: &[u8],
    member_len: usize,
    t_ns: u64,
    out: &mut Vec<Record>,
    labels: &mut HashMap<u16, String>,
) {
    if m.len() < 40 {
        return;
    }
    let ch = m[0] as u16;
    let valid = m[2] as usize;
    let id = u32le(m, 4);
    let fd_flags = u32le(m, 12);
    let direction = u16le(m, 34);
    let ext = u32le(m, 36) as usize;
    // 有效数据区:ext_data_offset 为 0 时用对象大小兜底(CANoe/binlog.dll 行为)
    let avail = (if ext == 0 { member_len } else { ext }).saturating_sub(40);
    let want = valid.min(64);
    let take = want.min(avail);
    let mut data = m[40..40 + take].to_vec();
    data.resize(want, 0); // 截断处补零
    if fd_flags & FD64_REMOTE != 0 {
        data.clear();
    }
    note_channel(ch, labels);
    let dir = if direction != 0 { Dir::Tx } else { Dir::Rx };
    let mut r = rec(t_ns, dir, Proto::CanFd, data);
    r.channel = ch;
    r.can_id = Some((id & 0x1FFF_FFFF) | (((id & FLAG_EXT_ID) != 0) as u32) << 31);
    out.push(r);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实语料字节:test_CanMessage.blf(python-can 测试夹具,420B;经典 CAN ×2 + 全局标记对象)
    const TEST_CAN_MESSAGE: &[u8] = &[
        0x4c, 0x4f, 0x47, 0x47, 0x90, 0x00, 0x00, 0x00, 0xd4, 0x1a, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4c, 0x4f, 0x42, 0x4a, 0x10, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4c, 0x4f, 0x42, 0x4a, 0x20, 0x00, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x11, 0x11, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x11, 0x11, 0x22, 0x33, 0x44, 0x44, 0x44, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0x4c, 0x4f, 0x42, 0x4a, 0x20, 0x00, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x11, 0x11, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x11, 0x11, 0x22, 0x33, 0x44, 0x44, 0x44, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0x4c, 0x4f, 0x42, 0x4a, 0x10, 0x00, 0x01, 0x00, 0x94, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4c, 0x4f, 0x42, 0x4a, 0x20, 0x00, 0x01, 0x00, 0x38, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x08, 0x00,
        0x08, 0x00, 0x18, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x4c, 0x4f, 0x42, 0x4a, 0x20, 0x00, 0x01, 0x00,
        0x3c, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
    ];

    /// 真实语料字节:issue_1905.blf(python-can 测试夹具,524B;zlib 压缩容器 + 22 个 FD64 对象;
    /// 容器间 4 字节对齐补垫;valid_bytes=64 但只有 48 字节在对象内 → 截断补零回归)
    const ISSUE_1905: &[u8] = &[
        0x4c, 0x4f, 0x47, 0x47, 0x90, 0x00, 0x00, 0x00, 0xfc, 0x60, 0x4d, 0x00, 0x06, 0x09, 0x01, 0x00,
        0x0c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb4, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xe8, 0x07, 0x0c, 0x00, 0x02, 0x00, 0x1f, 0x00,
        0x0e, 0x00, 0x09, 0x00, 0x28, 0x00, 0xde, 0x00, 0xe8, 0x07, 0x0c, 0x00, 0x02, 0x00, 0x1f, 0x00,
        0x0e, 0x00, 0x0b, 0x00, 0x1c, 0x00, 0xec, 0x01, 0x88, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4c, 0x4f, 0x42, 0x4a, 0x10, 0x00, 0x01, 0x00, 0xf6, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0xda, 0xf3, 0xf1, 0x77, 0xf2, 0x52, 0x60, 0x60, 0x64, 0xa8, 0x60, 0x60, 0x60, 0x48, 0x05,
        0x62, 0x26, 0x06, 0x08, 0x58, 0xb1, 0xe5, 0xd6, 0x21, 0x10, 0xcd, 0xce, 0xef, 0xc0, 0xb0, 0x92,
        0x8d, 0x81, 0xc1, 0x01, 0xc4, 0x31, 0x60, 0xc0, 0x09, 0xfe, 0x93, 0x08, 0x7c, 0x70, 0xd8, 0x5b,
        0x90, 0x71, 0xef, 0x0d, 0xe3, 0x00, 0xd8, 0x2b, 0xf0, 0xfc, 0x89, 0x18, 0xf3, 0x00, 0xd8, 0xeb,
        0xa1, 0xf9, 0xca, 0x81, 0x65, 0x00, 0xec, 0x4d, 0xe8, 0xfb, 0x98, 0xc5, 0x3a, 0x00, 0xf6, 0x36,
        0x84, 0x7f, 0x9b, 0xc2, 0x36, 0x00, 0xf6, 0x2a, 0xec, 0x63, 0xd8, 0xcf, 0x3e, 0x00, 0xf6, 0x4e,
        0x08, 0x60, 0x7d, 0xc9, 0x31, 0x00, 0xf6, 0x4a, 0x48, 0x89, 0x0a, 0x73, 0x0d, 0x80, 0xbd, 0x3f,
        0xf4, 0x64, 0x6d, 0xb9, 0x07, 0xc0, 0x5e, 0x03, 0x06, 0x85, 0x74, 0x9e, 0x01, 0xb0, 0x37, 0xc3,
        0x46, 0x6d, 0x22, 0xef, 0x00, 0xd8, 0xfb, 0x42, 0xc2, 0x6a, 0x37, 0xdf, 0x00, 0xd8, 0x7b, 0xe0,
        0xad, 0xdd, 0x53, 0xfe, 0x01, 0xb0, 0x77, 0x01, 0x9f, 0x2b, 0xbf, 0xe0, 0x40, 0xd8, 0x5b, 0xee,
        0x63, 0x29, 0x34, 0x10, 0xf6, 0xfe, 0xf3, 0x4b, 0x16, 0x1e, 0x88, 0xf4, 0xcc, 0x1a, 0xd5, 0x2b,
        0x32, 0x10, 0xf5, 0x7e, 0x71, 0xe4, 0x76, 0xd1, 0x81, 0xc8, 0x47, 0xe1, 0x71, 0x0f, 0xc5, 0x06,
        0xc0, 0xde, 0x0f, 0x85, 0xd9, 0xdc, 0x12, 0x03, 0x11, 0xbf, 0x31, 0xf9, 0xa6, 0x92, 0x34, 0xb4,
        0x17, 0x00, 0x46, 0xf2, 0x94, 0x75, 0x00, 0x00, 0x4c, 0x4f, 0x42, 0x4a, 0x10, 0x00, 0x01, 0x00,
        0x5a, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xda, 0xf3, 0xf1, 0x77, 0xf2, 0x52, 0x60,
        0x60, 0x64, 0xb0, 0x60, 0x60, 0x60, 0x28, 0x06, 0x62, 0x26, 0x06, 0x08, 0xc8, 0x88, 0xc9, 0x37,
        0x95, 0x64, 0x40, 0x07, 0x1c, 0x40, 0x28, 0xc1, 0xf0, 0x82, 0x99, 0x81, 0xc1, 0x07, 0xaa, 0xcf,
        0x06, 0x45, 0x1f, 0x23, 0x0e, 0x7d, 0x3c, 0x40, 0x08, 0x01, 0x02, 0x40, 0x0c, 0x00, 0x49, 0xbd,
        0x08, 0x2d, 0x00, 0x00, 0x4c, 0x4f, 0x42, 0x4a, 0x10, 0x00, 0x01, 0x00, 0x28, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x78, 0xda, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn parses_real_classic_can_fixture() {
        let (recs, labels, epoch, warns) = read(TEST_CAN_MESSAGE, "test_CanMessage.blf").unwrap();
        assert_eq!(recs.len(), 2, "两条经典 CAN;警告 {warns:?}");
        assert!(warns.iter().any(|w| w.contains("非 CAN 报文对象")), "类型 115 应计入跳过");
        let r = &recs[0];
        assert_eq!(r.proto, Proto::Can);
        assert_eq!(r.channel, 0x1111);
        // CAN ID 按规范掩码到 29 位(python-can 同语义);哨兵 0x44444444 → 0x04444444
        assert_eq!(r.can_id.unwrap() & 0x1FFF_FFFF, 0x0444_4444);
        assert_eq!(r.can_id.unwrap() & 0x8000_0000, 0, "哨兵 ID 无扩展位");
        assert_eq!(r.data.as_ref(), &[0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]);
        assert_eq!(r.dir, Dir::Rx, "标志 0x22 无 Tx 位");
        // 时间戳:ns 单位(flag=2),起始 SYSTEMTIME 为零 → 相对纳秒
        assert_eq!(r.t_ns, 0x2222_2222_2222_2222);
        assert_eq!(epoch, None);
        assert!(labels.contains_key(&0x1111));
    }

    #[test]
    fn parses_compressed_fd64_fixture_with_padding() {
        let (recs, _labels, _epoch, warns) = read(ISSUE_1905, "issue_1905.blf").unwrap();
        assert_eq!(recs.len(), 22, "22 条 FD64;警告 {warns:?}");
        for r in recs.iter().take(3) {
            assert_eq!(r.proto, Proto::CanFd);
            assert_eq!(r.can_id.unwrap(), 1705, "FD64 对象 ID=0x6a9");
            assert_eq!(r.channel, 7);
            assert_eq!(r.dir, Dir::Rx, "direction=0");
        }
        // #1905:对象内只有 48 字节真实数据(valid_bytes=64)→ 48B 哨兵 ff + 后 16 字节补零
        let d = recs[0].data.as_ref();
        assert_eq!(d.len(), 64);
        assert!(d[..48].iter().all(|&b| b == 0xff));
        assert!(d[48..].iter().all(|&b| b == 0), "截断处补零");
        // 最后一条时间戳递增(ns 单位)
        assert!(recs[1].t_ns > recs[0].t_ns);
        // 压缩容器 + 两个全局标记对象 → 警告提及跳过
        assert!(warns.iter().any(|w| w.contains("非 CAN 报文对象")));
    }

    #[test]
    fn rejects_non_blf() {
        assert!(read(b"not a blf file at all", "x.blf").is_err());
        assert!(read(&[], "x.blf").is_err());
    }

    /// 构造一个最小 BLF:单容器(裸)包一个指定对象
    fn wrap(obj: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 144];
        v[..4].copy_from_slice(b"LOGG");
        v[4..8].copy_from_slice(&144u32.to_le_bytes());
        let csize = 32 + obj.len();
        v.extend_from_slice(b"LOBJ");
        v.extend_from_slice(&16u16.to_le_bytes()); // 头大小
        v.extend_from_slice(&1u16.to_le_bytes()); // 头版本
        v.extend_from_slice(&(csize as u32).to_le_bytes());
        v.extend_from_slice(&10u32.to_le_bytes()); // LOG 容器
        v.extend_from_slice(&0u16.to_le_bytes()); // 压缩方法 0
        v.extend_from_slice(&[0u8; 6]);
        v.extend_from_slice(&(obj.len() as u32).to_le_bytes());
        v.extend_from_slice(&[0u8; 4]);
        v.extend_from_slice(obj);
        let pad = csize % 4;
        if pad != 0 {
            v.extend_from_slice(&vec![0u8; 4 - pad]); // 对齐补垫
        }
        v
    }

    /// 对象外壳:基础头 16B + v1 头(flags, ts)+ 成员数据
    fn obj(ty: u32, flags: u32, ts: u64, member: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[..4].copy_from_slice(b"LOBJ");
        v[4..6].copy_from_slice(&16u16.to_le_bytes());
        v[6..8].copy_from_slice(&1u16.to_le_bytes());
        v[8..12].copy_from_slice(&((32 + member.len()) as u32).to_le_bytes());
        v[12..16].copy_from_slice(&ty.to_le_bytes());
        v[16..20].copy_from_slice(&flags.to_le_bytes());
        v[24..32].copy_from_slice(&ts.to_le_bytes());
        v.extend_from_slice(member);
        v
    }

    #[test]
    fn ten_mics_factor_and_tx_remote_ext() {
        // 经典 CAN:channel=3, flags=TX|REMOTE=0x81, dlc=2, ext id 0x18FF0102, data 哨兵
        let mut member = Vec::new();
        member.extend_from_slice(&3u16.to_le_bytes());
        member.push(0x81); // Tx + remote
        member.push(2);
        member.extend_from_slice(&(0x18FF0102u32 | 0x8000_0000).to_le_bytes());
        member.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
        let data = wrap(&obj(OBJ_CAN, TIME_TEN_MICS, 100, &member)); // 100 × 10µs = 1ms
        let (recs, _labels, epoch, warns) = read(&data, "t.blf").unwrap();
        assert_eq!(recs.len(), 1, "{warns:?}");
        let r = &recs[0];
        assert_eq!(r.t_ns, 1_000_000, "10µs 单位换算");
        assert_eq!(r.dir, Dir::Tx);
        assert!(r.data.is_empty(), "远程帧无数据");
        assert_eq!(r.can_id.unwrap() & 0x1FFF_FFFF, 0x18FF_0102);
        assert_eq!(r.can_id.unwrap() & 0x8000_0000, 0x8000_0000, "扩展帧 bit31");
        assert_eq!(r.channel, 3);
        assert_eq!(epoch, None);
    }

    #[test]
    fn v2_header_member_offset() {
        // v2 头 24B,成员@40;构造 FD100 对象(成员 80B)
        let mut member = vec![0u8; 80];
        member[0..2].copy_from_slice(&5u16.to_le_bytes()); // channel
        member[2] = 0x00; // Rx
        member[3] = 15; // DLC 码 15 → 64B
        member[4..8].copy_from_slice(&0x123u32.to_le_bytes());
        member[12] = 0x1; // EDL
        member[13] = 32; // valid bytes
        for (i, b) in member[16..48].iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut v = vec![0u8; 40];
        v[..4].copy_from_slice(b"LOBJ");
        v[4..6].copy_from_slice(&16u16.to_le_bytes());
        v[6..8].copy_from_slice(&2u16.to_le_bytes()); // 头版本 2
        v[8..12].copy_from_slice(&((40 + member.len()) as u32).to_le_bytes());
        v[12..16].copy_from_slice(&OBJ_CAN_FD.to_le_bytes());
        v[16..20].copy_from_slice(&2u32.to_le_bytes()); // ns 单位
        v[24..32].copy_from_slice(&7u64.to_le_bytes());
        v.extend_from_slice(&member);
        let data = wrap(&v);
        let (recs, _labels, _epoch, warns) = read(&data, "t.blf").unwrap();
        assert_eq!(recs.len(), 1, "{warns:?}");
        let r = &recs[0];
        assert_eq!(r.proto, Proto::CanFd);
        assert_eq!(r.t_ns, 7);
        assert_eq!(r.channel, 5);
        assert_eq!(r.data.len(), 32, "有效字节 32");
        assert_eq!(r.data[0], 0);
    }

    #[test]
    fn object_spanning_containers() {
        // 两个经典 CAN 对象,容器在对象中间切开(跨容器拼接)
        let mut member = vec![0u8; 16];
        member[0..2].copy_from_slice(&1u16.to_le_bytes());
        member[2] = 0x00;
        member[3] = 8;
        member[4..8].copy_from_slice(&0x2A_u32.to_le_bytes());
        let o = obj(OBJ_CAN, 2, 5, &member);
        let (first, second) = o.split_at(30); // 在对象内部切
        let mut container = vec![0u8; 144];
        container[..4].copy_from_slice(b"LOGG");
        container[4..8].copy_from_slice(&144u32.to_le_bytes());
        let mut push_container = |v: &mut Vec<u8>, content: &[u8]| {
            let csize = 32 + content.len();
            v.extend_from_slice(b"LOBJ");
            v.extend_from_slice(&16u16.to_le_bytes());
            v.extend_from_slice(&1u16.to_le_bytes());
            v.extend_from_slice(&(csize as u32).to_le_bytes());
            v.extend_from_slice(&10u32.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&[0u8; 6]);
            v.extend_from_slice(&(content.len() as u32).to_le_bytes());
            v.extend_from_slice(&[0u8; 4]);
            v.extend_from_slice(content);
        };
        push_container(&mut container, first);
        let pad = (32 + first.len()) % 4;
        container.extend_from_slice(&vec![0u8; pad]); // 对齐补垫
        let mut file = container;
        let mut c2 = Vec::new();
        push_container(&mut c2, second);
        file.extend_from_slice(&c2);
        let (recs, _labels, _epoch, warns) = read(&file, "t.blf").unwrap();
        assert_eq!(recs.len(), 1, "跨容器对象应拼接后解析;{warns:?}");
        assert_eq!(recs[0].can_id.unwrap() & 0x1FFF_FFFF, 0x2A);
        assert_eq!(recs[0].t_ns, 5);
    }
}

#[cfg(test)]
mod corpus_walk {
    // 语料 6 个 fixture 的结构回归锁(合成 dummy,只锁对象 walk 不锁语义;见模块头注释)
    use super::*;

    fn frames_of(path: &str) -> Vec<Record> {
        let bytes = std::fs::read(path).unwrap();
        let (records, _labels, _epoch, warns) = read(&bytes, "fixture.blf").unwrap();
        // dummy 夹具含非 CAN 报文对象(GLOBAL_MARKER 等),walk 告警属预期
        for w in &warns {
            assert!(w.contains("跳过"), "未预期告警: {w}");
        }
        records
    }

    #[test]
    fn corpus_structure_walk() {
        let base = r"D:\dev\tools\test-corpus\08-real-captures\blf";
        if !std::path::Path::new(base).exists() {
            eprintln!("[skip] 语料不在本机");
            return;
        }
        let cm = frames_of(&format!(r"{base}\test_CanMessage.blf"));
        assert_eq!(cm.len(), 2, "CanMessage: 2 个 type1 对象");
        let cm2 = frames_of(&format!(r"{base}\test_CanMessage2.blf"));
        assert!(!cm2.is_empty(), "CanMessage2 至少 1 帧");
        let fd = frames_of(&format!(r"{base}\test_CanFdMessage64.blf"));
        assert_eq!(fd.len(), 2, "FD64: 2 个 type101 对象");
        let fd2 = frames_of(&format!(r"{base}\test_CanFdMessage.blf"));
        assert!(!fd2.is_empty(), "FD100 至少 1 帧");
        let err = frames_of(&format!(r"{base}\test_CanErrorFrameExt.blf"));
        assert_eq!(err.len(), 2, "ErrorFrameExt: 2 个 type73 对象");
    }
}
