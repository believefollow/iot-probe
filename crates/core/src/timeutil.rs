//! 时间:统一 u64 纳秒。日志没有时区概念,一律按 UTC 处理。

/// Howard Hinnant days_from_civil
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = ((m + 9) % 12) as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn wall_to_epoch_ns(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32, frac_ns: u32) -> u64 {
    let days = days_from_civil(y, mo, d);
    let secs = days * 86400 + (h as i64) * 3600 + (mi as i64) * 60 + s as i64;
    (secs as i128 * 1_000_000_000 + frac_ns as i128).max(0) as u64
}

pub fn epoch_ns_to_wall(epoch_ns: u64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let secs = (epoch_ns / 1_000_000_000) as i64;
    let ns = (epoch_ns % 1_000_000_000) as u32;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, (rem / 3600) as u32, (rem / 60 % 60) as u32, (rem % 60) as u32, ns)
}

/// 相对时间(秒),用于表格与坐标轴
pub fn fmt_rel_ns(t_ns: u64) -> String {
    let s = t_ns as f64 / 1e9;
    if s < 1.0 {
        format!("{:.3} ms", s * 1e3)
    } else if s < 60.0 {
        format!("{:.3} s", s)
    } else {
        format!("{}:{:06.3}", (s as u64) / 60, s % 60.0)
    }
}

/// 帧间隔(有符号,自适应单位)
pub fn fmt_dt_ns(d: i64) -> String {
    let a = d.abs();
    let (v, u) = if a < 1_000_000 {
        (a as f64 / 1e3, "µs")
    } else if a < 1_000_000_000 {
        (a as f64 / 1e6, "ms")
    } else {
        (a as f64 / 1e9, "s")
    };
    if d < 0 {
        format!("-{:.3} {}", v, u)
    } else {
        format!("{:.3} {}", v, u)
    }
}

pub fn fmt_wall_ns(epoch_ns: u64) -> String {
    let (y, mo, d, h, mi, s, ns) = epoch_ns_to_wall(epoch_ns);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", y, mo, d, h, mi, s, ns / 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let ns = wall_to_epoch_ns(2026, 1, 5, 10, 0, 0, 0);
        let (y, mo, d, h, mi, s, _) = epoch_ns_to_wall(ns);
        assert_eq!((y, mo, d, h, mi, s), (2026, 1, 5, 10, 0, 0));
        // 2026-01-01 00:00:00 UTC = 1767225600
        assert_eq!(wall_to_epoch_ns(2026, 1, 1, 0, 0, 0, 0) / 1_000_000_000, 1767225600);
    }
}
