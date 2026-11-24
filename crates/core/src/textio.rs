//! 配置文件文本读取:UTF-8 优先,失败时回退 GBK(国内车规 DBC/点表常见编码)。
//! DBC 里 `℃`、中文注释在 GBK 编码下 `read_to_string` 直接报 InvalidData,
//! 这里保证结构可解析,编码信息通过返回值透出给调用方做提示。

use std::io::Read;
use std::path::Path;

/// 读文本文件:先按 UTF-8,非法时按 GBK 解码(GBK 解不了的字节替换为 U+FFFD)。
/// 返回 (文本, 实际使用的编码);GBK 回退发生时编码为 "GBK",否则 "UTF-8"。
pub fn read_text(path: &Path) -> std::io::Result<(String, &'static str)> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok((s, "UTF-8")),
        Err(e) => {
            let bytes = e.into_bytes();
            let (cow, _, had_errors) = encoding_rs::GBK.decode(&bytes);
            if had_errors {
                // GBK 也有非法字节:仍返回尽力解码结果,结构解析不受影响
            }
            Ok((cow.into_owned(), "GBK"))
        }
    }
}

/// 同 [`read_text`] 但只取文本(忽略编码信息)。
pub fn read_text_simple(path: &Path) -> std::io::Result<String> {
    read_text(path).map(|(s, _)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_passthrough() {
        let p = std::env::temp_dir().join("iotprobe_textio_utf8.txt");
        std::fs::write(&p, "BO_ 123 abc: 8\n").unwrap();
        let (s, enc) = read_text(&p).unwrap();
        assert_eq!(enc, "UTF-8");
        assert!(s.contains("BO_ 123"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn gbk_fallback() {
        // "℃" 的 GBK 编码是 A1 E6
        let p = std::env::temp_dir().join("iotprobe_textio_gbk.dbc");
        std::fs::write(&p, b"SG_ temp : 0|8@1+ (1,-40) \"\xa1\xe6\" ECU\r\n").unwrap();
        let (s, enc) = read_text(&p).unwrap();
        assert_eq!(enc, "GBK");
        assert!(s.contains('℃'), "GBK 单位应解码为 ℃: {s:?}");
        let _ = std::fs::remove_file(&p);
    }
}
