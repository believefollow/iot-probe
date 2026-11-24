//! 核心数据模型:Record(摄入层) → Frame(协议层) → Decoded(字段树) + Series(时序) + Event(异常)。

use std::collections::HashMap;
use std::sync::Arc;

/// 时间戳来源等级(ADR-5):sw=L0 收包时刻, hw=L1 硬件时戳, mcu=L2 板载共时基, wall=墙钟无精度保证
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TsSrc {
    #[default]
    Sw,
    Hw,
    Mcu,
    Wall,
}

impl TsSrc {
    pub fn label(&self) -> &'static str {
        match self {
            TsSrc::Sw => "sw",
            TsSrc::Hw => "hw",
            TsSrc::Mcu => "mcu",
            TsSrc::Wall => "wall",
        }
    }
    pub fn level(&self) -> &'static str {
        match self {
            TsSrc::Sw => "L0",
            TsSrc::Hw => "L1",
            TsSrc::Mcu => "L2",
            TsSrc::Wall => "-",
        }
    }
    /// 精度排名(用于取通道内最差时基):mcu > hw > sw > wall
    pub fn rank(&self) -> i8 {
        match self {
            TsSrc::Mcu => 3,
            TsSrc::Hw => 2,
            TsSrc::Sw => 1,
            TsSrc::Wall => 0,
        }
    }
    pub fn from_rank(r: i8) -> TsSrc {
        match r {
            3 => TsSrc::Mcu,
            2 => TsSrc::Hw,
            1 => TsSrc::Sw,
            _ => TsSrc::Wall,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum Dir {
    Rx,
    Tx,
    Unknown,
}

impl Dir {
    pub fn label(&self) -> &'static str {
        match self {
            Dir::Rx => "RX",
            Dir::Tx => "TX",
            Dir::Unknown => "--",
        }
    }
    pub fn color(&self) -> [u8; 3] {
        match self {
            Dir::Rx => [96, 200, 235],
            Dir::Tx => [240, 166, 76],
            Dir::Unknown => [140, 140, 140],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum Proto {
    Raw,
    Tcp,
    ModbusRtu,
    ModbusAscii,
    ModbusTcp,
    Mqtt,
    Iec104,
    Dnp3,
    S7,
    Dl645,
    Http,
    EtherCat,
    Pn,
    Can,
    CanFd,
    Udp,
    Arp,
    Custom,
}

impl Proto {
    pub fn label(&self) -> &'static str {
        match self {
            Proto::Raw => "RAW",
            Proto::Tcp => "TCP",
            Proto::ModbusRtu => "Modbus RTU",
            Proto::ModbusAscii => "Modbus ASCII",
            Proto::ModbusTcp => "Modbus TCP",
            Proto::Mqtt => "MQTT",
            Proto::Iec104 => "IEC 104",
            Proto::Dnp3 => "DNP3",
            Proto::S7 => "S7comm",
            Proto::Dl645 => "DL/T 645",
            Proto::Http => "HTTP",
            Proto::EtherCat => "EtherCAT",
            Proto::Pn => "PROFINET",
            Proto::Can => "CAN",
            Proto::CanFd => "CAN FD",
            Proto::Udp => "UDP",
            Proto::Arp => "ARP",
            Proto::Custom => "Custom",
        }
    }
    pub fn color(&self) -> [u8; 3] {
        match self {
            Proto::Raw => [150, 150, 150],
            Proto::Tcp => [180, 180, 190],
            Proto::ModbusRtu => [98, 178, 235],
            Proto::ModbusAscii => [120, 150, 210],
            Proto::ModbusTcp => [80, 150, 220],
            Proto::Mqtt => [140, 200, 100],
            Proto::Iec104 => [230, 120, 180],
            Proto::Dnp3 => [200, 140, 90],
            Proto::S7 => [110, 150, 220],
            Proto::Dl645 => [90, 190, 210],
            Proto::Http => [160, 130, 210],
            Proto::EtherCat => [235, 130, 90],
            Proto::Pn => [90, 200, 160],
            Proto::Can | Proto::CanFd => [210, 160, 235],
            Proto::Udp => [120, 190, 170],
            Proto::Arp => [170, 170, 110],
            Proto::Custom => [235, 200, 90],
        }
    }
}

/// 摄入层记录:一个数据包 / 一行串口日志 / 一条 candump 行。
#[derive(Clone, Debug)]
pub struct Record {
    pub t_ns: u64,
    /// 时间戳来源等级(ADR-5)
    pub ts_src: TsSrc,
    pub dir: Dir,
    pub source: u16,
    pub channel: u16,
    pub proto: Proto,
    /// 距上一条记录估计丢失的帧数(0=无丢弃;抓包缺段时 ≥1)
    pub gap_n: u32,
    /// CAN 专属:报文 ID(扩展帧以 bit31 标记,导出时拆分为 id + id_type)
    pub can_id: Option<u32>,
    pub data: Arc<[u8]>,
}

impl Record {
    /// CAN ID 的 std/ext 拆分:(id_bits, is_ext)
    pub fn id_split(&self) -> (u32, bool) {
        match self.can_id {
            Some(raw) => (raw & 0x1FFF_FFFF, raw & 0x8000_0000 != 0),
            None => (0, false),
        }
    }
}

/// 协议层帧:定界后的一个 PDU / 报文。
#[derive(Clone)]
pub struct Frame {
    pub record: u32,
    /// 帧在 record.data 中的偏移与长度
    pub off: u32,
    pub len: u32,
    pub t_ns: u64,
    pub ts_src: TsSrc,
    pub dir: Dir,
    pub source: u16,
    pub channel: u16,
    pub proto: Proto,
    /// 同通道内递增序号(全局排序后分配,对应 schema meta.seq)
    pub seq: u32,
    /// 估计丢失帧数(继承自记录)
    pub gap_n: u32,
    pub summary: String,
}

#[derive(Clone, Default)]
pub struct Strings {
    map: HashMap<String, u32>,
    list: Vec<String>,
}

impl Strings {
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.map.get(s) {
            return i;
        }
        let i = self.list.len() as u32;
        self.list.push(s.to_string());
        self.map.insert(s.to_string(), i);
        i
    }
    pub fn get(&self, i: u32) -> &str {
        self.list.get(i as usize).map(|s| s.as_str()).unwrap_or("?")
    }
    pub fn len(&self) -> usize {
        self.list.len()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    U(u64),
    I(i64),
    F(f64),
    B(bool),
    S(String),
    Hex(Vec<u8>),
    None,
}

impl Value {
    pub fn to_f64(&self) -> Option<f64> {
        match self {
            Value::U(u) => Some(*u as f64),
            Value::I(i) => Some(*i as f64),
            Value::F(f) => Some(*f),
            Value::B(b) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        }
    }
    pub fn display(&self) -> String {
        match self {
            Value::U(u) => u.to_string(),
            Value::I(i) => i.to_string(),
            Value::F(f) => {
                if f.abs() >= 1e10 || (f.abs() < 1e-4 && *f != 0.0) {
                    format!("{:e}", f)
                } else {
                    let s = format!("{:.6}", f);
                    let t = s.trim_end_matches('0').trim_end_matches('.');
                    t.to_string()
                }
            }
            Value::B(b) => b.to_string(),
            Value::S(s) => s.clone(),
            Value::Hex(b) => b.iter().map(|x| format!("{:02X}", x)).collect::<Vec<_>>().join(" "),
            Value::None => "-".to_string(),
        }
    }
}

/// 解析出的字段节点。start/len 是帧数据内的字节区间(len=0 表示派生值无固定区间)。
#[derive(Clone, Debug)]
pub struct Field {
    pub name: u32,
    pub val: Value,
    pub start: u16,
    pub len: u16,
    pub plot: bool,
    pub unit: Option<u32>,
    pub children: Vec<Field>,
}

impl Field {
    pub fn name_str<'a>(&self, st: &'a Strings) -> &'a str {
        st.get(self.name)
    }
}

pub struct Decoded {
    pub proto: Proto,
    pub ok: bool,
    pub root: Vec<Field>,
}

/// 时序序列:(t_ns, value, frame_idx) 升序
#[derive(Clone)]
pub struct Series {
    pub key: String,
    pub unit: String,
    pub pts: Vec<(u64, f64, u32)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    Gap,
    CrcError,
    Exception,
    Malformed,
    WkcError,
    StreamDrop,
    Timeout,
    /// 规则引擎产出的语义事件(ADR-6;code/level/rule_ref 在 Event.rule 中)
    Rule,
    Info,
}

impl EventKind {
    pub fn label(&self) -> &'static str {
        match self {
            EventKind::Gap => "间隔异常",
            EventKind::CrcError => "校验错误",
            EventKind::Exception => "协议异常码",
            EventKind::Malformed => "无法解析",
            EventKind::WkcError => "EtherCAT WKC",
            EventKind::StreamDrop => "流丢段",
            EventKind::Timeout => "请求无响应",
            EventKind::Rule => "规则",
            EventKind::Info => "信息",
        }
    }
    /// 诊断事件的契约桥接事件码(ADR-0007:builtin-diag 规则包归属)
    pub fn diag_code(&self) -> &'static str {
        match self {
            EventKind::Rule => "RULE_EVENT",
            EventKind::Gap => "DIAG_TIMING_GAP",
            EventKind::CrcError => "DIAG_CRC_ERROR",
            EventKind::Exception => "DIAG_PROTOCOL_EXCEPTION",
            EventKind::Malformed => "DIAG_MALFORMED_FRAME",
            EventKind::WkcError => "DIAG_WKC_ZERO",
            EventKind::StreamDrop => "DIAG_STREAM_DROP",
            EventKind::Timeout => "DIAG_RESP_TIMEOUT",
            EventKind::Info => "DIAG_INFO",
        }
    }
    /// 诊断事件分级(fault/warn/info)
    pub fn diag_level(&self) -> &'static str {
        match self {
            EventKind::Rule => "info",
            EventKind::CrcError | EventKind::Exception | EventKind::Malformed | EventKind::WkcError | EventKind::Timeout => "fault",
            EventKind::Gap | EventKind::StreamDrop => "warn",
            EventKind::Info => "info",
        }
    }
    pub fn color(&self) -> [u8; 3] {
        match self {
            EventKind::Gap => [240, 150, 50],
            EventKind::CrcError => [235, 80, 70],
            EventKind::Exception => [235, 80, 70],
            EventKind::Malformed => [220, 80, 120],
            EventKind::WkcError => [235, 60, 60],
            EventKind::StreamDrop => [235, 110, 50],
            EventKind::Timeout => [255, 90, 60],
            EventKind::Rule => [80, 150, 240],
            EventKind::Info => [150, 150, 150],
        }
    }
}

/// 规则事件的契约元数据(ADR-6/ADR-0009;诊断事件为 None)
#[derive(Clone, Debug)]
pub struct RuleEventMeta {
    pub pack: String,
    pub file: String,
    pub rule_id: String,
    pub level: String, // info | warn | fault
    /// 证据信号:(键, 值, 单位)
    pub signals: Vec<(String, f64, String)>,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub t_ns: u64,
    pub frame: Option<u32>,
    pub kind: EventKind,
    pub detail: String,
    pub source: u16,
    pub channel: u16,
    /// 规则事件专有(诊断事件 None)
    pub rule: Option<RuleEventMeta>,
}

impl Event {
    /// 诊断事件构造(无规则元数据)
    pub fn diag(t_ns: u64, frame: Option<u32>, kind: EventKind, detail: String, source: u16, channel: u16) -> Self {
        Event { t_ns, frame, kind, detail, source, channel, rule: None }
    }
}

/// 通道的按需解码器类型(大文件懒解码时使用)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoder {
    ModbusRtu,
    ModbusAscii,
    ModbusTcp,
    Mqtt,
    Iec104,
    Dnp3,
    S7,
    Dl645,
    Http,
    EtherCat,
    Pn,
    Can,
    Custom,
    RawText,
    RawHex,
}

#[derive(Clone)]
pub struct ChannelMeta {
    pub source: u16,
    pub id: u16,
    pub label: String,
    pub proto: Proto,
    /// 通道时基等级(取通道内最差,FR-2.2 如实标注)
    pub ts_src: TsSrc,
    pub decoder: Decoder,
    /// Custom 通道对应的自定义协议在 decode_ctx.custom 中的下标
    pub spec_idx: Option<usize>,
    /// DBC 命中统计(MVP 体检卡):(解出信号的 CAN 帧数, CAN 帧总数);非 CAN 通道 = None
    pub dbc_hit: Option<(u32, u32)>,
}

/// 按需解码所需的配置快照(随数据集保存)
#[derive(Clone, Default)]
pub struct DecodeCtx {
    pub custom: Vec<crate::dissect::custom::CustomSpec>,
    pub map: Option<crate::dissect::modbus::ModbusMap>,
    pub map104: Option<crate::dissect::map104::Map104>,
    pub dbc: Option<crate::dbc::Dbc>,
}

/// 数据集(FR-3.7 规则热加载需要整体克隆,故 derive Clone)
#[derive(Clone)]
pub struct Dataset {
    pub name: String,
    /// 时间基准(首个绝对时间的 epoch ns;若日志无绝对时间则为 None)
    pub epoch_ns: Option<u64>,
    /// 全部记录(供 hex 回看)
    pub records: Vec<Record>,
    pub frames: Vec<Frame>,
    pub decoded: Vec<Option<Arc<Decoded>>>,
    pub signals: Vec<Series>,
    pub events: Vec<Event>,
    pub channels: Vec<ChannelMeta>,
    pub strings: Strings,
    pub warnings: Vec<String>,
    pub decode_ctx: DecodeCtx,
}

impl Dataset {
    pub fn channel_label(&self, source: u16, channel: u16) -> String {
        self.channels
            .iter()
            .find(|c| c.source == source && c.id == channel)
            .map(|c| c.label.clone())
            .unwrap_or_else(|| format!("ch{}", channel))
    }
    pub fn t_max_ns(&self) -> u64 {
        self.frames.last().map(|f| f.t_ns).unwrap_or(0)
    }
}
