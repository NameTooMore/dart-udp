use core::{error::Error, fmt};

/// UDP 协议解析与编解码错误类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// 数据报过短（小于固定报头长度）
    DatagramTooShort { minimum: usize, actual: usize },
    /// 数据报超出最大允许字节限制
    DatagramTooLarge { maximum: usize, actual: usize },
    /// 魔数不匹配（必须为 0xd7f1）
    InvalidMagic { expected: u16, actual: u16 },
    /// 不支持的协议版本号
    UnsupportedVersion { version: u8 },
    /// 无效的数据包类型字段
    InvalidPacketType { value: u8 },
    /// 包含未知的报头标志位
    InvalidFlags { value: u16 },
    /// 报头长度声明不正确
    InvalidHeaderLength { expected: usize, actual: usize },
    /// 载荷实际长度与报头中声明的 payload_len 不符
    PayloadLengthMismatch { declared: usize, actual: usize },
    /// CRC32C 校验和不匹配（数据包已损坏或篡改）
    ChecksumMismatch { expected: u32, actual: u32 },
    /// 数据包中未包含任何帧（空包非法）
    EmptyPacket,
    /// 数据包内帧数量超过上限（最大 64）
    TooManyFrames { maximum: usize },
    /// 未知的帧类型编号
    UnknownFrameType { value: u8 },
    /// 单个帧体数据过大
    FrameTooLarge { maximum: usize, actual: usize },
    /// 数据截断，输入字节不足以读取指定字段
    Truncated { context: &'static str },
    /// 变长整数数值超出 62 位限制
    VarIntOverflow,
    /// 变长整数编码长度非法
    InvalidVarIntLength { length: usize },
    /// 字段数值超出合法逻辑范围
    InvalidValue { field: &'static str },
    /// ACK 区间列表存在倒序、重叠或不合法
    InvalidAckRanges,
    /// ACK 区间段数量超出上限
    AckRangeCountExceeded { maximum: usize },
    /// 字符串字段不是合法的 UTF-8 编码
    InvalidUtf8 { field: &'static str },
    /// 加密数据包必须使用带密钥的安全解码器解码
    EncryptedPacketRequiresKeys,
    /// 未通过加密器进行加密编码时不得手动设置 ENCRYPTED 标志
    EncryptionNotAllowed,
    /// 密码学相关错误（加解密失败、重放等）
    Crypto(crate::CryptoError),
}


impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatagramTooShort { minimum, actual } => {
                write!(f, "datagram is too short: {actual} < {minimum}")
            }
            Self::DatagramTooLarge { maximum, actual } => {
                write!(f, "datagram is too large: {actual} > {maximum}")
            }
            Self::InvalidMagic { expected, actual } => {
                write!(
                    f,
                    "invalid magic: expected {expected:#06x}, got {actual:#06x}"
                )
            }
            Self::UnsupportedVersion { version } => write!(f, "unsupported version {version}"),
            Self::InvalidPacketType { value } => write!(f, "invalid packet type {value}"),
            Self::InvalidFlags { value } => write!(f, "invalid packet flags {value:#06x}"),
            Self::InvalidHeaderLength { expected, actual } => {
                write!(
                    f,
                    "invalid header length: expected {expected}, got {actual}"
                )
            }
            Self::PayloadLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "payload length mismatch: declared {declared}, got {actual}"
                )
            }
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
            ),
            Self::EmptyPacket => f.write_str("packet must contain at least one frame"),
            Self::TooManyFrames { maximum } => {
                write!(f, "packet contains more than {maximum} frames")
            }
            Self::UnknownFrameType { value } => write!(f, "unknown frame type {value}"),
            Self::FrameTooLarge { maximum, actual } => {
                write!(f, "frame is too large: {actual} > {maximum}")
            }
            Self::Truncated { context } => write!(f, "truncated {context}"),
            Self::VarIntOverflow => f.write_str("varint value exceeds the 62-bit limit"),
            Self::InvalidVarIntLength { length } => {
                write!(f, "invalid varint length {length}")
            }
            Self::InvalidValue { field } => write!(f, "invalid value for {field}"),
            Self::InvalidAckRanges => f.write_str("ACK ranges are invalid or overlap"),
            Self::AckRangeCountExceeded { maximum } => {
                write!(f, "ACK range count exceeds {maximum}")
            }
            Self::InvalidUtf8 { field } => write!(f, "{field} is not valid UTF-8"),
            Self::EncryptedPacketRequiresKeys => {
                f.write_str("encrypted packet requires the secure packet decoder")
            }
            Self::EncryptionNotAllowed => {
                f.write_str("the encrypted flag can only be set by the secure packet encoder")
            }
            Self::Crypto(error) => write!(f, "cryptographic error: {error}"),
        }
    }
}

impl Error for ProtocolError {}
