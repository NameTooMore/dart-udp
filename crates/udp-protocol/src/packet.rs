use core::{
    fmt,
    ops::{BitOr, BitOrAssign},
};

use crate::{codec, error::ProtocolError, frame::Frame};

/// 协议魔数：固定为 0xd7f1
pub const MAGIC: u16 = 0xd7f1;
/// 协议版本：当前为版本 2
pub const VERSION: u8 = 2;
/// 固定报头长度（30 字节）
pub const FIXED_HEADER_LEN: usize = 30;

/// 数据包类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// 握手发起包（客户端 ClientHello）
    Initial = 0,
    /// 握手响应与确认包（ServerHello / HandshakeAck）
    Handshake = 1,
    /// 业务应用数据包（传输流数据及普通控制帧）
    Data = 2,
    /// 连接关闭通知包
    Close = 3,
    /// 服务端重试包（用于防放大攻击与 Cookie 校验）
    Retry = 4,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Initial),
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Data),
            3 => Ok(Self::Close),
            4 => Ok(Self::Retry),
            value => Err(ProtocolError::InvalidPacketType { value }),
        }
    }
}

/// 连接标识（64 位无符号整数）
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ConnectionId").field(&self.0).finish()
    }
}

/// 数据包序号，按包单调递增
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PacketNumber(u64);

impl PacketNumber {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    /// 饱和相加操作，防止序号溢出
    pub const fn saturating_add(self, value: u64) -> Self {
        Self(self.0.saturating_add(value))
    }
}

impl fmt::Debug for PacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PacketNumber").field(&self.0).finish()
    }
}

/// 多路复用流标识（Stream ID）
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StreamId").field(&self.0).finish()
    }
}

/// 数据包报头标志位（16 位位掩码）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketFlags(u16);

impl PacketFlags {
    /// 触发应答标志：要求接收端回复 ACK
    pub const ACK_ELICITING: Self = Self(0x0001);
    /// 加密标志：表明载荷已被 AEAD 加密保护
    pub const ENCRYPTED: Self = Self(0x0002);
    /// 探测包标志：用于链路探测（如路径 MTU 探测或保活）
    pub const PROBE: Self = Self(0x0004);
    /// 填充标志：包末尾包含对齐填充
    pub const HAS_PADDING: Self = Self(0x0008);

    const KNOWN_BITS: u16 =
        Self::ACK_ELICITING.0 | Self::ENCRYPTED.0 | Self::PROBE.0 | Self::HAS_PADDING.0;

    /// 空标志集合
    pub const fn empty() -> Self {
        Self(0)
    }

    /// 获取底层位表示
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// 判断是否包含指定的标志位
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// 从原始位表示解析并校验是否仅包含已知标志
    pub fn from_bits(bits: u16) -> Result<Self, ProtocolError> {
        if bits & !Self::KNOWN_BITS != 0 {
            return Err(ProtocolError::InvalidFlags { value: bits });
        }
        Ok(Self(bits))
    }
}

impl BitOr for PacketFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for PacketFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// 协议定长报头（固定 30 字节）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// 协议版本号（1 字节）
    pub version: u8,
    /// 数据包类型（1 字节）
    pub packet_type: PacketType,
    /// 报头控制标志位（2 字节）
    pub flags: PacketFlags,
    /// 报头长度声明（2 字节，固定为 30）
    pub header_len: u16,
    /// 连接 ID（8 字节）
    pub connection_id: ConnectionId,
    /// 数据包编号（8 字节）
    pub packet_number: PacketNumber,
    /// 载荷字节长度（2 字节）
    pub payload_len: u16,
    /// CRC32C 校验和（4 字节）
    pub checksum: u32,
}

/// 完整数据包结构，包含报头元数据和载荷帧集合
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub packet_type: PacketType,
    pub flags: PacketFlags,
    pub connection_id: ConnectionId,
    pub packet_number: PacketNumber,
    pub frames: Vec<Frame>,
}

impl Packet {
    /// 构造新的数据包
    pub fn new(
        packet_type: PacketType,
        flags: PacketFlags,
        connection_id: ConnectionId,
        packet_number: PacketNumber,
        frames: Vec<Frame>,
    ) -> Self {
        Self {
            packet_type,
            flags,
            connection_id,
            packet_number,
            frames,
        }
    }

    /// 使用默认数据报大小（1200 字节）明文编码
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        codec::encode_packet(self, codec::DEFAULT_MAX_DATAGRAM_SIZE)
    }

    /// 使用指定最大数据报大小明文编码
    pub fn encode_with_limit(&self, max_datagram_size: usize) -> Result<Vec<u8>, ProtocolError> {
        codec::encode_packet(self, max_datagram_size)
    }

    /// 使用默认大小解码明文数据包
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        codec::decode_packet(bytes, codec::DEFAULT_MAX_DATAGRAM_SIZE)
    }

    /// 使用指定最大数据报大小解码明文数据包
    pub fn decode_with_limit(
        bytes: &[u8],
        max_datagram_size: usize,
    ) -> Result<Self, ProtocolError> {
        codec::decode_packet(bytes, max_datagram_size)
    }

    /// 使用密码学上下文加密并编码数据包
    pub fn encode_with_crypto(
        &self,
        max_datagram_size: usize,
        crypto: &crate::PacketCrypto,
    ) -> Result<Vec<u8>, ProtocolError> {
        codec::encode_packet_with_crypto(self, max_datagram_size, crypto)
    }

    /// 使用密码学上下文解密并解码数据包（自动执行防重放校验）
    pub fn decode_with_crypto(
        bytes: &[u8],
        max_datagram_size: usize,
        crypto: &mut crate::PacketCrypto,
    ) -> Result<Self, ProtocolError> {
        codec::decode_encrypted_packet(bytes, max_datagram_size, crypto)
    }
}

