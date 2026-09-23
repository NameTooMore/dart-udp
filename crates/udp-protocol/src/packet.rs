use core::{
    fmt,
    ops::{BitOr, BitOrAssign},
};

use crate::{codec, error::ProtocolError, frame::Frame};

pub const MAGIC: u16 = 0xd7f1;
pub const VERSION: u8 = 2;
pub const FIXED_HEADER_LEN: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Initial = 0,
    Handshake = 1,
    Data = 2,
    Close = 3,
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PacketNumber(u64);

impl PacketNumber {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn saturating_add(self, value: u64) -> Self {
        Self(self.0.saturating_add(value))
    }
}

impl fmt::Debug for PacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PacketNumber").field(&self.0).finish()
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketFlags(u16);

impl PacketFlags {
    pub const ACK_ELICITING: Self = Self(0x0001);
    pub const ENCRYPTED: Self = Self(0x0002);
    pub const PROBE: Self = Self(0x0004);
    pub const HAS_PADDING: Self = Self(0x0008);

    const KNOWN_BITS: u16 =
        Self::ACK_ELICITING.0 | Self::ENCRYPTED.0 | Self::PROBE.0 | Self::HAS_PADDING.0;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: PacketFlags,
    pub header_len: u16,
    pub connection_id: ConnectionId,
    pub packet_number: PacketNumber,
    pub payload_len: u16,
    pub checksum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub packet_type: PacketType,
    pub flags: PacketFlags,
    pub connection_id: ConnectionId,
    pub packet_number: PacketNumber,
    pub frames: Vec<Frame>,
}

impl Packet {
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

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        codec::encode_packet(self, codec::DEFAULT_MAX_DATAGRAM_SIZE)
    }

    pub fn encode_with_limit(&self, max_datagram_size: usize) -> Result<Vec<u8>, ProtocolError> {
        codec::encode_packet(self, max_datagram_size)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        codec::decode_packet(bytes, codec::DEFAULT_MAX_DATAGRAM_SIZE)
    }

    pub fn decode_with_limit(
        bytes: &[u8],
        max_datagram_size: usize,
    ) -> Result<Self, ProtocolError> {
        codec::decode_packet(bytes, max_datagram_size)
    }

    pub fn encode_with_crypto(
        &self,
        max_datagram_size: usize,
        crypto: &crate::PacketCrypto,
    ) -> Result<Vec<u8>, ProtocolError> {
        codec::encode_packet_with_crypto(self, max_datagram_size, crypto)
    }

    pub fn decode_with_crypto(
        bytes: &[u8],
        max_datagram_size: usize,
        crypto: &mut crate::PacketCrypto,
    ) -> Result<Self, ProtocolError> {
        codec::decode_encrypted_packet(bytes, max_datagram_size, crypto)
    }
}
