use core::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    DatagramTooShort { minimum: usize, actual: usize },
    DatagramTooLarge { maximum: usize, actual: usize },
    InvalidMagic { expected: u16, actual: u16 },
    UnsupportedVersion { version: u8 },
    InvalidPacketType { value: u8 },
    InvalidFlags { value: u16 },
    InvalidHeaderLength { expected: usize, actual: usize },
    PayloadLengthMismatch { declared: usize, actual: usize },
    ChecksumMismatch { expected: u32, actual: u32 },
    EmptyPacket,
    TooManyFrames { maximum: usize },
    UnknownFrameType { value: u8 },
    FrameTooLarge { maximum: usize, actual: usize },
    Truncated { context: &'static str },
    VarIntOverflow,
    InvalidVarIntLength { length: usize },
    InvalidValue { field: &'static str },
    InvalidAckRanges,
    AckRangeCountExceeded { maximum: usize },
    InvalidUtf8 { field: &'static str },
    EncryptedPacketRequiresKeys,
    EncryptionNotAllowed,
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
