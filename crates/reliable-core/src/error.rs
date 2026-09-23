use core::{error::Error, fmt};

use udp_protocol::StreamId;

#[derive(Debug)]
pub enum CoreError {
    InvalidConfig(crate::ConnectionConfigError),
    Protocol(udp_protocol::ProtocolError),
    Timer(time_wheel::TimerError),
    ConnectionIdMismatch,
    InvalidState {
        operation: &'static str,
    },
    InvalidPacketType,
    InvalidStreamId {
        stream_id: StreamId,
    },
    StreamLimit,
    UnknownStream {
        stream_id: StreamId,
    },
    StreamReset {
        stream_id: StreamId,
        error_code: u32,
    },
    FlowControlViolation {
        stream_id: Option<StreamId>,
    },
    ReceiveBufferFull,
    SendBufferFull,
    InvalidOffset,
    AckForUnsentPacket,
    RetransmissionLimit,
    RandomnessUnavailable,
    Crypto(udp_protocol::CryptoError),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid connection configuration: {error}"),
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Timer(error) => write!(f, "timer error: {error}"),
            Self::ConnectionIdMismatch => f.write_str("packet belongs to another connection"),
            Self::InvalidState { operation } => {
                write!(f, "operation is invalid in current state: {operation}")
            }
            Self::InvalidPacketType => f.write_str("packet type is invalid for current state"),
            Self::InvalidStreamId { stream_id } => {
                write!(f, "stream ID has invalid initiator parity: {stream_id:?}")
            }
            Self::StreamLimit => f.write_str("stream limit has been reached"),
            Self::UnknownStream { stream_id } => write!(f, "unknown stream: {stream_id:?}"),
            Self::StreamReset {
                stream_id,
                error_code,
            } => {
                write!(f, "stream {stream_id:?} was reset with error {error_code}")
            }
            Self::FlowControlViolation {
                stream_id: Some(stream_id),
            } => {
                write!(f, "stream {stream_id:?} exceeded its receive window")
            }
            Self::FlowControlViolation { stream_id: None } => {
                f.write_str("connection exceeded its receive window")
            }
            Self::ReceiveBufferFull => f.write_str("receive buffer is full"),
            Self::SendBufferFull => f.write_str("send buffer is full"),
            Self::InvalidOffset => f.write_str("stream offset overflowed"),
            Self::AckForUnsentPacket => f.write_str("acknowledgement refers to an unsent packet"),
            Self::RetransmissionLimit => f.write_str("retransmission limit was reached"),
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
            Self::Crypto(error) => write!(f, "cryptographic error: {error}"),
        }
    }
}

impl Error for CoreError {}

impl From<udp_protocol::ProtocolError> for CoreError {
    fn from(error: udp_protocol::ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<time_wheel::TimerError> for CoreError {
    fn from(error: time_wheel::TimerError) -> Self {
        Self::Timer(error)
    }
}

impl From<udp_protocol::CryptoError> for CoreError {
    fn from(error: udp_protocol::CryptoError) -> Self {
        Self::Crypto(error)
    }
}
