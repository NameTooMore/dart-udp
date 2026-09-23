use core::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomnessError;

impl fmt::Display for RandomnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("secure randomness is unavailable")
    }
}

impl Error for RandomnessError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    MessageTooShort {
        minimum: usize,
        actual: usize,
    },
    MessageTooLarge {
        maximum: usize,
        actual: usize,
    },
    DeclaredLengthMismatch {
        declared: usize,
        actual: usize,
    },
    UnsupportedVersion {
        version: u8,
    },
    UnknownMessageType {
        value: u8,
    },
    InvalidFlags {
        value: u16,
    },
    Truncated {
        context: &'static str,
    },
    InvalidValue {
        field: &'static str,
    },
    InvalidUtf8 {
        field: &'static str,
    },
    FieldTooLarge {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    TooManyItems {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    InvalidPairingCode,
    RandomnessUnavailable,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooShort { minimum, actual } => {
                write!(f, "message is too short: {actual} < {minimum}")
            }
            Self::MessageTooLarge { maximum, actual } => {
                write!(f, "message is too large: {actual} > {maximum}")
            }
            Self::DeclaredLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "declared message length {declared} != actual length {actual}"
                )
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported protocol version {version}")
            }
            Self::UnknownMessageType { value } => write!(f, "unknown message type {value}"),
            Self::InvalidFlags { value } => write!(f, "unknown message flags {value:#06x}"),
            Self::Truncated { context } => write!(f, "truncated {context}"),
            Self::InvalidValue { field } => write!(f, "invalid value for {field}"),
            Self::InvalidUtf8 { field } => write!(f, "{field} is not valid UTF-8"),
            Self::FieldTooLarge {
                field,
                maximum,
                actual,
            } => write!(f, "{field} is too large: {actual} > {maximum}"),
            Self::TooManyItems {
                field,
                maximum,
                actual,
            } => write!(f, "{field} contains too many items: {actual} > {maximum}"),
            Self::InvalidPairingCode => f.write_str("invalid pairing code"),
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
        }
    }
}

impl Error for ProtocolError {}

impl From<RandomnessError> for ProtocolError {
    fn from(_: RandomnessError) -> Self {
        Self::RandomnessUnavailable
    }
}
