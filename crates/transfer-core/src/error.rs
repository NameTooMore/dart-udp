use core::{error::Error, fmt};

use transfer_protocol::{FileId, TransferId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    InvalidState {
        operation: &'static str,
        state: &'static str,
    },
    InvalidRole {
        operation: &'static str,
    },
    InvalidTransferId,
    ProtocolVersionMismatch {
        expected: u8,
        actual: u8,
    },
    CryptoSuiteMismatch,
    ManifestRequired,
    ManifestNotReady,
    ManifestMismatch,
    ManifestCountMismatch {
        expected: u64,
        actual: usize,
    },
    ManifestSizeMismatch {
        expected: u64,
        actual: u64,
    },
    DuplicateFile {
        file_id: FileId,
    },
    UnknownFile {
        file_id: FileId,
    },
    InvalidPath,
    InvalidFileSize {
        file_id: FileId,
    },
    InvalidOffset {
        file_id: FileId,
        offset: u64,
        maximum: u64,
    },
    InvalidCheckpoint {
        file_id: FileId,
        checkpoint_id: u64,
        current: u64,
    },
    InvalidStream {
        file_id: FileId,
        stream_id: u64,
    },
    InvalidDataOffset {
        file_id: FileId,
        expected: u64,
        actual: u64,
    },
    DataExceedsFile {
        file_id: FileId,
        offset: u64,
        length: usize,
        maximum: u64,
    },
    IntegrityMismatch {
        file_id: FileId,
    },
    ActiveFileLimit {
        maximum: usize,
    },
    PathUnavailable,
    InvalidPathTransition,
    DuplicateControl,
    Cancelled,
    Channel(String),
    Storage(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState { operation, state } => {
                write!(f, "{operation} is invalid in state {state}")
            }
            Self::InvalidRole { operation } => write!(f, "{operation} is invalid for this role"),
            Self::InvalidTransferId => f.write_str("transfer id does not match the session"),
            Self::ProtocolVersionMismatch { expected, actual } => {
                write!(
                    f,
                    "protocol version mismatch: expected {expected}, got {actual}"
                )
            }
            Self::CryptoSuiteMismatch => f.write_str("crypto suite does not match the session"),
            Self::ManifestRequired => f.write_str("manifest is required"),
            Self::ManifestNotReady => f.write_str("manifest is not ready"),
            Self::ManifestMismatch => f.write_str("manifest digest does not match"),
            Self::ManifestCountMismatch { expected, actual } => {
                write!(
                    f,
                    "manifest count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ManifestSizeMismatch { expected, actual } => {
                write!(
                    f,
                    "manifest size mismatch: expected {expected}, got {actual}"
                )
            }
            Self::DuplicateFile { file_id } => write!(f, "duplicate file {file_id}"),
            Self::UnknownFile { file_id } => write!(f, "unknown file {file_id}"),
            Self::InvalidPath => f.write_str("invalid relative file path"),
            Self::InvalidFileSize { file_id } => write!(f, "invalid size for file {file_id}"),
            Self::InvalidOffset {
                file_id,
                offset,
                maximum,
            } => write!(
                f,
                "invalid offset {offset} for file {file_id}, maximum {maximum}"
            ),
            Self::InvalidCheckpoint {
                file_id,
                checkpoint_id,
                current,
            } => write!(
                f,
                "checkpoint {checkpoint_id} for file {file_id} is older than {current}"
            ),
            Self::InvalidStream { file_id, stream_id } => {
                write!(f, "stream {stream_id} is invalid for file {file_id}")
            }
            Self::InvalidDataOffset {
                file_id,
                expected,
                actual,
            } => write!(
                f,
                "data offset for file {file_id}: expected {expected}, got {actual}"
            ),
            Self::DataExceedsFile {
                file_id,
                offset,
                length,
                maximum,
            } => write!(
                f,
                "data for file {file_id} exceeds size: offset {offset}, length {length}, maximum {maximum}"
            ),
            Self::IntegrityMismatch { file_id } => {
                write!(f, "integrity check failed for file {file_id}")
            }
            Self::ActiveFileLimit { maximum } => {
                write!(f, "active file limit reached: {maximum}")
            }
            Self::PathUnavailable => f.write_str("no usable path is available"),
            Self::InvalidPathTransition => f.write_str("invalid path transition"),
            Self::DuplicateControl => f.write_str("duplicate control message"),
            Self::Cancelled => f.write_str("transfer was cancelled"),
            Self::Channel(message) => write!(f, "channel error: {message}"),
            Self::Storage(message) => write!(f, "storage error: {message}"),
        }
    }
}

impl Error for CoreError {}

impl CoreError {
    pub(crate) fn state(operation: &'static str, state: &'static str) -> Self {
        Self::InvalidState { operation, state }
    }

    pub(crate) fn check_transfer_id(expected: TransferId, actual: TransferId) -> Result<(), Self> {
        if expected == actual {
            Ok(())
        } else {
            Err(Self::InvalidTransferId)
        }
    }
}
