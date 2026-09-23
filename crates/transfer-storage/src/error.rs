use std::{fmt, io, path::PathBuf};

use transfer_protocol::{Digest, FileId, HashAlgorithm, TransferId};

#[derive(Debug)]
pub enum StorageError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    InvalidRoot,
    InvalidPath {
        path: String,
    },
    PathEscapesRoot {
        path: String,
    },
    SymbolicLinkNotAllowed {
        path: PathBuf,
    },
    UnsupportedFileType {
        path: PathBuf,
    },
    TooManyFiles {
        maximum: usize,
    },
    FileTooLarge {
        file_id: Option<FileId>,
        maximum: u64,
        actual: u64,
    },
    TotalSizeTooLarge {
        maximum: u64,
        actual: u64,
    },
    ManifestPathCollision {
        path: String,
    },
    SourceChanged {
        path: PathBuf,
    },
    RandomnessUnavailable,
    UnknownFile {
        transfer_id: TransferId,
        file_id: FileId,
    },
    InvalidRegistration {
        file_id: FileId,
        reason: &'static str,
    },
    InvalidOffset {
        file_id: FileId,
        offset: u64,
        maximum: u64,
    },
    DataConflict {
        file_id: FileId,
        offset: u64,
    },
    CheckpointRegression {
        file_id: FileId,
    },
    CheckpointCorrupt {
        file_id: FileId,
    },
    IntegrityMismatch {
        file_id: FileId,
        expected: Digest,
        actual: Digest,
    },
    FileIntegrityMismatch {
        expected: Digest,
        actual: Digest,
    },
    SizeMismatch {
        file_id: FileId,
        expected: u64,
        actual: u64,
    },
    AlreadyExists {
        file_id: FileId,
    },
    OverwriteNeedsConfirmation {
        file_id: FileId,
    },
    InvalidHashAlgorithm(HashAlgorithm),
    MalformedState,
    Core(String),
}

impl StorageError {
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(f, "{operation} failed: {source}"),
            Self::InvalidRoot => f.write_str("storage root must be a directory"),
            Self::InvalidPath { path } => write!(f, "invalid relative path: {path}"),
            Self::PathEscapesRoot { path } => {
                write!(f, "relative path escapes storage root: {path}")
            }
            Self::SymbolicLinkNotAllowed { path } => {
                write!(f, "symbolic links are not allowed: {}", path.display())
            }
            Self::UnsupportedFileType { path } => {
                write!(f, "unsupported file type: {}", path.display())
            }
            Self::TooManyFiles { maximum } => {
                write!(f, "manifest contains more than {maximum} files")
            }
            Self::FileTooLarge {
                file_id,
                maximum,
                actual,
            } => write!(f, "file {:?} is too large: {actual} > {maximum}", file_id),
            Self::TotalSizeTooLarge { maximum, actual } => {
                write!(f, "manifest is too large: {actual} > {maximum}")
            }
            Self::ManifestPathCollision { path } => {
                write!(f, "manifest contains duplicate path: {path}")
            }
            Self::SourceChanged { path } => {
                write!(f, "source file changed while hashing: {}", path.display())
            }
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
            Self::UnknownFile {
                transfer_id,
                file_id,
            } => write!(f, "unknown file {file_id} in transfer {transfer_id}"),
            Self::InvalidRegistration { file_id, reason } => {
                write!(f, "invalid registration for file {file_id}: {reason}")
            }
            Self::InvalidOffset {
                file_id,
                offset,
                maximum,
            } => write!(
                f,
                "invalid offset {offset} for file {file_id}, maximum {maximum}"
            ),
            Self::DataConflict { file_id, offset } => {
                write!(
                    f,
                    "data conflicts with existing bytes for file {file_id} at {offset}"
                )
            }
            Self::CheckpointRegression { file_id } => {
                write!(f, "checkpoint regresses for file {file_id}")
            }
            Self::CheckpointCorrupt { file_id } => {
                write!(f, "checkpoint is inconsistent for file {file_id}")
            }
            Self::IntegrityMismatch {
                file_id,
                expected,
                actual,
            } => write!(
                f,
                "integrity check failed for file {file_id}: expected {expected:?}, got {actual:?}"
            ),
            Self::FileIntegrityMismatch { expected, actual } => write!(
                f,
                "integrity check failed: expected {expected:?}, got {actual:?}"
            ),
            Self::SizeMismatch {
                file_id,
                expected,
                actual,
            } => write!(
                f,
                "size check failed for file {file_id}: expected {expected}, got {actual}"
            ),
            Self::AlreadyExists { file_id } => {
                write!(f, "destination already exists for file {file_id}")
            }
            Self::OverwriteNeedsConfirmation { file_id } => {
                write!(f, "overwriting file {file_id} requires confirmation")
            }
            Self::InvalidHashAlgorithm(algorithm) => {
                write!(f, "unsupported hash algorithm: {algorithm:?}")
            }
            Self::MalformedState => f.write_str("checkpoint state is malformed"),
            Self::Core(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
