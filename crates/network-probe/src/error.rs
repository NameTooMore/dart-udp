use std::{error::Error, fmt, io};

use transfer_protocol::{CandidateId, ProtocolError};

#[derive(Debug)]
pub enum ProbeError {
    InvalidConfig(&'static str),
    Io(io::Error),
    Protocol(ProtocolError),
    RandomnessUnavailable,
    NoCandidates,
    AuthorizationExpired,
    UnauthorizedCheck,
    InvalidCandidate(CandidateId),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(field) => write!(f, "invalid probe configuration: {field}"),
            Self::Io(error) => write!(f, "probe I/O error: {error}"),
            Self::Protocol(error) => write!(f, "probe protocol error: {error}"),
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
            Self::NoCandidates => f.write_str("no usable network candidate is available"),
            Self::AuthorizationExpired => f.write_str("path check authorization has expired"),
            Self::UnauthorizedCheck => f.write_str("path check is not authorized"),
            Self::InvalidCandidate(id) => write!(f, "invalid network candidate {id}"),
        }
    }
}

impl Error for ProbeError {}

impl From<io::Error> for ProbeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for ProbeError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    NoSuccessfulDirectPath,
    RandomnessUnavailable,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuccessfulDirectPath => f.write_str("no successful direct path is available"),
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
        }
    }
}

impl Error for SelectionError {}
