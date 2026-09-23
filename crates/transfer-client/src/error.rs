use std::{error::Error, fmt, io};

use network_probe::ProbeError;
use reliable_udp::{ConnectError, EndpointError, StreamError};
use transfer_core::CoreError;
use transfer_protocol::ProtocolError;
use transfer_storage::StorageError;

#[derive(Debug)]
pub enum ClientError {
    InvalidConfig(&'static str),
    Endpoint(EndpointError),
    Connect(ConnectError),
    Stream(StreamError),
    Protocol(ProtocolError),
    Core(CoreError),
    Storage(StorageError),
    Io(io::Error),
    Probe(ProbeError),
    RandomnessUnavailable,
    ResumeTicketExpired,
    DirectPathUnavailable,
    Server { code: u32, message: String },
    InvalidState(&'static str),
    Cancelled,
    Closed,
    TaskJoin(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(field) => write!(f, "invalid client configuration: {field}"),
            Self::Endpoint(error) => write!(f, "client endpoint error: {error}"),
            Self::Connect(error) => write!(f, "client connection error: {error}"),
            Self::Stream(error) => write!(f, "client stream error: {error}"),
            Self::Protocol(error) => write!(f, "transfer protocol error: {error}"),
            Self::Core(error) => write!(f, "transfer state error: {error}"),
            Self::Storage(error) => write!(f, "transfer storage error: {error}"),
            Self::Io(error) => write!(f, "client I/O error: {error}"),
            Self::Probe(error) => write!(f, "network probe error: {error}"),
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
            Self::ResumeTicketExpired => f.write_str("resume ticket has expired"),
            Self::DirectPathUnavailable => f.write_str("direct network path is unavailable"),
            Self::Server { code, message } => write!(f, "server error {code}: {message}"),
            Self::InvalidState(operation) => write!(f, "invalid client state: {operation}"),
            Self::Cancelled => f.write_str("transfer was cancelled"),
            Self::Closed => f.write_str("server connection was closed"),
            Self::TaskJoin(error) => write!(f, "transfer task failed: {error}"),
        }
    }
}

impl Error for ClientError {}

impl From<EndpointError> for ClientError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}

impl From<ConnectError> for ClientError {
    fn from(error: ConnectError) -> Self {
        Self::Connect(error)
    }
}

impl From<StreamError> for ClientError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<ProtocolError> for ClientError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<CoreError> for ClientError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

impl From<StorageError> for ClientError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProbeError> for ClientError {
    fn from(error: ProbeError) -> Self {
        Self::Probe(error)
    }
}
