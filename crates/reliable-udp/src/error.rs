use std::{error::Error, fmt, io};

use reliable_core::{ConnectionConfigError, CoreError};
use udp_protocol::ProtocolError;

use crate::retry::RetryError;

#[derive(Debug)]
pub enum EndpointError {
    Io(io::Error),
    InvalidConfig(ConnectionConfigError),
    Protocol(ProtocolError),
    Core(CoreError),
    Closed,
    InvalidCapacity { field: &'static str },
    ConnectionLimit,
    AcceptQueueFull,
    CommandChannelClosed,
    InvalidRetryConfig,
    RandomnessUnavailable,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "UDP socket error: {error}"),
            Self::InvalidConfig(error) => write!(f, "invalid endpoint configuration: {error}"),
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Core(error) => write!(f, "transport state error: {error}"),
            Self::Closed => f.write_str("endpoint is closed"),
            Self::InvalidCapacity { field } => {
                write!(f, "endpoint capacity must be greater than zero: {field}")
            }
            Self::ConnectionLimit => f.write_str("endpoint connection limit reached"),
            Self::AcceptQueueFull => f.write_str("endpoint accept queue is full"),
            Self::CommandChannelClosed => f.write_str("endpoint task is no longer running"),
            Self::InvalidRetryConfig => f.write_str("retry cookie configuration is invalid"),
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
        }
    }
}

impl Error for EndpointError {}

impl From<io::Error> for EndpointError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ConnectionConfigError> for EndpointError {
    fn from(error: ConnectionConfigError) -> Self {
        Self::InvalidConfig(error)
    }
}

impl From<ProtocolError> for EndpointError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<CoreError> for EndpointError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

impl From<RetryError> for EndpointError {
    fn from(error: RetryError) -> Self {
        match error {
            RetryError::InvalidConfig => Self::InvalidRetryConfig,
            RetryError::RandomnessUnavailable => Self::RandomnessUnavailable,
        }
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Endpoint(EndpointError),
    Core(CoreError),
    ConnectionClosed { error_code: u32 },
    CommandChannelClosed,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(f),
            Self::Core(error) => write!(f, "transport state error: {error}"),
            Self::ConnectionClosed { error_code } => {
                write!(f, "connection closed with error code {error_code}")
            }
            Self::CommandChannelClosed => f.write_str("endpoint task is no longer running"),
        }
    }
}

impl Error for ConnectError {}

impl From<EndpointError> for ConnectError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}

#[derive(Debug)]
pub enum StreamError {
    Core(CoreError),
    ConnectionClosed { error_code: u32 },
    CommandChannelClosed,
    ResponseChannelClosed,
    InvalidState(&'static str),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "stream state error: {error}"),
            Self::ConnectionClosed { error_code } => {
                write!(f, "connection closed with error code {error_code}")
            }
            Self::CommandChannelClosed => f.write_str("endpoint task is no longer running"),
            Self::ResponseChannelClosed => f.write_str("endpoint response channel was closed"),
            Self::InvalidState(operation) => write!(f, "invalid stream state: {operation}"),
        }
    }
}

impl Error for StreamError {}

impl From<CoreError> for StreamError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}
