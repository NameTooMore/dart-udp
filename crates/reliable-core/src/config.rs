use core::{fmt, time::Duration};

use udp_protocol::DEFAULT_MAX_DATAGRAM_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Client,
    Server,
}

impl ConnectionRole {
    pub(crate) const fn local_stream_parity(self) -> u64 {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }

    pub(crate) const fn peer_stream_parity(self) -> u64 {
        1 - self.local_stream_parity()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub max_datagram_size: usize,
    pub max_streams: u32,
    pub initial_connection_window: u64,
    pub initial_stream_window: u64,
    pub max_send_buffer: usize,
    pub max_receive_buffer: usize,
    pub initial_congestion_window: u64,
    pub min_congestion_window: u64,
    pub max_congestion_window: u64,
    pub initial_rto: Duration,
    pub min_rto: Duration,
    pub max_rto: Duration,
    pub clock_granularity: Duration,
    pub ack_delay: Duration,
    pub idle_timeout: Duration,
    pub keepalive_interval: Option<Duration>,
    pub handshake_timeout: Duration,
    pub close_timeout: Duration,
    pub max_retransmissions: u32,
    pub fast_loss_threshold: u64,
    pub handshake_cookie: Vec<u8>,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            max_streams: 64,
            initial_connection_window: 4 * 1024 * 1024,
            initial_stream_window: 1024 * 1024,
            max_send_buffer: 4 * 1024 * 1024,
            max_receive_buffer: 4 * 1024 * 1024,
            initial_congestion_window: 10 * 1200,
            min_congestion_window: 1200,
            max_congestion_window: 16 * 1024 * 1024,
            initial_rto: Duration::from_secs(1),
            min_rto: Duration::from_millis(200),
            max_rto: Duration::from_secs(60),
            clock_granularity: Duration::from_millis(10),
            ack_delay: Duration::from_millis(25),
            idle_timeout: Duration::from_secs(30),
            keepalive_interval: Some(Duration::from_secs(10)),
            handshake_timeout: Duration::from_secs(5),
            close_timeout: Duration::from_secs(1),
            max_retransmissions: 8,
            fast_loss_threshold: 3,
            handshake_cookie: Vec::new(),
        }
    }
}

impl ConnectionConfig {
    pub fn validate(&self) -> Result<(), ConnectionConfigError> {
        if self.max_datagram_size < udp_protocol::FIXED_HEADER_LEN {
            return Err(ConnectionConfigError::DatagramSizeTooSmall);
        }
        if self.max_datagram_size > usize::from(u16::MAX) {
            return Err(ConnectionConfigError::DatagramSizeTooLarge);
        }
        if self.max_streams == 0 {
            return Err(ConnectionConfigError::ZeroMaxStreams);
        }
        if self.initial_connection_window == 0 || self.initial_stream_window == 0 {
            return Err(ConnectionConfigError::ZeroWindow);
        }
        if self.max_send_buffer == 0 || self.max_receive_buffer == 0 {
            return Err(ConnectionConfigError::ZeroBuffer);
        }
        if self.min_congestion_window == 0
            || self.initial_congestion_window < self.min_congestion_window
            || self.max_congestion_window < self.initial_congestion_window
        {
            return Err(ConnectionConfigError::InvalidCongestionWindow);
        }
        if self.initial_rto.is_zero()
            || self.min_rto.is_zero()
            || self.max_rto < self.min_rto
            || self.initial_rto < self.min_rto
            || self.initial_rto > self.max_rto
            || self.clock_granularity.is_zero()
        {
            return Err(ConnectionConfigError::InvalidTimeout);
        }
        if self.ack_delay > self.max_rto
            || self.idle_timeout.is_zero()
            || self.handshake_timeout.is_zero()
            || self.close_timeout.is_zero()
            || self.fast_loss_threshold == 0
            || self.handshake_cookie.len() > udp_protocol::MAX_COOKIE_LEN
        {
            return Err(ConnectionConfigError::InvalidTimeout);
        }
        if self
            .keepalive_interval
            .is_some_and(|interval| interval.is_zero() || interval >= self.idle_timeout)
        {
            return Err(ConnectionConfigError::InvalidKeepalive);
        }
        Ok(())
    }

    pub(crate) fn wheel_config(&self) -> Result<time_wheel::WheelConfig, ConnectionConfigError> {
        time_wheel::WheelConfig::builder()
            .base_tick(self.clock_granularity)
            .level_slots(512)
            .level_slots(64)
            .level_slots(64)
            .build()
            .map_err(ConnectionConfigError::Wheel)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionConfigError {
    DatagramSizeTooSmall,
    DatagramSizeTooLarge,
    ZeroMaxStreams,
    ZeroWindow,
    ZeroBuffer,
    InvalidCongestionWindow,
    InvalidTimeout,
    InvalidKeepalive,
    Wheel(time_wheel::ConfigError),
}

impl fmt::Display for ConnectionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatagramSizeTooSmall => f.write_str("maximum datagram size is too small"),
            Self::DatagramSizeTooLarge => f.write_str("maximum datagram size is too large"),
            Self::ZeroMaxStreams => f.write_str("maximum stream count must be greater than zero"),
            Self::ZeroWindow => f.write_str("flow-control windows must be greater than zero"),
            Self::ZeroBuffer => f.write_str("stream buffers must be greater than zero"),
            Self::InvalidCongestionWindow => f.write_str("congestion-window bounds are invalid"),
            Self::InvalidTimeout => f.write_str("timeout configuration is invalid"),
            Self::InvalidKeepalive => f.write_str("keepalive interval is invalid"),
            Self::Wheel(error) => write!(f, "invalid timer-wheel configuration: {error}"),
        }
    }
}

impl std::error::Error for ConnectionConfigError {}
