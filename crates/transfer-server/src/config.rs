use std::{net::SocketAddr, time::Duration};

use reliable_udp::EndpointConfig;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// 单个配对会话允许转发的累计字节数；0 表示不允许转发数据。
    pub max_bytes_per_session: u64,
    /// 服务端生命周期内允许转发的累计字节数；0 表示不限制总量。
    pub max_bytes_total: u64,
    /// 同一配对会话同时转发的 data stream 数量。
    pub max_streams_per_session: usize,
    /// relay 复制缓冲区大小，避免按文件大小分配内存。
    pub buffer_size: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_bytes_per_session: 4 * 1024 * 1024 * 1024,
            max_bytes_total: 0,
            max_streams_per_session: 2,
            buffer_size: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub endpoint: EndpointConfig,
    pub pairing_ttl: Duration,
    pub max_pairings: usize,
    pub max_join_attempts: usize,
    pub max_pending_messages: usize,
    pub relay: RelayConfig,
}

impl ServerConfig {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            endpoint: EndpointConfig::new(bind_addr),
            pairing_ttl: Duration::from_secs(600),
            max_pairings: 1024,
            max_join_attempts: 8,
            max_pending_messages: 1024,
            relay: RelayConfig::default(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.pairing_ttl.is_zero() {
            return Err("pairing_ttl");
        }
        if self.max_pairings == 0 {
            return Err("max_pairings");
        }
        if self.max_join_attempts == 0 {
            return Err("max_join_attempts");
        }
        if self.max_pending_messages == 0 {
            return Err("max_pending_messages");
        }
        if self.relay.max_streams_per_session == 0 {
            return Err("relay.max_streams_per_session");
        }
        if self.relay.buffer_size == 0 {
            return Err("relay.buffer_size");
        }
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new(SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

#[derive(Debug, Default)]
pub(crate) struct ServerCounters {
    pub created_pairings: AtomicU64,
    pub joined_pairings: AtomicU64,
    pub expired_pairings: AtomicU64,
    pub rejected_joins: AtomicU64,
    pub relay_bytes: AtomicU64,
    pub relay_failures: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerMetricsSnapshot {
    pub active_pairings: usize,
    pub created_pairings: u64,
    pub joined_pairings: u64,
    pub expired_pairings: u64,
    pub rejected_joins: u64,
    pub relay_bytes: u64,
    pub relay_failures: u64,
}

#[derive(Debug, Clone)]
pub struct ServerMetrics {
    pub(crate) active_pairings: usize,
    pub(crate) counters: std::sync::Arc<ServerCounters>,
}

impl ServerMetrics {
    pub fn snapshot(&self) -> ServerMetricsSnapshot {
        ServerMetricsSnapshot {
            active_pairings: self.active_pairings,
            created_pairings: self.counters.created_pairings.load(Ordering::Relaxed),
            joined_pairings: self.counters.joined_pairings.load(Ordering::Relaxed),
            expired_pairings: self.counters.expired_pairings.load(Ordering::Relaxed),
            rejected_joins: self.counters.rejected_joins.load(Ordering::Relaxed),
            relay_bytes: self.counters.relay_bytes.load(Ordering::Relaxed),
            relay_failures: self.counters.relay_failures.load(Ordering::Relaxed),
        }
    }
}
