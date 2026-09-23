use std::{net::SocketAddr, path::PathBuf};

use network_probe::ProbeConfig;
use reliable_udp::EndpointConfig;
use transfer_core::SessionConfig;
use transfer_protocol::{OverwritePolicy, PROTOCOL_VERSION};
use transfer_storage::ManifestBuildConfig;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub endpoint: EndpointConfig,
    pub network: ProbeConfig,
    pub enable_direct: bool,
    pub direct_only: bool,
    pub manifest: ManifestBuildConfig,
    pub session: SessionConfig,
    pub display_name: String,
    pub chunk_size: usize,
    pub checkpoint_interval_bytes: u64,
    pub control_queue_capacity: usize,
}

impl ClientConfig {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            endpoint: EndpointConfig::default(),
            network: ProbeConfig::default(),
            enable_direct: true,
            direct_only: false,
            manifest: ManifestBuildConfig::default(),
            session: SessionConfig {
                max_parallel_files: 1,
                protocol_version: PROTOCOL_VERSION,
                ..SessionConfig::default()
            },
            display_name: "udp-file-client".to_owned(),
            chunk_size: 64 * 1024,
            checkpoint_interval_bytes: 4 * 1024 * 1024,
            control_queue_capacity: 128,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.display_name.len() > transfer_protocol::MAX_DISPLAY_NAME_LEN {
            return Err("display_name");
        }
        if self.chunk_size == 0 || self.chunk_size > 1024 * 1024 {
            return Err("chunk_size");
        }
        if self.checkpoint_interval_bytes == 0 {
            return Err("checkpoint_interval_bytes");
        }
        if self.control_queue_capacity == 0 {
            return Err("control_queue_capacity");
        }
        self.network
            .validate()
            .map_err(|_| "network probe configuration")?;
        Ok(())
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new(SocketAddr::from(([127, 0, 0, 1], 41000)))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PairingOptions {
    pub requested_ttl_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct ReceiveOptions {
    pub root: PathBuf,
    pub overwrite_policy: OverwritePolicy,
    pub target_root_label: String,
    pub sync_data: bool,
    pub sync_all: bool,
}

impl ReceiveOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            overwrite_policy: OverwritePolicy::Ask,
            target_root_label: "default".to_owned(),
            sync_data: true,
            sync_all: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    User,
    Policy,
}

impl RejectReason {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::User => 1,
            Self::Policy => 2,
        }
    }
}
