//! 面向集成测试、CLI 和 GUI 的文件传输客户端 API。

mod client;
mod config;
mod error;
mod manifest_files;
mod protocol;
mod resume;
mod transfer;

pub use client::{IncomingOffer, PairingOffer, TransferClient};
pub use config::{ClientConfig, PairingOptions, ReceiveOptions, RejectReason};
pub use error::ClientError;
pub use network_probe::ProbeConfig;
pub use resume::{ResumeSession, ResumeTicket, cleanup_resume_session, list_resume_sessions};
pub use transfer::{TransferEvent, TransferHandle, TransferSummary};
pub use transfer_core::SessionConfig;
pub use transfer_protocol::{OverwritePolicy, PairingCode, TransferRole};
pub use transfer_storage::ManifestBuildConfig;
