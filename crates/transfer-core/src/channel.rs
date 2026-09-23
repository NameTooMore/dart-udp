use transfer_protocol::{
    Candidate, Digest, FileId, PairingControl, PathId, PathKind, RelayId, SessionTicket,
    TransferControl, TransferId,
};

use crate::{CoreError, DataChunk};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundMessage {
    Pairing(PairingControl),
    Transfer(TransferControl),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelError {
    pub message: String,
}

impl ChannelError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait ControlChannel {
    fn send(&mut self, message: OutboundMessage) -> Result<(), ChannelError>;
}

pub trait DataChannel {
    fn send(&mut self, chunk: DataChunk) -> Result<(), ChannelError>;
}

pub trait Clock {
    fn now_millis(&self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableState {
    pub durable_offset: u64,
    pub checkpoint_id: u64,
    pub state_hash: Digest,
}

pub trait Storage {
    fn durable_state(
        &self,
        transfer_id: TransferId,
        file_id: FileId,
    ) -> Result<DurableState, CoreError>;

    fn write_data(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        absolute_offset: u64,
        data: &[u8],
    ) -> Result<(), CoreError>;

    fn checkpoint(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        state: DurableState,
    ) -> Result<(), CoreError>;

    fn complete_file(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<(), CoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSelection {
    pub path_id: PathId,
    pub kind: PathKind,
    pub rtt_millis: u64,
    pub mtu: u16,
}

pub trait PathSelector {
    fn select(
        &mut self,
        transfer_id: TransferId,
        candidates: &[Candidate],
    ) -> Result<PathSelection, CoreError>;

    fn relay(&mut self, transfer_id: TransferId) -> Result<(RelayId, SessionTicket), CoreError>;
}
