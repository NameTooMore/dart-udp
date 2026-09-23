use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    rc::Rc,
};

use transfer_core::{
    ChannelError, ControlChannel, CoreError, DataChannel, DataChunk, DurableState, OutboundMessage,
    PathSelection, PathSelector, Storage,
};
use transfer_protocol::{
    Candidate, Digest, FileId, HashAlgorithm, PathId, RelayId, SessionTicket, TransferId,
};

#[derive(Debug, Clone, Default)]
pub struct InMemoryClock {
    now_millis: u64,
}

impl InMemoryClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_millis(&mut self, now_millis: u64) {
        self.now_millis = now_millis;
    }

    pub fn advance_millis(&mut self, amount: u64) {
        self.now_millis = self.now_millis.saturating_add(amount);
    }
}

impl transfer_core::Clock for InMemoryClock {
    fn now_millis(&self) -> u64 {
        self.now_millis
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryControlChannel {
    messages: VecDeque<OutboundMessage>,
    fail_next: Option<String>,
}

impl InMemoryControlChannel {
    pub fn take(&mut self) -> Vec<OutboundMessage> {
        self.messages.drain(..).collect()
    }

    pub fn replay_last(&mut self) {
        if let Some(message) = self.messages.back().cloned() {
            self.messages.push_back(message);
        }
    }

    pub fn fail_next(&mut self, message: impl Into<String>) {
        self.fail_next = Some(message.into());
    }
}

impl ControlChannel for InMemoryControlChannel {
    fn send(&mut self, message: OutboundMessage) -> Result<(), ChannelError> {
        if let Some(message) = self.fail_next.take() {
            return Err(ChannelError::new(message));
        }
        self.messages.push_back(message);
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryDataChannel {
    chunks: VecDeque<DataChunk>,
    fail_next: Option<String>,
}

impl InMemoryDataChannel {
    pub fn take(&mut self) -> Vec<DataChunk> {
        self.chunks.drain(..).collect()
    }

    pub fn fail_next(&mut self, message: impl Into<String>) {
        self.fail_next = Some(message.into());
    }
}

impl DataChannel for InMemoryDataChannel {
    fn send(&mut self, chunk: DataChunk) -> Result<(), ChannelError> {
        if let Some(message) = self.fail_next.take() {
            return Err(ChannelError::new(message));
        }
        self.chunks.push_back(chunk);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct MemoryFile {
    expected_size: u64,
    expected_hash: Digest,
    bytes: Vec<u8>,
    durable_offset: u64,
    checkpoint_id: u64,
    state_hash: Digest,
    complete: bool,
}

#[derive(Debug, Default)]
pub struct InMemoryStorage {
    files: HashMap<(TransferId, FileId), MemoryFile>,
}

impl InMemoryStorage {
    pub fn register_file(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        size: u64,
        content_hash: Digest,
    ) -> Result<(), CoreError> {
        let capacity = usize::try_from(size).map_err(|_| CoreError::InvalidFileSize { file_id })?;
        self.files.insert(
            (transfer_id, file_id),
            MemoryFile {
                expected_size: size,
                expected_hash: content_hash,
                bytes: vec![0; capacity],
                durable_offset: 0,
                checkpoint_id: 0,
                state_hash: Digest::new(content_hash.algorithm, [0; 32]),
                complete: false,
            },
        );
        Ok(())
    }

    pub fn bytes(&self, transfer_id: TransferId, file_id: FileId) -> Option<&[u8]> {
        self.files
            .get(&(transfer_id, file_id))
            .map(|file| file.bytes.as_slice())
    }

    pub fn is_complete(&self, transfer_id: TransferId, file_id: FileId) -> bool {
        self.files
            .get(&(transfer_id, file_id))
            .is_some_and(|file| file.complete)
    }
}

impl Storage for InMemoryStorage {
    fn durable_state(
        &self,
        transfer_id: TransferId,
        file_id: FileId,
    ) -> Result<DurableState, CoreError> {
        self.files
            .get(&(transfer_id, file_id))
            .map(|file| DurableState {
                durable_offset: file.durable_offset,
                checkpoint_id: file.checkpoint_id,
                state_hash: file.state_hash,
            })
            .ok_or(CoreError::UnknownFile { file_id })
    }

    fn write_data(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        absolute_offset: u64,
        data: &[u8],
    ) -> Result<(), CoreError> {
        let file = self
            .files
            .get_mut(&(transfer_id, file_id))
            .ok_or(CoreError::UnknownFile { file_id })?;
        let end =
            absolute_offset
                .checked_add(data.len() as u64)
                .ok_or(CoreError::DataExceedsFile {
                    file_id,
                    offset: absolute_offset,
                    length: data.len(),
                    maximum: file.expected_size,
                })?;
        if end > file.expected_size {
            return Err(CoreError::DataExceedsFile {
                file_id,
                offset: absolute_offset,
                length: data.len(),
                maximum: file.expected_size,
            });
        }
        let start =
            usize::try_from(absolute_offset).map_err(|_| CoreError::InvalidFileSize { file_id })?;
        file.bytes[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn checkpoint(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        state: DurableState,
    ) -> Result<(), CoreError> {
        let file = self
            .files
            .get_mut(&(transfer_id, file_id))
            .ok_or(CoreError::UnknownFile { file_id })?;
        if state.durable_offset > file.expected_size
            || state.durable_offset < file.durable_offset
            || state.checkpoint_id < file.checkpoint_id
            || (state.checkpoint_id == file.checkpoint_id
                && state.durable_offset != file.durable_offset)
        {
            return Err(CoreError::InvalidCheckpoint {
                file_id,
                checkpoint_id: state.checkpoint_id,
                current: file.checkpoint_id,
            });
        }
        file.durable_offset = state.durable_offset;
        file.checkpoint_id = state.checkpoint_id;
        file.state_hash = state.state_hash;
        Ok(())
    }

    fn complete_file(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<(), CoreError> {
        let file = self
            .files
            .get_mut(&(transfer_id, file_id))
            .ok_or(CoreError::UnknownFile { file_id })?;
        if final_size != file.expected_size
            || content_hash != file.expected_hash
            || file.durable_offset != file.expected_size
        {
            return Err(CoreError::IntegrityMismatch { file_id });
        }
        file.complete = true;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct LinkState {
    a_to_b_control: VecDeque<OutboundMessage>,
    b_to_a_control: VecDeque<OutboundMessage>,
    a_to_b_data: VecDeque<DataChunk>,
    b_to_a_data: VecDeque<DataChunk>,
    drop_next_control: usize,
    drop_next_data: usize,
    replay_next_control: bool,
    replay_next_data: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkSide {
    A,
    B,
}

#[derive(Debug, Clone)]
pub struct MemoryEndpoint {
    state: Rc<RefCell<LinkState>>,
    side: LinkSide,
}

#[derive(Debug, Clone)]
pub struct MemoryLink {
    state: Rc<RefCell<LinkState>>,
}

impl MemoryLink {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(LinkState::default())),
        }
    }

    pub fn endpoints(&self) -> (MemoryEndpoint, MemoryEndpoint) {
        (self.endpoint_a(), self.endpoint_b())
    }

    pub fn endpoint_a(&self) -> MemoryEndpoint {
        MemoryEndpoint {
            state: Rc::clone(&self.state),
            side: LinkSide::A,
        }
    }

    pub fn endpoint_b(&self) -> MemoryEndpoint {
        MemoryEndpoint {
            state: Rc::clone(&self.state),
            side: LinkSide::B,
        }
    }

    pub fn drop_next_control(&self, count: usize) {
        self.state.borrow_mut().drop_next_control = count;
    }

    pub fn drop_next_data(&self, count: usize) {
        self.state.borrow_mut().drop_next_data = count;
    }

    pub fn replay_next_control(&self) {
        self.state.borrow_mut().replay_next_control = true;
    }

    pub fn replay_next_data(&self) {
        self.state.borrow_mut().replay_next_data = true;
    }
}

impl Default for MemoryLink {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryEndpoint {
    pub fn take_controls(&mut self) -> Vec<OutboundMessage> {
        let mut state = self.state.borrow_mut();
        let queue = match self.side {
            LinkSide::A => &mut state.b_to_a_control,
            LinkSide::B => &mut state.a_to_b_control,
        };
        queue.drain(..).collect()
    }

    pub fn take_data(&mut self) -> Vec<DataChunk> {
        let mut state = self.state.borrow_mut();
        let queue = match self.side {
            LinkSide::A => &mut state.b_to_a_data,
            LinkSide::B => &mut state.a_to_b_data,
        };
        queue.drain(..).collect()
    }

    fn send_control(&mut self, message: OutboundMessage) {
        let mut state = self.state.borrow_mut();
        if state.drop_next_control > 0 {
            state.drop_next_control -= 1;
            return;
        }
        let replay = state.replay_next_control;
        state.replay_next_control = false;
        let queue = match self.side {
            LinkSide::A => &mut state.a_to_b_control,
            LinkSide::B => &mut state.b_to_a_control,
        };
        queue.push_back(message.clone());
        if replay {
            queue.push_back(message);
        }
    }

    fn send_data(&mut self, chunk: DataChunk) {
        let mut state = self.state.borrow_mut();
        if state.drop_next_data > 0 {
            state.drop_next_data -= 1;
            return;
        }
        let replay = state.replay_next_data;
        state.replay_next_data = false;
        let queue = match self.side {
            LinkSide::A => &mut state.a_to_b_data,
            LinkSide::B => &mut state.b_to_a_data,
        };
        queue.push_back(chunk.clone());
        if replay {
            queue.push_back(chunk);
        }
    }
}

impl ControlChannel for MemoryEndpoint {
    fn send(&mut self, message: OutboundMessage) -> Result<(), ChannelError> {
        self.send_control(message);
        Ok(())
    }
}

impl DataChannel for MemoryEndpoint {
    fn send(&mut self, chunk: DataChunk) -> Result<(), ChannelError> {
        self.send_data(chunk);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MemoryPathSelector {
    direct: Option<PathSelection>,
    relay: Option<(RelayId, SessionTicket)>,
}

impl MemoryPathSelector {
    pub fn direct(path: PathSelection) -> Self {
        Self {
            direct: Some(path),
            relay: None,
        }
    }

    pub fn relay(relay_id: RelayId, ticket: SessionTicket) -> Self {
        Self {
            direct: None,
            relay: Some((relay_id, ticket)),
        }
    }

    pub fn with_fallback(path: PathSelection, relay_id: RelayId, ticket: SessionTicket) -> Self {
        Self {
            direct: Some(path),
            relay: Some((relay_id, ticket)),
        }
    }
}

impl PathSelector for MemoryPathSelector {
    fn select(
        &mut self,
        _transfer_id: TransferId,
        _candidates: &[Candidate],
    ) -> Result<PathSelection, CoreError> {
        self.direct.clone().ok_or(CoreError::PathUnavailable)
    }

    fn relay(&mut self, _transfer_id: TransferId) -> Result<(RelayId, SessionTicket), CoreError> {
        self.relay.clone().ok_or(CoreError::PathUnavailable)
    }
}

pub fn test_digest(byte: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3, [byte; 32])
}

pub fn test_path(byte: u8, kind: transfer_protocol::PathKind) -> PathSelection {
    PathSelection {
        path_id: PathId::from_bytes([byte; 16]),
        kind,
        rtt_millis: 1,
        mtu: 1200,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transfer_core::{
        Clock, Manifest, ManifestEntry, SessionConfig, SessionEvent, SessionState, TransferSession,
    };
    use transfer_protocol::{AcceptDecision, FileMetadata, OverwritePolicy, TransferControl};

    fn ids() -> (TransferId, FileId) {
        (TransferId::from_bytes([1; 16]), FileId::from_bytes([2; 16]))
    }

    struct SessionFixtures {
        offerer: TransferSession,
        accepter: TransferSession,
        transfer_id: TransferId,
        file_id: FileId,
        digest: Digest,
    }

    fn make_sessions() -> SessionFixtures {
        let (transfer_id, file_id) = ids();
        let digest = test_digest(9);
        let entry = ManifestEntry::new(
            file_id,
            "folder/file.bin".to_owned(),
            5,
            digest,
            FileMetadata {
                modified_time_unix_seconds: None,
                mode: None,
            },
        )
        .unwrap();
        let manifest = Manifest::new(test_digest(8), vec![entry]).unwrap();
        let offerer =
            TransferSession::new_offerer(transfer_id, manifest, SessionConfig::default()).unwrap();
        let accepter =
            TransferSession::new_accepter(transfer_id, SessionConfig::default()).unwrap();
        SessionFixtures {
            offerer,
            accepter,
            transfer_id,
            file_id,
            digest,
        }
    }

    fn deliver_transfer(target: &mut TransferSession, messages: Vec<OutboundMessage>) {
        for message in messages {
            match message {
                OutboundMessage::Transfer(message) => target.handle_control(message).unwrap(),
                OutboundMessage::Pairing(message) => target.handle_pairing(message).unwrap(),
            };
        }
    }

    fn prepare_transfer(offerer: &mut TransferSession, accepter: &mut TransferSession) {
        accepter.start().unwrap();
        offerer.start().unwrap();
        let initial = offerer.drain_control();
        deliver_transfer(accepter, initial.clone());
        accepter
            .accept_offer(
                AcceptDecision::Accept,
                OverwritePolicy::NoReplace,
                "downloads".to_owned(),
            )
            .unwrap();
        deliver_transfer(offerer, accepter.drain_control());
        deliver_transfer(accepter, offerer.drain_control());
        deliver_transfer(offerer, accepter.drain_control());
        deliver_transfer(accepter, offerer.drain_control());
    }

    #[test]
    fn completes_transfer_without_tokio() {
        let SessionFixtures {
            mut offerer,
            mut accepter,
            transfer_id,
            file_id,
            digest,
        } = make_sessions();
        let mut storage = InMemoryStorage::default();
        storage
            .register_file(transfer_id, file_id, 5, digest)
            .unwrap();
        prepare_transfer(&mut offerer, &mut accepter);
        let chunk = offerer
            .queue_data(file_id, b"hello".to_vec(), true)
            .unwrap();
        accepter
            .handle_data_with_storage(&mut storage, chunk)
            .unwrap();
        accepter
            .checkpoint_with_storage(&mut storage, file_id, 5, 1, test_digest(7))
            .unwrap();
        accepter
            .complete_file_with_storage(&mut storage, file_id, 5, digest)
            .unwrap();
        deliver_transfer(&mut offerer, accepter.drain_control());
        assert_eq!(offerer.state(), SessionState::Completed);
        assert!(offerer.is_complete());
        assert!(storage.is_complete(transfer_id, file_id));
        assert_eq!(storage.bytes(transfer_id, file_id), Some(&b"hello"[..]));
    }

    #[test]
    fn reconnect_uses_last_durable_offset_and_replayed_data_is_idempotent() {
        let SessionFixtures {
            mut offerer,
            mut accepter,
            transfer_id,
            file_id,
            digest,
        } = make_sessions();
        let mut storage = InMemoryStorage::default();
        storage
            .register_file(transfer_id, file_id, 5, digest)
            .unwrap();
        prepare_transfer(&mut offerer, &mut accepter);
        let first = offerer.queue_data(file_id, b"he".to_vec(), false).unwrap();
        accepter
            .handle_data_with_storage(&mut storage, first.clone())
            .unwrap();
        assert!(matches!(
            accepter.handle_data(first),
            Ok(events) if events.contains(&SessionEvent::DuplicateData { file_id, offset: 0 })
        ));
        accepter
            .checkpoint_with_storage(&mut storage, file_id, 2, 1, test_digest(7))
            .unwrap();
        deliver_transfer(&mut offerer, accepter.drain_control());
        offerer.reconnect().unwrap();
        accepter.reconnect().unwrap();
        deliver_transfer(&mut accepter, offerer.drain_control());
        deliver_transfer(&mut offerer, accepter.drain_control());
        deliver_transfer(&mut accepter, offerer.drain_control());
        let second = offerer.queue_data(file_id, b"llo".to_vec(), true).unwrap();
        accepter
            .handle_data_with_storage(&mut storage, second)
            .unwrap();
        accepter
            .checkpoint_with_storage(&mut storage, file_id, 5, 2, test_digest(6))
            .unwrap();
        accepter
            .complete_file_with_storage(&mut storage, file_id, 5, digest)
            .unwrap();
        deliver_transfer(&mut offerer, accepter.drain_control());
        assert_eq!(offerer.state(), SessionState::Completed);
        assert_eq!(storage.bytes(transfer_id, file_id), Some(&b"hello"[..]));
    }

    #[test]
    fn duplicate_manifest_controls_are_ignored() {
        let SessionFixtures {
            mut offerer,
            mut accepter,
            transfer_id: _transfer_id,
            file_id: _file_id,
            digest: _digest,
        } = make_sessions();
        accepter.start().unwrap();
        offerer.start().unwrap();
        let initial = offerer.drain_control();
        deliver_transfer(&mut accepter, initial.clone());
        for message in initial {
            if let OutboundMessage::Transfer(message) = message {
                let result = accepter.handle_control(message).unwrap();
                assert!(result.contains(&SessionEvent::DuplicateControl));
            }
        }
    }

    #[test]
    fn path_falls_back_to_relay_after_direct_failure() {
        let SessionFixtures {
            mut offerer,
            accepter: _accepter,
            transfer_id,
            file_id: _file_id,
            digest: _digest,
        } = make_sessions();
        let path = test_path(3, transfer_protocol::PathKind::Host);
        let relay_id = RelayId::from_bytes([4; 16]);
        let mut selector =
            MemoryPathSelector::with_fallback(path, relay_id, SessionTicket::new(vec![1, 2, 3]));
        offerer.select_path(&mut selector, &[]).unwrap();
        offerer.mark_path_failed();
        let events = offerer.fallback_to_relay(&mut selector).unwrap();
        assert_eq!(events, vec![SessionEvent::PathFallback { relay_id }]);
        assert!(
            matches!(offerer.path(), transfer_core::PathState::Relay { relay_id: id } if *id == relay_id)
        );
        assert!(offerer
            .drain_control()
            .iter()
            .any(|message| matches!(message, OutboundMessage::Pairing(transfer_protocol::PairingControl::RelayOpen { transfer_id: id, .. }) if *id == transfer_id)));
    }

    #[test]
    fn empty_manifest_reaches_completed_state() {
        let transfer_id = TransferId::from_bytes([5; 16]);
        let manifest = Manifest::new(test_digest(4), Vec::new()).unwrap();
        let mut offerer =
            TransferSession::new_offerer(transfer_id, manifest, SessionConfig::default()).unwrap();
        let mut accepter =
            TransferSession::new_accepter(transfer_id, SessionConfig::default()).unwrap();
        accepter.start().unwrap();
        offerer.start().unwrap();
        deliver_transfer(&mut accepter, offerer.drain_control());
        accepter
            .accept_offer(
                AcceptDecision::Accept,
                OverwritePolicy::NoReplace,
                "downloads".to_owned(),
            )
            .unwrap();
        deliver_transfer(&mut offerer, accepter.drain_control());
        assert_eq!(offerer.state(), SessionState::Completed);
        assert!(offerer.is_complete());
    }

    #[test]
    fn memory_link_can_drop_and_replay_messages() {
        let link = MemoryLink::new();
        let (mut a, mut b) = link.endpoints();
        link.drop_next_control(1);
        ControlChannel::send(
            &mut a,
            OutboundMessage::Transfer(TransferControl::ManifestEnd {
                manifest_digest: test_digest(1),
            }),
        )
        .unwrap();
        assert!(b.take_controls().is_empty());
        link.replay_next_control();
        ControlChannel::send(
            &mut a,
            OutboundMessage::Transfer(TransferControl::ManifestEnd {
                manifest_digest: test_digest(1),
            }),
        )
        .unwrap();
        assert_eq!(b.take_controls().len(), 2);
        let mut clock = InMemoryClock::new();
        clock.advance_millis(10);
        assert_eq!(clock.now_millis(), 10);
    }
}
