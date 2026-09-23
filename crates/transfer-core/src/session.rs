use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

use transfer_protocol::{
    AcceptDecision, Candidate, CryptoSuite, Digest, FileId, FileRejectReason, MAX_MANIFEST_FILES,
    MessageFlags, OverwritePolicy, PROTOCOL_VERSION, PairingControl, RelayCloseReason,
    TransferControl, TransferErrorScope, TransferId,
};

use crate::{
    Clock, PathSelection, PathSelector,
    channel::{ControlChannel, DataChannel, DurableState, OutboundMessage, Storage},
    error::CoreError,
    manifest::{Manifest, ManifestEntry},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Offerer,
    Accepter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    New,
    AwaitingHello,
    SendingManifest,
    ReceivingManifest,
    AwaitingDecision,
    AwaitingResume,
    SendingData,
    ReceivingData,
    AwaitingTransferComplete,
    Completed,
    Rejected,
    Cancelled,
    Failed,
}

impl SessionState {
    pub const fn name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::AwaitingHello => "awaiting hello",
            Self::SendingManifest => "sending manifest",
            Self::ReceivingManifest => "receiving manifest",
            Self::AwaitingDecision => "awaiting decision",
            Self::AwaitingResume => "awaiting resume",
            Self::SendingData => "sending data",
            Self::ReceivingData => "receiving data",
            Self::AwaitingTransferComplete => "awaiting transfer complete",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub max_parallel_files: usize,
    pub protocol_version: u8,
    pub crypto_suite: CryptoSuite,
    pub first_data_stream_id: u64,
    pub idle_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_parallel_files: 2,
            protocol_version: PROTOCOL_VERSION,
            crypto_suite: CryptoSuite::X25519ChaCha20Poly1305,
            first_data_stream_id: 1,
            idle_timeout: Duration::from_secs(60),
        }
    }
}

impl SessionConfig {
    fn validate(&self) -> Result<(), CoreError> {
        if self.max_parallel_files == 0
            || self.first_data_stream_id == 0
            || self.idle_timeout.is_zero()
        {
            return Err(CoreError::InvalidState {
                operation: "create session",
                state: "invalid configuration",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChunk {
    pub file_id: FileId,
    pub stream_id: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub fin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProgress {
    pub file_id: FileId,
    pub durable_offset: u64,
    pub received_offset: u64,
    pub checkpoint_id: u64,
    pub active_stream_id: Option<u64>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    Unselected,
    Direct(PathSelection),
    Relay {
        relay_id: transfer_protocol::RelayId,
    },
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    StateChanged {
        from: SessionState,
        to: SessionState,
    },
    DataReceived {
        file_id: FileId,
        absolute_offset: u64,
        bytes: Vec<u8>,
        fin: bool,
    },
    DuplicateData {
        file_id: FileId,
        offset: u64,
    },
    DuplicateControl,
    Checkpointed {
        file_id: FileId,
        durable_offset: u64,
        checkpoint_id: u64,
    },
    FileReadyToComplete {
        file_id: FileId,
    },
    FileCompleted {
        file_id: FileId,
    },
    TransferCompleted,
    PathSelected {
        path: PathSelection,
    },
    PathFallback {
        relay_id: transfer_protocol::RelayId,
    },
}

#[derive(Debug, Clone)]
struct FileRuntime {
    entry: ManifestEntry,
    durable_offset: u64,
    received_offset: u64,
    checkpoint_id: u64,
    state_hash: Digest,
    active_stream_id: Option<u64>,
    base_offset: u64,
    send_offset: u64,
    fin_queued: bool,
    awaiting_finish: bool,
    complete: bool,
}

impl FileRuntime {
    fn new(entry: ManifestEntry, zero_digest: Digest) -> Self {
        Self {
            entry,
            durable_offset: 0,
            received_offset: 0,
            checkpoint_id: 0,
            state_hash: zero_digest,
            active_stream_id: None,
            base_offset: 0,
            send_offset: 0,
            fin_queued: false,
            awaiting_finish: false,
            complete: false,
        }
    }

    fn progress(&self) -> FileProgress {
        FileProgress {
            file_id: self.entry.file_id,
            durable_offset: self.durable_offset,
            received_offset: self.received_offset,
            checkpoint_id: self.checkpoint_id,
            active_stream_id: self.active_stream_id,
            complete: self.complete,
        }
    }
}

#[derive(Debug, Clone)]
struct ManifestAssembly {
    expected_count: u64,
    expected_size: u64,
    digest: Digest,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone)]
pub struct TransferSession {
    role: SessionRole,
    transfer_id: TransferId,
    config: SessionConfig,
    state: SessionState,
    manifest: Option<Manifest>,
    remote_manifest_digest: Option<Digest>,
    receive_decision: Option<bool>,
    assembly: Option<ManifestAssembly>,
    files: BTreeMap<FileId, FileRuntime>,
    pending_resumes: BTreeMap<FileId, DurableState>,
    completed_files: u64,
    completed_size: u64,
    next_stream_id: u64,
    controls: VecDeque<OutboundMessage>,
    data: VecDeque<DataChunk>,
    path: PathState,
    last_activity_millis: u64,
}

impl TransferSession {
    pub fn new_offerer(
        transfer_id: TransferId,
        manifest: Manifest,
        config: SessionConfig,
    ) -> Result<Self, CoreError> {
        config.validate()?;
        let mut session = Self::empty(SessionRole::Offerer, transfer_id, config);
        session.install_manifest(manifest)?;
        Ok(session)
    }

    pub fn new_accepter(transfer_id: TransferId, config: SessionConfig) -> Result<Self, CoreError> {
        config.validate()?;
        Ok(Self::empty(SessionRole::Accepter, transfer_id, config))
    }

    fn empty(role: SessionRole, transfer_id: TransferId, config: SessionConfig) -> Self {
        Self {
            role,
            transfer_id,
            next_stream_id: config.first_data_stream_id,
            config,
            state: SessionState::New,
            manifest: None,
            remote_manifest_digest: None,
            receive_decision: None,
            assembly: None,
            files: BTreeMap::new(),
            pending_resumes: BTreeMap::new(),
            completed_files: 0,
            completed_size: 0,
            controls: VecDeque::new(),
            data: VecDeque::new(),
            path: PathState::Unselected,
            last_activity_millis: 0,
        }
    }

    fn install_manifest(&mut self, manifest: Manifest) -> Result<(), CoreError> {
        let zero_digest = Digest::new(manifest.digest().algorithm, [0; 32]);
        self.files = manifest
            .entries()
            .iter()
            .cloned()
            .map(|entry| (entry.file_id, FileRuntime::new(entry, zero_digest)))
            .collect();
        self.manifest = Some(manifest);
        Ok(())
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn path(&self) -> &PathState {
        &self.path
    }

    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    pub fn file_progress(&self, file_id: FileId) -> Result<FileProgress, CoreError> {
        self.files
            .get(&file_id)
            .map(FileRuntime::progress)
            .ok_or(CoreError::UnknownFile { file_id })
    }

    pub fn drain_control(&mut self) -> Vec<OutboundMessage> {
        self.controls.drain(..).collect()
    }

    pub fn drain_data(&mut self) -> Vec<DataChunk> {
        self.data.drain(..).collect()
    }

    pub fn start(&mut self) -> Result<Vec<SessionEvent>, CoreError> {
        if self.state != SessionState::New {
            return Err(CoreError::state("start", self.state.name()));
        }
        match self.role {
            SessionRole::Offerer => self.start_offerer(),
            SessionRole::Accepter => Ok(self.change_state(SessionState::AwaitingHello)),
        }
    }

    fn start_offerer(&mut self) -> Result<Vec<SessionEvent>, CoreError> {
        let manifest = self
            .manifest
            .as_ref()
            .ok_or(CoreError::ManifestRequired)?
            .clone();
        let mut events = self.change_state(SessionState::SendingManifest);
        self.queue_transfer(TransferControl::SessionHello {
            transfer_id: self.transfer_id,
            protocol_version: self.config.protocol_version,
            crypto_suite: self.config.crypto_suite,
            manifest_digest: manifest.digest(),
            resume_namespace: *self.transfer_id.as_bytes(),
        });
        self.queue_transfer(TransferControl::ManifestBegin {
            file_count: manifest.file_count(),
            total_size: manifest.total_size(),
            manifest_digest: manifest.digest(),
        });
        for entry in manifest.entries() {
            self.queue_transfer(TransferControl::ManifestItem {
                file_id: entry.file_id,
                relative_path: entry.relative_path.clone(),
                size: entry.size,
                content_hash: entry.content_hash,
                metadata: entry.metadata,
            });
        }
        self.queue_transfer(TransferControl::ManifestEnd {
            manifest_digest: manifest.digest(),
        });
        events.extend(self.change_state(SessionState::AwaitingDecision));
        Ok(events)
    }

    pub fn accept_offer(
        &mut self,
        decision: AcceptDecision,
        overwrite_policy: OverwritePolicy,
        target_root_label: String,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "accept offer")?;
        if self.state != SessionState::AwaitingDecision {
            return Err(CoreError::state("accept offer", self.state.name()));
        }
        let accepted = decision == AcceptDecision::Accept;
        self.queue_transfer(TransferControl::ReceiveDecision {
            accepted,
            overwrite_policy,
            target_root_label,
        });
        if !accepted {
            return Ok(self.change_state(SessionState::Rejected));
        }

        let mut events = self.change_state(SessionState::AwaitingResume);
        if self.files.is_empty() {
            self.queue_transfer(TransferControl::TransferComplete {
                transfer_id: self.transfer_id,
                completed_files: 0,
                total_size: 0,
            });
            events.extend(self.change_state(SessionState::Completed));
        }
        Ok(events)
    }

    pub fn reject_offer(&mut self, reason_code: u16) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "reject offer")?;
        if self.state != SessionState::AwaitingDecision {
            return Err(CoreError::state("reject offer", self.state.name()));
        }
        self.queue_pairing(PairingControl::Cancel {
            transfer_id: self.transfer_id,
            reason_code,
        });
        Ok(self.change_state(SessionState::Rejected))
    }

    pub fn handle_control(
        &mut self,
        message: TransferControl,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        let events = match message {
            TransferControl::SessionHello {
                transfer_id,
                protocol_version,
                crypto_suite,
                manifest_digest,
                ..
            } => self.handle_session_hello(
                transfer_id,
                protocol_version,
                crypto_suite,
                manifest_digest,
            )?,
            TransferControl::ManifestBegin {
                file_count,
                total_size,
                manifest_digest,
            } => self.handle_manifest_begin(file_count, total_size, manifest_digest)?,
            TransferControl::ManifestItem {
                file_id,
                relative_path,
                size,
                content_hash,
                metadata,
            } => self.handle_manifest_item(ManifestEntry::new(
                file_id,
                relative_path,
                size,
                content_hash,
                metadata,
            )?)?,
            TransferControl::ManifestEnd { manifest_digest } => {
                self.handle_manifest_end(manifest_digest)?
            }
            TransferControl::ReceiveDecision {
                accepted,
                overwrite_policy: _,
                target_root_label: _,
            } => self.handle_receive_decision(accepted)?,
            TransferControl::ResumeQuery {
                file_id,
                content_hash,
                size,
            } => self.handle_resume_query(file_id, content_hash, size)?,
            TransferControl::ResumeState {
                file_id,
                durable_offset,
                checkpoint_id,
                state_hash,
            } => self.handle_resume_state(
                file_id,
                DurableState {
                    durable_offset,
                    checkpoint_id,
                    state_hash,
                },
            )?,
            TransferControl::FileBegin {
                file_id,
                data_stream_id,
                base_offset,
                remaining_size,
                content_hash,
            } => self.handle_file_begin(
                file_id,
                data_stream_id,
                base_offset,
                remaining_size,
                content_hash,
            )?,
            TransferControl::Checkpoint {
                file_id,
                durable_offset,
                checkpoint_id,
            } => self.handle_remote_checkpoint(file_id, durable_offset, checkpoint_id)?,
            TransferControl::FileComplete {
                file_id,
                final_size,
                content_hash,
            } => self.handle_file_complete_ack(file_id, final_size, content_hash)?,
            TransferControl::FileRejected { file_id, reason } => {
                self.handle_file_rejected(file_id, reason)?
            }
            TransferControl::TransferComplete {
                transfer_id,
                completed_files,
                total_size,
            } => self.handle_transfer_complete(transfer_id, completed_files, total_size)?,
            TransferControl::TransferError {
                scope,
                code,
                retryable,
                message,
            } => self.handle_transfer_error(scope, code, retryable, message)?,
        };
        Ok(events)
    }

    fn handle_session_hello(
        &mut self,
        transfer_id: TransferId,
        protocol_version: u8,
        crypto_suite: CryptoSuite,
        manifest_digest: Digest,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "handle session hello")?;
        CoreError::check_transfer_id(self.transfer_id, transfer_id)?;
        if self.remote_manifest_digest == Some(manifest_digest)
            && self.state != SessionState::AwaitingHello
        {
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        if self.state != SessionState::AwaitingHello {
            return Err(CoreError::state("handle session hello", self.state.name()));
        }
        if protocol_version != self.config.protocol_version {
            return Err(CoreError::ProtocolVersionMismatch {
                expected: self.config.protocol_version,
                actual: protocol_version,
            });
        }
        if crypto_suite != self.config.crypto_suite {
            return Err(CoreError::CryptoSuiteMismatch);
        }
        self.remote_manifest_digest = Some(manifest_digest);
        Ok(self.change_state(SessionState::ReceivingManifest))
    }

    fn handle_manifest_begin(
        &mut self,
        file_count: u64,
        total_size: u64,
        digest: Digest,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "handle manifest begin")?;
        if self.state != SessionState::ReceivingManifest {
            if self
                .manifest
                .as_ref()
                .is_some_and(|manifest| manifest.digest() == digest)
            {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::state("handle manifest begin", self.state.name()));
        }
        if self.remote_manifest_digest != Some(digest) {
            return Err(CoreError::ManifestMismatch);
        }
        if file_count > MAX_MANIFEST_FILES as u64 {
            return Err(CoreError::ManifestCountMismatch {
                expected: MAX_MANIFEST_FILES as u64,
                actual: usize::try_from(file_count).unwrap_or(usize::MAX),
            });
        }
        self.assembly = Some(ManifestAssembly {
            expected_count: file_count,
            expected_size: total_size,
            digest,
            entries: Vec::new(),
        });
        Ok(Vec::new())
    }

    fn handle_manifest_item(
        &mut self,
        entry: ManifestEntry,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "handle manifest item")?;
        let Some(assembly) = self.assembly.as_mut() else {
            if self
                .manifest
                .as_ref()
                .and_then(|manifest| manifest.entry(entry.file_id))
                .is_some_and(|existing| existing == &entry)
            {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::ManifestNotReady);
        };
        if assembly.entries.len() as u64 >= assembly.expected_count {
            return Err(CoreError::ManifestCountMismatch {
                expected: assembly.expected_count,
                actual: assembly.entries.len() + 1,
            });
        }
        if let Some(existing) = assembly
            .entries
            .iter()
            .find(|item| item.file_id == entry.file_id)
        {
            if existing == &entry {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::DuplicateFile {
                file_id: entry.file_id,
            });
        }
        assembly.entries.push(entry);
        Ok(Vec::new())
    }

    fn handle_manifest_end(&mut self, digest: Digest) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "handle manifest end")?;
        let Some(assembly) = self.assembly.take() else {
            if self
                .manifest
                .as_ref()
                .is_some_and(|manifest| manifest.digest() == digest)
            {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::ManifestNotReady);
        };
        if digest != assembly.digest {
            return Err(CoreError::ManifestMismatch);
        }
        if assembly.entries.len() as u64 != assembly.expected_count {
            return Err(CoreError::ManifestCountMismatch {
                expected: assembly.expected_count,
                actual: assembly.entries.len(),
            });
        }
        let actual_size = assembly.entries.iter().try_fold(0_u64, |sum, entry| {
            sum.checked_add(entry.size)
                .ok_or(CoreError::InvalidFileSize {
                    file_id: entry.file_id,
                })
        })?;
        if actual_size != assembly.expected_size {
            return Err(CoreError::ManifestSizeMismatch {
                expected: assembly.expected_size,
                actual: actual_size,
            });
        }
        let manifest = Manifest::new(digest, assembly.entries)?;
        self.install_manifest(manifest)?;
        Ok(self.change_state(SessionState::AwaitingDecision))
    }

    fn handle_receive_decision(&mut self, accepted: bool) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Offerer, "handle receive decision")?;
        if self.state != SessionState::AwaitingDecision {
            if self.receive_decision == Some(accepted)
                || (self.state == SessionState::AwaitingResume && accepted)
            {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::state(
                "handle receive decision",
                self.state.name(),
            ));
        }
        self.receive_decision = Some(accepted);
        if !accepted {
            return Ok(self.change_state(SessionState::Rejected));
        }
        let entries = self
            .manifest
            .as_ref()
            .ok_or(CoreError::ManifestRequired)?
            .entries()
            .to_vec();
        for entry in entries {
            self.queue_transfer(TransferControl::ResumeQuery {
                file_id: entry.file_id,
                content_hash: entry.content_hash,
                size: entry.size,
            });
        }
        let mut events = self.change_state(SessionState::AwaitingResume);
        if self.files.is_empty() {
            events.extend(self.change_state(SessionState::AwaitingTransferComplete));
        }
        Ok(events)
    }

    fn handle_resume_query(
        &mut self,
        file_id: FileId,
        content_hash: Digest,
        size: u64,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "handle resume query")?;
        let file = self.file(&file_id)?;
        if file.entry.content_hash != content_hash || file.entry.size != size {
            return Err(CoreError::ManifestMismatch);
        }
        if file.complete {
            self.queue_transfer(TransferControl::FileComplete {
                file_id,
                final_size: file.entry.size,
                content_hash: file.entry.content_hash,
            });
            self.queue_transfer(TransferControl::TransferComplete {
                transfer_id: self.transfer_id,
                completed_files: self.completed_files,
                total_size: self.completed_size,
            });
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        if !matches!(
            self.state,
            SessionState::AwaitingResume | SessionState::ReceivingData
        ) {
            if self.files.get(&file_id).is_some_and(|file| file.complete) {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::state("handle resume query", self.state.name()));
        }
        self.queue_transfer(TransferControl::ResumeState {
            file_id,
            durable_offset: file.durable_offset,
            checkpoint_id: file.checkpoint_id,
            state_hash: file.state_hash,
        });
        Ok(Vec::new())
    }

    fn handle_resume_state(
        &mut self,
        file_id: FileId,
        state: DurableState,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Offerer, "handle resume state")?;
        if !matches!(
            self.state,
            SessionState::AwaitingResume
                | SessionState::SendingData
                | SessionState::AwaitingTransferComplete
        ) {
            return Err(CoreError::state("handle resume state", self.state.name()));
        }
        let file = self.file(&file_id)?;
        validate_offset(file_id, state.durable_offset, file.entry.size)?;
        if file.complete {
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        if state.checkpoint_id < file.checkpoint_id
            || (state.checkpoint_id == file.checkpoint_id
                && state.durable_offset != file.durable_offset)
        {
            return Err(CoreError::InvalidCheckpoint {
                file_id,
                checkpoint_id: state.checkpoint_id,
                current: file.checkpoint_id,
            });
        }
        if state.checkpoint_id == file.checkpoint_id
            && state.durable_offset == file.durable_offset
            && state.state_hash == file.state_hash
            && file.active_stream_id.is_some()
        {
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        let file = self.file_mut(&file_id)?;
        file.durable_offset = state.durable_offset;
        file.checkpoint_id = state.checkpoint_id;
        file.state_hash = state.state_hash;
        self.pending_resumes.insert(file_id, state);
        self.start_pending_files()
    }

    fn start_pending_files(&mut self) -> Result<Vec<SessionEvent>, CoreError> {
        let mut events = Vec::new();
        while self.active_file_count() < self.config.max_parallel_files {
            let Some(file_id) = self.pending_resumes.keys().next().copied() else {
                break;
            };
            self.pending_resumes.remove(&file_id);
            events.extend(self.start_file(file_id)?);
        }
        if self.active_file_count() > 0 && self.state == SessionState::AwaitingResume {
            events.extend(self.change_state(SessionState::SendingData));
        }
        Ok(events)
    }

    fn start_file(&mut self, file_id: FileId) -> Result<Vec<SessionEvent>, CoreError> {
        let stream_id = self.allocate_stream_id()?;
        let (base_offset, remaining_size, content_hash) = {
            let file = self.file_mut(&file_id)?;
            if file.active_stream_id.is_some() || file.complete {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            file.active_stream_id = Some(stream_id);
            file.base_offset = file.durable_offset;
            file.send_offset = 0;
            file.fin_queued = file.entry.size == file.base_offset;
            (
                file.base_offset,
                file.entry.size - file.base_offset,
                file.entry.content_hash,
            )
        };
        self.queue_transfer(TransferControl::FileBegin {
            file_id,
            data_stream_id: stream_id,
            base_offset,
            remaining_size,
            content_hash,
        });
        Ok(Vec::new())
    }

    pub fn queue_data(
        &mut self,
        file_id: FileId,
        bytes: Vec<u8>,
        fin: bool,
    ) -> Result<DataChunk, CoreError> {
        self.require_role(SessionRole::Offerer, "queue data")?;
        let file = self.file_mut(&file_id)?;
        let stream_id = file.active_stream_id.ok_or(CoreError::InvalidStream {
            file_id,
            stream_id: 0,
        })?;
        let remaining = file.entry.size - file.base_offset;
        let new_offset =
            file.send_offset
                .checked_add(bytes.len() as u64)
                .ok_or(CoreError::DataExceedsFile {
                    file_id,
                    offset: file.send_offset,
                    length: bytes.len(),
                    maximum: remaining,
                })?;
        if new_offset > remaining || (fin && new_offset != remaining) {
            return Err(CoreError::DataExceedsFile {
                file_id,
                offset: file.send_offset,
                length: bytes.len(),
                maximum: remaining,
            });
        }
        if file.fin_queued {
            return Err(CoreError::InvalidState {
                operation: "queue data",
                state: "file already finished",
            });
        }
        file.send_offset = new_offset;
        file.fin_queued = fin;
        let chunk = DataChunk {
            file_id,
            stream_id,
            offset: new_offset - bytes.len() as u64,
            bytes,
            fin,
        };
        self.data.push_back(chunk.clone());
        Ok(chunk)
    }

    fn handle_file_begin(
        &mut self,
        file_id: FileId,
        stream_id: u64,
        base_offset: u64,
        remaining_size: u64,
        content_hash: Digest,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "handle file begin")?;
        let file = self.file(&file_id)?;
        if file.complete {
            let final_size = file.entry.size;
            let content_hash = file.entry.content_hash;
            let completed_files = self.completed_files;
            let total_size = self.completed_size;
            self.queue_transfer(TransferControl::FileComplete {
                file_id,
                final_size,
                content_hash,
            });
            self.queue_transfer(TransferControl::TransferComplete {
                transfer_id: self.transfer_id,
                completed_files,
                total_size,
            });
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        validate_offset(file_id, base_offset, file.entry.size)?;
        if content_hash != file.entry.content_hash
            || remaining_size != file.entry.size - base_offset
        {
            return Err(CoreError::ManifestMismatch);
        }
        if let Some(active_stream_id) = file.active_stream_id {
            if active_stream_id == stream_id && file.base_offset == base_offset {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::InvalidStream { file_id, stream_id });
        }
        if self.active_file_count() >= self.config.max_parallel_files {
            return Err(CoreError::ActiveFileLimit {
                maximum: self.config.max_parallel_files,
            });
        }
        if base_offset != file.durable_offset {
            return Err(CoreError::InvalidOffset {
                file_id,
                offset: base_offset,
                maximum: file.durable_offset,
            });
        }
        let file = self.file_mut(&file_id)?;
        file.active_stream_id = Some(stream_id);
        file.base_offset = base_offset;
        file.received_offset = base_offset;
        file.awaiting_finish = remaining_size == 0;
        Ok(self.change_state(SessionState::ReceivingData))
    }

    pub fn handle_data(&mut self, chunk: DataChunk) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "handle data")?;
        let file = self.file_mut(&chunk.file_id)?;
        let active_stream_id = file.active_stream_id.ok_or(CoreError::InvalidStream {
            file_id: chunk.file_id,
            stream_id: chunk.stream_id,
        })?;
        if active_stream_id != chunk.stream_id {
            return Err(CoreError::InvalidStream {
                file_id: chunk.file_id,
                stream_id: chunk.stream_id,
            });
        }
        let expected = file.received_offset - file.base_offset;
        let end = chunk.offset.checked_add(chunk.bytes.len() as u64).ok_or(
            CoreError::DataExceedsFile {
                file_id: chunk.file_id,
                offset: chunk.offset,
                length: chunk.bytes.len(),
                maximum: file.entry.size - file.base_offset,
            },
        )?;
        let remaining = file.entry.size - file.base_offset;
        if end > remaining {
            return Err(CoreError::DataExceedsFile {
                file_id: chunk.file_id,
                offset: chunk.offset,
                length: chunk.bytes.len(),
                maximum: remaining,
            });
        }
        if chunk.offset < expected && end <= expected {
            return Ok(vec![SessionEvent::DuplicateData {
                file_id: chunk.file_id,
                offset: chunk.offset,
            }]);
        }
        if chunk.offset != expected {
            return Err(CoreError::InvalidDataOffset {
                file_id: chunk.file_id,
                expected,
                actual: chunk.offset,
            });
        }
        file.received_offset = file.base_offset + end;
        if chunk.fin {
            if file.received_offset != file.entry.size {
                return Err(CoreError::InvalidOffset {
                    file_id: chunk.file_id,
                    offset: file.received_offset,
                    maximum: file.entry.size,
                });
            }
            file.awaiting_finish = true;
        }
        let event = SessionEvent::DataReceived {
            file_id: chunk.file_id,
            absolute_offset: file.base_offset + chunk.offset,
            bytes: chunk.bytes,
            fin: chunk.fin,
        };
        if file.awaiting_finish {
            Ok(vec![
                event,
                SessionEvent::FileReadyToComplete {
                    file_id: chunk.file_id,
                },
            ])
        } else {
            Ok(vec![event])
        }
    }

    pub fn checkpoint(
        &mut self,
        file_id: FileId,
        durable_offset: u64,
        checkpoint_id: u64,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "checkpoint")?;
        let file = self.file_mut(&file_id)?;
        validate_offset(file_id, durable_offset, file.received_offset)?;
        if checkpoint_id < file.checkpoint_id
            || durable_offset < file.durable_offset
            || (checkpoint_id == file.checkpoint_id && durable_offset != file.durable_offset)
        {
            return Err(CoreError::InvalidCheckpoint {
                file_id,
                checkpoint_id,
                current: file.checkpoint_id,
            });
        }
        if checkpoint_id == file.checkpoint_id && durable_offset == file.durable_offset {
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        file.durable_offset = durable_offset;
        file.checkpoint_id = checkpoint_id;
        self.queue_transfer(TransferControl::Checkpoint {
            file_id,
            durable_offset,
            checkpoint_id,
        });
        Ok(vec![SessionEvent::Checkpointed {
            file_id,
            durable_offset,
            checkpoint_id,
        }])
    }

    fn handle_remote_checkpoint(
        &mut self,
        file_id: FileId,
        durable_offset: u64,
        checkpoint_id: u64,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Offerer, "handle checkpoint")?;
        let file = self.file(&file_id)?;
        if checkpoint_id == file.checkpoint_id {
            if durable_offset == file.durable_offset {
                return Ok(vec![SessionEvent::DuplicateControl]);
            }
            return Err(CoreError::InvalidCheckpoint {
                file_id,
                checkpoint_id,
                current: file.checkpoint_id,
            });
        }
        let maximum = file
            .base_offset
            .checked_add(file.send_offset)
            .ok_or(CoreError::InvalidFileSize { file_id })?;
        validate_offset(file_id, durable_offset, maximum)?;
        if checkpoint_id < file.checkpoint_id
            || durable_offset < file.durable_offset
            || (checkpoint_id == file.checkpoint_id && durable_offset != file.durable_offset)
        {
            return Err(CoreError::InvalidCheckpoint {
                file_id,
                checkpoint_id,
                current: file.checkpoint_id,
            });
        }
        let file = self.file_mut(&file_id)?;
        file.durable_offset = durable_offset;
        file.checkpoint_id = checkpoint_id;
        Ok(Vec::new())
    }

    pub fn complete_file(
        &mut self,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Accepter, "complete file")?;
        let file = self.file_mut(&file_id)?;
        if file.complete {
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        if !file.awaiting_finish || file.received_offset != file.entry.size {
            return Err(CoreError::state("complete file", "file data is incomplete"));
        }
        if final_size != file.entry.size || content_hash != file.entry.content_hash {
            return Err(CoreError::IntegrityMismatch { file_id });
        }
        if file.durable_offset != file.entry.size {
            return Err(CoreError::InvalidOffset {
                file_id,
                offset: file.durable_offset,
                maximum: file.entry.size,
            });
        }
        file.complete = true;
        file.active_stream_id = None;
        self.completed_files += 1;
        self.completed_size += final_size;
        self.queue_transfer(TransferControl::FileComplete {
            file_id,
            final_size,
            content_hash,
        });
        let mut events = vec![SessionEvent::FileCompleted { file_id }];
        if self.completed_files == self.files.len() as u64 {
            self.queue_transfer(TransferControl::TransferComplete {
                transfer_id: self.transfer_id,
                completed_files: self.completed_files,
                total_size: self.completed_size,
            });
            events.extend(self.change_state(SessionState::Completed));
            events.push(SessionEvent::TransferCompleted);
        }
        Ok(events)
    }

    fn handle_file_complete_ack(
        &mut self,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Offerer, "handle file complete")?;
        let file = self.file_mut(&file_id)?;
        if file.complete {
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        if final_size != file.entry.size || content_hash != file.entry.content_hash {
            return Err(CoreError::IntegrityMismatch { file_id });
        }
        let remaining = file.entry.size - file.base_offset;
        if file.send_offset != remaining || (!file.fin_queued && remaining != 0) {
            return Err(CoreError::state(
                "handle file complete",
                "data stream is incomplete",
            ));
        }
        file.complete = true;
        file.active_stream_id = None;
        self.completed_files += 1;
        self.completed_size += final_size;
        let mut events = vec![SessionEvent::FileCompleted { file_id }];
        events.extend(self.start_pending_files()?);
        if self.completed_files == self.files.len() as u64 {
            events.extend(self.change_state(SessionState::AwaitingTransferComplete));
        }
        Ok(events)
    }

    fn handle_file_rejected(
        &mut self,
        file_id: FileId,
        _reason: FileRejectReason,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Offerer, "handle file rejected")?;
        self.file(&file_id)?;
        Ok(self.change_state(SessionState::Failed))
    }

    fn handle_transfer_complete(
        &mut self,
        transfer_id: TransferId,
        completed_files: u64,
        total_size: u64,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.require_role(SessionRole::Offerer, "handle transfer complete")?;
        CoreError::check_transfer_id(self.transfer_id, transfer_id)?;
        if self.state == SessionState::Completed {
            return Ok(vec![SessionEvent::DuplicateControl]);
        }
        if self.state != SessionState::AwaitingTransferComplete
            || completed_files != self.completed_files
            || total_size != self.completed_size
        {
            return Err(CoreError::state(
                "handle transfer complete",
                self.state.name(),
            ));
        }
        let mut events = self.change_state(SessionState::Completed);
        events.push(SessionEvent::TransferCompleted);
        Ok(events)
    }

    fn handle_transfer_error(
        &mut self,
        _scope: TransferErrorScope,
        _code: u32,
        retryable: bool,
        _message: String,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        if retryable {
            self.reconnect()
        } else {
            Ok(self.change_state(SessionState::Failed))
        }
    }

    pub fn handle_data_with_storage<S: Storage>(
        &mut self,
        storage: &mut S,
        chunk: DataChunk,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        let file_id = chunk.file_id;
        let absolute_offset = self
            .file(&file_id)
            .map(|file| file.base_offset.saturating_add(chunk.offset))?;
        let events = self.handle_data(chunk)?;
        if let Some(event) = events.iter().find_map(|event| match event {
            SessionEvent::DataReceived { bytes, .. } => Some(bytes.as_slice()),
            _ => None,
        }) && let Err(error) =
            storage.write_data(self.transfer_id, file_id, absolute_offset, event)
        {
            self.state = SessionState::Failed;
            return Err(error);
        }
        Ok(events)
    }

    pub fn respond_to_resume_query_with_storage<S: Storage>(
        &mut self,
        storage: &S,
        file_id: FileId,
        content_hash: Digest,
        size: u64,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        let state = storage.durable_state(self.transfer_id, file_id)?;
        self.set_durable_state(file_id, state)?;
        self.handle_resume_query(file_id, content_hash, size)
    }

    pub fn checkpoint_with_storage<S: Storage>(
        &mut self,
        storage: &mut S,
        file_id: FileId,
        durable_offset: u64,
        checkpoint_id: u64,
        state_hash: Digest,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.validate_checkpoint(file_id, durable_offset, checkpoint_id)?;
        storage.checkpoint(
            self.transfer_id,
            file_id,
            DurableState {
                durable_offset,
                checkpoint_id,
                state_hash,
            },
        )?;
        let file = self.file_mut(&file_id)?;
        file.state_hash = state_hash;
        self.checkpoint(file_id, durable_offset, checkpoint_id)
    }

    pub fn complete_file_with_storage<S: Storage>(
        &mut self,
        storage: &mut S,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        self.validate_file_completion(file_id, final_size, content_hash)?;
        storage.complete_file(self.transfer_id, file_id, final_size, content_hash)?;
        self.complete_file(file_id, final_size, content_hash)
    }

    pub fn set_durable_state(
        &mut self,
        file_id: FileId,
        state: DurableState,
    ) -> Result<(), CoreError> {
        let file = self.file_mut(&file_id)?;
        validate_offset(file_id, state.durable_offset, file.entry.size)?;
        if state.checkpoint_id < file.checkpoint_id
            || state.durable_offset < file.durable_offset
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

    pub fn reconnect(&mut self) -> Result<Vec<SessionEvent>, CoreError> {
        if self.state == SessionState::Completed && self.role == SessionRole::Accepter {
            self.controls.clear();
            self.data.clear();
            let completed = self
                .files
                .values()
                .filter(|file| file.complete)
                .map(|file| (file.entry.file_id, file.entry.size, file.entry.content_hash))
                .collect::<Vec<_>>();
            for (file_id, final_size, content_hash) in completed {
                self.queue_transfer(TransferControl::FileComplete {
                    file_id,
                    final_size,
                    content_hash,
                });
            }
            self.queue_transfer(TransferControl::TransferComplete {
                transfer_id: self.transfer_id,
                completed_files: self.completed_files,
                total_size: self.completed_size,
            });
            return Ok(Vec::new());
        }
        if matches!(
            self.state,
            SessionState::Completed | SessionState::Rejected | SessionState::Cancelled
        ) {
            return Err(CoreError::state("reconnect", self.state.name()));
        }
        self.data.clear();
        self.pending_resumes.clear();
        for file in self.files.values_mut() {
            if !file.complete {
                file.active_stream_id = None;
                file.send_offset = 0;
                file.fin_queued = false;
                file.awaiting_finish = false;
                if self.role == SessionRole::Accepter {
                    file.received_offset = file.durable_offset;
                }
            }
        }
        match self.role {
            SessionRole::Offerer => {
                let manifest = self
                    .manifest
                    .as_ref()
                    .ok_or(CoreError::ManifestRequired)?
                    .clone();
                self.queue_transfer(TransferControl::SessionHello {
                    transfer_id: self.transfer_id,
                    protocol_version: self.config.protocol_version,
                    crypto_suite: self.config.crypto_suite,
                    manifest_digest: manifest.digest(),
                    resume_namespace: *self.transfer_id.as_bytes(),
                });
                self.queue_transfer(TransferControl::ManifestBegin {
                    file_count: manifest.file_count(),
                    total_size: manifest.total_size(),
                    manifest_digest: manifest.digest(),
                });
                for entry in manifest.entries() {
                    self.queue_transfer(TransferControl::ManifestItem {
                        file_id: entry.file_id,
                        relative_path: entry.relative_path.clone(),
                        size: entry.size,
                        content_hash: entry.content_hash,
                        metadata: entry.metadata,
                    });
                }
                self.queue_transfer(TransferControl::ManifestEnd {
                    manifest_digest: manifest.digest(),
                });
                let entries = manifest.entries().to_vec();
                for entry in entries {
                    if !self.file(&entry.file_id)?.complete {
                        self.queue_transfer(TransferControl::ResumeQuery {
                            file_id: entry.file_id,
                            content_hash: entry.content_hash,
                            size: entry.size,
                        });
                    }
                }
            }
            SessionRole::Accepter => {}
        }
        Ok(self.change_state(SessionState::AwaitingResume))
    }

    pub fn select_path<P: PathSelector>(
        &mut self,
        selector: &mut P,
        candidates: &[Candidate],
    ) -> Result<Vec<SessionEvent>, CoreError> {
        let selection = selector.select(self.transfer_id, candidates)?;
        self.path = PathState::Direct(selection.clone());
        self.queue_pairing(PairingControl::PathSelected {
            transfer_id: self.transfer_id,
            path_id: selection.path_id,
            kind: selection.kind,
            rtt_millis: selection.rtt_millis,
            mtu: selection.mtu,
        });
        Ok(vec![SessionEvent::PathSelected { path: selection }])
    }

    pub fn fallback_to_relay<P: PathSelector>(
        &mut self,
        selector: &mut P,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        if !matches!(self.path, PathState::Direct(_) | PathState::Failed) {
            return Err(CoreError::InvalidPathTransition);
        }
        let (relay_id, relay_ticket) = selector.relay(self.transfer_id)?;
        self.path = PathState::Relay { relay_id };
        self.queue_pairing(PairingControl::RelayOpen {
            transfer_id: self.transfer_id,
            relay_id,
            relay_ticket,
        });
        Ok(vec![SessionEvent::PathFallback { relay_id }])
    }

    pub fn handle_pairing(
        &mut self,
        message: PairingControl,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        match message {
            PairingControl::PathSelected {
                transfer_id,
                path_id,
                kind,
                rtt_millis,
                mtu,
            } => {
                CoreError::check_transfer_id(self.transfer_id, transfer_id)?;
                if matches!(self.path, PathState::Relay { .. }) {
                    return Err(CoreError::InvalidPathTransition);
                }
                let path = PathSelection {
                    path_id,
                    kind,
                    rtt_millis,
                    mtu,
                };
                self.path = PathState::Direct(path.clone());
                Ok(vec![SessionEvent::PathSelected { path }])
            }
            PairingControl::RelayOpen {
                transfer_id,
                relay_id,
                relay_ticket: _,
            } => {
                CoreError::check_transfer_id(self.transfer_id, transfer_id)?;
                self.path = PathState::Relay { relay_id };
                Ok(vec![SessionEvent::PathFallback { relay_id }])
            }
            PairingControl::RelayClosed {
                transfer_id,
                reason,
            } => {
                CoreError::check_transfer_id(self.transfer_id, transfer_id)?;
                if !matches!(self.path, PathState::Relay { .. }) {
                    return Err(CoreError::InvalidPathTransition);
                }
                self.path = PathState::Failed;
                if reason == RelayCloseReason::Failed {
                    Ok(self.change_state(SessionState::Failed))
                } else {
                    Ok(Vec::new())
                }
            }
            PairingControl::Cancel {
                transfer_id,
                reason_code: _,
            } => {
                CoreError::check_transfer_id(self.transfer_id, transfer_id)?;
                Ok(self.change_state(SessionState::Cancelled))
            }
            _ => Err(CoreError::InvalidPathTransition),
        }
    }

    pub fn mark_path_failed(&mut self) -> Vec<SessionEvent> {
        self.path = PathState::Failed;
        Vec::new()
    }

    pub fn touch<C: Clock>(&mut self, clock: &C) {
        self.last_activity_millis = clock.now_millis();
    }

    pub fn is_idle_expired<C: Clock>(&self, clock: &C) -> bool {
        clock.now_millis().saturating_sub(self.last_activity_millis)
            >= self.config.idle_timeout.as_millis() as u64
    }

    pub fn flush<C: ControlChannel, D: DataChannel>(
        &mut self,
        control: &mut C,
        data: &mut D,
    ) -> Result<(), CoreError> {
        while let Some(message) = self.controls.pop_front() {
            control.send(message.clone()).map_err(|error| {
                self.controls.push_front(message);
                CoreError::Channel(error.message)
            })?;
        }
        while let Some(chunk) = self.data.pop_front() {
            if let Err(error) = data.send(chunk.clone()) {
                self.data.push_front(chunk);
                return Err(CoreError::Channel(error.message));
            }
        }
        Ok(())
    }

    fn set_state(&mut self, state: SessionState) -> SessionEvent {
        let from = self.state;
        self.state = state;
        SessionEvent::StateChanged { from, to: state }
    }

    fn change_state(&mut self, state: SessionState) -> Vec<SessionEvent> {
        if self.state == state {
            Vec::new()
        } else {
            vec![self.set_state(state)]
        }
    }

    fn require_role(&self, role: SessionRole, operation: &'static str) -> Result<(), CoreError> {
        if self.role == role {
            Ok(())
        } else {
            Err(CoreError::InvalidRole { operation })
        }
    }

    fn file(&self, file_id: &FileId) -> Result<&FileRuntime, CoreError> {
        self.files
            .get(file_id)
            .ok_or(CoreError::UnknownFile { file_id: *file_id })
    }

    fn file_mut(&mut self, file_id: &FileId) -> Result<&mut FileRuntime, CoreError> {
        self.files
            .get_mut(file_id)
            .ok_or(CoreError::UnknownFile { file_id: *file_id })
    }

    fn active_file_count(&self) -> usize {
        self.files
            .values()
            .filter(|file| file.active_stream_id.is_some())
            .count()
    }

    fn all_completed(&self) -> bool {
        self.completed_files == self.files.len() as u64
    }

    fn allocate_stream_id(&mut self) -> Result<u64, CoreError> {
        let stream_id = self.next_stream_id;
        self.next_stream_id =
            self.next_stream_id
                .checked_add(1)
                .ok_or(CoreError::InvalidState {
                    operation: "allocate data stream",
                    state: "stream id exhausted",
                })?;
        Ok(stream_id)
    }

    fn queue_transfer(&mut self, message: TransferControl) {
        self.controls.push_back(OutboundMessage::Transfer(message));
    }

    fn queue_pairing(&mut self, message: PairingControl) {
        self.controls.push_back(OutboundMessage::Pairing(message));
    }

    fn validate_checkpoint(
        &self,
        file_id: FileId,
        durable_offset: u64,
        checkpoint_id: u64,
    ) -> Result<(), CoreError> {
        let file = self.file(&file_id)?;
        validate_offset(file_id, durable_offset, file.received_offset)?;
        if checkpoint_id < file.checkpoint_id
            || durable_offset < file.durable_offset
            || (checkpoint_id == file.checkpoint_id && durable_offset != file.durable_offset)
        {
            return Err(CoreError::InvalidCheckpoint {
                file_id,
                checkpoint_id,
                current: file.checkpoint_id,
            });
        }
        Ok(())
    }

    fn validate_file_completion(
        &self,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<(), CoreError> {
        let file = self.file(&file_id)?;
        if file.complete {
            return Ok(());
        }
        if !file.awaiting_finish || file.received_offset != file.entry.size {
            return Err(CoreError::state("complete file", "file data is incomplete"));
        }
        if final_size != file.entry.size || content_hash != file.entry.content_hash {
            return Err(CoreError::IntegrityMismatch { file_id });
        }
        if file.durable_offset != file.entry.size {
            return Err(CoreError::InvalidOffset {
                file_id,
                offset: file.durable_offset,
                maximum: file.entry.size,
            });
        }
        Ok(())
    }
}

fn validate_offset(file_id: FileId, offset: u64, maximum: u64) -> Result<(), CoreError> {
    if offset <= maximum {
        Ok(())
    } else {
        Err(CoreError::InvalidOffset {
            file_id,
            offset,
            maximum,
        })
    }
}

impl TransferSession {
    pub fn handle_control_with_flags(
        &mut self,
        message: TransferControl,
        flags: MessageFlags,
    ) -> Result<Vec<SessionEvent>, CoreError> {
        if flags.contains(MessageFlags::ERROR) {
            return Err(CoreError::InvalidState {
                operation: "handle control",
                state: "error flag requires an error message",
            });
        }
        self.handle_control(message)
    }

    pub fn reset_for_test(&mut self) {
        self.controls.clear();
        self.data.clear();
        self.path = PathState::Unselected;
        self.last_activity_millis = 0;
    }

    pub fn build_transfer_error(
        &self,
        scope: TransferErrorScope,
        code: u32,
        retryable: bool,
        message: String,
    ) -> OutboundMessage {
        OutboundMessage::Transfer(TransferControl::TransferError {
            scope,
            code,
            retryable,
            message,
        })
    }

    pub fn build_file_rejection(
        &self,
        file_id: FileId,
        reason: FileRejectReason,
    ) -> OutboundMessage {
        OutboundMessage::Transfer(TransferControl::FileRejected { file_id, reason })
    }

    pub fn send_path_check_authorization(
        &mut self,
        check_token: transfer_protocol::CheckToken,
        expires_at: u64,
    ) {
        self.queue_pairing(PairingControl::PathCheckAuthorization {
            transfer_id: self.transfer_id,
            check_token,
            expires_at,
        });
    }

    pub fn send_candidate_list(&mut self, candidates: Vec<Candidate>, digest: Digest) {
        self.queue_pairing(PairingControl::CandidateList {
            transfer_id: self.transfer_id,
            candidates,
            candidate_digest: digest,
        });
    }

    pub fn send_file_rejection(&mut self, file_id: FileId, reason: FileRejectReason) {
        self.queue_transfer(TransferControl::FileRejected { file_id, reason });
    }

    pub fn send_cancel(&mut self, reason_code: u16) {
        self.queue_pairing(PairingControl::Cancel {
            transfer_id: self.transfer_id,
            reason_code,
        });
        self.state = SessionState::Cancelled;
    }

    pub fn is_complete(&self) -> bool {
        self.state == SessionState::Completed && self.all_completed()
    }
}
