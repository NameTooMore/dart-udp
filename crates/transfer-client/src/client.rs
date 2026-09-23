use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use getrandom::fill as fill_random;
use network_probe::{NetworkSnapshot, candidate_digest};
use reliable_udp::Endpoint;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::watch,
    task,
};
use transfer_core::{DataChunk, Manifest, SessionEvent, SessionState, TransferSession};
use transfer_protocol::{
    AcceptDecision, Digest, FileId, HashAlgorithm, Message, OverwritePolicy, PairingControl,
    PairingId, PathKind, TransferControl, TransferId, TransferRole,
};
use transfer_storage::{FileStorage, ManifestBuilder, StorageConfig};

use crate::{
    ClientError,
    config::{ClientConfig, PairingOptions, ReceiveOptions, RejectReason},
    manifest_files::collect_source_files,
    protocol::{ClientConnection, read_data_frame, write_data_frame},
    resume::ResumeTicket,
    transfer::{TransferChannels, TransferEvent, TransferHandle, TransferSummary, publish_events},
};

pub struct TransferClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    endpoint: Arc<Endpoint>,
    connection: Arc<ClientConnection>,
    config: ClientConfig,
    instance_id: transfer_protocol::ClientInstanceId,
}

pub struct PairingOffer {
    inner: Arc<ClientInner>,
    pairing_id: PairingId,
    code: transfer_protocol::PairingCode,
    expires_at_millis: u64,
    started: AtomicBool,
}

pub struct IncomingOffer {
    inner: Arc<ClientInner>,
    pairing_id: PairingId,
    transfer_id: TransferId,
    manifest_digest: Digest,
    file_count: u64,
    total_size: u64,
    sender_display_name: String,
    resume_ticket: ResumeTicket,
    accepted: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
struct FileSendInfo {
    file_id: FileId,
    base_offset: u64,
    remaining_size: u64,
}

#[derive(Debug, Clone, Copy)]
struct FileReceiveInfo {
    file_id: FileId,
    stream_id: u64,
    base_offset: u64,
    remaining_size: u64,
}

impl TransferClient {
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        config.validate().map_err(ClientError::InvalidConfig)?;
        let instance_id = transfer_protocol::ClientInstanceId::random()
            .map_err(|_| ClientError::RandomnessUnavailable)?;
        let endpoint = Arc::new(Endpoint::bind(config.endpoint.clone()).await?);
        let connection = endpoint.handle().connect(config.server_addr).await?;
        let stream = connection.open_stream().await?;
        let control =
            ClientConnection::new(connection, stream, config.control_queue_capacity).await;
        Ok(Self {
            inner: Arc::new(ClientInner {
                endpoint,
                connection: control,
                config,
                instance_id,
            }),
        })
    }

    /// 获取当前网络接口和路由快照，供 UI 展示和路径诊断使用。
    pub fn network_snapshot(&self) -> Result<NetworkSnapshot, ClientError> {
        NetworkSnapshot::collect().map_err(ClientError::from)
    }

    /// 根据可靠 UDP endpoint 的实际端口生成本地候选地址。
    pub fn local_candidates(&self) -> Result<Vec<transfer_protocol::Candidate>, ClientError> {
        let snapshot = self.network_snapshot()?;
        let port = self.inner.endpoint.local_addr().port();
        snapshot
            .candidates(port, self.inner.config.network.max_candidates)
            .map_err(ClientError::from)
    }

    pub async fn create_pairing(
        &self,
        options: PairingOptions,
    ) -> Result<PairingOffer, ClientError> {
        let ephemeral_key = random_key()?;
        self.inner
            .connection
            .send(&Message::Pairing(PairingControl::CreatePairing {
                client_instance_id: self.inner.instance_id,
                capability: transfer_protocol::Capability::Upload,
                requested_ttl: options.requested_ttl_seconds,
                client_ephemeral_key: ephemeral_key,
            }))
            .await?;
        let response = self.inner.connection.recv().await?;
        let Message::Pairing(PairingControl::PairingCreated {
            pairing_id,
            pairing_code,
            expires_at,
            ..
        }) = response.message
        else {
            return Err(unexpected_message("PairingCreated"));
        };
        Ok(PairingOffer {
            inner: Arc::clone(&self.inner),
            pairing_id,
            code: pairing_code,
            expires_at_millis: expires_at,
            started: AtomicBool::new(false),
        })
    }

    pub async fn join_pairing(
        &self,
        code: transfer_protocol::PairingCode,
    ) -> Result<IncomingOffer, ClientError> {
        let ephemeral_key = random_key()?;
        self.inner
            .connection
            .send(&Message::Pairing(PairingControl::JoinPairing {
                pairing_code: code,
                client_instance_id: self.inner.instance_id,
                client_ephemeral_key: ephemeral_key,
            }))
            .await?;
        let pairing_id = loop {
            match self.inner.connection.recv().await?.message {
                Message::Pairing(PairingControl::PairingJoined { pairing_id, .. }) => {
                    break pairing_id;
                }
                Message::Transfer(error) => return Err(transfer_error(error)),
                _ => {}
            }
        };
        let mut resume_ticket: Option<ResumeTicket> = None;
        loop {
            match self.inner.connection.recv().await?.message {
                Message::Pairing(PairingControl::OfferReady {
                    transfer_id,
                    manifest_digest,
                    file_count,
                    total_size,
                    sender_display_name,
                }) => {
                    let resume_ticket = resume_ticket.ok_or(ClientError::InvalidState(
                        "offer did not include a resume ticket",
                    ))?;
                    if resume_ticket.transfer_id() != transfer_id
                        || resume_ticket.manifest_digest() != manifest_digest
                    {
                        return Err(ClientError::InvalidState(
                            "resume ticket does not match offer",
                        ));
                    }
                    return Ok(IncomingOffer {
                        inner: Arc::clone(&self.inner),
                        pairing_id,
                        transfer_id,
                        manifest_digest,
                        file_count,
                        total_size,
                        sender_display_name,
                        resume_ticket,
                        accepted: AtomicBool::new(false),
                    });
                }
                Message::Pairing(PairingControl::ResumeTicket {
                    pairing_id: ticket_pairing_id,
                    transfer_id: ticket_transfer_id,
                    role: TransferRole::Accepter,
                    manifest_digest,
                    expires_at,
                    resume_ticket: wire_ticket,
                }) if ticket_pairing_id == pairing_id => {
                    resume_ticket = Some(ResumeTicket::from_wire(
                        ticket_pairing_id,
                        ticket_transfer_id,
                        TransferRole::Accepter,
                        manifest_digest,
                        expires_at,
                        wire_ticket,
                    )?);
                }
                Message::Transfer(error) => return Err(transfer_error(error)),
                _ => {}
            }
        }
    }

    /// 使用发送方 ticket 在新进程中恢复传输。
    pub async fn resume_send<I, P>(
        &self,
        ticket: ResumeTicket,
        sources: I,
    ) -> Result<TransferHandle, ClientError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        if ticket.role() != TransferRole::Offerer {
            return Err(ClientError::InvalidState(
                "resume ticket is not for sending",
            ));
        }
        if ticket.is_expired() {
            return Err(ClientError::ResumeTicketExpired);
        }
        let manifest = ticket.manifest().cloned().ok_or(ClientError::InvalidState(
            "sender manifest is missing from resume ticket",
        ))?;
        let sources = sources.into_iter().map(Into::into).collect::<Vec<_>>();
        let manifest_config = self.inner.config.manifest;
        let (source_files, actual_manifest) = task::spawn_blocking(move || {
            let source_files = collect_source_files(&sources)?;
            let actual_manifest = ManifestBuilder::new(manifest_config).build(&sources)?;
            Ok::<_, ClientError>((source_files, actual_manifest))
        })
        .await
        .map_err(|error| ClientError::TaskJoin(error.to_string()))??;
        validate_resume_sources(&manifest, &actual_manifest)?;
        let accepted = reconnect_ticket(&self.inner, &ticket).await?;
        if accepted.manifest_digest != manifest.digest() {
            return Err(ClientError::InvalidState("resume manifest digest mismatch"));
        }
        let mut session = TransferSession::new_offerer(
            ticket.transfer_id(),
            manifest.clone(),
            self.inner.config.session.clone(),
        )?;
        let mut events = session.start()?;
        events.extend(session.reconnect()?);
        let transfer_channels = TransferHandle::channels();
        let TransferChannels {
            cancel,
            cancel_receiver,
            event_sender,
            resume_ticket_sender,
            resume_ticket_receiver,
        } = transfer_channels;
        resume_ticket_sender
            .send(Some(ticket.clone()))
            .map_err(|_| ClientError::Closed)?;
        let inner = Arc::clone(&self.inner);
        let task_events = event_sender.clone();
        let task = tokio::spawn(async move {
            run_offerer(OffererRuntime {
                inner,
                session,
                manifest,
                source_files,
                cancel: cancel_receiver,
                event_sender: task_events,
                initial_events: events,
                resume_ticket_sender,
            })
            .await
        });
        Ok(TransferHandle::new(
            Arc::clone(&self.inner.connection),
            ticket.transfer_id(),
            task,
            cancel,
            event_sender,
            resume_ticket_receiver,
        ))
    }

    /// 使用接收方 ticket 在新进程中恢复传输，并继续使用原有临时文件。
    pub async fn resume_receive(
        &self,
        ticket: ResumeTicket,
        options: ReceiveOptions,
    ) -> Result<TransferHandle, ClientError> {
        if ticket.role() != TransferRole::Accepter {
            return Err(ClientError::InvalidState(
                "resume ticket is not for receiving",
            ));
        }
        if ticket.is_expired() {
            return Err(ClientError::ResumeTicketExpired);
        }
        let _accepted = reconnect_ticket(&self.inner, &ticket).await?;
        let mut session =
            TransferSession::new_accepter(ticket.transfer_id(), self.inner.config.session.clone())?;
        let initial_events = session.start()?;
        let transfer_channels = TransferHandle::channels();
        let TransferChannels {
            cancel,
            cancel_receiver,
            event_sender,
            resume_ticket_sender,
            resume_ticket_receiver,
        } = transfer_channels;
        resume_ticket_sender
            .send(Some(ticket.clone()))
            .map_err(|_| ClientError::Closed)?;
        let inner = Arc::clone(&self.inner);
        let task_events = event_sender.clone();
        let task = tokio::spawn(async move {
            run_accepter(
                inner,
                session,
                options,
                cancel_receiver,
                task_events,
                initial_events,
                true,
            )
            .await
        });
        Ok(TransferHandle::new(
            Arc::clone(&self.inner.connection),
            ticket.transfer_id(),
            task,
            cancel,
            event_sender,
            resume_ticket_receiver,
        ))
    }
}

impl PairingOffer {
    pub fn pairing_id(&self) -> PairingId {
        self.pairing_id
    }

    pub fn code(&self) -> &transfer_protocol::PairingCode {
        &self.code
    }

    pub fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }

    pub async fn offer_files<I, P>(&self, sources: I) -> Result<TransferHandle, ClientError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        if self.started.swap(true, Ordering::AcqRel) {
            return Err(ClientError::InvalidState("pairing offer already started"));
        }
        let sources = sources.into_iter().map(Into::into).collect::<Vec<_>>();
        let manifest_config = self.inner.config.manifest;
        let (manifest, source_files) = task::spawn_blocking(move || {
            let source_files = collect_source_files(&sources)?;
            let manifest = ManifestBuilder::new(manifest_config).build(&sources)?;
            Ok::<_, ClientError>((manifest, source_files))
        })
        .await
        .map_err(|error| ClientError::TaskJoin(error.to_string()))??;
        let transfer_id = TransferId::random().map_err(|_| ClientError::RandomnessUnavailable)?;
        self.inner
            .connection
            .send(&Message::Pairing(PairingControl::OfferReady {
                transfer_id,
                manifest_digest: manifest.digest(),
                file_count: manifest.file_count(),
                total_size: manifest.total_size(),
                sender_display_name: self.inner.config.display_name.clone(),
            }))
            .await?;
        send_local_candidates(&self.inner, transfer_id).await?;
        let mut session = TransferSession::new_offerer(
            transfer_id,
            manifest.clone(),
            self.inner.config.session.clone(),
        )?;
        let events = session.start()?;
        let transfer_channels = TransferHandle::channels();
        let TransferChannels {
            cancel,
            cancel_receiver,
            event_sender,
            resume_ticket_sender,
            resume_ticket_receiver,
        } = transfer_channels;
        let inner = Arc::clone(&self.inner);
        let task_events = event_sender.clone();
        let task = tokio::spawn(async move {
            run_offerer(OffererRuntime {
                inner,
                session,
                manifest,
                source_files,
                cancel: cancel_receiver,
                event_sender: task_events,
                initial_events: events,
                resume_ticket_sender,
            })
            .await
        });
        Ok(TransferHandle::new(
            Arc::clone(&self.inner.connection),
            transfer_id,
            task,
            cancel,
            event_sender,
            resume_ticket_receiver,
        ))
    }
}

impl IncomingOffer {
    pub fn pairing_id(&self) -> PairingId {
        self.pairing_id
    }
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }
    pub fn manifest_digest(&self) -> Digest {
        self.manifest_digest
    }
    pub fn file_count(&self) -> u64 {
        self.file_count
    }
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
    pub fn sender_display_name(&self) -> &str {
        &self.sender_display_name
    }

    pub fn resume_ticket(&self) -> &ResumeTicket {
        &self.resume_ticket
    }

    pub fn save_resume_ticket(
        &self,
        root: impl AsRef<std::path::Path>,
    ) -> Result<std::path::PathBuf, ClientError> {
        self.resume_ticket.save_to(root)
    }

    pub async fn accept_offer(
        self,
        options: ReceiveOptions,
    ) -> Result<TransferHandle, ClientError> {
        if self.accepted.swap(true, Ordering::AcqRel) {
            return Err(ClientError::InvalidState("incoming offer already decided"));
        }
        self.inner
            .connection
            .send(&Message::Pairing(PairingControl::AcceptOffer {
                transfer_id: self.transfer_id,
                decision: AcceptDecision::Accept,
                receiver_root_policy: options.target_root_label.clone(),
            }))
            .await?;
        send_local_candidates(&self.inner, self.transfer_id).await?;
        let session =
            TransferSession::new_accepter(self.transfer_id, self.inner.config.session.clone())?;
        let transfer_channels = TransferHandle::channels();
        let TransferChannels {
            cancel,
            cancel_receiver,
            event_sender,
            resume_ticket_sender,
            resume_ticket_receiver,
        } = transfer_channels;
        resume_ticket_sender
            .send(Some(self.resume_ticket.clone()))
            .map_err(|_| ClientError::Closed)?;
        let inner = Arc::clone(&self.inner);
        let task_events = event_sender.clone();
        let task = tokio::spawn(async move {
            run_accepter(
                inner,
                session,
                options,
                cancel_receiver,
                task_events,
                Vec::new(),
                false,
            )
            .await
        });
        Ok(TransferHandle::new(
            Arc::clone(&self.inner.connection),
            self.transfer_id,
            task,
            cancel,
            event_sender,
            resume_ticket_receiver,
        ))
    }

    pub async fn reject_offer(self, reason: RejectReason) -> Result<(), ClientError> {
        if self.accepted.swap(true, Ordering::AcqRel) {
            return Err(ClientError::InvalidState("incoming offer already decided"));
        }
        self.inner
            .connection
            .send(&Message::Pairing(PairingControl::AcceptOffer {
                transfer_id: self.transfer_id,
                decision: AcceptDecision::Reject,
                receiver_root_policy: format!("reject:{}", reason.code()),
            }))
            .await
    }
}

async fn send_local_candidates(
    inner: &Arc<ClientInner>,
    transfer_id: TransferId,
) -> Result<(), ClientError> {
    if !inner.config.enable_direct {
        return Ok(());
    }
    let snapshot = NetworkSnapshot::collect()?;
    let port = inner.endpoint.local_addr().port();
    let candidates = match snapshot.candidates(port, inner.config.network.max_candidates) {
        Ok(candidates) => candidates,
        Err(network_probe::ProbeError::NoCandidates) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    inner
        .connection
        .send(&Message::Pairing(PairingControl::CandidateList {
            transfer_id,
            candidate_digest: candidate_digest(&candidates),
            candidates,
        }))
        .await
}

struct OffererRuntime {
    inner: Arc<ClientInner>,
    session: TransferSession,
    manifest: Manifest,
    source_files: HashMap<String, PathBuf>,
    cancel: watch::Receiver<bool>,
    event_sender: tokio::sync::broadcast::Sender<TransferEvent>,
    initial_events: Vec<SessionEvent>,
    resume_ticket_sender: tokio::sync::watch::Sender<Option<ResumeTicket>>,
}

async fn run_offerer(runtime: OffererRuntime) -> Result<TransferSummary, ClientError> {
    let OffererRuntime {
        inner,
        session,
        manifest,
        source_files,
        cancel,
        event_sender,
        initial_events,
        resume_ticket_sender,
    } = runtime;
    let mut session = session;
    let mut cancel = cancel;
    publish_events(&event_sender, &initial_events);
    if session.state() != SessionState::AwaitingDecision {
        flush_session(&mut session, &inner.connection).await?;
    }
    loop {
        let decoded = tokio::select! {
            changed = cancel.changed() => {
                if changed.is_ok() && *cancel.borrow() { return Err(ClientError::Cancelled); }
                continue;
            }
            message = inner.connection.recv() => message?,
        };
        match decoded.message {
            Message::Pairing(message) => match message {
                PairingControl::ResumeTicket {
                    pairing_id,
                    transfer_id,
                    role: TransferRole::Offerer,
                    manifest_digest,
                    expires_at,
                    resume_ticket,
                } if transfer_id == session.transfer_id() => {
                    let ticket = ResumeTicket::from_wire(
                        pairing_id,
                        transfer_id,
                        TransferRole::Offerer,
                        manifest_digest,
                        expires_at,
                        resume_ticket,
                    )?
                    .with_manifest(manifest.clone());
                    resume_ticket_sender
                        .send(Some(ticket))
                        .map_err(|_| ClientError::Closed)?;
                }
                PairingControl::PeerReconnected { transfer_id, .. }
                    if transfer_id == session.transfer_id() =>
                {
                    let events = session.reconnect()?;
                    publish_events(&event_sender, &events);
                    flush_session(&mut session, &inner.connection).await?;
                }
                PairingControl::RelayOpen {
                    transfer_id,
                    relay_id,
                    relay_ticket,
                } if transfer_id == session.transfer_id() => {
                    if inner.config.direct_only {
                        return Err(ClientError::DirectPathUnavailable);
                    }
                    let events = session.handle_pairing(PairingControl::RelayOpen {
                        transfer_id,
                        relay_id,
                        relay_ticket,
                    })?;
                    publish_events(&event_sender, &events);
                    let _ = event_sender.send(TransferEvent::PathSelected {
                        kind: PathKind::Relay,
                    });
                }
                PairingControl::AcceptOffer {
                    transfer_id,
                    decision,
                    ..
                } if transfer_id == session.transfer_id() => {
                    let events = session.handle_control(TransferControl::ReceiveDecision {
                        accepted: decision == AcceptDecision::Accept,
                        overwrite_policy: OverwritePolicy::Ask,
                        target_root_label: "default".to_owned(),
                    })?;
                    publish_events(&event_sender, &events);
                    flush_session(&mut session, &inner.connection).await?;
                }
                PairingControl::Cancel { transfer_id, .. }
                    if transfer_id == session.transfer_id() =>
                {
                    return Err(ClientError::Cancelled);
                }
                _ => {}
            },
            Message::Transfer(message) => {
                if let TransferControl::TransferError { code, message, .. } = &message {
                    return Err(ClientError::Server {
                        code: *code,
                        message: message.clone(),
                    });
                }
                let events = session.handle_control(message)?;
                publish_events(&event_sender, &events);
                let controls = session.drain_control();
                for control in controls {
                    let file_begin = match &control {
                        transfer_core::OutboundMessage::Transfer(TransferControl::FileBegin {
                            file_id,
                            data_stream_id: _,
                            base_offset,
                            remaining_size,
                            content_hash: _,
                        }) => Some(FileSendInfo {
                            file_id: *file_id,
                            base_offset: *base_offset,
                            remaining_size: *remaining_size,
                        }),
                        _ => None,
                    };
                    send_outbound(&inner.connection, control).await?;
                    if let Some(file_begin) = file_begin {
                        send_file_data(&inner, &mut session, &manifest, &source_files, file_begin)
                            .await?;
                    }
                }
                if session.is_complete() {
                    return Ok(summary(&session, &manifest));
                }
            }
            Message::Path(_) => {}
        }
    }
}

async fn send_file_data(
    inner: &Arc<ClientInner>,
    session: &mut TransferSession,
    manifest: &Manifest,
    source_files: &HashMap<String, PathBuf>,
    info: FileSendInfo,
) -> Result<(), ClientError> {
    if info.remaining_size == 0 {
        return Ok(());
    }
    let entry = manifest
        .entry(info.file_id)
        .ok_or(ClientError::InvalidState("manifest entry missing"))?;
    let path = source_files
        .get(&entry.relative_path)
        .ok_or(ClientError::InvalidState("source file mapping missing"))?;
    let mut file = tokio::fs::File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(info.base_offset))
        .await?;
    let mut stream = inner.connection.connection().open_stream().await?;
    let mut sent = 0_u64;
    while sent < info.remaining_size {
        let amount =
            usize::try_from((info.remaining_size - sent).min(inner.config.chunk_size as u64))
                .map_err(|_| ClientError::InvalidState("chunk size overflow"))?;
        let mut bytes = vec![0_u8; amount];
        file.read_exact(&mut bytes).await?;
        let fin = sent + amount as u64 == info.remaining_size;
        let chunk = session.queue_data(info.file_id, bytes, fin)?;
        write_data_frame(&mut stream, chunk.offset, chunk.fin, &chunk.bytes).await?;
        sent += amount as u64;
    }
    stream.shutdown().await?;
    Ok(())
}

async fn run_accepter(
    inner: Arc<ClientInner>,
    mut session: TransferSession,
    options: ReceiveOptions,
    mut cancel: watch::Receiver<bool>,
    event_sender: tokio::sync::broadcast::Sender<TransferEvent>,
    initial_events: Vec<SessionEvent>,
    already_started: bool,
) -> Result<TransferSummary, ClientError> {
    let storage_config = StorageConfig {
        overwrite_policy: options.overwrite_policy,
        sync_data: options.sync_data,
        sync_all: options.sync_all,
    };
    let mut storage = FileStorage::open_with_config(&options.root, storage_config)?;
    if already_started {
        publish_events(&event_sender, &initial_events);
    } else {
        let events = session.start()?;
        publish_events(&event_sender, &events);
    }
    loop {
        let decoded = tokio::select! {
            changed = cancel.changed() => {
                if changed.is_ok() && *cancel.borrow() { return Err(ClientError::Cancelled); }
                continue;
            }
            message = inner.connection.recv() => message?,
        };
        match decoded.message {
            Message::Pairing(PairingControl::RelayOpen {
                transfer_id,
                relay_id,
                relay_ticket,
            }) if transfer_id == session.transfer_id() => {
                if inner.config.direct_only {
                    return Err(ClientError::DirectPathUnavailable);
                }
                let events = session.handle_pairing(PairingControl::RelayOpen {
                    transfer_id,
                    relay_id,
                    relay_ticket,
                })?;
                publish_events(&event_sender, &events);
                let _ = event_sender.send(TransferEvent::PathSelected {
                    kind: PathKind::Relay,
                });
            }
            Message::Pairing(PairingControl::PeerReconnected { transfer_id, .. })
                if transfer_id == session.transfer_id() =>
            {
                if session.manifest().is_some() {
                    let events = session.reconnect()?;
                    publish_events(&event_sender, &events);
                    flush_session(&mut session, &inner.connection).await?;
                }
            }
            Message::Pairing(PairingControl::Cancel { transfer_id, .. })
                if transfer_id == session.transfer_id() =>
            {
                return Err(ClientError::Cancelled);
            }
            Message::Transfer(message) => {
                if let TransferControl::TransferError { code, message, .. } = &message {
                    return Err(ClientError::Server {
                        code: *code,
                        message: message.clone(),
                    });
                }
                let file_begin = match &message {
                    TransferControl::FileBegin {
                        file_id,
                        data_stream_id,
                        base_offset,
                        remaining_size,
                        ..
                    } => Some(FileReceiveInfo {
                        file_id: *file_id,
                        stream_id: *data_stream_id,
                        base_offset: *base_offset,
                        remaining_size: *remaining_size,
                    }),
                    _ => None,
                };
                let is_manifest_end = matches!(message, TransferControl::ManifestEnd { .. });
                let resume = match &message {
                    TransferControl::ResumeQuery {
                        file_id,
                        content_hash,
                        size,
                    } => Some((*file_id, *content_hash, *size)),
                    _ => None,
                };
                let events = if let Some((file_id, content_hash, size)) = resume {
                    session.respond_to_resume_query_with_storage(
                        &storage,
                        file_id,
                        content_hash,
                        size,
                    )?
                } else {
                    session.handle_control(message)?
                };
                publish_events(&event_sender, &events);
                if is_manifest_end && session.state() == SessionState::AwaitingDecision {
                    let manifest = session
                        .manifest()
                        .ok_or(ClientError::InvalidState("manifest not assembled"))?
                        .clone();
                    storage.register_manifest(session.transfer_id(), &manifest)?;
                    let events = session.accept_offer(
                        AcceptDecision::Accept,
                        options.overwrite_policy,
                        options.target_root_label.clone(),
                    )?;
                    publish_events(&event_sender, &events);
                }
                flush_session(&mut session, &inner.connection).await?;
                if session.is_complete() {
                    let manifest = session
                        .manifest()
                        .ok_or(ClientError::InvalidState("manifest not available"))?;
                    return Ok(summary(&session, manifest));
                }
                if let Some(file_begin) = file_begin {
                    receive_file_data(
                        &inner,
                        &mut session,
                        &mut storage,
                        file_begin,
                        &event_sender,
                    )
                    .await?;
                    flush_session(&mut session, &inner.connection).await?;
                    if session.is_complete() {
                        let manifest = session
                            .manifest()
                            .ok_or(ClientError::InvalidState("manifest not available"))?;
                        return Ok(summary(&session, manifest));
                    }
                }
            }
            Message::Pairing(_) => {}
            Message::Path(_) => {}
        }
    }
}

async fn receive_file_data(
    inner: &Arc<ClientInner>,
    session: &mut TransferSession,
    storage: &mut FileStorage,
    info: FileReceiveInfo,
    event_sender: &tokio::sync::broadcast::Sender<TransferEvent>,
) -> Result<(), ClientError> {
    if info.remaining_size > 0 {
        let mut stream = inner.connection.connection().accept_stream().await?;
        let mut buffer = Vec::new();
        let mut saw_fin = false;
        while let Some((offset, fin, bytes)) = read_data_frame(&mut stream, &mut buffer).await? {
            let chunk = DataChunk {
                file_id: info.file_id,
                stream_id: info.stream_id,
                offset,
                bytes,
                fin,
            };
            let events = session.handle_data_with_storage(storage, chunk)?;
            publish_events(event_sender, &events);
            if fin {
                saw_fin = true;
                break;
            }
        }
        if !saw_fin {
            return Err(ClientError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "data stream ended before FIN",
            )));
        }
    }
    let progress = session.file_progress(info.file_id)?;
    let state_hash = Digest::new(progress_hash_algorithm(session, info.file_id), [0; 32]);
    let events = session.checkpoint_with_storage(
        storage,
        info.file_id,
        info.base_offset.saturating_add(info.remaining_size),
        progress.checkpoint_id.saturating_add(1),
        state_hash,
    )?;
    publish_events(event_sender, &events);
    let manifest = session
        .manifest()
        .ok_or(ClientError::InvalidState("manifest not available"))?;
    let entry = manifest
        .entry(info.file_id)
        .ok_or(ClientError::InvalidState("manifest entry missing"))?;
    let events = session.complete_file_with_storage(
        storage,
        info.file_id,
        entry.size,
        entry.content_hash,
    )?;
    publish_events(event_sender, &events);
    Ok(())
}

async fn flush_session(
    session: &mut TransferSession,
    connection: &Arc<ClientConnection>,
) -> Result<(), ClientError> {
    for control in session.drain_control() {
        send_outbound(connection, control).await?;
    }
    Ok(())
}

async fn send_outbound(
    connection: &Arc<ClientConnection>,
    control: transfer_core::OutboundMessage,
) -> Result<(), ClientError> {
    let message = match control {
        transfer_core::OutboundMessage::Pairing(message) => Message::Pairing(message),
        transfer_core::OutboundMessage::Transfer(message) => Message::Transfer(message),
    };
    connection.send(&message).await
}

fn summary(session: &TransferSession, manifest: &Manifest) -> TransferSummary {
    TransferSummary {
        transfer_id: session.transfer_id(),
        completed_files: manifest.file_count(),
        total_size: manifest.total_size(),
        path_kind: PathKind::Relay,
        relay_used: true,
    }
}

struct ResumeAcceptedInfo {
    manifest_digest: Digest,
}

async fn reconnect_ticket(
    inner: &Arc<ClientInner>,
    ticket: &ResumeTicket,
) -> Result<ResumeAcceptedInfo, ClientError> {
    inner
        .connection
        .send(&Message::Pairing(PairingControl::ResumeTransfer {
            pairing_id: ticket.pairing_id(),
            transfer_id: ticket.transfer_id(),
            role: ticket.role(),
            client_instance_id: inner.instance_id,
            resume_ticket: ticket.wire_ticket(),
        }))
        .await?;
    loop {
        match inner.connection.recv().await?.message {
            Message::Pairing(PairingControl::ResumeAccepted {
                pairing_id,
                transfer_id,
                role,
                manifest_digest,
                expires_at: _,
            }) if pairing_id == ticket.pairing_id()
                && transfer_id == ticket.transfer_id()
                && role == ticket.role() =>
            {
                return Ok(ResumeAcceptedInfo { manifest_digest });
            }
            Message::Transfer(TransferControl::TransferError { code, message, .. }) => {
                return Err(ClientError::Server { code, message });
            }
            _ => {}
        }
    }
}

fn validate_resume_sources(expected: &Manifest, actual: &Manifest) -> Result<(), ClientError> {
    if expected.file_count() != actual.file_count() || expected.total_size() != actual.total_size()
    {
        return Err(ClientError::InvalidState(
            "resume source manifest does not match",
        ));
    }
    for expected_entry in expected.entries() {
        let Some(actual_entry) = actual
            .entries()
            .iter()
            .find(|entry| entry.relative_path == expected_entry.relative_path)
        else {
            return Err(ClientError::InvalidState("resume source file is missing"));
        };
        if actual_entry.size != expected_entry.size
            || actual_entry.content_hash != expected_entry.content_hash
        {
            return Err(ClientError::InvalidState("resume source file changed"));
        }
    }
    Ok(())
}

fn random_key() -> Result<[u8; 32], ClientError> {
    let mut key = [0_u8; 32];
    fill_random(&mut key).map_err(|_| ClientError::RandomnessUnavailable)?;
    Ok(key)
}

fn unexpected_message(expected: &'static str) -> ClientError {
    ClientError::InvalidState(expected)
}

fn transfer_error(error: TransferControl) -> ClientError {
    match error {
        TransferControl::TransferError { code, message, .. } => {
            ClientError::Server { code, message }
        }
        _ => ClientError::InvalidState("unexpected server response"),
    }
}

fn progress_hash_algorithm(session: &TransferSession, file_id: FileId) -> HashAlgorithm {
    session
        .manifest()
        .and_then(|manifest| manifest.entry(file_id))
        .map(|entry| entry.content_hash.algorithm)
        .unwrap_or(HashAlgorithm::Blake3)
}
