use std::{
    collections::HashMap,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use blake3::Hasher;
use getrandom::fill as fill_random;
use reliable_udp::{Connection, Endpoint, EndpointError, ReliableStream};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::{Mutex, Semaphore},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};
use transfer_protocol::{
    Capability, CheckToken, Message, PairingCode, PairingControl, PairingId, RelayId,
    SessionTicket, TransferControl, TransferErrorScope, TransferId, TransferRole,
};

use crate::{
    config::{ServerConfig, ServerCounters, ServerMetrics},
    protocol::{read_message, write_message},
};

const ERROR_PAIRING_UNAVAILABLE: u32 = 1;
const ERROR_PAIRING_EXPIRED: u32 = 2;
const ERROR_PAIRING_ALREADY_JOINED: u32 = 3;
const ERROR_SERVER_LIMIT: u32 = 4;
const ERROR_RELAY_FAILED: u32 = 6;
const ERROR_PATH_UNAUTHORIZED: u32 = 7;

#[derive(Debug)]
pub enum ServerError {
    InvalidConfig(&'static str),
    Endpoint(EndpointError),
    Io(io::Error),
    RandomnessUnavailable,
    Closed,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(field) => write!(f, "invalid server configuration: {field}"),
            Self::Endpoint(error) => write!(f, "server endpoint error: {error}"),
            Self::Io(error) => write!(f, "server I/O error: {error}"),
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
            Self::Closed => f.write_str("server is closed"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<EndpointError> for ServerError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}

impl From<io::Error> for ServerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerRole {
    Offerer,
    Accepter,
}

type PeerWriter = Arc<Mutex<tokio::io::WriteHalf<ReliableStream>>>;

#[derive(Clone)]
struct Peer {
    connection: Connection,
    writer: PeerWriter,
}

struct PairingState {
    id: PairingId,
    expires_at: Instant,
    offerer: Peer,
    accepter: Option<Peer>,
    join_attempts: usize,
    pending_for_accepter: Vec<(Message, u64)>,
    relay_id: RelayId,
    relay_ticket: SessionTicket,
    relay_bytes: Arc<AtomicU64>,
    relay_slots: Arc<Semaphore>,
    path_authorizations: HashMap<TransferId, PathAuthorization>,
    transfers: HashMap<TransferId, ResumeState>,
}

struct ResumeState {
    manifest_digest: transfer_protocol::Digest,
    expires_at: Instant,
    expires_at_millis: u64,
    offerer_ticket: SessionTicket,
    accepter_ticket: Option<SessionTicket>,
}

struct ResumeTicketContext {
    pairing_id: PairingId,
    expires_at: u64,
    offerer_writer: PeerWriter,
    accepter_writer: Option<PeerWriter>,
    offerer_ticket: SessionTicket,
    accepter_ticket: Option<SessionTicket>,
}

struct OfferReadyRoute {
    offerer: PeerWriter,
    accepter: Option<PeerWriter>,
    relay_id: RelayId,
    relay_ticket: SessionTicket,
    authorization: PathAuthorization,
}

#[derive(Clone, Copy)]
struct PathAuthorization {
    check_token: CheckToken,
    expires_at_millis: u64,
}

struct ServerInner {
    config: ServerConfig,
    pairings: Mutex<HashMap<[u8; 32], Arc<Mutex<PairingState>>>>,
    counters: Arc<ServerCounters>,
    total_relay_bytes: AtomicU64,
}

pub struct TransferServer {
    endpoint: Arc<Endpoint>,
    inner: Arc<ServerInner>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    cleanup_task: Mutex<Option<JoinHandle<()>>>,
}

impl TransferServer {
    pub async fn bind(config: ServerConfig) -> Result<Self, ServerError> {
        config.validate().map_err(ServerError::InvalidConfig)?;
        let endpoint = Arc::new(Endpoint::bind(config.endpoint.clone()).await?);
        let inner = Arc::new(ServerInner {
            config,
            pairings: Mutex::new(HashMap::new()),
            counters: Arc::new(ServerCounters::default()),
            total_relay_bytes: AtomicU64::new(0),
        });
        let accept_inner = Arc::clone(&inner);
        let accept_endpoint = Arc::clone(&endpoint);
        let accept_task = tokio::spawn(async move {
            loop {
                let connection = match accept_endpoint.accept().await {
                    Ok(connection) => connection,
                    Err(_) => break,
                };
                let inner = Arc::clone(&accept_inner);
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(inner, connection).await {
                        tracing::debug!(%error, "transfer server connection stopped");
                    }
                });
            }
        });
        let cleanup_inner = Arc::clone(&inner);
        let cleanup_task = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                purge_expired(&cleanup_inner).await;
            }
        });
        Ok(Self {
            endpoint,
            inner,
            accept_task: Mutex::new(Some(accept_task)),
            cleanup_task: Mutex::new(Some(cleanup_task)),
        })
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.endpoint.local_addr()
    }

    pub async fn metrics(&self) -> ServerMetrics {
        ServerMetrics {
            active_pairings: self.inner.pairings.lock().await.len(),
            counters: Arc::clone(&self.inner.counters),
        }
    }

    pub async fn shutdown(&self) -> Result<(), ServerError> {
        self.endpoint.shutdown().await.map_err(ServerError::from)?;
        if let Some(task) = self.accept_task.lock().await.take() {
            task.abort();
        }
        if let Some(task) = self.cleanup_task.lock().await.take() {
            task.abort();
        }
        Ok(())
    }
}

#[allow(clippy::cognitive_complexity)]
async fn serve_connection(inner: Arc<ServerInner>, connection: Connection) -> io::Result<()> {
    let stream = connection
        .accept_stream()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let mut role = None;
    let mut pairing = None;
    loop {
        let decoded = read_message(&mut reader).await?;
        match decoded.message {
            Message::Pairing(message) => {
                if let Some(current_role) = role {
                    if let Some(session) = pairing
                        .as_ref()
                        .map(|key: &PairingKey| Arc::clone(&key.session))
                    {
                        route_pairing(
                            Arc::clone(&inner),
                            session,
                            current_role,
                            message,
                            decoded.envelope.request_id,
                            connection.clone(),
                        )
                        .await?;
                    }
                } else {
                    match message {
                        PairingControl::CreatePairing {
                            capability: Capability::Upload,
                            requested_ttl,
                            ..
                        } => {
                            match create_pairing(
                                Arc::clone(&inner),
                                Peer {
                                    connection: connection.clone(),
                                    writer: Arc::clone(&writer),
                                },
                                requested_ttl,
                            )
                            .await
                            {
                                Ok((key, response)) => {
                                    send_message(&writer, &response, decoded.envelope.request_id)
                                        .await?;
                                    role = Some(PeerRole::Offerer);
                                    pairing = Some(key);
                                }
                                Err(error) => {
                                    send_error(
                                        &writer,
                                        server_error_code(&error, ERROR_SERVER_LIMIT),
                                        &error.to_string(),
                                    )
                                    .await?;
                                }
                            }
                        }
                        PairingControl::JoinPairing { pairing_code, .. } => {
                            match join_pairing(
                                Arc::clone(&inner),
                                Peer {
                                    connection: connection.clone(),
                                    writer: Arc::clone(&writer),
                                },
                                pairing_code,
                            )
                            .await
                            {
                                Ok((key, responses)) => {
                                    for (peer_writer, message) in responses {
                                        send_message(
                                            &peer_writer,
                                            &message,
                                            decoded.envelope.request_id,
                                        )
                                        .await?;
                                    }
                                    role = Some(PeerRole::Accepter);
                                    pairing = Some(key);
                                }
                                Err(error) => {
                                    send_error(
                                        &writer,
                                        server_error_code(&error, ERROR_PAIRING_UNAVAILABLE),
                                        &error.to_string(),
                                    )
                                    .await?;
                                }
                            }
                        }
                        PairingControl::ResumeTransfer {
                            pairing_id,
                            transfer_id,
                            role: requested_role,
                            resume_ticket,
                            ..
                        } => {
                            match resume_transfer(
                                Arc::clone(&inner),
                                Peer {
                                    connection: connection.clone(),
                                    writer: Arc::clone(&writer),
                                },
                                pairing_id,
                                transfer_id,
                                requested_role,
                                resume_ticket,
                            )
                            .await
                            {
                                Ok((key, peer_role, response, peer)) => {
                                    send_message(&writer, &response, decoded.envelope.request_id)
                                        .await?;
                                    if let Some(peer) = peer {
                                        let _ = send_message(
                                            &peer.writer,
                                            &Message::Pairing(PairingControl::PeerReconnected {
                                                transfer_id,
                                                role: requested_role,
                                            }),
                                            decoded.envelope.request_id,
                                        )
                                        .await;
                                    }
                                    role = Some(peer_role);
                                    pairing = Some(key);
                                }
                                Err(error) => {
                                    send_error(
                                        &writer,
                                        server_error_code(&error, ERROR_PAIRING_UNAVAILABLE),
                                        &error.to_string(),
                                    )
                                    .await?;
                                }
                            }
                        }
                        _ => {
                            send_error(&writer, ERROR_PAIRING_UNAVAILABLE, "pairing is required")
                                .await?;
                        }
                    }
                }
            }
            message => {
                if let (Some(current_role), Some(key)) = (role, pairing.as_ref()) {
                    if let Err(error) = route_message(
                        Arc::clone(&inner),
                        Arc::clone(&key.session),
                        current_role,
                        message,
                        decoded.envelope.request_id,
                        connection.clone(),
                    )
                    .await
                    {
                        send_error(
                            &writer,
                            server_error_code(&error, ERROR_PAIRING_EXPIRED),
                            &error.to_string(),
                        )
                        .await?;
                    }
                } else {
                    send_error(&writer, ERROR_PAIRING_UNAVAILABLE, "pairing is required").await?;
                }
            }
        }
    }
}

#[derive(Clone)]
struct PairingKey {
    session: Arc<Mutex<PairingState>>,
}

async fn create_pairing(
    inner: Arc<ServerInner>,
    offerer: Peer,
    requested_ttl: u32,
) -> io::Result<(PairingKey, Message)> {
    purge_expired(&inner).await;
    let requested_ttl = Duration::from_secs(u64::from(requested_ttl));
    let ttl = if requested_ttl.is_zero() {
        inner.config.pairing_ttl
    } else {
        requested_ttl.min(inner.config.pairing_ttl)
    };
    let pairing_id = PairingId::random().map_err(|_| io::Error::other("randomness unavailable"))?;
    let pairing_code =
        PairingCode::generate().map_err(|_| io::Error::other("randomness unavailable"))?;
    let relay_id = RelayId::random().map_err(|_| io::Error::other("randomness unavailable"))?;
    let relay_ticket = random_ticket()?;
    let now = Instant::now();
    let session = Arc::new(Mutex::new(PairingState {
        id: pairing_id,
        expires_at: now + ttl,
        offerer,
        accepter: None,
        join_attempts: 0,
        pending_for_accepter: Vec::new(),
        relay_id,
        relay_ticket: relay_ticket.clone(),
        relay_bytes: Arc::new(AtomicU64::new(0)),
        relay_slots: Arc::new(Semaphore::new(inner.config.relay.max_streams_per_session)),
        path_authorizations: HashMap::new(),
        transfers: HashMap::new(),
    }));
    let key = pairing_key(&pairing_code);
    let mut pairings = inner.pairings.lock().await;
    if pairings.len() >= inner.config.max_pairings {
        return Err(server_error(ERROR_SERVER_LIMIT, "pairing limit reached"));
    }
    if pairings.contains_key(&key) {
        return Err(io::Error::other("pairing code collision"));
    }
    pairings.insert(key, Arc::clone(&session));
    drop(pairings);
    inner
        .counters
        .created_pairings
        .fetch_add(1, Ordering::Relaxed);
    Ok((
        PairingKey { session },
        Message::Pairing(PairingControl::PairingCreated {
            pairing_id,
            pairing_code,
            expires_at: unix_millis_after(ttl),
            server_session_ticket: relay_ticket,
        }),
    ))
}

async fn resume_transfer(
    inner: Arc<ServerInner>,
    peer: Peer,
    pairing_id: PairingId,
    transfer_id: TransferId,
    role: TransferRole,
    resume_ticket: SessionTicket,
) -> io::Result<(PairingKey, PeerRole, Message, Option<Peer>)> {
    let sessions = inner
        .pairings
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for session in sessions {
        let mut state = session.lock().await;
        if state.id != pairing_id || state.expires_at <= Instant::now() {
            continue;
        }
        let Some(resume) = state.transfers.get(&transfer_id) else {
            continue;
        };
        if resume.expires_at <= Instant::now() {
            return Err(server_error(
                ERROR_PAIRING_EXPIRED,
                "resume ticket has expired",
            ));
        }
        let expected = match role {
            TransferRole::Offerer => &resume.offerer_ticket,
            TransferRole::Accepter => resume
                .accepter_ticket
                .as_ref()
                .ok_or_else(|| server_error(ERROR_PAIRING_UNAVAILABLE, "accepter is not ready"))?,
        };
        if expected != &resume_ticket {
            return Err(server_error(
                ERROR_PAIRING_UNAVAILABLE,
                "resume ticket is invalid",
            ));
        }
        let manifest_digest = resume.manifest_digest;
        let expires_at_millis = resume.expires_at_millis;

        match role {
            TransferRole::Offerer => {
                let _ = std::mem::replace(&mut state.offerer, peer);
                let counterpart = state.accepter.clone();
                let response = Message::Pairing(PairingControl::ResumeAccepted {
                    pairing_id,
                    transfer_id,
                    role,
                    manifest_digest,
                    expires_at: expires_at_millis,
                });
                return Ok((
                    PairingKey {
                        session: Arc::clone(&session),
                    },
                    PeerRole::Offerer,
                    response,
                    counterpart,
                ));
            }
            TransferRole::Accepter => {
                let counterpart = state.offerer.clone();
                state.accepter = Some(peer);
                let response = Message::Pairing(PairingControl::ResumeAccepted {
                    pairing_id,
                    transfer_id,
                    role,
                    manifest_digest,
                    expires_at: expires_at_millis,
                });
                return Ok((
                    PairingKey {
                        session: Arc::clone(&session),
                    },
                    PeerRole::Accepter,
                    response,
                    Some(counterpart),
                ));
            }
        };
    }
    Err(server_error(
        ERROR_PAIRING_UNAVAILABLE,
        "resume ticket is unknown",
    ))
}

async fn join_pairing(
    inner: Arc<ServerInner>,
    accepter: Peer,
    code: PairingCode,
) -> io::Result<(
    PairingKey,
    Vec<(Arc<Mutex<tokio::io::WriteHalf<ReliableStream>>>, Message)>,
)> {
    purge_expired(&inner).await;
    let session = inner
        .pairings
        .lock()
        .await
        .get(&pairing_key(&code))
        .cloned()
        .ok_or_else(|| server_error(ERROR_PAIRING_UNAVAILABLE, "pairing code is unknown"))?;
    let mut state = session.lock().await;
    if state.expires_at <= Instant::now() {
        return Err(server_error(
            ERROR_PAIRING_EXPIRED,
            "pairing code has expired",
        ));
    }
    state.join_attempts += 1;
    if state.join_attempts > inner.config.max_join_attempts {
        inner
            .counters
            .rejected_joins
            .fetch_add(1, Ordering::Relaxed);
        return Err(server_error(
            ERROR_PAIRING_UNAVAILABLE,
            "pairing attempts are limited",
        ));
    }
    if state.accepter.is_some() {
        inner
            .counters
            .rejected_joins
            .fetch_add(1, Ordering::Relaxed);
        return Err(server_error(
            ERROR_PAIRING_ALREADY_JOINED,
            "pairing already has an accepter",
        ));
    }
    state.accepter = Some(accepter.clone());
    let offerer_writer = Arc::clone(&state.offerer.writer);
    let accepter_writer = Arc::clone(&accepter.writer);
    let pairing_id = state.id;
    let relay_id = state.relay_id;
    let relay_ticket = state.relay_ticket.clone();
    let pending = std::mem::take(&mut state.pending_for_accepter);
    let offerer_connection = state.offerer.connection.clone();
    let offerer_for_auth = Arc::clone(&state.offerer.writer);
    let path_auth = pending.iter().find_map(|(message, _)| {
        let Message::Pairing(PairingControl::OfferReady { transfer_id, .. }) = message else {
            return None;
        };
        Some((
            *transfer_id,
            ensure_path_authorization(&mut state, *transfer_id),
        ))
    });
    let mut pending_resume_tickets = HashMap::new();
    for (message, _) in &pending {
        let Message::Pairing(PairingControl::OfferReady {
            transfer_id,
            manifest_digest,
            ..
        }) = message
        else {
            continue;
        };
        let pairing_id = state.id;
        let resume = state
            .transfers
            .get_mut(transfer_id)
            .ok_or_else(|| io::Error::other("resume state is missing for offered transfer"))?;
        let ticket = ensure_accepter_ticket(resume)?;
        pending_resume_tickets.insert(
            *transfer_id,
            resume_ticket_message(
                pairing_id,
                *transfer_id,
                TransferRole::Accepter,
                *manifest_digest,
                resume.expires_at_millis,
                ticket,
            ),
        );
    }
    drop(state);
    inner
        .counters
        .joined_pairings
        .fetch_add(1, Ordering::Relaxed);
    let joined_offerer = Message::Pairing(PairingControl::PairingJoined {
        pairing_id,
        offerer_identity_hint: "offerer".to_owned(),
        accepter_identity_hint: "accepter".to_owned(),
        peer_control_ticket: random_ticket()?,
    });
    let joined_accepter = joined_offerer.clone();
    let mut responses = vec![
        (Arc::clone(&offerer_writer), joined_offerer),
        (Arc::clone(&accepter_writer), joined_accepter),
    ];
    for (message, request_id) in pending {
        if let Message::Pairing(PairingControl::OfferReady { transfer_id, .. }) = &message {
            if let Some(ticket) = pending_resume_tickets.get(transfer_id) {
                responses.push((Arc::clone(&accepter_writer), ticket.clone()));
            }
            if let Some((auth_transfer_id, Ok(authorization))) = path_auth
                && auth_transfer_id == *transfer_id
            {
                let authorization = path_authorization_message(*transfer_id, authorization);
                responses.push((Arc::clone(&offerer_for_auth), authorization.clone()));
                responses.push((Arc::clone(&accepter_writer), authorization));
            }
            responses.push((
                Arc::clone(&offerer_writer),
                relay_open(*transfer_id, relay_id, relay_ticket.clone()),
            ));
            responses.push((
                Arc::clone(&accepter_writer),
                relay_open(*transfer_id, relay_id, relay_ticket.clone()),
            ));
        }
        responses.push((Arc::clone(&accepter_writer), message.clone()));
        if let Message::Transfer(TransferControl::FileBegin { .. }) = message {
            spawn_relay(
                Arc::clone(&inner),
                Arc::clone(&session),
                offerer_connection.clone(),
                accepter.connection.clone(),
            );
        }
        let _ = request_id;
    }
    Ok((PairingKey { session }, responses))
}

async fn route_pairing(
    inner: Arc<ServerInner>,
    session: Arc<Mutex<PairingState>>,
    role: PeerRole,
    message: PairingControl,
    request_id: u64,
    source_connection: Connection,
) -> io::Result<()> {
    route_message(
        inner,
        session,
        role,
        Message::Pairing(message),
        request_id,
        source_connection,
    )
    .await
}

async fn route_message(
    inner: Arc<ServerInner>,
    session: Arc<Mutex<PairingState>>,
    role: PeerRole,
    message: Message,
    request_id: u64,
    source_connection: Connection,
) -> io::Result<()> {
    validate_message_role(role, &message)?;
    if let Message::Pairing(PairingControl::OfferReady { transfer_id, .. }) = &message {
        let manifest_digest = match &message {
            Message::Pairing(PairingControl::OfferReady {
                manifest_digest, ..
            }) => *manifest_digest,
            _ => unreachable!(),
        };
        let resume_context = {
            let mut state = session.lock().await;
            ensure_path_authorization(&mut state, *transfer_id)?;
            let pairing_id = state.id;
            let accepter_present = state.accepter.is_some();
            let resume = ensure_resume_state(&mut state, *transfer_id, manifest_digest)?;
            let expires_at = resume.expires_at_millis;
            let offerer_ticket = resume.offerer_ticket.clone();
            let accepter_ticket = if accepter_present {
                Some(ensure_accepter_ticket(resume)?)
            } else {
                None
            };
            ResumeTicketContext {
                pairing_id,
                expires_at,
                offerer_writer: Arc::clone(&state.offerer.writer),
                accepter_writer: state.accepter.as_ref().map(|peer| Arc::clone(&peer.writer)),
                offerer_ticket,
                accepter_ticket,
            }
        };
        send_message(
            &resume_context.offerer_writer,
            &resume_ticket_message(
                resume_context.pairing_id,
                *transfer_id,
                TransferRole::Offerer,
                manifest_digest,
                resume_context.expires_at,
                resume_context.offerer_ticket,
            ),
            request_id,
        )
        .await?;
        if let (Some(writer), Some(ticket)) = (
            resume_context.accepter_writer,
            resume_context.accepter_ticket,
        ) {
            send_message(
                &writer,
                &resume_ticket_message(
                    resume_context.pairing_id,
                    *transfer_id,
                    TransferRole::Accepter,
                    manifest_digest,
                    resume_context.expires_at,
                    ticket,
                ),
                request_id,
            )
            .await?;
        }
    }
    if let Message::Pairing(message) = &message {
        validate_path_authorization(&session, message).await?;
    }
    let target = {
        let mut state = session.lock().await;
        if state.expires_at <= Instant::now() {
            return Err(server_error(
                ERROR_PAIRING_EXPIRED,
                "pairing session has expired",
            ));
        }
        match (role, state.accepter.as_ref()) {
            (PeerRole::Offerer, Some(peer)) => Some(peer.clone()),
            (PeerRole::Accepter, _) => Some(state.offerer.clone()),
            (PeerRole::Offerer, None) => {
                if state.pending_for_accepter.len() >= inner.config.max_pending_messages {
                    return Err(server_error(
                        ERROR_SERVER_LIMIT,
                        "pairing control queue is full",
                    ));
                }
                state
                    .pending_for_accepter
                    .push((message.clone(), request_id));
                None
            }
        }
    };
    let Some(target) = target else {
        return Ok(());
    };
    if let Message::Pairing(PairingControl::OfferReady { transfer_id, .. }) = &message {
        let route = {
            let state = session.lock().await;
            let authorization = state
                .path_authorizations
                .get(transfer_id)
                .copied()
                .ok_or_else(|| io::Error::other("path authorization was not created"))?;
            OfferReadyRoute {
                offerer: Arc::clone(&state.offerer.writer),
                accepter: state.accepter.as_ref().map(|peer| Arc::clone(&peer.writer)),
                relay_id: state.relay_id,
                relay_ticket: state.relay_ticket.clone(),
                authorization,
            }
        };
        let authorization = path_authorization_message(*transfer_id, route.authorization);
        send_message(&route.offerer, &authorization, request_id).await?;
        if let Some(accepter) = &route.accepter {
            send_message(accepter, &authorization, request_id).await?;
        }
        let relay = relay_open(*transfer_id, route.relay_id, route.relay_ticket);
        send_message(&route.offerer, &relay, request_id).await?;
        if let Some(accepter) = route.accepter {
            send_message(&accepter, &relay, request_id).await?;
        }
    }
    if let Message::Transfer(TransferControl::FileBegin { .. }) = &message {
        if role != PeerRole::Offerer {
            send_error(
                &target.writer,
                ERROR_RELAY_FAILED,
                "only the offerer may open a data stream",
            )
            .await?;
            return Ok(());
        }
        send_message(&target.writer, &message, request_id).await?;
        spawn_relay(inner, session, source_connection, target.connection);
    } else {
        send_message(&target.writer, &message, request_id).await?;
    }
    Ok(())
}

fn validate_message_role(role: PeerRole, message: &Message) -> io::Result<()> {
    let forbidden = match message {
        Message::Pairing(PairingControl::OfferReady { .. })
        | Message::Pairing(PairingControl::RelayOpen { .. })
        | Message::Pairing(PairingControl::PathCheckAuthorization { .. })
        | Message::Pairing(PairingControl::ResumeTicket { .. })
        | Message::Pairing(PairingControl::ResumeTransfer { .. })
        | Message::Pairing(PairingControl::ResumeAccepted { .. })
        | Message::Pairing(PairingControl::PeerReconnected { .. }) => role == PeerRole::Accepter,
        Message::Transfer(TransferControl::FileBegin { .. }) => role == PeerRole::Accepter,
        _ => false,
    };
    if forbidden {
        return Err(server_error(
            ERROR_PATH_UNAUTHORIZED,
            "message is not allowed for this pairing role",
        ));
    }
    Ok(())
}

async fn validate_path_authorization(
    session: &Arc<Mutex<PairingState>>,
    message: &PairingControl,
) -> io::Result<()> {
    let PairingControl::PathCheckAuthorization {
        transfer_id,
        check_token,
        expires_at,
    } = message
    else {
        return Ok(());
    };
    let state = session.lock().await;
    let Some(expected) = state.path_authorizations.get(transfer_id) else {
        return Err(server_error(
            ERROR_PATH_UNAUTHORIZED,
            "path check authorization is unknown",
        ));
    };
    if expected.check_token != *check_token || expected.expires_at_millis != *expires_at {
        return Err(server_error(
            ERROR_PATH_UNAUTHORIZED,
            "path check authorization does not match the transfer",
        ));
    }
    if unix_millis_now() >= *expires_at {
        return Err(server_error(
            ERROR_PATH_UNAUTHORIZED,
            "path check authorization has expired",
        ));
    }
    Ok(())
}

fn spawn_relay(
    inner: Arc<ServerInner>,
    session: Arc<Mutex<PairingState>>,
    source_connection: Connection,
    target_connection: Connection,
) {
    tokio::spawn(async move {
        let permit = match session.lock().await.relay_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let _ =
                    send_relay_error(&session, ERROR_RELAY_FAILED, "relay stream limit reached")
                        .await;
                return;
            }
        };
        let result = relay_stream(
            Arc::clone(&inner),
            Arc::clone(&session),
            source_connection,
            target_connection,
        )
        .await;
        drop(permit);
        if let Err(error) = result {
            inner
                .counters
                .relay_failures
                .fetch_add(1, Ordering::Relaxed);
            let _ = send_relay_error(&session, ERROR_RELAY_FAILED, &error.to_string()).await;
        }
    });
}

async fn relay_stream(
    inner: Arc<ServerInner>,
    session: Arc<Mutex<PairingState>>,
    source_connection: Connection,
    target_connection: Connection,
) -> io::Result<()> {
    let mut source = source_connection
        .accept_stream()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut target = target_connection
        .open_stream()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let relay_bytes = session.lock().await.relay_bytes.clone();
    let buffer_size = inner.config.relay.buffer_size;
    let mut buffer = vec![0_u8; buffer_size];
    let result = loop {
        let count = match tokio::io::AsyncReadExt::read(&mut source, &mut buffer).await {
            Ok(count) => count,
            Err(error) => break Err(error),
        };
        if count == 0 {
            break Ok(());
        }
        let allowed = match reserve_relay_bytes(&inner, &relay_bytes, count) {
            Ok(allowed) => allowed,
            Err(error) => break Err(error),
        };
        if let Err(error) = target.write_all(&buffer[..allowed]).await {
            break Err(error);
        }
        if allowed != count {
            break Err(io::Error::other("relay byte quota exceeded"));
        }
    };
    let shutdown = target
        .shutdown()
        .await
        .map_err(|error| io::Error::other(error.to_string()));
    result.and(shutdown)
}

fn reserve_relay_bytes(
    inner: &ServerInner,
    session_bytes: &AtomicU64,
    count: usize,
) -> io::Result<usize> {
    let count = u64::try_from(count).map_err(|_| io::Error::other("byte count overflow"))?;
    if reserve_counter(
        session_bytes,
        count,
        inner.config.relay.max_bytes_per_session,
    )
    .is_none()
    {
        return Err(io::Error::other("per-session relay quota exceeded"));
    }
    if reserve_counter(
        &inner.total_relay_bytes,
        count,
        inner.config.relay.max_bytes_total,
    )
    .is_none()
    {
        session_bytes.fetch_sub(count, Ordering::Relaxed);
        return Err(io::Error::other("server relay quota exceeded"));
    }
    inner
        .counters
        .relay_bytes
        .fetch_add(count, Ordering::Relaxed);
    Ok(usize::try_from(count).unwrap_or(usize::MAX))
}

fn reserve_counter(counter: &AtomicU64, amount: u64, limit: u64) -> Option<()> {
    if limit == 0 {
        counter.fetch_add(amount, Ordering::Relaxed);
        return Some(());
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(amount)?;
        if next > limit {
            return None;
        }
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(()),
            Err(observed) => current = observed,
        }
    }
}

async fn send_relay_error(
    session: &Arc<Mutex<PairingState>>,
    code: u32,
    text: &str,
) -> io::Result<()> {
    let (offerer, accepter) = {
        let state = session.lock().await;
        (
            Arc::clone(&state.offerer.writer),
            state.accepter.as_ref().map(|peer| Arc::clone(&peer.writer)),
        )
    };
    let message = Message::Transfer(TransferControl::TransferError {
        scope: TransferErrorScope::Path,
        code,
        retryable: false,
        message: text.chars().take(256).collect(),
    });
    send_message(&offerer, &message, 0).await?;
    if let Some(accepter) = accepter {
        send_message(&accepter, &message, 0).await?;
    }
    Ok(())
}

async fn send_error(
    writer: &Arc<Mutex<tokio::io::WriteHalf<ReliableStream>>>,
    code: u32,
    text: &str,
) -> io::Result<()> {
    let message = Message::Transfer(TransferControl::TransferError {
        scope: TransferErrorScope::Session,
        code,
        retryable: false,
        message: text.to_owned(),
    });
    send_message(writer, &message, 0).await
}

async fn send_message<W: AsyncWrite + Unpin>(
    writer: &Arc<Mutex<W>>,
    message: &Message,
    request_id: u64,
) -> io::Result<()> {
    let mut writer = writer.lock().await;
    write_message(&mut *writer, message, request_id).await
}

fn purge_expired_blocking(
    pairings: &mut HashMap<[u8; 32], Arc<Mutex<PairingState>>>,
) -> Vec<Arc<Mutex<PairingState>>> {
    let now = Instant::now();
    let expired = pairings
        .iter()
        .filter_map(|(key, state)| {
            state
                .try_lock()
                .ok()
                .and_then(|state| (state.expires_at <= now).then_some(*key))
        })
        .collect::<Vec<_>>();
    expired
        .into_iter()
        .filter_map(|key| pairings.remove(&key))
        .collect()
}

async fn purge_expired(inner: &ServerInner) {
    let expired = purge_expired_blocking(&mut *inner.pairings.lock().await);
    if !expired.is_empty() {
        inner
            .counters
            .expired_pairings
            .fetch_add(expired.len() as u64, Ordering::Relaxed);
    }
}

fn pairing_key(code: &PairingCode) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"udp-transfer-pairing-v1\0");
    hasher.update(code.as_str().as_bytes());
    *hasher.finalize().as_bytes()
}

fn random_ticket() -> io::Result<SessionTicket> {
    let mut bytes = vec![0_u8; 32];
    fill_random(&mut bytes).map_err(|_| io::Error::other("randomness unavailable"))?;
    Ok(SessionTicket::new(bytes))
}

fn ensure_resume_state(
    state: &mut PairingState,
    transfer_id: TransferId,
    manifest_digest: transfer_protocol::Digest,
) -> io::Result<&mut ResumeState> {
    if let Some(existing) = state.transfers.get(&transfer_id) {
        if existing.manifest_digest != manifest_digest {
            return Err(io::Error::other("transfer manifest changed"));
        }
        return state
            .transfers
            .get_mut(&transfer_id)
            .ok_or_else(|| io::Error::other("resume state disappeared"));
    }
    let expires_at = state.expires_at;
    let resume = ResumeState {
        manifest_digest,
        expires_at,
        expires_at_millis: unix_millis_after(expires_at.saturating_duration_since(Instant::now())),
        offerer_ticket: random_ticket()?,
        accepter_ticket: None,
    };
    state.transfers.insert(transfer_id, resume);
    state
        .transfers
        .get_mut(&transfer_id)
        .ok_or_else(|| io::Error::other("resume state was not inserted"))
}

fn ensure_accepter_ticket(resume: &mut ResumeState) -> io::Result<SessionTicket> {
    if let Some(ticket) = &resume.accepter_ticket {
        return Ok(ticket.clone());
    }
    let ticket = random_ticket()?;
    resume.accepter_ticket = Some(ticket.clone());
    Ok(ticket)
}

fn resume_ticket_message(
    pairing_id: PairingId,
    transfer_id: TransferId,
    role: TransferRole,
    manifest_digest: transfer_protocol::Digest,
    expires_at: u64,
    resume_ticket: SessionTicket,
) -> Message {
    Message::Pairing(PairingControl::ResumeTicket {
        pairing_id,
        transfer_id,
        role,
        manifest_digest,
        expires_at,
        resume_ticket,
    })
}

fn ensure_path_authorization(
    state: &mut PairingState,
    transfer_id: TransferId,
) -> io::Result<PathAuthorization> {
    if let Some(authorization) = state.path_authorizations.get(&transfer_id).copied()
        && unix_millis_now() < authorization.expires_at_millis
    {
        return Ok(authorization);
    }
    let authorization = PathAuthorization {
        check_token: CheckToken::random()
            .map_err(|_| io::Error::other("randomness unavailable"))?,
        expires_at_millis: unix_millis_after(Duration::from_secs(30)),
    };
    state.path_authorizations.insert(transfer_id, authorization);
    Ok(authorization)
}

fn path_authorization_message(
    transfer_id: TransferId,
    authorization: PathAuthorization,
) -> Message {
    Message::Pairing(PairingControl::PathCheckAuthorization {
        transfer_id,
        check_token: authorization.check_token,
        expires_at: authorization.expires_at_millis,
    })
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn unix_millis_after(duration: Duration) -> u64 {
    let millis = u128::from(unix_millis_now());
    millis
        .saturating_add(duration.as_millis())
        .min(u128::from(u64::MAX)) as u64
}

fn relay_open(
    transfer_id: transfer_protocol::TransferId,
    relay_id: RelayId,
    relay_ticket: SessionTicket,
) -> Message {
    Message::Pairing(PairingControl::RelayOpen {
        transfer_id,
        relay_id,
        relay_ticket,
    })
}

fn server_error(code: u32, message: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{code}: {message}"),
    )
}

fn server_error_code(error: &io::Error, fallback: u32) -> u32 {
    error
        .to_string()
        .split_once(':')
        .and_then(|(code, _)| code.parse().ok())
        .unwrap_or(fallback)
}

impl fmt::Display for PeerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offerer => f.write_str("offerer"),
            Self::Accepter => f.write_str("accepter"),
        }
    }
}
