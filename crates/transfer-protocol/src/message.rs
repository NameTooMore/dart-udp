use std::net::SocketAddr;

use crate::{
    error::ProtocolError,
    types::{
        CandidateId, CheckToken, ClientInstanceId, Digest, FileId, PairingCode, PairingId, PathId,
        RelayId, SessionTicket, TransactionId, TransferId,
    },
};

pub const MAX_CANDIDATES: usize = 64;
pub const MAX_MANIFEST_FILES: usize = 1_000_000;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_DISPLAY_NAME_LEN: usize = 256;
pub const MAX_IDENTITY_HINT_LEN: usize = 256;
pub const MAX_ROOT_LABEL_LEN: usize = 256;
pub const MAX_TICKET_LEN: usize = 4096;
pub const MAX_TRANSFER_ERROR_MESSAGE_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Pairing(PairingControl),
    Transfer(TransferControl),
    Path(PathCheck),
}

impl Message {
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Pairing(message) => message.message_type(),
            Self::Transfer(message) => message.message_type(),
            Self::Path(message) => message.message_type(),
        }
    }

    pub fn encode(
        &self,
        request_id: u64,
        flags: crate::MessageFlags,
    ) -> Result<Vec<u8>, ProtocolError> {
        crate::encode_message(self, request_id, flags)
    }

    pub fn decode(bytes: &[u8]) -> Result<crate::DecodedMessage, ProtocolError> {
        crate::decode_message(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    CreatePairing = 1,
    PairingCreated = 2,
    JoinPairing = 3,
    PairingJoined = 4,
    OfferReady = 5,
    AcceptOffer = 6,
    CandidateList = 7,
    PathCheckAuthorization = 8,
    PathSelected = 9,
    RelayOpen = 10,
    RelayClosed = 11,
    Cancel = 12,
    ResumeTicket = 13,
    ResumeTransfer = 14,
    ResumeAccepted = 15,
    PeerReconnected = 16,
    SessionHello = 20,
    ManifestBegin = 21,
    ManifestItem = 22,
    ManifestEnd = 23,
    ReceiveDecision = 24,
    ResumeQuery = 25,
    ResumeState = 26,
    FileBegin = 27,
    Checkpoint = 28,
    FileComplete = 29,
    FileRejected = 30,
    TransferComplete = 31,
    TransferError = 32,
    PathCheckRequest = 40,
    PathCheckResponse = 41,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let message_type = match value {
            1 => Self::CreatePairing,
            2 => Self::PairingCreated,
            3 => Self::JoinPairing,
            4 => Self::PairingJoined,
            5 => Self::OfferReady,
            6 => Self::AcceptOffer,
            7 => Self::CandidateList,
            8 => Self::PathCheckAuthorization,
            9 => Self::PathSelected,
            10 => Self::RelayOpen,
            11 => Self::RelayClosed,
            12 => Self::Cancel,
            13 => Self::ResumeTicket,
            14 => Self::ResumeTransfer,
            15 => Self::ResumeAccepted,
            16 => Self::PeerReconnected,
            20 => Self::SessionHello,
            21 => Self::ManifestBegin,
            22 => Self::ManifestItem,
            23 => Self::ManifestEnd,
            24 => Self::ReceiveDecision,
            25 => Self::ResumeQuery,
            26 => Self::ResumeState,
            27 => Self::FileBegin,
            28 => Self::Checkpoint,
            29 => Self::FileComplete,
            30 => Self::FileRejected,
            31 => Self::TransferComplete,
            32 => Self::TransferError,
            40 => Self::PathCheckRequest,
            41 => Self::PathCheckResponse,
            value => return Err(ProtocolError::UnknownMessageType { value }),
        };
        Ok(message_type)
    }
}

impl PairingControl {
    pub(crate) fn message_type(&self) -> MessageType {
        match self {
            Self::CreatePairing { .. } => MessageType::CreatePairing,
            Self::PairingCreated { .. } => MessageType::PairingCreated,
            Self::JoinPairing { .. } => MessageType::JoinPairing,
            Self::PairingJoined { .. } => MessageType::PairingJoined,
            Self::OfferReady { .. } => MessageType::OfferReady,
            Self::AcceptOffer { .. } => MessageType::AcceptOffer,
            Self::CandidateList { .. } => MessageType::CandidateList,
            Self::PathCheckAuthorization { .. } => MessageType::PathCheckAuthorization,
            Self::PathSelected { .. } => MessageType::PathSelected,
            Self::RelayOpen { .. } => MessageType::RelayOpen,
            Self::RelayClosed { .. } => MessageType::RelayClosed,
            Self::Cancel { .. } => MessageType::Cancel,
            Self::ResumeTicket { .. } => MessageType::ResumeTicket,
            Self::ResumeTransfer { .. } => MessageType::ResumeTransfer,
            Self::ResumeAccepted { .. } => MessageType::ResumeAccepted,
            Self::PeerReconnected { .. } => MessageType::PeerReconnected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingControl {
    CreatePairing {
        client_instance_id: ClientInstanceId,
        capability: Capability,
        requested_ttl: u32,
        client_ephemeral_key: [u8; 32],
    },
    PairingCreated {
        pairing_id: PairingId,
        pairing_code: PairingCode,
        expires_at: u64,
        server_session_ticket: SessionTicket,
    },
    JoinPairing {
        pairing_code: PairingCode,
        client_instance_id: ClientInstanceId,
        client_ephemeral_key: [u8; 32],
    },
    PairingJoined {
        pairing_id: PairingId,
        offerer_identity_hint: String,
        accepter_identity_hint: String,
        peer_control_ticket: SessionTicket,
    },
    OfferReady {
        transfer_id: TransferId,
        manifest_digest: Digest,
        file_count: u64,
        total_size: u64,
        sender_display_name: String,
    },
    AcceptOffer {
        transfer_id: TransferId,
        decision: AcceptDecision,
        receiver_root_policy: String,
    },
    CandidateList {
        transfer_id: TransferId,
        candidates: Vec<Candidate>,
        candidate_digest: Digest,
    },
    PathCheckAuthorization {
        transfer_id: TransferId,
        check_token: CheckToken,
        expires_at: u64,
    },
    PathSelected {
        transfer_id: TransferId,
        path_id: PathId,
        kind: PathKind,
        rtt_millis: u64,
        mtu: u16,
    },
    RelayOpen {
        transfer_id: TransferId,
        relay_id: RelayId,
        relay_ticket: SessionTicket,
    },
    RelayClosed {
        transfer_id: TransferId,
        reason: RelayCloseReason,
    },
    Cancel {
        transfer_id: TransferId,
        reason_code: u16,
    },
    ResumeTicket {
        pairing_id: PairingId,
        transfer_id: TransferId,
        role: TransferRole,
        manifest_digest: Digest,
        expires_at: u64,
        resume_ticket: SessionTicket,
    },
    ResumeTransfer {
        pairing_id: PairingId,
        transfer_id: TransferId,
        role: TransferRole,
        client_instance_id: ClientInstanceId,
        resume_ticket: SessionTicket,
    },
    ResumeAccepted {
        pairing_id: PairingId,
        transfer_id: TransferId,
        role: TransferRole,
        manifest_digest: Digest,
        expires_at: u64,
    },
    PeerReconnected {
        transfer_id: TransferId,
        role: TransferRole,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferRole {
    Offerer = 1,
    Accepter = 2,
}

impl TryFrom<u8> for TransferRole {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Offerer),
            2 => Ok(Self::Accepter),
            _ => Err(ProtocolError::InvalidValue {
                field: "transfer role",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Capability {
    Upload = 1,
}

impl TryFrom<u8> for Capability {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Upload),
            _ => Err(ProtocolError::InvalidValue {
                field: "capability",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AcceptDecision {
    Accept = 1,
    Reject = 2,
}

impl TryFrom<u8> for AcceptDecision {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Accept),
            2 => Ok(Self::Reject),
            _ => Err(ProtocolError::InvalidValue { field: "decision" }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CandidateKind {
    Host = 1,
    RoutedLan = 2,
    ServerReflexive = 3,
    PeerReflexive = 4,
    Relay = 5,
}

impl TryFrom<u8> for CandidateKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::RoutedLan),
            3 => Ok(Self::ServerReflexive),
            4 => Ok(Self::PeerReflexive),
            5 => Ok(Self::Relay),
            _ => Err(ProtocolError::InvalidValue {
                field: "candidate kind",
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: CandidateId,
    pub kind: CandidateKind,
    pub address: Option<SocketAddr>,
    pub priority: u16,
    pub interface_index: Option<u32>,
}

impl Candidate {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.kind == CandidateKind::Relay {
            if self.address.is_some() {
                return Err(ProtocolError::InvalidValue {
                    field: "relay candidate address",
                });
            }
        } else {
            let Some(address) = self.address else {
                return Err(ProtocolError::InvalidValue {
                    field: "candidate address",
                });
            };
            if address.ip().is_unspecified() || address.ip().is_multicast() || address.port() == 0 {
                return Err(ProtocolError::InvalidValue {
                    field: "candidate address",
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PathKind {
    Host = 1,
    RoutedLan = 2,
    ReflexiveDirect = 3,
    Relay = 4,
}

impl TryFrom<u8> for PathKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::RoutedLan),
            3 => Ok(Self::ReflexiveDirect),
            4 => Ok(Self::Relay),
            _ => Err(ProtocolError::InvalidValue { field: "path kind" }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCloseReason {
    Complete = 1,
    Cancelled = 2,
    Failed = 3,
    Expired = 4,
}

impl TryFrom<u8> for RelayCloseReason {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Complete),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::Failed),
            4 => Ok(Self::Expired),
            _ => Err(ProtocolError::InvalidValue {
                field: "relay close reason",
            }),
        }
    }
}

impl TransferControl {
    pub(crate) fn message_type(&self) -> MessageType {
        match self {
            Self::SessionHello { .. } => MessageType::SessionHello,
            Self::ManifestBegin { .. } => MessageType::ManifestBegin,
            Self::ManifestItem { .. } => MessageType::ManifestItem,
            Self::ManifestEnd { .. } => MessageType::ManifestEnd,
            Self::ReceiveDecision { .. } => MessageType::ReceiveDecision,
            Self::ResumeQuery { .. } => MessageType::ResumeQuery,
            Self::ResumeState { .. } => MessageType::ResumeState,
            Self::FileBegin { .. } => MessageType::FileBegin,
            Self::Checkpoint { .. } => MessageType::Checkpoint,
            Self::FileComplete { .. } => MessageType::FileComplete,
            Self::FileRejected { .. } => MessageType::FileRejected,
            Self::TransferComplete { .. } => MessageType::TransferComplete,
            Self::TransferError { .. } => MessageType::TransferError,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferControl {
    SessionHello {
        transfer_id: TransferId,
        protocol_version: u8,
        crypto_suite: CryptoSuite,
        manifest_digest: Digest,
        resume_namespace: [u8; 16],
    },
    ManifestBegin {
        file_count: u64,
        total_size: u64,
        manifest_digest: Digest,
    },
    ManifestItem {
        file_id: FileId,
        relative_path: String,
        size: u64,
        content_hash: Digest,
        metadata: FileMetadata,
    },
    ManifestEnd {
        manifest_digest: Digest,
    },
    ReceiveDecision {
        accepted: bool,
        overwrite_policy: OverwritePolicy,
        target_root_label: String,
    },
    ResumeQuery {
        file_id: FileId,
        content_hash: Digest,
        size: u64,
    },
    ResumeState {
        file_id: FileId,
        durable_offset: u64,
        checkpoint_id: u64,
        state_hash: Digest,
    },
    FileBegin {
        file_id: FileId,
        data_stream_id: u64,
        base_offset: u64,
        remaining_size: u64,
        content_hash: Digest,
    },
    Checkpoint {
        file_id: FileId,
        durable_offset: u64,
        checkpoint_id: u64,
    },
    FileComplete {
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    },
    FileRejected {
        file_id: FileId,
        reason: FileRejectReason,
    },
    TransferComplete {
        transfer_id: TransferId,
        completed_files: u64,
        total_size: u64,
    },
    TransferError {
        scope: TransferErrorScope,
        code: u32,
        retryable: bool,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptoSuite {
    InsecureTesting = 0,
    X25519ChaCha20Poly1305 = 1,
}

impl TryFrom<u8> for CryptoSuite {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::InsecureTesting),
            1 => Ok(Self::X25519ChaCha20Poly1305),
            _ => Err(ProtocolError::InvalidValue {
                field: "crypto suite",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMetadata {
    pub modified_time_unix_seconds: Option<i64>,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OverwritePolicy {
    Ask = 1,
    NoReplace = 2,
    ReplaceAfterConfirm = 3,
    RenameWithSuffix = 4,
}

impl TryFrom<u8> for OverwritePolicy {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ask),
            2 => Ok(Self::NoReplace),
            3 => Ok(Self::ReplaceAfterConfirm),
            4 => Ok(Self::RenameWithSuffix),
            _ => Err(ProtocolError::InvalidValue {
                field: "overwrite policy",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileRejectReason {
    Policy = 1,
    AlreadyExists = 2,
    InvalidPath = 3,
    StorageError = 4,
    IntegrityError = 5,
}

impl TryFrom<u8> for FileRejectReason {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Policy),
            2 => Ok(Self::AlreadyExists),
            3 => Ok(Self::InvalidPath),
            4 => Ok(Self::StorageError),
            5 => Ok(Self::IntegrityError),
            _ => Err(ProtocolError::InvalidValue {
                field: "file reject reason",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferErrorScope {
    Session = 1,
    File = 2,
    Path = 3,
}

impl TryFrom<u8> for TransferErrorScope {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Session),
            2 => Ok(Self::File),
            3 => Ok(Self::Path),
            _ => Err(ProtocolError::InvalidValue {
                field: "transfer error scope",
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathCheck {
    Request {
        transfer_id: TransferId,
        transaction_id: TransactionId,
        check_token: CheckToken,
        candidate_id: CandidateId,
        send_timestamp_millis: u64,
    },
    Response {
        transfer_id: TransferId,
        transaction_id: TransactionId,
        check_token: CheckToken,
        candidate_id: CandidateId,
        observed_address: SocketAddr,
        receive_timestamp_millis: u64,
    },
}

impl PathCheck {
    pub(crate) fn message_type(&self) -> MessageType {
        match self {
            Self::Request { .. } => MessageType::PathCheckRequest,
            Self::Response { .. } => MessageType::PathCheckResponse,
        }
    }
}

impl Message {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Pairing(message) => message.validate(),
            Self::Transfer(message) => message.validate(),
            Self::Path(message) => message.validate(),
        }
    }
}

impl PairingControl {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::PairingCreated {
                pairing_code,
                server_session_ticket,
                ..
            } => {
                validate_ticket(server_session_ticket)?;
                validate_code(pairing_code)
            }
            Self::PairingJoined {
                offerer_identity_hint,
                accepter_identity_hint,
                peer_control_ticket,
                ..
            } => {
                validate_string(
                    offerer_identity_hint,
                    MAX_IDENTITY_HINT_LEN,
                    "offerer identity",
                )?;
                validate_string(
                    accepter_identity_hint,
                    MAX_IDENTITY_HINT_LEN,
                    "accepter identity",
                )?;
                validate_ticket(peer_control_ticket)
            }
            Self::OfferReady {
                file_count,
                sender_display_name,
                ..
            } => {
                if *file_count > MAX_MANIFEST_FILES as u64 {
                    return Err(ProtocolError::TooManyItems {
                        field: "file_count",
                        maximum: MAX_MANIFEST_FILES,
                        actual: usize::try_from(*file_count).unwrap_or(usize::MAX),
                    });
                }
                validate_string(
                    sender_display_name,
                    MAX_DISPLAY_NAME_LEN,
                    "sender display name",
                )
            }
            Self::AcceptOffer {
                receiver_root_policy,
                ..
            } => validate_string(
                receiver_root_policy,
                MAX_ROOT_LABEL_LEN,
                "receiver root policy",
            ),
            Self::CandidateList { candidates, .. } => validate_candidates(candidates),
            Self::RelayOpen { relay_ticket, .. } => validate_ticket(relay_ticket),
            Self::ResumeTicket { resume_ticket, .. }
            | Self::ResumeTransfer { resume_ticket, .. } => {
                validate_non_empty_ticket(resume_ticket)
            }
            _ => Ok(()),
        }
    }
}

impl TransferControl {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::ManifestBegin { file_count, .. } => {
                if *file_count > MAX_MANIFEST_FILES as u64 {
                    return Err(ProtocolError::TooManyItems {
                        field: "file_count",
                        maximum: MAX_MANIFEST_FILES,
                        actual: usize::try_from(*file_count).unwrap_or(usize::MAX),
                    });
                }
                Ok(())
            }
            Self::ManifestItem { relative_path, .. } => {
                validate_string(relative_path, MAX_PATH_LEN, "relative path")
            }
            Self::ReceiveDecision {
                target_root_label, ..
            } => validate_string(target_root_label, MAX_ROOT_LABEL_LEN, "target root label"),
            Self::TransferError { message, .. } => validate_string(
                message,
                MAX_TRANSFER_ERROR_MESSAGE_LEN,
                "transfer error message",
            ),
            _ => Ok(()),
        }
    }
}

impl PathCheck {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        let observed_address = match self {
            Self::Request { .. } => None,
            Self::Response {
                observed_address, ..
            } => Some(*observed_address),
        };
        if observed_address.is_some_and(|address| {
            address.ip().is_unspecified() || address.ip().is_multicast() || address.port() == 0
        }) {
            return Err(ProtocolError::InvalidValue {
                field: "path check observed address",
            });
        }
        Ok(())
    }
}

fn validate_candidates(candidates: &[Candidate]) -> Result<(), ProtocolError> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(ProtocolError::TooManyItems {
            field: "candidates",
            maximum: MAX_CANDIDATES,
            actual: candidates.len(),
        });
    }
    for candidate in candidates {
        candidate.validate()?;
    }
    Ok(())
}

fn validate_code(code: &PairingCode) -> Result<(), ProtocolError> {
    PairingCode::parse(code.as_str()).map(|_| ())
}

fn validate_ticket(ticket: &SessionTicket) -> Result<(), ProtocolError> {
    if ticket.as_bytes().len() > MAX_TICKET_LEN {
        return Err(ProtocolError::FieldTooLarge {
            field: "session ticket",
            maximum: MAX_TICKET_LEN,
            actual: ticket.as_bytes().len(),
        });
    }
    Ok(())
}

fn validate_non_empty_ticket(ticket: &SessionTicket) -> Result<(), ProtocolError> {
    validate_ticket(ticket)?;
    if ticket.as_bytes().is_empty() {
        return Err(ProtocolError::InvalidValue {
            field: "resume ticket",
        });
    }
    Ok(())
}

fn validate_string(value: &str, maximum: usize, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() > maximum || value.len() > usize::from(u16::MAX) {
        return Err(ProtocolError::FieldTooLarge {
            field,
            maximum: maximum.min(usize::from(u16::MAX)),
            actual: value.len(),
        });
    }
    Ok(())
}
