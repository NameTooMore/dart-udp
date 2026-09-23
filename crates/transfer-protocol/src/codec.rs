use core::ops::{BitOr, BitOrAssign};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{
    error::ProtocolError,
    message::{
        Candidate, FileMetadata, MAX_CANDIDATES, MAX_MANIFEST_FILES, MAX_PATH_LEN,
        MAX_ROOT_LABEL_LEN, MAX_TICKET_LEN, MAX_TRANSFER_ERROR_MESSAGE_LEN, Message, MessageType,
        PairingControl, PathCheck, TransferControl,
    },
    types::{
        CandidateId, CheckToken, ClientInstanceId, Digest, FileId, HashAlgorithm, ID_LEN,
        PairingCode, PairingId, PathId, RelayId, SessionTicket, TransactionId, TransferId,
    },
};

pub const PROTOCOL_VERSION: u8 = 1;
pub const ENVELOPE_LEN: usize = 16;
pub const MAX_CONTROL_MESSAGE_LEN: usize = 1024 * 1024;
pub const MAX_MANIFEST_ITEM_LEN: usize = 16 * 1024;

const MAX_MESSAGE_FLAGS: u16 = 0b111;
const MAX_STRING_LEN: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageFlags(u16);

impl MessageFlags {
    pub const RESPONSE: Self = Self(0b001);
    pub const ERROR: Self = Self(0b010);
    pub const MORE_FRAGMENTS: Self = Self(0b100);

    pub const fn all() -> Self {
        Self(MAX_MESSAGE_FLAGS)
    }

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn from_bits(bits: u16) -> Result<Self, ProtocolError> {
        if bits & !MAX_MESSAGE_FLAGS != 0 {
            return Err(ProtocolError::InvalidFlags { value: bits });
        }
        Ok(Self(bits))
    }
}

impl BitOr for MessageFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for MessageFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl Default for MessageFlags {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    pub message_type: MessageType,
    pub version: u8,
    pub flags: MessageFlags,
    pub request_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedMessage {
    pub envelope: Envelope,
    pub message: Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecLimits {
    pub max_message_len: usize,
    pub max_candidates: usize,
    pub max_manifest_files: usize,
}

impl Default for CodecLimits {
    fn default() -> Self {
        Self {
            max_message_len: MAX_CONTROL_MESSAGE_LEN,
            max_candidates: MAX_CANDIDATES,
            max_manifest_files: MAX_MANIFEST_FILES,
        }
    }
}

pub fn encode_message(
    message: &Message,
    request_id: u64,
    flags: MessageFlags,
) -> Result<Vec<u8>, ProtocolError> {
    encode_message_with_limits(message, request_id, flags, CodecLimits::default())
}

pub fn encode_message_with_limits(
    message: &Message,
    request_id: u64,
    flags: MessageFlags,
    limits: CodecLimits,
) -> Result<Vec<u8>, ProtocolError> {
    validate_limits(limits)?;
    message.validate()?;
    let mut body = Writer::new();
    encode_body(message, &mut body, limits)?;
    let total_len =
        ENVELOPE_LEN
            .checked_add(body.bytes.len())
            .ok_or(ProtocolError::MessageTooLarge {
                maximum: limits.max_message_len,
                actual: usize::MAX,
            })?;
    let max_message_len = if message.message_type() == MessageType::ManifestItem {
        limits.max_message_len.min(MAX_MANIFEST_ITEM_LEN)
    } else {
        limits.max_message_len
    };
    if total_len > max_message_len || total_len > u32::MAX as usize {
        return Err(ProtocolError::MessageTooLarge {
            maximum: max_message_len.min(u32::MAX as usize),
            actual: total_len,
        });
    }

    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(&(total_len as u32).to_be_bytes());
    output.push(message.message_type() as u8);
    output.push(PROTOCOL_VERSION);
    output.extend_from_slice(&flags.bits().to_be_bytes());
    output.extend_from_slice(&request_id.to_be_bytes());
    output.extend_from_slice(&body.bytes);
    Ok(output)
}

pub fn decode_message(bytes: &[u8]) -> Result<DecodedMessage, ProtocolError> {
    decode_message_with_limits(bytes, CodecLimits::default())
}

pub fn decode_message_with_limits(
    bytes: &[u8],
    limits: CodecLimits,
) -> Result<DecodedMessage, ProtocolError> {
    validate_limits(limits)?;
    if bytes.len() < ENVELOPE_LEN {
        return Err(ProtocolError::MessageTooShort {
            minimum: ENVELOPE_LEN,
            actual: bytes.len(),
        });
    }
    if bytes.len() > limits.max_message_len {
        return Err(ProtocolError::MessageTooLarge {
            maximum: limits.max_message_len,
            actual: bytes.len(),
        });
    }

    let declared_len =
        usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])).map_err(
            |_| ProtocolError::InvalidValue {
                field: "message length",
            },
        )?;
    if declared_len < ENVELOPE_LEN {
        return Err(ProtocolError::InvalidValue {
            field: "message length",
        });
    }
    if declared_len > limits.max_message_len {
        return Err(ProtocolError::MessageTooLarge {
            maximum: limits.max_message_len,
            actual: declared_len,
        });
    }
    if declared_len != bytes.len() {
        return Err(ProtocolError::DeclaredLengthMismatch {
            declared: declared_len,
            actual: bytes.len(),
        });
    }

    let message_type = MessageType::try_from(bytes[4])?;
    if message_type == MessageType::ManifestItem && declared_len > MAX_MANIFEST_ITEM_LEN {
        return Err(ProtocolError::MessageTooLarge {
            maximum: MAX_MANIFEST_ITEM_LEN,
            actual: declared_len,
        });
    }
    let version = bytes[5];
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion { version });
    }
    let flags = MessageFlags::from_bits(u16::from_be_bytes([bytes[6], bytes[7]]))?;
    let request_id = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let mut reader = Reader::new(&bytes[ENVELOPE_LEN..]);
    let message = decode_body(message_type, &mut reader, limits)?;
    reader.finish()?;
    Ok(DecodedMessage {
        envelope: Envelope {
            message_type,
            version,
            flags,
            request_id,
        },
        message,
    })
}

fn encode_body(
    message: &Message,
    writer: &mut Writer,
    limits: CodecLimits,
) -> Result<(), ProtocolError> {
    match message {
        Message::Pairing(message) => encode_pairing(message, writer, limits),
        Message::Transfer(message) => encode_transfer(message, writer, limits),
        Message::Path(message) => encode_path(message, writer),
    }
}

fn decode_body(
    message_type: MessageType,
    reader: &mut Reader<'_>,
    limits: CodecLimits,
) -> Result<Message, ProtocolError> {
    if message_type as u8 >= 40 {
        return decode_path(message_type, reader).map(Message::Path);
    }
    if message_type as u8 >= 20 {
        return decode_transfer(message_type, reader, limits).map(Message::Transfer);
    }
    decode_pairing(message_type, reader, limits).map(Message::Pairing)
}

fn encode_pairing(
    message: &PairingControl,
    writer: &mut Writer,
    limits: CodecLimits,
) -> Result<(), ProtocolError> {
    match message {
        PairingControl::CreatePairing {
            client_instance_id,
            capability,
            requested_ttl,
            client_ephemeral_key,
        } => {
            writer.id(client_instance_id);
            writer.u8(*capability as u8);
            writer.u32(*requested_ttl);
            writer.bytes_fixed(client_ephemeral_key);
        }
        PairingControl::PairingCreated {
            pairing_id,
            pairing_code,
            expires_at,
            server_session_ticket,
        } => {
            writer.id(pairing_id);
            writer.pairing_code(pairing_code)?;
            writer.u64(*expires_at);
            writer.blob(server_session_ticket.as_bytes(), MAX_TICKET_LEN)?;
        }
        PairingControl::JoinPairing {
            pairing_code,
            client_instance_id,
            client_ephemeral_key,
        } => {
            writer.pairing_code(pairing_code)?;
            writer.id(client_instance_id);
            writer.bytes_fixed(client_ephemeral_key);
        }
        PairingControl::PairingJoined {
            pairing_id,
            offerer_identity_hint,
            accepter_identity_hint,
            peer_control_ticket,
        } => {
            writer.id(pairing_id);
            writer.string(offerer_identity_hint, 256, "offerer identity")?;
            writer.string(accepter_identity_hint, 256, "accepter identity")?;
            writer.blob(peer_control_ticket.as_bytes(), MAX_TICKET_LEN)?;
        }
        PairingControl::OfferReady {
            transfer_id,
            manifest_digest,
            file_count,
            total_size,
            sender_display_name,
        } => {
            if *file_count > limits.max_manifest_files as u64 {
                return Err(ProtocolError::TooManyItems {
                    field: "file_count",
                    maximum: limits.max_manifest_files,
                    actual: usize::try_from(*file_count).unwrap_or(usize::MAX),
                });
            }
            writer.id(transfer_id);
            writer.digest(manifest_digest);
            writer.u64(*file_count);
            writer.u64(*total_size);
            writer.string(sender_display_name, 256, "sender display name")?;
        }
        PairingControl::AcceptOffer {
            transfer_id,
            decision,
            receiver_root_policy,
        } => {
            writer.id(transfer_id);
            writer.u8(*decision as u8);
            writer.string(
                receiver_root_policy,
                MAX_ROOT_LABEL_LEN,
                "receiver root policy",
            )?;
        }
        PairingControl::CandidateList {
            transfer_id,
            candidates,
            candidate_digest,
        } => {
            if candidates.len() > limits.max_candidates {
                return Err(ProtocolError::TooManyItems {
                    field: "candidates",
                    maximum: limits.max_candidates,
                    actual: candidates.len(),
                });
            }
            writer.id(transfer_id);
            writer.u16(candidates.len() as u16);
            for candidate in candidates {
                encode_candidate(candidate, writer)?;
            }
            writer.digest(candidate_digest);
        }
        PairingControl::PathCheckAuthorization {
            transfer_id,
            check_token,
            expires_at,
        } => {
            writer.id(transfer_id);
            writer.bytes_fixed(check_token.as_bytes());
            writer.u64(*expires_at);
        }
        PairingControl::PathSelected {
            transfer_id,
            path_id,
            kind,
            rtt_millis,
            mtu,
        } => {
            writer.id(transfer_id);
            writer.id(path_id);
            writer.u8(*kind as u8);
            writer.u64(*rtt_millis);
            writer.u16(*mtu);
        }
        PairingControl::RelayOpen {
            transfer_id,
            relay_id,
            relay_ticket,
        } => {
            writer.id(transfer_id);
            writer.id(relay_id);
            writer.blob(relay_ticket.as_bytes(), MAX_TICKET_LEN)?;
        }
        PairingControl::RelayClosed {
            transfer_id,
            reason,
        } => {
            writer.id(transfer_id);
            writer.u8(*reason as u8);
        }
        PairingControl::Cancel {
            transfer_id,
            reason_code,
        } => {
            writer.id(transfer_id);
            writer.u16(*reason_code);
        }
        PairingControl::ResumeTicket {
            pairing_id,
            transfer_id,
            role,
            manifest_digest,
            expires_at,
            resume_ticket,
        } => {
            writer.id(pairing_id);
            writer.id(transfer_id);
            writer.u8(*role as u8);
            writer.digest(manifest_digest);
            writer.u64(*expires_at);
            writer.blob(resume_ticket.as_bytes(), MAX_TICKET_LEN)?;
        }
        PairingControl::ResumeTransfer {
            pairing_id,
            transfer_id,
            role,
            client_instance_id,
            resume_ticket,
        } => {
            writer.id(pairing_id);
            writer.id(transfer_id);
            writer.u8(*role as u8);
            writer.id(client_instance_id);
            writer.blob(resume_ticket.as_bytes(), MAX_TICKET_LEN)?;
        }
        PairingControl::ResumeAccepted {
            pairing_id,
            transfer_id,
            role,
            manifest_digest,
            expires_at,
        } => {
            writer.id(pairing_id);
            writer.id(transfer_id);
            writer.u8(*role as u8);
            writer.digest(manifest_digest);
            writer.u64(*expires_at);
        }
        PairingControl::PeerReconnected { transfer_id, role } => {
            writer.id(transfer_id);
            writer.u8(*role as u8);
        }
    }
    Ok(())
}

fn decode_pairing(
    message_type: MessageType,
    reader: &mut Reader<'_>,
    limits: CodecLimits,
) -> Result<PairingControl, ProtocolError> {
    let message = match message_type {
        MessageType::CreatePairing => PairingControl::CreatePairing {
            client_instance_id: reader.id("client instance id")?,
            capability: reader.enum_value("capability")?,
            requested_ttl: reader.u32()?,
            client_ephemeral_key: reader.array("client ephemeral key")?,
        },
        MessageType::PairingCreated => PairingControl::PairingCreated {
            pairing_id: reader.id("pairing id")?,
            pairing_code: reader.pairing_code()?,
            expires_at: reader.u64()?,
            server_session_ticket: SessionTicket::new(
                reader.blob(MAX_TICKET_LEN, "session ticket")?,
            ),
        },
        MessageType::JoinPairing => PairingControl::JoinPairing {
            pairing_code: reader.pairing_code()?,
            client_instance_id: reader.id("client instance id")?,
            client_ephemeral_key: reader.array("client ephemeral key")?,
        },
        MessageType::PairingJoined => PairingControl::PairingJoined {
            pairing_id: reader.id("pairing id")?,
            offerer_identity_hint: reader.string(256, "offerer identity")?,
            accepter_identity_hint: reader.string(256, "accepter identity")?,
            peer_control_ticket: SessionTicket::new(reader.blob(MAX_TICKET_LEN, "session ticket")?),
        },
        MessageType::OfferReady => {
            let transfer_id = reader.id("transfer id")?;
            let manifest_digest = reader.digest()?;
            let file_count = reader.u64()?;
            if file_count > limits.max_manifest_files as u64 {
                return Err(ProtocolError::TooManyItems {
                    field: "file_count",
                    maximum: limits.max_manifest_files,
                    actual: usize::try_from(file_count).unwrap_or(usize::MAX),
                });
            }
            PairingControl::OfferReady {
                transfer_id,
                manifest_digest,
                file_count,
                total_size: reader.u64()?,
                sender_display_name: reader.string(256, "sender display name")?,
            }
        }
        MessageType::AcceptOffer => PairingControl::AcceptOffer {
            transfer_id: reader.id("transfer id")?,
            decision: reader.enum_value("decision")?,
            receiver_root_policy: reader.string(MAX_ROOT_LABEL_LEN, "receiver root policy")?,
        },
        MessageType::CandidateList => {
            let transfer_id = reader.id("transfer id")?;
            let count = usize::from(reader.u16()?);
            if count > limits.max_candidates {
                return Err(ProtocolError::TooManyItems {
                    field: "candidates",
                    maximum: limits.max_candidates,
                    actual: count,
                });
            }
            let mut candidates = Vec::with_capacity(count);
            for _ in 0..count {
                candidates.push(decode_candidate(reader)?);
            }
            PairingControl::CandidateList {
                transfer_id,
                candidates,
                candidate_digest: reader.digest()?,
            }
        }
        MessageType::PathCheckAuthorization => PairingControl::PathCheckAuthorization {
            transfer_id: reader.id("transfer id")?,
            check_token: CheckToken::from_bytes(reader.array("check token")?),
            expires_at: reader.u64()?,
        },
        MessageType::PathSelected => PairingControl::PathSelected {
            transfer_id: reader.id("transfer id")?,
            path_id: reader.id("path id")?,
            kind: reader.enum_value("path kind")?,
            rtt_millis: reader.u64()?,
            mtu: reader.u16()?,
        },
        MessageType::RelayOpen => PairingControl::RelayOpen {
            transfer_id: reader.id("transfer id")?,
            relay_id: reader.id("relay id")?,
            relay_ticket: SessionTicket::new(reader.blob(MAX_TICKET_LEN, "relay ticket")?),
        },
        MessageType::RelayClosed => PairingControl::RelayClosed {
            transfer_id: reader.id("transfer id")?,
            reason: reader.enum_value("relay close reason")?,
        },
        MessageType::Cancel => PairingControl::Cancel {
            transfer_id: reader.id("transfer id")?,
            reason_code: reader.u16()?,
        },
        MessageType::ResumeTicket => PairingControl::ResumeTicket {
            pairing_id: reader.id("pairing id")?,
            transfer_id: reader.id("transfer id")?,
            role: reader.enum_value("transfer role")?,
            manifest_digest: reader.digest()?,
            expires_at: reader.u64()?,
            resume_ticket: SessionTicket::new(reader.blob(MAX_TICKET_LEN, "resume ticket")?),
        },
        MessageType::ResumeTransfer => PairingControl::ResumeTransfer {
            pairing_id: reader.id("pairing id")?,
            transfer_id: reader.id("transfer id")?,
            role: reader.enum_value("transfer role")?,
            client_instance_id: reader.id("client instance id")?,
            resume_ticket: SessionTicket::new(reader.blob(MAX_TICKET_LEN, "resume ticket")?),
        },
        MessageType::ResumeAccepted => PairingControl::ResumeAccepted {
            pairing_id: reader.id("pairing id")?,
            transfer_id: reader.id("transfer id")?,
            role: reader.enum_value("transfer role")?,
            manifest_digest: reader.digest()?,
            expires_at: reader.u64()?,
        },
        MessageType::PeerReconnected => PairingControl::PeerReconnected {
            transfer_id: reader.id("transfer id")?,
            role: reader.enum_value("transfer role")?,
        },
        _ => {
            return Err(ProtocolError::InvalidValue {
                field: "pairing message type",
            });
        }
    };
    message.validate()?;
    Ok(message)
}

fn encode_transfer(
    message: &TransferControl,
    writer: &mut Writer,
    limits: CodecLimits,
) -> Result<(), ProtocolError> {
    match message {
        TransferControl::SessionHello {
            transfer_id,
            protocol_version,
            crypto_suite,
            manifest_digest,
            resume_namespace,
        } => {
            writer.id(transfer_id);
            writer.u8(*protocol_version);
            writer.u8(*crypto_suite as u8);
            writer.digest(manifest_digest);
            writer.bytes_fixed(resume_namespace);
        }
        TransferControl::ManifestBegin {
            file_count,
            total_size,
            manifest_digest,
        } => {
            if *file_count > limits.max_manifest_files as u64 {
                return Err(ProtocolError::TooManyItems {
                    field: "file_count",
                    maximum: limits.max_manifest_files,
                    actual: usize::try_from(*file_count).unwrap_or(usize::MAX),
                });
            }
            writer.u64(*file_count);
            writer.u64(*total_size);
            writer.digest(manifest_digest);
        }
        TransferControl::ManifestItem {
            file_id,
            relative_path,
            size,
            content_hash,
            metadata,
        } => {
            writer.id(file_id);
            writer.string(relative_path, MAX_PATH_LEN, "relative path")?;
            writer.u64(*size);
            writer.digest(content_hash);
            encode_metadata(metadata, writer);
        }
        TransferControl::ManifestEnd { manifest_digest } => writer.digest(manifest_digest),
        TransferControl::ReceiveDecision {
            accepted,
            overwrite_policy,
            target_root_label,
        } => {
            writer.u8(u8::from(*accepted));
            writer.u8(*overwrite_policy as u8);
            writer.string(target_root_label, MAX_ROOT_LABEL_LEN, "target root label")?;
        }
        TransferControl::ResumeQuery {
            file_id,
            content_hash,
            size,
        } => {
            writer.id(file_id);
            writer.digest(content_hash);
            writer.u64(*size);
        }
        TransferControl::ResumeState {
            file_id,
            durable_offset,
            checkpoint_id,
            state_hash,
        } => {
            writer.id(file_id);
            writer.u64(*durable_offset);
            writer.u64(*checkpoint_id);
            writer.digest(state_hash);
        }
        TransferControl::FileBegin {
            file_id,
            data_stream_id,
            base_offset,
            remaining_size,
            content_hash,
        } => {
            writer.id(file_id);
            writer.u64(*data_stream_id);
            writer.u64(*base_offset);
            writer.u64(*remaining_size);
            writer.digest(content_hash);
        }
        TransferControl::Checkpoint {
            file_id,
            durable_offset,
            checkpoint_id,
        } => {
            writer.id(file_id);
            writer.u64(*durable_offset);
            writer.u64(*checkpoint_id);
        }
        TransferControl::FileComplete {
            file_id,
            final_size,
            content_hash,
        } => {
            writer.id(file_id);
            writer.u64(*final_size);
            writer.digest(content_hash);
        }
        TransferControl::FileRejected { file_id, reason } => {
            writer.id(file_id);
            writer.u8(*reason as u8);
        }
        TransferControl::TransferComplete {
            transfer_id,
            completed_files,
            total_size,
        } => {
            writer.id(transfer_id);
            writer.u64(*completed_files);
            writer.u64(*total_size);
        }
        TransferControl::TransferError {
            scope,
            code,
            retryable,
            message,
        } => {
            writer.u8(*scope as u8);
            writer.u32(*code);
            writer.u8(u8::from(*retryable));
            writer.string(
                message,
                MAX_TRANSFER_ERROR_MESSAGE_LEN,
                "transfer error message",
            )?;
        }
    }
    Ok(())
}

fn decode_transfer(
    message_type: MessageType,
    reader: &mut Reader<'_>,
    limits: CodecLimits,
) -> Result<TransferControl, ProtocolError> {
    let message = match message_type {
        MessageType::SessionHello => TransferControl::SessionHello {
            transfer_id: reader.id("transfer id")?,
            protocol_version: reader.u8()?,
            crypto_suite: reader.enum_value("crypto suite")?,
            manifest_digest: reader.digest()?,
            resume_namespace: reader.array("resume namespace")?,
        },
        MessageType::ManifestBegin => {
            let file_count = reader.u64()?;
            if file_count > limits.max_manifest_files as u64 {
                return Err(ProtocolError::TooManyItems {
                    field: "file_count",
                    maximum: limits.max_manifest_files,
                    actual: usize::try_from(file_count).unwrap_or(usize::MAX),
                });
            }
            TransferControl::ManifestBegin {
                file_count,
                total_size: reader.u64()?,
                manifest_digest: reader.digest()?,
            }
        }
        MessageType::ManifestItem => TransferControl::ManifestItem {
            file_id: reader.id("file id")?,
            relative_path: reader.string(MAX_PATH_LEN, "relative path")?,
            size: reader.u64()?,
            content_hash: reader.digest()?,
            metadata: decode_metadata(reader)?,
        },
        MessageType::ManifestEnd => TransferControl::ManifestEnd {
            manifest_digest: reader.digest()?,
        },
        MessageType::ReceiveDecision => TransferControl::ReceiveDecision {
            accepted: reader.bool("accepted")?,
            overwrite_policy: reader.enum_value("overwrite policy")?,
            target_root_label: reader.string(MAX_ROOT_LABEL_LEN, "target root label")?,
        },
        MessageType::ResumeQuery => TransferControl::ResumeQuery {
            file_id: reader.id("file id")?,
            content_hash: reader.digest()?,
            size: reader.u64()?,
        },
        MessageType::ResumeState => TransferControl::ResumeState {
            file_id: reader.id("file id")?,
            durable_offset: reader.u64()?,
            checkpoint_id: reader.u64()?,
            state_hash: reader.digest()?,
        },
        MessageType::FileBegin => TransferControl::FileBegin {
            file_id: reader.id("file id")?,
            data_stream_id: reader.u64()?,
            base_offset: reader.u64()?,
            remaining_size: reader.u64()?,
            content_hash: reader.digest()?,
        },
        MessageType::Checkpoint => TransferControl::Checkpoint {
            file_id: reader.id("file id")?,
            durable_offset: reader.u64()?,
            checkpoint_id: reader.u64()?,
        },
        MessageType::FileComplete => TransferControl::FileComplete {
            file_id: reader.id("file id")?,
            final_size: reader.u64()?,
            content_hash: reader.digest()?,
        },
        MessageType::FileRejected => TransferControl::FileRejected {
            file_id: reader.id("file id")?,
            reason: reader.enum_value("file reject reason")?,
        },
        MessageType::TransferComplete => TransferControl::TransferComplete {
            transfer_id: reader.id("transfer id")?,
            completed_files: reader.u64()?,
            total_size: reader.u64()?,
        },
        MessageType::TransferError => TransferControl::TransferError {
            scope: reader.enum_value("transfer error scope")?,
            code: reader.u32()?,
            retryable: reader.bool("retryable")?,
            message: reader.string(MAX_TRANSFER_ERROR_MESSAGE_LEN, "transfer error message")?,
        },
        _ => {
            return Err(ProtocolError::InvalidValue {
                field: "transfer message type",
            });
        }
    };
    message.validate()?;
    Ok(message)
}

fn encode_path(message: &PathCheck, writer: &mut Writer) -> Result<(), ProtocolError> {
    match message {
        PathCheck::Request {
            transfer_id,
            transaction_id,
            check_token,
            candidate_id,
            send_timestamp_millis,
        } => {
            writer.id(transfer_id);
            writer.id(transaction_id);
            writer.bytes_fixed(check_token.as_bytes());
            writer.id(candidate_id);
            writer.u64(*send_timestamp_millis);
        }
        PathCheck::Response {
            transfer_id,
            transaction_id,
            check_token,
            candidate_id,
            observed_address,
            receive_timestamp_millis,
        } => {
            writer.id(transfer_id);
            writer.id(transaction_id);
            writer.bytes_fixed(check_token.as_bytes());
            writer.id(candidate_id);
            writer.socket_addr(*observed_address)?;
            writer.u64(*receive_timestamp_millis);
        }
    }
    Ok(())
}

fn decode_path(
    message_type: MessageType,
    reader: &mut Reader<'_>,
) -> Result<PathCheck, ProtocolError> {
    match message_type {
        MessageType::PathCheckRequest => Ok(PathCheck::Request {
            transfer_id: reader.id("transfer id")?,
            transaction_id: reader.id("transaction id")?,
            check_token: CheckToken::from_bytes(reader.array("check token")?),
            candidate_id: reader.id("candidate id")?,
            send_timestamp_millis: reader.u64()?,
        }),
        MessageType::PathCheckResponse => Ok(PathCheck::Response {
            transfer_id: reader.id("transfer id")?,
            transaction_id: reader.id("transaction id")?,
            check_token: CheckToken::from_bytes(reader.array("check token")?),
            candidate_id: reader.id("candidate id")?,
            observed_address: reader.socket_addr()?,
            receive_timestamp_millis: reader.u64()?,
        }),
        _ => Err(ProtocolError::InvalidValue {
            field: "path message type",
        }),
    }
}

fn encode_candidate(candidate: &Candidate, writer: &mut Writer) -> Result<(), ProtocolError> {
    candidate.validate()?;
    writer.id(&candidate.id);
    writer.u8(candidate.kind as u8);
    writer.socket_addr_option(candidate.address)?;
    writer.u16(candidate.priority);
    writer.u32(candidate.interface_index.unwrap_or(u32::MAX));
    Ok(())
}

fn decode_candidate(reader: &mut Reader<'_>) -> Result<Candidate, ProtocolError> {
    let candidate = Candidate {
        id: reader.id("candidate id")?,
        kind: reader.enum_value("candidate kind")?,
        address: reader.socket_addr_option()?,
        priority: reader.u16()?,
        interface_index: match reader.u32()? {
            u32::MAX => None,
            value => Some(value),
        },
    };
    candidate.validate()?;
    Ok(candidate)
}

fn encode_metadata(metadata: &FileMetadata, writer: &mut Writer) {
    let mut flags = 0_u8;
    if metadata.modified_time_unix_seconds.is_some() {
        flags |= 1;
    }
    if metadata.mode.is_some() {
        flags |= 2;
    }
    writer.u8(flags);
    if let Some(value) = metadata.modified_time_unix_seconds {
        writer.i64(value);
    }
    if let Some(value) = metadata.mode {
        writer.u32(value);
    }
}

fn decode_metadata(reader: &mut Reader<'_>) -> Result<FileMetadata, ProtocolError> {
    let flags = reader.u8()?;
    if flags & !0b11 != 0 {
        return Err(ProtocolError::InvalidValue {
            field: "file metadata",
        });
    }
    Ok(FileMetadata {
        modified_time_unix_seconds: (flags & 1 != 0).then(|| reader.i64()).transpose()?,
        mode: (flags & 2 != 0).then(|| reader.u32()).transpose()?,
    })
}

fn validate_limits(limits: CodecLimits) -> Result<(), ProtocolError> {
    if limits.max_message_len < ENVELOPE_LEN || limits.max_message_len > MAX_CONTROL_MESSAGE_LEN {
        return Err(ProtocolError::InvalidValue {
            field: "max_message_len",
        });
    }
    if limits.max_candidates > MAX_CANDIDATES {
        return Err(ProtocolError::InvalidValue {
            field: "max_candidates",
        });
    }
    if limits.max_manifest_files > MAX_MANIFEST_FILES {
        return Err(ProtocolError::InvalidValue {
            field: "max_manifest_files",
        });
    }
    Ok(())
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes_fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn id<T: AsIdBytes>(&mut self, value: &T) {
        self.bytes.extend_from_slice(value.as_id_bytes());
    }

    fn blob(&mut self, value: &[u8], maximum: usize) -> Result<(), ProtocolError> {
        if value.len() > maximum || value.len() > u32::MAX as usize {
            return Err(ProtocolError::FieldTooLarge {
                field: "blob",
                maximum: maximum.min(u32::MAX as usize),
                actual: value.len(),
            });
        }
        self.u32(value.len() as u32);
        self.bytes_fixed(value);
        Ok(())
    }

    fn string(
        &mut self,
        value: &str,
        maximum: usize,
        field: &'static str,
    ) -> Result<(), ProtocolError> {
        if value.len() > maximum || value.len() > MAX_STRING_LEN {
            return Err(ProtocolError::FieldTooLarge {
                field,
                maximum: maximum.min(MAX_STRING_LEN),
                actual: value.len(),
            });
        }
        self.u16(value.len() as u16);
        self.bytes_fixed(value.as_bytes());
        Ok(())
    }

    fn pairing_code(&mut self, value: &PairingCode) -> Result<(), ProtocolError> {
        let bytes = value.as_str().as_bytes();
        if bytes.len() > u8::MAX as usize {
            return Err(ProtocolError::InvalidPairingCode);
        }
        self.u8(bytes.len() as u8);
        self.bytes_fixed(bytes);
        Ok(())
    }

    fn digest(&mut self, value: &Digest) {
        self.u8(value.algorithm as u8);
        self.bytes_fixed(&value.bytes);
    }

    fn socket_addr_option(&mut self, value: Option<SocketAddr>) -> Result<(), ProtocolError> {
        match value {
            Some(value) => self.socket_addr(value),
            None => {
                self.u8(0);
                Ok(())
            }
        }
    }

    fn socket_addr(&mut self, value: SocketAddr) -> Result<(), ProtocolError> {
        match value {
            SocketAddr::V4(value) => {
                self.u8(4);
                self.bytes_fixed(&value.ip().octets());
                self.u16(value.port());
            }
            SocketAddr::V6(value) => {
                self.u8(6);
                self.bytes_fixed(&value.ip().octets());
                self.u16(value.port());
                self.u32(value.flowinfo());
                self.u32(value.scope_id());
            }
        }
        Ok(())
    }
}

trait AsIdBytes {
    fn as_id_bytes(&self) -> &[u8; ID_LEN];
}

macro_rules! impl_as_id_bytes {
    ($($type:ty),+ $(,)?) => {
        $(
            impl AsIdBytes for $type {
                fn as_id_bytes(&self) -> &[u8; ID_LEN] {
                    self.as_bytes()
                }
            }
        )+
    };
}

impl_as_id_bytes!(
    CandidateId,
    ClientInstanceId,
    FileId,
    PairingId,
    PathId,
    RelayId,
    TransactionId,
    TransferId,
);

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::InvalidValue {
                field: "trailing message body",
            })
        }
    }

    fn take(&mut self, length: usize, context: &'static str) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::Truncated { context })?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::Truncated { context })?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        self.take(1, "u8")?
            .first()
            .copied()
            .ok_or(ProtocolError::Truncated { context: "u8" })
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.array("u16")?))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.array("u32")?))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.array("u64")?))
    }

    fn i64(&mut self) -> Result<i64, ProtocolError> {
        Ok(i64::from_be_bytes(self.array("i64")?))
    }

    fn array<const N: usize>(&mut self, context: &'static str) -> Result<[u8; N], ProtocolError> {
        self.take(N, context).map(|bytes| {
            let mut output = [0_u8; N];
            output.copy_from_slice(bytes);
            output
        })
    }

    fn id<T>(&mut self, context: &'static str) -> Result<T, ProtocolError>
    where
        T: From<[u8; ID_LEN]>,
    {
        Ok(T::from(self.array(context)?))
    }

    fn blob(&mut self, maximum: usize, context: &'static str) -> Result<Vec<u8>, ProtocolError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ProtocolError::InvalidValue { field: context })?;
        if length > maximum {
            return Err(ProtocolError::FieldTooLarge {
                field: context,
                maximum,
                actual: length,
            });
        }
        Ok(self.take(length, context)?.to_vec())
    }

    fn string(&mut self, maximum: usize, context: &'static str) -> Result<String, ProtocolError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(ProtocolError::FieldTooLarge {
                field: context,
                maximum,
                actual: length,
            });
        }
        let bytes = self.take(length, context)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| ProtocolError::InvalidUtf8 { field: context })
    }

    fn pairing_code(&mut self) -> Result<PairingCode, ProtocolError> {
        let length = usize::from(self.u8()?);
        let bytes = self.take(length, "pairing code")?;
        let value = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8 {
            field: "pairing code",
        })?;
        PairingCode::parse(value)
    }

    fn digest(&mut self) -> Result<Digest, ProtocolError> {
        let algorithm =
            HashAlgorithm::try_from(self.u8()?).map_err(|_| ProtocolError::InvalidValue {
                field: "hash algorithm",
            })?;
        Ok(Digest::new(algorithm, self.array("digest")?))
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, ProtocolError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtocolError::InvalidValue { field }),
        }
    }

    fn enum_value<T>(&mut self, field: &'static str) -> Result<T, ProtocolError>
    where
        T: TryFrom<u8, Error = ProtocolError>,
    {
        self.u8()?
            .try_into()
            .map_err(|_| ProtocolError::InvalidValue { field })
    }

    fn socket_addr_option(&mut self) -> Result<Option<SocketAddr>, ProtocolError> {
        match self.u8()? {
            0 => Ok(None),
            4 | 6 => {
                self.offset -= 1;
                Ok(Some(self.socket_addr()?))
            }
            _ => Err(ProtocolError::InvalidValue {
                field: "candidate address",
            }),
        }
    }

    fn socket_addr(&mut self) -> Result<SocketAddr, ProtocolError> {
        match self.u8()? {
            4 => {
                let ip = Ipv4Addr::from(self.array("IPv4 address")?);
                let port = self.u16()?;
                Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            6 => {
                let ip = Ipv6Addr::from(self.array("IPv6 address")?);
                let port = self.u16()?;
                let flowinfo = self.u32()?;
                let scope_id = self.u32()?;
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    ip, port, flowinfo, scope_id,
                )))
            }
            _ => Err(ProtocolError::InvalidValue {
                field: "socket address",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PAIRING_CODE_MAX_LEN, PAIRING_CODE_MIN_LEN};
    use crate::{
        AcceptDecision, CandidateKind, Capability, CheckToken, CryptoSuite, Digest, FileId,
        FileMetadata, FileRejectReason, HashAlgorithm, OverwritePolicy, PairingId, PathKind,
        RelayCloseReason, TransferErrorScope, TransferRole,
    };

    fn id() -> PairingId {
        PairingId::from_bytes([7; ID_LEN])
    }

    fn digest() -> Digest {
        Digest::new(HashAlgorithm::Blake3, [9; 32])
    }

    fn sample_messages() -> Vec<Message> {
        let transfer_id = TransferId::from_bytes([1; 16]);
        let file_id = FileId::from_bytes([2; 16]);
        let candidate_id = CandidateId::from_bytes([3; 16]);
        let path_id = PathId::from_bytes([4; 16]);
        let relay_id = RelayId::from_bytes([5; 16]);
        let transaction_id = TransactionId::from_bytes([6; 16]);
        let pairing_code = PairingCode::parse("ABC23456").unwrap();
        let candidate = Candidate {
            id: candidate_id,
            kind: CandidateKind::Host,
            address: Some("127.0.0.1:4000".parse().unwrap()),
            priority: 100,
            interface_index: Some(2),
        };
        vec![
            Message::Pairing(PairingControl::CreatePairing {
                client_instance_id: ClientInstanceId::from_bytes([7; 16]),
                capability: Capability::Upload,
                requested_ttl: 600,
                client_ephemeral_key: [8; 32],
            }),
            Message::Pairing(PairingControl::PairingCreated {
                pairing_id: id(),
                pairing_code: pairing_code.clone(),
                expires_at: 100,
                server_session_ticket: SessionTicket::new(vec![1, 2, 3]),
            }),
            Message::Pairing(PairingControl::JoinPairing {
                pairing_code,
                client_instance_id: ClientInstanceId::from_bytes([7; 16]),
                client_ephemeral_key: [8; 32],
            }),
            Message::Pairing(PairingControl::PairingJoined {
                pairing_id: id(),
                offerer_identity_hint: "sender".into(),
                accepter_identity_hint: "receiver".into(),
                peer_control_ticket: SessionTicket::new(vec![4, 5]),
            }),
            Message::Pairing(PairingControl::OfferReady {
                transfer_id,
                manifest_digest: digest(),
                file_count: 2,
                total_size: 128,
                sender_display_name: "Alice".into(),
            }),
            Message::Pairing(PairingControl::AcceptOffer {
                transfer_id,
                decision: AcceptDecision::Accept,
                receiver_root_policy: "downloads".into(),
            }),
            Message::Pairing(PairingControl::CandidateList {
                transfer_id,
                candidates: vec![
                    candidate,
                    Candidate {
                        id: CandidateId::from_bytes([9; 16]),
                        kind: CandidateKind::Relay,
                        address: None,
                        priority: 10,
                        interface_index: None,
                    },
                ],
                candidate_digest: digest(),
            }),
            Message::Pairing(PairingControl::PathCheckAuthorization {
                transfer_id,
                check_token: CheckToken::from_bytes([10; 32]),
                expires_at: 101,
            }),
            Message::Pairing(PairingControl::PathSelected {
                transfer_id,
                path_id,
                kind: PathKind::RoutedLan,
                rtt_millis: 4,
                mtu: 1200,
            }),
            Message::Pairing(PairingControl::RelayOpen {
                transfer_id,
                relay_id,
                relay_ticket: SessionTicket::new(vec![11, 12]),
            }),
            Message::Pairing(PairingControl::RelayClosed {
                transfer_id,
                reason: RelayCloseReason::Complete,
            }),
            Message::Pairing(PairingControl::Cancel {
                transfer_id,
                reason_code: 7,
            }),
            Message::Pairing(PairingControl::ResumeTicket {
                pairing_id: id(),
                transfer_id,
                role: TransferRole::Offerer,
                manifest_digest: digest(),
                expires_at: 600,
                resume_ticket: SessionTicket::new(vec![14; 32]),
            }),
            Message::Pairing(PairingControl::ResumeTransfer {
                pairing_id: id(),
                transfer_id,
                role: TransferRole::Accepter,
                client_instance_id: ClientInstanceId::from_bytes([15; 16]),
                resume_ticket: SessionTicket::new(vec![16; 32]),
            }),
            Message::Pairing(PairingControl::ResumeAccepted {
                pairing_id: id(),
                transfer_id,
                role: TransferRole::Offerer,
                manifest_digest: digest(),
                expires_at: 601,
            }),
            Message::Pairing(PairingControl::PeerReconnected {
                transfer_id,
                role: TransferRole::Accepter,
            }),
            Message::Transfer(TransferControl::SessionHello {
                transfer_id,
                protocol_version: PROTOCOL_VERSION,
                crypto_suite: CryptoSuite::InsecureTesting,
                manifest_digest: digest(),
                resume_namespace: [13; 16],
            }),
            Message::Transfer(TransferControl::ManifestBegin {
                file_count: 2,
                total_size: 128,
                manifest_digest: digest(),
            }),
            Message::Transfer(TransferControl::ManifestItem {
                file_id,
                relative_path: "folder/file.bin".into(),
                size: 128,
                content_hash: digest(),
                metadata: FileMetadata {
                    modified_time_unix_seconds: Some(42),
                    mode: Some(0o644),
                },
            }),
            Message::Transfer(TransferControl::ManifestEnd {
                manifest_digest: digest(),
            }),
            Message::Transfer(TransferControl::ReceiveDecision {
                accepted: true,
                overwrite_policy: OverwritePolicy::NoReplace,
                target_root_label: "downloads".into(),
            }),
            Message::Transfer(TransferControl::ResumeQuery {
                file_id,
                content_hash: digest(),
                size: 128,
            }),
            Message::Transfer(TransferControl::ResumeState {
                file_id,
                durable_offset: 64,
                checkpoint_id: 3,
                state_hash: digest(),
            }),
            Message::Transfer(TransferControl::FileBegin {
                file_id,
                data_stream_id: 9,
                base_offset: 64,
                remaining_size: 64,
                content_hash: digest(),
            }),
            Message::Transfer(TransferControl::Checkpoint {
                file_id,
                durable_offset: 96,
                checkpoint_id: 4,
            }),
            Message::Transfer(TransferControl::FileComplete {
                file_id,
                final_size: 128,
                content_hash: digest(),
            }),
            Message::Transfer(TransferControl::FileRejected {
                file_id,
                reason: FileRejectReason::Policy,
            }),
            Message::Transfer(TransferControl::TransferComplete {
                transfer_id,
                completed_files: 2,
                total_size: 128,
            }),
            Message::Transfer(TransferControl::TransferError {
                scope: TransferErrorScope::File,
                code: 9,
                retryable: true,
                message: "temporary storage error".into(),
            }),
            Message::Path(PathCheck::Request {
                transfer_id,
                transaction_id,
                check_token: CheckToken::from_bytes([10; 32]),
                candidate_id,
                send_timestamp_millis: 99,
            }),
            Message::Path(PathCheck::Response {
                transfer_id,
                transaction_id,
                check_token: CheckToken::from_bytes([10; 32]),
                candidate_id,
                observed_address: "[2001:db8::1]:4000".parse().unwrap(),
                receive_timestamp_millis: 100,
            }),
        ]
    }

    #[test]
    fn every_message_variant_round_trips() {
        for (request_id, message) in sample_messages().into_iter().enumerate() {
            let encoded = encode_message(
                &message,
                request_id as u64,
                MessageFlags::RESPONSE | MessageFlags::MORE_FRAGMENTS,
            )
            .unwrap();
            let decoded = decode_message(&encoded).unwrap();
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.envelope.message_type, message.message_type());
            assert_eq!(decoded.envelope.request_id, request_id as u64);
            assert!(decoded.envelope.flags.contains(MessageFlags::RESPONSE));
        }
    }

    #[test]
    fn rejects_truncation_without_panicking() {
        let message = Message::Pairing(PairingControl::PairingCreated {
            pairing_id: id(),
            pairing_code: PairingCode::parse("ABC23456").unwrap(),
            expires_at: 42,
            server_session_ticket: SessionTicket::new(vec![1, 2, 3]),
        });
        let encoded = encode_message(&message, 11, MessageFlags::empty()).unwrap();
        for length in 0..encoded.len() {
            let result = std::panic::catch_unwind(|| decode_message(&encoded[..length]));
            assert!(result.is_ok());
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn rejects_unknown_version_and_type() {
        let message = Message::Transfer(TransferControl::ManifestEnd {
            manifest_digest: digest(),
        });
        let mut encoded = encode_message(&message, 1, MessageFlags::empty()).unwrap();
        encoded[5] = PROTOCOL_VERSION + 1;
        assert!(matches!(
            decode_message(&encoded),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        encoded[5] = PROTOCOL_VERSION;
        encoded[4] = 255;
        assert!(matches!(
            decode_message(&encoded),
            Err(ProtocolError::UnknownMessageType { value: 255 })
        ));
    }

    #[test]
    fn rejects_unknown_flags_and_oversized_messages_before_body_decode() {
        let message = Message::Transfer(TransferControl::ManifestEnd {
            manifest_digest: digest(),
        });
        let mut encoded = encode_message(&message, 1, MessageFlags::empty()).unwrap();
        encoded[6] = 0x80;
        assert!(matches!(
            decode_message(&encoded),
            Err(ProtocolError::InvalidFlags { .. })
        ));

        let mut oversized = vec![0_u8; ENVELOPE_LEN];
        oversized[..4].copy_from_slice(&((MAX_CONTROL_MESSAGE_LEN as u32) + 1).to_be_bytes());
        assert!(matches!(
            decode_message(&oversized),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn random_inputs_never_panic() {
        let mut state = 0x1234_5678_u64;
        for length in 0..=4096 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                *byte = (state >> 56) as u8;
            }
            let result = std::panic::catch_unwind(|| decode_message(&input));
            assert!(result.is_ok(), "decoder panicked for input length {length}");
        }
    }

    #[test]
    fn generated_pairing_codes_use_the_crockford_alphabet() {
        for length in PAIRING_CODE_MIN_LEN..=PAIRING_CODE_MAX_LEN {
            let code = PairingCode::generate_with_len(length).unwrap();
            assert_eq!(code.as_str().len(), length);
            assert_eq!(PairingCode::parse(code.as_str()).unwrap(), code);
        }
    }

    #[test]
    fn pairing_code_is_canonical_and_bounded() {
        let parsed = PairingCode::parse("abce2345").unwrap();
        assert_eq!(parsed.as_str(), "ABCE2345");
        assert!(PairingCode::parse("ABC2345").is_err());
        assert!(PairingCode::parse("ABC2345I").is_err());
    }
}
