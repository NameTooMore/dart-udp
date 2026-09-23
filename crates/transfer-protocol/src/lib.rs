mod codec;
mod error;
mod message;
mod types;

pub use codec::{
    CodecLimits, DecodedMessage, ENVELOPE_LEN, Envelope, MAX_CONTROL_MESSAGE_LEN,
    MAX_MANIFEST_ITEM_LEN, MessageFlags, PROTOCOL_VERSION, decode_message,
    decode_message_with_limits, encode_message, encode_message_with_limits,
};
pub use error::{ProtocolError, RandomnessError};
pub use message::{
    AcceptDecision, Candidate, CandidateKind, Capability, CryptoSuite, FileMetadata,
    FileRejectReason, MAX_CANDIDATES, MAX_DISPLAY_NAME_LEN, MAX_IDENTITY_HINT_LEN,
    MAX_MANIFEST_FILES, MAX_PATH_LEN, MAX_ROOT_LABEL_LEN, MAX_TICKET_LEN,
    MAX_TRANSFER_ERROR_MESSAGE_LEN, Message, MessageType, OverwritePolicy, PairingControl,
    PathCheck, PathKind, RelayCloseReason, TransferControl, TransferErrorScope, TransferRole,
};
pub use types::{
    CHECK_TOKEN_LEN, CandidateId, CheckToken, ClientInstanceId, Digest, FileId, HashAlgorithm,
    ID_LEN, PAIRING_CODE_MAX_LEN, PAIRING_CODE_MIN_LEN, PairingCode, PairingId, PathId, RelayId,
    SessionTicket, TransactionId, TransferId,
};
