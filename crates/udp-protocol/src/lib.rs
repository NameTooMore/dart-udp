//! 自定义可靠 UDP 协议编解码与密码学层
//!
//! 包含数据包（Packet）定长头、可变帧（Frame）、分段 ACK（AckFrame）、
//! QUIC 风格 62-bit 可变长整数（VarInt）、CRC32C 校验，以及基于
//! X25519 + ChaCha20-Poly1305 + HKDF 的会话加密与防重放滑动窗口。

mod ack;
mod checksum;
mod codec;
mod crypto;
mod error;
mod frame;
mod packet;
mod varint;

// 确认应答帧与区间集合
pub use ack::{AckFrame, AckRange, AckRanges, MAX_ACK_RANGES};
// 数据包编解码接口与常量
pub use codec::{
    DEFAULT_MAX_DATAGRAM_SIZE, MAX_FRAME_COUNT, decode_encrypted_packet, decode_packet,
    encode_packet, encode_packet_with_crypto, peek_connection_id, peek_packet_flags,
};
// 密码学安全握手与数据包加解密
pub use crypto::{
    AEAD_KEY_LEN, AEAD_TAG_LEN, CryptoError, CryptoRole, EphemeralKeyPair, FINISHED_TAG_LEN,
    PACKET_NONCE_LEN, PacketCrypto, REPLAY_WINDOW_SIZE, ReplayError, ReplayWindow, SessionKeys,
    X25519_PUBLIC_KEY_LEN, derive_session_keys, handshake_transcript_hash,
};
// 协议错误类型
pub use error::ProtocolError;
// 各种控制与数据帧定义
pub use frame::{
    ClientHello, ConnectionClose, Frame, HandshakeAck, MAX_CLOSE_REASON_LEN, MAX_COOKIE_LEN,
    MAX_FRAME_BODY_LEN, MAX_RETRY_COOKIE_LEN, MaxData, MaxStreamData, NONCE_LEN, Ping, Pong,
    ResetStream, Retry, ServerHello, StreamData, StreamOpen,
};
// 数据包头、标志位与基础类型
pub use packet::{
    ConnectionId, FIXED_HEADER_LEN, MAGIC, Packet, PacketFlags, PacketHeader, PacketNumber,
    PacketType, StreamId, VERSION,
};

