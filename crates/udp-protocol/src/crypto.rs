use std::{error::Error, fmt};

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag, aead::AeadInPlace};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{ConnectionId, PacketNumber};

/// X25519 椭圆曲线公钥长度（32 字节）
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 AEAD 对称密钥长度（32 字节）
pub const AEAD_KEY_LEN: usize = 32;
/// Poly1305 认证标签（Tag）长度（16 字节）
pub const AEAD_TAG_LEN: usize = 16;
/// 每个数据包加密时使用的 Nonce 长度（12 字节：4 字节盐值 + 8 字节包号）
pub const PACKET_NONCE_LEN: usize = 12;
/// 握手 Finished 校验标签长度（16 字节）
pub const FINISHED_TAG_LEN: usize = 16;
/// 防重放滑动窗口大小（4096 个包）
pub const REPLAY_WINDOW_SIZE: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

/// 通信端点在密码学协商中的角色
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoRole {
    Client,
    Server,
}

/// 重放保护检测错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// 重复的数据包（已被记录过）
    Duplicate,
    /// 数据包序号过旧，已落后于当前滑动窗口左边界
    TooOld,
}

/// 密码学处理错误
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// 安全随机数生成器不可用
    RandomnessUnavailable,
    /// 对端提供的公钥在低阶子群或无效
    InvalidPeerPublicKey,
    /// ECDH 密钥协商得到的共享密钥无效（全零点）
    InvalidSharedSecret,
    /// HKDF 密钥派生失败
    KeyDerivationFailed,
    /// Poly1305 AEAD 密文认证失败（数据被篡改或密钥不匹配）
    AuthenticationFailed,
    /// 防重放检测失败（重复包或过期包）
    Replay(ReplayError),
    /// 加密载荷长度小于认证标签所需长度（小于 16 字节）
    EncryptedPayloadTooShort,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable => f.write_str("secure randomness is unavailable"),
            Self::InvalidPeerPublicKey => f.write_str("peer public key is invalid"),
            Self::InvalidSharedSecret => f.write_str("key exchange produced an invalid secret"),
            Self::KeyDerivationFailed => f.write_str("session key derivation failed"),
            Self::AuthenticationFailed => f.write_str("AEAD authentication failed"),
            Self::Replay(ReplayError::Duplicate) => f.write_str("packet was already received"),
            Self::Replay(ReplayError::TooOld) => f.write_str("packet is outside the replay window"),
            Self::EncryptedPayloadTooShort => {
                f.write_str("encrypted payload is shorter than its tag")
            }
        }
    }
}

impl Error for CryptoError {}

/// 临时 X25519 密钥对，用于 ECDH 前向安全密钥交换
pub struct EphemeralKeyPair {
    secret: StaticSecret,
    public_key: [u8; X25519_PUBLIC_KEY_LEN],
}

impl fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl EphemeralKeyPair {
    /// 借助系统安全随机源生成新的临时密钥对
    pub fn generate() -> Result<Self, CryptoError> {
        let mut secret_bytes = Zeroizing::new([0_u8; X25519_PUBLIC_KEY_LEN]);
        getrandom::fill(&mut *secret_bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        let secret = StaticSecret::from(*secret_bytes);
        let public_key = PublicKey::from(&secret).to_bytes();
        Ok(Self { secret, public_key })
    }

    /// 获取公钥切片
    pub const fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.public_key
    }

    /// 与对端公钥计算 ECDH 共享密钥（全零弱密钥将被拒绝）
    pub fn agree(
        &self,
        peer_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    ) -> Result<[u8; X25519_PUBLIC_KEY_LEN], CryptoError> {
        let peer = PublicKey::from(peer_public_key);
        let shared_secret = self.secret.diffie_hellman(&peer).to_bytes();
        // 拒绝可能因弱公钥导致的全零共享密钥
        if shared_secret == [0_u8; X25519_PUBLIC_KEY_LEN] {
            return Err(CryptoError::InvalidPeerPublicKey);
        }
        Ok(shared_secret)
    }
}

/// 派生出的会话双向密钥集，内部自动执行内存擦除（Zeroize）
#[derive(Clone)]
pub struct SessionKeys {
    /// 客户端发往服务端的 AEAD 密钥
    client_to_server: Zeroizing<[u8; AEAD_KEY_LEN]>,
    /// 服务端发往客户端的 AEAD 密钥
    server_to_client: Zeroizing<[u8; AEAD_KEY_LEN]>,
    /// 用于计算握手 Finished 标签的 HMAC 密钥
    finished: Zeroizing<[u8; AEAD_KEY_LEN]>,
    /// 用于 Nonce 前缀混合的 4 字节静态盐值
    nonce_salt: Zeroizing<[u8; 4]>,
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("client_to_server", &"[redacted]")
            .field("server_to_client", &"[redacted]")
            .field("finished", &"[redacted]")
            .field("nonce_salt", &"[redacted]")
            .finish()
    }
}

/// 计算握手转录摘要（Transcript Hash），绑定连接 ID、两端 Nonce 及公钥
pub fn handshake_transcript_hash(
    connection_id: ConnectionId,
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
    client_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    server_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"udp-protocol/v2/x25519-chacha20poly1305");
    hasher.update(connection_id.raw().to_be_bytes());
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    hasher.update(client_public_key);
    hasher.update(server_public_key);
    hasher.finalize().into()
}

/// 基于 ECDH 共享密钥和握手转录摘要，使用 HKDF-SHA256 派生会话密钥集
pub fn derive_session_keys(
    shared_secret: &[u8; X25519_PUBLIC_KEY_LEN],
    transcript_hash: &[u8; 32],
) -> Result<SessionKeys, CryptoError> {
    if *shared_secret == [0_u8; X25519_PUBLIC_KEY_LEN] {
        return Err(CryptoError::InvalidSharedSecret);
    }
    // HKDF 提取阶段：以 transcript_hash 为 salt，shared_secret 为 IKM
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);
    let mut client_to_server = [0_u8; AEAD_KEY_LEN];
    let mut server_to_client = [0_u8; AEAD_KEY_LEN];
    let mut finished = [0_u8; AEAD_KEY_LEN];
    let mut nonce_salt = [0_u8; 4];
    // 扩展派生各个定向密钥与盐值
    hkdf.expand(b"udp-protocol/v2/client-to-server", &mut client_to_server)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    hkdf.expand(b"udp-protocol/v2/server-to-client", &mut server_to_client)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    hkdf.expand(b"udp-protocol/v2/finished", &mut finished)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    hkdf.expand(b"udp-protocol/v2/packet-nonce", &mut nonce_salt)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(SessionKeys {
        client_to_server: Zeroizing::new(client_to_server),
        server_to_client: Zeroizing::new(server_to_client),
        finished: Zeroizing::new(finished),
        nonce_salt: Zeroizing::new(nonce_salt),
    })
}

impl SessionKeys {
    /// 计算指定角色的握手 Finished 验证标签
    pub fn finished_tag(
        &self,
        role: CryptoRole,
        transcript_hash: &[u8; 32],
    ) -> Result<[u8; FINISHED_TAG_LEN], CryptoError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&*self.finished)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        mac.update(b"udp-protocol/v2/finished");
        mac.update(&[match role {
            CryptoRole::Client => 0,
            CryptoRole::Server => 1,
        }]);
        mac.update(transcript_hash);
        let digest = mac.finalize().into_bytes();
        let mut tag = [0_u8; FINISHED_TAG_LEN];
        tag.copy_from_slice(&digest[..FINISHED_TAG_LEN]);
        Ok(tag)
    }

    /// 使用恒定时间比较校验对端发来的 Finished 标签，防止时序侧信道攻击
    pub fn verify_finished(
        &self,
        role: CryptoRole,
        transcript_hash: &[u8; 32],
        received: &[u8; FINISHED_TAG_LEN],
    ) -> Result<(), CryptoError> {
        let expected = self.finished_tag(role, transcript_hash)?;
        if expected.ct_eq(received).unwrap_u8() != 1 {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }

    /// 获取本机出方向加密密钥
    fn outbound_key(&self, role: CryptoRole) -> &[u8; AEAD_KEY_LEN] {
        match role {
            CryptoRole::Client => &self.client_to_server,
            CryptoRole::Server => &self.server_to_client,
        }
    }

    /// 获取本机入方向解密密钥
    fn inbound_key(&self, role: CryptoRole) -> &[u8; AEAD_KEY_LEN] {
        match role {
            CryptoRole::Client => &self.server_to_client,
            CryptoRole::Server => &self.client_to_server,
        }
    }

    /// 组合 4 字节盐值和 8 字节包号构成 12 字节的数据包 Nonce
    fn packet_nonce(&self, packet_number: PacketNumber) -> [u8; PACKET_NONCE_LEN] {
        let mut nonce = [0_u8; PACKET_NONCE_LEN];
        nonce[..self.nonce_salt.len()].copy_from_slice(&*self.nonce_salt);
        nonce[4..].copy_from_slice(&packet_number.raw().to_be_bytes());
        nonce
    }
}

/// 4096 位防重放位图滑动窗口
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    /// 迄今为止接收到的最高数据包序号
    highest: Option<u64>,
    /// 4096 位位图数组（64 个 u64，第 0 位代表 highest 包号）
    bits: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// 创建初始防重放窗口
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    /// 获取当前窗口已确认的最高包号
    pub fn highest(&self) -> Option<PacketNumber> {
        self.highest.map(PacketNumber::new)
    }

    /// 检查包号是否重放并在位图中标记已接收
    pub fn check_and_mark(&mut self, packet_number: PacketNumber) -> Result<(), ReplayError> {
        let value = packet_number.raw();
        // 1. 首包处理：直接初始化 highest 并置位首 bit
        let Some(highest) = self.highest else {
            self.highest = Some(value);
            self.bits[0] = 1;
            return Ok(());
        };

        // 2. 新包序号超过最高序号：向前移动滑动窗口
        if value > highest {
            let shift = usize::try_from(value - highest).unwrap_or(REPLAY_WINDOW_SIZE);
            if shift >= REPLAY_WINDOW_SIZE {
                // 超出整个窗口长度，清空所有历史标记
                self.bits = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                // 窗口位图右移 shift 位
                self.shift_older_bits(shift);
            }
            self.highest = Some(value);
            self.bits[0] |= 1;
            return Ok(());
        }

        // 3. 包序号在最高序号之前：检查是否在窗口范围内
        let distance = usize::try_from(highest - value).unwrap_or(REPLAY_WINDOW_SIZE);
        if distance >= REPLAY_WINDOW_SIZE {
            return Err(ReplayError::TooOld);
        }
        let word = distance / 64;
        let mask = 1_u64 << (distance % 64);
        if self.bits[word] & mask != 0 {
            return Err(ReplayError::Duplicate);
        }
        self.bits[word] |= mask;
        Ok(())
    }

    /// 将旧位图向后平移 `shift` 个 bit
    fn shift_older_bits(&mut self, shift: usize) {
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let old = self.bits;
        for index in (0..self.bits.len()).rev() {
            let mut value = 0_u64;
            if index >= word_shift {
                value = old[index - word_shift] << bit_shift;
                // 处理跨 64 位 word 的进位/截断
                if bit_shift != 0 && index > word_shift {
                    value |= old[index - word_shift - 1] >> (64 - bit_shift);
                }
            }
            self.bits[index] = value;
        }
    }
}

/// 维护单个会话的加密器上下文（包含通信角色、密钥对及防重放窗口）
pub struct PacketCrypto {
    role: CryptoRole,
    keys: SessionKeys,
    replay: ReplayWindow,
}

impl fmt::Debug for PacketCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketCrypto")
            .field("role", &self.role)
            .field("keys", &self.keys)
            .field("replay", &self.replay)
            .finish()
    }
}

impl PacketCrypto {
    /// 构造新的数据包密码学上下文
    pub fn new(role: CryptoRole, keys: SessionKeys) -> Self {
        Self {
            role,
            keys,
            replay: ReplayWindow::new(),
        }
    }

    /// 获取本机当前角色
    pub const fn role(&self) -> CryptoRole {
        self.role
    }

    /// 计算握手完成标签
    pub fn finished_tag(
        &self,
        role: CryptoRole,
        transcript_hash: &[u8; 32],
    ) -> Result<[u8; FINISHED_TAG_LEN], CryptoError> {
        self.keys.finished_tag(role, transcript_hash)
    }

    /// 使用 ChaCha20-Poly1305 加密数据包明文并附加 16 字节 Tag
    pub(crate) fn seal(
        &self,
        packet_number: PacketNumber,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.keys.outbound_key(self.role)));
        let nonce = self.keys.packet_nonce(packet_number);
        let mut ciphertext = plaintext.to_vec();
        // 原地加密并生成独立认证标签
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), associated_data, &mut ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// 使用 ChaCha20-Poly1305 解密数据包密文并进行防重放检测
    pub(crate) fn open(
        &mut self,
        packet_number: PacketNumber,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(CryptoError::EncryptedPayloadTooShort);
        }
        // 分割密文主体与末尾 16 字节 Poly1305 Tag
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - AEAD_TAG_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.keys.inbound_key(self.role)));
        let nonce = self.keys.packet_nonce(packet_number);
        let mut plaintext = ciphertext.to_vec();
        // 校验 AAD 与 Tag 并就地解密
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                associated_data,
                &mut plaintext,
                Tag::from_slice(tag),
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        // 解密成功后才标记并检测防重放窗口
        self.replay
            .check_and_mark(packet_number)
            .map_err(CryptoError::Replay)?;
        Ok(plaintext)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FIXED_HEADER_LEN, Frame, Packet, PacketFlags, PacketType, Ping};

    fn session() -> (PacketCrypto, PacketCrypto) {
        let client = EphemeralKeyPair::generate().unwrap();
        let server = EphemeralKeyPair::generate().unwrap();
        let client_nonce = [1_u8; 16];
        let server_nonce = [2_u8; 16];
        let transcript = handshake_transcript_hash(
            ConnectionId::new(7),
            &client_nonce,
            &server_nonce,
            &client.public_key(),
            &server.public_key(),
        );
        let client_shared = client.agree(server.public_key()).unwrap();
        let server_shared = server.agree(client.public_key()).unwrap();
        let client_keys = derive_session_keys(&client_shared, &transcript).unwrap();
        let server_keys = derive_session_keys(&server_shared, &transcript).unwrap();
        (
            PacketCrypto::new(CryptoRole::Client, client_keys),
            PacketCrypto::new(CryptoRole::Server, server_keys),
        )
    }

    #[test]
    fn derives_matching_keys_and_encrypts_in_both_directions() {
        let (mut client, mut server) = session();
        let packet = Packet::new(
            PacketType::Data,
            PacketFlags::ACK_ELICITING,
            ConnectionId::new(7),
            PacketNumber::new(3),
            vec![Frame::Ping(Ping { nonce: 42 })],
        );
        let encoded = crate::encode_packet_with_crypto(&packet, 1200, &client).unwrap();
        let decoded = crate::decode_encrypted_packet(&encoded, 1200, &mut server).unwrap();
        assert_eq!(decoded.frames, packet.frames);

        let response = Packet::new(
            PacketType::Data,
            PacketFlags::empty(),
            ConnectionId::new(7),
            PacketNumber::new(9),
            vec![Frame::Ping(Ping { nonce: 43 })],
        );
        let encoded = crate::encode_packet_with_crypto(&response, 1200, &server).unwrap();
        let decoded = crate::decode_encrypted_packet(&encoded, 1200, &mut client).unwrap();
        assert_eq!(decoded.frames, response.frames);
    }

    #[test]
    fn rejects_tampering_and_replay_after_authentication() {
        let (client, mut server) = session();
        let packet = Packet::new(
            PacketType::Data,
            PacketFlags::ACK_ELICITING,
            ConnectionId::new(7),
            PacketNumber::new(3),
            vec![Frame::Ping(Ping { nonce: 42 })],
        );
        let encoded = crate::encode_packet_with_crypto(&packet, 1200, &client).unwrap();
        let mut tampered = encoded.clone();
        tampered[FIXED_HEADER_LEN] ^= 1;
        let checksum = crate::checksum::crc32c_with_zeroed_range(&tampered, 26, 30);
        tampered[26..30].copy_from_slice(&checksum.to_be_bytes());
        assert!(matches!(
            crate::decode_encrypted_packet(&tampered, 1200, &mut server),
            Err(crate::ProtocolError::Crypto(
                CryptoError::AuthenticationFailed
            ))
        ));
        crate::decode_encrypted_packet(&encoded, 1200, &mut server).unwrap();
        assert!(matches!(
            crate::decode_encrypted_packet(&encoded, 1200, &mut server),
            Err(crate::ProtocolError::Crypto(CryptoError::Replay(
                ReplayError::Duplicate
            )))
        ));
    }

    #[test]
    fn replay_window_handles_forward_jumps_and_old_packets() {
        let mut window = ReplayWindow::new();
        window.check_and_mark(PacketNumber::new(10)).unwrap();
        window.check_and_mark(PacketNumber::new(12)).unwrap();
        window.check_and_mark(PacketNumber::new(11)).unwrap();
        assert_eq!(
            window.check_and_mark(PacketNumber::new(10)),
            Err(ReplayError::Duplicate)
        );
        assert_eq!(
            window.check_and_mark(PacketNumber::new(12)),
            Err(ReplayError::Duplicate)
        );
        window
            .check_and_mark(PacketNumber::new(12 + REPLAY_WINDOW_SIZE as u64))
            .unwrap();
        assert_eq!(
            window.check_and_mark(PacketNumber::new(12)),
            Err(ReplayError::TooOld)
        );
    }
}
