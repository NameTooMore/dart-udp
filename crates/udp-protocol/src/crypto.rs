use std::{error::Error, fmt};

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag, aead::AeadInPlace};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{ConnectionId, PacketNumber};

pub const X25519_PUBLIC_KEY_LEN: usize = 32;
pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;
pub const PACKET_NONCE_LEN: usize = 12;
pub const FINISHED_TAG_LEN: usize = 16;
pub const REPLAY_WINDOW_SIZE: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    Duplicate,
    TooOld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    RandomnessUnavailable,
    InvalidPeerPublicKey,
    InvalidSharedSecret,
    KeyDerivationFailed,
    AuthenticationFailed,
    Replay(ReplayError),
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
    pub fn generate() -> Result<Self, CryptoError> {
        let mut secret_bytes = Zeroizing::new([0_u8; X25519_PUBLIC_KEY_LEN]);
        getrandom::fill(&mut *secret_bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        let secret = StaticSecret::from(*secret_bytes);
        let public_key = PublicKey::from(&secret).to_bytes();
        Ok(Self { secret, public_key })
    }

    pub const fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.public_key
    }

    pub fn agree(
        &self,
        peer_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    ) -> Result<[u8; X25519_PUBLIC_KEY_LEN], CryptoError> {
        let peer = PublicKey::from(peer_public_key);
        let shared_secret = self.secret.diffie_hellman(&peer).to_bytes();
        if shared_secret == [0_u8; X25519_PUBLIC_KEY_LEN] {
            return Err(CryptoError::InvalidPeerPublicKey);
        }
        Ok(shared_secret)
    }
}

#[derive(Clone)]
pub struct SessionKeys {
    client_to_server: Zeroizing<[u8; AEAD_KEY_LEN]>,
    server_to_client: Zeroizing<[u8; AEAD_KEY_LEN]>,
    finished: Zeroizing<[u8; AEAD_KEY_LEN]>,
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

pub fn derive_session_keys(
    shared_secret: &[u8; X25519_PUBLIC_KEY_LEN],
    transcript_hash: &[u8; 32],
) -> Result<SessionKeys, CryptoError> {
    if *shared_secret == [0_u8; X25519_PUBLIC_KEY_LEN] {
        return Err(CryptoError::InvalidSharedSecret);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);
    let mut client_to_server = [0_u8; AEAD_KEY_LEN];
    let mut server_to_client = [0_u8; AEAD_KEY_LEN];
    let mut finished = [0_u8; AEAD_KEY_LEN];
    let mut nonce_salt = [0_u8; 4];
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

    fn outbound_key(&self, role: CryptoRole) -> &[u8; AEAD_KEY_LEN] {
        match role {
            CryptoRole::Client => &self.client_to_server,
            CryptoRole::Server => &self.server_to_client,
        }
    }

    fn inbound_key(&self, role: CryptoRole) -> &[u8; AEAD_KEY_LEN] {
        match role {
            CryptoRole::Client => &self.server_to_client,
            CryptoRole::Server => &self.client_to_server,
        }
    }

    fn packet_nonce(&self, packet_number: PacketNumber) -> [u8; PACKET_NONCE_LEN] {
        let mut nonce = [0_u8; PACKET_NONCE_LEN];
        nonce[..self.nonce_salt.len()].copy_from_slice(&*self.nonce_salt);
        nonce[4..].copy_from_slice(&packet_number.raw().to_be_bytes());
        nonce
    }
}

#[derive(Clone, Debug)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    pub fn highest(&self) -> Option<PacketNumber> {
        self.highest.map(PacketNumber::new)
    }

    pub fn check_and_mark(&mut self, packet_number: PacketNumber) -> Result<(), ReplayError> {
        let value = packet_number.raw();
        let Some(highest) = self.highest else {
            self.highest = Some(value);
            self.bits[0] = 1;
            return Ok(());
        };
        if value > highest {
            let shift = usize::try_from(value - highest).unwrap_or(REPLAY_WINDOW_SIZE);
            if shift >= REPLAY_WINDOW_SIZE {
                self.bits = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                self.shift_older_bits(shift);
            }
            self.highest = Some(value);
            self.bits[0] |= 1;
            return Ok(());
        }
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

    fn shift_older_bits(&mut self, shift: usize) {
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let old = self.bits;
        for index in (0..self.bits.len()).rev() {
            let mut value = 0_u64;
            if index >= word_shift {
                value = old[index - word_shift] << bit_shift;
                if bit_shift != 0 && index > word_shift {
                    value |= old[index - word_shift - 1] >> (64 - bit_shift);
                }
            }
            self.bits[index] = value;
        }
    }
}

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
    pub fn new(role: CryptoRole, keys: SessionKeys) -> Self {
        Self {
            role,
            keys,
            replay: ReplayWindow::new(),
        }
    }

    pub const fn role(&self) -> CryptoRole {
        self.role
    }

    pub fn finished_tag(
        &self,
        role: CryptoRole,
        transcript_hash: &[u8; 32],
    ) -> Result<[u8; FINISHED_TAG_LEN], CryptoError> {
        self.keys.finished_tag(role, transcript_hash)
    }

    pub(crate) fn seal(
        &self,
        packet_number: PacketNumber,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.keys.outbound_key(self.role)));
        let nonce = self.keys.packet_nonce(packet_number);
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), associated_data, &mut ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    pub(crate) fn open(
        &mut self,
        packet_number: PacketNumber,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(CryptoError::EncryptedPayloadTooShort);
        }
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - AEAD_TAG_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.keys.inbound_key(self.role)));
        let nonce = self.keys.packet_nonce(packet_number);
        let mut plaintext = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                associated_data,
                &mut plaintext,
                Tag::from_slice(tag),
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
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
