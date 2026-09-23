use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use udp_protocol::{ConnectionId, MAX_RETRY_COOKIE_LEN, NONCE_LEN};

const COOKIE_VERSION: u8 = 1;
const TIMESTAMP_LEN: usize = 8;
const TAG_LEN: usize = 16;
const COOKIE_LEN: usize = 1 + TIMESTAMP_LEN + TAG_LEN;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryConfig {
    pub enabled: bool,
    pub cookie_secret: Option<[u8; 32]>,
    pub cookie_ttl: Duration,
    pub clock_skew: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cookie_secret: None,
            cookie_ttl: Duration::from_secs(10),
            clock_skew: Duration::from_secs(5),
        }
    }
}

impl RetryConfig {
    pub(crate) fn prepare(&mut self) -> Result<(), RetryError> {
        if !self.enabled {
            return Ok(());
        }
        if self.cookie_ttl < Duration::from_secs(1) || self.clock_skew > self.cookie_ttl {
            return Err(RetryError::InvalidConfig);
        }
        if self.cookie_secret.is_none() {
            let mut secret = [0_u8; 32];
            getrandom::fill(&mut secret).map_err(|_| RetryError::RandomnessUnavailable)?;
            self.cookie_secret = Some(secret);
        }
        if self
            .cookie_secret
            .is_some_and(|secret| secret.iter().all(|byte| *byte == 0))
        {
            return Err(RetryError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryError {
    InvalidConfig,
    RandomnessUnavailable,
}

pub(crate) struct CookieContext<'a> {
    pub(crate) peer: SocketAddr,
    pub(crate) connection_id: ConnectionId,
    pub(crate) client_nonce: &'a [u8; NONCE_LEN],
    pub(crate) cookie_ttl: Duration,
    pub(crate) clock_skew: Duration,
}

pub(crate) fn issue_cookie(
    secret: &[u8; 32],
    peer: SocketAddr,
    connection_id: ConnectionId,
    client_nonce: &[u8; NONCE_LEN],
    now: SystemTime,
) -> Result<Vec<u8>, RetryError> {
    let timestamp = unix_seconds(now)?;
    let mut cookie = Vec::with_capacity(COOKIE_LEN);
    cookie.push(COOKIE_VERSION);
    cookie.extend_from_slice(&timestamp.to_be_bytes());
    let tag = sign(secret, peer, connection_id, client_nonce, timestamp);
    cookie.extend_from_slice(&tag[..TAG_LEN]);
    debug_assert_eq!(cookie.len(), COOKIE_LEN);
    debug_assert!(cookie.len() <= MAX_RETRY_COOKIE_LEN);
    Ok(cookie)
}

pub(crate) fn validate_cookie(
    secret: &[u8; 32],
    cookie: &[u8],
    now: SystemTime,
    context: CookieContext<'_>,
) -> bool {
    if cookie.len() != COOKIE_LEN || cookie[0] != COOKIE_VERSION {
        return false;
    }
    let mut timestamp_bytes = [0_u8; TIMESTAMP_LEN];
    timestamp_bytes.copy_from_slice(&cookie[1..1 + TIMESTAMP_LEN]);
    let timestamp = u64::from_be_bytes(timestamp_bytes);
    let Ok(now_seconds) = unix_seconds(now) else {
        return false;
    };
    let allowed_future = context.clock_skew.as_secs();
    if timestamp > now_seconds.saturating_add(allowed_future)
        || now_seconds.saturating_sub(timestamp)
            > context.cookie_ttl.as_secs().saturating_add(allowed_future)
    {
        return false;
    }
    let expected = sign(
        secret,
        context.peer,
        context.connection_id,
        context.client_nonce,
        timestamp,
    );
    expected[..TAG_LEN]
        .ct_eq(&cookie[1 + TIMESTAMP_LEN..])
        .into()
}

fn sign(
    secret: &[u8; 32],
    peer: SocketAddr,
    connection_id: ConnectionId,
    client_nonce: &[u8; NONCE_LEN],
    timestamp: u64,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts every non-empty key");
    update_mac(&mut mac, peer, connection_id, client_nonce, timestamp);
    mac.finalize().into_bytes().into()
}

fn update_mac(
    mac: &mut HmacSha256,
    peer: SocketAddr,
    connection_id: ConnectionId,
    client_nonce: &[u8; NONCE_LEN],
    timestamp: u64,
) {
    mac.update(b"reliable-udp retry cookie v1");
    encode_addr(mac, peer);
    mac.update(&connection_id.raw().to_be_bytes());
    mac.update(client_nonce);
    mac.update(&timestamp.to_be_bytes());
}

fn encode_addr(mac: &mut HmacSha256, peer: SocketAddr) {
    match peer {
        SocketAddr::V4(addr) => {
            mac.update(&[4]);
            mac.update(&addr.ip().octets());
            mac.update(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            mac.update(&[6]);
            mac.update(&addr.ip().octets());
            mac.update(&addr.port().to_be_bytes());
            mac.update(&addr.flowinfo().to_be_bytes());
            mac.update(&addr.scope_id().to_be_bytes());
        }
    }
}

fn unix_seconds(now: SystemTime) -> Result<u64, RetryError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RetryError::InvalidConfig)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{CookieContext, issue_cookie, validate_cookie};
    use udp_protocol::{ConnectionId, NONCE_LEN};

    #[test]
    fn cookie_is_bound_to_peer_connection_and_nonce() {
        let secret = [7_u8; 32];
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let nonce = [9_u8; NONCE_LEN];
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(100);
        let cookie = issue_cookie(&secret, peer, ConnectionId::new(3), &nonce, now).unwrap();

        assert!(validate_cookie(
            &secret,
            &cookie,
            now,
            CookieContext {
                peer,
                connection_id: ConnectionId::new(3),
                client_nonce: &nonce,
                cookie_ttl: std::time::Duration::from_secs(10),
                clock_skew: std::time::Duration::ZERO,
            },
        ));
        assert!(!validate_cookie(
            &secret,
            &cookie,
            now,
            CookieContext {
                peer: "127.0.0.1:9001".parse().unwrap(),
                connection_id: ConnectionId::new(3),
                client_nonce: &nonce,
                cookie_ttl: std::time::Duration::from_secs(10),
                clock_skew: std::time::Duration::ZERO,
            },
        ));
    }
}
