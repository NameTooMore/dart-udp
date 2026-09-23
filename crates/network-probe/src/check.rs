use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{net::UdpSocket, time};
use transfer_protocol::{
    Candidate, CandidateId, CheckToken, DecodedMessage, Message, MessageFlags, PathCheck,
    TransactionId, TransferId, decode_message,
};

use crate::ProbeError;

pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEFAULT_PROBE_RETRIES: usize = 2;
pub const DEFAULT_SAMPLE_COUNT: usize = 3;
pub const DEFAULT_MTU_SAMPLE: usize = 1200;
pub const MAX_PROBE_DATAGRAM: usize = 1472;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeConfig {
    pub timeout: Duration,
    pub retries: usize,
    pub samples: usize,
    pub max_candidates: usize,
    pub max_datagram_size: usize,
    /// 连通性检查采用的 UDP 报文上限；它是成功路径的保守 MTU 样本，而不是完整 PMTU 发现。
    pub mtu_sample_size: usize,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_PROBE_TIMEOUT,
            retries: DEFAULT_PROBE_RETRIES,
            samples: DEFAULT_SAMPLE_COUNT,
            max_candidates: 16,
            max_datagram_size: MAX_PROBE_DATAGRAM,
            mtu_sample_size: DEFAULT_MTU_SAMPLE,
        }
    }
}

impl ProbeConfig {
    pub fn validate(&self) -> Result<(), ProbeError> {
        if self.timeout.is_zero() {
            return Err(ProbeError::InvalidConfig("timeout"));
        }
        if self.samples == 0 {
            return Err(ProbeError::InvalidConfig("samples"));
        }
        if self.max_candidates == 0 {
            return Err(ProbeError::InvalidConfig("max_candidates"));
        }
        if !(64..=65_507).contains(&self.max_datagram_size) {
            return Err(ProbeError::InvalidConfig("max_datagram_size"));
        }
        if self.mtu_sample_size < 64 || self.mtu_sample_size > self.max_datagram_size {
            return Err(ProbeError::InvalidConfig("mtu_sample_size"));
        }
        Ok(())
    }

    fn rounds(&self) -> usize {
        self.samples.max(self.retries.saturating_add(1))
    }
}

#[derive(Debug, Clone)]
pub struct CheckAuthorization {
    transfer_id: TransferId,
    check_token: CheckToken,
    expires_at_millis: u64,
    candidates: HashMap<CandidateId, SocketAddr>,
}

impl CheckAuthorization {
    pub fn new(
        transfer_id: TransferId,
        check_token: CheckToken,
        expires_at_millis: u64,
        candidates: &[Candidate],
    ) -> Result<Self, ProbeError> {
        let mut authorized = HashMap::with_capacity(candidates.len());
        for candidate in candidates {
            let Some(address) = candidate.address else {
                continue;
            };
            if address.ip().is_unspecified() || address.port() == 0 {
                return Err(ProbeError::InvalidCandidate(candidate.id));
            }
            authorized.insert(candidate.id, address);
        }
        if authorized.is_empty() {
            return Err(ProbeError::NoCandidates);
        }
        Ok(Self {
            transfer_id,
            check_token,
            expires_at_millis,
            candidates: authorized,
        })
    }

    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    pub fn check_token(&self) -> CheckToken {
        self.check_token
    }

    pub fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }

    pub fn is_expired(&self, now_millis: u64) -> bool {
        now_millis >= self.expires_at_millis
    }

    fn permits(&self, candidate_id: CandidateId, source: SocketAddr, now_millis: u64) -> bool {
        !self.is_expired(now_millis)
            && self.candidates.contains_key(&candidate_id)
            && !source.ip().is_unspecified()
            && !source.ip().is_multicast()
            && source.port() != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub candidate: Candidate,
    pub sent: u32,
    pub received: u32,
    pub rtt_millis: Option<u64>,
    pub mtu: u16,
    pub observed_address: Option<SocketAddr>,
}

impl CheckResult {
    pub fn succeeded(&self) -> bool {
        self.received > 0
    }

    pub fn loss_percent(&self) -> u8 {
        if self.sent == 0 {
            return 100;
        }
        let lost = self.sent.saturating_sub(self.received);
        u8::try_from((u64::from(lost) * 100 / u64::from(self.sent)).min(100)).unwrap_or(100)
    }
}

pub struct ProbeSocket {
    socket: UdpSocket,
    config: ProbeConfig,
}

impl ProbeSocket {
    pub async fn bind(bind_addr: SocketAddr, config: ProbeConfig) -> Result<Self, ProbeError> {
        config.validate()?;
        Ok(Self {
            socket: UdpSocket::bind(bind_addr).await?,
            config,
        })
    }

    pub fn from_socket(socket: UdpSocket, config: ProbeConfig) -> Result<Self, ProbeError> {
        config.validate()?;
        Ok(Self { socket, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProbeError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn config(&self) -> &ProbeConfig {
        &self.config
    }

    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }

    pub async fn check(
        &self,
        transfer_id: TransferId,
        check_token: CheckToken,
        candidate: Candidate,
    ) -> Result<CheckResult, ProbeError> {
        let mut results = self
            .check_candidates(transfer_id, check_token, &[candidate])
            .await?;
        results.pop().ok_or(ProbeError::NoCandidates)
    }

    pub async fn check_candidates(
        &self,
        transfer_id: TransferId,
        check_token: CheckToken,
        candidates: &[Candidate],
    ) -> Result<Vec<CheckResult>, ProbeError> {
        self.config.validate()?;
        if candidates.is_empty() {
            return Err(ProbeError::NoCandidates);
        }
        if candidates.len() > self.config.max_candidates {
            return Err(ProbeError::InvalidConfig("candidate count"));
        }

        let usable = candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| candidate.address.map(|address| (index, address)))
            .collect::<Vec<_>>();
        if usable.is_empty() {
            return Err(ProbeError::NoCandidates);
        }
        let mut results = candidates
            .iter()
            .cloned()
            .map(|candidate| CheckResult {
                candidate,
                sent: 0,
                received: 0,
                rtt_millis: None,
                mtu: 0,
                observed_address: None,
            })
            .collect::<Vec<_>>();

        for _round in 0..self.config.rounds() {
            let mut pending = HashMap::new();
            for (index, address) in &usable {
                let transaction_id =
                    TransactionId::random().map_err(|_| ProbeError::RandomnessUnavailable)?;
                let message = Message::Path(PathCheck::Request {
                    transfer_id,
                    transaction_id,
                    check_token,
                    candidate_id: results[*index].candidate.id,
                    send_timestamp_millis: unix_millis(),
                });
                let bytes = message.encode(0, MessageFlags::empty())?;
                if bytes.len() > self.config.max_datagram_size {
                    return Err(ProbeError::InvalidConfig("encoded probe datagram"));
                }
                self.socket.send_to(&bytes, address).await?;
                results[*index].sent = results[*index].sent.saturating_add(1);
                pending.insert(transaction_id, (*index, time::Instant::now()));
            }

            let deadline = time::Instant::now() + self.config.timeout;
            let mut buffer = vec![0_u8; self.config.max_datagram_size];
            while !pending.is_empty() {
                let received = time::timeout_at(deadline, self.socket.recv_from(&mut buffer)).await;
                let Ok(Ok((length, _source))) = received else {
                    break;
                };
                let decoded = match decode_message(&buffer[..length]) {
                    Ok(decoded) => decoded,
                    Err(_) => continue,
                };
                let Some((transaction_id, index, started)) =
                    response_transaction(&decoded, &pending)
                else {
                    continue;
                };
                let Message::Path(PathCheck::Response {
                    transfer_id: response_transfer,
                    check_token: response_token,
                    candidate_id,
                    observed_address,
                    ..
                }) = decoded.message
                else {
                    continue;
                };
                if response_transfer != transfer_id
                    || response_token != check_token
                    || candidate_id != results[index].candidate.id
                {
                    continue;
                }
                pending.remove(&transaction_id);
                results[index].received = results[index].received.saturating_add(1);
                let rtt = started.elapsed().as_millis() as u64;
                results[index].rtt_millis = Some(
                    results[index]
                        .rtt_millis
                        .map_or(rtt, |current| current.min(rtt)),
                );
                results[index].observed_address = Some(observed_address);
                results[index].mtu = u16::try_from(self.config.mtu_sample_size).unwrap_or(u16::MAX);
            }
        }
        Ok(results)
    }

    pub async fn respond_once(
        &self,
        authorization: &CheckAuthorization,
    ) -> Result<CheckResult, ProbeError> {
        let mut buffer = vec![0_u8; self.config.max_datagram_size];
        let (length, source) = self.socket.recv_from(&mut buffer).await?;
        let decoded = decode_message(&buffer[..length])?;
        let Message::Path(PathCheck::Request {
            transfer_id,
            transaction_id,
            check_token,
            candidate_id,
            ..
        }) = decoded.message
        else {
            return Err(ProbeError::UnauthorizedCheck);
        };
        if transfer_id != authorization.transfer_id
            || check_token != authorization.check_token
            || !authorization.permits(candidate_id, source, unix_millis())
        {
            if authorization.is_expired(unix_millis()) {
                return Err(ProbeError::AuthorizationExpired);
            }
            return Err(ProbeError::UnauthorizedCheck);
        }
        let response = Message::Path(PathCheck::Response {
            transfer_id,
            transaction_id,
            check_token,
            candidate_id,
            observed_address: source,
            receive_timestamp_millis: unix_millis(),
        });
        let bytes = response.encode(0, MessageFlags::RESPONSE)?;
        self.socket.send_to(&bytes, source).await?;
        Ok(CheckResult {
            candidate: Candidate {
                id: candidate_id,
                kind: transfer_protocol::CandidateKind::PeerReflexive,
                address: Some(source),
                priority: 0,
                interface_index: None,
            },
            sent: 1,
            received: 1,
            rtt_millis: None,
            mtu: u16::try_from(self.config.mtu_sample_size).unwrap_or(u16::MAX),
            observed_address: Some(source),
        })
    }
}

fn response_transaction(
    decoded: &DecodedMessage,
    pending: &HashMap<TransactionId, (usize, time::Instant)>,
) -> Option<(TransactionId, usize, time::Instant)> {
    let Message::Path(PathCheck::Response { transaction_id, .. }) = &decoded.message else {
        return None;
    };
    pending
        .get(transaction_id)
        .map(|(index, started)| (*transaction_id, *index, *started))
}

pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use transfer_protocol::{CandidateId, CandidateKind};

    #[tokio::test]
    async fn authorized_loopback_check_records_rtt_and_mtu() {
        let config = ProbeConfig {
            retries: 0,
            samples: 1,
            timeout: Duration::from_millis(100),
            ..ProbeConfig::default()
        };
        let responder = ProbeSocket::bind(([127, 0, 0, 1], 0).into(), config.clone())
            .await
            .unwrap();
        let initiator = ProbeSocket::bind(([127, 0, 0, 1], 0).into(), config)
            .await
            .unwrap();
        let candidate = Candidate {
            id: CandidateId::from_bytes([7; 16]),
            kind: CandidateKind::Host,
            address: Some(responder.local_addr().unwrap()),
            priority: 100,
            interface_index: None,
        };
        let transfer_id = TransferId::from_bytes([8; 16]);
        let token = CheckToken::from_bytes([9; 32]);
        let authorization = CheckAuthorization::new(
            transfer_id,
            token,
            unix_millis().saturating_add(10_000),
            std::slice::from_ref(&candidate),
        )
        .unwrap();
        let responder_task =
            tokio::spawn(async move { responder.respond_once(&authorization).await });
        let result = initiator
            .check(transfer_id, token, candidate)
            .await
            .unwrap();
        responder_task.await.unwrap().unwrap();
        assert!(result.succeeded());
        assert_eq!(result.received, 1);
        assert_eq!(result.mtu, DEFAULT_MTU_SAMPLE as u16);
    }
}
