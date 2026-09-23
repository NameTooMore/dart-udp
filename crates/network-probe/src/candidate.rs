use std::net::{IpAddr, SocketAddr};

use blake3::Hasher;
use transfer_protocol::{
    Candidate, CandidateKind, CheckToken, Digest, HashAlgorithm, PathKind, TransferId,
};

use crate::ProbeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateExchange {
    pub transfer_id: TransferId,
    pub local: Vec<Candidate>,
    pub remote: Vec<Candidate>,
    pub digest: Digest,
    pub check_token: CheckToken,
}

impl CandidateExchange {
    pub fn new(
        transfer_id: TransferId,
        local: Vec<Candidate>,
        remote: Vec<Candidate>,
        check_token: CheckToken,
    ) -> Result<Self, ProbeError> {
        if local.is_empty() || remote.is_empty() {
            return Err(ProbeError::NoCandidates);
        }
        Ok(Self {
            transfer_id,
            digest: candidate_digest(&local),
            local,
            remote,
            check_token,
        })
    }

    pub fn pairs(&self, max_pairs: usize) -> Vec<CandidatePair> {
        pair_candidates(&self.local, &self.remote, max_pairs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub kind: PathKind,
    pub priority: u32,
}

pub fn pair_candidates(
    local: &[Candidate],
    remote: &[Candidate],
    max_pairs: usize,
) -> Vec<CandidatePair> {
    if max_pairs == 0 {
        return Vec::new();
    }
    let mut pairs = local
        .iter()
        .flat_map(|local| {
            remote.iter().filter_map(move |remote| {
                let local_address = local.address?;
                let remote_address = remote.address?;
                let kind = pair_kind(local, remote, local_address, remote_address);
                let priority = u32::from(local.priority)
                    .saturating_add(u32::from(remote.priority))
                    .saturating_add(path_priority(kind));
                Some(CandidatePair {
                    local: local.clone(),
                    remote: remote.clone(),
                    kind,
                    priority,
                })
            })
        })
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.remote.address.cmp(&right.remote.address))
            .then_with(|| left.local.address.cmp(&right.local.address))
    });
    pairs.truncate(max_pairs);
    pairs
}

pub fn candidate_digest(candidates: &[Candidate]) -> Digest {
    let mut sorted = candidates.to_vec();
    sorted.sort_by_key(|candidate| candidate.id);
    let mut hasher = Hasher::new();
    hasher.update(b"udp-transfer-candidates-v1\0");
    for candidate in sorted {
        hasher.update(candidate.id.as_bytes());
        hasher.update(&[candidate.kind as u8]);
        encode_socket(&mut hasher, candidate.address);
        hasher.update(&candidate.priority.to_be_bytes());
        hasher.update(&candidate.interface_index.unwrap_or(u32::MAX).to_be_bytes());
    }
    Digest::new(HashAlgorithm::Blake3, *hasher.finalize().as_bytes())
}

fn pair_kind(
    local: &Candidate,
    remote: &Candidate,
    local_address: SocketAddr,
    remote_address: SocketAddr,
) -> PathKind {
    if local.kind == CandidateKind::Relay || remote.kind == CandidateKind::Relay {
        return PathKind::Relay;
    }
    if matches!(
        local.kind,
        CandidateKind::ServerReflexive | CandidateKind::PeerReflexive
    ) || matches!(
        remote.kind,
        CandidateKind::ServerReflexive | CandidateKind::PeerReflexive
    ) {
        return PathKind::ReflexiveDirect;
    }
    if same_subnet(
        local_address.ip(),
        remote_address.ip(),
        local.interface_index,
    ) {
        PathKind::Host
    } else {
        PathKind::RoutedLan
    }
}

fn same_subnet(left: IpAddr, right: IpAddr, _interface_index: Option<u32>) -> bool {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            let left = left.octets();
            let right = right.octets();
            left[..3] == right[..3]
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            let left = left.octets();
            let right = right.octets();
            left[..8] == right[..8]
        }
        _ => false,
    }
}

fn path_priority(kind: PathKind) -> u32 {
    match kind {
        PathKind::Host => 100,
        PathKind::RoutedLan => 90,
        PathKind::ReflexiveDirect => 70,
        PathKind::Relay => 10,
    }
}

fn encode_socket(hasher: &mut Hasher, address: Option<SocketAddr>) {
    match address {
        None => {
            hasher.update(&[0]);
        }
        Some(SocketAddr::V4(address)) => {
            hasher.update(&[4]);
            hasher.update(&address.ip().octets());
            hasher.update(&address.port().to_be_bytes());
        }
        Some(SocketAddr::V6(address)) => {
            hasher.update(&[6]);
            hasher.update(&address.ip().octets());
            hasher.update(&address.port().to_be_bytes());
            hasher.update(&address.flowinfo().to_be_bytes());
            hasher.update(&address.scope_id().to_be_bytes());
        }
    }
}
