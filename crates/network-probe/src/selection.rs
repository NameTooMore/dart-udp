use std::net::SocketAddr;

use transfer_protocol::{CandidateKind, PathId, PathKind, RelayId, SessionTicket};

use crate::{CheckResult, SelectionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSelectionConfig {
    pub address_family_bonus: i64,
    pub rtt_penalty_per_millis: i64,
    pub loss_penalty_per_percent: i64,
    pub mtu_penalty_per_100_bytes: i64,
    pub minimum_mtu: u16,
}

impl Default for PathSelectionConfig {
    fn default() -> Self {
        Self {
            address_family_bonus: 4,
            rtt_penalty_per_millis: 1,
            loss_penalty_per_percent: 8,
            mtu_penalty_per_100_bytes: 2,
            minimum_mtu: 576,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedPath {
    pub path_id: PathId,
    pub candidate_id: transfer_protocol::CandidateId,
    pub address: SocketAddr,
    pub kind: PathKind,
    pub rtt_millis: u64,
    pub loss_percent: u8,
    pub mtu: u16,
    pub score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPath {
    pub relay_id: RelayId,
    pub relay_ticket: SessionTicket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathDecision {
    Direct(SelectedPath),
    Relay(RelayPath),
}

pub fn select_best(
    results: &[CheckResult],
    config: PathSelectionConfig,
) -> Result<SelectedPath, SelectionError> {
    let mut best = results
        .iter()
        .filter(|result| result.succeeded() && result.mtu >= config.minimum_mtu)
        .filter_map(|result| {
            let address = result.candidate.address?;
            let rtt = result.rtt_millis?;
            let kind = path_kind(result.candidate.kind);
            if kind == PathKind::Relay {
                return None;
            }
            let score = score(result, kind, rtt, config);
            Some((score, result, address, rtt, kind))
        })
        .collect::<Vec<_>>();
    best.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.candidate.id.cmp(&right.1.candidate.id))
    });
    let Some((score, result, address, rtt, kind)) = best.first().copied() else {
        return Err(SelectionError::NoSuccessfulDirectPath);
    };
    let path_id = PathId::random().map_err(|_| SelectionError::RandomnessUnavailable)?;
    Ok(SelectedPath {
        path_id,
        candidate_id: result.candidate.id,
        address,
        kind,
        rtt_millis: rtt,
        loss_percent: result.loss_percent(),
        mtu: result.mtu,
        score,
    })
}

pub fn choose_path(
    results: &[CheckResult],
    config: PathSelectionConfig,
    relay: Option<RelayPath>,
    direct_only: bool,
) -> Result<PathDecision, SelectionError> {
    match select_best(results, config) {
        Ok(path) => Ok(PathDecision::Direct(path)),
        Err(error) if !direct_only => relay.map(PathDecision::Relay).ok_or(error),
        Err(error) => Err(error),
    }
}

fn score(result: &CheckResult, kind: PathKind, rtt: u64, config: PathSelectionConfig) -> i64 {
    let topology = match kind {
        PathKind::Host => 100,
        PathKind::RoutedLan => 90,
        PathKind::ReflexiveDirect => 70,
        PathKind::Relay => 10,
    };
    let family_bonus = match result.candidate.address.map(|address| address.is_ipv6()) {
        Some(true) => config.address_family_bonus,
        _ => 0,
    };
    let mtu_penalty = u64::from(1200_u16.saturating_sub(result.mtu)) / 100;
    i64::from(result.candidate.priority) + topology + family_bonus
        - i64::try_from(rtt).unwrap_or(i64::MAX) * config.rtt_penalty_per_millis
        - i64::from(result.loss_percent()) * config.loss_penalty_per_percent
        - i64::try_from(mtu_penalty).unwrap_or(i64::MAX) * config.mtu_penalty_per_100_bytes
}

fn path_kind(kind: CandidateKind) -> PathKind {
    match kind {
        CandidateKind::Host => PathKind::Host,
        CandidateKind::RoutedLan => PathKind::RoutedLan,
        CandidateKind::ServerReflexive | CandidateKind::PeerReflexive => PathKind::ReflexiveDirect,
        CandidateKind::Relay => PathKind::Relay,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use transfer_protocol::{Candidate, CandidateId, CandidateKind};

    use super::*;

    fn result(id: u8, kind: CandidateKind, priority: u16, rtt: u64) -> CheckResult {
        CheckResult {
            candidate: Candidate {
                id: CandidateId::from_bytes([id; 16]),
                kind,
                address: Some(SocketAddr::from(([192, 0, 2, id], 4000))),
                priority,
                interface_index: Some(2),
            },
            sent: 3,
            received: 3,
            rtt_millis: Some(rtt),
            mtu: 1200,
            observed_address: None,
        }
    }

    #[test]
    fn topology_and_rtt_are_used_for_selection() {
        let selected = select_best(
            &[
                result(1, CandidateKind::ServerReflexive, 70, 5),
                result(2, CandidateKind::Host, 100, 20),
            ],
            PathSelectionConfig::default(),
        )
        .unwrap();
        assert_eq!(selected.candidate_id, CandidateId::from_bytes([2; 16]));
        assert_eq!(selected.kind, PathKind::Host);
    }
}
