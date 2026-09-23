//! 文件传输使用的候选收集、连通性检查和路径选择。
//!
//! 该 crate 不创建可靠传输连接，也不负责 relay 数据转发。它只产生可验证的
//! 路径结果，调用方可以据此创建 direct 连接，或者立即选择已有的 relay ticket。

mod candidate;
mod check;
mod error;
mod interface;
mod selection;

pub use candidate::{CandidateExchange, CandidatePair, candidate_digest, pair_candidates};
pub use check::{CheckAuthorization, CheckResult, ProbeConfig, ProbeSocket, unix_millis};
pub use error::{ProbeError, SelectionError};
pub use interface::{NetworkInterface, NetworkRoute, NetworkSnapshot};
pub use selection::{
    PathDecision, PathSelectionConfig, RelayPath, SelectedPath, choose_path, select_best,
};
