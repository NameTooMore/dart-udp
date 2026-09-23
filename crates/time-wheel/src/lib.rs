//! 分层时间轮（Hierarchical Timing Wheel）模块
//!
//! 提供基于分层槽位与最小堆的高性能、低开销定时器实现，支持高精度步进、
//! 定时器动态增删改查、以及长跨度跳跃（fast-forward）。

#![no_std]

extern crate alloc;

mod config;
mod deadline;
mod error;
mod id;
mod level;
mod wheel;

// 导出对外核心类型与配置
pub use config::{WheelConfig, WheelConfigBuilder};
pub use error::{ConfigError, TimerError};
pub use id::TimerId;
pub use wheel::{AdvanceReport, Expired, Wheel};

