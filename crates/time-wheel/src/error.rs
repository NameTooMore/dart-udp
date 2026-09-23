use core::{error::Error, fmt};

/// 时间轮配置错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// 基础时钟滴答时长为零
    ZeroTick,
    /// 基础滴答时长转换为纳秒时超出 u64 范围
    TickRangeOverflow,
    /// 层级数量无效（超出上限或为空）
    InvalidLevelCount { count: usize, max: usize },
    /// 层级槽位数无效（必须为 2 的幂且在合法区间内）
    InvalidSlotCount { level: usize, slot_count: usize },
    /// 槽位总数超出预设预算上限
    SlotBudgetExceeded { total_slots: usize, max: usize },
    /// 层级跨度滴答数溢出 u64
    DerivedRangeOverflow { level: usize },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTick => f.write_str("base tick must be greater than zero"),
            Self::TickRangeOverflow => {
                f.write_str("base tick is too large to represent in nanoseconds")
            }
            Self::InvalidLevelCount { count, max } => {
                write!(f, "invalid level count {count}; expected 1..={max}")
            }
            Self::InvalidSlotCount { level, slot_count } => write!(
                f,
                "invalid slot count {slot_count} for level {level}; expected a power of two in 2..={}",
                1 << 16
            ),
            Self::SlotBudgetExceeded { total_slots, max } => {
                write!(f, "slot budget exceeded: {total_slots} > {max}")
            }
            Self::DerivedRangeOverflow { level } => {
                write!(f, "derived tick range overflowed at level {level}")
            }
        }
    }
}

impl Error for ConfigError {}

/// 定时器运行时错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    /// 延迟时长换算为滴答时溢出
    DelayOverflow,
    /// 推进的时间跨度换算时溢出
    ElapsedOverflow,
    /// 时间轮全局时钟滴答数溢出 u64
    ClockOverflow,
    /// 到期时刻换算为 Duration 溢出
    DeadlineOverflow,
    /// 定时器 ID 无效或已过期
    StaleTimerId,
    /// 内部数据结构不变性破坏（严重内部异常）
    InvariantViolation,
}

impl fmt::Display for TimerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DelayOverflow => "timer delay cannot be represented by the wheel clock",
            Self::ElapsedOverflow => "elapsed duration cannot be represented by the wheel clock",
            Self::ClockOverflow => "wheel clock would overflow its u64 tick range",
            Self::DeadlineOverflow => "timer deadline cannot be represented as a Duration",
            Self::StaleTimerId => "timer ID is stale or does not belong to this wheel",
            Self::InvariantViolation => "timing wheel invariant was violated",
        };
        f.write_str(message)
    }
}

impl Error for TimerError {}

