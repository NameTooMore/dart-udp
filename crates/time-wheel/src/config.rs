use alloc::vec::Vec;
use core::time::Duration;

use crate::error::ConfigError;

/// 默认基础滴答精度（10ms）
const DEFAULT_BASE_TICK: Duration = Duration::from_millis(10);
/// 默认 3 层结构各层槽位数：L0=512, L1=64, L2=64
const DEFAULT_LEVEL_SLOTS: &[usize] = &[512, 64, 64];
/// 最大允许的时间轮层级数
const MAX_LEVELS: usize = 8;
/// 单层最大槽位数（65536）
const MAX_LEVEL_SLOTS: usize = 1 << 16;
/// 时间轮总槽位预算上限（防止内存暴涨）
const MAX_TOTAL_SLOTS: usize = 300_000;

/// 时间轮静态拓扑配置
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelConfig {
    base_tick: Duration,
    base_tick_nanos: u64,
    levels: Vec<LevelConfig>,
    total_slots: usize,
}

/// 单个层级的静态配置参数
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LevelConfig {
    /// 该层单个槽位对应的滴答数
    pub(crate) unit_ticks: u64,
    /// 该层所有槽位能够覆盖的总滴答跨度
    pub(crate) span_ticks: u64,
    /// 槽位数量（必须为 2 的幂）
    pub(crate) slot_count: usize,
    /// 槽位快速取模掩码（slot_count - 1）
    pub(crate) mask: usize,
}

impl Default for WheelConfig {
    fn default() -> Self {
        let mut builder = Self::builder().base_tick(DEFAULT_BASE_TICK);
        for &slots in DEFAULT_LEVEL_SLOTS {
            builder = builder.level_slots(slots);
        }
        builder
            .build()
            .expect("default wheel configuration must be valid")
    }
}

impl WheelConfig {
    /// 创建配置构建器
    pub fn builder() -> WheelConfigBuilder {
        WheelConfigBuilder::default()
    }

    /// 获取基础滴答时长
    pub fn base_tick(&self) -> Duration {
        self.base_tick
    }

    /// 获取层级数量
    pub fn level_count(&self) -> usize {
        self.levels.len()
    }

    /// 获取总槽位数
    pub fn total_slots(&self) -> usize {
        self.total_slots
    }

    /// 获取基础滴答对应的纳秒数
    pub(crate) fn base_tick_nanos(&self) -> u64 {
        self.base_tick_nanos
    }

    /// 获取所有层级的配置切片
    pub(crate) fn levels(&self) -> &[LevelConfig] {
        &self.levels
    }
}

/// 时间轮配置构建器
#[derive(Debug, Clone)]
pub struct WheelConfigBuilder {
    base_tick: Duration,
    levels: Vec<usize>,
}

impl Default for WheelConfigBuilder {
    fn default() -> Self {
        Self {
            base_tick: DEFAULT_BASE_TICK,
            levels: Vec::new(),
        }
    }
}

impl WheelConfigBuilder {
    /// 设置基础时钟滴答时长
    pub fn base_tick(mut self, tick: Duration) -> Self {
        self.base_tick = tick;
        self
    }

    /// 按从低到高顺序添加层级的槽位数（必须为 2 的幂）
    pub fn level_slots(mut self, slots: usize) -> Self {
        self.levels.push(slots);
        self
    }

    /// 校验并构建时间轮配置
    pub fn build(self) -> Result<WheelConfig, ConfigError> {
        // 1. 校验基础滴答时长并转换为纳秒
        let base_tick_nanos = self
            .base_tick
            .as_nanos()
            .try_into()
            .map_err(|_| ConfigError::TickRangeOverflow)?;
        if base_tick_nanos == 0 {
            return Err(ConfigError::ZeroTick);
        }

        // 2. 校验层级数量在 [1, MAX_LEVELS] 范围内
        if self.levels.is_empty() || self.levels.len() > MAX_LEVELS {
            return Err(ConfigError::InvalidLevelCount {
                count: self.levels.len(),
                max: MAX_LEVELS,
            });
        }

        let mut total_slots = 0usize;
        let mut unit_ticks = 1u64;
        let mut derived = Vec::with_capacity(self.levels.len());

        // 3. 逐层推导并校验各层的槽位范围与滴答跨度
        for (level, &slot_count) in self.levels.iter().enumerate() {
            // 槽位数必须为 2 的幂且在 2..=MAX_LEVEL_SLOTS 范围内
            if slot_count < 2 || !slot_count.is_power_of_two() || slot_count > MAX_LEVEL_SLOTS {
                return Err(ConfigError::InvalidSlotCount { level, slot_count });
            }

            // 累计总槽位并检查预算上限
            total_slots =
                total_slots
                    .checked_add(slot_count)
                    .ok_or(ConfigError::SlotBudgetExceeded {
                        total_slots: usize::MAX,
                        max: MAX_TOTAL_SLOTS,
                    })?;
            if total_slots > MAX_TOTAL_SLOTS {
                return Err(ConfigError::SlotBudgetExceeded {
                    total_slots,
                    max: MAX_TOTAL_SLOTS,
                });
            }

            // 计算当前层级的覆盖跨度：unit_ticks * slot_count
            let span_ticks = unit_ticks
                .checked_mul(slot_count as u64)
                .ok_or(ConfigError::DerivedRangeOverflow { level })?;
            derived.push(LevelConfig {
                unit_ticks,
                span_ticks,
                slot_count,
                mask: slot_count - 1,
            });
            // 下一层的单位步长即为上一层的总跨度
            unit_ticks = span_ticks;
        }

        Ok(WheelConfig {
            base_tick: self.base_tick,
            base_tick_nanos,
            levels: derived,
            total_slots,
        })
    }
}

