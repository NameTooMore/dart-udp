use alloc::vec::Vec;
use core::time::Duration;
#[cfg(debug_assertions)]
use slotmap::Key;
use slotmap::{DefaultKey, SlotMap};

use crate::{
    config::WheelConfig, deadline::DeadlineHeap, error::TimerError, id::TimerId, level::Level,
};

/// 小跨度推进阈值：单次步进滴答数不超过此阈值时走逐滴答级联，超过时触发直接快进（全量重新桶化）
const SMALL_ADVANCE_LIMIT: u64 = 4096;

/// 时间轮内部存储的任务条目
struct WheelEntry<T> {
    /// 任务携带的用户数据
    item: T,
    /// 任务绝对到期时间（滴答数）
    deadline_tick: u64,
    /// 当前挂载的时间轮层级索引
    level: u8,
    /// 当前挂载的槽位索引
    slot: u32,
    /// 同一槽位双向链表中的前一个任务节点
    prev: Option<DefaultKey>,
    /// 同一槽位双向链表中的后一个任务节点
    next: Option<DefaultKey>,
    /// 在全局到期最小堆中的数组下标
    heap_index: usize,
}

/// 已到期定时器条目，包含 ID、载荷及触发滴答
pub struct Expired<T> {
    pub id: TimerId,
    pub item: T,
    pub deadline_tick: u64,
}

/// 时间轮推进执行报告
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvanceReport {
    /// 本次实际推进的滴答数
    pub elapsed_ticks: u64,
    /// 本次触发到期的定时器数量
    pub expired_count: usize,
    /// 是否采用了快进模式
    pub fast_forwarded: bool,
}

/// 分层时间轮核心结构体
pub struct Wheel<T> {
    /// 任务存储池，以稳定高效的 slotmap 维护节点生命周期
    tasks: SlotMap<DefaultKey, WheelEntry<T>>,
    /// 全局最早到期最小堆，支持 O(1) 探测最近到期时间
    deadline_heap: DeadlineHeap,
    /// 多层槽位结构（L0, L1, ...）
    levels: Vec<Level>,
    /// 当前时间轮全局滴答时钟
    current_tick: u64,
    /// 累积的亚滴答纳秒残差（不足一个 base_tick 时暂存）
    remainder_nanos: u64,
    /// 基础滴答时长的纳秒数
    base_tick_nanos: u64,
}

impl<T> Wheel<T> {
    /// 根据配置初始化分层时间轮
    pub fn new(config: WheelConfig) -> Self {
        let levels = config
            .levels()
            .iter()
            .map(|level| {
                Level::new(
                    level.unit_ticks,
                    level.span_ticks,
                    level.slot_count,
                    level.mask,
                )
            })
            .collect();
        Self {
            tasks: SlotMap::new(),
            deadline_heap: DeadlineHeap::new(),
            levels,
            current_tick: 0,
            remainder_nanos: 0,
            base_tick_nanos: config.base_tick_nanos(),
        }
    }

    /// 插入新定时任务，指定延迟时长 `delay`
    pub fn insert(&mut self, item: T, delay: Duration) -> Result<TimerId, TimerError> {
        // 1. 计算绝对到期滴答
        let deadline_tick = self.deadline_after(delay)?;
        // 2. 将条目记录到 slotmap 存储池中
        let key = self.tasks.insert(WheelEntry {
            item,
            deadline_tick,
            level: 0,
            slot: 0,
            prev: None,
            next: None,
            heap_index: 0,
        });
        // 3. 计算适合该到期滴答的层级与槽位，并接入该槽位链表
        let (level, slot) = self.determine_location(deadline_tick);
        if let Err(error) = self.link(key, level, slot) {
            self.tasks.remove(key);
            return Err(error);
        }
        // 4. 将任务同步插入全局到期最小堆
        if let Err(error) = self.insert_deadline(key, deadline_tick) {
            let _ = self.unlink(key);
            self.tasks.remove(key);
            return Err(error);
        }
        self.debug_assert_invariants();
        Ok(TimerId::from_key(key))
    }

    /// 重新调度现有定时器（修改延迟时长）
    pub fn reschedule(&mut self, id: TimerId, delay: Duration) -> Result<(), TimerError> {
        let key = id.key();
        if !self.tasks.contains_key(key) {
            return Err(TimerError::StaleTimerId);
        }
        // 1. 计算新的目标到期滴答
        let deadline_tick = self.deadline_after(delay)?;
        // 2. 从旧槽位链表摘除
        self.unlink(key)?;
        self.tasks
            .get_mut(key)
            .ok_or(TimerError::StaleTimerId)?
            .deadline_tick = deadline_tick;
        // 3. 重新计算层级并链入新槽位
        let (level, slot) = self.determine_location(deadline_tick);
        self.link(key, level, slot)?;
        // 4. 更新最小堆中的节点到期时间
        let heap_index = self
            .tasks
            .get(key)
            .ok_or(TimerError::InvariantViolation)?
            .heap_index;
        self.update_deadline(key, heap_index, deadline_tick)?;
        self.debug_assert_invariants();
        Ok(())
    }

    /// 取消指定定时器并返回其关联的用户数据（若定时器不存在或已过期则返回 None）
    pub fn cancel(&mut self, id: TimerId) -> Option<T> {
        let key = id.key();
        if !self.tasks.contains_key(key) {
            return None;
        }
        // 从所在槽位双向链表中移除
        self.unlink(key).ok()?;
        // 从最小堆中移除
        let heap_index = self.tasks.get(key)?.heap_index;
        self.remove_deadline(key, heap_index).ok()?;
        // 从 slotmap 释放并返回数据
        let entry = self.tasks.remove(key)?;
        self.debug_assert_invariants();
        Some(entry.item)
    }

    /// 按流逝时间 `elapsed` 推进时间轮，并将到期的定时器追加至 `expired`
    pub fn advance_by(
        &mut self,
        elapsed: Duration,
        expired: &mut Vec<Expired<T>>,
    ) -> Result<AdvanceReport, TimerError> {
        // 1. 纳秒转换与残差累加
        let elapsed_nanos: u64 = elapsed
            .as_nanos()
            .try_into()
            .map_err(|_| TimerError::ElapsedOverflow)?;
        let total_nanos = self
            .remainder_nanos
            .checked_add(elapsed_nanos)
            .ok_or(TimerError::ElapsedOverflow)?;
        let elapsed_ticks = total_nanos / self.base_tick_nanos;
        let remainder_nanos = total_nanos % self.base_tick_nanos;
        let target_tick = self
            .current_tick
            .checked_add(elapsed_ticks)
            .ok_or(TimerError::ClockOverflow)?;

        self.remainder_nanos = remainder_nanos;
        let expired_start = expired.len();
        let fast_forwarded = elapsed_ticks > SMALL_ADVANCE_LIMIT;

        // 2. 根据步进距离选择推进策略
        if fast_forwarded {
            // 大跨度跳跃：直接扫描所有存活任务重新分桶，避免庞大的逐滴答级联循环
            self.fast_forward(target_tick, expired)?;
        } else {
            // 逐滴答步进：先处理当前滴答的高层级联和 L0 槽位
            self.cascade_at_current_tick(expired)?;
            self.process_l0_slot(expired)?;
            // 逐步推进至 target_tick
            while self.current_tick < target_tick {
                self.current_tick += 1;
                self.cascade_at_current_tick(expired)?;
                self.process_l0_slot(expired)?;
            }
        }
        self.debug_assert_invariants();
        Ok(AdvanceReport {
            elapsed_ticks,
            expired_count: expired.len() - expired_start,
            fast_forwarded,
        })
    }

    /// 获取距离下一个定时器到期的剩余时长（若无定时器则返回 Ok(None)）
    pub fn next_deadline(&self) -> Result<Option<Duration>, TimerError> {
        // 借助最小堆直接在 O(1) 内获取最近到期任务
        let Some(node) = self.deadline_heap.peek() else {
            return if self.tasks.is_empty() {
                Ok(None)
            } else {
                Err(TimerError::InvariantViolation)
            };
        };
        if self
            .tasks
            .get(node.key)
            .is_none_or(|entry| entry.deadline_tick != node.deadline_tick)
        {
            return Err(TimerError::InvariantViolation);
        }
        self.duration_until_tick(node.deadline_tick).map(Some)
    }

    /// 获取单个基础滴答的时长
    pub fn tick_duration(&self) -> Duration {
        Duration::from_nanos(self.base_tick_nanos)
    }

    /// 获取当前全局滴答计数
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// 获取当前时间轮内活动定时器的总数
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// 检查时间轮是否为空
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// 清空时间轮并将其中的所有任务条目收集输出到 `out`
    pub fn clear(&mut self, out: &mut Vec<T>) {
        for level in &mut self.levels {
            level.clear_slots();
        }
        self.deadline_heap.clear();
        for (_, entry) in self.tasks.drain() {
            out.push(entry.item);
        }
        self.debug_assert_invariants();
    }

    /// 计算给定延迟后对应的目标绝对滴答（向上取整，结合当前累积残差）
    fn deadline_after(&self, delay: Duration) -> Result<u64, TimerError> {
        let delay_ticks = if delay.is_zero() {
            0
        } else {
            let offset = delay.as_nanos() + u128::from(self.remainder_nanos);
            // 向上取整，避免未满一滴答提前到期
            let ticks = offset.div_ceil(u128::from(self.base_tick_nanos));
            ticks.try_into().map_err(|_| TimerError::DelayOverflow)?
        };
        self.current_tick
            .checked_add(delay_ticks)
            .ok_or(TimerError::DelayOverflow)
    }

    /// 根据目标到期滴答与当前滴答的差值，计算其应安放的层级与槽位索引
    fn determine_location(&self, deadline_tick: u64) -> (usize, usize) {
        let delta = deadline_tick.saturating_sub(self.current_tick);
        let mut selected = self.levels.len() - 1;
        // 寻找能容纳 delta 的最低层级
        for (index, level) in self.levels.iter().enumerate() {
            if delta < level.span_ticks {
                selected = index;
                break;
            }
        }
        let level = &self.levels[selected];
        // 根据该层单位步长折算并掩码得到槽位下标
        let slot = ((deadline_tick / level.unit_ticks) as usize) & level.mask;
        (selected, slot)
    }

    /// 将任务节点链接至指定层级与槽位的双向链表尾部
    fn link(
        &mut self,
        key: DefaultKey,
        level_index: usize,
        slot_index: usize,
    ) -> Result<(), TimerError> {
        let old_head = self.levels[level_index].slots[slot_index].head;
        if old_head.is_none() {
            // 当前槽位为空，该节点成为唯一的 head 和 tail
            let slot = &mut self.levels[level_index].slots[slot_index];
            slot.head = Some(key);
            slot.tail = Some(key);
            let entry = self
                .tasks
                .get_mut(key)
                .ok_or(TimerError::InvariantViolation)?;
            entry.level = level_index as u8;
            entry.slot = slot_index as u32;
            entry.prev = None;
            entry.next = None;
            return Ok(());
        }

        // 槽位非空，追加到链表尾部
        let old_tail = self.levels[level_index].slots[slot_index]
            .tail
            .ok_or(TimerError::InvariantViolation)?;
        self.tasks
            .get_mut(old_tail)
            .ok_or(TimerError::InvariantViolation)?
            .next = Some(key);
        let entry = self
            .tasks
            .get_mut(key)
            .ok_or(TimerError::InvariantViolation)?;
        entry.level = level_index as u8;
        entry.slot = slot_index as u32;
        entry.prev = Some(old_tail);
        entry.next = None;
        self.levels[level_index].slots[slot_index].tail = Some(key);
        Ok(())
    }

    /// 从任务当前所在槽位的双向链表中将其摘除
    fn unlink(&mut self, key: DefaultKey) -> Result<(), TimerError> {
        let (level_index, slot_index, prev, next) = {
            let entry = self.tasks.get(key).ok_or(TimerError::StaleTimerId)?;
            (
                usize::from(entry.level),
                entry.slot as usize,
                entry.prev,
                entry.next,
            )
        };
        if level_index >= self.levels.len() || slot_index >= self.levels[level_index].slots.len() {
            return Err(TimerError::InvariantViolation);
        }

        // 修复前驱节点的 next 指针或槽位 head
        match prev {
            Some(prev) => {
                self.tasks
                    .get_mut(prev)
                    .ok_or(TimerError::InvariantViolation)?
                    .next = next;
            }
            None => self.levels[level_index].slots[slot_index].head = next,
        }
        // 修复后继节点的 prev 指针或槽位 tail
        match next {
            Some(next) => {
                self.tasks
                    .get_mut(next)
                    .ok_or(TimerError::InvariantViolation)?
                    .prev = prev;
            }
            None => self.levels[level_index].slots[slot_index].tail = prev,
        }
        let entry = self
            .tasks
            .get_mut(key)
            .ok_or(TimerError::InvariantViolation)?;
        entry.prev = None;
        entry.next = None;
        Ok(())
    }

    /// 处理第 0 层（L0）当前滴答槽位中的任务
    fn process_l0_slot(&mut self, expired: &mut Vec<Expired<T>>) -> Result<(), TimerError> {
        let slot_index = (self.current_tick as usize) & self.levels[0].mask;
        self.process_slot(0, slot_index, expired)
    }

    /// 在当前滴答检查并触发高层级联（Cascade）
    ///
    /// 当当前滴答是更高层单位步长的倍数时，对应高层槽位已转到触发点，需要将其中的任务重新下移分桶
    fn cascade_at_current_tick(&mut self, expired: &mut Vec<Expired<T>>) -> Result<(), TimerError> {
        for level_index in (1..self.levels.len()).rev() {
            if self
                .current_tick
                .is_multiple_of(self.levels[level_index].unit_ticks)
            {
                let level_tick = self.current_tick / self.levels[level_index].unit_ticks;
                let slot = (level_tick as usize) & self.levels[level_index].mask;
                self.process_slot(level_index, slot, expired)?;
            }
        }
        Ok(())
    }

    /// 处理指定层级和槽位的所有节点：已到期的移入 expired，未到期的重新计算位置降级分桶
    fn process_slot(
        &mut self,
        level_index: usize,
        slot_index: usize,
        expired: &mut Vec<Expired<T>>,
    ) -> Result<(), TimerError> {
        // 取出整条链表头
        let mut current = {
            let slot = &mut self.levels[level_index].slots[slot_index];
            let head = slot.head.take();
            slot.tail = None;
            head
        };
        while let Some(key) = current {
            let next = self
                .tasks
                .get(key)
                .ok_or(TimerError::InvariantViolation)?
                .next;
            self.detach_entry(key)?;
            let deadline_tick = self
                .tasks
                .get(key)
                .ok_or(TimerError::InvariantViolation)?
                .deadline_tick;
            if deadline_tick <= self.current_tick {
                // 已到期：从最小堆和任务表中彻底移除，并收集到 expired
                let heap_index = self
                    .tasks
                    .get(key)
                    .ok_or(TimerError::InvariantViolation)?
                    .heap_index;
                self.remove_deadline(key, heap_index)?;
                let entry = self
                    .tasks
                    .remove(key)
                    .ok_or(TimerError::InvariantViolation)?;
                expired.push(Expired {
                    id: TimerId::from_key(key),
                    item: entry.item,
                    deadline_tick,
                });
            } else {
                // 尚未到期：级联降级到更低层级或同层槽位
                let (new_level, new_slot) = self.determine_location(deadline_tick);
                self.link(key, new_level, new_slot)?;
            }
            current = next;
        }
        Ok(())
    }

    /// 清空节点的链表指针
    fn detach_entry(&mut self, key: DefaultKey) -> Result<(), TimerError> {
        let entry = self
            .tasks
            .get_mut(key)
            .ok_or(TimerError::InvariantViolation)?;
        entry.prev = None;
        entry.next = None;
        Ok(())
    }

    /// 快进模式：当跳过大量滴答时，直接清空所有层级槽位并遍历所有任务重新分桶或到期
    fn fast_forward(
        &mut self,
        target_tick: u64,
        expired: &mut Vec<Expired<T>>,
    ) -> Result<(), TimerError> {
        let keys: Vec<DefaultKey> = self.tasks.keys().collect();
        for level in &mut self.levels {
            level.clear_slots();
        }
        self.current_tick = target_tick;
        for key in keys {
            let deadline_tick = self
                .tasks
                .get(key)
                .ok_or(TimerError::InvariantViolation)?
                .deadline_tick;
            if deadline_tick <= target_tick {
                let heap_index = self
                    .tasks
                    .get(key)
                    .ok_or(TimerError::InvariantViolation)?
                    .heap_index;
                self.remove_deadline(key, heap_index)?;
                let entry = self
                    .tasks
                    .remove(key)
                    .ok_or(TimerError::InvariantViolation)?;
                expired.push(Expired {
                    id: TimerId::from_key(key),
                    item: entry.item,
                    deadline_tick,
                });
            } else {
                let (level, slot) = self.determine_location(deadline_tick);
                self.link(key, level, slot)?;
            }
        }
        Ok(())
    }

    /// 向最小堆插入到期时间并保持 entry 的 `heap_index` 同步
    fn insert_deadline(&mut self, key: DefaultKey, deadline_tick: u64) -> Result<(), TimerError> {
        let (tasks, deadline_heap) = (&mut self.tasks, &mut self.deadline_heap);
        deadline_heap.insert(key, deadline_tick, |key, index| {
            tasks
                .get_mut(key)
                .map(|entry| entry.heap_index = index)
                .ok_or(TimerError::InvariantViolation)
        })
    }

    /// 更新最小堆中的节点到期时间
    fn update_deadline(
        &mut self,
        key: DefaultKey,
        heap_index: usize,
        deadline_tick: u64,
    ) -> Result<(), TimerError> {
        let (tasks, deadline_heap) = (&mut self.tasks, &mut self.deadline_heap);
        deadline_heap.update(key, heap_index, deadline_tick, |key, index| {
            tasks
                .get_mut(key)
                .map(|entry| entry.heap_index = index)
                .ok_or(TimerError::InvariantViolation)
        })
    }

    /// 从最小堆中删除节点
    fn remove_deadline(&mut self, key: DefaultKey, heap_index: usize) -> Result<(), TimerError> {
        let (tasks, deadline_heap) = (&mut self.tasks, &mut self.deadline_heap);
        deadline_heap.remove(key, heap_index, |key, index| {
            tasks
                .get_mut(key)
                .map(|entry| entry.heap_index = index)
                .ok_or(TimerError::InvariantViolation)
        })
    }

    /// 计算给定目标滴答距离当前时间的实际剩余 Duration
    fn duration_until_tick(&self, deadline_tick: u64) -> Result<Duration, TimerError> {
        if deadline_tick <= self.current_tick {
            return Ok(Duration::ZERO);
        }
        let ticks = deadline_tick - self.current_tick;
        // 总纳秒 = 滴答数 * base_tick_nanos - 已经累积的残差纳秒
        let nanos = u128::from(ticks)
            .checked_mul(u128::from(self.base_tick_nanos))
            .ok_or(TimerError::DeadlineOverflow)?
            .checked_sub(u128::from(self.remainder_nanos))
            .ok_or(TimerError::DeadlineOverflow)?;
        let seconds = nanos / 1_000_000_000;
        let remainder = nanos % 1_000_000_000;
        let seconds = u64::try_from(seconds).map_err(|_| TimerError::DeadlineOverflow)?;
        Ok(Duration::new(seconds, remainder as u32))
    }

    #[cfg(debug_assertions)]
    fn debug_assert_invariants(&self) {
        self.debug_assert_level_invariants();
        self.debug_assert_deadline_invariants();
    }

    #[cfg(debug_assertions)]
    fn debug_assert_level_invariants(&self) {
        let mut linked = 0usize;
        for (level_index, level) in self.levels.iter().enumerate() {
            for (slot_index, slot) in level.slots.iter().enumerate() {
                let occupied = slot.head.is_some();
                debug_assert_eq!(occupied, slot.tail.is_some());
                let mut key = slot.head;
                let mut prev = None;
                while let Some(current) = key {
                    let Some(entry) = self.tasks.get(current) else {
                        debug_assert!(false, "linked wheel entry is missing");
                        break;
                    };
                    debug_assert_eq!(entry.level, level_index as u8);
                    debug_assert_eq!(entry.slot, slot_index as u32);
                    debug_assert_eq!(entry.prev, prev);
                    if let Some(next) = entry.next {
                        debug_assert_eq!(
                            self.tasks.get(next).and_then(|item| item.prev),
                            Some(current)
                        );
                    } else {
                        debug_assert_eq!(slot.tail, Some(current));
                    }
                    prev = Some(current);
                    key = entry.next;
                    linked += 1;
                }
            }
        }
        debug_assert_eq!(linked, self.tasks.len());
    }

    #[cfg(debug_assertions)]
    fn debug_assert_deadline_invariants(&self) {
        debug_assert_eq!(self.deadline_heap.len(), self.tasks.len());
        for index in 0..self.deadline_heap.len() {
            let Some(node) = self.deadline_heap.node(index) else {
                debug_assert!(false, "deadline heap node is missing");
                continue;
            };
            let Some(entry) = self.tasks.get(node.key) else {
                debug_assert!(false, "deadline heap entry is missing");
                continue;
            };
            debug_assert_eq!(entry.heap_index, index);
            debug_assert_eq!(entry.deadline_tick, node.deadline_tick);
            if index != 0 {
                let parent = (index - 1) / 2;
                let Some(parent_node) = self.deadline_heap.node(parent) else {
                    debug_assert!(false, "deadline heap parent is missing");
                    continue;
                };
                debug_assert!(
                    (parent_node.deadline_tick, parent_node.key.data().as_ffi())
                        <= (node.deadline_tick, node.key.data().as_ffi())
                );
            }
        }
        for (key, entry) in &self.tasks {
            let Some(node) = self.deadline_heap.node(entry.heap_index) else {
                debug_assert!(false, "task points to a missing deadline heap node");
                continue;
            };
            debug_assert_eq!(node.key, key);
            debug_assert_eq!(node.deadline_tick, entry.deadline_tick);
        }
    }

    #[cfg(not(debug_assertions))]
    fn debug_assert_invariants(&self) {}
}


#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};
    use core::time::Duration;

    use crate::{ConfigError, TimerError, WheelConfig};

    use super::{Expired, Wheel};

    fn config(base_tick: u64, slots: &[usize]) -> WheelConfig {
        let mut builder = WheelConfig::builder().base_tick(Duration::from_nanos(base_tick));
        for &slot_count in slots {
            builder = builder.level_slots(slot_count);
        }
        builder.build().expect("test wheel configuration")
    }

    fn expired_items(expired: &[Expired<&'static str>]) -> Vec<&'static str> {
        expired.iter().map(|entry| entry.item).collect()
    }

    #[test]
    fn validates_builder_and_derives_aligned_levels() {
        assert_eq!(
            WheelConfig::builder()
                .base_tick(Duration::ZERO)
                .level_slots(4)
                .build(),
            Err(ConfigError::ZeroTick)
        );
        assert!(matches!(
            WheelConfig::builder().build(),
            Err(ConfigError::InvalidLevelCount { .. })
        ));
        assert!(matches!(
            WheelConfig::builder().level_slots(3).build(),
            Err(ConfigError::InvalidSlotCount { level: 0, .. })
        ));
        assert!(matches!(
            WheelConfig::builder()
                .level_slots(1 << 16)
                .level_slots(1 << 16)
                .level_slots(1 << 16)
                .level_slots(1 << 16)
                .level_slots(2)
                .build(),
            Err(ConfigError::DerivedRangeOverflow { level: 3 })
        ));

        let config = config(10_000_000, &[4, 8, 2]);
        assert_eq!(config.base_tick(), Duration::from_millis(10));
        assert_eq!(config.level_count(), 3);
        assert_eq!(config.total_slots(), 14);
    }

    #[test]
    fn rounds_delays_up_without_early_expiration() {
        let mut wheel = Wheel::new(config(10_000_000, &[16, 4]));
        for (item, delay) in [
            ("1ms", 1),
            ("9ms", 9),
            ("10ms", 10),
            ("19ms", 19),
            ("20ms", 20),
        ] {
            wheel
                .insert(item, Duration::from_millis(delay))
                .expect("timer insertion");
        }

        let mut expired = Vec::new();
        wheel
            .advance_by(Duration::from_millis(10), &mut expired)
            .expect("wheel advance");
        assert_eq!(expired_items(&expired), vec!["1ms", "9ms", "10ms"]);
        expired.clear();
        wheel
            .advance_by(Duration::from_millis(9), &mut expired)
            .expect("wheel advance");
        assert!(expired.is_empty());
        wheel
            .advance_by(Duration::from_millis(1), &mut expired)
            .expect("wheel advance");
        assert_eq!(expired_items(&expired), vec!["19ms", "20ms"]);
    }

    #[test]
    fn accumulates_sub_tick_time_and_expires_zero_delay() {
        let mut wheel = Wheel::new(config(10_000_000, &[16]));
        wheel
            .insert("delayed", Duration::from_millis(10))
            .expect("timer insertion");
        let mut expired = Vec::new();
        for _ in 0..9 {
            wheel
                .advance_by(Duration::from_millis(1), &mut expired)
                .expect("wheel advance");
        }
        assert!(expired.is_empty());
        wheel
            .advance_by(Duration::from_millis(1), &mut expired)
            .expect("wheel advance");
        assert_eq!(expired_items(&expired), vec!["delayed"]);

        wheel
            .insert("immediate", Duration::ZERO)
            .expect("timer insertion");
        expired.clear();
        wheel
            .advance_by(Duration::ZERO, &mut expired)
            .expect("zero advance");
        assert_eq!(expired_items(&expired), vec!["immediate"]);
    }

    #[test]
    fn cancel_and_reschedule_are_immediate_and_generation_safe() {
        let mut wheel = Wheel::new(config(10_000_000, &[4, 4, 4]));
        let canceled = wheel
            .insert("canceled", Duration::from_secs(10))
            .expect("timer insertion");
        assert_eq!(wheel.len(), 1);
        assert_eq!(wheel.cancel(canceled), Some("canceled"));
        assert_eq!(wheel.len(), 0);
        assert!(wheel.is_empty());
        assert_eq!(wheel.next_deadline(), Ok(None));
        assert_eq!(wheel.cancel(canceled), None);
        assert_eq!(
            wheel.reschedule(canceled, Duration::MAX),
            Err(TimerError::StaleTimerId)
        );

        let reused = wheel
            .insert("reused", Duration::from_secs(10))
            .expect("timer insertion");
        assert_eq!(wheel.cancel(canceled), None);
        assert_eq!(wheel.len(), 1);
        wheel
            .reschedule(reused, Duration::from_millis(10))
            .expect("timer reschedule");
        let mut expired = Vec::new();
        wheel
            .advance_by(Duration::from_millis(10), &mut expired)
            .expect("wheel advance");
        assert_eq!(expired_items(&expired), vec!["reused"]);
        assert_eq!(
            wheel.reschedule(reused, Duration::ZERO),
            Err(TimerError::StaleTimerId)
        );
    }

    #[test]
    fn cascades_multiple_levels_and_handles_rounds() {
        let mut wheel = Wheel::new(config(10_000_000, &[4, 4, 4]));
        wheel
            .insert("level-one", Duration::from_millis(150))
            .expect("timer insertion");
        wheel
            .insert("level-two-round", Duration::from_millis(700))
            .expect("timer insertion");
        let mut expired = Vec::new();
        wheel
            .advance_by(Duration::from_millis(149), &mut expired)
            .expect("wheel advance");
        assert!(expired.is_empty());
        wheel
            .advance_by(Duration::from_millis(1), &mut expired)
            .expect("wheel advance");
        assert_eq!(expired_items(&expired), vec!["level-one"]);
        expired.clear();
        wheel
            .advance_by(Duration::from_millis(549), &mut expired)
            .expect("wheel advance");
        assert!(expired.is_empty());
        wheel
            .advance_by(Duration::from_millis(1), &mut expired)
            .expect("wheel advance");
        assert_eq!(expired_items(&expired), vec!["level-two-round"]);
    }

    #[test]
    fn fast_forwards_large_jumps_and_keeps_future_timers() {
        let mut wheel = Wheel::new(config(10_000_000, &[4, 4, 4]));
        wheel
            .insert("expired", Duration::from_secs(1))
            .expect("timer insertion");
        wheel
            .insert("future", Duration::from_secs(1_000))
            .expect("timer insertion");
        let mut expired = Vec::new();
        let report = wheel
            .advance_by(Duration::from_secs(100), &mut expired)
            .expect("wheel advance");
        assert!(report.fast_forwarded);
        assert_eq!(expired_items(&expired), vec!["expired"]);
        assert_eq!(wheel.len(), 1);
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_secs(900))));
    }

    #[test]
    fn next_deadline_returns_the_global_earliest_deadline() {
        let mut wheel = Wheel::new(config(10_000_000, &[4, 4]));
        wheel
            .insert("upper", Duration::from_millis(50))
            .expect("timer insertion");
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(50))));
        let mut expired = Vec::new();
        wheel
            .advance_by(Duration::from_millis(40), &mut expired)
            .expect("wheel advance");
        assert!(expired.is_empty());
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(10))));
        wheel
            .advance_by(Duration::ZERO, &mut expired)
            .expect("zero advance");
        assert!(expired.is_empty());
        wheel
            .advance_by(Duration::from_millis(10), &mut expired)
            .expect("wheel advance");
        assert_eq!(expired_items(&expired), vec!["upper"]);
    }

    #[test]
    fn next_deadline_subtracts_sub_tick_remainder() {
        let mut wheel = Wheel::new(config(10_000_000, &[4]));
        wheel
            .insert("deadline", Duration::from_millis(20))
            .expect("timer insertion");
        let mut expired = Vec::new();
        wheel
            .advance_by(Duration::from_millis(5), &mut expired)
            .expect("wheel advance");
        assert!(expired.is_empty());
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(15))));
        wheel
            .advance_by(Duration::from_millis(1), &mut expired)
            .expect("wheel advance");
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(14))));
    }

    #[test]
    fn next_deadline_switches_root_after_insert_reschedule_and_cancel() {
        let mut wheel = Wheel::new(config(10_000_000, &[4, 4, 4]));
        let later = wheel
            .insert("later", Duration::from_millis(30))
            .expect("timer insertion");
        let earliest = wheel
            .insert("earliest", Duration::from_millis(10))
            .expect("timer insertion");
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(10))));

        wheel
            .reschedule(earliest, Duration::from_millis(40))
            .expect("timer reschedule");
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(30))));

        let newest = wheel
            .insert("newest", Duration::from_millis(10))
            .expect("timer insertion");
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(10))));
        assert_eq!(wheel.cancel(newest), Some("newest"));
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(30))));
        assert_eq!(wheel.cancel(later), Some("later"));
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::from_millis(40))));
    }

    #[test]
    fn next_deadline_returns_zero_without_expiring_timer() {
        let mut wheel = Wheel::new(config(10_000_000, &[4]));
        wheel
            .insert("immediate", Duration::ZERO)
            .expect("timer insertion");
        assert_eq!(wheel.next_deadline(), Ok(Some(Duration::ZERO)));
        let mut expired = Vec::new();
        assert_eq!(wheel.len(), 1);
        wheel
            .advance_by(Duration::ZERO, &mut expired)
            .expect("zero advance");
        assert_eq!(expired_items(&expired), vec!["immediate"]);
    }

    #[test]
    fn next_deadline_reports_duration_overflow_without_mutating_state() {
        let mut wheel = Wheel::new(config(u64::MAX, &[2]));
        wheel
            .insert("overflow", Duration::new(u64::MAX, 999_999_999))
            .expect("timer insertion");
        assert_eq!(wheel.next_deadline(), Err(TimerError::DeadlineOverflow));
        assert_eq!(wheel.len(), 1);
        assert!(!wheel.is_empty());
    }

    #[test]
    fn advance_overflow_does_not_change_clock() {
        let mut wheel: Wheel<()> = Wheel::new(config(1, &[4]));
        let mut expired = Vec::new();
        wheel
            .advance_by(Duration::from_nanos(u64::MAX - 1), &mut expired)
            .expect("wheel advance");
        assert_eq!(wheel.current_tick(), u64::MAX - 1);
        wheel
            .advance_by(Duration::from_nanos(1), &mut expired)
            .expect("wheel may advance to the maximum tick");
        assert_eq!(
            wheel.advance_by(Duration::from_nanos(1), &mut expired),
            Err(TimerError::ClockOverflow)
        );
        assert_eq!(wheel.current_tick(), u64::MAX);
    }
}
