use alloc::vec::Vec;
use slotmap::{DefaultKey, Key};

use crate::error::TimerError;

/// 到期时间最小堆节点，记录任务 key 及其绝对到期滴答
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeadlineNode {
    pub(crate) key: DefaultKey,
    pub(crate) deadline_tick: u64,
}

/// 维护全局最早到期时间的二叉最小堆
///
/// 配合时间轮使用，使 `next_deadline()` 能够以 O(1) 获取全局最近到期时间，
/// 并通过回调闭包实时同步元素在堆中的下标（`heap_index`），以支持 O(log N) 的任意删除与重新调度。
pub(crate) struct DeadlineHeap {
    nodes: Vec<DeadlineNode>,
}

impl DeadlineHeap {
    /// 创建空的到期堆
    pub(crate) fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    /// 查看堆顶元素（最早到期任务），时间复杂度 O(1)
    pub(crate) fn peek(&self) -> Option<DeadlineNode> {
        self.nodes.first().copied()
    }

    #[cfg(debug_assertions)]
    pub(crate) fn node(&self, index: usize) -> Option<DeadlineNode> {
        self.nodes.get(index).copied()
    }

    /// 向堆中插入新任务，并通过 `set_index` 回调同步其在 slotmap entry 中的堆索引
    pub(crate) fn insert<F>(
        &mut self,
        key: DefaultKey,
        deadline_tick: u64,
        mut set_index: F,
    ) -> Result<(), TimerError>
    where
        F: FnMut(DefaultKey, usize) -> Result<(), TimerError>,
    {
        let index = self.nodes.len();
        self.nodes.push(DeadlineNode { key, deadline_tick });
        // 先记录初始末尾下标，失败则回滚弹出
        if let Err(error) = set_index(key, index) {
            self.nodes.pop();
            return Err(error);
        }
        // 执行向上调整以维持最小堆性质
        self.sift_up(index, &mut set_index)
    }

    /// 更新指定任务的到期时间并调整堆结构
    pub(crate) fn update<F>(
        &mut self,
        key: DefaultKey,
        index: usize,
        deadline_tick: u64,
        mut set_index: F,
    ) -> Result<(), TimerError>
    where
        F: FnMut(DefaultKey, usize) -> Result<(), TimerError>,
    {
        let node = self
            .nodes
            .get_mut(index)
            .ok_or(TimerError::InvariantViolation)?;
        if node.key != key {
            return Err(TimerError::InvariantViolation);
        }
        node.deadline_tick = deadline_tick;

        // 根据新到期时间与父节点比较，决定向上或向下调整
        if index != 0 && self.less(index, (index - 1) / 2) {
            self.sift_up(index, &mut set_index)
        } else {
            self.sift_down(index, &mut set_index)
        }
    }

    /// 从堆中移除指定下标的任务（Swap-Remove 策略）
    pub(crate) fn remove<F>(
        &mut self,
        key: DefaultKey,
        index: usize,
        mut set_index: F,
    ) -> Result<(), TimerError>
    where
        F: FnMut(DefaultKey, usize) -> Result<(), TimerError>,
    {
        if index >= self.nodes.len() || self.nodes[index].key != key {
            return Err(TimerError::InvariantViolation);
        }

        // 将末尾节点移到删除位置
        let last = self.nodes.pop().ok_or(TimerError::InvariantViolation)?;
        if index == self.nodes.len() {
            // 正好是末尾元素，无需移动和调整
            return Ok(());
        }

        self.nodes[index] = last;
        set_index(last.key, index)?;
        // 恢复被替换位置的堆性质
        if index != 0 && self.less(index, (index - 1) / 2) {
            self.sift_up(index, &mut set_index)
        } else {
            self.sift_down(index, &mut set_index)
        }
    }

    /// 清空堆内所有节点
    pub(crate) fn clear(&mut self) {
        self.nodes.clear();
    }

    /// 最小堆向上调整（Sift Up）
    fn sift_up<F>(&mut self, mut index: usize, set_index: &mut F) -> Result<(), TimerError>
    where
        F: FnMut(DefaultKey, usize) -> Result<(), TimerError>,
    {
        while index != 0 {
            let parent = (index - 1) / 2;
            if !self.less(index, parent) {
                break;
            }
            self.swap_nodes(index, parent, set_index)?;
            index = parent;
        }
        Ok(())
    }

    /// 最小堆向下调整（Sift Down）
    fn sift_down<F>(&mut self, mut index: usize, set_index: &mut F) -> Result<(), TimerError>
    where
        F: FnMut(DefaultKey, usize) -> Result<(), TimerError>,
    {
        loop {
            let left = index * 2 + 1;
            if left >= self.nodes.len() {
                break;
            }
            let right = left + 1;
            // 选取较小的子节点比较
            let child = if right < self.nodes.len() && self.less(right, left) {
                right
            } else {
                left
            };
            if !self.less(child, index) {
                break;
            }
            self.swap_nodes(index, child, set_index)?;
            index = child;
        }
        Ok(())
    }

    /// 交换两节点位置并同步更新对应条目的 `heap_index`
    fn swap_nodes<F>(
        &mut self,
        left: usize,
        right: usize,
        set_index: &mut F,
    ) -> Result<(), TimerError>
    where
        F: FnMut(DefaultKey, usize) -> Result<(), TimerError>,
    {
        self.nodes.swap(left, right);
        set_index(self.nodes[left].key, left)?;
        set_index(self.nodes[right].key, right)?;
        Ok(())
    }

    /// 比较两节点优先级（以 deadline_tick 为主，key 为辅保证确定性全序）
    fn less(&self, left: usize, right: usize) -> bool {
        let left = self.nodes[left];
        let right = self.nodes[right];
        (left.deadline_tick, left.key.data().as_ffi())
            < (right.deadline_tick, right.key.data().as_ffi())
    }
}

