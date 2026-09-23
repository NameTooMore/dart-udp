use alloc::vec::Vec;
use slotmap::DefaultKey;

/// 时间轮槽位，维护双向链表的头尾指针（指向 slotmap 中的 key）
pub(crate) struct Slot {
    /// 槽位链表头节点
    pub(crate) head: Option<DefaultKey>,
    /// 槽位链表尾节点
    pub(crate) tail: Option<DefaultKey>,
}

impl Slot {
    /// 创建空槽位
    pub(crate) fn empty() -> Self {
        Self {
            head: None,
            tail: None,
        }
    }
}

/// 时间轮单个层级，管理属于该层级的多个槽位
pub(crate) struct Level {
    /// 单个槽位覆盖的时间滴答数（步长）
    pub(crate) unit_ticks: u64,
    /// 整个层级覆盖的总时间滴答数（unit_ticks * slot_count）
    pub(crate) span_ticks: u64,
    /// 槽位索引掩码（要求 slot_count 为 2 的幂，mask = slot_count - 1）
    pub(crate) mask: usize,
    /// 槽位数组
    pub(crate) slots: Vec<Slot>,
}

impl Level {
    /// 创建新的层级并初始化各槽位
    pub(crate) fn new(unit_ticks: u64, span_ticks: u64, slot_count: usize, mask: usize) -> Self {
        Self {
            unit_ticks,
            span_ticks,
            mask,
            slots: (0..slot_count).map(|_| Slot::empty()).collect(),
        }
    }

    /// 清空该层级的所有槽位指针
    pub(crate) fn clear_slots(&mut self) {
        for slot in &mut self.slots {
            slot.head = None;
            slot.tail = None;
        }
    }
}

