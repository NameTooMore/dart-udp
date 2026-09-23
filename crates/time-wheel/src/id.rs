use slotmap::{DefaultKey, Key};

/// 定时器句柄，用于唯一定位并追踪时间轮中的任务
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(DefaultKey);

impl TimerId {
    /// 从内部 slotmap 键构造 TimerId
    pub(crate) fn from_key(key: DefaultKey) -> Self {
        Self(key)
    }

    /// 获取底层的 slotmap 键
    pub(crate) fn key(self) -> DefaultKey {
        self.0
    }

    /// 获取底层原始的 64 位整数表示（便于跨 FFI 或日志记录）
    pub fn raw(self) -> u64 {
        self.0.data().as_ffi()
    }
}

