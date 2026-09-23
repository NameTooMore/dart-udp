use core::time::Duration;

use crate::{error::ProtocolError, packet::PacketNumber};

/// 单个 ACK 帧中最多允许携带的确认区间段数
pub const MAX_ACK_RANGES: usize = 32;

/// 单个确认区间 [start, end]（包含两端序号）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    pub start: PacketNumber,
    pub end: PacketNumber,
}

impl AckRange {
    /// 构造确认区间，要求 start <= end
    pub fn new(start: PacketNumber, end: PacketNumber) -> Result<Self, ProtocolError> {
        if start > end {
            return Err(ProtocolError::InvalidAckRanges);
        }
        Ok(Self { start, end })
    }

    /// 检查指定数据包序号是否落在该区间内
    pub fn contains(self, packet_number: PacketNumber) -> bool {
        self.start <= packet_number && packet_number <= self.end
    }
}

/// 确认区间集合，按包号从大到小严格降序且规范化排列（无重叠、无相邻）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRanges(Vec<AckRange>);

impl AckRanges {
    /// 从任意区间列表构造，内部自动执行降序排序与重叠/相邻合并校验
    pub fn new(mut ranges: Vec<AckRange>) -> Result<Self, ProtocolError> {
        if ranges.is_empty() {
            return Err(ProtocolError::InvalidAckRanges);
        }
        // 按 end 降序排序，若 end 相等按 start 降序
        ranges.sort_by(|left, right| {
            right
                .end
                .cmp(&left.end)
                .then_with(|| right.start.cmp(&left.start))
        });
        Self::from_descending(ranges)
    }

    /// 构造仅确认单个包号的区间集合
    pub fn single(packet_number: PacketNumber) -> Self {
        Self(vec![AckRange {
            start: packet_number,
            end: packet_number,
        }])
    }

    /// 获取底层区间切片引用
    pub fn as_slice(&self) -> &[AckRange] {
        &self.0
    }

    /// 获取已确认的最大包号（集合首个区间的 end）
    pub fn largest(&self) -> PacketNumber {
        self.0[0].end
    }

    /// 检查是否确认了指定包号
    pub fn contains(&self, packet_number: PacketNumber) -> bool {
        self.0.iter().any(|range| range.contains(packet_number))
    }

    /// 校验并基于已降序排列的区间列表构造集合
    pub(crate) fn from_descending(ranges: Vec<AckRange>) -> Result<Self, ProtocolError> {
        if ranges.is_empty() || ranges.len() > MAX_ACK_RANGES {
            return Err(if ranges.is_empty() {
                ProtocolError::InvalidAckRanges
            } else {
                ProtocolError::AckRangeCountExceeded {
                    maximum: MAX_ACK_RANGES,
                }
            });
        }
        let mut previous: Option<&AckRange> = None;
        // 逐个校验区间合法性及与前一区间的间隔
        for range in &ranges {
            if range.start > range.end {
                return Err(ProtocolError::InvalidAckRanges);
            }
            if let Some(previous) = previous {
                // 检查是否与较大区间重叠
                let overlaps = range.end >= previous.start;
                // 检查是否与较大区间紧邻（紧邻应合并，不允许作为独立区间传输）
                let adjacent = previous.start != PacketNumber::new(0)
                    && range.end.saturating_add(1) >= previous.start;
                if overlaps || adjacent {
                    return Err(ProtocolError::InvalidAckRanges);
                }
            }
            previous = Some(range);
        }
        Ok(Self(ranges))
    }

    /// 将区间列表编码写入输出缓冲区（数量 + 逐个 start/end 变长整数）
    pub(crate) fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        if self.0.len() > MAX_ACK_RANGES {
            return Err(ProtocolError::AckRangeCountExceeded {
                maximum: MAX_ACK_RANGES,
            });
        }
        crate::varint::encode(self.0.len() as u64, output)?;
        for range in &self.0 {
            crate::varint::encode(range.start.raw(), output)?;
            crate::varint::encode(range.end.raw(), output)?;
        }
        Ok(())
    }

    /// 从字节流解码区间集合
    pub(crate) fn decode_from(input: &[u8], offset: &mut usize) -> Result<Self, ProtocolError> {
        let count = crate::varint::decode(input, offset)?;
        let count = usize::try_from(count).map_err(|_| ProtocolError::AckRangeCountExceeded {
            maximum: MAX_ACK_RANGES,
        })?;
        if count == 0 {
            return Err(ProtocolError::InvalidAckRanges);
        }
        if count > MAX_ACK_RANGES {
            return Err(ProtocolError::AckRangeCountExceeded {
                maximum: MAX_ACK_RANGES,
            });
        }
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            let start = PacketNumber::new(crate::varint::decode(input, offset)?);
            let end = PacketNumber::new(crate::varint::decode(input, offset)?);
            ranges.push(AckRange { start, end });
        }
        Self::from_descending(ranges)
    }
}

/// 确认应答帧（AckFrame）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame {
    /// 确认的最大数据包序号
    pub largest: PacketNumber,
    /// 接收到 largest 到发送该 ACK 的延迟时长（微秒级）
    pub ack_delay: Duration,
    /// 所有确认区间段
    pub ranges: AckRanges,
}

impl AckFrame {
    /// 构造新的确认帧并进行一致性校验
    pub fn new(ack_delay: Duration, ranges: AckRanges) -> Result<Self, ProtocolError> {
        let frame = Self {
            largest: ranges.largest(),
            ack_delay,
            ranges,
        };
        frame.validate()?;
        Ok(frame)
    }

    /// 校验帧属性的一致性（区间非空、largest 与首区间一致、延迟时间合法）
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.ranges.as_slice().is_empty() || self.ranges.largest() != self.largest {
            return Err(ProtocolError::InvalidAckRanges);
        }
        if self.ack_delay.as_micros() > u128::from(u64::MAX) {
            return Err(ProtocolError::InvalidValue { field: "ack_delay" });
        }
        Ok(())
    }

    /// 编码 ACK 帧至输出缓冲区（largest + ack_delay 微秒数 + ranges）
    pub(crate) fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        self.validate()?;
        crate::varint::encode(self.largest.raw(), output)?;
        crate::varint::encode(self.ack_delay.as_micros() as u64, output)?;
        self.ranges.encode_into(output)
    }

    /// 从字节流解码 ACK 帧
    pub(crate) fn decode_from(input: &[u8], offset: &mut usize) -> Result<Self, ProtocolError> {
        let largest = PacketNumber::new(crate::varint::decode(input, offset)?);
        let delay_micros = crate::varint::decode(input, offset)?;
        let ranges = AckRanges::decode_from(input, offset)?;
        let frame = Self {
            largest,
            ack_delay: Duration::from_micros(delay_micros),
            ranges,
        };
        frame.validate()?;
        Ok(frame)
    }
}


#[cfg(test)]
mod tests {
    use super::{AckRange, AckRanges};
    use crate::PacketNumber;

    #[test]
    fn sorts_ranges_from_largest_to_smallest() {
        let ranges = AckRanges::new(vec![
            AckRange::new(PacketNumber::new(1), PacketNumber::new(2)).unwrap(),
            AckRange::new(PacketNumber::new(10), PacketNumber::new(12)).unwrap(),
        ])
        .unwrap();
        assert_eq!(ranges.largest(), PacketNumber::new(12));
        assert_eq!(ranges.as_slice()[1].start, PacketNumber::new(1));
    }

    #[test]
    fn rejects_overlapping_or_adjacent_wire_ranges() {
        let ranges = vec![
            AckRange::new(PacketNumber::new(10), PacketNumber::new(12)).unwrap(),
            AckRange::new(PacketNumber::new(3), PacketNumber::new(10)).unwrap(),
        ];
        assert!(super::AckRanges::from_descending(ranges).is_err());
    }
}
