use core::time::Duration;

use crate::{error::ProtocolError, packet::PacketNumber};

pub const MAX_ACK_RANGES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    pub start: PacketNumber,
    pub end: PacketNumber,
}

impl AckRange {
    pub fn new(start: PacketNumber, end: PacketNumber) -> Result<Self, ProtocolError> {
        if start > end {
            return Err(ProtocolError::InvalidAckRanges);
        }
        Ok(Self { start, end })
    }

    pub fn contains(self, packet_number: PacketNumber) -> bool {
        self.start <= packet_number && packet_number <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRanges(Vec<AckRange>);

impl AckRanges {
    pub fn new(mut ranges: Vec<AckRange>) -> Result<Self, ProtocolError> {
        if ranges.is_empty() {
            return Err(ProtocolError::InvalidAckRanges);
        }
        ranges.sort_by(|left, right| {
            right
                .end
                .cmp(&left.end)
                .then_with(|| right.start.cmp(&left.start))
        });
        Self::from_descending(ranges)
    }

    pub fn single(packet_number: PacketNumber) -> Self {
        Self(vec![AckRange {
            start: packet_number,
            end: packet_number,
        }])
    }

    pub fn as_slice(&self) -> &[AckRange] {
        &self.0
    }

    pub fn largest(&self) -> PacketNumber {
        self.0[0].end
    }

    pub fn contains(&self, packet_number: PacketNumber) -> bool {
        self.0.iter().any(|range| range.contains(packet_number))
    }

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
        for range in &ranges {
            if range.start > range.end {
                return Err(ProtocolError::InvalidAckRanges);
            }
            if let Some(previous) = previous {
                let overlaps = range.end >= previous.start;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame {
    pub largest: PacketNumber,
    pub ack_delay: Duration,
    pub ranges: AckRanges,
}

impl AckFrame {
    pub fn new(ack_delay: Duration, ranges: AckRanges) -> Result<Self, ProtocolError> {
        let frame = Self {
            largest: ranges.largest(),
            ack_delay,
            ranges,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.ranges.as_slice().is_empty() || self.ranges.largest() != self.largest {
            return Err(ProtocolError::InvalidAckRanges);
        }
        if self.ack_delay.as_micros() > u128::from(u64::MAX) {
            return Err(ProtocolError::InvalidValue { field: "ack_delay" });
        }
        Ok(())
    }

    pub(crate) fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        self.validate()?;
        crate::varint::encode(self.largest.raw(), output)?;
        crate::varint::encode(self.ack_delay.as_micros() as u64, output)?;
        self.ranges.encode_into(output)
    }

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
