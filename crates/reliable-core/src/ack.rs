use core::time::Duration;

use udp_protocol::{AckFrame, AckRange, AckRanges, PacketNumber, ProtocolError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceivedPackets {
    ranges: Vec<AckRange>,
    largest_received_at: Option<Duration>,
}

impl ReceivedPackets {
    pub(crate) const fn new() -> Self {
        Self {
            ranges: Vec::new(),
            largest_received_at: None,
        }
    }

    pub(crate) fn record(&mut self, packet_number: PacketNumber, now: Duration) -> bool {
        if self
            .ranges
            .iter()
            .any(|range| range.contains(packet_number))
        {
            return false;
        }

        self.ranges.push(AckRange {
            start: packet_number,
            end: packet_number,
        });
        self.ranges.sort_by(|left, right| {
            right
                .end
                .cmp(&left.end)
                .then_with(|| right.start.cmp(&left.start))
        });
        self.merge_adjacent();
        if self
            .ranges
            .first()
            .is_some_and(|range| range.end == packet_number)
        {
            self.largest_received_at = Some(now);
        }
        if self.ranges.len() > udp_protocol::MAX_ACK_RANGES {
            self.ranges.truncate(udp_protocol::MAX_ACK_RANGES);
        }
        true
    }

    pub(crate) fn largest(&self) -> Option<PacketNumber> {
        self.ranges.first().map(|range| range.end)
    }

    pub(crate) fn frame(
        &self,
        now: Duration,
        ack_delay: Duration,
    ) -> Result<Option<AckFrame>, ProtocolError> {
        let Some(_largest) = self.largest() else {
            return Ok(None);
        };
        let delay = self
            .largest_received_at
            .map(|received_at| now.saturating_sub(received_at).min(ack_delay))
            .unwrap_or(Duration::ZERO);
        Ok(Some(AckFrame::new(
            delay,
            AckRanges::new(self.ranges.clone())?,
        )?))
    }

    fn merge_adjacent(&mut self) {
        let mut merged: Vec<AckRange> = Vec::with_capacity(self.ranges.len());
        for range in self.ranges.drain(..) {
            if let Some(previous) = merged.last_mut()
                && range.end.saturating_add(1) >= previous.start
            {
                previous.start = previous.start.min(range.start);
                previous.end = previous.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        self.ranges = merged;
    }

    #[cfg(test)]
    pub(crate) fn ranges(&self) -> &[AckRange] {
        &self.ranges
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use udp_protocol::PacketNumber;

    use super::ReceivedPackets;

    #[test]
    fn records_out_of_order_packets_as_merged_ranges() {
        let mut received = ReceivedPackets::new();
        assert!(received.record(PacketNumber::new(5), Duration::ZERO));
        assert!(received.record(PacketNumber::new(3), Duration::from_millis(1)));
        assert!(received.record(PacketNumber::new(4), Duration::from_millis(2)));
        assert!(!received.record(PacketNumber::new(4), Duration::from_millis(3)));
        assert_eq!(received.ranges()[0].start.raw(), 3);
        assert_eq!(received.ranges()[0].end.raw(), 5);
    }
}
