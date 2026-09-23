use core::time::Duration;

use time_wheel::TimerId;
use udp_protocol::PacketNumber;

use crate::send::QueuedFrame;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SentPacket {
    packet_number: PacketNumber,
    sent_at: Duration,
    encoded_len: usize,
    frames: Vec<QueuedFrame>,
    retransmit_count: u32,
    timer_id: TimerId,
    generation: u32,
}

impl SentPacket {
    pub(crate) fn new(
        packet_number: PacketNumber,
        sent_at: Duration,
        encoded_len: usize,
        frames: Vec<QueuedFrame>,
        retransmit_count: u32,
        timer_id: TimerId,
        generation: u32,
    ) -> Self {
        Self {
            packet_number,
            sent_at,
            encoded_len,
            frames,
            retransmit_count,
            timer_id,
            generation,
        }
    }

    pub(crate) const fn generation(&self) -> u32 {
        self.generation
    }

    pub(crate) const fn sent_at(&self) -> Duration {
        self.sent_at
    }

    pub(crate) const fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    pub(crate) const fn timer_id(&self) -> TimerId {
        self.timer_id
    }

    pub(crate) const fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    pub(crate) fn into_parts(self) -> (PacketNumber, Vec<QueuedFrame>, u32) {
        (self.packet_number, self.frames, self.retransmit_count)
    }
}
