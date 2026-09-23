use udp_protocol::PacketNumber;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerEvent {
    HandshakeTimeout,
    Retransmit {
        packet_number: PacketNumber,
        generation: u32,
    },
    AckDelay,
    Keepalive,
    IdleTimeout,
    CloseTimeout,
}
