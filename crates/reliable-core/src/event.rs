use core::time::Duration;

use udp_protocol::{Packet, StreamId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreEvent {
    Datagram(Packet),
    TimePassed(Duration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreOutput {
    Send(Packet),
    StreamOpened(StreamId),
    StreamReadable(StreamId),
    StreamFinished(StreamId),
    StreamReset {
        stream_id: StreamId,
        error_code: u32,
    },
    ConnectionStateChanged(crate::ConnectionState),
    ConnectionClosed {
        error_code: u32,
    },
}
