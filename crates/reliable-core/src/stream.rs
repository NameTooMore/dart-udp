use udp_protocol::StreamId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Open,
    Reset { error_code: u32 },
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamInfo {
    pub stream_id: StreamId,
    pub state: StreamState,
    pub bidirectional: bool,
    pub send_offset: u64,
    pub receive_offset: u64,
    pub receive_window: u64,
    pub buffered_bytes: usize,
}
