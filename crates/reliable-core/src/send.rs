use std::collections::VecDeque;

use udp_protocol::{Frame, StreamData, StreamId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueuedFrame {
    frame: Frame,
    retransmit_count: u32,
}

impl QueuedFrame {
    pub(crate) const fn new(frame: Frame) -> Self {
        Self {
            frame,
            retransmit_count: 0,
        }
    }

    pub(crate) const fn with_count(frame: Frame, retransmit_count: u32) -> Self {
        Self {
            frame,
            retransmit_count,
        }
    }

    pub(crate) fn stream_data(
        stream_id: StreamId,
        offset: u64,
        fin: bool,
        data: Vec<u8>,
        retransmit_count: u32,
    ) -> Self {
        Self {
            frame: Frame::StreamData(StreamData {
                stream_id,
                offset,
                fin,
                data,
            }),
            retransmit_count,
        }
    }

    pub(crate) const fn frame(&self) -> &Frame {
        &self.frame
    }

    pub(crate) const fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    pub(crate) fn into_parts(self) -> (Frame, u32) {
        (self.frame, self.retransmit_count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingData {
    offset: u64,
    data: Vec<u8>,
    fin: bool,
    retransmit_count: u32,
}

impl PendingData {
    pub(crate) const fn offset(&self) -> u64 {
        self.offset
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) const fn fin(&self) -> bool {
        self.fin
    }

    pub(crate) const fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SendStream {
    stream_id: StreamId,
    max_offset: u64,
    next_offset: u64,
    queued_bytes: usize,
    fin_requested: bool,
    fin_sent: bool,
    queue: VecDeque<PendingData>,
}

impl SendStream {
    pub(crate) fn has_pending_data(&self) -> bool {
        !self.queue.is_empty()
    }
    pub(crate) fn new(stream_id: StreamId, max_offset: u64) -> Self {
        Self {
            stream_id,
            max_offset,
            next_offset: 0,
            queued_bytes: 0,
            fin_requested: false,
            fin_sent: false,
            queue: VecDeque::new(),
        }
    }

    pub(crate) const fn max_offset(&self) -> u64 {
        self.max_offset
    }

    pub(crate) const fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub(crate) fn write(
        &mut self,
        data: &[u8],
        fin: bool,
        max_buffer: usize,
        max_chunk: usize,
    ) -> Result<usize, crate::CoreError> {
        if self.fin_requested || self.fin_sent {
            return Err(crate::CoreError::InvalidState {
                operation: "write after FIN",
            });
        }
        let available = max_buffer.saturating_sub(self.queued_bytes);
        let accepted = data.len().min(available);
        if accepted != data.len() {
            return Err(crate::CoreError::SendBufferFull);
        }
        let chunk_size = max_chunk.max(1);
        let end = self
            .next_offset
            .checked_add(data.len() as u64)
            .ok_or(crate::CoreError::InvalidOffset)?;
        if end > self.max_offset {
            return Err(crate::CoreError::FlowControlViolation {
                stream_id: Some(self.stream_id),
            });
        }
        let mut offset = self.next_offset;
        for chunk in data.chunks(chunk_size) {
            let chunk_end = offset
                .checked_add(chunk.len() as u64)
                .ok_or(crate::CoreError::InvalidOffset)?;
            self.queue.push_back(PendingData {
                offset,
                data: chunk.to_vec(),
                fin: false,
                retransmit_count: 0,
            });
            offset = chunk_end;
        }
        self.next_offset = offset;
        self.queued_bytes = self.queued_bytes.saturating_add(accepted);
        if fin {
            self.fin_requested = true;
            if data.is_empty() {
                self.queue.push_back(PendingData {
                    offset,
                    data: Vec::new(),
                    fin: true,
                    retransmit_count: 0,
                });
            } else if let Some(last) = self.queue.back_mut() {
                last.fin = true;
            }
        }
        Ok(accepted)
    }

    pub(crate) fn pop_sendable(&mut self) -> Option<PendingData> {
        let item = self.queue.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(item.data.len());
        if item.fin {
            self.fin_sent = true;
        }
        Some(item)
    }

    pub(crate) fn front_sendable(&self) -> Option<&PendingData> {
        self.queue.front()
    }

    pub(crate) fn requeue(&mut self, frame: &StreamData, retransmit_count: u32) {
        self.queue.push_front(PendingData {
            offset: frame.offset,
            data: frame.data.clone(),
            fin: frame.fin,
            retransmit_count,
        });
        self.queued_bytes = self.queued_bytes.saturating_add(frame.data.len());
        if frame.fin {
            self.fin_sent = false;
        }
    }

    pub(crate) fn update_window(&mut self, max_offset: u64) {
        self.max_offset = self.max_offset.max(max_offset);
    }
}
