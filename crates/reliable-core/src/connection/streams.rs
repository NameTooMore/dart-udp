use std::collections::BTreeMap;

use udp_protocol::{StreamData, StreamId};

use crate::{
    config::ConnectionRole,
    error::CoreError,
    flow_control::ReceiveFlowControl,
    receive::ReceiveStream,
    send::{QueuedFrame, SendStream},
    stream::{StreamInfo, StreamState},
};

struct StreamRecord {
    id: StreamId,
    bidirectional: bool,
    state: StreamState,
    send: SendStream,
    recv: ReceiveStream,
    recv_flow: ReceiveFlowControl,
}

impl StreamRecord {
    fn info(&self) -> StreamInfo {
        StreamInfo {
            stream_id: self.id,
            state: self.state,
            bidirectional: self.bidirectional,
            send_offset: self.send.next_offset(),
            receive_offset: self.recv.next_offset(),
            receive_window: self.recv.max_offset(),
            buffered_bytes: self.recv.buffered_len(),
        }
    }
}

pub(crate) struct StreamManager {
    next_stream_number: u64,
    streams: BTreeMap<StreamId, StreamRecord>,
}

pub(crate) struct StreamRead {
    data: Vec<u8>,
    eof: bool,
    window_update: Option<u64>,
}

impl StreamRead {
    pub(crate) fn into_parts(self) -> (Vec<u8>, bool, Option<u64>) {
        (self.data, self.eof, self.window_update)
    }
}

pub(crate) struct StreamDataStatus {
    readable: bool,
    finished: bool,
    buffered: usize,
}

impl StreamDataStatus {
    pub(crate) const fn readable(&self) -> bool {
        self.readable
    }

    pub(crate) const fn finished(&self) -> bool {
        self.finished
    }

    pub(crate) const fn buffered(&self) -> usize {
        self.buffered
    }
}

impl StreamManager {
    pub(crate) fn has_pending_data(&self) -> bool {
        self.streams
            .values()
            .any(|stream| stream.send.has_pending_data())
    }
    pub(crate) const fn new(next_stream_number: u64) -> Self {
        Self {
            next_stream_number,
            streams: BTreeMap::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.streams.len()
    }

    pub(crate) fn info(&self, stream_id: StreamId) -> Result<StreamInfo, CoreError> {
        self.streams
            .get(&stream_id)
            .map(StreamRecord::info)
            .ok_or(CoreError::UnknownStream { stream_id })
    }

    pub(crate) fn send_window(&self, stream_id: StreamId) -> Result<u64, CoreError> {
        self.streams
            .get(&stream_id)
            .map(|stream| stream.send.max_offset())
            .ok_or(CoreError::UnknownStream { stream_id })
    }

    pub(crate) fn open_local(
        &mut self,
        role: ConnectionRole,
        send_window: u64,
        receive_window: u64,
    ) -> Result<StreamId, CoreError> {
        let raw = self
            .next_stream_number
            .checked_add(2)
            .ok_or(CoreError::InvalidState {
                operation: "allocate stream ID",
            })?;
        let stream_id = StreamId::new(self.next_stream_number);
        self.next_stream_number = raw;
        self.insert(
            stream_id,
            true,
            send_window,
            role.local_stream_parity(),
            receive_window,
        )?;
        Ok(stream_id)
    }

    pub(crate) fn insert(
        &mut self,
        stream_id: StreamId,
        bidirectional: bool,
        send_window: u64,
        expected_parity: u64,
        receive_window: u64,
    ) -> Result<(), CoreError> {
        if self.streams.contains_key(&stream_id) {
            return Ok(());
        }
        if stream_id.raw() % 2 != expected_parity {
            return Err(CoreError::InvalidStreamId { stream_id });
        }
        self.streams.insert(
            stream_id,
            StreamRecord {
                id: stream_id,
                bidirectional,
                state: StreamState::Open,
                send: SendStream::new(stream_id, send_window),
                recv: ReceiveStream::new(stream_id, receive_window),
                recv_flow: ReceiveFlowControl::new(receive_window),
            },
        );
        Ok(())
    }

    pub(crate) fn write(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        max_buffer: usize,
        max_chunk: usize,
    ) -> Result<usize, CoreError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(CoreError::UnknownStream { stream_id })?;
        if stream.state != StreamState::Open {
            return Err(CoreError::InvalidState {
                operation: "write closed stream",
            });
        }
        stream.send.write(data, fin, max_buffer, max_chunk)
    }

    pub(crate) fn read(
        &mut self,
        stream_id: StreamId,
        max_len: usize,
    ) -> Result<StreamRead, CoreError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(CoreError::UnknownStream { stream_id })?;
        if let StreamState::Reset { error_code } = stream.state {
            return Err(CoreError::StreamReset {
                stream_id,
                error_code,
            });
        }
        let data = stream.recv.read(max_len);
        let window_update = stream.recv_flow.consume(data.len());
        if let Some(max_offset) = window_update {
            stream.recv.set_max_offset(max_offset);
        }
        let eof = stream.recv.is_finished();
        if eof {
            stream.state = StreamState::Finished;
        }
        Ok(StreamRead {
            data,
            eof,
            window_update,
        })
    }

    pub(crate) fn new_data_bytes(
        &self,
        data: &StreamData,
        max_receive_buffer: usize,
    ) -> Result<usize, CoreError> {
        let stream = self
            .streams
            .get(&data.stream_id)
            .ok_or(CoreError::UnknownStream {
                stream_id: data.stream_id,
            })?;
        if stream.state != StreamState::Open {
            return Ok(0);
        }
        let new_bytes = stream.recv.new_bytes(data.offset, &data.data)?;
        if new_bytes > max_receive_buffer.saturating_sub(stream.recv.buffered_len()) {
            return Err(CoreError::ReceiveBufferFull);
        }
        Ok(new_bytes)
    }

    pub(crate) fn insert_data(&mut self, data: &StreamData) -> Result<StreamDataStatus, CoreError> {
        let stream = self
            .streams
            .get_mut(&data.stream_id)
            .ok_or(CoreError::UnknownStream {
                stream_id: data.stream_id,
            })?;
        if stream.state != StreamState::Open {
            return Ok(StreamDataStatus {
                readable: false,
                finished: false,
                buffered: stream.recv.buffered_len(),
            });
        }
        stream.recv.insert(data.offset, &data.data, data.fin)?;
        Ok(StreamDataStatus {
            readable: stream.recv.readable(),
            finished: stream.recv.is_finished(),
            buffered: stream.recv.buffered_len(),
        })
    }

    pub(crate) fn finish(&mut self, stream_id: StreamId) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamState::Finished;
        }
    }

    pub(crate) fn reset(&mut self, stream_id: StreamId, error_code: u32) -> Result<(), CoreError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(CoreError::UnknownStream { stream_id })?;
        stream.state = StreamState::Reset { error_code };
        Ok(())
    }

    pub(crate) fn update_send_window(
        &mut self,
        stream_id: StreamId,
        max_offset: u64,
    ) -> Result<(), CoreError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(CoreError::UnknownStream { stream_id })?;
        stream.send.update_window(max_offset);
        Ok(())
    }

    pub(crate) fn take_sendable(&mut self) -> Option<QueuedFrame> {
        let stream_ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for stream_id in stream_ids {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            let Some(item) = stream.send.front_sendable() else {
                continue;
            };
            let end = item.offset().saturating_add(item.data().len() as u64);
            if item.retransmit_count() == 0 && end > stream.send.max_offset() {
                continue;
            }
            let item = stream.send.pop_sendable()?;
            return Some(QueuedFrame::stream_data(
                stream_id,
                item.offset(),
                item.fin(),
                item.data().to_vec(),
                item.retransmit_count(),
            ));
        }
        None
    }

    pub(crate) fn requeue(
        &mut self,
        data: &StreamData,
        retransmit_count: u32,
    ) -> Result<(), CoreError> {
        let stream = self
            .streams
            .get_mut(&data.stream_id)
            .ok_or(CoreError::UnknownStream {
                stream_id: data.stream_id,
            })?;
        stream.send.requeue(data, retransmit_count);
        Ok(())
    }
}
