use std::{collections::VecDeque, time::Duration};

use udp_protocol::{
    ConnectionClose, ConnectionId, Frame, MaxData, MaxStreamData, Packet, PacketCrypto,
    PacketFlags, PacketType, Ping, ResetStream, StreamData, StreamId, StreamOpen,
};

use crate::{
    config::{ConnectionConfig, ConnectionRole},
    error::CoreError,
    event::CoreOutput,
    flow_control::{ReceiveFlowControl, SendFlowControl},
    stream::StreamInfo,
    timer::TimerEvent,
};

mod handshake;
mod streams;
mod timers;
mod transport;

use handshake::{HandshakeState, HandshakeTimeout};
use streams::StreamManager;
use timers::TimerState;
use transport::{FlushContext, FlushIdentity, FlushRuntime, TransportState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Handshaking,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub eof: bool,
}

pub struct Connection {
    role: ConnectionRole,
    id: ConnectionId,
    config: ConnectionConfig,
    state: ConnectionState,
    now: Duration,
    streams: StreamManager,
    transport: TransportState,
    handshake: HandshakeState,
    packet_crypto: Option<PacketCrypto>,
    timers: TimerState,
    output: VecDeque<CoreOutput>,
    connection_send: SendFlowControl,
    connection_receive: ReceiveFlowControl,
    close_error: Option<u32>,
}

impl Connection {
    pub fn new_client(
        connection_id: ConnectionId,
        config: ConnectionConfig,
    ) -> Result<Self, CoreError> {
        Self::new(ConnectionRole::Client, connection_id, config, true)
    }

    pub fn new_server(
        connection_id: ConnectionId,
        config: ConnectionConfig,
    ) -> Result<Self, CoreError> {
        Self::new(ConnectionRole::Server, connection_id, config, false)
    }

    fn new(
        role: ConnectionRole,
        id: ConnectionId,
        config: ConnectionConfig,
        start_handshake: bool,
    ) -> Result<Self, CoreError> {
        config.validate().map_err(CoreError::InvalidConfig)?;
        let mut connection = Self {
            role,
            id,
            state: if start_handshake {
                ConnectionState::Handshaking
            } else {
                ConnectionState::Idle
            },
            config: config.clone(),
            now: Duration::ZERO,
            streams: StreamManager::new(role.local_stream_parity()),
            transport: TransportState::new(&config),
            handshake: HandshakeState::new(id, &config)?,
            packet_crypto: None,
            timers: TimerState::new(&config)?,
            output: VecDeque::new(),
            connection_send: SendFlowControl::new(config.initial_connection_window),
            connection_receive: ReceiveFlowControl::new(config.initial_connection_window),
            close_error: None,
        };
        connection
            .timers
            .schedule_idle(connection.config.idle_timeout)?;
        if let Some(interval) = connection.config.keepalive_interval {
            connection.timers.schedule_keepalive(interval)?;
        }
        if start_handshake {
            connection.handshake.start_client(
                &connection.config,
                &mut connection.transport,
                &mut connection.timers,
            )?;
            connection.flush()?;
        }
        Ok(connection)
    }

    pub fn connection_id(&self) -> ConnectionId {
        self.id
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn now(&self) -> Duration {
        self.now
    }

    pub fn congestion_window(&self) -> u64 {
        self.transport.congestion_window()
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.transport.bytes_in_flight()
    }

    pub fn rto(&self) -> Duration {
        self.transport.rto()
    }

    /// 返回当前连接是否已经没有待发送或待确认的可靠数据。
    pub fn is_reliably_flushed(&self) -> bool {
        self.transport.is_reliably_flushed(&self.streams)
    }

    pub fn next_deadline(&self) -> Result<Option<Duration>, CoreError> {
        self.timers.next_deadline()
    }

    pub fn stream_info(&self, stream_id: StreamId) -> Result<StreamInfo, CoreError> {
        self.streams.info(stream_id)
    }

    pub fn drain_output(&mut self) -> Vec<CoreOutput> {
        self.output.drain(..).collect()
    }

    pub fn on_datagram(&mut self, packet: Packet) -> Result<(), CoreError> {
        if self.state == ConnectionState::Closed {
            return Err(CoreError::InvalidState {
                operation: "receive on closed connection",
            });
        }
        if packet.connection_id != self.id {
            return Err(CoreError::ConnectionIdMismatch);
        }
        self.reset_idle_timer()?;
        // Retry 是无状态握手挑战，不属于可靠传输的包号/ACK 空间。
        let is_new = if packet.packet_type == PacketType::Retry {
            true
        } else {
            self.transport
                .record_received(packet.packet_number, self.now)
        };
        let ack_eliciting = packet.frames.iter().any(Frame::is_ack_eliciting);

        for frame in &packet.frames {
            if let Frame::Ack(ack) = frame
                && let Err(error) = self.transport.apply_ack(
                    ack,
                    self.now,
                    &self.config,
                    &mut self.timers,
                    &mut self.streams,
                )
            {
                if matches!(error, CoreError::RetransmissionLimit) {
                    self.close_error = Some(3);
                    self.set_state(ConnectionState::Closing);
                }
                return Err(error);
            }
        }
        if !is_new {
            if ack_eliciting {
                self.transport
                    .schedule_ack(&self.config, &mut self.timers)?;
            }
            self.flush()?;
            return Ok(());
        }

        for frame in packet.frames {
            if !matches!(frame, Frame::Ack(_)) {
                self.process_frame(packet.packet_type, frame)?;
            }
        }
        if ack_eliciting {
            self.transport
                .schedule_ack(&self.config, &mut self.timers)?;
        }
        self.flush()
    }

    pub fn on_datagram_bytes(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        let flags = udp_protocol::peek_packet_flags(bytes, self.config.max_datagram_size)?;
        let packet = if flags.contains(PacketFlags::ENCRYPTED) {
            let crypto = self.packet_crypto.as_mut().ok_or(CoreError::InvalidState {
                operation: "receive encrypted packet before handshake completion",
            })?;
            Packet::decode_with_crypto(bytes, self.config.max_datagram_size, crypto)?
        } else {
            Packet::decode_with_limit(bytes, self.config.max_datagram_size)?
        };
        self.on_datagram(packet)
    }

    pub fn encode_packet(&self, packet: &Packet) -> Result<Vec<u8>, CoreError> {
        let encrypted = self.packet_crypto.is_some()
            && matches!(
                self.state,
                ConnectionState::Established | ConnectionState::Closing
            )
            && matches!(packet.packet_type, PacketType::Data | PacketType::Close);
        if encrypted {
            let crypto = self.packet_crypto.as_ref().ok_or(CoreError::InvalidState {
                operation: "encode encrypted packet without session keys",
            })?;
            Ok(packet.encode_with_crypto(self.config.max_datagram_size, crypto)?)
        } else {
            Ok(packet.encode_with_limit(self.config.max_datagram_size)?)
        }
    }

    pub fn advance_time(&mut self, elapsed: Duration) -> Result<(), CoreError> {
        self.now = self
            .now
            .checked_add(elapsed)
            .ok_or(CoreError::InvalidState {
                operation: "advance clock",
            })?;
        let expired = self.timers.advance(elapsed)?;
        for event in expired {
            self.timers.clear_slot(event);
            self.process_timer(event)?;
        }
        self.flush()
    }

    pub fn open_stream(&mut self) -> Result<StreamId, CoreError> {
        self.ensure_established("open stream")?;
        if self.streams.len() >= self.effective_max_streams() as usize {
            return Err(CoreError::StreamLimit);
        }
        let stream_id = self.streams.open_local(
            self.role,
            self.handshake.peer_initial_stream_window(),
            self.config.initial_stream_window,
        )?;
        self.transport.queue(Frame::StreamOpen(StreamOpen {
            stream_id,
            initial_receive_window: self.handshake.peer_initial_stream_window(),
            bidirectional: true,
        }));
        self.flush()?;
        Ok(stream_id)
    }

    pub fn write_stream(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, CoreError> {
        self.ensure_established("write stream")?;
        let max_chunk = self.max_stream_data_chunk();
        let written =
            self.streams
                .write(stream_id, data, fin, self.config.max_send_buffer, max_chunk)?;
        self.flush()?;
        Ok(written)
    }

    pub fn read_stream(
        &mut self,
        stream_id: StreamId,
        max_len: usize,
    ) -> Result<ReadResult, CoreError> {
        let (data, eof, window_update) = self.streams.read(stream_id, max_len)?.into_parts();
        if let Some(max_offset) = window_update {
            self.transport.queue(Frame::MaxStreamData(MaxStreamData {
                stream_id,
                max_offset,
            }));
        }
        if !data.is_empty() {
            self.connection_receive.consume(data.len());
        }
        if eof {
            self.output.push_back(CoreOutput::StreamFinished(stream_id));
        }
        self.flush()?;
        Ok(ReadResult { data, eof })
    }

    pub fn close(&mut self, error_code: u32, reason: impl Into<String>) -> Result<(), CoreError> {
        if self.state == ConnectionState::Closed {
            return Ok(());
        }
        self.close_error = Some(error_code);
        self.set_state(ConnectionState::Closing);
        self.transport
            .queue(Frame::ConnectionClose(ConnectionClose {
                error_code,
                frame_type: 0,
                reason: reason.into(),
            }));
        self.timers.schedule_close(self.config.close_timeout)?;
        self.flush()
    }

    fn process_frame(&mut self, packet_type: PacketType, frame: Frame) -> Result<(), CoreError> {
        match frame {
            Frame::ClientHello(hello) => {
                let (frame, next_state, connection_max_offset) =
                    self.handshake.receive_client_hello(
                        self.role,
                        packet_type,
                        hello,
                        self.state,
                        &mut self.config,
                    )?;
                if let Some(max_offset) = connection_max_offset {
                    self.connection_send.set_max_offset(max_offset);
                }
                self.handshake.set_frame(frame.clone());
                self.transport.queue(frame);
                if self.role == ConnectionRole::Server {
                    self.activate_crypto()?;
                }
                if let Some(next_state) = next_state {
                    self.timers
                        .schedule_handshake(self.config.handshake_timeout)?;
                    self.set_state(next_state);
                }
                Ok(())
            }
            Frame::ServerHello(hello) => {
                let (frame, connection_max_offset) = self.handshake.receive_server_hello(
                    self.role,
                    packet_type,
                    hello,
                    self.state,
                    &mut self.config,
                )?;
                self.connection_send.set_max_offset(connection_max_offset);
                self.handshake.set_frame(frame.clone());
                self.transport.queue(frame);
                self.timers.cancel_handshake();
                self.set_state(ConnectionState::Established);
                self.activate_crypto()?;
                Ok(())
            }
            Frame::HandshakeAck(ack) => {
                let next_state = self.handshake.receive_handshake_ack(
                    self.role,
                    packet_type,
                    ack,
                    self.state,
                    &mut self.timers,
                )?;
                self.set_state(next_state);
                self.activate_crypto()?;
                Ok(())
            }
            Frame::Retry(retry) => {
                let frame = self.handshake.receive_retry(
                    self.role,
                    packet_type,
                    retry,
                    self.state,
                    &mut self.config,
                )?;
                self.transport.queue_front(frame);
                self.timers
                    .schedule_handshake(self.config.handshake_timeout)
            }
            Frame::StreamOpen(open) => self.process_stream_open(packet_type, open),
            Frame::StreamData(data) => self.process_stream_data(packet_type, data),
            Frame::ResetStream(reset) => self.process_reset_stream(packet_type, reset),
            Frame::MaxStreamData(update) => self.process_max_stream_data(packet_type, update),
            Frame::MaxData(update) => self.process_max_data(packet_type, update),
            Frame::Ping(ping) => self.process_ping(packet_type, ping),
            Frame::Pong(_) => Ok(()),
            Frame::ConnectionClose(close) => self.process_connection_close(packet_type, close),
            Frame::Ack(_) => Ok(()),
        }
    }

    fn process_stream_open(
        &mut self,
        packet_type: PacketType,
        open: StreamOpen,
    ) -> Result<(), CoreError> {
        if packet_type != PacketType::Data || self.state != ConnectionState::Established {
            return Err(CoreError::InvalidPacketType);
        }
        if open.stream_id.raw() % 2 != self.role.peer_stream_parity() {
            return Err(CoreError::InvalidStreamId {
                stream_id: open.stream_id,
            });
        }
        if let Ok(existing_window) = self.streams.send_window(open.stream_id) {
            if existing_window != open.initial_receive_window {
                return Err(CoreError::InvalidState {
                    operation: "stream was opened with different parameters",
                });
            }
            return Ok(());
        }
        if self.streams.len() >= self.effective_max_streams() as usize {
            return Err(CoreError::StreamLimit);
        }
        self.streams.insert(
            open.stream_id,
            open.bidirectional,
            open.initial_receive_window,
            self.role.peer_stream_parity(),
            self.config.initial_stream_window,
        )?;
        self.output
            .push_back(CoreOutput::StreamOpened(open.stream_id));
        Ok(())
    }

    fn process_stream_data(
        &mut self,
        packet_type: PacketType,
        data: StreamData,
    ) -> Result<(), CoreError> {
        if packet_type != PacketType::Data || self.state != ConnectionState::Established {
            return Err(CoreError::InvalidPacketType);
        }
        let new_bytes = self
            .streams
            .new_data_bytes(&data, self.config.max_receive_buffer)?;
        let connection_end = self
            .connection_receive
            .unique_received()
            .checked_add(new_bytes as u64)
            .ok_or(CoreError::FlowControlViolation { stream_id: None })?;
        self.connection_receive
            .check(None, connection_end, new_bytes)?;
        let status = self.streams.insert_data(&data)?;
        self.connection_receive.account(None, new_bytes)?;
        if status.buffered() > self.config.max_receive_buffer {
            return Err(CoreError::ReceiveBufferFull);
        }
        if status.readable() {
            self.output
                .push_back(CoreOutput::StreamReadable(data.stream_id));
        }
        if status.finished() && !status.readable() {
            self.streams.finish(data.stream_id);
            self.output
                .push_back(CoreOutput::StreamFinished(data.stream_id));
        }
        Ok(())
    }

    fn process_reset_stream(
        &mut self,
        packet_type: PacketType,
        reset: ResetStream,
    ) -> Result<(), CoreError> {
        if packet_type != PacketType::Data || self.state != ConnectionState::Established {
            return Err(CoreError::InvalidPacketType);
        }
        self.streams.reset(reset.stream_id, reset.error_code)?;
        self.output.push_back(CoreOutput::StreamReset {
            stream_id: reset.stream_id,
            error_code: reset.error_code,
        });
        Ok(())
    }

    fn process_max_stream_data(
        &mut self,
        packet_type: PacketType,
        update: MaxStreamData,
    ) -> Result<(), CoreError> {
        if packet_type != PacketType::Data || self.state != ConnectionState::Established {
            return Err(CoreError::InvalidPacketType);
        }
        self.streams
            .update_send_window(update.stream_id, update.max_offset)
    }

    fn process_max_data(
        &mut self,
        packet_type: PacketType,
        update: MaxData,
    ) -> Result<(), CoreError> {
        if packet_type != PacketType::Data || self.state != ConnectionState::Established {
            return Err(CoreError::InvalidPacketType);
        }
        self.connection_send.update(update.max_offset);
        Ok(())
    }

    fn process_ping(&mut self, packet_type: PacketType, ping: Ping) -> Result<(), CoreError> {
        if packet_type != PacketType::Data || self.state != ConnectionState::Established {
            return Err(CoreError::InvalidPacketType);
        }
        self.transport
            .queue(Frame::Pong(udp_protocol::Pong { nonce: ping.nonce }));
        Ok(())
    }

    fn process_connection_close(
        &mut self,
        packet_type: PacketType,
        close: ConnectionClose,
    ) -> Result<(), CoreError> {
        if packet_type != PacketType::Close {
            return Err(CoreError::InvalidPacketType);
        }
        self.close_error = Some(close.error_code);
        self.timers.cancel_all();
        self.set_state(ConnectionState::Closed);
        self.output.push_back(CoreOutput::ConnectionClosed {
            error_code: close.error_code,
        });
        Ok(())
    }

    fn process_timer(&mut self, event: TimerEvent) -> Result<(), CoreError> {
        match event {
            TimerEvent::HandshakeTimeout => {
                if self.state == ConnectionState::Handshaking {
                    let timeout = self.handshake.on_timeout(
                        self.state,
                        &self.config,
                        &mut self.transport,
                        &mut self.timers,
                    )?;
                    if matches!(timeout, HandshakeTimeout::Close) {
                        self.close(1, "handshake timeout")?;
                    }
                }
            }
            TimerEvent::Retransmit {
                packet_number,
                generation,
            } => {
                if let Err(error) = self.transport.process_retransmit(
                    packet_number,
                    generation,
                    &self.config,
                    &mut self.streams,
                ) {
                    if matches!(error, CoreError::RetransmissionLimit) {
                        self.close_error = Some(3);
                        self.set_state(ConnectionState::Closing);
                    }
                    return Err(error);
                }
            }
            TimerEvent::AckDelay => self.transport.on_ack_timer(),
            TimerEvent::Keepalive => {
                if self.state == ConnectionState::Established {
                    self.transport.queue_keepalive();
                }
                if let Some(interval) = self.config.keepalive_interval {
                    self.timers.schedule_keepalive(interval)?;
                }
            }
            TimerEvent::IdleTimeout => {
                if !matches!(
                    self.state,
                    ConnectionState::Closed | ConnectionState::Closing
                ) {
                    self.close(2, "idle timeout")?;
                }
            }
            TimerEvent::CloseTimeout => {
                self.timers.cancel_all();
                self.set_state(ConnectionState::Closed);
                self.output.push_back(CoreOutput::ConnectionClosed {
                    error_code: self.close_error.unwrap_or(0),
                });
            }
        }
        Ok(())
    }

    fn effective_max_streams(&self) -> u32 {
        self.handshake.effective_max_streams(&self.config)
    }

    fn ensure_established(&self, operation: &'static str) -> Result<(), CoreError> {
        if self.state == ConnectionState::Established {
            Ok(())
        } else {
            Err(CoreError::InvalidState { operation })
        }
    }

    fn max_stream_data_chunk(&self) -> usize {
        self.config.max_datagram_size.saturating_sub(100).max(1)
    }

    fn reset_idle_timer(&mut self) -> Result<(), CoreError> {
        self.timers.schedule_idle(self.config.idle_timeout)
    }

    fn flush(&mut self) -> Result<(), CoreError> {
        let identity = FlushIdentity::new(
            self.id,
            self.state,
            self.now,
            &self.config,
            self.packet_crypto.is_some()
                && matches!(
                    self.state,
                    ConnectionState::Established | ConnectionState::Closing
                ),
        );
        let runtime = FlushRuntime::new(
            &mut self.timers,
            &mut self.streams,
            &mut self.connection_send,
            &mut self.output,
        );
        self.transport.flush(FlushContext::new(identity, runtime))
    }

    fn set_state(&mut self, state: ConnectionState) {
        if self.state != state {
            self.state = state;
            self.output
                .push_back(CoreOutput::ConnectionStateChanged(state));
        }
    }

    fn activate_crypto(&mut self) -> Result<(), CoreError> {
        if self.packet_crypto.is_some() {
            return Ok(());
        }
        let keys = self
            .handshake
            .session_keys()
            .cloned()
            .ok_or(CoreError::InvalidState {
                operation: "establish connection without session keys",
            })?;
        let role = match self.role {
            ConnectionRole::Client => udp_protocol::CryptoRole::Client,
            ConnectionRole::Server => udp_protocol::CryptoRole::Server,
        };
        self.packet_crypto = Some(PacketCrypto::new(role, keys));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use udp_protocol::{ConnectionId, Frame, Packet, PacketType, StreamData};

    use super::{Connection, ConnectionConfig, ConnectionState};
    use crate::event::CoreOutput;

    fn config() -> ConnectionConfig {
        ConnectionConfig {
            clock_granularity: Duration::from_millis(1),
            ack_delay: Duration::from_millis(2),
            handshake_timeout: Duration::from_millis(50),
            idle_timeout: Duration::from_millis(200),
            keepalive_interval: None,
            initial_rto: Duration::from_millis(20),
            min_rto: Duration::from_millis(5),
            max_rto: Duration::from_millis(100),
            ..ConnectionConfig::default()
        }
    }

    fn take_packet(connection: &mut Connection) -> Packet {
        connection
            .drain_output()
            .into_iter()
            .find_map(|output| match output {
                CoreOutput::Send(packet) => Some(packet),
                _ => None,
            })
            .expect("a packet should be queued")
    }

    fn establish() -> (Connection, Connection) {
        let id = ConnectionId::new(9);
        let mut client = Connection::new_client(id, config()).unwrap();
        let mut server = Connection::new_server(id, config()).unwrap();
        let initial = take_packet(&mut client);
        server.on_datagram(initial).unwrap();
        let hello = take_packet(&mut server);
        client.on_datagram(hello).unwrap();
        let handshake_ack = take_packet(&mut client);
        server.on_datagram(handshake_ack).unwrap();
        assert_eq!(client.state(), ConnectionState::Established);
        assert_eq!(server.state(), ConnectionState::Established);
        (client, server)
    }

    #[test]
    fn encrypted_datagrams_complete_handshake_and_stream_delivery() {
        let id = ConnectionId::new(21);
        let mut client = Connection::new_client(id, config()).unwrap();
        let mut server = Connection::new_server(id, config()).unwrap();

        let initial = take_packet(&mut client);
        let initial_bytes = client.encode_packet(&initial).unwrap();
        server.on_datagram_bytes(&initial_bytes).unwrap();
        let server_hello = take_packet(&mut server);
        let server_hello_bytes = server.encode_packet(&server_hello).unwrap();
        client.on_datagram_bytes(&server_hello_bytes).unwrap();
        let handshake_ack = take_packet(&mut client);
        let handshake_ack_bytes = client.encode_packet(&handshake_ack).unwrap();
        server.on_datagram_bytes(&handshake_ack_bytes).unwrap();
        server.advance_time(Duration::from_millis(2)).unwrap();
        let encrypted_ack = server
            .drain_output()
            .into_iter()
            .find_map(|output| match output {
                CoreOutput::Send(packet) => Some(packet),
                _ => None,
            })
            .expect("server should acknowledge the handshake");
        let encrypted_ack_bytes = server.encode_packet(&encrypted_ack).unwrap();
        client.on_datagram_bytes(&encrypted_ack_bytes).unwrap();

        let stream_id = client.open_stream().unwrap();
        let open = take_packet(&mut client);
        server
            .on_datagram_bytes(&client.encode_packet(&open).unwrap())
            .unwrap();
        server.drain_output();
        client.write_stream(stream_id, b"secret", true).unwrap();
        let data = take_packet(&mut client);
        server
            .on_datagram_bytes(&client.encode_packet(&data).unwrap())
            .unwrap();
        assert_eq!(server.read_stream(stream_id, 64).unwrap().data, b"secret");
    }

    #[test]
    fn completes_handshake_and_opens_stream() {
        let (mut client, mut server) = establish();
        let stream_id = client.open_stream().unwrap();
        let open = take_packet(&mut client);
        server.on_datagram(open).unwrap();
        assert!(server.stream_info(stream_id).is_ok());
        assert!(
            server
                .drain_output()
                .contains(&CoreOutput::StreamOpened(stream_id))
        );
    }

    #[test]
    fn generates_a_fresh_client_nonce_per_connection() {
        let mut first = Connection::new_client(ConnectionId::new(1), config()).unwrap();
        let mut second = Connection::new_client(ConnectionId::new(2), config()).unwrap();
        let first_nonce = first
            .drain_output()
            .into_iter()
            .find_map(|output| match output {
                CoreOutput::Send(packet) => {
                    packet.frames.into_iter().find_map(|frame| match frame {
                        Frame::ClientHello(hello) => Some(hello.client_nonce),
                        _ => None,
                    })
                }
                _ => None,
            })
            .expect("first client hello should contain a nonce");
        let second_nonce = second
            .drain_output()
            .into_iter()
            .find_map(|output| match output {
                CoreOutput::Send(packet) => {
                    packet.frames.into_iter().find_map(|frame| match frame {
                        Frame::ClientHello(hello) => Some(hello.client_nonce),
                        _ => None,
                    })
                }
                _ => None,
            })
            .expect("second client hello should contain a nonce");
        assert_ne!(first_nonce, second_nonce);
        assert_ne!(first_nonce, [0_u8; 16]);
        assert_ne!(second_nonce, [0_u8; 16]);
    }

    #[test]
    fn reliable_flush_waits_for_packet_acknowledgements() {
        let (mut client, mut server) = establish();
        let stream_id = client.open_stream().unwrap();
        let open = take_packet(&mut client);
        assert!(!client.is_reliably_flushed());
        server.on_datagram(open).unwrap();
        server.advance_time(Duration::from_millis(2)).unwrap();
        let ack = server
            .drain_output()
            .into_iter()
            .find_map(|output| match output {
                CoreOutput::Send(packet)
                    if packet
                        .frames
                        .iter()
                        .any(|frame| matches!(frame, Frame::Ack(_))) =>
                {
                    Some(packet)
                }
                _ => None,
            })
            .expect("an ACK should be emitted");
        client.on_datagram(ack).unwrap();
        assert!(client.is_reliably_flushed());
        let _ = stream_id;
    }

    #[test]
    fn retry_does_not_consume_the_server_packet_number_zero() {
        let id = ConnectionId::new(19);
        let mut client = Connection::new_client(id, config()).unwrap();
        let initial = take_packet(&mut client);
        let nonce = match &initial.frames[0] {
            Frame::ClientHello(hello) => hello.client_nonce,
            _ => panic!("client must start with ClientHello"),
        };
        let retry = Packet::new(
            PacketType::Retry,
            udp_protocol::PacketFlags::empty(),
            id,
            udp_protocol::PacketNumber::new(u64::MAX),
            vec![Frame::Retry(udp_protocol::Retry {
                cookie: vec![7, 8, 9],
            })],
        );
        client.on_datagram(retry).unwrap();
        let retried_initial = take_packet(&mut client);
        assert!(matches!(
            &retried_initial.frames[0],
            Frame::ClientHello(hello) if hello.client_nonce == nonce && hello.cookie == vec![7, 8, 9]
        ));

        let mut server = Connection::new_server(id, config()).unwrap();
        server.on_datagram(retried_initial).unwrap();
        let server_hello = take_packet(&mut server);
        assert_eq!(server_hello.packet_number.raw(), 0);
        client.on_datagram(server_hello).unwrap();
        assert_eq!(client.state(), ConnectionState::Established);
    }

    #[test]
    fn delivers_out_of_order_duplicate_data_in_order() {
        let (mut client, mut server) = establish();
        let stream_id = client.open_stream().unwrap();
        server.on_datagram(take_packet(&mut client)).unwrap();
        server.drain_output();

        let first = Packet::new(
            PacketType::Data,
            udp_protocol::PacketFlags::ACK_ELICITING,
            ConnectionId::new(9),
            udp_protocol::PacketNumber::new(20),
            vec![Frame::StreamData(StreamData {
                stream_id,
                offset: 5,
                fin: true,
                data: b" world".to_vec(),
            })],
        );
        let second = Packet::new(
            PacketType::Data,
            udp_protocol::PacketFlags::ACK_ELICITING,
            ConnectionId::new(9),
            udp_protocol::PacketNumber::new(19),
            vec![Frame::StreamData(StreamData {
                stream_id,
                offset: 0,
                fin: false,
                data: b"hello".to_vec(),
            })],
        );
        server.on_datagram(first).unwrap();
        server.on_datagram(second.clone()).unwrap();
        server.on_datagram(second).unwrap();
        assert_eq!(
            server.read_stream(stream_id, 100).unwrap().data,
            b"hello world"
        );
        assert!(server.read_stream(stream_id, 100).unwrap().eof);
    }

    #[test]
    fn retransmits_after_rto_and_recovers_from_ack() {
        let (mut client, mut server) = establish();
        let stream_id = client.open_stream().unwrap();
        server.on_datagram(take_packet(&mut client)).unwrap();
        server.drain_output();
        client.write_stream(stream_id, b"reliable", true).unwrap();
        let data = take_packet(&mut client);
        client.advance_time(Duration::from_millis(21)).unwrap();
        let mut pending_packets = Vec::new();
        let mut retransmission = None;
        for output in client.drain_output() {
            if let CoreOutput::Send(packet) = output {
                if packet
                    .frames
                    .iter()
                    .any(|frame| matches!(frame, Frame::StreamData(_)))
                {
                    retransmission = Some(packet.clone());
                }
                pending_packets.push(packet);
            }
        }
        let retransmission = retransmission.expect("a stream-data retransmission should be queued");
        assert_ne!(data.packet_number, retransmission.packet_number);
        for packet in pending_packets {
            server.on_datagram(packet).unwrap();
        }
        assert_eq!(
            server.read_stream(stream_id, 100).unwrap().data,
            b"reliable"
        );
        server.advance_time(Duration::from_millis(2)).unwrap();
        let ack = server
            .drain_output()
            .into_iter()
            .find_map(|output| match output {
                CoreOutput::Send(packet)
                    if packet
                        .frames
                        .iter()
                        .any(|frame| matches!(frame, Frame::Ack(_))) =>
                {
                    Some(packet)
                }
                _ => None,
            })
            .expect("an acknowledgement should be queued");
        client.on_datagram(ack).unwrap();
        assert_eq!(client.bytes_in_flight(), 0);
    }

    #[test]
    fn fast_forward_timer_expires_without_tokio() {
        let (mut client, _) = establish();
        client.advance_time(Duration::from_secs(60)).unwrap();
        assert!(matches!(
            client.state(),
            ConnectionState::Closing | ConnectionState::Closed
        ));
    }

    #[test]
    fn rejects_corrupted_bytes_and_wrong_connection_id() {
        let id = ConnectionId::new(9);
        let mut client = Connection::new_client(id, config()).unwrap();
        let initial = take_packet(&mut client);
        let mut encoded = initial.encode().unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        let mut server = Connection::new_server(id, config()).unwrap();
        assert!(matches!(
            server.on_datagram_bytes(&encoded),
            Err(crate::CoreError::Protocol(
                udp_protocol::ProtocolError::ChecksumMismatch { .. }
            ))
        ));

        let wrong = Packet::new(
            PacketType::Initial,
            udp_protocol::PacketFlags::ACK_ELICITING,
            ConnectionId::new(10),
            initial.packet_number,
            initial.frames,
        );
        assert!(matches!(
            server.on_datagram(wrong),
            Err(crate::CoreError::ConnectionIdMismatch)
        ));
    }

    #[test]
    fn rejects_peer_stream_with_local_parity() {
        let (mut client, mut server) = establish();
        let invalid = Packet::new(
            PacketType::Data,
            udp_protocol::PacketFlags::ACK_ELICITING,
            ConnectionId::new(9),
            udp_protocol::PacketNumber::new(50),
            vec![Frame::StreamOpen(udp_protocol::StreamOpen {
                stream_id: udp_protocol::StreamId::new(1),
                initial_receive_window: 10,
                bidirectional: true,
            })],
        );
        assert!(matches!(
            server.on_datagram(invalid),
            Err(crate::CoreError::InvalidStreamId { .. })
        ));
        assert!(client.open_stream().is_ok());
    }

    #[test]
    fn receive_window_error_does_not_poison_stream_state() {
        let mut small = config();
        small.initial_stream_window = 4;
        let id = ConnectionId::new(9);
        let mut client = Connection::new_client(id, small.clone()).unwrap();
        let mut server = Connection::new_server(id, small).unwrap();
        let initial = take_packet(&mut client);
        server.on_datagram(initial).unwrap();
        let hello = take_packet(&mut server);
        client.on_datagram(hello).unwrap();
        let handshake_ack = take_packet(&mut client);
        server.on_datagram(handshake_ack).unwrap();
        let stream_id = client.open_stream().unwrap();
        server.on_datagram(take_packet(&mut client)).unwrap();
        server.drain_output();

        let oversized = Packet::new(
            PacketType::Data,
            udp_protocol::PacketFlags::ACK_ELICITING,
            id,
            udp_protocol::PacketNumber::new(30),
            vec![Frame::StreamData(StreamData {
                stream_id,
                offset: 0,
                fin: false,
                data: b"12345".to_vec(),
            })],
        );
        assert!(matches!(
            server.on_datagram(oversized),
            Err(crate::CoreError::FlowControlViolation { .. })
        ));

        let valid = Packet::new(
            PacketType::Data,
            udp_protocol::PacketFlags::ACK_ELICITING,
            id,
            udp_protocol::PacketNumber::new(31),
            vec![Frame::StreamData(StreamData {
                stream_id,
                offset: 0,
                fin: true,
                data: b"ok".to_vec(),
            })],
        );
        server.on_datagram(valid).unwrap();
        assert_eq!(server.read_stream(stream_id, 10).unwrap().data, b"ok");
    }

    #[test]
    fn independent_stream_can_progress_when_another_stream_is_lost() {
        let (mut client, mut server) = establish();
        let first = client.open_stream().unwrap();
        let first_open = take_packet(&mut client);
        server.on_datagram(first_open).unwrap();
        let second = client.open_stream().unwrap();
        let second_open = take_packet(&mut client);
        server.on_datagram(second_open).unwrap();
        server.drain_output();

        client.write_stream(first, b"lost", false).unwrap();
        let _lost = take_packet(&mut client);
        client.write_stream(second, b"delivered", true).unwrap();
        let delivered = take_packet(&mut client);
        server.on_datagram(delivered).unwrap();
        assert_eq!(server.read_stream(second, 100).unwrap().data, b"delivered");
        assert_eq!(server.read_stream(first, 100).unwrap().data, b"");
    }

    #[test]
    fn ack_cancels_retransmission_timer() {
        let (mut client, mut server) = establish();
        let stream_id = client.open_stream().unwrap();
        let open = take_packet(&mut client);
        server.on_datagram(open).unwrap();
        server.advance_time(Duration::from_millis(2)).unwrap();
        let ack = server
            .drain_output()
            .into_iter()
            .find_map(|output| match output {
                CoreOutput::Send(packet)
                    if packet
                        .frames
                        .iter()
                        .any(|frame| matches!(frame, Frame::Ack(_))) =>
                {
                    Some(packet)
                }
                _ => None,
            })
            .expect("an ACK should be emitted");
        client.on_datagram(ack).unwrap();
        client.advance_time(Duration::from_millis(25)).unwrap();
        assert!(!client.drain_output().into_iter().any(|output| {
            matches!(
                output,
                CoreOutput::Send(packet)
                    if packet
                        .frames
                        .iter()
                        .any(|frame| matches!(frame, Frame::StreamOpen(_)))
            )
        }));
        let _ = stream_id;
    }
}
