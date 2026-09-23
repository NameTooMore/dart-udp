use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

use udp_protocol::{
    AEAD_TAG_LEN, AckFrame, ConnectionId, Frame, Packet, PacketFlags, PacketNumber, PacketType,
    Ping,
};

use crate::{
    ack::ReceivedPackets, config::ConnectionConfig, congestion::CongestionController,
    error::CoreError, event::CoreOutput, flow_control::SendFlowControl, recovery::SentPacket,
    rtt::RttEstimator, send::QueuedFrame, timer::TimerEvent,
};

use super::{ConnectionState, streams::StreamManager, timers::TimerState};

pub(crate) struct FlushIdentity<'a> {
    connection_id: ConnectionId,
    state: ConnectionState,
    now: Duration,
    encrypt_data: bool,
    config: &'a ConnectionConfig,
}

impl<'a> FlushIdentity<'a> {
    pub(crate) const fn new(
        connection_id: ConnectionId,
        state: ConnectionState,
        now: Duration,
        config: &'a ConnectionConfig,
        encrypt_data: bool,
    ) -> Self {
        Self {
            connection_id,
            state,
            now,
            config,
            encrypt_data,
        }
    }
}

pub(crate) struct FlushRuntime<'a> {
    timers: &'a mut TimerState,
    streams: &'a mut StreamManager,
    connection_send: &'a mut SendFlowControl,
    output: &'a mut VecDeque<CoreOutput>,
}

impl<'a> FlushRuntime<'a> {
    pub(crate) const fn new(
        timers: &'a mut TimerState,
        streams: &'a mut StreamManager,
        connection_send: &'a mut SendFlowControl,
        output: &'a mut VecDeque<CoreOutput>,
    ) -> Self {
        Self {
            timers,
            streams,
            connection_send,
            output,
        }
    }
}

pub(crate) struct FlushContext<'a> {
    identity: FlushIdentity<'a>,
    runtime: FlushRuntime<'a>,
}

impl<'a> FlushContext<'a> {
    pub(crate) const fn new(identity: FlushIdentity<'a>, runtime: FlushRuntime<'a>) -> Self {
        Self { identity, runtime }
    }
}

pub(crate) struct TransportState {
    next_packet_number: u64,
    pending_frames: VecDeque<QueuedFrame>,
    sent: BTreeMap<PacketNumber, SentPacket>,
    received: ReceivedPackets,
    ack_pending: bool,
    ack_ready: bool,
    generation: u32,
    congestion: CongestionController,
    rtt: RttEstimator,
    last_ping_nonce: u64,
}

impl TransportState {
    pub(crate) fn new(config: &ConnectionConfig) -> Self {
        Self {
            next_packet_number: 0,
            pending_frames: VecDeque::new(),
            sent: BTreeMap::new(),
            received: ReceivedPackets::new(),
            ack_pending: false,
            ack_ready: false,
            generation: 0,
            congestion: CongestionController::new(
                config.initial_congestion_window,
                config.min_congestion_window,
                config.max_congestion_window,
                config.max_datagram_size,
            ),
            rtt: RttEstimator::new(
                config.initial_rto,
                config.min_rto,
                config.max_rto,
                config.clock_granularity,
            ),
            last_ping_nonce: 0,
        }
    }

    pub(crate) const fn congestion_window(&self) -> u64 {
        self.congestion.cwnd()
    }

    pub(crate) const fn bytes_in_flight(&self) -> u64 {
        self.congestion.bytes_in_flight()
    }

    pub(crate) const fn rto(&self) -> Duration {
        self.rtt.rto()
    }

    pub(crate) fn is_reliably_flushed(&self, streams: &StreamManager) -> bool {
        self.pending_frames.is_empty() && self.sent.is_empty() && !streams.has_pending_data()
    }

    pub(crate) fn queue(&mut self, frame: Frame) {
        self.pending_frames.push_back(QueuedFrame::new(frame));
    }

    pub(crate) fn queue_front(&mut self, frame: Frame) {
        self.pending_frames.push_front(QueuedFrame::new(frame));
    }

    pub(crate) fn record_received(&mut self, packet_number: PacketNumber, now: Duration) -> bool {
        self.received.record(packet_number, now)
    }

    pub(crate) fn schedule_ack(
        &mut self,
        config: &ConnectionConfig,
        timers: &mut TimerState,
    ) -> Result<(), CoreError> {
        self.ack_pending = true;
        if config.ack_delay.is_zero() {
            self.ack_ready = true;
            return Ok(());
        }
        if !self.ack_ready {
            timers.schedule_ack(config.ack_delay)?;
        }
        Ok(())
    }

    pub(crate) fn on_ack_timer(&mut self) {
        if self.ack_pending {
            self.ack_ready = true;
        }
    }

    pub(crate) fn queue_keepalive(&mut self) {
        self.last_ping_nonce = self.last_ping_nonce.wrapping_add(1);
        self.queue(Frame::Ping(Ping {
            nonce: self.last_ping_nonce,
        }));
    }

    pub(crate) fn apply_ack(
        &mut self,
        ack: &AckFrame,
        now: Duration,
        config: &ConnectionConfig,
        timers: &mut TimerState,
        streams: &mut StreamManager,
    ) -> Result<(), CoreError> {
        ack.validate()?;
        if ack.largest.raw() >= self.next_packet_number {
            return Err(CoreError::AckForUnsentPacket);
        }
        let acknowledged: Vec<PacketNumber> = self
            .sent
            .keys()
            .copied()
            .filter(|packet_number| ack.ranges.contains(*packet_number))
            .collect();
        let acknowledged_set = acknowledged.clone();
        let mut rtt_sample = None;
        for packet_number in acknowledged {
            let Some(packet) = self.sent.remove(&packet_number) else {
                continue;
            };
            timers.cancel(packet.timer_id());
            self.congestion.on_acked(packet.encoded_len());
            if packet.retransmit_count() == 0 && rtt_sample.is_none() {
                rtt_sample = Some(now.saturating_sub(packet.sent_at()));
            }
        }
        if let Some(sample) = rtt_sample {
            self.rtt.on_ack(sample, ack.ack_delay);
            self.rtt.reset_backoff();
        }

        let threshold = config.fast_loss_threshold;
        let candidates: Vec<PacketNumber> = self
            .sent
            .keys()
            .copied()
            .filter(|packet_number| {
                let higher_acks = acknowledged_set
                    .iter()
                    .filter(|acked| acked.raw() > packet_number.raw())
                    .count() as u64;
                higher_acks >= threshold
            })
            .collect();
        for packet_number in candidates {
            if let Some(packet) = self.sent.remove(&packet_number) {
                timers.cancel(packet.timer_id());
                self.congestion.on_loss(packet.encoded_len());
                let (_, frames, retransmit_count) = packet.into_parts();
                self.requeue_lost(frames, retransmit_count, config, streams)?;
            }
        }
        Ok(())
    }

    pub(crate) fn process_retransmit(
        &mut self,
        packet_number: PacketNumber,
        generation: u32,
        config: &ConnectionConfig,
        streams: &mut StreamManager,
    ) -> Result<(), CoreError> {
        let Some(packet) = self.sent.get(&packet_number) else {
            return Ok(());
        };
        if packet.generation() != generation {
            return Ok(());
        }
        let packet = self
            .sent
            .remove(&packet_number)
            .ok_or(CoreError::InvalidState {
                operation: "remove retransmission record",
            })?;
        self.congestion.on_loss(packet.encoded_len());
        self.rtt.on_timeout();
        let (_, frames, retransmit_count) = packet.into_parts();
        self.requeue_lost(frames, retransmit_count, config, streams)
    }

    pub(crate) fn flush(&mut self, context: FlushContext<'_>) -> Result<(), CoreError> {
        let FlushContext { identity, runtime } = context;
        let FlushIdentity {
            connection_id,
            state,
            now,
            encrypt_data,
            config,
        } = identity;
        let FlushRuntime {
            timers,
            streams,
            connection_send,
            output,
        } = runtime;
        loop {
            let candidate = if self.ack_pending && self.ack_ready {
                let ack = self.received.frame(now, config.ack_delay)?;
                ack.map(Candidate::Ack)
            } else {
                self.take_data_candidate(streams)
            };
            let Some(candidate) = candidate else {
                break;
            };
            let (mut queued, packet_type, is_ack) = match candidate {
                Candidate::Ack(ack) => (None, PacketType::Data, Some(ack)),
                Candidate::Frame(queued) => {
                    let packet_type = packet_type(queued.frame(), state);
                    (Some(queued), packet_type, None)
                }
            };
            let frame = if let Some(ack) = is_ack {
                Frame::Ack(ack)
            } else {
                queued
                    .as_ref()
                    .map(|item| item.frame().clone())
                    .ok_or(CoreError::InvalidState {
                        operation: "build outbound frame",
                    })?
            };
            let packet_number = PacketNumber::new(self.next_packet_number);
            let ack_eliciting = frame.is_ack_eliciting();
            let flags = if ack_eliciting {
                PacketFlags::ACK_ELICITING
            } else {
                PacketFlags::empty()
            };
            let packet = Packet::new(
                packet_type,
                flags,
                connection_id,
                packet_number,
                vec![frame],
            );
            let plain_encoded_len = packet
                .encode_with_limit(config.max_datagram_size)
                .map_err(CoreError::Protocol)?
                .len();
            let encoded_len =
                if encrypt_data && matches!(packet_type, PacketType::Data | PacketType::Close) {
                    plain_encoded_len
                        .checked_add(AEAD_TAG_LEN)
                        .ok_or(CoreError::InvalidState {
                            operation: "calculate encrypted packet length",
                        })?
                } else {
                    plain_encoded_len
                };
            if encoded_len > config.max_datagram_size {
                return Err(CoreError::Protocol(
                    udp_protocol::ProtocolError::DatagramTooLarge {
                        maximum: config.max_datagram_size,
                        actual: encoded_len,
                    },
                ));
            }
            if ack_eliciting && !self.congestion.can_send(encoded_len) {
                if let Some(queued) = queued.take() {
                    self.requeue_candidate(queued, streams)?;
                }
                break;
            }
            self.next_packet_number =
                self.next_packet_number
                    .checked_add(1)
                    .ok_or(CoreError::InvalidState {
                        operation: "allocate packet number",
                    })?;
            if let Some(queued_frame) = queued.as_ref()
                && let Frame::StreamData(data) = queued_frame.frame()
            {
                if !connection_send.can_send(data.data.len(), queued_frame.retransmit_count() != 0)
                {
                    self.requeue_candidate(
                        queued.take().ok_or(CoreError::InvalidState {
                            operation: "restore blocked stream frame",
                        })?,
                        streams,
                    )?;
                    self.next_packet_number = self.next_packet_number.saturating_sub(1);
                    break;
                }
                if queued_frame.retransmit_count() == 0 {
                    connection_send.account_new_data(data.data.len());
                }
            }
            output.push_back(CoreOutput::Send(packet));
            if let Some(queued) = queued {
                if ack_eliciting {
                    self.record_sent(packet_number, encoded_len, queued, now, timers)?;
                }
            } else {
                self.ack_pending = false;
                self.ack_ready = false;
                timers.cancel_ack();
            }
        }
        Ok(())
    }

    fn take_data_candidate(&mut self, streams: &mut StreamManager) -> Option<Candidate> {
        self.pending_frames
            .pop_front()
            .map(Candidate::Frame)
            .or_else(|| streams.take_sendable().map(Candidate::Frame))
    }

    fn requeue_candidate(
        &mut self,
        queued: QueuedFrame,
        streams: &mut StreamManager,
    ) -> Result<(), CoreError> {
        let (frame, retransmit_count) = queued.into_parts();
        match frame {
            Frame::StreamData(data) => streams.requeue(&data, retransmit_count),
            frame => {
                self.pending_frames
                    .push_front(QueuedFrame::with_count(frame, retransmit_count));
                Ok(())
            }
        }
    }

    fn record_sent(
        &mut self,
        packet_number: PacketNumber,
        encoded_len: usize,
        queued: QueuedFrame,
        now: Duration,
        timers: &mut TimerState,
    ) -> Result<(), CoreError> {
        if matches!(
            queued.frame(),
            Frame::ClientHello(_) | Frame::ServerHello(_) | Frame::HandshakeAck(_)
        ) {
            return Ok(());
        }
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        let timer_id = timers.schedule(
            TimerEvent::Retransmit {
                packet_number,
                generation,
            },
            self.rtt.rto(),
        )?;
        self.congestion.on_sent(encoded_len);
        let retransmit_count = queued.retransmit_count();
        self.sent.insert(
            packet_number,
            SentPacket::new(
                packet_number,
                now,
                encoded_len,
                vec![queued],
                retransmit_count,
                timer_id,
                generation,
            ),
        );
        Ok(())
    }

    fn requeue_lost(
        &mut self,
        frames: Vec<QueuedFrame>,
        retransmit_count: u32,
        config: &ConnectionConfig,
        streams: &mut StreamManager,
    ) -> Result<(), CoreError> {
        let next_count = retransmit_count.saturating_add(1);
        if next_count > config.max_retransmissions {
            return Err(CoreError::RetransmissionLimit);
        }
        for queued in frames.into_iter().rev() {
            let (frame, _) = queued.into_parts();
            match frame {
                Frame::StreamData(data) => streams.requeue(&data, next_count)?,
                frame => self
                    .pending_frames
                    .push_front(QueuedFrame::with_count(frame, next_count)),
            }
        }
        Ok(())
    }
}

enum Candidate {
    Ack(AckFrame),
    Frame(QueuedFrame),
}

fn packet_type(frame: &Frame, state: ConnectionState) -> PacketType {
    match frame {
        Frame::ClientHello(_) => PacketType::Initial,
        Frame::HandshakeAck(_) | Frame::ServerHello(_) => PacketType::Handshake,
        Frame::ConnectionClose(_) => PacketType::Close,
        _ if state == ConnectionState::Handshaking => PacketType::Handshake,
        _ => PacketType::Data,
    }
}
