use udp_protocol::{
    ClientHello, ConnectionId, CryptoRole, EphemeralKeyPair, Frame, HandshakeAck, PacketType,
    Retry, ServerHello, SessionKeys, derive_session_keys, handshake_transcript_hash,
};

use crate::{
    config::{ConnectionConfig, ConnectionRole},
    error::CoreError,
};

use super::{ConnectionState, timers::TimerState, transport::TransportState};

pub(crate) struct HandshakeState {
    connection_id: ConnectionId,
    key_pair: EphemeralKeyPair,
    local_nonce: [u8; 16],
    client_nonce: Option<[u8; 16]>,
    peer_client_nonce: Option<[u8; 16]>,
    peer_cookie: Vec<u8>,
    frame: Option<Frame>,
    transcript_hash: Option<[u8; 32]>,
    session_keys: Option<SessionKeys>,
    retries: u32,
    peer_max_streams: u32,
    peer_initial_stream_window: u64,
}

pub(crate) enum HandshakeTimeout {
    Retry,
    Close,
}

impl HandshakeState {
    pub(crate) fn new(
        connection_id: ConnectionId,
        config: &ConnectionConfig,
    ) -> Result<Self, CoreError> {
        let mut local_nonce = [0_u8; 16];
        getrandom::fill(&mut local_nonce).map_err(|_| CoreError::RandomnessUnavailable)?;
        Ok(Self {
            connection_id,
            key_pair: EphemeralKeyPair::generate()?,
            local_nonce,
            client_nonce: None,
            peer_client_nonce: None,
            peer_cookie: Vec::new(),
            frame: None,
            transcript_hash: None,
            session_keys: None,
            retries: 0,
            peer_max_streams: config.max_streams,
            peer_initial_stream_window: config.initial_stream_window,
        })
    }

    pub(crate) const fn peer_initial_stream_window(&self) -> u64 {
        self.peer_initial_stream_window
    }

    pub(crate) fn effective_max_streams(&self, config: &ConnectionConfig) -> u32 {
        config.max_streams.min(self.peer_max_streams)
    }

    pub(crate) fn session_keys(&self) -> Option<&SessionKeys> {
        self.session_keys.as_ref()
    }

    pub(crate) fn start_client(
        &mut self,
        config: &ConnectionConfig,
        transport: &mut TransportState,
        timers: &mut TimerState,
    ) -> Result<(), CoreError> {
        let frame = Frame::ClientHello(ClientHello {
            client_nonce: self.local_nonce,
            client_public_key: self.key_pair.public_key(),
            max_datagram_size: config.max_datagram_size as u16,
            max_streams: config.max_streams,
            initial_connection_window: config.initial_connection_window,
            initial_stream_window: config.initial_stream_window,
            cookie: config.handshake_cookie.clone(),
        });
        self.client_nonce = Some(self.local_nonce);
        transport.queue(frame.clone());
        self.frame = Some(frame);
        timers.schedule_handshake(config.handshake_timeout)
    }

    pub(crate) fn set_frame(&mut self, frame: Frame) {
        self.frame = Some(frame);
    }

    pub(crate) fn receive_client_hello(
        &mut self,
        role: ConnectionRole,
        packet_type: PacketType,
        hello: ClientHello,
        state: ConnectionState,
        config: &mut ConnectionConfig,
    ) -> Result<(Frame, Option<ConnectionState>, Option<u64>), CoreError> {
        if role != ConnectionRole::Server || packet_type != PacketType::Initial {
            return Err(CoreError::InvalidPacketType);
        }
        if let Some(previous_nonce) = self.peer_client_nonce
            && previous_nonce != hello.client_nonce
        {
            return Err(CoreError::InvalidState {
                operation: "client nonce changed during handshake",
            });
        }
        self.peer_client_nonce = Some(hello.client_nonce);
        self.peer_cookie = hello.cookie.clone();
        self.peer_max_streams = self.peer_max_streams.min(hello.max_streams);
        self.peer_initial_stream_window = hello.initial_stream_window;
        let mut connection_max_offset = None;
        if state != ConnectionState::Established {
            connection_max_offset = Some(hello.initial_connection_window);
            config.max_datagram_size = config
                .max_datagram_size
                .min(hello.max_datagram_size as usize);
        }
        let transcript_hash = handshake_transcript_hash(
            self.connection_id,
            &hello.client_nonce,
            &self.local_nonce,
            &hello.client_public_key,
            &self.key_pair.public_key(),
        );
        let shared_secret = self.key_pair.agree(hello.client_public_key)?;
        let session_keys = derive_session_keys(&shared_secret, &transcript_hash)?;
        let server_finished = session_keys.finished_tag(CryptoRole::Server, &transcript_hash)?;
        self.transcript_hash = Some(transcript_hash);
        self.session_keys = Some(session_keys);
        let frame = Frame::ServerHello(ServerHello {
            server_nonce: self.local_nonce,
            server_public_key: self.key_pair.public_key(),
            server_finished,
            max_datagram_size: config.max_datagram_size as u16,
            max_streams: self.effective_max_streams(config),
            initial_connection_window: config.initial_connection_window,
            initial_stream_window: config.initial_stream_window,
            cookie: hello.cookie,
        });
        if state == ConnectionState::Idle {
            return Ok((
                frame,
                Some(ConnectionState::Handshaking),
                connection_max_offset,
            ));
        }
        Ok((frame, None, connection_max_offset))
    }

    pub(crate) fn receive_server_hello(
        &mut self,
        role: ConnectionRole,
        packet_type: PacketType,
        hello: ServerHello,
        state: ConnectionState,
        config: &mut ConnectionConfig,
    ) -> Result<(Frame, u64), CoreError> {
        if role != ConnectionRole::Client
            || packet_type != PacketType::Handshake
            || state != ConnectionState::Handshaking
        {
            return Err(CoreError::InvalidPacketType);
        }
        self.peer_cookie = hello.cookie.clone();
        self.peer_max_streams = self.peer_max_streams.min(hello.max_streams);
        self.peer_initial_stream_window = hello.initial_stream_window;
        config.max_datagram_size = config
            .max_datagram_size
            .min(hello.max_datagram_size as usize);
        let client_nonce = self.client_nonce.ok_or(CoreError::InvalidState {
            operation: "receive server hello before client hello",
        })?;
        let transcript_hash = handshake_transcript_hash(
            self.connection_id,
            &client_nonce,
            &hello.server_nonce,
            &self.key_pair.public_key(),
            &hello.server_public_key,
        );
        let shared_secret = self.key_pair.agree(hello.server_public_key)?;
        let session_keys = derive_session_keys(&shared_secret, &transcript_hash)?;
        session_keys.verify_finished(
            CryptoRole::Server,
            &transcript_hash,
            &hello.server_finished,
        )?;
        let client_finished = session_keys.finished_tag(CryptoRole::Client, &transcript_hash)?;
        self.transcript_hash = Some(transcript_hash);
        self.session_keys = Some(session_keys);
        let frame = Frame::HandshakeAck(HandshakeAck {
            cookie: hello.cookie,
            client_finished,
        });
        Ok((frame, hello.initial_connection_window))
    }

    pub(crate) fn receive_retry(
        &mut self,
        role: ConnectionRole,
        packet_type: PacketType,
        retry: Retry,
        state: ConnectionState,
        config: &mut ConnectionConfig,
    ) -> Result<Frame, CoreError> {
        if role != ConnectionRole::Client
            || packet_type != PacketType::Retry
            || state != ConnectionState::Handshaking
            || retry.cookie.is_empty()
            || retry.cookie.len() > udp_protocol::MAX_COOKIE_LEN
        {
            return Err(CoreError::InvalidPacketType);
        }
        if self.client_nonce.is_none() {
            return Err(CoreError::InvalidState {
                operation: "receive retry before client hello",
            });
        }
        config.handshake_cookie = retry.cookie;
        let frame = Frame::ClientHello(ClientHello {
            client_nonce: self.local_nonce,
            client_public_key: self.key_pair.public_key(),
            max_datagram_size: config.max_datagram_size as u16,
            max_streams: config.max_streams,
            initial_connection_window: config.initial_connection_window,
            initial_stream_window: config.initial_stream_window,
            cookie: config.handshake_cookie.clone(),
        });
        self.frame = Some(frame.clone());
        Ok(frame)
    }

    pub(crate) fn receive_handshake_ack(
        &mut self,
        role: ConnectionRole,
        packet_type: PacketType,
        ack: HandshakeAck,
        state: ConnectionState,
        timers: &mut TimerState,
    ) -> Result<ConnectionState, CoreError> {
        if role != ConnectionRole::Server
            || packet_type != PacketType::Handshake
            || state != ConnectionState::Handshaking
            || ack.cookie != self.peer_cookie
        {
            return Err(CoreError::InvalidPacketType);
        }
        let transcript_hash = self.transcript_hash.ok_or(CoreError::InvalidState {
            operation: "receive handshake acknowledgement before key exchange",
        })?;
        let session_keys = self.session_keys.as_ref().ok_or(CoreError::InvalidState {
            operation: "receive handshake acknowledgement without session keys",
        })?;
        session_keys.verify_finished(CryptoRole::Client, &transcript_hash, &ack.client_finished)?;
        timers.cancel_handshake();
        Ok(ConnectionState::Established)
    }

    pub(crate) fn on_timeout(
        &mut self,
        state: ConnectionState,
        config: &ConnectionConfig,
        transport: &mut TransportState,
        timers: &mut TimerState,
    ) -> Result<HandshakeTimeout, CoreError> {
        if state != ConnectionState::Handshaking {
            return Ok(HandshakeTimeout::Retry);
        }
        let Some(frame) = self.frame.clone() else {
            return Ok(HandshakeTimeout::Close);
        };
        if self.retries >= config.max_retransmissions {
            return Ok(HandshakeTimeout::Close);
        }
        self.retries = self.retries.saturating_add(1);
        transport.queue_front(frame);
        timers.schedule_handshake(config.handshake_timeout)?;
        Ok(HandshakeTimeout::Retry)
    }
}
