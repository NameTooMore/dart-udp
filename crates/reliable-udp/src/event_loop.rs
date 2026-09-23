use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
    time::SystemTime,
};

use reliable_core::{
    Connection as CoreConnection, ConnectionState, CoreError, CoreOutput, ReadResult,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::yield_now,
    time::{self, Instant},
};
use udp_protocol::{
    ClientHello, ConnectionId, Frame, Packet, PacketFlags, PacketNumber, PacketType, Retry,
    StreamId,
};

use crate::{
    endpoint::EndpointConfig,
    error::{ConnectError, EndpointError, StreamError},
    handle::{Command, Connection, EndpointInner},
    path::PathBinding,
};

pub(crate) struct EventLoop {
    socket: Arc<UdpSocket>,
    command_rx: mpsc::Receiver<Command>,
    accept_tx: mpsc::Sender<Result<Connection, EndpointError>>,
    inner: Arc<EndpointInner>,
    config: EndpointConfig,
    connections: HashMap<ConnectionId, ConnectionRuntime>,
}

struct ConnectionRuntime {
    core: CoreConnection,
    path: PathBinding,
    is_server: bool,
    last_advanced_at: Instant,
    connect_waiter: Option<oneshot::Sender<Result<Connection, ConnectError>>>,
    accepted: bool,
    incoming_streams: VecDeque<StreamId>,
    pending_accepts: VecDeque<oneshot::Sender<Result<StreamId, StreamError>>>,
    pending_reads: HashMap<StreamId, PendingRead>,
    pending_writes: HashMap<StreamId, PendingWrite>,
    pending_flushes: Vec<oneshot::Sender<Result<(), StreamError>>>,
}

struct PendingRead {
    max_len: usize,
    response: oneshot::Sender<Result<ReadResult, StreamError>>,
}

struct PendingWrite {
    data: Vec<u8>,
    fin: bool,
    response: oneshot::Sender<Result<usize, StreamError>>,
}

impl EventLoop {
    pub(crate) fn new(
        socket: UdpSocket,
        command_rx: mpsc::Receiver<Command>,
        accept_tx: mpsc::Sender<Result<Connection, EndpointError>>,
        inner: Arc<EndpointInner>,
        config: EndpointConfig,
    ) -> Self {
        Self {
            socket: Arc::new(socket),
            command_rx,
            accept_tx,
            inner,
            config,
            connections: HashMap::new(),
        }
    }

    pub(crate) async fn run(mut self) {
        let mut recv_buf = vec![0_u8; self.config.connection.max_datagram_size.saturating_add(1)];
        loop {
            if self.advance_time().await.is_err() {
                self.close_all();
                return;
            }
            let now = Instant::now();
            let deadline = match self.next_deadline() {
                Ok(Some(deadline)) => deadline,
                Ok(None) => now + Duration::from_secs(3600),
                Err(_) => {
                    self.close_all();
                    return;
                }
            };
            let sleep = time::sleep_until(deadline);
            tokio::pin!(sleep);
            tokio::select! {
                received = self.socket.recv_from(&mut recv_buf) => {
                    match received {
                        Ok((length, peer)) => {
                            if self.handle_datagram(&recv_buf[..length], peer).await.is_err() {
                                self.close_all();
                                return;
                            }
                        }
                        Err(_) => {
                            self.close_all();
                            return;
                        }
                    }
                }
                command = self.command_rx.recv() => {
                    self.inner.command_notify.notify_waiters();
                    match command {
                        Some(Command::Shutdown) | None => {
                            self.close_all();
                            return;
                        }
                        Some(command) => {
                            if self.handle_command(command).await.is_err() {
                                self.close_all();
                                return;
                            }
                        }
                    }
                }
                _ = &mut sleep => {}
            }
        }
    }

    async fn advance_time(&mut self) -> Result<(), EndpointError> {
        let now = Instant::now();
        let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for id in ids {
            let result = if let Some(runtime) = self.connections.get_mut(&id) {
                let elapsed = now.saturating_duration_since(runtime.last_advanced_at);
                runtime.last_advanced_at = now;
                runtime.core.advance_time(elapsed)
            } else {
                continue;
            };
            if result.is_err() {
                self.remove_runtime(id, 4);
                continue;
            }
            self.process_outputs(id).await?;
        }
        Ok(())
    }

    fn next_deadline(&self) -> Result<Option<Instant>, EndpointError> {
        self.connections
            .values()
            .try_fold(None, |earliest, runtime| {
                let deadline = runtime
                    .core
                    .next_deadline()
                    .map_err(EndpointError::Core)?
                    .map(|delay| runtime.last_advanced_at + delay);
                Ok(match (earliest, deadline) {
                    (None, value) => value,
                    (value, None) => value,
                    (Some(left), Some(right)) => Some(left.min(right)),
                })
            })
    }

    async fn handle_datagram(
        &mut self,
        bytes: &[u8],
        peer: SocketAddr,
    ) -> Result<(), EndpointError> {
        if bytes.len() > self.config.connection.max_datagram_size {
            return Ok(());
        }
        let id =
            match udp_protocol::peek_connection_id(bytes, self.config.connection.max_datagram_size)
            {
                Ok(id) => id,
                Err(_) => return Ok(()),
            };
        if let Some(runtime) = self.connections.get(&id)
            && runtime.path.peer() != peer
        {
            return Ok(());
        }
        if !self.connections.contains_key(&id) {
            let packet =
                match Packet::decode_with_limit(bytes, self.config.connection.max_datagram_size) {
                    Ok(packet) => packet,
                    Err(_) => return Ok(()),
                };
            if packet.packet_type != PacketType::Initial {
                return Ok(());
            }
            let [Frame::ClientHello(hello)] = packet.frames.as_slice() else {
                return Ok(());
            };
            if self.config.retry.enabled && !self.cookie_is_valid(peer, id, hello) {
                self.send_retry(peer, id, hello, bytes.len()).await?;
                return Ok(());
            }
            if self.connections.len() >= self.config.max_connections {
                return Ok(());
            }
            let core = match CoreConnection::new_server(id, self.config.connection.clone()) {
                Ok(core) => core,
                Err(_) => return Ok(()),
            };
            self.connections.insert(
                id,
                ConnectionRuntime {
                    core,
                    path: PathBinding::new(peer),
                    is_server: true,
                    last_advanced_at: Instant::now(),
                    connect_waiter: None,
                    accepted: false,
                    incoming_streams: VecDeque::new(),
                    pending_accepts: VecDeque::new(),
                    pending_reads: HashMap::new(),
                    pending_writes: HashMap::new(),
                    pending_flushes: Vec::new(),
                },
            );
        }
        let result = self
            .connections
            .get_mut(&id)
            .map(|runtime| runtime.core.on_datagram_bytes(bytes));
        if let Some(Err(error)) = result
            && !matches!(
                error,
                CoreError::Protocol(_) | CoreError::ConnectionIdMismatch
            )
            && let Some(runtime) = self.connections.get_mut(&id)
        {
            let _ = runtime.core.close(4, "invalid datagram");
        }
        self.process_outputs(id).await
    }

    async fn handle_command(&mut self, command: Command) -> Result<(), EndpointError> {
        match command {
            Command::Connect { path, response } => self.handle_connect(path, response).await,
            Command::OpenStream {
                connection_id,
                response,
            } => {
                let result = self.with_runtime(connection_id, |runtime| {
                    runtime.core.open_stream().map_err(StreamError::Core)
                });
                send_response(response, result);
                self.process_outputs(connection_id).await
            }
            Command::AcceptStream {
                connection_id,
                response,
            } => {
                if let Some(runtime) = self.connections.get_mut(&connection_id) {
                    if let Some(stream_id) = runtime.incoming_streams.pop_front() {
                        let _ = response.send(Ok(stream_id));
                    } else {
                        runtime.pending_accepts.push_back(response);
                    }
                } else {
                    let _ = response.send(Err(StreamError::ConnectionClosed { error_code: 0 }));
                }
                Ok(())
            }
            Command::Read {
                connection_id,
                stream_id,
                max_len,
                response,
            } => {
                if let Some(runtime) = self.connections.get_mut(&connection_id) {
                    match runtime.core.read_stream(stream_id, max_len) {
                        Ok(result) if !result.data.is_empty() || result.eof => {
                            let _ = response.send(Ok(result));
                        }
                        Ok(_) => {
                            runtime
                                .pending_reads
                                .insert(stream_id, PendingRead { max_len, response });
                        }
                        Err(error) => {
                            let _ = response.send(Err(StreamError::Core(error)));
                        }
                    }
                } else {
                    let _ = response.send(Err(StreamError::ConnectionClosed { error_code: 0 }));
                }
                self.process_outputs(connection_id).await
            }
            Command::Write {
                connection_id,
                stream_id,
                data,
                fin,
                response,
            } => {
                if let Some(runtime) = self.connections.get_mut(&connection_id) {
                    Self::try_write(runtime, stream_id, data, fin, response);
                } else {
                    let _ = response.send(Err(StreamError::ConnectionClosed { error_code: 0 }));
                }
                self.process_outputs(connection_id).await
            }
            Command::Flush {
                connection_id,
                response,
            } => {
                if let Some(runtime) = self.connections.get_mut(&connection_id) {
                    if runtime.core.is_reliably_flushed() {
                        let _ = response.send(Ok(()));
                    } else {
                        runtime.pending_flushes.push(response);
                    }
                } else {
                    let _ = response.send(Err(StreamError::ConnectionClosed { error_code: 0 }));
                }
                self.process_outputs(connection_id).await
            }
            Command::Close {
                connection_id,
                error_code,
                reason,
                response,
            } => {
                let result = if let Some(runtime) = self.connections.get_mut(&connection_id) {
                    runtime
                        .core
                        .close(error_code, reason)
                        .map_err(ConnectError::Core)
                } else {
                    Err(ConnectError::ConnectionClosed { error_code: 0 })
                };
                let _ = response.send(result);
                self.process_outputs(connection_id).await
            }
            Command::Shutdown => Ok(()),
        }
    }

    async fn handle_connect(
        &mut self,
        path: PathBinding,
        response: oneshot::Sender<Result<Connection, ConnectError>>,
    ) -> Result<(), EndpointError> {
        if self.connections.len() >= self.config.max_connections {
            let _ = response.send(Err(ConnectError::Endpoint(EndpointError::ConnectionLimit)));
            return Ok(());
        }
        let id = match self.allocate_connection_id() {
            Ok(id) => id,
            Err(error) => {
                let _ = response.send(Err(ConnectError::Endpoint(error)));
                return Ok(());
            }
        };
        let core = match CoreConnection::new_client(id, self.config.connection.clone()) {
            Ok(core) => core,
            Err(error) => {
                let _ = response.send(Err(ConnectError::Core(error)));
                return Ok(());
            }
        };
        self.connections.insert(
            id,
            ConnectionRuntime {
                core,
                path,
                is_server: false,
                last_advanced_at: Instant::now(),
                connect_waiter: Some(response),
                accepted: true,
                incoming_streams: VecDeque::new(),
                pending_accepts: VecDeque::new(),
                pending_reads: HashMap::new(),
                pending_writes: HashMap::new(),
                pending_flushes: Vec::new(),
            },
        );
        self.process_outputs(id).await
    }

    fn allocate_connection_id(&self) -> Result<ConnectionId, EndpointError> {
        loop {
            let mut bytes = [0_u8; 8];
            getrandom::fill(&mut bytes).map_err(|_| EndpointError::RandomnessUnavailable)?;
            let raw = u64::from_ne_bytes(bytes);
            if raw == 0 {
                continue;
            }
            let id = ConnectionId::new(raw);
            if !self.connections.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    async fn process_outputs(&mut self, connection_id: ConnectionId) -> Result<(), EndpointError> {
        let mut sent = 0;
        loop {
            let outputs = match self.connections.get_mut(&connection_id) {
                Some(runtime) => runtime.core.drain_output(),
                None => return Ok(()),
            };
            if outputs.is_empty() {
                if !self.service_pending_writes(connection_id) {
                    break;
                }
                continue;
            }
            for output in outputs {
                match output {
                    CoreOutput::Send(packet) => {
                        let bytes = self
                            .connections
                            .get(&connection_id)
                            .ok_or(EndpointError::Closed)?
                            .core
                            .encode_packet(&packet)
                            .map_err(EndpointError::Core)?;
                        let peer = self
                            .connections
                            .get(&connection_id)
                            .map(|runtime| runtime.path.peer())
                            .ok_or(EndpointError::Closed)?;
                        let written = self.socket.send_to(&bytes, peer).await?;
                        if written != bytes.len() {
                            return Err(EndpointError::Io(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "UDP socket wrote a partial datagram",
                            )));
                        }
                        sent += 1;
                        if sent >= self.config.max_send_batch {
                            sent = 0;
                            yield_now().await;
                        }
                    }
                    CoreOutput::StreamOpened(stream_id) => {
                        self.on_stream_opened(connection_id, stream_id)
                    }
                    CoreOutput::StreamReadable(stream_id)
                    | CoreOutput::StreamFinished(stream_id) => {
                        self.service_read(connection_id, stream_id)
                    }
                    CoreOutput::StreamReset {
                        stream_id,
                        error_code,
                    } => self.fail_stream_waiters(connection_id, stream_id, error_code),
                    CoreOutput::ConnectionStateChanged(ConnectionState::Established) => {
                        self.on_established(connection_id)?;
                    }
                    CoreOutput::ConnectionStateChanged(_) => {}
                    CoreOutput::ConnectionClosed { error_code } => {
                        self.fail_connection_waiters(connection_id, error_code);
                    }
                }
            }
        }
        self.service_flushes(connection_id);
        if self
            .connections
            .get(&connection_id)
            .is_some_and(|runtime| runtime.core.state() == ConnectionState::Closed)
        {
            self.remove_runtime(connection_id, 0);
        }
        Ok(())
    }

    fn on_established(&mut self, connection_id: ConnectionId) -> Result<(), EndpointError> {
        let Some(runtime) = self.connections.get(&connection_id) else {
            return Ok(());
        };
        let should_accept = runtime.is_server && !runtime.accepted;
        if should_accept {
            let connection = Connection::new(Arc::clone(&self.inner), connection_id);
            match self.accept_tx.try_send(Ok(connection)) {
                Ok(()) => {
                    if let Some(runtime) = self.connections.get_mut(&connection_id) {
                        runtime.accepted = true;
                    }
                }
                Err(mpsc::error::TrySendError::Full(_))
                | Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.remove_runtime(connection_id, 0);
                    return Ok(());
                }
            }
        }
        if let Some(runtime) = self.connections.get_mut(&connection_id)
            && let Some(response) = runtime.connect_waiter.take()
        {
            let _ = response.send(Ok(Connection::new(Arc::clone(&self.inner), connection_id)));
        }
        Ok(())
    }

    fn on_stream_opened(&mut self, connection_id: ConnectionId, stream_id: StreamId) {
        let Some(runtime) = self.connections.get_mut(&connection_id) else {
            return;
        };
        if let Some(response) = runtime.pending_accepts.pop_front() {
            let _ = response.send(Ok(stream_id));
        } else {
            runtime.incoming_streams.push_back(stream_id);
        }
    }

    fn service_read(&mut self, connection_id: ConnectionId, stream_id: StreamId) {
        let Some(runtime) = self.connections.get_mut(&connection_id) else {
            return;
        };
        let Some(pending) = runtime.pending_reads.remove(&stream_id) else {
            return;
        };
        match runtime.core.read_stream(stream_id, pending.max_len) {
            Ok(result) if !result.data.is_empty() || result.eof => {
                let _ = pending.response.send(Ok(result));
            }
            Ok(_) => {
                runtime.pending_reads.insert(stream_id, pending);
            }
            Err(error) => {
                let _ = pending.response.send(Err(StreamError::Core(error)));
            }
        }
    }

    fn service_pending_writes(&mut self, connection_id: ConnectionId) -> bool {
        let stream_ids = self
            .connections
            .get(&connection_id)
            .map(|runtime| runtime.pending_writes.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut changed = false;
        for stream_id in stream_ids {
            let Some(runtime) = self.connections.get_mut(&connection_id) else {
                break;
            };
            let Some(pending) = runtime.pending_writes.remove(&stream_id) else {
                continue;
            };
            match runtime
                .core
                .write_stream(stream_id, &pending.data, pending.fin)
            {
                Ok(amount) => {
                    let _ = pending.response.send(Ok(amount));
                    changed = true;
                }
                Err(CoreError::SendBufferFull) => {
                    runtime.pending_writes.insert(stream_id, pending);
                }
                Err(error) => {
                    let _ = pending.response.send(Err(StreamError::Core(error)));
                    changed = true;
                }
            }
        }
        changed
    }

    fn try_write(
        runtime: &mut ConnectionRuntime,
        stream_id: StreamId,
        data: Vec<u8>,
        fin: bool,
        response: oneshot::Sender<Result<usize, StreamError>>,
    ) {
        match runtime.core.write_stream(stream_id, &data, fin) {
            Ok(amount) => {
                let _ = response.send(Ok(amount));
            }
            Err(CoreError::SendBufferFull) => {
                runtime.pending_writes.insert(
                    stream_id,
                    PendingWrite {
                        data,
                        fin,
                        response,
                    },
                );
            }
            Err(error) => {
                let _ = response.send(Err(StreamError::Core(error)));
            }
        }
    }

    fn fail_stream_waiters(
        &mut self,
        connection_id: ConnectionId,
        stream_id: StreamId,
        error_code: u32,
    ) {
        if let Some(runtime) = self.connections.get_mut(&connection_id) {
            if let Some(pending) = runtime.pending_reads.remove(&stream_id) {
                let _ = pending
                    .response
                    .send(Err(StreamError::ConnectionClosed { error_code }));
            }
            if let Some(pending) = runtime.pending_writes.remove(&stream_id) {
                let _ = pending
                    .response
                    .send(Err(StreamError::ConnectionClosed { error_code }));
            }
        }
    }

    fn fail_connection_waiters(&mut self, connection_id: ConnectionId, error_code: u32) {
        if let Some(runtime) = self.connections.get_mut(&connection_id) {
            for (_, pending) in runtime.pending_reads.drain() {
                let _ = pending
                    .response
                    .send(Err(StreamError::ConnectionClosed { error_code }));
            }
            for (_, pending) in runtime.pending_writes.drain() {
                let _ = pending
                    .response
                    .send(Err(StreamError::ConnectionClosed { error_code }));
            }
            for response in runtime.pending_accepts.drain(..) {
                let _ = response.send(Err(StreamError::ConnectionClosed { error_code }));
            }
            if let Some(response) = runtime.connect_waiter.take() {
                let _ = response.send(Err(ConnectError::ConnectionClosed { error_code }));
            }
            for response in runtime.pending_flushes.drain(..) {
                let _ = response.send(Err(StreamError::ConnectionClosed { error_code }));
            }
        }
    }

    fn service_flushes(&mut self, connection_id: ConnectionId) {
        let Some(runtime) = self.connections.get_mut(&connection_id) else {
            return;
        };
        if !runtime.core.is_reliably_flushed() {
            return;
        }
        for response in runtime.pending_flushes.drain(..) {
            let _ = response.send(Ok(()));
        }
    }

    fn cookie_is_valid(&self, peer: SocketAddr, id: ConnectionId, hello: &ClientHello) -> bool {
        let Some(secret) = self.config.retry.cookie_secret.as_ref() else {
            return false;
        };
        crate::retry::validate_cookie(
            secret,
            &hello.cookie,
            SystemTime::now(),
            crate::retry::CookieContext {
                peer,
                connection_id: id,
                client_nonce: &hello.client_nonce,
                cookie_ttl: self.config.retry.cookie_ttl,
                clock_skew: self.config.retry.clock_skew,
            },
        )
    }

    async fn send_retry(
        &self,
        peer: SocketAddr,
        id: ConnectionId,
        hello: &ClientHello,
        received_len: usize,
    ) -> Result<(), EndpointError> {
        let Some(secret) = self.config.retry.cookie_secret.as_ref() else {
            return Ok(());
        };
        let cookie =
            crate::retry::issue_cookie(secret, peer, id, &hello.client_nonce, SystemTime::now())
                .map_err(|_| EndpointError::RandomnessUnavailable)?;
        let packet = Packet::new(
            PacketType::Retry,
            PacketFlags::empty(),
            id,
            // Retry 不属于服务端有状态传输的包号空间，避免与随后 ServerHello 的 0 冲突。
            PacketNumber::new(u64::MAX),
            vec![Frame::Retry(Retry { cookie })],
        );
        let bytes = packet
            .encode_with_limit(self.config.connection.max_datagram_size)
            .map_err(EndpointError::Protocol)?;
        if bytes.len() > received_len {
            return Ok(());
        }
        let written = self.socket.send_to(&bytes, peer).await?;
        if written != bytes.len() {
            return Err(EndpointError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "UDP socket wrote a partial datagram",
            )));
        }
        Ok(())
    }

    fn with_runtime<T>(
        &mut self,
        connection_id: ConnectionId,
        operation: impl FnOnce(&mut ConnectionRuntime) -> Result<T, StreamError>,
    ) -> Result<T, StreamError> {
        self.connections
            .get_mut(&connection_id)
            .map(operation)
            .unwrap_or(Err(StreamError::ConnectionClosed { error_code: 0 }))
    }

    fn remove_runtime(&mut self, connection_id: ConnectionId, error_code: u32) {
        let Some(mut runtime) = self.connections.remove(&connection_id) else {
            return;
        };
        for (_, pending) in runtime.pending_reads.drain() {
            let _ = pending
                .response
                .send(Err(StreamError::ConnectionClosed { error_code }));
        }
        for (_, pending) in runtime.pending_writes.drain() {
            let _ = pending
                .response
                .send(Err(StreamError::ConnectionClosed { error_code }));
        }
        for response in runtime.pending_flushes.drain(..) {
            let _ = response.send(Err(StreamError::ConnectionClosed { error_code }));
        }
        for response in runtime.pending_accepts.drain(..) {
            let _ = response.send(Err(StreamError::ConnectionClosed { error_code }));
        }
        if let Some(response) = runtime.connect_waiter.take() {
            let _ = response.send(Err(ConnectError::ConnectionClosed { error_code }));
        }
    }

    fn close_all(&mut self) {
        let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for id in ids {
            self.remove_runtime(id, 0);
        }
    }
}

fn send_response<T>(
    response: oneshot::Sender<Result<T, StreamError>>,
    result: Result<T, StreamError>,
) {
    let _ = response.send(result);
}
