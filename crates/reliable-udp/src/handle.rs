use std::{net::SocketAddr, sync::Arc};

use reliable_core::ReadResult;
use tokio::sync::{Notify, mpsc, oneshot};
use udp_protocol::{ConnectionId, StreamId};

use crate::{
    error::{ConnectError, EndpointError, StreamError},
    path::PathBinding,
    stream::ReliableStream,
};

pub(crate) struct EndpointInner {
    pub(crate) command_tx: mpsc::Sender<Command>,
    pub(crate) command_notify: Arc<Notify>,
    pub(crate) max_write_size: usize,
    pub(crate) local_addr: SocketAddr,
}

#[derive(Clone)]
pub struct EndpointHandle {
    pub(crate) inner: Arc<EndpointInner>,
}

impl EndpointHandle {
    pub(crate) fn new(inner: Arc<EndpointInner>) -> Self {
        Self { inner }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    pub async fn connect(&self, peer: SocketAddr) -> Result<Connection, ConnectError> {
        self.connect_path(PathBinding::new(peer)).await
    }

    pub async fn connect_path(&self, path: PathBinding) -> Result<Connection, ConnectError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::Connect {
                path,
                response: response_tx,
            })
            .await
            .map_err(|_| ConnectError::CommandChannelClosed)?;
        response_rx
            .await
            .map_err(|_| ConnectError::CommandChannelClosed)?
    }

    pub async fn shutdown(&self) -> Result<(), EndpointError> {
        self.inner
            .command_tx
            .send(Command::Shutdown)
            .await
            .map_err(|_| EndpointError::CommandChannelClosed)
    }
}

#[derive(Clone)]
pub struct Connection {
    pub(crate) inner: Arc<EndpointInner>,
    id: ConnectionId,
}

impl Connection {
    pub(crate) fn new(inner: Arc<EndpointInner>, id: ConnectionId) -> Self {
        Self { inner, id }
    }

    pub fn connection_id(&self) -> ConnectionId {
        self.id
    }

    pub async fn open_stream(&self) -> Result<ReliableStream, StreamError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::OpenStream {
            connection_id: self.id,
            response: response_tx,
        })
        .await?;
        let stream_id = response_rx
            .await
            .map_err(|_| StreamError::ResponseChannelClosed)??;
        Ok(ReliableStream::new(self.clone(), stream_id))
    }

    pub async fn accept_stream(&self) -> Result<ReliableStream, StreamError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::AcceptStream {
            connection_id: self.id,
            response: response_tx,
        })
        .await?;
        let stream_id = response_rx
            .await
            .map_err(|_| StreamError::ResponseChannelClosed)??;
        Ok(ReliableStream::new(self.clone(), stream_id))
    }

    pub async fn close(
        &self,
        error_code: u32,
        reason: impl Into<String>,
    ) -> Result<(), ConnectError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::Close {
                connection_id: self.id,
                error_code,
                reason: reason.into(),
                response: response_tx,
            })
            .await
            .map_err(|_| ConnectError::CommandChannelClosed)?;
        response_rx
            .await
            .map_err(|_| ConnectError::CommandChannelClosed)?
    }

    pub(crate) async fn send(&self, command: Command) -> Result<(), StreamError> {
        self.inner
            .command_tx
            .send(command)
            .await
            .map_err(|_| StreamError::CommandChannelClosed)
    }
}

pub(crate) enum Command {
    Connect {
        path: PathBinding,
        response: oneshot::Sender<Result<Connection, ConnectError>>,
    },
    OpenStream {
        connection_id: ConnectionId,
        response: oneshot::Sender<Result<StreamId, StreamError>>,
    },
    AcceptStream {
        connection_id: ConnectionId,
        response: oneshot::Sender<Result<StreamId, StreamError>>,
    },
    Read {
        connection_id: ConnectionId,
        stream_id: StreamId,
        max_len: usize,
        response: oneshot::Sender<Result<ReadResult, StreamError>>,
    },
    Write {
        connection_id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
        fin: bool,
        response: oneshot::Sender<Result<usize, StreamError>>,
    },
    Flush {
        connection_id: ConnectionId,
        response: oneshot::Sender<Result<(), StreamError>>,
    },
    Close {
        connection_id: ConnectionId,
        error_code: u32,
        reason: String,
        response: oneshot::Sender<Result<(), ConnectError>>,
    },
    Shutdown,
}
