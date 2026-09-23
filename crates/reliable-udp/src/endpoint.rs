use std::{net::SocketAddr, sync::Arc};

use reliable_core::ConnectionConfig;
use tokio::sync::{Mutex, Notify, mpsc};

use crate::{
    error::EndpointError,
    event_loop::EventLoop,
    handle::{EndpointHandle, EndpointInner},
    retry::RetryConfig,
    socket,
};

#[derive(Debug, Clone)]
pub struct EndpointConfig {
    pub bind_addr: SocketAddr,
    pub connection: ConnectionConfig,
    pub command_capacity: usize,
    pub accept_capacity: usize,
    pub max_connections: usize,
    pub max_send_batch: usize,
    pub retry: RetryConfig,
}

impl EndpointConfig {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            connection: ConnectionConfig::default(),
            command_capacity: 1024,
            accept_capacity: 64,
            max_connections: 1024,
            max_send_batch: 64,
            retry: RetryConfig::default(),
        }
    }

    fn validate(&mut self) -> Result<(), EndpointError> {
        self.connection
            .validate()
            .map_err(EndpointError::InvalidConfig)?;
        self.retry.prepare().map_err(EndpointError::from)?;
        if self.command_capacity == 0 {
            return Err(EndpointError::InvalidCapacity {
                field: "command_capacity",
            });
        }
        if self.accept_capacity == 0 {
            return Err(EndpointError::InvalidCapacity {
                field: "accept_capacity",
            });
        }
        if self.max_connections == 0 {
            return Err(EndpointError::InvalidCapacity {
                field: "max_connections",
            });
        }
        if self.max_send_batch == 0 {
            return Err(EndpointError::InvalidCapacity {
                field: "max_send_batch",
            });
        }
        Ok(())
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::new(SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

pub struct Endpoint {
    handle: EndpointHandle,
    accept_rx: Arc<Mutex<mpsc::Receiver<Result<crate::Connection, EndpointError>>>>,
}

impl Endpoint {
    pub async fn bind(config: EndpointConfig) -> Result<Self, EndpointError> {
        let udp_socket = socket::bind(config.bind_addr).await?;
        Self::from_socket(udp_socket, config).await
    }

    pub async fn from_socket(
        udp_socket: tokio::net::UdpSocket,
        mut config: EndpointConfig,
    ) -> Result<Self, EndpointError> {
        config.validate()?;
        let local_addr = udp_socket.local_addr()?;
        let (command_tx, command_rx) = mpsc::channel(config.command_capacity);
        let (accept_tx, accept_rx) = mpsc::channel(config.accept_capacity);
        let command_notify = Arc::new(Notify::new());
        let inner = Arc::new(EndpointInner {
            command_tx,
            command_notify: Arc::clone(&command_notify),
            max_write_size: config.connection.max_send_buffer,
            local_addr,
        });
        let handle = EndpointHandle::new(Arc::clone(&inner));
        let event_loop = EventLoop::new(udp_socket, command_rx, accept_tx, inner, config);
        tokio::spawn(event_loop.run());
        Ok(Self {
            handle,
            accept_rx: Arc::new(Mutex::new(accept_rx)),
        })
    }

    pub fn handle(&self) -> EndpointHandle {
        self.handle.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.handle.local_addr()
    }

    pub async fn accept(&self) -> Result<crate::Connection, EndpointError> {
        let mut receiver = self.accept_rx.lock().await;
        receiver.recv().await.ok_or(EndpointError::Closed)?
    }

    pub async fn shutdown(&self) -> Result<(), EndpointError> {
        self.handle.shutdown().await
    }
}
