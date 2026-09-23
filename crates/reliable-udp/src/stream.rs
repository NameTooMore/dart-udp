use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use reliable_core::ReadResult;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use udp_protocol::StreamId;

use crate::{
    error::StreamError,
    handle::{Command, Connection},
    wakeup::PendingCommand,
};

pub struct ReliableStream {
    connection: Connection,
    id: StreamId,
    read_eof: bool,
    write_closed: bool,
    shutdown_requested: bool,
    read_command: Option<PendingCommand>,
    read_response: Option<oneshot::Receiver<Result<ReadResult, StreamError>>>,
    write_command: Option<PendingCommand>,
    write_response: Option<oneshot::Receiver<Result<usize, StreamError>>>,
    flush_command: Option<PendingCommand>,
    flush_response: Option<oneshot::Receiver<Result<(), StreamError>>>,
}

impl ReliableStream {
    pub(crate) fn new(connection: Connection, id: StreamId) -> Self {
        Self {
            connection,
            id,
            read_eof: false,
            write_closed: false,
            shutdown_requested: false,
            read_command: None,
            read_response: None,
            write_command: None,
            write_response: None,
            flush_command: None,
            flush_response: None,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.id
    }

    pub async fn shutdown(&mut self) -> Result<(), StreamError> {
        if self.write_closed {
            return Ok(());
        }
        if self.write_command.is_some()
            || self.write_response.is_some()
            || self.flush_command.is_some()
            || self.flush_response.is_some()
        {
            return Err(StreamError::InvalidState(
                "stream has a pending I/O operation",
            ));
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.connection
            .send(Command::Write {
                connection_id: self.connection.connection_id(),
                stream_id: self.id,
                data: Vec::new(),
                fin: true,
                response: response_tx,
            })
            .await?;
        response_rx
            .await
            .map_err(|_| StreamError::ResponseChannelClosed)??;
        self.write_closed = true;
        Ok(())
    }

    fn start_read(&mut self, max_len: usize) {
        let (response_tx, response_rx) = oneshot::channel();
        self.read_response = Some(response_rx);
        self.read_command = Some(PendingCommand::new(
            Command::Read {
                connection_id: self.connection.connection_id(),
                stream_id: self.id,
                max_len,
                response: response_tx,
            },
            self.connection.inner.command_notify.clone(),
        ));
    }

    fn start_write(&mut self, data: &[u8], fin: bool) {
        let (response_tx, response_rx) = oneshot::channel();
        self.write_response = Some(response_rx);
        self.write_command = Some(PendingCommand::new(
            Command::Write {
                connection_id: self.connection.connection_id(),
                stream_id: self.id,
                data: data.to_vec(),
                fin,
                response: response_tx,
            },
            self.connection.inner.command_notify.clone(),
        ));
    }

    fn start_flush(&mut self) {
        let (response_tx, response_rx) = oneshot::channel();
        self.flush_response = Some(response_rx);
        self.flush_command = Some(PendingCommand::new(
            Command::Flush {
                connection_id: self.connection.connection_id(),
                response: response_tx,
            },
            self.connection.inner.command_notify.clone(),
        ));
    }

    fn poll_read_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReadResult, StreamError>> {
        if let Some(command) = self.read_command.as_mut() {
            match command.poll(cx, &self.connection.inner.command_tx) {
                Poll::Ready(Ok(())) => self.read_command = None,
                Poll::Ready(Err(error)) => {
                    self.read_command = None;
                    self.read_response = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let response = self
            .read_response
            .as_mut()
            .expect("read response must exist while reading");
        match Pin::new(response).poll(cx) {
            Poll::Ready(Ok(result)) => {
                self.read_response = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => {
                self.read_response = None;
                Poll::Ready(Err(StreamError::ResponseChannelClosed))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_response(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, StreamError>> {
        if let Some(command) = self.write_command.as_mut() {
            match command.poll(cx, &self.connection.inner.command_tx) {
                Poll::Ready(Ok(())) => self.write_command = None,
                Poll::Ready(Err(error)) => {
                    self.write_command = None;
                    self.write_response = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let response = self
            .write_response
            .as_mut()
            .expect("write response must exist while writing");
        let result = match Pin::new(response).poll(cx) {
            Poll::Ready(Ok(result)) => result,
            Poll::Ready(Err(_)) => Err(StreamError::ResponseChannelClosed),
            Poll::Pending => return Poll::Pending,
        };
        self.write_response = None;
        if self.shutdown_requested && result.is_ok() {
            self.write_closed = true;
        }
        Poll::Ready(result)
    }

    fn poll_flush_response(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if let Some(command) = self.flush_command.as_mut() {
            match command.poll(cx, &self.connection.inner.command_tx) {
                Poll::Ready(Ok(())) => self.flush_command = None,
                Poll::Ready(Err(error)) => {
                    self.flush_command = None;
                    self.flush_response = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let response = self
            .flush_response
            .as_mut()
            .expect("flush response must exist while flushing");
        let result = match Pin::new(response).poll(cx) {
            Poll::Ready(Ok(result)) => result,
            Poll::Ready(Err(_)) => Err(StreamError::ResponseChannelClosed),
            Poll::Pending => return Poll::Pending,
        };
        self.flush_response = None;
        Poll::Ready(result)
    }
}

impl AsyncRead for ReliableStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_response.is_none() && self.read_command.is_none() {
            self.start_read(buf.remaining());
        }
        match self.poll_read_response(cx) {
            Poll::Ready(Ok(result)) => {
                if !result.data.is_empty() {
                    buf.put_slice(&result.data);
                }
                if result.eof {
                    self.read_eof = true;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(to_io_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ReliableStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed || self.shutdown_requested {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream write side is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_response.is_none() && self.write_command.is_none() {
            let amount = buf.len().min(self.connection.inner.max_write_size.max(1));
            self.start_write(&buf[..amount], false);
        }
        match self.poll_write_response(cx) {
            Poll::Ready(Ok(amount)) => Poll::Ready(Ok(amount)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(to_io_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_response.is_some() || self.write_command.is_some() {
            match self.poll_write_response(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(to_io_error(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.flush_response.is_none() && self.flush_command.is_none() {
            self.start_flush();
        }
        match self.poll_flush_response(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(to_io_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if self.write_response.is_some() || self.write_command.is_some() {
            if !self.shutdown_requested {
                match self.poll_write_response(cx) {
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(to_io_error(error))),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match self.poll_write_response(cx) {
                    Poll::Ready(Ok(_)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(to_io_error(error))),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        self.shutdown_requested = true;
        self.start_write(&[], true);
        match self.poll_write_response(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(to_io_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn to_io_error(error: StreamError) -> io::Error {
    io::Error::other(error)
}
