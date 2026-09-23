use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::sync::{Notify, mpsc};

use crate::{error::StreamError, handle::Command};

pub(crate) type WakeFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub(crate) struct PendingCommand {
    command: Option<Command>,
    notify: Arc<Notify>,
    wake: Option<WakeFuture>,
}

impl PendingCommand {
    pub(crate) fn new(command: Command, notify: Arc<Notify>) -> Self {
        Self {
            command: Some(command),
            notify,
            wake: None,
        }
    }

    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        sender: &mpsc::Sender<Command>,
    ) -> Poll<Result<(), StreamError>> {
        loop {
            if self.wake.is_none() {
                let notify = Arc::clone(&self.notify);
                self.wake = Some(Box::pin(async move {
                    notify.notified().await;
                }));
            }
            let command = self
                .command
                .take()
                .expect("pending command must contain a command");
            match sender.try_send(command) {
                Ok(()) => {
                    self.wake = None;
                    return Poll::Ready(Ok(()));
                }
                Err(mpsc::error::TrySendError::Full(command)) => {
                    self.command = Some(command);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(StreamError::CommandChannelClosed));
                }
            }

            let wake = self.wake.as_mut().expect("wake future was just created");
            match wake.as_mut().poll(cx) {
                Poll::Ready(()) => self.wake = None,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
