use std::sync::Arc;

use tokio::{
    sync::{broadcast, watch},
    task::JoinHandle,
};
use transfer_core::{SessionEvent, SessionState};
use transfer_protocol::{PathKind, TransferId};

use crate::{ClientError, ResumeTicket, protocol::ClientConnection};

pub(crate) struct TransferChannels {
    pub cancel: watch::Sender<bool>,
    pub cancel_receiver: watch::Receiver<bool>,
    pub event_sender: broadcast::Sender<TransferEvent>,
    pub resume_ticket_sender: watch::Sender<Option<ResumeTicket>>,
    pub resume_ticket_receiver: watch::Receiver<Option<ResumeTicket>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferSummary {
    pub transfer_id: TransferId,
    pub completed_files: u64,
    pub total_size: u64,
    pub path_kind: PathKind,
    pub relay_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferEvent {
    StateChanged {
        from: SessionState,
        to: SessionState,
    },
    FileProgress {
        file_id: transfer_protocol::FileId,
        durable_offset: u64,
        total_size: u64,
    },
    PathSelected {
        kind: PathKind,
    },
    PathFallback,
    Completed(TransferSummary),
    Failed(String),
}

pub(crate) struct TransferHandleInner {
    pub connection: Arc<ClientConnection>,
    pub transfer_id: TransferId,
    pub cancel: watch::Sender<bool>,
    pub events: broadcast::Sender<TransferEvent>,
    pub resume_ticket: watch::Receiver<Option<ResumeTicket>>,
    pub task: tokio::sync::Mutex<Option<JoinHandle<Result<TransferSummary, ClientError>>>>,
}

#[derive(Clone)]
pub struct TransferHandle {
    pub(crate) inner: Arc<TransferHandleInner>,
}

impl TransferHandle {
    pub(crate) fn new(
        connection: Arc<ClientConnection>,
        transfer_id: TransferId,
        task: JoinHandle<Result<TransferSummary, ClientError>>,
        cancel: watch::Sender<bool>,
        events: broadcast::Sender<TransferEvent>,
        resume_ticket: watch::Receiver<Option<ResumeTicket>>,
    ) -> Self {
        Self {
            inner: Arc::new(TransferHandleInner {
                connection,
                transfer_id,
                cancel,
                events,
                resume_ticket,
                task: tokio::sync::Mutex::new(Some(task)),
            }),
        }
    }

    pub(crate) fn channels() -> TransferChannels {
        let (cancel, cancel_receiver) = watch::channel(false);
        let (events, _) = broadcast::channel(256);
        let (resume_ticket_sender, resume_ticket_receiver) = watch::channel(None);
        TransferChannels {
            cancel,
            cancel_receiver,
            event_sender: events,
            resume_ticket_sender,
            resume_ticket_receiver,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransferEvent> {
        self.inner.events.subscribe()
    }

    pub fn try_resume_ticket(&self) -> Option<ResumeTicket> {
        self.inner.resume_ticket.borrow().clone()
    }

    pub async fn resume_ticket(&self) -> Result<ResumeTicket, ClientError> {
        let mut receiver = self.inner.resume_ticket.clone();
        loop {
            if let Some(ticket) = receiver.borrow().clone() {
                return Ok(ticket);
            }
            receiver.changed().await.map_err(|_| ClientError::Closed)?;
        }
    }

    pub async fn save_resume_ticket(
        &self,
        root: impl AsRef<std::path::Path>,
    ) -> Result<std::path::PathBuf, ClientError> {
        self.resume_ticket().await?.save_to(root)
    }

    pub async fn cancel(&self) -> Result<(), ClientError> {
        self.inner
            .cancel
            .send(true)
            .map_err(|_| ClientError::Closed)?;
        self.inner
            .connection
            .send(&transfer_protocol::Message::Pairing(
                transfer_protocol::PairingControl::Cancel {
                    transfer_id: self.inner.transfer_id,
                    reason_code: 1,
                },
            ))
            .await
    }

    /// 立即停止本地传输任务，供进程重启或宿主生命周期管理使用。
    pub async fn abort(&self) -> Result<(), ClientError> {
        if let Some(task) = self.inner.task.lock().await.take() {
            task.abort();
        }
        Ok(())
    }

    pub async fn wait(self) -> Result<TransferSummary, ClientError> {
        let task = self
            .inner
            .task
            .lock()
            .await
            .take()
            .ok_or(ClientError::InvalidState("transfer handle already waited"))?;
        match task.await {
            Ok(result) => result,
            Err(error) => Err(ClientError::TaskJoin(error.to_string())),
        }
    }
}

pub(crate) fn publish_events(sender: &broadcast::Sender<TransferEvent>, events: &[SessionEvent]) {
    for event in events {
        match event {
            SessionEvent::StateChanged { from, to } => {
                let _ = sender.send(TransferEvent::StateChanged {
                    from: *from,
                    to: *to,
                });
            }
            SessionEvent::Checkpointed {
                file_id,
                durable_offset,
                ..
            } => {
                let _ = sender.send(TransferEvent::FileProgress {
                    file_id: *file_id,
                    durable_offset: *durable_offset,
                    total_size: 0,
                });
            }
            SessionEvent::PathSelected { path } => {
                let _ = sender.send(TransferEvent::PathSelected { kind: path.kind });
            }
            SessionEvent::PathFallback { .. } => {
                let _ = sender.send(TransferEvent::PathFallback);
            }
            _ => {}
        }
    }
}
