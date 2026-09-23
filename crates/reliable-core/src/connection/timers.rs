use core::time::Duration;

use time_wheel::{Expired, TimerId, Wheel};

use crate::{config::ConnectionConfig, error::CoreError, timer::TimerEvent};

pub(crate) struct TimerState {
    wheel: Wheel<TimerEvent>,
    handshake: Option<TimerId>,
    ack: Option<TimerId>,
    keepalive: Option<TimerId>,
    idle: Option<TimerId>,
    close: Option<TimerId>,
}

impl TimerState {
    pub(crate) fn new(config: &ConnectionConfig) -> Result<Self, CoreError> {
        Ok(Self {
            wheel: Wheel::new(config.wheel_config().map_err(CoreError::InvalidConfig)?),
            handshake: None,
            ack: None,
            keepalive: None,
            idle: None,
            close: None,
        })
    }

    pub(crate) fn advance(&mut self, elapsed: Duration) -> Result<Vec<TimerEvent>, CoreError> {
        let mut expired = Vec::new();
        self.wheel.advance_by(elapsed, &mut expired)?;
        Ok(expired
            .into_iter()
            .map(|Expired { item, .. }| item)
            .collect())
    }

    pub(crate) fn next_deadline(&self) -> Result<Option<Duration>, CoreError> {
        Ok(self.wheel.next_deadline()?)
    }

    pub(crate) fn schedule(
        &mut self,
        event: TimerEvent,
        delay: Duration,
    ) -> Result<TimerId, CoreError> {
        Ok(self.wheel.insert(event, delay)?)
    }

    pub(crate) fn schedule_handshake(&mut self, delay: Duration) -> Result<(), CoreError> {
        self.handshake = Some(self.schedule(TimerEvent::HandshakeTimeout, delay)?);
        Ok(())
    }

    pub(crate) fn schedule_ack(&mut self, delay: Duration) -> Result<(), CoreError> {
        if self.ack.is_none() {
            self.ack = Some(self.schedule(TimerEvent::AckDelay, delay)?);
        }
        Ok(())
    }

    pub(crate) fn schedule_keepalive(&mut self, delay: Duration) -> Result<(), CoreError> {
        self.keepalive = Some(self.schedule(TimerEvent::Keepalive, delay)?);
        Ok(())
    }

    pub(crate) fn schedule_idle(&mut self, delay: Duration) -> Result<(), CoreError> {
        Self::cancel_slot(&mut self.wheel, &mut self.idle);
        self.idle = Some(self.schedule(TimerEvent::IdleTimeout, delay)?);
        Ok(())
    }

    pub(crate) fn schedule_close(&mut self, delay: Duration) -> Result<(), CoreError> {
        self.close = Some(self.schedule(TimerEvent::CloseTimeout, delay)?);
        Ok(())
    }

    pub(crate) fn cancel(&mut self, timer: TimerId) {
        let _ = self.wheel.cancel(timer);
    }

    pub(crate) fn clear_slot(&mut self, event: TimerEvent) {
        match event {
            TimerEvent::HandshakeTimeout => self.handshake = None,
            TimerEvent::AckDelay => self.ack = None,
            TimerEvent::Keepalive => self.keepalive = None,
            TimerEvent::IdleTimeout => self.idle = None,
            TimerEvent::CloseTimeout => self.close = None,
            TimerEvent::Retransmit { .. } => {}
        }
    }

    pub(crate) fn cancel_ack(&mut self) {
        Self::cancel_slot(&mut self.wheel, &mut self.ack);
    }

    pub(crate) fn cancel_handshake(&mut self) {
        Self::cancel_slot(&mut self.wheel, &mut self.handshake);
    }

    pub(crate) fn cancel_all(&mut self) {
        Self::cancel_slot(&mut self.wheel, &mut self.handshake);
        Self::cancel_slot(&mut self.wheel, &mut self.ack);
        Self::cancel_slot(&mut self.wheel, &mut self.keepalive);
        Self::cancel_slot(&mut self.wheel, &mut self.idle);
        Self::cancel_slot(&mut self.wheel, &mut self.close);
        let mut discarded = Vec::new();
        self.wheel.clear(&mut discarded);
    }

    fn cancel_slot(wheel: &mut Wheel<TimerEvent>, slot: &mut Option<TimerId>) {
        if let Some(timer) = slot.take() {
            let _ = wheel.cancel(timer);
        }
    }
}
