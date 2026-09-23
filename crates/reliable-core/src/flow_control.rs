use udp_protocol::StreamId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SendFlowControl {
    connection_max_offset: u64,
    connection_sent_offset: u64,
}

impl SendFlowControl {
    pub(crate) const fn new(max_offset: u64) -> Self {
        Self {
            connection_max_offset: max_offset,
            connection_sent_offset: 0,
        }
    }

    pub(crate) fn update(&mut self, max_offset: u64) {
        self.connection_max_offset = self.connection_max_offset.max(max_offset);
    }

    pub(crate) fn set_max_offset(&mut self, max_offset: u64) {
        self.connection_max_offset = max_offset;
    }

    pub(crate) fn can_send(&self, length: usize, retransmission: bool) -> bool {
        retransmission
            || self
                .connection_sent_offset
                .checked_add(length as u64)
                .is_some_and(|end| end <= self.connection_max_offset)
    }

    pub(crate) fn account_new_data(&mut self, length: usize) {
        self.connection_sent_offset = self.connection_sent_offset.saturating_add(length as u64);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceiveFlowControl {
    max_offset: u64,
    unique_received: u64,
    consumed: u64,
    window_size: u64,
    advertised_offset: u64,
}

impl ReceiveFlowControl {
    pub(crate) const fn new(window_size: u64) -> Self {
        Self {
            max_offset: window_size,
            unique_received: 0,
            consumed: 0,
            window_size,
            advertised_offset: window_size,
        }
    }

    pub(crate) fn check(
        &self,
        stream_id: Option<StreamId>,
        end: u64,
        new_bytes: usize,
    ) -> Result<(), crate::CoreError> {
        if end > self.max_offset {
            return Err(crate::CoreError::FlowControlViolation { stream_id });
        }
        self.unique_received
            .checked_add(new_bytes as u64)
            .ok_or(crate::CoreError::FlowControlViolation { stream_id })?;
        Ok(())
    }

    pub(crate) const fn unique_received(&self) -> u64 {
        self.unique_received
    }

    pub(crate) fn account(
        &mut self,
        stream_id: Option<StreamId>,
        new_bytes: usize,
    ) -> Result<(), crate::CoreError> {
        self.unique_received = self
            .unique_received
            .checked_add(new_bytes as u64)
            .ok_or(crate::CoreError::FlowControlViolation { stream_id })?;
        Ok(())
    }

    pub(crate) fn consume(&mut self, amount: usize) -> Option<u64> {
        self.consumed = self.consumed.saturating_add(amount as u64);
        let desired = self.consumed.saturating_add(self.window_size);
        if desired > self.advertised_offset {
            self.advertised_offset = desired;
            self.max_offset = desired;
            Some(desired)
        } else {
            None
        }
    }
}
