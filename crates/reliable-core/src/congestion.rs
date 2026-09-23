use core::cmp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CongestionController {
    cwnd: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    min_cwnd: u64,
    max_cwnd: u64,
    mss: u64,
}

impl CongestionController {
    pub(crate) fn new(initial_cwnd: u64, min_cwnd: u64, max_cwnd: u64, mss: usize) -> Self {
        let mss = mss.max(1) as u64;
        Self {
            cwnd: initial_cwnd.clamp(min_cwnd, max_cwnd),
            ssthresh: max_cwnd,
            bytes_in_flight: 0,
            min_cwnd,
            max_cwnd,
            mss,
        }
    }

    pub(crate) const fn cwnd(self) -> u64 {
        self.cwnd
    }

    pub(crate) const fn bytes_in_flight(self) -> u64 {
        self.bytes_in_flight
    }

    pub(crate) const fn can_send(self, bytes: usize) -> bool {
        self.bytes_in_flight.saturating_add(bytes as u64) <= self.cwnd
    }

    pub(crate) fn on_sent(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes as u64);
    }

    pub(crate) fn on_acked(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes as u64);
        let bytes = bytes as u64;
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(bytes).min(self.max_cwnd);
        } else {
            let increment = self
                .mss
                .saturating_mul(bytes)
                .checked_div(self.cwnd.max(1))
                .unwrap_or(1)
                .max(1);
            self.cwnd = self.cwnd.saturating_add(increment).min(self.max_cwnd);
        }
    }

    pub(crate) fn on_loss(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes as u64);
        self.ssthresh = cmp::max(self.cwnd / 2, self.min_cwnd);
        self.cwnd = self.ssthresh;
    }
}

#[cfg(test)]
mod tests {
    use super::CongestionController;

    #[test]
    fn slow_start_grows_after_ack_and_loss_halves_the_window() {
        let mut controller = CongestionController::new(1_200, 1_200, 12_000, 1_200);
        assert!(controller.can_send(1_200));
        controller.on_sent(1_200);
        controller.on_acked(1_200);
        assert_eq!(controller.cwnd(), 2_400);
        controller.on_loss(1_200);
        assert_eq!(controller.cwnd(), 1_200);
        assert_eq!(controller.bytes_in_flight(), 0);
    }
}
