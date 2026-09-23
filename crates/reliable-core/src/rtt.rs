use core::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RttEstimator {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    initial_rto: Duration,
    min_rto: Duration,
    max_rto: Duration,
    granularity: Duration,
}

impl RttEstimator {
    pub(crate) const fn new(
        initial_rto: Duration,
        min_rto: Duration,
        max_rto: Duration,
        granularity: Duration,
    ) -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: initial_rto,
            initial_rto,
            min_rto,
            max_rto,
            granularity,
        }
    }

    pub(crate) const fn rto(self) -> Duration {
        self.rto
    }

    #[cfg(test)]
    pub(crate) const fn srtt(self) -> Option<Duration> {
        self.srtt
    }

    pub(crate) fn on_ack(&mut self, sample: Duration, ack_delay: Duration) {
        let sample = sample.saturating_sub(ack_delay);
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                let difference = srtt.abs_diff(sample);
                self.rttvar = (self.rttvar * 3 + difference) / 4;
                self.srtt = Some((srtt * 7 + sample) / 8);
            }
        }
        self.recalculate();
    }

    pub(crate) fn on_timeout(&mut self) {
        self.rto = self
            .rto
            .checked_mul(2)
            .unwrap_or(self.max_rto)
            .min(self.max_rto);
    }

    pub(crate) fn reset_backoff(&mut self) {
        if self.srtt.is_none() {
            self.rto = self.initial_rto;
        } else {
            self.recalculate();
        }
    }

    fn recalculate(&mut self) {
        let srtt = self.srtt.unwrap_or(self.initial_rto);
        let variance = (self.rttvar * 4).max(self.granularity);
        self.rto = (srtt + variance).clamp(self.min_rto, self.max_rto);
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::RttEstimator;

    #[test]
    fn computes_bounded_rto_and_backoff() {
        let mut rtt = RttEstimator::new(
            Duration::from_secs(1),
            Duration::from_millis(200),
            Duration::from_secs(60),
            Duration::from_millis(10),
        );
        rtt.on_ack(Duration::from_millis(100), Duration::ZERO);
        assert_eq!(rtt.srtt(), Some(Duration::from_millis(100)));
        assert_eq!(rtt.rto(), Duration::from_millis(300));
        rtt.on_timeout();
        assert_eq!(rtt.rto(), Duration::from_millis(600));
    }
}
