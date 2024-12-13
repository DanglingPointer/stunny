use std::cmp;
use std::net::SocketAddr;
use std::time::Duration;

pub trait RtoPolicy {
    /// Submit a new RTT measurement for the given remote address.
    fn submit_rtt(&mut self, remote_addr: SocketAddr, rtt: Duration);

    /// Calculate RTO for the next retransmission that will happen immediately after this call.
    /// If `None` is returned, no retransmission will be made.
    fn calculate_rto(&mut self, remote_addr: SocketAddr, attempts_made: usize) -> Option<Duration>;
}

pub struct NoRetransmissionsConstTimeout {
    timeout: Duration,
}

impl NoRetransmissionsConstTimeout {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl RtoPolicy for NoRetransmissionsConstTimeout {
    fn submit_rtt(&mut self, _remote_addr: SocketAddr, _rtt: Duration) {
        /* noop */
    }

    fn calculate_rto(
        &mut self,
        _remote_addr: SocketAddr,
        attempts_made: usize,
    ) -> Option<Duration> {
        match attempts_made {
            0 => Some(self.timeout),
            _ => None,
        }
    }
}

pub struct ExponentialBackoffFixedRtt<const RC: usize, const RM: u32> {
    rto: Duration,
}

pub type DefaultExponentialBackoffFixedRtt = ExponentialBackoffFixedRtt<7, 16>;

impl Default for DefaultExponentialBackoffFixedRtt {
    fn default() -> Self {
        Self {
            rto: Duration::from_millis(500),
        }
    }
}

impl<const RC: usize, const RM: u32> ExponentialBackoffFixedRtt<RC, RM> {
    pub fn new(rto: Duration) -> Self {
        Self { rto }
    }
}

impl<const RC: usize, const RM: u32> RtoPolicy for ExponentialBackoffFixedRtt<RC, RM> {
    fn submit_rtt(&mut self, _remote_addr: SocketAddr, _rtt: Duration) {
        /* noop */
    }

    fn calculate_rto(
        &mut self,
        _remote_addr: SocketAddr,
        attempts_made: usize,
    ) -> Option<Duration> {
        macro_rules! exp_backoff {
            () => {{
                self.rto * (2 << (attempts_made - 1))
            }};
        }

        if attempts_made == 0 {
            Some(self.rto)
        } else if attempts_made == RC {
            None
        } else if attempts_made == RC - 1 {
            Some(cmp::min(exp_backoff!(), self.rto * RM))
        } else {
            Some(exp_backoff!())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use local_async_utils::millisec;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::time::{sleep, Instant};

    const IP: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, 12345));

    #[tokio::test(start_paused = true)]
    async fn exponential_backoff_fixed_rtt() {
        let mut policy = DefaultExponentialBackoffFixedRtt::default();

        let start_time = Instant::now();
        let mut attempts = 0;

        macro_rules! assert_elapsed {
            ($expected_elapsed:expr) => {{
                let rto = policy.calculate_rto(IP, attempts).unwrap();
                attempts += 1;
                sleep(rto).await;
                assert_eq!(start_time.elapsed(), $expected_elapsed);
            }};
        }

        assert_elapsed!(millisec!(500));
        assert_elapsed!(millisec!(1500));
        assert_elapsed!(millisec!(3500));
        assert_elapsed!(millisec!(7500));
        assert_elapsed!(millisec!(15500));
        assert_elapsed!(millisec!(31500));
        assert_elapsed!(millisec!(39500));

        let rto = policy.calculate_rto(IP, attempts);
        assert!(rto.is_none());
    }
}
