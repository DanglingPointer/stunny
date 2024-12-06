use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::Instant;

pub trait RtoPolicy {
    fn submit_rtt(&mut self, remote_addr: SocketAddr, rtt: Duration);
    fn calculate_rto(
        &mut self,
        remote_addr: SocketAddr,
        attempts_made: usize,
        transaction_start: Instant,
    ) -> Option<Duration>;
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
        _transaction_start: Instant,
    ) -> Option<Duration> {
        match attempts_made {
            0 => Some(self.timeout),
            _ => None,
        }
    }
}
