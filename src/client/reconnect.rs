//! Reconnect backoff policy for the client.

use std::time::Duration;

pub struct Backoff {
    cur: Duration,
    max: Duration,
}

impl Backoff {
    pub fn new() -> Self {
        Backoff { cur: Duration::from_millis(250), max: Duration::from_secs(5) }
    }
    pub fn reset(&mut self) {
        self.cur = Duration::from_millis(250);
    }
    /// Current delay, then double it (capped).
    pub fn next_delay(&mut self) -> Duration {
        let d = self.cur;
        self.cur = (self.cur * 2).min(self.max);
        d
    }
}
