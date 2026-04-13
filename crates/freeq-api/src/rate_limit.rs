//! Lightweight token-bucket rate limiting for the local API.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Small lock-free token bucket used to shed bursts cheaply.
pub struct TokenBucket {
    capacity: u64,
    refill_per_second: u64,
    state: AtomicU64,
}

impl TokenBucket {
    /// Build a bucket with a fixed burst capacity and steady refill rate.
    pub fn new(capacity: u64, refill_per_second: u64) -> Self {
        Self {
            capacity,
            refill_per_second,
            state: AtomicU64::new(pack_state(capacity, unix_seconds())),
        }
    }

    /// Try to consume a token, returning `true` when the caller may proceed.
    pub fn allow(&self) -> bool {
        let now = unix_seconds();

        loop {
            let current = self.state.load(Ordering::Relaxed);
            let (tokens, last_refill) = unpack_state(current);
            let elapsed = now.saturating_sub(last_refill);
            let replenished = tokens.saturating_add(elapsed.saturating_mul(self.refill_per_second));
            let available = replenished.min(self.capacity);

            if available == 0 {
                let updated = pack_state(0, now);
                if self
                    .state
                    .compare_exchange(current, updated, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return false;
                }
                continue;
            }

            let updated = pack_state(available - 1, now);
            if self
                .state
                .compare_exchange(current, updated, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn pack_state(tokens: u64, last_refill: u64) -> u64 {
    (tokens << 32) | (last_refill & 0xffff_ffff)
}

fn unpack_state(state: u64) -> (u64, u64) {
    (state >> 32, state & 0xffff_ffff)
}

#[cfg(test)]
mod tests {
    use super::TokenBucket;

    #[test]
    fn bucket_allows_initial_burst_then_sheds() {
        let bucket = TokenBucket::new(2, 1);
        assert!(bucket.allow());
        assert!(bucket.allow());
        assert!(!bucket.allow());
    }
}
