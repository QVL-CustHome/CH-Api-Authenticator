use crate::error::AppError;
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::time::Duration;

type KeyedLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

pub struct RateLimitPolicy {
    limiter: KeyedLimiter,
    clock: DefaultClock,
}

impl RateLimitPolicy {
    pub fn new(max: u32, window: Duration) -> Self {
        let quota = quota_for(max, window);
        Self {
            limiter: RateLimiter::keyed(quota),
            clock: DefaultClock::default(),
        }
    }

    pub fn cleanup(&self) {
        self.limiter.retain_recent();
    }

    pub fn enforce(&self, key: String) -> Result<(), AppError> {
        match self.limiter.check_key(&key) {
            Ok(_) => Ok(()),
            Err(negative) => {
                let wait = negative.wait_time_from(self.clock.now());
                Err(AppError::TooManyRequests {
                    retry_after_secs: wait.as_secs().max(1),
                })
            }
        }
    }
}

fn quota_for(max: u32, window: Duration) -> Quota {
    let burst = NonZeroU32::new(max).unwrap_or(NonZeroU32::MIN);
    let cell = window
        .checked_div(burst.get())
        .filter(|d| !d.is_zero())
        .unwrap_or(Duration::from_secs(1));
    Quota::with_period(cell)
        .unwrap_or_else(|| Quota::per_second(burst))
        .allow_burst(burst)
}

pub struct RateLimiters {
    pub login: RateLimitPolicy,
    pub forgot: RateLimitPolicy,
    pub refresh: RateLimitPolicy,
}

impl RateLimiters {
    pub fn from_config(config: &RateLimitConfig) -> Self {
        Self {
            login: RateLimitPolicy::new(config.login.max, config.login.window),
            forgot: RateLimitPolicy::new(config.forgot.max, config.forgot.window),
            refresh: RateLimitPolicy::new(config.refresh.max, config.refresh.window),
        }
    }

    pub fn cleanup(&self) {
        self.login.cleanup();
        self.forgot.cleanup();
        self.refresh.cleanup();
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub login: RateLimitRule,
    pub forgot: RateLimitRule,
    pub refresh: RateLimitRule,
}

#[derive(Debug, Clone)]
pub struct RateLimitRule {
    pub max: u32,
    pub window: Duration,
}
