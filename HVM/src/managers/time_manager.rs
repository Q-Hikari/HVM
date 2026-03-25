use std::time::Instant;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

/// Represents the current emulated wall-clock tick state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmulatedTime {
    pub tick_ms: u64,
    pub filetime: u64,
}

/// Tracks the emulated clock used by the scheduler and waits.
#[derive(Debug, Clone)]
pub struct TimeManager {
    base_filetime: u64,
    start_mono: Instant,
    virtual_sleep_ms: u64,
}

impl Default for TimeManager {
    fn default() -> Self {
        Self {
            base_filetime: current_filetime(),
            start_mono: Instant::now(),
            virtual_sleep_ms: 0,
        }
    }
}

impl TimeManager {
    /// Returns the current emulated time snapshot.
    pub fn current(&self) -> EmulatedTime {
        let elapsed_real_ms = self.start_mono.elapsed().as_millis() as u64;
        let total_ms = elapsed_real_ms.saturating_add(self.virtual_sleep_ms);
        EmulatedTime {
            tick_ms: total_ms & 0xFFFF_FFFF,
            filetime: self
                .base_filetime
                .saturating_add(total_ms.saturating_mul(10_000)),
        }
    }

    /// Advances the emulated time by the requested number of milliseconds.
    pub fn advance(&mut self, delta_ms: u64) {
        self.virtual_sleep_ms = self.virtual_sleep_ms.saturating_add(delta_ms);
    }
}

fn current_filetime() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| WINDOWS_TO_UNIX_EPOCH_100NS + duration.as_nanos() as u64 / 100)
        .unwrap_or(WINDOWS_TO_UNIX_EPOCH_100NS)
}
