use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use cadence_macros::statsd_count;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;
use crate::project::ProjectId;

const LIMITER_PRUNE_THRESHOLD: usize = 10_000;

/// Caps each project's concurrent enclave calls; a Bootstrap or Prove can
/// hold one for the full request timeout.
pub struct InFlightLimiter {
    max_per_project: u32,
    by_project: Mutex<HashMap<ProjectId, Arc<Semaphore>>>,
}

impl InFlightLimiter {
    pub fn new(max_per_project: u32) -> Self {
        Self {
            max_per_project,
            by_project: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_acquire(&self, project: &ProjectId) -> Result<OwnedSemaphorePermit, ApiError> {
        let semaphore = self.semaphore(project);
        semaphore.try_acquire_owned().map_err(|_| {
            statsd_count!("enclave.in_flight_rejected", 1);
            ApiError::TooManyInFlight
        })
    }

    fn semaphore(&self, project: &ProjectId) -> Arc<Semaphore> {
        let mut by_project = self
            .by_project
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if by_project.len() > LIMITER_PRUNE_THRESHOLD {
            let idle = self.max_per_project as usize;
            by_project.retain(|_, semaphore| semaphore.available_permits() < idle);
        }
        let semaphore = by_project
            .entry(project.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_project as usize)));
        Arc::clone(semaphore)
    }
}

/// Refuses a ciphertext seen within the window. Two generations rotate, so a
/// ciphertext is remembered for between one and two windows.
pub struct ReplayGuard {
    window: Duration,
    max_entries: usize,
    state: Mutex<Generations>,
}

struct Generations {
    sets: [HashSet<[u8; 32]>; 2],
    current: usize,
    rotated_at: Instant,
}

impl ReplayGuard {
    pub fn new(window: Duration, max_entries: usize) -> Self {
        Self {
            window,
            max_entries,
            state: Mutex::new(Generations {
                sets: [HashSet::new(), HashSet::new()],
                current: 0,
                rotated_at: Instant::now(),
            }),
        }
    }

    pub fn check(&self, ciphertext: &[u8]) -> Result<(), ApiError> {
        let digest: [u8; 32] = Sha256::digest(ciphertext).into();
        self.check_digest(digest, Instant::now())
    }

    fn check_digest(&self, digest: [u8; 32], now: Instant) -> Result<(), ApiError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let expired = now.saturating_duration_since(state.rotated_at) >= self.window;
        if expired || state.sets[state.current].len() >= self.max_entries {
            if !expired {
                statsd_count!("enclave.replay_guard_early_rotation", 1);
            }
            state.rotate(now);
        }
        if state.sets.iter().any(|set| set.contains(&digest)) {
            statsd_count!("enclave.replay_rejected", 1);
            return Err(ApiError::ReplayedRequest);
        }
        let current = state.current;
        state.sets[current].insert(digest);
        Ok(())
    }
}

impl Generations {
    fn rotate(&mut self, now: Instant) {
        self.current ^= 1;
        self.sets[self.current].clear();
        self.rotated_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_guard_refuses_a_repeat_within_the_window() {
        crate::metrics::init_for_tests();
        let guard = ReplayGuard::new(Duration::from_secs(60), 16);
        let now = Instant::now();
        assert_eq!(guard.check_digest([1; 32], now), Ok(()));
        assert_eq!(
            guard.check_digest([1; 32], now + Duration::from_secs(59)),
            Err(ApiError::ReplayedRequest)
        );
    }

    #[test]
    fn replay_guard_remembers_across_one_rotation_then_forgets() {
        crate::metrics::init_for_tests();
        let guard = ReplayGuard::new(Duration::from_secs(60), 16);
        let now = Instant::now();
        assert_eq!(guard.check_digest([1; 32], now), Ok(()));
        assert_eq!(
            guard.check_digest([1; 32], now + Duration::from_secs(61)),
            Err(ApiError::ReplayedRequest)
        );
        assert_eq!(
            guard.check_digest([2; 32], now + Duration::from_secs(122)),
            Ok(())
        );
        assert_eq!(
            guard.check_digest([1; 32], now + Duration::from_secs(123)),
            Ok(())
        );
    }

    #[test]
    fn in_flight_limiter_caps_each_project_independently() {
        crate::metrics::init_for_tests();
        let limiter = InFlightLimiter::new(1);
        let a = ProjectId::for_tests("a");
        let b = ProjectId::for_tests("b");
        let held = limiter.try_acquire(&a);
        assert!(held.is_ok());
        assert_eq!(
            limiter.try_acquire(&a).err(),
            Some(ApiError::TooManyInFlight)
        );
        assert!(limiter.try_acquire(&b).is_ok());
        drop(held);
        assert!(limiter.try_acquire(&a).is_ok());
    }
}
