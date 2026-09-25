use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use cadence_macros::statsd_count;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;
use crate::project::ProjectId;

const LIMITER_PRUNE_THRESHOLD: usize = 10_000;
const REPLAY_KEY_PREFIX: &str = "tvc-gateway:replay:";
const REDIS_TIMEOUT: Duration = Duration::from_millis(500);

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

/// Refuses an `/operations` ciphertext seen within the window, in this process
/// or, when shared, in any gateway task.
pub enum ReplayGuard {
    Local(LocalReplayGuard),
    Shared(SharedReplayGuard),
}

impl ReplayGuard {
    pub async fn connect(
        window: Duration,
        max_entries: usize,
        redis_url: Option<&str>,
    ) -> anyhow::Result<Self> {
        let Some(url) = redis_url else {
            return Ok(Self::Local(LocalReplayGuard::new(window, max_entries)));
        };
        let connection = ConnectionManager::new(redis::Client::open(url)?).await?;
        Ok(Self::Shared(SharedReplayGuard {
            connection,
            window_secs: window.as_secs().max(1),
        }))
    }

    pub async fn check(&self, ciphertext: &[u8]) -> Result<(), ApiError> {
        let digest: [u8; 32] = Sha256::digest(ciphertext).into();
        match self {
            Self::Local(guard) => guard.check_digest(digest, Instant::now()),
            Self::Shared(guard) => guard.check_digest(digest).await,
        }
    }
}

/// Records each ciphertext digest with `SET NX EX`, so exactly one task
/// accepts it. An unreachable Redis refuses the request.
pub struct SharedReplayGuard {
    connection: ConnectionManager,
    window_secs: u64,
}

impl SharedReplayGuard {
    async fn check_digest(&self, digest: [u8; 32]) -> Result<(), ApiError> {
        let key = format!("{REPLAY_KEY_PREFIX}{}", hex::encode(digest));
        let mut connection = self.connection.clone();
        let mut set = redis::cmd("SET");
        set.arg(&key)
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(self.window_secs);
        let reply = set.query_async::<Option<String>>(&mut connection);
        match tokio::time::timeout(REDIS_TIMEOUT, reply).await {
            Ok(Ok(Some(_))) => Ok(()),
            Ok(Ok(None)) => {
                statsd_count!("enclave.replay_rejected", 1);
                Err(ApiError::ReplayedRequest)
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "replay guard unavailable");
                statsd_count!("enclave.replay_guard_unavailable", 1);
                Err(ApiError::Upstream("ReplayGuardUnavailable"))
            }
            Err(_) => {
                tracing::warn!("replay guard timed out");
                statsd_count!("enclave.replay_guard_unavailable", 1);
                Err(ApiError::Upstream("ReplayGuardUnavailable"))
            }
        }
    }
}

/// Refuses a ciphertext seen within the window in this process. Two
/// generations rotate, so a digest is remembered for one to two windows.
pub struct LocalReplayGuard {
    window: Duration,
    max_entries: usize,
    state: Mutex<Generations>,
}

struct Generations {
    sets: [HashSet<[u8; 32]>; 2],
    current: usize,
    rotated_at: Instant,
}

impl LocalReplayGuard {
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
        let guard = LocalReplayGuard::new(Duration::from_secs(60), 16);
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
        let guard = LocalReplayGuard::new(Duration::from_secs(60), 16);
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

    /// A Redis stand-in on loopback: `SET key value NX EX n` behaves as in
    /// Redis, and any other command answers `+OK`. With `answer_set` false it
    /// never answers a `SET`.
    async fn fake_redis(answer_set: bool) -> String {
        use tokio::net::TcpListener;

        let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
            panic!("fake redis did not bind");
        };
        let Ok(addr) = listener.local_addr() else {
            panic!("fake redis has no address");
        };
        let keys = Arc::new(Mutex::new(HashSet::<String>::new()));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_fake_redis(stream, Arc::clone(&keys), answer_set));
            }
        });
        format!("redis://{addr}/2")
    }

    async fn serve_fake_redis(
        stream: tokio::net::TcpStream,
        keys: Arc<Mutex<HashSet<String>>>,
        answer_set: bool,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let count: usize = line.trim().trim_start_matches('*').parse().unwrap_or(0);
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                line.clear();
                let _ = reader.read_line(&mut line).await;
                let len: usize = line.trim().trim_start_matches('$').parse().unwrap_or(0);
                let mut arg = vec![0u8; len + 2];
                let _ = reader.read_exact(&mut arg).await;
                args.push(String::from_utf8_lossy(&arg[..len]).into_owned());
            }
            let is_set_nx = args
                .first()
                .is_some_and(|name| name.eq_ignore_ascii_case("SET"))
                && args.iter().any(|arg| arg.eq_ignore_ascii_case("NX"));
            let reply = match (is_set_nx, answer_set) {
                (true, false) => continue,
                (true, true) => {
                    let first = args.get(1).is_some_and(|key| {
                        keys.lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(key.clone())
                    });
                    if first { "+OK\r\n" } else { "$-1\r\n" }
                }
                (false, _) => "+OK\r\n",
            };
            if write.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    async fn shared_guard(url: &str) -> ReplayGuard {
        let Ok(guard) = ReplayGuard::connect(Duration::from_secs(360), 16, Some(url)).await else {
            panic!("shared replay guard did not connect");
        };
        guard
    }

    #[tokio::test]
    async fn gateway_tasks_sharing_redis_accept_a_ciphertext_once() {
        crate::metrics::init_for_tests();
        let url = fake_redis(true).await;
        let (first_task, second_task) = (shared_guard(&url).await, shared_guard(&url).await);
        assert_eq!(first_task.check(b"ciphertext").await, Ok(()));
        assert_eq!(
            second_task.check(b"ciphertext").await,
            Err(ApiError::ReplayedRequest)
        );
        assert_eq!(second_task.check(b"another").await, Ok(()));
    }

    #[tokio::test]
    async fn an_unresponsive_redis_refuses_the_request() {
        crate::metrics::init_for_tests();
        let guard = shared_guard(&fake_redis(false).await).await;
        assert_eq!(
            guard.check(b"ciphertext").await,
            Err(ApiError::Upstream("ReplayGuardUnavailable"))
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
