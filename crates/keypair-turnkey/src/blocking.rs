//! Driving one async Turnkey call from a synchronous trait method.
//!
//! The [`zolana_keypair::ShieldedKeypairTrait`] signing methods are
//! synchronous while every
//! Turnkey call is async, and `Runtime::block_on` panics when the calling thread
//! is already inside *any* runtime — which is exactly where a wallet service
//! calls from. So the future is driven by this executor's own runtime and the
//! calling thread waits on a channel instead:
//!
//! - inside a multi-thread runtime, the wait is wrapped in `block_in_place` so
//!   tokio hands the parked worker's tasks to another thread;
//! - inside a current-thread runtime there is no worker to hand off, so the
//!   caller's runtime stalls for the duration of the call. That is inherent to
//!   using a synchronous API from an async context, and is why every backend
//!   also exposes an `async` twin — prefer it whenever the caller is async.

use std::{
    future::Future,
    sync::{mpsc, OnceLock},
};

use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};

use crate::error::TurnkeyKeypairError;

/// A handle to the process-wide blocking bridge.
///
/// The runtime is initialized only by the first synchronous signing call. Async
/// callers therefore create no executor thread, and every backend that does use
/// the synchronous trait methods shares one worker instead of retaining one per
/// wallet.
#[derive(Debug, Default)]
pub(crate) struct Executor;

fn shared_runtime() -> Result<&'static Runtime, TurnkeyKeypairError> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("zolana-turnkey")
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| TurnkeyKeypairError::Executor(error.clone()))
}

impl Executor {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn block_on<F, T>(&self, future: F) -> Result<T, TurnkeyKeypairError>
    where
        F: Future<Output = Result<T, TurnkeyKeypairError>> + Send + 'static,
        T: Send + 'static,
    {
        let runtime = shared_runtime()?;

        let (sender, receiver) = mpsc::sync_channel(1);
        runtime.spawn(async move {
            // A closed channel means the caller is gone; nothing to report to.
            let _ = sender.send(future.await);
        });

        let received = match Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| receiver.recv())
            }
            _ => receiver.recv(),
        };

        // Only reachable if the spawned task was dropped without sending, i.e.
        // the runtime shut down or the task panicked.
        received.map_err(|_| {
            TurnkeyKeypairError::Executor("the Turnkey request did not run to completion".into())
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ok(value: u8) -> Result<u8, TurnkeyKeypairError> {
        Ok(value)
    }

    /// The plain synchronous case, with no ambient runtime at all.
    #[test]
    fn runs_outside_any_runtime() {
        let executor = Executor::new();
        assert_eq!(executor.block_on(ok(7)).unwrap(), 7);
    }

    /// The case a wallet service actually hits: a sync trait method called from
    /// inside a multi-thread runtime. `Runtime::block_on` would panic here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runs_inside_a_multi_thread_runtime() {
        let executor = Executor::new();
        let value = tokio::task::spawn_blocking(move || executor.block_on(ok(9)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value, 9);
    }

    /// Called directly on a multi-thread runtime's worker, without an
    /// intervening `spawn_blocking`, which is the path `block_in_place` covers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runs_on_a_runtime_worker_thread() {
        let executor = Executor::new();
        assert_eq!(executor.block_on(ok(11)).unwrap(), 11);
    }

    /// A current-thread caller stalls its own runtime but still completes,
    /// rather than panicking the way `Runtime::block_on` would.
    #[tokio::test(flavor = "current_thread")]
    async fn runs_inside_a_current_thread_runtime() {
        let executor = Executor::new();
        assert_eq!(executor.block_on(ok(13)).unwrap(), 13);
    }

    #[test]
    fn all_executors_share_one_runtime() {
        let first = shared_runtime().unwrap();
        let second = shared_runtime().unwrap();
        assert!(std::ptr::eq(first, second));
        assert_eq!(std::mem::size_of::<Executor>(), 0);
    }
}
