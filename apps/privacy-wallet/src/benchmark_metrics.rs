//! Compile-time opt-in counters for temporary benchmark images.
//! No request contents or operation names are exposed. These HTTP headers are
//! diagnostic metadata, not part of the signed App Proof. Process deltas include
//! concurrent tasks; never add overlapping process deltas to estimate CPU load.
use std::future::{poll_fn, Future};
use std::pin::pin;

use axum::body::Body;
use axum::http::{HeaderValue, Request, Response};
use axum::middleware::Next;
use nix::time::{clock_gettime, ClockId};

fn clock_ns(clock: ClockId) -> Option<u64> {
    let t = clock_gettime(clock).ok()?;
    u64::try_from(t.tv_sec())
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec()).ok()?)
}

/// Count only CPU consumed while this future is being polled, including when
/// successive polls run on different Tokio threads. Waiting is not CPU time.
async fn task_cpu<F: Future>(future: F) -> (F::Output, Option<u64>) {
    let mut future = pin!(future);
    let mut total = Some(0u64);
    let output = poll_fn(|cx| {
        let start = clock_ns(ClockId::CLOCK_THREAD_CPUTIME_ID);
        let result = future.as_mut().poll(cx);
        let end = clock_ns(ClockId::CLOCK_THREAD_CPUTIME_ID);
        total = total.and_then(|sum| sum.checked_add(end?.checked_sub(start?)?));
        result
    })
    .await;
    (output, total)
}

pub(crate) async fn measure(request: Request<Body>, next: Next) -> Response<Body> {
    if request.uri().path() != "/v1/operations" {
        return next.run(request).await;
    }
    let wall_start = clock_ns(ClockId::CLOCK_MONOTONIC);
    let process_start = clock_ns(ClockId::CLOCK_PROCESS_CPUTIME_ID);
    let (mut response, task) = task_cpu(next.run(request)).await;
    let process_end = clock_ns(ClockId::CLOCK_PROCESS_CPUTIME_ID);
    let wall_end = clock_ns(ClockId::CLOCK_MONOTONIC);
    if response.status().is_success() {
        if let (Some(task), Some(ps), Some(pe), Some(ws), Some(we)) =
            (task, process_start, process_end, wall_start, wall_end)
        {
            // Integer microseconds stay exactly representable by JS at realistic
            // process uptimes. Keep missing/failed clocks distinct from zero CPU.
            let value =
                format!(
                "task_us={},process_start_us={},process_end_us={},wall_start_us={},wall_end_us={}",
                task / 1_000, ps / 1_000, pe / 1_000, ws / 1_000, we / 1_000
            );
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().insert("x-tvc-benchmark-cpu", value);
            }
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn cpu_clock_excludes_time_waiting_between_polls() {
        let wall = Instant::now();
        let (answer, cpu) = task_cpu(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            42
        })
        .await;
        assert_eq!(answer, 42);
        assert!(cpu.expect("thread CPU clock") < wall.elapsed().as_nanos() as u64 / 2);
    }

    #[tokio::test]
    async fn cpu_clock_counts_executing_work() {
        let ((), cpu) = task_cpu(async {
            let start = clock_ns(ClockId::CLOCK_THREAD_CPUTIME_ID).unwrap();
            while clock_ns(ClockId::CLOCK_THREAD_CPUTIME_ID).unwrap() - start < 5_000_000 {
                std::hint::black_box(7u64.wrapping_mul(11));
            }
        })
        .await;
        assert!(cpu.unwrap() >= 5_000_000);
    }
}
