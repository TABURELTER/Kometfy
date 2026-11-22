//! Hangs. Every operation that changes the core or the capture runs under one lock (`Manager::op_lock`); when one
//! runs far longer than it ever should, it is counted (`hang.<operation>`), noted in the recent events and logged,
//! once per run, and logged again with its full length when it ends. A stuck app then shows in the statistics and in
//! the log, instead of only as one that "does nothing". The app adds its own: the main thread (`hang.main`) and the
//! interface (`hang.ui`).

use std::{
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Mutex,
    },
    time::{Duration, Instant},
};

/// Longer than any operation should take: a first connect waits up to 40 s for the core's rule lists.
pub const HANG_AFTER: Duration = Duration::from_secs(90);

struct Busy {
    op: &'static str,
    since: Instant,
    id: u64,
    reported: bool,
}

#[derive(Default)]
pub struct Watch {
    cur: Mutex<Option<Busy>>,
    next: AtomicU64,
}

impl Watch {
    pub fn begin(&self, op: &'static str) -> u64 {
        let id = self.next.fetch_add(1, SeqCst) + 1;
        if let Ok(mut c) = self.cur.lock() {
            *c = Some(Busy { op, since: Instant::now(), id, reported: false });
        }
        id
    }

    /// Ends the operation `id` began; logs how long a hung one took in the end.
    pub fn end(&self, id: u64) {
        let Ok(mut c) = self.cur.lock() else { return };
        if c.as_ref().is_some_and(|b| b.id == id) {
            let b = c.take().unwrap();
            if b.reported {
                tracing::warn!("hang over: {} ran for {} s", b.op, b.since.elapsed().as_secs());
            }
        }
    }

    /// The running operation, the first time it has run longer than `after`; None otherwise.
    pub fn check(&self, after: Duration) -> Option<(&'static str, Duration)> {
        let mut c = self.cur.lock().ok()?;
        let b = c.as_mut()?;
        if b.reported || b.since.elapsed() < after {
            return None;
        }
        b.reported = true;
        Some((b.op, b.since.elapsed()))
    }
}

/// The operation lock, held, with its operation watched until it is dropped.
pub struct OpGuard<'a> {
    _lock: tokio::sync::MutexGuard<'a, ()>,
    watch: &'a Watch,
    id: u64,
}

impl<'a> OpGuard<'a> {
    pub fn new(lock: tokio::sync::MutexGuard<'a, ()>, watch: &'a Watch, op: &'static str) -> Self {
        let id = watch.begin(op);
        Self { _lock: lock, watch, id }
    }
}

impl Drop for OpGuard<'_> {
    fn drop(&mut self) {
        self.watch.end(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_operation_is_reported_once() {
        let w = Watch::default();
        let id = w.begin("connect");
        assert_eq!(w.check(Duration::from_secs(60)), None, "not long yet");
        let (op, _) = w.check(Duration::ZERO).unwrap();
        assert_eq!(op, "connect");
        assert_eq!(w.check(Duration::ZERO), None, "once per run");
        w.end(id);
        assert_eq!(w.check(Duration::ZERO), None, "nothing runs");
    }

    #[test]
    fn an_old_operation_ending_late_does_not_end_the_new_one() {
        let w = Watch::default();
        let old = w.begin("disconnect");
        let _new = w.begin("connect");
        w.end(old);
        assert_eq!(w.check(Duration::ZERO).map(|(op, _)| op), Some("connect"));
    }
}
