//! Coordinate the one-shot privileged utun handoff with core startup.
//!
//! This is only the descriptor handoff, not a complete VPN: routing, DNS,
//! recovery and connection lifecycle must be implemented before enabling it.

/// Run the supervisor and helper concurrently: the supervisor cannot report
/// its child until it receives the descriptor, while the helper waits for the
/// supervisor's acknowledgement. If either fails, never leave a successfully
/// started core running with an uncertain descriptor handoff.
fn coordinate<S, P, A, K, C, T>(start: S, prepare: P, abort_wait: A, stop: K, close_guard: C) -> Result<(u32, String), String>
where
    S: FnOnce() -> Result<(u32, T), String> + Send,
    T: Send,
    P: FnOnce() -> Result<String, String>,
    A: FnOnce(),
    K: FnOnce(T),
    C: FnOnce() -> Result<(), String>,
{
    let (started, prepared) = std::thread::scope(|scope| {
        let child = scope.spawn(start);
        let prepared = prepare();
        if prepared.is_err() { abort_wait(); }
        let started = child.join().unwrap_or_else(|_| Err("core startup task failed".into()));
        (started, prepared)
    });
    match (started, prepared) {
        (Ok((pid, _)), Ok(name)) => Ok((pid, name)),
        (started, prepared) => {
            // Only stop a process this call actually started. In particular, a
            // rejected duplicate start must never stop an existing connection.
            let started = match started {
                Ok((_, identity)) => { stop(identity); Ok(()) }
                Err(error) => Err(error),
            };
            let close = close_guard();
            let mut error = match (started, prepared) {
                (Err(core), Err(tun)) => format!("TUN setup failed: {tun}; core startup failed: {core}"),
                (Err(core), _) => format!("core startup failed: {core}"),
                (_, Err(tun)) => format!("TUN setup failed: {tun}"),
                _ => unreachable!(),
            };
            if let Err(close) = close { error.push_str(&format!("; helper shutdown failed: {close}")); }
            Err(error)
        }
    }
}

/// The guard must already be authorized with the peer end of `channel` and
/// the caller must retain it for the lifetime of the resulting session. Open
/// the guard before calling this function so user authorization cannot consume
/// the supervisor's short descriptor deadline. Do not call from the UI thread.
#[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
pub(crate) fn start(
    core: &crate::mihomo::Core,
    guard: &crate::macos_proxy_session::GuardSession,
    command: std::process::Command,
    sink: crate::mihomo::LineSink,
    channel: std::os::unix::net::UnixStream,
) -> Result<(u32, String), String> {
    use std::os::fd::{AsFd, OwnedFd};
    let interrupt = (|| {
        crate::tun_macos::validate_handoff_socket(channel.as_fd())?;
        channel.try_clone()
    })().map_err(|e| {
        let mut error = format!("invalid TUN handoff channel: {e}");
        if let Err(close) = guard.shutdown() { error.push_str(&format!("; helper shutdown failed: {close}")); }
        error
    })?;
    let descriptor: OwnedFd = channel.into();
    coordinate(
        move || core.spawn_with_tun_channel_identified(command, sink, descriptor).map_err(|e| e.to_string()),
        || guard.prepare_tun(),
        || { let _ = interrupt.shutdown(std::net::Shutdown::Both); },
        |identity| { core.stop_if_identity(&identity); },
        || guard.shutdown(),
    )
}

#[cfg(test)]
mod tests {
    use super::coordinate;
    use std::sync::{Arc, Mutex, mpsc};

    #[test]
    fn waits_for_both_supervisor_and_helper() {
        let (ack, ready) = mpsc::channel();
        let result = coordinate(
            move || { ready.recv().unwrap(); Ok((42, ())) },
            || { ack.send(()).unwrap(); Ok("utun7".into()) },
            || panic!("unexpected interrupt"), |_| panic!("unexpected stop"), || panic!("unexpected close"),
        );
        assert_eq!(result.unwrap(), (42, "utun7".into()));
    }

    #[test]
    fn uncertain_transfer_interrupts_wait_and_stops_started_core() {
        let (interrupt, wait) = mpsc::channel();
        let events = Arc::new(Mutex::new(Vec::new()));
        let stopped = events.clone();
        let closed = events.clone();
        let result = coordinate(
            move || { wait.recv().unwrap(); Ok((42, ())) },
            || Err("lost acknowledgement".into()),
            || interrupt.send(()).unwrap(),
            move |_| stopped.lock().unwrap().push("stop"),
            move || { closed.lock().unwrap().push("close"); Ok(()) },
        );
        assert!(result.unwrap_err().contains("lost acknowledgement"));
        assert_eq!(*events.lock().unwrap(), ["stop", "close"]);
    }

    #[test]
    fn failed_start_does_not_stop_a_preexisting_core() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let closed = events.clone();
        let result = coordinate(|| Err::<(u32, ()), _>("already running".into()), || Ok("utun7".into()),
            || panic!("unexpected interrupt"), |_| panic!("must not stop existing core"),
            move || { closed.lock().unwrap().push("close"); Ok(()) });
        assert!(result.unwrap_err().contains("already running"));
        assert_eq!(*events.lock().unwrap(), ["close"]);
    }

    #[test]
    fn reports_failure_to_close_guard() {
        let result = coordinate(|| Err::<(u32, ()), _>("core failed".into()), || Ok("utun7".into()),
            || panic!("unexpected interrupt"), |_| panic!("unexpected stop"),
            || Err("guard unresponsive".into()));
        let error = result.unwrap_err();
        assert!(error.contains("core failed"));
        assert!(error.contains("guard unresponsive"));
    }
}
