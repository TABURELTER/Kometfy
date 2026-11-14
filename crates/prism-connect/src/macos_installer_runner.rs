//! Bounded process runner for the fixed launchd commands. It is not connected
//! to installation. Runtime recovery and handling escaped descendants remain
//! required before an installer can safely rely on it.
use std::{io::{self, Read}, os::{fd::AsRawFd, unix::process::CommandExt}, process::{Child, Command as ProcessCommand, Stdio}, thread, time::{Duration, Instant}};
use crate::macos_installer_services::{Command, Output, Runner};

const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const TIME_LIMIT: Duration = Duration::from_secs(15);

pub(crate) struct LaunchctlRunner;
impl Runner for LaunchctlRunner {
    fn run(&mut self, command: Command) -> Result<Output, &'static str> {
        let mut process = ProcessCommand::new("/bin/launchctl");
        process.args(command.args()).env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").env("LC_ALL", "C");
        run_process(&mut process, TIME_LIMIT, OUTPUT_LIMIT)
    }
}

/// Own the child until it is reaped. The separate process group lets us also
/// kill ordinary descendants on a timeout, before the parent's PID is reaped.
struct ChildGuard { child: Child, reaped: bool }
impl ChildGuard {
    fn terminate_and_wait(&mut self) {
        if self.reaped { return; }
        let pid = self.child.id() as libc::pid_t;
        // This process was spawned as a fresh process-group leader. A child
        // which deliberately creates a new session is outside this guarantee.
        unsafe { libc::kill(-pid, libc::SIGKILL); }
        let _ = self.child.kill();
        loop {
            match self.child.wait() {
                Ok(_) => { self.reaped = true; return; }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.raw_os_error() == Some(libc::ECHILD) => { self.reaped = true; return; }
                // Keep retrying: returning while a child can still change
                // launchd would make releasing the guard lock unsafe.
                Err(_) => thread::yield_now(),
            }
        }
    }
}
impl Drop for ChildGuard { fn drop(&mut self) { self.terminate_and_wait(); } }

pub(crate) fn run_process(process: &mut ProcessCommand, timeout: Duration, limit: usize) -> Result<Output, &'static str> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) || limit == 0 || limit > OUTPUT_LIMIT {
        return Err("invalid runner limits");
    }
    process.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).process_group(0);
    let child = process.spawn().map_err(|_| "cannot start launchd command")?;
    let mut guard = ChildGuard { child, reaped: false };
    let mut stdout = guard.child.stdout.take().ok_or("cannot capture launchd output")?;
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("cannot bound launchd output");
    }
    let deadline = Instant::now().checked_add(timeout).ok_or("invalid runner deadline")?;
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        // Check the clock inside the drain loop as well: a continuous stream of
        // small writes must not delay the deadline.
        let closed = loop {
            if Instant::now() >= deadline { return Err("launchd command timed out"); }
            match stdout.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    if bytes.len().checked_add(n).is_none_or(|len| len > limit) { return Err("launchd output exceeded limit"); }
                    bytes.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break false,
                Err(_) => return Err("cannot read launchd output"),
            }
        };
        match guard.child.try_wait() {
            Ok(Some(status)) => {
                guard.reaped = true;
                // EOF means no other process still owns this pipe. A lingering
                // writer makes its side effects uncertain; fail closed.
                if !closed {
                    loop {
                        if Instant::now() >= deadline { return Err("launchd command timed out"); }
                        match stdout.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if bytes.len().checked_add(n).is_none_or(|len| len > limit) { return Err("launchd output exceeded limit"); }
                                bytes.extend_from_slice(&buf[..n]);
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err("launchd output pipe remained open"),
                            Err(_) => return Err("cannot read launchd output"),
                        }
                    }
                }
                let stdout = String::from_utf8(bytes).map_err(|_| "invalid launchd output")?;
                return Ok(Output { success: status.success(), stdout });
            }
            Ok(None) => (),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("cannot wait for launchd command"),
        }
        if Instant::now() >= deadline { return Err("launchd command timed out"); }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    #[ignore = "spawned only by bounded_runner_uses_a_harmless_fixture"]
    fn subprocess_fixture() {
        match std::env::var("PRISM_LAUNCHD_RUNNER_FIXTURE").as_deref() {
            Ok("ok") => { print!("prism-fixture-ok"); io::stdout().flush().unwrap(); }
            Ok("flood") => { let _ = io::stdout().write_all(&vec![b'x'; 64 * 1024]); }
            Ok("hang") => {
                let path = std::env::var_os("PRISM_LAUNCHD_RUNNER_PID_FILE").unwrap();
                std::fs::write(path, std::process::id().to_string()).unwrap();
                thread::sleep(Duration::from_secs(10));
            }
            _ => panic!("fixture must be invoked explicitly"),
        }
    }
    fn fixture(mode: &str) -> ProcessCommand {
        let mut command = ProcessCommand::new(std::env::current_exe().unwrap());
        command.args(["--exact", "macos_installer_runner::tests::subprocess_fixture", "--ignored", "--nocapture"])
            .env("PRISM_LAUNCHD_RUNNER_FIXTURE", mode);
        command
    }
    #[test]
    fn bounded_runner_uses_a_harmless_fixture() {
        let result = run_process(&mut fixture("ok"), Duration::from_secs(5), 8192).unwrap();
        assert!(result.success && result.stdout.contains("prism-fixture-ok"));
        assert!(run_process(&mut fixture("flood"), Duration::from_secs(5), 64).is_err());
        let path = std::env::temp_dir().join(format!("prism-runner-pid-{}", uuid::Uuid::new_v4()));
        let mut hanging = fixture("hang");
        hanging.env("PRISM_LAUNCHD_RUNNER_PID_FILE", &path);
        let start = Instant::now();
        assert!(run_process(&mut hanging, Duration::from_millis(500), 8192).is_err());
        assert!(start.elapsed() < Duration::from_secs(5), "child did not terminate and get reaped");
        let pid: libc::pid_t = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        std::fs::remove_file(path).unwrap();
    }
}
