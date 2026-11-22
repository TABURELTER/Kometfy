//! mihomo child process: spawn hidden, die with us (Windows job object), capture output.

use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};

#[cfg(windows)]
use std::os::windows::{io::AsRawHandle, process::CommandExt};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
};

use crate::{
    error::{Error, Result},
};
#[cfg(windows)]
use crate::util::CREATE_NO_WINDOW;

pub type LineSink = Arc<dyn Fn(String) + Send + Sync>;

/// Reserved in the freshly exec'd supervisor and used in mihomo's config.
#[cfg(target_os = "macos")]
pub const MACOS_TUN_CORE_FD: i32 = 198;

#[cfg(all(target_os = "macos", debug_assertions))]
#[doc(hidden)]
pub fn test_send_descriptor(socket: std::os::fd::BorrowedFd<'_>, descriptor: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    crate::tun_macos::send_descriptor(socket, descriptor)
}

#[cfg(all(target_os = "macos", debug_assertions))]
#[doc(hidden)]
pub fn test_send_descriptor_and_confirm(socket: std::os::fd::BorrowedFd<'_>, descriptor: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    crate::tun_macos::send_descriptor_and_confirm(socket, descriptor)
}

#[cfg(target_os = "macos")]
enum TunHandoff {
    Direct(std::os::fd::OwnedFd),
    Channel(std::os::fd::OwnedFd),
    #[cfg(debug_assertions)]
    TestChannel(std::os::fd::OwnedFd),
}

/// Called before the GUI starts. The supervisor is the parent of the core, and watches a pipe
/// held only by the GUI. EOF (including GUI crashes) causes it to kill and reap its own child.
/// It never signals a PID that has already been reaped and could have been reused.
#[cfg(target_os = "macos")]
pub fn supervisor_entry() {
    use std::io::Write;
    use std::sync::mpsc;
    let mut args = std::env::args_os().skip(1);
    let mode = args.next();
    let standard = mode.as_deref() == Some(std::ffi::OsStr::new("--prism-supervise-core"));
    let tun = mode.as_deref() == Some(std::ffi::OsStr::new("--prism-supervise-core-tun"));
    #[cfg(debug_assertions)]
    let test_tun = mode.as_deref() == Some(std::ffi::OsStr::new("--prism-supervise-core-test-fd"));
    #[cfg(not(debug_assertions))]
    let test_tun = false;
    if !standard && !tun && !test_tun { return; }
    // Receive before starting any threads: Darwin lacks atomic
    // MSG_CMSG_CLOEXEC. The channel must be authenticated by the launcher.
    let _inherited_tun = if tun || test_tun {
        use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
        let channel = args.next().and_then(|s| s.to_str().and_then(|s| s.parse::<i32>().ok()))
            .filter(|fd| *fd >= 3).unwrap_or_else(|| std::process::exit(2));
        if unsafe { libc::fcntl(channel, libc::F_GETFD) } < 0 { eprintln!("TUN channel is invalid: {}", std::io::Error::last_os_error()); std::process::exit(2); }
        let channel = unsafe { OwnedFd::from_raw_fd(channel) };
        let mut wait = libc::pollfd { fd: channel.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut wait, 1, 5000) } <= 0 || wait.revents & libc::POLLIN == 0 {
            eprintln!("TUN descriptor channel closed or timed out"); std::process::exit(2);
        }
        let received = match crate::tun_macos::receive_descriptor_single_threaded(channel.as_fd()) {
            Ok(fd) => fd,
            Err(e) => { eprintln!("TUN descriptor handoff failed: {e}"); std::process::exit(2); }
        };
        if tun && crate::tun_macos::descriptor_utun_name(received.as_fd()).is_err() {
            eprintln!("TUN descriptor is not a macOS utun"); std::process::exit(2);
        }
        let source = received.as_raw_fd();
        let inherited = if source == MACOS_TUN_CORE_FD { received } else {
            if unsafe { libc::fcntl(MACOS_TUN_CORE_FD, libc::F_GETFD) } >= 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
                eprintln!("reserved TUN descriptor is already in use"); std::process::exit(2);
            }
            if unsafe { libc::dup2(source, MACOS_TUN_CORE_FD) } < 0 { eprintln!("TUN descriptor duplication failed: {}", std::io::Error::last_os_error()); std::process::exit(2); }
            drop(received);
            unsafe { OwnedFd::from_raw_fd(MACOS_TUN_CORE_FD) }
        };
        let flags = unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 { std::process::exit(2); }
        if let Err(e) = crate::tun_macos::confirm_descriptor_received(channel.as_fd()) {
            eprintln!("TUN descriptor acknowledgement failed: {e}"); std::process::exit(2);
        }
        drop(channel);
        Some(inherited)
    } else { None };
    let Some(program) = args.next() else { std::process::exit(2) };
    let mut child = match Command::new(program).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(e) => { eprintln!("could not start core: {e}"); std::process::exit(1); }
    };
    // Reserve the first line for a private handshake, before forwarding any core output.
    println!("PRISM_CORE_PID={}", child.id());
    if std::io::stdout().flush().is_err() {
        let _ = child.kill();
        let _ = child.wait();
        std::process::exit(1);
    }
    let (output_tx, output_rx) = mpsc::channel();
    if let Some(mut out) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut stdout = std::io::stdout();
            let _ = std::io::copy(&mut out, &mut stdout);
            let _ = stdout.flush();
            let _ = output_tx.send(());
        });
    }
    // The child can exit while its final output is still in the pipe. Give the forwarder time
    // to flush it, but don't hang forever if a grandchild keeps the pipe open or the GUI stalls.
    let drain_output = || { let _ = output_rx.recv_timeout(std::time::Duration::from_secs(2)); };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut buf = [0u8; 128];
        loop {
            match input.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = tx.send(());
    });
    loop {
        if rx.try_recv().is_ok() {
            // The child has not been waited for; its PID cannot yet have been reused.
            let _ = child.kill();
            let _ = child.wait();
            drain_output();
            std::process::exit(0);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                drain_output();
                std::process::exit(status.code().unwrap_or(1));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(e) => {
                eprintln!("could not monitor core: {e}");
                let _ = child.kill();
                let _ = child.wait();
                drain_output();
                std::process::exit(1);
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn supervisor_entry() {}

#[cfg(windows)]
struct Job(HANDLE);
// SAFETY: a job handle is just a kernel object id, usable from any thread.
#[cfg(windows)]
unsafe impl Send for Job {}
#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        // Closing the handle kills the core (KILL_ON_JOB_CLOSE): no orphaned TUN adapters.
        unsafe { CloseHandle(self.0) };
    }
}

struct Running {
    child: Child,
    pid: u32,
    // compared only by the macOS proxy guard (and tests)
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
    identity: CoreIdentity,
    #[cfg(windows)]
    _job: Option<Job>,
}

/// An identity remains unique while held, including if the OS recycles a PID.
#[derive(Clone)]
pub(crate) struct CoreIdentity(#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))] Arc<()>);

#[derive(Default)]
pub struct Core {
    inner: Mutex<Option<Running>>,
}

#[cfg(windows)]
fn kill_on_close_job(child: &Child) -> Option<Job> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let set = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if set == 0 || AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) == 0 {
            CloseHandle(job);
            return None;
        }
        Some(Job(job))
    }
}

fn spawn_reader<R: Read + Send + 'static>(r: R, sink: LineSink) {
    std::thread::spawn(move || {
        let mut rd = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match rd.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).trim_end().to_string();
                    if !line.is_empty() {
                        sink(line);
                    }
                }
            }
        }
    });
}

impl Core {
    pub fn start(&self, bin: &Path, home: &Path, config: &Path, sink: LineSink) -> Result<u32> {
        let mut cmd = Command::new(bin);
        cmd.arg("-d").arg(home).arg("-f").arg(config);
        self.spawn(cmd, sink)
    }

    /// Android: start the core with the tunnel's descriptor passed down to it. The descriptor lives on in
    /// the child for as long as the core does; the VPN ends when the core exits and closes it.
    #[cfg(target_os = "android")]
    pub fn start_with_fd(&self, bin: &Path, home: &Path, config: &Path, sink: LineSink, fd: std::os::fd::RawFd) -> Result<u32> {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new(bin);
        cmd.arg("-d").arg(home).arg("-f").arg(config);
        // changed only in the forked child, so another launch never inherits the descriptor
        unsafe {
            cmd.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        self.spawn(cmd, sink)
    }

    /// Run a prepared command as the core process: hidden, output captured, killed with us.
    /// Also used for the Xray sidecar, which has its own `Core` slot.
    pub fn spawn(&self, cmd: Command, sink: LineSink) -> Result<u32> {
        #[cfg(target_os = "macos")]
        { self.spawn_inner(cmd, sink, None, None).map(|(pid, _)| pid) }
        #[cfg(not(target_os = "macos"))]
        { self.spawn_inner(cmd, sink).map(|(pid, _)| pid) }
    }

    /// Pass a previously authenticated TUN descriptor through the supervisor.
    /// The caller must use the same descriptor number in the core configuration
    /// and keep routing disabled until the privileged setup has been verified.
    #[cfg(target_os = "macos")]
    pub fn spawn_with_tun_descriptor(&self, cmd: Command, sink: LineSink, descriptor: std::os::fd::OwnedFd) -> Result<u32> {
        use std::os::fd::AsRawFd;
        if descriptor.as_raw_fd() < 3 { return Err(Error::msg("invalid TUN descriptor")); }
        self.spawn_inner(cmd, sink, Some(TunHandoff::Direct(descriptor)), None).map(|(pid, _)| pid)
    }

    /// Spawn a supervisor that receives the TUN fd over a private authenticated
    /// channel. Build mihomo's config with `MACOS_TUN_CORE_FD` beforehand.
    #[cfg(target_os = "macos")]
    pub fn spawn_with_tun_channel(&self, cmd: Command, sink: LineSink, channel: std::os::fd::OwnedFd) -> Result<u32> {
        use std::os::fd::AsRawFd;
        if channel.as_raw_fd() < 3 { return Err(Error::msg("invalid TUN channel")); }
        self.spawn_with_tun_channel_identified(cmd, sink, channel).map(|(pid, _)| pid)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn spawn_with_tun_channel_identified(&self, cmd: Command, sink: LineSink, channel: std::os::fd::OwnedFd) -> Result<(u32, CoreIdentity)> {
        use std::os::fd::AsRawFd;
        if channel.as_raw_fd() < 3 { return Err(Error::msg("invalid TUN channel")); }
        self.spawn_inner(cmd, sink, Some(TunHandoff::Channel(channel)), None)
    }

    /// Integration tests run outside the app executable and supply its path.
    #[cfg(all(target_os = "macos", debug_assertions))]
    #[doc(hidden)]
    pub fn test_spawn_with_tun_descriptor(&self, cmd: Command, sink: LineSink, descriptor: std::os::fd::OwnedFd, supervisor: &Path) -> Result<u32> {
        use std::os::fd::AsRawFd;
        if descriptor.as_raw_fd() < 3 { return Err(Error::msg("invalid TUN descriptor")); }
        self.spawn_inner(cmd, sink, Some(TunHandoff::Direct(descriptor)), Some(supervisor)).map(|(pid, _)| pid)
    }

    #[cfg(all(target_os = "macos", debug_assertions))]
    #[doc(hidden)]
    pub fn test_spawn_with_tun_channel(&self, cmd: Command, sink: LineSink, channel: std::os::fd::OwnedFd, supervisor: &Path) -> Result<u32> {
        self.spawn_inner(cmd, sink, Some(TunHandoff::TestChannel(channel)), Some(supervisor)).map(|(pid, _)| pid)
    }

    #[cfg(all(target_os = "macos", debug_assertions))]
    #[doc(hidden)]
    pub fn test_spawn_with_validated_tun_channel(&self, cmd: Command, sink: LineSink, channel: std::os::fd::OwnedFd, supervisor: &Path) -> Result<u32> {
        self.spawn_inner(cmd, sink, Some(TunHandoff::Channel(channel)), Some(supervisor)).map(|(pid, _)| pid)
    }

    fn spawn_inner(&self, mut cmd: Command, sink: LineSink, #[cfg(target_os = "macos")] descriptor: Option<TunHandoff>, #[cfg(target_os = "macos")] supervisor_path: Option<&Path>) -> Result<(u32, CoreIdentity)> {
        let mut g = self.inner.lock().unwrap();
        if let Some(r) = g.as_mut() {
            if r.child.try_wait()?.is_none() {
                return Err(Error::msg("core is already running"));
            }
        }
        #[cfg(target_os = "macos")]
        let mut cmd = {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let executable = match supervisor_path { Some(path) => path.to_path_buf(), None => std::env::current_exe()? };
            let mut supervisor = Command::new(executable);
            let (mode, fd) = match descriptor.as_ref() {
                Some(TunHandoff::Direct(fd)) => ("--prism-supervise-core", Some(fd.as_raw_fd())),
                Some(TunHandoff::Channel(fd)) => ("--prism-supervise-core-tun", Some(fd.as_raw_fd())),
                #[cfg(debug_assertions)]
                Some(TunHandoff::TestChannel(fd)) => ("--prism-supervise-core-test-fd", Some(fd.as_raw_fd())),
                None => ("--prism-supervise-core", None),
            };
            supervisor.arg(mode);
            if mode != "--prism-supervise-core" { supervisor.arg(fd.unwrap().to_string()); }
            supervisor.arg(cmd.get_program()).args(cmd.get_args());
            if let Some(dir) = cmd.get_current_dir() { supervisor.current_dir(dir); }
            for (key, value) in cmd.get_envs() {
                if let Some(value) = value { supervisor.env(key, value); } else { supervisor.env_remove(key); }
            }
            if let Some(fd) = fd {
                // Change the flag only in the forked child: concurrent launches
                // in the GUI must never inherit this descriptor accidentally.
                unsafe { supervisor.pre_exec(move || {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                }); }
            }
            supervisor
        };
        // Android: for every direct UDP packet the core's loop detector lists the network interfaces, and an
        // app may not do that (Android 11+ refuses the request), so each of those packets failed with
        // "netlinkrib: permission denied". What it guards against, the core sending to its own listeners
        // through its own tunnel, cannot happen here: the app and the core are kept out of the tunnel.
        #[cfg(target_os = "android")]
        cmd.env("DISABLE_LOOPBACK_DETECTOR", "1");
        #[cfg(target_os = "macos")]
        cmd.stdin(Stdio::piped());
        #[cfg(not(target_os = "macos"))]
        cmd.stdin(Stdio::null());
        cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let mut child = cmd.spawn()?;
        #[cfg(not(target_os = "macos"))]
        let pid = child.id();
        #[cfg(target_os = "macos")]
        let (pid, stdout) = {
            let out = child.stdout.take().ok_or_else(|| Error::msg("supervisor stdout unavailable"))?;
            let mut out = BufReader::new(out);
            let mut header = String::new();
            let pid = match out.read_line(&mut header) {
                Ok(_) => header.trim().strip_prefix("PRISM_CORE_PID=").and_then(|s| s.parse::<u32>().ok()),
                Err(_) => None,
            };
            match pid {
                Some(pid) => (pid, out),
                None => {
                    drop(child.stdin.take());
                    let _ = child.wait();
                    let mut detail = String::new();
                    if let Some(stderr) = child.stderr.take() { let _ = stderr.take(4096).read_to_string(&mut detail); }
                    return Err(Error::msg(format!("could not start core supervisor: {}", detail.trim())));
                }
            }
        };
        #[cfg(target_os = "macos")]
        spawn_reader(stdout, sink.clone());
        #[cfg(not(target_os = "macos"))]
        if let Some(o) = child.stdout.take() {
            spawn_reader(o, sink.clone());
        }
        if let Some(e) = child.stderr.take() {
            spawn_reader(e, sink);
        }
        #[cfg(windows)]
        let job = kill_on_close_job(&child);
        let identity = CoreIdentity(Arc::new(()));
        *g = Some(Running {
            child,
            pid,
            identity: identity.clone(),
            #[cfg(windows)]
            _job: job,
        });
        Ok((pid, identity))
    }

    pub fn stop(&self) {
        let taken = self.inner.lock().unwrap().take();
        Self::stop_taken(taken);
    }

    /// Only remove the exact instance that the caller started. The check and
    /// removal share one lock, so a replacement cannot be stopped by cleanup.
    #[cfg(any(test, target_os = "macos"))]
    pub(crate) fn stop_if_identity(&self, identity: &CoreIdentity) -> bool {
        let taken = {
            let mut slot = self.inner.lock().unwrap();
            if slot.as_ref().is_some_and(|r| Arc::ptr_eq(&r.identity.0, &identity.0)) {
                slot.take()
            } else { None }
        };
        let stopped = taken.is_some();
        Self::stop_taken(taken);
        stopped
    }

    fn stop_taken(taken: Option<Running>) {
        if let Some(mut r) = taken {
            #[cfg(target_os = "macos")]
            drop(r.child.stdin.take());
            #[cfg(not(target_os = "macos"))]
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }

    /// Some(pid) while the process is alive. Clears the slot once it has exited.
    pub fn pid(&self) -> Option<u32> {
        let mut g = self.inner.lock().unwrap();
        let alive = match g.as_mut() {
            Some(r) => matches!(r.child.try_wait(), Ok(None)).then_some(r.pid),
            None => None,
        };
        if alive.is_none() {
            *g = None;
        }
        alive
    }

    /// Capture a stable identity while the supervised child is still alive.
    #[cfg(target_os = "macos")]
    pub(crate) fn live_identity(&self) -> Option<CoreIdentity> {
        let mut slot = self.inner.lock().ok()?;
        let live = slot.as_mut().and_then(|r| matches!(r.child.try_wait(), Ok(None)).then(|| r.identity.clone()));
        if live.is_none() { *slot = None; }
        live
    }

    /// Compare identity and process state under the same lock. A replacement
    /// or reused PID never makes an old identity appear alive.
    #[cfg(target_os = "macos")]
    pub(crate) fn identity_is_running(&self, identity: &CoreIdentity) -> bool {
        let Ok(mut slot) = self.inner.lock() else { return false };
        match slot.as_mut() {
            Some(r) if Arc::ptr_eq(&r.identity.0, &identity.0) => matches!(r.child.try_wait(), Ok(None)),
            _ => false,
        }
    }

    /// Exercise lifecycle ownership with an actual, network-inert child in
    /// macOS unit tests; production always starts the supervisor instead.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn test_start_inert_child(&self) -> CoreIdentity {
        let child = Command::new("/bin/cat").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let pid = child.id();
        let identity = CoreIdentity(Arc::new(()));
        let mut slot = self.inner.lock().unwrap();
        assert!(slot.is_none());
        *slot = Some(Running { child, pid, identity: identity.clone() });
        identity
    }
}

impl Drop for Core {
    fn drop(&mut self) { self.stop(); }
}

/// `mihomo -t`: validate a config without touching the running core.
pub fn validate(bin: &Path, home: &Path, config: &Path) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.arg("-t")
        .arg("-d")
        .arg(home)
        .arg("-f")
        .arg(config)
        .stdin(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output()?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Err(Error::msg(summarize_error(&text)))
}

/// Pull the human part out of mihomo's logfmt lines.
pub fn summarize_error(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let pick = lines
        .iter()
        .rev()
        .find(|l| l.contains("level=error") || l.contains("level=fatal") || l.to_lowercase().contains("error"))
        .or_else(|| lines.last())
        .copied()
        .unwrap_or("core rejected the config");
    match pick.find("msg=\"") {
        Some(i) => pick[i + 5..].trim_end_matches('"').replace("\\\"", "\"").to_string(),
        None => pick.to_string(),
    }
}

/// Why the core's controller did not come up in time, from its last lines: its own error if it logged one; that it
/// was still downloading its rule lists if that is the last thing it did (a slow or blocked list server); otherwise
/// that it did not become ready. A plain last line such as "Start initial provider …" read as the error before.
pub fn not_ready(tail: &str, secs: u64) -> String {
    let lines: Vec<&str> = tail.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return format!("core did not become ready in {secs} s");
    }
    if lines.iter().any(|l| l.contains("level=error") || l.contains("level=fatal")) {
        return summarize_error(tail);
    }
    if lines.last().is_some_and(|l| l.contains("initial provider")) {
        return format!("the core was still downloading its rule lists after {secs} s");
    }
    format!("core did not become ready in {secs} s")
}

/// `v1.19.33`, `alpha-abc123`, ... from `mihomo -v`.
pub fn version(bin: &Path) -> Option<String> {
    let mut cmd = Command::new(bin);
    cmd.arg("-v").stdin(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    let lower = first.to_lowercase();
    if !lower.contains("mihomo") && !lower.contains("clash meta") && !lower.contains("clash.meta") { return None; }
    first
        .split_whitespace()
        .find(|t| {
            (t.starts_with('v') && t[1..].starts_with(|c: char| c.is_ascii_digit()))
                || t.starts_with("alpha")
        })
        .map(String::from)
        .or_else(|| Some(first.chars().take(40).collect()))
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_core_that_is_not_ready_says_why() {
        let loading = "time=\"x\" level=info msg=\"Use tcp concurrent\"
time=\"x\" level=info msg=\"Start initial provider whitelist\"";
        assert_eq!(not_ready(loading, 40), "the core was still downloading its rule lists after 40 s");
        let failed = "time=\"x\" level=error msg=\"listen tcp: bind: address already in use\"";
        assert_eq!(not_ready(failed, 40), "listen tcp: bind: address already in use");
        assert_eq!(not_ready("time=\"x\" level=info msg=\"Use tcp concurrent\"", 40), "core did not become ready in 40 s");
        assert_eq!(not_ready("", 40), "core did not become ready in 40 s");
    }
    use super::*;

    #[test]
    #[cfg(any(unix, windows))]
    fn stale_identity_cannot_stop_replacement_core() {
        #[cfg(unix)]
        let mut command = { let mut c = Command::new("/bin/sh"); c.args(["-c", "read ignored"]); c };
        #[cfg(windows)]
        let mut command = { let mut c = Command::new("ping.exe"); c.args(["-n", "30", "127.0.0.1"]); c };
        let child = command.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let pid = child.id();
        let replacement = CoreIdentity(Arc::new(()));
        let stale = CoreIdentity(Arc::new(()));
        let core = Core::default();
        *core.inner.lock().unwrap() = Some(Running {
            child, pid, identity: replacement.clone(),
            #[cfg(windows)]
            _job: None,
        });
        assert!(!core.stop_if_identity(&stale));
        assert_eq!(core.pid(), Some(pid));
        assert!(core.stop_if_identity(&replacement));
        assert_eq!(core.pid(), None);
    }

    #[test]
    fn error_summary_extracts_msg() {
        let t = "time=\"2026\" level=info msg=\"start\"\ntime=\"2026\" level=error msg=\"proxy 0: unsupported\"\n";
        assert_eq!(summarize_error(t), "proxy 0: unsupported");
    }
}
