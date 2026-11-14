//! Session wrapper for an already authenticated guard channel. Establishing
//! peer identity and obtaining administrator authorization are separate.
use std::{io::{self, BufReader, Read, Write}, os::unix::net::UnixStream, sync::{Arc, Mutex}, time::{Duration, Instant}};
use crate::macos_proxy_client::{Client, State};

pub(crate) struct GuardSession {
    client: Mutex<Client<BufReader<DeadlineStream>, DeadlineStream>>,
    deadline: Arc<Mutex<Instant>>,
    timeout: Duration,
}

/// The same absolute deadline applies to every read and write in one exchange.
struct DeadlineStream { stream: UnixStream, deadline: Arc<Mutex<Instant>> }
impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        let deadline = *self.deadline.lock().map_err(|_| io::Error::other("guard deadline unavailable"))?;
        deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "guard operation timed out"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

impl GuardSession {
    /// Check both XPC code requirements without showing an authorization
    /// dialog. A stale bridge or an older client policy requires installation.
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    pub(crate) fn native_peer_ready() -> Result<bool, String> {
        use std::ffi::CString;
        unsafe extern "C" { fn prism_proxy_bridge_probe(hash: *const libc::c_char) -> libc::c_int; }
        let hash = option_env!("PRISM_BRIDGE_CDHASH").ok_or("privileged bridge pin is not configured")?;
        if hash.len() != 40 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid privileged bridge pin".into());
        }
        let hash = CString::new(hash).map_err(|_| "invalid privileged bridge pin")?;
        Ok(unsafe { prism_proxy_bridge_probe(hash.as_ptr()) } == 0)
    }
    /// Invoke the statically linked Swift bridge. The daemon hash is fixed at
    /// compile time; neither the frontend nor a daemon response supplies it.
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    pub(crate) fn open_native(timeout: Duration) -> Result<Self, String> {
        Self::open_native_with_fd(timeout, -1)
    }

    /// Transfer one end of a private socket to the authorized bridge. The
    /// other end belongs to the core supervisor and is used only for TUN fd
    /// handoff. The caller retains ownership until this synchronous call ends.
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    pub(crate) fn open_native_tun(timeout: Duration, channel: std::os::fd::BorrowedFd<'_>) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        if channel.as_raw_fd() < 3 { return Err("invalid TUN channel".into()); }
        crate::tun_macos::validate_handoff_socket(channel).map_err(|_| "invalid TUN channel".to_string())?;
        Self::open_native_with_fd(timeout, channel.as_raw_fd())
    }

    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    fn open_native_with_fd(timeout: Duration, tun_fd: i32) -> Result<Self, String> {
        use std::{ffi::CString, os::fd::FromRawFd};
        unsafe extern "C" { fn prism_proxy_bridge_open(hash: *const libc::c_char, tun_fd: libc::c_int) -> libc::c_int; }
        let hash = option_env!("PRISM_BRIDGE_CDHASH").ok_or("privileged bridge pin is not configured")?;
        if hash.len() != 40 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid privileged bridge pin".into());
        }
        let hash = CString::new(hash).map_err(|_| "invalid privileged bridge pin")?;
        // Swift performs live peer verification before the system authorization
        // dialog and returns an owned connected socket only after guard startup.
        let fd = unsafe { prism_proxy_bridge_open(hash.as_ptr(), tun_fd) };
        if fd < 0 { return Err("privileged bridge unavailable or authorization denied".into()); }
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        Self::from_authenticated_stream(stream, timeout)
    }

    /// Call only after authenticating the privileged peer and verifying that it
    /// owns this private channel. Every request has one total deadline.
    pub(crate) fn from_authenticated_stream(stream: UnixStream, timeout: Duration) -> Result<Self, String> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) { return Err("invalid guard timeout".into()); }
        let input = stream.try_clone().map_err(|e| e.to_string())?;
        let deadline = Arc::new(Mutex::new(Instant::now() + timeout));
        let reader = DeadlineStream { stream: input, deadline: deadline.clone() };
        let writer = DeadlineStream { stream, deadline: deadline.clone() };
        Ok(Self { client: Mutex::new(Client::new(BufReader::new(reader), writer)), deadline, timeout })
    }

    fn reset_deadline(&self) -> Result<(), String> {
        *self.deadline.lock().map_err(|_| "proxy guard deadline unavailable".to_string())? = Instant::now() + self.timeout;
        Ok(())
    }

    pub(crate) fn enable(&self, port: u16, bypass: &str) -> Result<(), String> {
        let mut client = self.client.lock().map_err(|_| "proxy guard state is unavailable".to_string())?;
        self.reset_deadline()?;
        client.enable(port, bypass)
    }
    /// The supervisor must already be waiting on the one-shot fd channel.
    /// If this fails, the caller must stop the supervisor before retrying.
    pub(crate) fn prepare_tun(&self) -> Result<String, String> {
        let mut client = self.client.lock().map_err(|_| "proxy guard state is unavailable".to_string())?;
        self.reset_deadline()?;
        client.prepare_tun()
    }
    pub(crate) fn activate_tun(&self) -> Result<(), String> {
        let mut client = self.client.lock().map_err(|_| "proxy guard state is unavailable".to_string())?;
        self.reset_deadline()?;
        client.activate_tun()
    }
    pub(crate) fn check_tun_session(&self) -> Result<(), String> {
        let mut client = self.client.lock().map_err(|_| "TUN guard state is unavailable".to_string())?;
        self.reset_deadline()?;
        client.check_tun_session()
    }
    pub(crate) fn restore(&self) -> Result<(), String> {
        let mut client = self.client.lock().map_err(|_| "proxy guard state is unavailable".to_string())?;
        self.reset_deadline()?;
        client.restore()
    }
    pub(crate) fn shutdown(&self) -> Result<(), String> {
        let mut client = self.client.lock().map_err(|_| "proxy guard state is unavailable".to_string())?;
        self.reset_deadline()?;
        client.shutdown()
    }
    pub(crate) fn state(&self) -> Result<State, String> {
        Ok(self.client.lock().map_err(|_| "proxy guard state is unavailable".to_string())?.state())
    }
    /// A watchdog must not block the async executor behind an in-flight guard
    /// request; busy is rechecked on its next tick.
    pub(crate) fn try_state(&self) -> Result<Option<State>, String> {
        match self.client.try_lock() {
            Ok(client) => Ok(Some(client.state())),
            Err(std::sync::TryLockError::WouldBlock) => Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => Err("proxy guard state is unavailable".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_proxy_guard::{self, Backend};
    use std::{io::{BufRead, BufReader}, thread};

    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    #[test]
    fn native_tun_rejects_non_socket_before_requesting_authorization() {
        use std::os::fd::AsFd;
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(GuardSession::open_native_tun(Duration::from_secs(1), file.as_fd()).is_err());
    }

    #[derive(Default)]
    struct Fake(Vec<&'static str>);
    impl Backend for Fake {
        fn recover_previous(&mut self) -> Result<(), String> { self.0.push("startup"); Ok(()) }
        fn enable(&mut self, _: u16, _: &str) -> Result<(), String> { self.0.push("enable"); Ok(()) }
        fn restore(&mut self, _: u16) -> Result<(), String> { self.0.push("restore"); Ok(()) }
    }
    #[test]
    fn session_runs_and_restores_before_shutdown() {
        let (app, guard) = UnixStream::pair().unwrap();
        let task = thread::spawn(move || {
            let mut backend = Fake::default();
            macos_proxy_guard::serve(&mut BufReader::new(guard.try_clone().unwrap()), &mut &guard, &mut backend).unwrap();
            backend.0
        });
        let session = GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap();
        session.enable(7890, "localhost;<local>").unwrap();
        assert_eq!(session.state().unwrap(), State::Active(7890));
        session.shutdown().unwrap();
        assert_eq!(session.state().unwrap(), State::Stopped);
        assert_eq!(task.join().unwrap(), ["startup", "enable", "restore"]);
    }
    #[test]
    fn timed_out_guard_is_never_treated_as_restored() {
        let (app, guard) = UnixStream::pair().unwrap();
        let task = thread::spawn(move || {
            let mut input = BufReader::new(guard);
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            // Hold the channel open without replying until the client closes it.
            line.clear();
            input.read_line(&mut line).unwrap();
        });
        let session = GuardSession::from_authenticated_stream(app, Duration::from_millis(100)).unwrap();
        assert!(session.enable(7890, "localhost;<local>").is_err());
        assert_eq!(session.state().unwrap(), State::Uncertain);
        assert!(session.restore().is_err());
        drop(session);
        task.join().unwrap();
    }
    #[test]
    fn slow_drip_cannot_extend_the_total_deadline() {
        let (app, mut guard) = UnixStream::pair().unwrap();
        let task = thread::spawn(move || {
            let mut input = BufReader::new(guard.try_clone().unwrap());
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            for byte in b"{\"status\":\"active\"}\n" {
                if guard.write_all(&[*byte]).is_err() { break; }
                thread::sleep(Duration::from_millis(30));
            }
        });
        let session = GuardSession::from_authenticated_stream(app, Duration::from_millis(120)).unwrap();
        let started = Instant::now();
        assert!(session.enable(7890, "localhost;<local>").is_err());
        assert!(started.elapsed() < Duration::from_secs(2), "slow peer exceeded deadline");
        assert_eq!(session.state().unwrap(), State::Uncertain);
        drop(session);
        task.join().unwrap();
    }
}
