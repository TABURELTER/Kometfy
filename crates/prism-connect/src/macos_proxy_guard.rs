//! Narrow, single-client proxy guard protocol. The application does not start
//! this guard yet; installation, peer authentication and boot recovery remain
//! prerequisites for enabling the macOS capture mode.
use std::io::{BufRead, Read, Write};

// Keep 0.0.0.0/0 addressable as the physical default route on Darwin. A
// 0.0.0.0/1 route through utun also matches the kernel's default-route lookup
// for IP_BOUND_IF sockets and makes otherwise valid outbound dials fail with
// ENETUNREACH. These disjoint prefixes cover routable IPv4 outside 0/8.
#[cfg(any(target_os = "macos", test))]
const MACOS_TUN_IPV4_ROUTES: [([u8; 4], [u8; 4]); 8] = [
    ([1, 0, 0, 0], [255, 0, 0, 0]),
    ([2, 0, 0, 0], [254, 0, 0, 0]),
    ([4, 0, 0, 0], [252, 0, 0, 0]),
    ([8, 0, 0, 0], [248, 0, 0, 0]),
    ([16, 0, 0, 0], [240, 0, 0, 0]),
    ([32, 0, 0, 0], [224, 0, 0, 0]),
    ([64, 0, 0, 0], [192, 0, 0, 0]),
    ([128, 0, 0, 0], [128, 0, 0, 0]),
];

#[derive(serde::Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Enable { port: u16, bypass: String },
    PrepareTun,
    ActivateTun,
    Restore,
    Status,
    Shutdown,
}

/// Platform operations are deliberately limited to a loopback port. The backend
/// owns the backup location and must preserve it on every unresolved failure.
pub trait Backend {
    fn recover_previous(&mut self) -> Result<(), String>;
    fn enable(&mut self, port: u16, bypass: &str) -> Result<(), String>;
    fn restore(&mut self, port: u16) -> Result<(), String>;
    /// Transfer one newly created utun to the pre-established handoff channel.
    /// A failure may happen after transfer; the caller must stop its supervisor.
    fn prepare_tun(&mut self) -> Result<String, String> { Err("TUN handoff unavailable".into()) }
    fn activate_tun(&mut self) -> Result<(), String> { Err("TUN routing unavailable".into()) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State { Idle, Active(u16), Recovery(u16) }

/// Bound the untrusted exceptions list before any network configuration is
/// read or changed. Semantics match the adapter's semicolon-separated format.
pub fn validate_bypass(bypass: &str) -> bool {
    if bypass.len() > 2048 || bypass.chars().any(char::is_control) { return false; }
    // JSON escaping can make the wire representation larger than the source.
    // Leave room for the command and port inside the 4096-byte frame limit.
    if !serde_json::to_string(bypass).is_ok_and(|encoded| encoded.len() <= 4000) { return false; }
    let mut count = 0;
    for item in bypass.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        count += 1;
        if count > 128 || item.len() > 255 || (item.starts_with('<') && !item.eq_ignore_ascii_case("<local>")) {
            return false;
        }
    }
    true
}

#[cfg(any(target_os = "macos", test))]
const RECOVERY_LABEL: &str = "dev.prismroute.proxy-recovery";
#[cfg(any(target_os = "macos", test))]
const RECOVERY_PLIST: &str = "/Library/LaunchDaemons/dev.prismroute.proxy-recovery.plist";
#[cfg(any(target_os = "macos", test))]
const RECOVERY_EXECUTABLE: &str = "/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard";

/// `launchctl print` is diagnostic output, not a stable API. Any format we do
/// not recognize fails closed; successful validation is only a point-in-time
/// check and cannot prevent later disabling of the daemon.
#[cfg(any(target_os = "macos", test))]
fn recovery_service_ready(plist_bytes: &[u8], service: &str, disabled: &str) -> bool {
    if plist_bytes.len() > 16384 || service.len() > 131072 || disabled.len() > 1048576 { return false; }
    let Ok(plist::Value::Dictionary(map)) = plist::Value::from_reader(std::io::Cursor::new(plist_bytes)) else { return false };
    if map.len() != 5 || map.get("Label").and_then(plist::Value::as_string) != Some(RECOVERY_LABEL)
        || map.get("RunAtLoad").and_then(plist::Value::as_boolean) != Some(true)
        || map.get("StartInterval").and_then(plist::Value::as_unsigned_integer) != Some(15)
        || map.get("ProcessType").and_then(plist::Value::as_string) != Some("Background") { return false; }
    let Some(args) = map.get("ProgramArguments").and_then(plist::Value::as_array) else { return false };
    if args.len() != 2 || args[0].as_string() != Some(RECOVERY_EXECUTABLE) || args[1].as_string() != Some("--recover-only") { return false; }
    let lines: Vec<_> = service.lines().map(str::trim).collect();
    let unique = |expected: &str| lines.iter().filter(|line| **line == expected).count() == 1;
    if !unique(&format!("system/{RECOVERY_LABEL} = {{")) || !unique(&format!("path = {RECOVERY_PLIST}"))
        || !unique(&format!("program = {RECOVERY_EXECUTABLE}")) || !unique("type = LaunchDaemon")
        || !unique("run interval = 15 seconds") { return false; }
    let Some(i) = lines.iter().position(|line| *line == "arguments = {") else { return false };
    if lines.get(i + 1..i + 4) != Some(&[RECOVERY_EXECUTABLE, "--recover-only", "}"][..]) { return false; }
    let mut disabled_lines = disabled.lines().map(str::trim);
    if !disabled_lines.any(|line| line == "disabled services = {") || !disabled.lines().any(|line| line.trim() == "}") { return false; }
    let needle = format!("\"{RECOVERY_LABEL}\" => ");
    let entries: Vec<_> = disabled.lines().map(str::trim).filter_map(|line| line.strip_prefix(&needle)).collect();
    // Absent means no override. Duplicates or unknown values are not trusted.
    entries.is_empty() || (entries.len() == 1 && entries[0] == "enabled")
}

fn reply(output: &mut impl Write, value: &str) -> std::io::Result<()> {
    writeln!(output, "{{\"status\":\"{value}\"}}")?;
    output.flush()
}

pub(crate) fn valid_tun_name(name: &str) -> bool {
    let Some(unit) = name.strip_prefix("utun") else { return false };
    name.len() < 16 && !unit.is_empty() && unit.bytes().all(|b| b.is_ascii_digit())
        && unit.parse::<i16>().is_ok_and(|n| n >= 0 && n.to_string() == unit)
}

/// Process a single trusted channel. An EOF, malformed oversized request or
/// broken output causes recovery before the guard exits. Real privileged use
/// additionally requires a protected executable, single-instance lock, client
/// authentication, and a service manager to recover after guard/OS failure.
pub fn serve(input: &mut impl BufRead, output: &mut impl Write, backend: &mut impl Backend) -> Result<(), String> {
    backend.recover_previous()?;
    let mut state = State::Idle;
    let mut tun_attempted = false;
    let mut tun_ready = false;
    let mut tun_activation_attempted = false;
    let session_result = (|| -> Result<(), String> {
        loop {
            let mut line = Vec::new();
            let read = (&mut *input).take(4097).read_until(b'\n', &mut line).map_err(|e| e.to_string())?;
            if read == 0 { return Ok(()); }
            if line.len() > 4096 || !line.ends_with(b"\n") { return Err("invalid request framing".into()); }
            let request: Request = match serde_json::from_slice(&line) {
                Ok(value) => value,
                Err(_) => { reply(output, "invalid_request").map_err(|e| e.to_string())?; continue; }
            };
            let status = match request {
                Request::Status => match state { State::Idle => "idle", State::Active(_) => "active", State::Recovery(_) => "recovery_required" },
                Request::PrepareTun if state == State::Idle && !tun_attempted => {
                    // A transferred fd may be live even when the acknowledgement
                    // fails; never retry on a consumed one-shot channel.
                    tun_attempted = true;
                    match backend.prepare_tun() {
                        Ok(name) if valid_tun_name(&name) => {
                            tun_ready = true;
                            serde_json::to_writer(&mut *output, &serde_json::json!({"status":"tun_ready", "device":name})).map_err(|e| e.to_string())?;
                            output.write_all(b"\n").and_then(|_| output.flush()).map_err(|e| e.to_string())?;
                            continue;
                        }
                        _ => "tun_uncertain",
                    }
                }
                Request::PrepareTun => "busy",
                Request::ActivateTun if state == State::Idle && tun_ready && !tun_activation_attempted => {
                    // A failed acknowledgement or partially added route is
                    // uncertain. The caller must stop the owning core.
                    tun_activation_attempted = true;
                    match backend.activate_tun() {
                        Ok(()) => "tun_active",
                        Err(error) if error == "ipv6" => "tun_ipv6_unsupported",
                        Err(error) if error == "dns" => "tun_dns_unsupported",
                        Err(error) if error == "dns_gateway" => "tun_dns_gateway",
                        Err(_) => "tun_route_failed",
                    }
                }
                Request::ActivateTun => "busy",
                Request::Enable { port, ref bypass } if port == 0 || !validate_bypass(bypass) => "invalid_request",
                Request::Enable { port, bypass } if state == State::Idle && !tun_attempted => {
                    // Mark dirty before the call: an error may occur after commit.
                    state = State::Recovery(port);
                    match backend.enable(port, &bypass) {
                        Ok(()) => { state = State::Active(port); "active" }
                        Err(_) => match backend.restore(port) {
                            Ok(()) => { state = State::Idle; "enable_failed" }
                            Err(_) => "recovery_required",
                        },
                    }
                }
                Request::Enable { .. } => "busy",
                Request::Restore | Request::Shutdown => {
                    let shutdown = matches!(request, Request::Shutdown);
                    match state {
                        State::Idle => {
                            if shutdown { reply(output, "stopped").map_err(|e| e.to_string())?; return Ok(()); }
                            "idle"
                        }
                        State::Active(port) | State::Recovery(port) => match backend.restore(port) {
                            Ok(()) => {
                                state = State::Idle;
                                if shutdown { reply(output, "stopped").map_err(|e| e.to_string())?; return Ok(()); }
                                "restored"
                            }
                            Err(_) => { state = State::Recovery(port); "recovery_required" }
                        },
                    }
                }
            };
            reply(output, status).map_err(|e| e.to_string())?;
        }
    })();
    if let State::Active(port) | State::Recovery(port) = state {
        backend.restore(port).map_err(|_| "proxy recovery failed; backup retained".to_string())?;
    }
    session_result
}

/// Real SystemConfiguration backend for a separately installed, root-owned
/// guard. It is deliberately not started by the app until the installer,
/// channel authentication and independent restart/boot recovery are ready.
#[cfg(target_os = "macos")]
mod installed {
    use super::{recovery_service_ready, serve, Backend, RECOVERY_LABEL, RECOVERY_PLIST};
    use std::{fs::{self, File, OpenOptions}, io::Read, os::{fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd}, unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt}}, path::{Path, PathBuf}};

    const EXECUTABLE: &str = "/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard";
    const STATE: &str = "/private/var/db/dev.prismroute";

    fn trusted(path: &Path, directory: bool, private: bool) -> Result<(), String> {
        let meta = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if meta.uid() != 0 || (if directory { !meta.is_dir() } else { !meta.is_file() })
            || meta.mode() & if private { 0o077 } else { 0o022 } != 0 {
            return Err(format!("untrusted path: {}", path.display()));
        }
        if !directory && meta.nlink() != 1 { return Err("untrusted helper link count".into()); }
        Ok(())
    }

    struct SystemProxy {
        backup: PathBuf,
        tun_channel: Option<OwnedFd>,
        // Created while this process is still single-threaded, before calls
        // into SystemConfiguration can start framework threads.
        prepared_tun: Option<crate::tun_macos::Utun>,
        // Keep the kernel interface alive until the session ends, even if
        // the core exits between handoff and route activation. This prevents
        // the interface name being reused by an unrelated process.
        active_tun: Option<crate::tun_macos::Utun>,
        route_socket: Option<OwnedFd>,
        tun_device: Option<String>,
    }
    fn require_recovery_service() -> Result<(), String> {
        trusted(Path::new("/Library/LaunchDaemons"), true, false)?;
        trusted(Path::new(RECOVERY_PLIST), false, false)?;
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(RECOVERY_PLIST).map_err(|_| "cannot open recovery service plist")?;
        let meta = file.metadata().map_err(|_| "cannot inspect recovery service plist")?;
        if !meta.is_file() || meta.uid() != 0 || meta.nlink() != 1 || meta.mode() & 0o022 != 0 {
            return Err("untrusted recovery service plist".into());
        }
        let mut bytes = Vec::new();
        file.take(16385).read_to_end(&mut bytes).map_err(|_| "cannot read recovery service plist")?;
        let invoke = |args: &[&str]| -> Result<String, String> {
            let out = std::process::Command::new("/bin/launchctl").args(args).env_clear().output()
                .map_err(|_| "cannot inspect recovery service")?;
            if !out.status.success() { return Err("recovery service is not loaded".into()); }
            String::from_utf8(out.stdout).map_err(|_| "invalid recovery service status".into())
        };
        let service = invoke(&["print", &format!("system/{RECOVERY_LABEL}")])?;
        let disabled = invoke(&["print-disabled", "system"])?;
        if !recovery_service_ready(&bytes, &service, &disabled) { return Err("recovery service is disabled or misconfigured".into()); }
        Ok(())
    }
    impl Backend for SystemProxy {
        fn recover_previous(&mut self) -> Result<(), String> {
            match fs::symlink_metadata(&self.backup) {
                Ok(_) => crate::sysproxy_macos::disable(&self.backup, "127.0.0.1:1").map_err(|e| e.to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        fn enable(&mut self, port: u16, bypass: &str) -> Result<(), String> {
            require_recovery_service()?;
            crate::sysproxy_macos::enable(&format!("127.0.0.1:{port}"), bypass, &self.backup).map_err(|e| e.to_string())
        }
        fn restore(&mut self, port: u16) -> Result<(), String> {
            crate::sysproxy_macos::disable(&self.backup, &format!("127.0.0.1:{port}")).map_err(|e| e.to_string())
        }
        fn prepare_tun(&mut self) -> Result<String, String> {
            let channel = self.tun_channel.take().ok_or("TUN handoff channel unavailable")?;
            let tun = self.prepared_tun.take().ok_or("configured TUN interface unavailable")?;
            // Retain our copy until the supervisor has validated and secured
            // its copy; a failed acknowledgement may still require the caller
            // to terminate its supervisor.
            crate::tun_macos::send_descriptor_and_confirm(channel.as_fd(), tun.descriptor.as_fd())
                .map_err(|e| format!("cannot transfer utun: {e}"))?;
            self.tun_device = Some(tun.name.clone());
            let name = tun.name.clone();
            self.active_tun = Some(tun);
            Ok(name)
        }
        fn activate_tun(&mut self) -> Result<(), String> {
            crate::tun_macos::require_no_ipv6().map_err(|_| "ipv6".to_string())?;
            let dns = crate::tun_macos::system_ipv4_dns().map_err(|_| "dns".to_string())?;
            if crate::tun_macos::dns_uses_active_gateway(&dns).map_err(|_| "dns".to_string())? {
                return Err("dns_gateway".into());
            }
            let name = self.tun_device.as_deref().ok_or("route")?;
            let socket = self.route_socket.as_ref().ok_or("route")?;
            let mut sequence = 1;
            // Host routes are necessary for DNS servers on the local LAN,
            // whose existing connected /24 outranks the catch-all /1 routes.
            for server in dns {
                crate::tun_macos::add_ipv4_route(socket.as_fd(), name, server.octets(), [255; 4], sequence)
                    .map_err(|_| "route".to_string())?;
                sequence += 1;
            }
            for (destination, mask) in super::MACOS_TUN_IPV4_ROUTES {
                crate::tun_macos::add_ipv4_route(socket.as_fd(), name, destination, mask, sequence)
                    .map_err(|_| "route".to_string())?;
                sequence += 1;
            }
            Ok(())
        }
    }

    fn lock(dir: &Path) -> Result<File, String> {
        let file = OpenOptions::new().read(true).write(true).create(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dir.join("guard.lock"))
            .map_err(|e| format!("cannot open guard lock: {e}"))?;
        let m = file.metadata().map_err(|e| e.to_string())?;
        if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.permissions().mode() & 0o077 != 0 {
            return Err("untrusted guard lock".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another proxy guard is active".into());
        }
        Ok(file)
    }

    pub fn run() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 { return Err("proxy guard requires administrator authorization".into()); }
        let mut args = std::env::args_os().skip(1);
        let (recover_only, tun_channel) = match args.next() {
            None => (false, false),
            Some(arg) if arg == "--recover-only" => (true, false),
            Some(arg) if arg == "--tun-channel" => (false, true),
            Some(_) => return Err("invalid guard mode".into()),
        };
        if args.next().is_some() { return Err("invalid guard arguments".into()); }
        for path in ["/", "/Library", "/Library/PrivilegedHelperTools", "/private", "/private/var", "/private/var/db"] {
            trusted(Path::new(path), true, false)?;
        }
        trusted(Path::new(EXECUTABLE), false, false)?;
        let actual = std::env::current_exe().map_err(|e| e.to_string())?;
        if actual != Path::new(EXECUTABLE) { return Err("guard is not running from its protected installation path".into()); }
        let state = Path::new(STATE);
        match fs::DirBuilder::new().mode(0o700).create(state) {
            Ok(()) => File::open("/private/var/db").and_then(|f| f.sync_all()).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(format!("cannot create state directory: {e}")),
        }
        trusted(state, true, true)?;
        let _lock = lock(state)?;
        let mut backend = SystemProxy { backup: state.join("proxy-backup.json"), tun_channel: None, prepared_tun: None, active_tun: None, route_socket: None, tun_device: None };
        if recover_only { return backend.recover_previous(); }
        if tun_channel {
            // The bridge must authenticate both peers before transferring this
            // channel. No buffered JSON reads are permitted before recvmsg.
            let input = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
            crate::tun_macos::validate_handoff_socket(input).map_err(|e| format!("invalid bridge channel: {e}"))?;
            let mut poll = libc::pollfd { fd: input.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut poll, 1, 5000) } <= 0 || poll.revents & libc::POLLIN == 0 {
                return Err("TUN handoff channel was not provided".into());
            }
            let received = crate::tun_macos::receive_descriptor_single_threaded(input).map_err(|e| format!("invalid TUN handoff: {e}"))?;
            crate::tun_macos::validate_handoff_socket(received.as_fd()).map_err(|e| format!("invalid TUN handoff socket: {e}"))?;
            backend.tun_channel = Some(received);
            // Create and configure the interface before SystemConfiguration can
            // introduce threads. The interface is owned exclusively by this
            // process until the authenticated handoff succeeds, and dropping
            // it on any subsequent failure closes the temporary interface.
            let tun = crate::tun_macos::create_utun().map_err(|e| format!("cannot create utun: {e}"))?;
            backend.prepared_tun = Some(crate::tun_macos_interface::configure_created_utun(
                tun, crate::tun_macos_interface::TunInterfacePlan::experimental_ipv4(),
            ).map_err(|e| format!("cannot configure utun: {e}"))?);
            backend.route_socket = Some(crate::tun_macos::open_route_socket().map_err(|e| format!("cannot open routing socket: {e}"))?);
            // Keep recvmsg before SystemConfiguration: framework calls may
            // start threads, while Darwin cannot atomically set CLOEXEC on
            // received descriptors. Do not acknowledge until recovery succeeds.
            backend.recover_previous()?;
            crate::tun_macos::confirm_descriptor_received(input).map_err(|e| format!("cannot acknowledge TUN channel: {e}"))?;
        }
        let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
        serve(&mut stdin.lock(), &mut stdout.lock(), &mut backend)
    }
}

#[cfg(target_os = "macos")]
pub fn run_installed() -> Result<(), String> { installed::run() }

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn macos_capture_routes_leave_default_key_free_and_cover_routable_ipv4() {
        for first_octet in 0_u8..=255 {
            let matches = MACOS_TUN_IPV4_ROUTES.iter().filter(|(destination, mask)| {
                first_octet & mask[0] == destination[0]
            }).count();
            assert_eq!(matches, usize::from(first_octet != 0), "unexpected route coverage for {first_octet}/8");
        }
        for (destination, mask) in MACOS_TUN_IPV4_ROUTES {
            assert_ne!(destination, [0; 4], "do not shadow Darwin's default route key");
            assert_eq!(destination[0] & !mask[0], 0, "network address must be canonical");
        }
    }

    #[derive(Default)]
    struct Fake { calls: Vec<String>, last_bypass: Option<String>, fail_enable: bool, fail_restore: usize, fail_startup: bool, tun_name: Option<String> }
    impl Backend for Fake {
        fn recover_previous(&mut self) -> Result<(), String> {
            self.calls.push("startup".into());
            if self.fail_startup { Err("startup".into()) } else { Ok(()) }
        }
        fn enable(&mut self, port: u16, bypass: &str) -> Result<(), String> {
            self.calls.push(format!("enable:{port}"));
            self.last_bypass = Some(bypass.to_owned());
            if self.fail_enable { Err("enable".into()) } else { Ok(()) }
        }
        fn restore(&mut self, port: u16) -> Result<(), String> {
            self.calls.push(format!("restore:{port}"));
            if self.fail_restore > 0 { self.fail_restore -= 1; Err("restore".into()) } else { Ok(()) }
        }
        fn prepare_tun(&mut self) -> Result<String, String> {
            self.calls.push("prepare_tun".into());
            self.tun_name.clone().ok_or_else(|| "TUN failure".into())
        }
        fn activate_tun(&mut self) -> Result<(), String> {
            self.calls.push("activate_tun".into());
            Ok(())
        }
    }
    fn run(input: &str, backend: &mut Fake) -> (Result<(), String>, String) {
        let mut output = Vec::new();
        let result = serve(&mut Cursor::new(input), &mut output, backend);
        (result, String::from_utf8(output).unwrap())
    }
    #[test]
    fn eof_restores_active_proxy() {
        let mut backend = Fake::default();
        let (result, output) = run("{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}\n", &mut backend);
        assert!(result.is_ok()); assert!(output.contains("active"));
        assert_eq!(backend.calls, ["startup", "enable:7890", "restore:7890"]);
    }
    #[test]
    fn tun_handoff_is_one_shot_and_excludes_proxy_enable() {
        let mut backend = Fake { tun_name: Some("utun42".into()), ..Fake::default() };
        let (result, output) = run("{\"command\":\"prepare_tun\"}\n{\"command\":\"prepare_tun\"}\n{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}\n{\"command\":\"shutdown\"}\n", &mut backend);
        assert!(result.is_ok());
        assert!(output.contains("\"device\":\"utun42\""));
        assert_eq!(output.matches("busy").count(), 2);
        assert_eq!(backend.calls, ["startup", "prepare_tun"]);
    }
    #[test]
    fn routes_can_only_be_activated_once_after_successful_handoff() {
        let mut backend = Fake { tun_name: Some("utun42".into()), ..Fake::default() };
        let (result, output) = run("{\"command\":\"activate_tun\"}\n{\"command\":\"prepare_tun\"}\n{\"command\":\"activate_tun\"}\n{\"command\":\"activate_tun\"}\n{\"command\":\"shutdown\"}\n", &mut backend);
        assert!(result.is_ok());
        assert_eq!(backend.calls, ["startup", "prepare_tun", "activate_tun"]);
        assert!(output.contains("tun_active"));
        assert_eq!(output.matches("busy").count(), 2);
    }
    #[test]
    fn failed_or_invalid_tun_handoff_cannot_be_retried_on_the_same_channel() {
        for name in [None, Some("utun01".to_string()), Some("en0".to_string())] {
            let mut backend = Fake { tun_name: name, ..Fake::default() };
            let (_, output) = run("{\"command\":\"prepare_tun\"}\n{\"command\":\"prepare_tun\"}\n", &mut backend);
            assert!(output.contains("tun_uncertain")); assert!(output.contains("busy"));
            assert_eq!(backend.calls, ["startup", "prepare_tun"]);
        }
    }
    #[test]
    fn failure_after_enable_always_attempts_recovery_and_allows_retry() {
        let mut backend = Fake { fail_enable: true, fail_restore: 1, ..Fake::default() };
        let (result, output) = run("{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}\n{\"command\":\"enable\",\"port\":7891,\"bypass\":\"\"}\n{\"command\":\"restore\"}\n", &mut backend);
        assert!(result.is_ok()); assert!(output.contains("recovery_required")); assert!(output.contains("busy"));
        assert_eq!(backend.calls, ["startup", "enable:7890", "restore:7890", "restore:7890"]);
    }
    #[test]
    fn unresolved_recovery_is_an_error_even_after_the_client_disconnects() {
        let mut backend = Fake { fail_enable: true, fail_restore: 2, ..Fake::default() };
        let (result, output) = run("{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}\n", &mut backend);
        assert!(result.is_err());
        assert!(output.contains("recovery_required"));
        assert_eq!(backend.calls, ["startup", "enable:7890", "restore:7890", "restore:7890"]);
    }
    #[test]
    fn rejects_extra_fields_and_refuses_enable_if_startup_recovery_failed() {
        let mut backend = Fake::default();
        let (_, output) = run("{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\",\"path\":\"/tmp/x\"}\n", &mut backend);
        assert!(output.contains("invalid_request")); assert_eq!(backend.calls, ["startup"]);
        let mut backend = Fake { fail_startup: true, ..Fake::default() };
        assert!(run("{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}\n", &mut backend).0.is_err());
        assert_eq!(backend.calls, ["startup"]);
    }
    #[test]
    fn forwards_user_exceptions_and_rejects_invalid_lists_before_mutation() {
        let bypass = crate::settings::Settings::default().sysproxy_bypass;
        let input = format!("{}\n", serde_json::json!({"command":"enable", "port":7890, "bypass":bypass}));
        let mut backend = Fake::default();
        assert!(run(&input, &mut backend).0.is_ok());
        assert_eq!(backend.last_bypass.as_deref(), Some(bypass.as_str()));

        for invalid in ["bad\nentry".to_string(), "<unexpected>".to_string(), "x".repeat(2049), "x".repeat(256), vec!["a"; 129].join(";"), "\\".repeat(2001)] {
            assert!(!validate_bypass(&invalid), "{invalid:?}");
            let mut backend = Fake::default();
            let input = format!("{}\n", serde_json::json!({"command":"enable", "port":7890, "bypass":invalid}));
            let _ = run(&input, &mut backend);
            assert_eq!(backend.calls, ["startup"]);
        }
        assert!(validate_bypass(""));
        assert!(validate_bypass("localhost;10.0.0.0/8;<LOCAL>"));
    }
    #[test]
    fn recovery_service_must_be_loaded_unmodified_scheduled_and_enabled() {
        let plist = include_bytes!("../../../app/src-tauri/macos/dev.prismroute.proxy-recovery.plist");
        let service = format!("system/{RECOVERY_LABEL} = {{\n path = {RECOVERY_PLIST}\n type = LaunchDaemon\n program = {RECOVERY_EXECUTABLE}\n arguments = {{\n {RECOVERY_EXECUTABLE}\n --recover-only\n }}\n run interval = 15 seconds\n}}");
        let enabled = "disabled services = {\n}";
        assert!(recovery_service_ready(plist, &service, enabled));
        assert!(recovery_service_ready(plist, &service, &format!("disabled services = {{\n\"{RECOVERY_LABEL}\" => enabled\n}}")));
        assert!(!recovery_service_ready(plist, &service, &format!("disabled services = {{\n\"{RECOVERY_LABEL}\" => disabled\n}}")));
        assert!(!recovery_service_ready(plist, &service, "unrecognized output"));
        assert!(!recovery_service_ready(plist, &service.replace("run interval = 15 seconds", "run interval = 300 seconds"), enabled));
        assert!(!recovery_service_ready(plist, &service.replace("--recover-only", "--other"), enabled));
        assert!(!recovery_service_ready(plist, &service.replace(RECOVERY_PLIST, "/tmp/other.plist"), enabled));
        assert!(!recovery_service_ready(b"not a plist", &service, enabled));
    }
    #[test]
    fn malformed_frame_and_output_failure_restore_before_exit() {
        let mut backend = Fake::default();
        let input = format!("{{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}}\n{}\n", "x".repeat(4097));
        assert!(run(&input, &mut backend).0.is_err());
        assert_eq!(backend.calls, ["startup", "enable:7890", "restore:7890"]);
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::ErrorKind::BrokenPipe.into()) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let mut backend = Fake::default();
        let mut input = Cursor::new("{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}\n");
        assert!(serve(&mut input, &mut Broken, &mut backend).is_err());
        assert_eq!(backend.calls, ["startup", "enable:7890", "restore:7890"]);
    }

    #[test]
    #[ignore = "fixture launched by eof_of_a_real_client_pipe_triggers_recovery"]
    fn subprocess_guard_fixture() {
        struct FileBackend(std::path::PathBuf);
        impl Backend for FileBackend {
            fn recover_previous(&mut self) -> Result<(), String> { Ok(()) }
            fn enable(&mut self, _: u16, _: &str) -> Result<(), String> { std::fs::write(&self.0, "active").map_err(|e| e.to_string()) }
            fn restore(&mut self, _: u16) -> Result<(), String> { std::fs::write(&self.0, "restored").map_err(|e| e.to_string()) }
        }
        let path = std::env::var_os("PRISM_GUARD_TEST_STATE").expect("test fixture only");
        let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
        serve(&mut stdin.lock(), &mut stdout.lock(), &mut FileBackend(path.into())).unwrap();
    }

    #[test]
    fn eof_of_a_real_client_pipe_triggers_recovery() {
        use std::process::{Command, Stdio};
        let dir = std::env::temp_dir().join(format!("prism-guard-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("state");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "macos_proxy_guard::tests::subprocess_guard_fixture", "--ignored", "--nocapture"])
            .env("PRISM_GUARD_TEST_STATE", &path)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(b"{\"command\":\"enable\",\"port\":7890,\"bypass\":\"\"}\n").unwrap();
        drop(input); // The OS closes the client channel, as it does after a crash.
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "restored");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
