//! One-time privileged installer for the bundled proxy guard and bridge.
//! The two executables are embedded at build time; no privileged executable,
//! target path or code-signing policy is accepted from the caller.
use crate::{macos_installer_fs::{Directory, GuardLock, Slot, Transaction},
    macos_installer_runner::LaunchctlRunner, macos_installer_services::Controller};
use std::{io, process::Command};

const GUARD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/installer_guard"));
const BRIDGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/installer_bridge"));
const RECOVERY_PLIST: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../app/src-tauri/macos/dev.prismroute.proxy-recovery.plist"));
const BRIDGE_PLIST: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../app/src-tauri/macos/dev.prismroute.proxy-bridge.plist"));

/// The right the app asks for when it opens a helper session. It follows the system rule `is-admin`: an
/// administrator, who typed the password once for this installation, gets it without another prompt on every
/// start; anyone else is still asked for an administrator's password. Only root can change it.
const SESSION_RIGHT: &str = "dev.prismroute.proxy-bridge.session";

/// Not fatal: without the right every start asks for the administrator password, as before.
fn register_session_right() {
    let mut process = Command::new("/usr/bin/security");
    process.args(["authorizationdb", "write", SESSION_RIGHT, "is-admin"]).env_clear();
    let _ = crate::macos_installer_runner::run_process(&mut process, std::time::Duration::from_secs(10), 4096);
}

fn same_plist(actual: &[u8], expected: &[u8]) -> bool {
    let parse = |bytes: &[u8]| plist::Value::from_reader(std::io::Cursor::new(bytes));
    matches!((parse(actual), parse(expected)), (Ok(a), Ok(b)) if a == b)
}

fn verify_installed_signatures() -> Result<(), String> {
    for path in ["/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard", "/Library/PrivilegedHelperTools/dev.prismroute.proxy-bridge"] {
        let status = Command::new("/usr/bin/codesign").args(["--verify", "--strict", path]).env_clear()
            .status().map_err(|e| format!("cannot verify installed helper: {e}"))?;
        if !status.success() { return Err("existing helper signature is invalid".into()); }
    }
    Ok(())
}

fn rollback_update(helpers: &Directory, state: &Directory, old_guard: &[u8], old_bridge: &[u8], old_policy: &[u8], new_policy: &[u8]) -> io::Result<()> {
    for (dir, slot, old, new) in [(helpers, Slot::Guard, old_guard, GUARD), (helpers, Slot::Bridge, old_bridge, BRIDGE), (state, Slot::ClientPolicy, old_policy, new_policy)] {
        let current = dir.read_slot(slot)?;
        if current == old { continue; }
        if current != new { return Err(io::Error::other("updated file changed externally; retained for recovery")); }
        dir.replace_slot(slot, new, old)?;
    }
    Ok(())
}

fn upgrade(helpers: &Directory, daemons: &Directory, state: &Directory, lock: &GuardLock,
           old_guard: Vec<u8>, old_bridge: Vec<u8>, old_policy: Vec<u8>, identity: &str) -> Result<(), String> {
    if !valid_policy(&old_policy) { return Err("existing client policy is invalid".into()); }
    let recovery_plist = daemons.read_slot(Slot::RecoveryPlist).map_err(|e| format!("cannot inspect recovery service: {e}"))?;
    let bridge_plist = daemons.read_slot(Slot::BridgePlist).map_err(|e| format!("cannot inspect bridge service: {e}"))?;
    if !same_plist(&recovery_plist, RECOVERY_PLIST) || !same_plist(&bridge_plist, BRIDGE_PLIST) {
        return Err("existing service configuration is different; update refused".into());
    }
    verify_installed_signatures()?;
    let mut controller = Controller::new(LaunchctlRunner, lock);
    controller.verify_existing().map_err(str::to_owned)?;
    let backup = state.retain_backup(&[(Slot::Guard, &old_guard), (Slot::Bridge, &old_bridge),
        (Slot::ClientPolicy, &old_policy), (Slot::RecoveryPlist, &recovery_plist), (Slot::BridgePlist, &bridge_plist)])
        .map_err(|e| format!("cannot preserve previous helper version: {e}"))?;
    if let Err(error) = controller.stop_existing() {
        // Do not replace files while a stop is uncertain. Best-effort restart
        // restores any service already stopped, while preserving the backup.
        let restart = controller.start_existing();
        return match restart {
            Ok(()) => Err(format!("could not stop existing services: {error}; previous services restarted; backup: {backup}")),
            Err(restart) => Err(format!("could not stop existing services: {error}; service recovery failed: {restart}; previous files retained in {backup}")),
        };
    }
    let update = (|| {
        helpers.replace_slot(Slot::Guard, &old_guard, GUARD)?;
        helpers.replace_slot(Slot::Bridge, &old_bridge, BRIDGE)?;
        state.replace_slot(Slot::ClientPolicy, &old_policy, identity.as_bytes())?;
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = update {
        let restored = rollback_update(helpers, state, &old_guard, &old_bridge, &old_policy, identity.as_bytes())
            .map_err(|e| format!("cannot restore previous files: {e}"))
            .and_then(|_| controller.start_existing().map_err(str::to_owned));
        return match restored { Ok(()) => Err(format!("helper update failed and previous version was restored: {error}")),
            Err(restore) => Err(format!("helper update failed: {error}; {restore}; previous files retained in {backup}")) };
    }
    if let Err(error) = controller.register() {
        if !error.safe_to_remove_files { return Err(format!("helper restart outcome uncertain: {}; previous files retained in {backup}", error.reason)); }
        let restored = rollback_update(helpers, state, &old_guard, &old_bridge, &old_policy, identity.as_bytes())
            .map_err(|e| format!("cannot restore previous files: {e}"))
            .and_then(|_| controller.start_existing().map_err(str::to_owned));
        return match restored { Ok(()) => Err(format!("helper restart failed and previous version was restored: {}", error.reason)),
            Err(restore) => Err(format!("helper restart failed: {}; {restore}; previous files retained in {backup}", error.reason)) };
    }
    Ok(())
}

/// Ask Security.framework for the identity of the live process, rather than
/// trusting an executable path or a caller-provided hash. The requesting app
/// stays alive while Authorization Services waits for this installer to exit.
fn client_cdhash(pid: i32) -> Result<String, String> {
    unsafe extern "C" { fn prism_macos_live_cdhash(pid: i32, output: *mut libc::c_char) -> libc::c_int; }
    let mut hash = [0i8; 41];
    if unsafe { prism_macos_live_cdhash(pid, hash.as_mut_ptr()) } != 0 { return Err("cannot authenticate the requesting application".into()); }
    let hash = unsafe { std::ffi::CStr::from_ptr(hash.as_ptr()) }.to_str().map_err(|_| "invalid application identity")?;
    if hash.len() != 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid application identity".into()); }
    Ok(hash.to_ascii_lowercase())
}

/// The code requirement the bridge holds an app to when the policy names a certificate. The bridge
/// (main.swift) spells out the same text.
fn certificate_requirement(sha1: &str) -> String {
    format!("identifier \"dev.prismroute.console\" and certificate leaf = H\"{sha1}\"")
}

/// A client policy: a build's code hash (40 hex digits), or `cert:` and the SHA-1 of the certificate the
/// app is signed with.
fn valid_policy(policy: &[u8]) -> bool {
    let hex = policy.strip_prefix(b"cert:").unwrap_or(policy);
    hex.len() == 40 && hex.iter().all(u8::is_ascii_hexdigit)
}

/// Whom the bridge will trust. A build signed with our own certificate (`PRISM_CLIENT_CERT_SHA1`, see
/// scripts/macos/signing-identity.sh) records that certificate: every later build signed with it is
/// trusted as well, so an update asks for no administrator password. An ad-hoc build records its code hash.
fn client_identity(pid: i32) -> Result<String, String> {
    let Some(cert) = option_env!("PRISM_CLIENT_CERT_SHA1") else { return client_cdhash(pid) };
    if cert.len() != 40 || !cert.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid signing certificate pin".into()); }
    let cert = cert.to_ascii_lowercase();
    let requirement = std::ffi::CString::new(certificate_requirement(&cert)).map_err(|_| "invalid signing certificate pin")?;
    unsafe extern "C" { fn prism_macos_live_satisfies(pid: i32, requirement: *const libc::c_char) -> libc::c_int; }
    if unsafe { prism_macos_live_satisfies(pid, requirement.as_ptr()) } != 0 {
        return Err("the requesting application is not signed with this build's certificate".into());
    }
    let policy = format!("cert:{cert}");
    debug_assert!(valid_policy(policy.as_bytes()));
    Ok(policy)
}

pub fn run_installer() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 { return Err("administrator authorization required".into()); }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--client-pid" { return Err("unexpected installer arguments".into()); }
    let pid: i32 = args[2].parse().map_err(|_| "invalid client process")?;
    if pid <= 0 { return Err("invalid client process".into()); }
    // An ordinary cargo test may build an installer without a payload. Never
    // install the placeholder or accept a payload supplied at runtime.
    if GUARD.len() < 1024 || BRIDGE.len() < 1024 { return Err("installer payload was not embedded at build time".into()); }
    let identity = client_identity(pid)?;
    let (helpers, daemons, state) = Directory::provision_system_directories().map_err(|e| format!("cannot provision helper directories: {e}"))?;
    let lock = GuardLock::acquire(&state).map_err(|e| format!("cannot acquire helper lock: {e}"))?;
    let guard = helpers.read_slot(Slot::Guard);
    let bridge = helpers.read_slot(Slot::Bridge);
    let policy = state.read_slot(Slot::ClientPolicy);
    match (guard, bridge, policy) {
        (Ok(guard), Ok(bridge), Ok(policy)) => {
            upgrade(&helpers, &daemons, &state, &lock, guard, bridge, policy, &identity)?;
            register_session_right();
            return Ok(());
        }
        (Err(a), Err(b), Err(c)) if [a.kind(), b.kind(), c.kind()].iter().all(|kind| *kind == io::ErrorKind::NotFound) => {},
        _ => return Err("existing helper installation is incomplete or untrusted; update refused".into()),
    }
    let mut controller = Controller::new(LaunchctlRunner, &lock);
    controller.preflight().map_err(str::to_owned)?;
    let mut tx = Transaction::new(&lock);
    let published = (|| {
        tx.publish(&helpers, Slot::Guard, GUARD)?;
        tx.publish(&helpers, Slot::Bridge, BRIDGE)?;
        tx.publish(&daemons, Slot::RecoveryPlist, RECOVERY_PLIST)?;
        tx.publish(&daemons, Slot::BridgePlist, BRIDGE_PLIST)?;
        tx.publish(&state, Slot::ClientPolicy, identity.as_bytes())?;
        Ok::<_, std::io::Error>(())
    })();
    if let Err(error) = published {
        if !controller.files_safe_to_remove() { return Err(format!("installation failed; files retained for recovery: {error}")); }
        return match tx.rollback() { Ok(()) => Err(format!("installation failed: {error}")),
            Err(cleanup) => Err(format!("installation failed: {error}; cleanup incomplete: {cleanup}")) };
    }
    if let Err(error) = controller.register() {
        if !error.safe_to_remove_files { return Err(format!("service installation failed; files retained for recovery: {}", error.reason)); }
        return match tx.rollback() { Ok(()) => Err(format!("service installation failed: {}", error.reason)),
            Err(cleanup) => Err(format!("service installation failed: {}; cleanup incomplete: {cleanup}", error.reason)) };
    }
    tx.commit().map_err(|e| format!("cannot complete installation: {e}"))?;
    register_session_right();
    Ok(())
}
