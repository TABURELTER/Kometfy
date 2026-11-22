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

/// Accept either an exact match with this build's plist or an earlier Kometfy/PrismRoute plist for the same
/// label and helper executable, so future plist changes upgrade cleanly without touching third-party daemons.
fn owned_plist(actual: &[u8], expected: &[u8], label: &str, program: &str) -> bool {
    if same_plist(actual, expected) { return true; }
    let Ok(plist::Value::Dictionary(map)) = plist::Value::from_reader(std::io::Cursor::new(actual)) else { return false };
    let same_label = map.get("Label").and_then(plist::Value::as_string) == Some(label);
    let same_program = map
        .get("ProgramArguments")
        .and_then(plist::Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(plist::Value::as_string)
        == Some(program);
    same_label && same_program
}

fn verify_installed_signatures() -> Result<(), String> {
    for path in ["/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard", "/Library/PrivilegedHelperTools/dev.prismroute.proxy-bridge"] {
        let status = Command::new("/usr/bin/codesign").args(["--verify", "--strict", path]).env_clear()
            .status().map_err(|e| format!("cannot verify installed helper: {e}"))?;
        if !status.success() { return Err("installed helper signature is invalid".into()); }
    }
    Ok(())
}

fn read_optional_slot(dir: &Directory, slot: Slot) -> Result<Option<Vec<u8>>, String> {
    match dir.read_slot(slot) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("existing helper file is untrusted: {e}")),
    }
}

fn rollback_update(
    helpers: &Directory, daemons: &Directory, state: &Directory,
    old_guard: Option<&[u8]>, old_bridge: Option<&[u8]>,
    old_recovery_plist: Option<&[u8]>, old_bridge_plist: Option<&[u8]>,
    old_policy: Option<&[u8]>, new_policy: &[u8],
) -> io::Result<()> {
    for (dir, slot, old, new) in [
        (helpers, Slot::Guard, old_guard, GUARD),
        (helpers, Slot::Bridge, old_bridge, BRIDGE),
        (daemons, Slot::RecoveryPlist, old_recovery_plist, RECOVERY_PLIST),
        (daemons, Slot::BridgePlist, old_bridge_plist, BRIDGE_PLIST),
        (state, Slot::ClientPolicy, old_policy, new_policy),
    ] {
        let Some(old) = old else { continue };
        let current = dir.read_slot(slot)?;
        if current == old { continue; }
        if current != new { return Err(io::Error::other("updated file changed externally; retained for recovery")); }
        dir.replace_slot(slot, new, old)?;
    }
    Ok(())
}

fn upgrade_or_repair(
    helpers: &Directory, daemons: &Directory, state: &Directory, lock: &GuardLock,
    old_guard: Option<Vec<u8>>, old_bridge: Option<Vec<u8>>,
    old_recovery_plist: Option<Vec<u8>>, old_bridge_plist: Option<Vec<u8>>,
    old_policy: Option<Vec<u8>>, identity: &str,
) -> Result<(), String> {
    if let Some(ref plist) = old_recovery_plist {
        if !owned_plist(plist, RECOVERY_PLIST, "dev.prismroute.proxy-recovery", "/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard") {
            return Err("existing recovery service configuration belongs to another program; update refused".into());
        }
    }
    if let Some(ref plist) = old_bridge_plist {
        if !owned_plist(plist, BRIDGE_PLIST, "dev.prismroute.proxy-bridge", "/Library/PrivilegedHelperTools/dev.prismroute.proxy-bridge") {
            return Err("existing bridge service configuration belongs to another program; update refused".into());
        }
    }
    let mut controller = Controller::new(LaunchctlRunner, lock);
    // Allows absent/unloaded services (e.g. after a crashed update or downgrade) while still
    // refusing any foreign loaded service under our labels.
    controller.verify_existing().map_err(str::to_owned)?;
    let mut backup_entries: Vec<(Slot, &[u8])> = Vec::new();
    if let Some(ref b) = old_guard { backup_entries.push((Slot::Guard, b)); }
    if let Some(ref b) = old_bridge { backup_entries.push((Slot::Bridge, b)); }
    if let Some(ref b) = old_policy { backup_entries.push((Slot::ClientPolicy, b)); }
    if let Some(ref b) = old_recovery_plist { backup_entries.push((Slot::RecoveryPlist, b)); }
    if let Some(ref b) = old_bridge_plist { backup_entries.push((Slot::BridgePlist, b)); }
    let backup = state.retain_backup(&backup_entries)
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
    controller.ensure_enabled().map_err(str::to_owned)?;
    let mut tx = Transaction::new(lock);
    let update = (|| {
        for (dir, slot, old, new) in [
            (helpers, Slot::Guard, old_guard.as_deref(), GUARD),
            (helpers, Slot::Bridge, old_bridge.as_deref(), BRIDGE),
            (daemons, Slot::RecoveryPlist, old_recovery_plist.as_deref(), RECOVERY_PLIST),
            (daemons, Slot::BridgePlist, old_bridge_plist.as_deref(), BRIDGE_PLIST),
            (state, Slot::ClientPolicy, old_policy.as_deref(), identity.as_bytes()),
        ] {
            match old {
                Some(prev) if prev == new => {}
                Some(prev) => dir.replace_slot(slot, prev, new)?,
                None => tx.publish(dir, slot, new)?,
            }
        }
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = update {
        let _ = tx.rollback();
        let restored = rollback_update(
            helpers, daemons, state,
            old_guard.as_deref(), old_bridge.as_deref(),
            old_recovery_plist.as_deref(), old_bridge_plist.as_deref(),
            old_policy.as_deref(), identity.as_bytes(),
        )
            .map_err(|e| format!("cannot restore previous files: {e}"))
            .and_then(|_| controller.start_existing().map_err(str::to_owned));
        return match restored {
            Ok(()) => Err(format!("helper update failed and previous version was restored: {error}")),
            Err(restore) => Err(format!("helper update failed: {error}; {restore}; previous files retained in {backup}")),
        };
    }
    // Verify the NEWLY installed helpers before registering them with launchd (never block
    // replacing a broken older helper from an earlier build).
    if let Err(error) = verify_installed_signatures() {
        let _ = tx.rollback();
        let _ = rollback_update(
            helpers, daemons, state,
            old_guard.as_deref(), old_bridge.as_deref(),
            old_recovery_plist.as_deref(), old_bridge_plist.as_deref(),
            old_policy.as_deref(), identity.as_bytes(),
        );
        return Err(error);
    }
    if let Err(error) = controller.register() {
        if !error.safe_to_remove_files { return Err(format!("helper restart outcome uncertain: {}; previous files retained in {backup}", error.reason)); }
        let _ = tx.rollback();
        let restored = rollback_update(
            helpers, daemons, state,
            old_guard.as_deref(), old_bridge.as_deref(),
            old_recovery_plist.as_deref(), old_bridge_plist.as_deref(),
            old_policy.as_deref(), identity.as_bytes(),
        )
            .map_err(|e| format!("cannot restore previous files: {e}"))
            .and_then(|_| controller.start_existing().map_err(str::to_owned));
        return match restored {
            Ok(()) => Err(format!("helper restart failed and previous version was restored: {}", error.reason)),
            Err(restore) => Err(format!("helper restart failed: {}; {restore}; previous files retained in {backup}", error.reason)),
        };
    }
    let _ = tx.commit();
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
    let guard = read_optional_slot(&helpers, Slot::Guard)?;
    let bridge = read_optional_slot(&helpers, Slot::Bridge)?;
    let recovery_plist = read_optional_slot(&daemons, Slot::RecoveryPlist)?;
    let bridge_plist = read_optional_slot(&daemons, Slot::BridgePlist)?;
    let policy = read_optional_slot(&state, Slot::ClientPolicy)?;
    if guard.is_some() || bridge.is_some() || recovery_plist.is_some() || bridge_plist.is_some() || policy.is_some() {
        upgrade_or_repair(&helpers, &daemons, &state, &lock, guard, bridge, recovery_plist, bridge_plist, policy, &identity)?;
        register_session_right();
        return Ok(());
    }
    let mut controller = Controller::new(LaunchctlRunner, &lock);
    controller.ensure_enabled().map_err(str::to_owned)?;
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
