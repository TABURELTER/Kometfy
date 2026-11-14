//! Experimental macOS proxy adapter. Not wired into the application until tested on a Mac.
use std::{fs::{self, OpenOptions}, io::{Read, Write}, os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}}, path::Path};
use serde::{Deserialize, Serialize};
use crate::{error::{Error, Result}, sysproxy_macos_prefs::Transaction, sysproxy_macos_read, sysproxy_macos_transform::{self as transform, Restoration}};

const MAX_BACKUP: u64 = 24 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Entry { id: String, before: Vec<u8>, applied: Vec<u8> }
#[derive(Serialize, Deserialize)]
struct Backup { version: u8, server: String, bypass: String, services: Vec<Entry> }

fn message(e: &'static str) -> Error { Error::msg(e) }
/// Compare membership and protocol availability independently of service ordering.
/// Individual proxy dictionaries are compared by SCPreferences under the same lock.
fn same_services(a: &[sysproxy_macos_read::ServiceSnapshot], b: &[sysproxy_macos_read::ServiceSnapshot]) -> bool {
    fn signature(services: &[sysproxy_macos_read::ServiceSnapshot]) -> Option<Vec<(String, bool, bool)>> {
        let mut result: Vec<_> = services.iter().map(|s| (
            s.service_id.to_ascii_lowercase(), s.proxy_protocol_exists, s.configuration.is_some()
        )).collect();
        result.sort_unstable();
        if result.windows(2).any(|w| w[0].0 == w[1].0) { return None; }
        Some(result)
    }
    match (signature(a), signature(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}
fn service_path(id: &str) -> Result<String> {
    // Apple assigns UUIDs; never treat backup contents as an arbitrary preference path.
    let parsed = uuid::Uuid::parse_str(id).map_err(|_| Error::msg("invalid network service identifier"))?;
    if !id.eq_ignore_ascii_case(&parsed.hyphenated().to_string()) { return Err(Error::msg("invalid network service identifier")); }
    Ok(format!("/NetworkServices/{id}/Proxies"))
}
/// Only unlink old, private temporary files made by this adapter while holding their lock.
fn clean_stale_temps(path: &Path) {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else { return };
    let prefix = format!(".{name}.prism-tmp-");
    let Ok(entries) = fs::read_dir(parent) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(suffix) = name.strip_prefix(&prefix) else { continue };
        if uuid::Uuid::parse_str(suffix).is_err() { continue; }
        let candidate = entry.path();
        let Ok(file) = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(&candidate) else { continue };
        let Ok(meta) = file.metadata() else { continue };
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.permissions().mode() & 0o777 != 0o600
            || !meta.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age >= std::time::Duration::from_secs(24 * 60 * 60)) { continue; }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { continue; }
        if fs::symlink_metadata(&candidate).is_ok_and(|m| m.is_file() && m.dev() == meta.dev() && m.ino() == meta.ino()) {
            let _ = fs::remove_file(&candidate);
        }
    }
}

fn save(path: &Path, backup: &Backup) -> Result<()> {
    let bytes = serde_json::to_vec(backup)?;
    if bytes.len() as u64 > MAX_BACKUP { return Err(Error::msg("network backup exceeds size limit")); }
    let parent = path.parent().ok_or_else(|| Error::msg("invalid backup location"))?;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| Error::msg("invalid backup name"))?;
    fs::create_dir_all(parent)?;
    clean_stale_temps(path);
    let temporary = parent.join(format!(".{name}.prism-tmp-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
    let result = (|| -> std::io::Result<()> {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Err(std::io::Error::last_os_error()); }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        // A hard link publishes the completed file atomically and cannot overwrite an existing backup.
        fs::hard_link(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    if let Err(e) = result { return Err(e.into()); }
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn load(path: &Path) -> Result<Backup> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.len() > MAX_BACKUP || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::msg("invalid or insecure network backup"));
    }
    let mut data = Vec::new();
    std::io::Read::by_ref(&mut file).take(MAX_BACKUP + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_BACKUP { return Err(Error::msg("network backup exceeds size limit")); }
    let backup: Backup = serde_json::from_slice(&data)?;
    if backup.version != 1 || backup.services.is_empty() || backup.services.len() > 1024 { return Err(Error::msg("invalid network backup")); }
    let mut ids = std::collections::HashSet::new();
    for e in &backup.services {
        service_path(&e.id)?;
        if !ids.insert(e.id.to_ascii_lowercase()) || transform::applied(&e.before, &backup.server, &backup.bypass).map_err(message)? != e.applied {
            return Err(Error::msg("invalid network backup contents"));
        }
    }
    Ok(backup)
}

pub fn is_active_for(server: &str) -> bool {
    let Some((host, port)) = server.rsplit_once(':') else { return false };
    let host = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    let Ok(port) = port.parse::<u16>() else { return false };
    let Ok(s) = sysproxy_macos_read::effective() else { return false };
    !s.auto_config && !s.auto_discovery && s.http.enabled && s.https.enabled
        && s.http.host.as_deref() == Some(host) && s.https.host.as_deref() == Some(host)
        && s.http.port == Some(port) && s.https.port == Some(port)
}

/// Verify the effective proxy and the managed fields of every service in the
/// current location. A newly added or externally edited service must not be
/// silently treated as protected.
pub(crate) fn active_configuration_matches(server: &str, bypass: &str) -> bool {
    if !is_active_for(server) { return false; }
    let Ok(services) = sysproxy_macos_read::service_snapshots() else { return false };
    let mut checked = false;
    for service in services {
        match service.configuration {
            Some(config) if service.proxy_protocol_exists => {
                checked = true;
                if !transform::matches_applied(&config, server, bypass).unwrap_or(false) { return false; }
            }
            // These services were not modified when capture was enabled. The
            // effective check above still catches one becoming the active path.
            None => (),
            _ => return false,
        }
    }
    checked
}

pub fn enable(server: &str, bypass: &str, backup_path: &Path) -> Result<()> {
    if backup_path.exists() { return Err(Error::msg("a previous proxy backup must be restored first")); }
    // Checking only the fully active HTTP+HTTPS configuration is insufficient: after a
    // crash or external edit just one protocol (or an inactive service) can still point
    // at our listener. Saving that state as the original would restore a dead proxy later.
    // Read failures are also unsafe, so the same conservative guard as disable applies.
    verify_no_owned_proxy(server)?;
    let transaction = Transaction::open_authorized().map_err(message)?;
    // Authorization can take arbitrarily long. Recheck after acquiring the lock so
    // an intervening network or proxy change cannot become the saved baseline.
    verify_no_owned_proxy(server)?;
    let location = sysproxy_macos_read::current_location_id().map_err(message)?;
    let snapshots = sysproxy_macos_read::service_snapshots().map_err(message)?;
    if sysproxy_macos_read::current_location_id().map_err(message)? != location {
        return Err(Error::msg("network location changed while reading proxy settings"));
    }
    if snapshots.is_empty() { return Err(Error::msg("no network services found")); }
    let mut entries = Vec::new();
    for s in &snapshots {
        service_path(&s.service_id)?;
        // Avoid creating a protocol or inventing a previous value on a service with no proxy config.
        if !s.proxy_protocol_exists || s.configuration.is_none() { continue; }
        let before = s.configuration.clone().unwrap();
        let applied = transform::applied(&before, server, bypass).map_err(message)?;
        entries.push(Entry { id: s.service_id.clone(), before, applied });
    }
    if entries.is_empty() { return Err(Error::msg("no network service has configurable proxy settings")); }
    let backup = Backup { version: 1, server: server.to_string(), bypass: bypass.to_string(), services: entries };
    // Save before any staged write. The backup remains on every failure and through a crash.
    save(backup_path, &backup)?;
    for e in &backup.services {
        if !transaction.stage_if_unchanged(&service_path(&e.id)?, Some(&e.before), Some(&e.applied)).map_err(message)? {
            return Err(Error::msg("network settings changed; restore the backup before retrying"));
        }
    }
    if sysproxy_macos_read::current_location_id().map_err(message)? != location
        || !same_services(&snapshots, &sysproxy_macos_read::service_snapshots().map_err(message)?) {
        return Err(Error::msg("network location or services changed; restore the backup before retrying"));
    }
    transaction.commit().map_err(message)?;
    transaction.apply_live().map_err(message)?;
    if !is_active_for(server) { return Err(Error::msg("the system proxy did not become active; restore the backup")); }
    Ok(())
}

fn verify_no_owned_proxy(ours: &str) -> Result<()> {
    let effective = sysproxy_macos_read::effective().map_err(message)?;
    for proxy in [&effective.http, &effective.https] {
        if transform::points_to_values(proxy.enabled, proxy.host.as_deref(), proxy.port, ours).map_err(message)? {
            return Err(Error::msg("proxy recovery required: backup missing and effective proxy points at PrismRoute"));
        }
    }
    // The effective proxy only describes the current connection. An inactive service can
    // become active later, so inspect all persistent service configurations as well.
    let services = sysproxy_macos_read::all_service_snapshots().map_err(message)?;
    if services.is_empty() { return Err(Error::msg("cannot verify network services without a proxy backup")); }
    for service in services {
        match service.configuration {
            Some(ref config) if transform::points_to_proxy(config, ours).map_err(message)? => {
                return Err(Error::msg("proxy recovery required: backup missing and a network service points at PrismRoute"));
            }
            Some(_) => (),
            None if !service.proxy_protocol_exists => (),
            None => return Err(Error::msg("cannot verify a network service without a proxy backup")),
        }
    }
    Ok(())
}

pub fn disable(backup_path: &Path, ours: &str) -> Result<()> {
    match fs::symlink_metadata(backup_path) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return verify_no_owned_proxy(ours),
        Err(e) => return Err(e.into()),
    }
    let backup = load(backup_path)?;
    let transaction = Transaction::open_authorized().map_err(message)?;
    let mut conflict = false;
    let mut staged = false;
    for e in &backup.services {
        let path = service_path(&e.id)?;
        let Some(current) = transaction.get(&path).map_err(message)? else { conflict = true; continue };
        match transform::restore(&current, &e.before, &e.applied).map_err(message)? {
            Restoration::AlreadyRestored => (),
            Restoration::Conflict => conflict = true,
            Restoration::Merged { data: restored, conflict: group_conflict } => {
                conflict |= group_conflict;
                if !transaction.stage_if_unchanged(&path, Some(&current), Some(&restored)).map_err(message)? { conflict = true; }
                else { staged = true; }
            }
        }
    }
    if staged { transaction.commit().map_err(message)?; }
    // Also re-apply after an earlier recovery committed but failed before apply.
    transaction.apply_live().map_err(message)?;
    if conflict { return Err(Error::msg("some proxy settings changed externally; backup retained")); }
    // Verify all managed fields, not only that the old listener is no longer in use.
    // Re-read persistent preferences after the commit; failures retain the backup.
    transaction.synchronize();
    for e in &backup.services {
        let current = transaction.get(&service_path(&e.id)?).map_err(message)?
            .ok_or_else(|| Error::msg("a network service disappeared; backup retained"))?;
        if !matches!(transform::restore(&current, &e.before, &e.applied).map_err(message)?, Restoration::AlreadyRestored) {
            return Err(Error::msg("restored proxy settings could not be verified; backup retained"));
        }
    }
    // A successful apply only means the request was accepted. Do not discard the
    // recovery data until both the effective proxy and every persistent service
    // have stopped pointing at our listener. A delayed or failed propagation is
    // recoverable on the next attempt with the backup still intact.
    verify_no_owned_proxy(&backup.server)?;
    fs::remove_file(backup_path)?;
    if let Some(parent) = backup_path.parent() { fs::File::open(parent)?.sync_all()?; }
    Ok(())
}
pub fn recover(backup: &Path, ours: &str) {
    if backup.exists() {
        if let Err(e) = disable(backup, ours) { tracing::error!("could not restore network proxy: {e}"); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_membership_must_remain_stable() {
        use crate::sysproxy_macos_read::ServiceSnapshot as S;
        let s = |id: &str, protocol: bool, config: bool| S { service_id: id.into(), proxy_protocol_exists: protocol, configuration: config.then(Vec::new) };
        let original = vec![s("a", true, true), s("b", false, false)];
        assert!(same_services(&original, &[s("B", false, false), s("A", true, true)]));
        assert!(!same_services(&original, &[s("a", true, true)]));
        assert!(!same_services(&original, &[s("a", true, true), s("b", true, true)]));
        assert!(!same_services(&original, &[s("a", true, true), s("a", true, true)]));
    }
    #[test]
    fn backup_is_private_and_tampering_is_rejected() {
        let dir = std::env::temp_dir().join(format!("prism-proxy-backup-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("proxy.json");
        let mut before = Vec::new();
        plist::Value::Dictionary(plist::Dictionary::new()).to_writer_binary(&mut before).unwrap();
        let entry = Entry { id: "A2A45B81-30A5-40DE-B0E5-1E0EA9232176".into(), applied: transform::applied(&before, "127.0.0.1:7890", "<local>").unwrap(), before };
        let mut backup = Backup { version: 1, server: "127.0.0.1:7890".into(), bypass: "<local>".into(), services: vec![entry] };
        save(&file, &backup).unwrap();
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(save(&file, &backup).is_err());
        assert_eq!(load(&file).unwrap().services.len(), 1);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&file).is_err(), "a readable backup must not be trusted");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&file).unwrap();
        backup.services[0].id = "../../system".into();
        save(&file, &backup).unwrap();
        assert!(load(&file).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn current_service_identifiers_are_safe_paths() {
        let services = sysproxy_macos_read::service_snapshots().unwrap();
        assert!(services.iter().all(|s| service_path(&s.service_id).is_ok()), "one or more service IDs cannot be represented safely");
    }

    fn test_bridge_inactive() -> Result<()> {
        let output = std::process::Command::new("/sbin/ifconfig").arg("bridge0").output()?;
        let text = std::str::from_utf8(&output.stdout).map_err(|_| Error::msg("invalid interface output"))?;
        if !output.status.success() || !text.lines().any(|s| s.trim() == "status: inactive")
            || text.lines().any(|s| s.trim_start().starts_with("inet ") || s.trim_start().starts_with("inet6 ")) {
            return Err(Error::msg("bridge0 is active or has an address"));
        }
        for interface in ["en1", "en2", "en3"] {
            let output = std::process::Command::new("/sbin/ifconfig").arg(interface).output()?;
            let text = std::str::from_utf8(&output.stdout).map_err(|_| Error::msg("invalid interface output"))?;
            if !output.status.success() || !text.lines().any(|s| s.trim() == "status: inactive") {
                return Err(Error::msg("a bridge member is active"));
            }
        }
        let route = std::process::Command::new("/sbin/route").args(["-n", "get", "default"]).output()?;
        let text = std::str::from_utf8(&route.stdout).map_err(|_| Error::msg("invalid route output"))?;
        if !route.status.success() || !text.lines().any(|s| s.trim() == "interface: en0") { return Err(Error::msg("default route is not Wi-Fi")); }
        Ok(())
    }

    /// Manual validation only: a specific inactive service, one commit followed by rollback.
    /// No SCPreferencesApplyChanges. A private durable backup remains on any failure.
    #[test]
    #[ignore = "manual test changes the persistent proxy dictionary of an inactive service"]
    fn manual_inactive_bridge_commit_and_rollback() {
        test_bridge_inactive().expect("bridge must be inactive");
        let id = sysproxy_macos_read::service_named("Thunderbolt Bridge", "bridge0").expect("resolve service");
        let path = service_path(&id).expect("valid service id");
        let tx = Transaction::open_authorized().expect("authorize and lock");
        test_bridge_inactive().expect("bridge changed state");
        let before = tx.get(&path).expect("read proxy").expect("service has no proxy dictionary");
        let applied = transform::applied(&before, "127.0.0.1:65534", "<local>").expect("plan");
        let dir = std::env::temp_dir().join(format!("prism-inactive-service-test-{}", std::process::id()));
        fs::create_dir(&dir).expect("create backup directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("protect backup directory");
        let file = dir.join("proxy.json");
        let backup = Backup { version: 1, server: "127.0.0.1:65534".into(), bypass: "<local>".into(), services: vec![Entry { id, before: before.clone(), applied: applied.clone() }] };
        save(&file, &backup).expect("durable backup");
        assert!(load(&file).is_ok(), "backup must be readable and valid before any staged write");
        eprintln!("Recovery backup: {}", file.display());
        test_bridge_inactive().expect("bridge changed state before commit");
        let change = (|| -> Result<()> {
            if !tx.stage_if_unchanged(&path, Some(&before), Some(&applied)).map_err(message)? { return Err(Error::msg("service settings changed")); }
            tx.commit().map_err(message)?;
            tx.synchronize();
            let current = tx.get(&path).map_err(message)?.ok_or_else(|| Error::msg("service disappeared"))?;
            if !matches!(transform::restore(&current, &before, &applied).map_err(message)?, Restoration::Merged { conflict: false, .. }) { return Err(Error::msg("commit verification failed")); }
            Ok(())
        })();
        // Attempt rollback on every path after staging, including a failed commit.
        let rollback = (|| -> Result<()> {
            tx.synchronize();
            let current = tx.get(&path).map_err(message)?.ok_or_else(|| Error::msg("service disappeared"))?;
            match transform::restore(&current, &before, &applied).map_err(message)? {
                Restoration::AlreadyRestored => (),
                Restoration::Merged { data: restored, conflict: false } => {
                    if !tx.stage_if_unchanged(&path, Some(&current), Some(&restored)).map_err(message)? { return Err(Error::msg("service changed during rollback")); }
                    tx.commit().map_err(message)?;
                    tx.synchronize();
                }
                Restoration::Merged { conflict: true, .. } => return Err(Error::msg("service changed externally; backup retained")),
                Restoration::Conflict => return Err(Error::msg("service changed externally; backup retained")),
            }
            let current = tx.get(&path).map_err(message)?.ok_or_else(|| Error::msg("service disappeared"))?;
            if !matches!(transform::restore(&current, &before, &applied).map_err(message)?, Restoration::AlreadyRestored) { return Err(Error::msg("rollback verification failed")); }
            let parse = |b: &[u8]| plist::Value::from_reader(std::io::Cursor::new(b)).map_err(|_| Error::msg("invalid proxy plist"));
            if parse(&current)? != parse(&before)? { return Err(Error::msg("other service settings changed; backup retained")); }
            Ok(())
        })();
        if rollback.is_ok() { fs::remove_file(&file).unwrap(); fs::remove_dir(&dir).unwrap(); }
        rollback.expect("rollback failed; backup retained");
        change.expect("commit verification failed; rollback succeeded");
    }
}
