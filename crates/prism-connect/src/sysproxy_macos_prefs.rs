//! Low-level SCPreferences transaction primitives. Not connected to the UI.
//! Callers must durably save a protected backup before staging a live change.
use std::{ffi::{c_char, c_void, CString}, path::Path, ptr};

type Ref = *const c_void;
const UTF8: u32 = 0x0800_0100;
const BINARY_PLIST: isize = 200;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Ref);
    fn CFStringCreateWithCString(alloc: Ref, string: *const c_char, encoding: u32) -> Ref;
    fn CFDataCreate(alloc: Ref, bytes: *const u8, length: isize) -> Ref;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFDataGetBytePtr(data: Ref) -> *const u8;
    fn CFPropertyListCreateData(alloc: Ref, plist: Ref, format: isize, options: usize, error: *mut Ref) -> Ref;
    fn CFPropertyListCreateWithData(alloc: Ref, data: Ref, options: usize, format: *mut isize, error: *mut Ref) -> Ref;
    fn CFGetTypeID(value: Ref) -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFEqual(a: Ref, b: Ref) -> u8;
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCPreferencesCreate(alloc: Ref, name: Ref, prefs_id: Ref) -> Ref;
    fn SCPreferencesCreateWithAuthorization(alloc: Ref, name: Ref, prefs_id: Ref, auth: Ref) -> Ref;
    fn SCPreferencesLock(prefs: Ref, wait: u8) -> u8;
    fn SCPreferencesUnlock(prefs: Ref) -> u8;
    fn SCPreferencesPathGetValue(prefs: Ref, path: Ref) -> Ref;
    fn SCPreferencesPathSetValue(prefs: Ref, path: Ref, value: Ref) -> u8;
    fn SCPreferencesPathRemoveValue(prefs: Ref, path: Ref) -> u8;
    fn SCPreferencesCommitChanges(prefs: Ref) -> u8;
    fn SCPreferencesApplyChanges(prefs: Ref) -> u8;
    fn SCPreferencesSynchronize(prefs: Ref);
    #[cfg(test)]
    fn SCError() -> i32;
    #[cfg(test)]
    fn SCErrorString(status: i32) -> *const c_char;
}

#[repr(C)]
struct AuthorizationItem { name: *const c_char, value_length: usize, value: *mut c_void, flags: u32 }
#[repr(C)]
struct AuthorizationRights { count: u32, items: *mut AuthorizationItem }

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn AuthorizationCreate(rights: *const AuthorizationRights, environment: Ref, flags: u32, auth: *mut Ref) -> i32;
    fn AuthorizationCopyRights(auth: Ref, rights: *const AuthorizationRights, environment: Ref, flags: u32, authorized: *mut *mut AuthorizationRights) -> i32;
    fn AuthorizationFree(auth: Ref, flags: u32) -> i32;
}

struct Authorization(Ref);
impl Drop for Authorization { fn drop(&mut self) { unsafe { AuthorizationFree(self.0, 0); } } }

impl Authorization {
    /// macOS asks the logged-in user to authorize network changes when required.
    fn request() -> Result<Self, &'static str> {
        let mut auth = ptr::null();
        if unsafe { AuthorizationCreate(ptr::null(), ptr::null(), 0, &mut auth) } != 0 || auth.is_null() {
            return Err("cannot create network authorization");
        }
        let auth = Self(auth);
        let mut item = AuthorizationItem { name: c"system.preferences.network".as_ptr(), value_length: 0, value: ptr::null_mut(), flags: 0 };
        let rights = AuthorizationRights { count: 1, items: &mut item };
        // interactionAllowed | extendRights. Fail closed when denied or no GUI is available.
        let status = unsafe { AuthorizationCopyRights(auth.0, &rights, ptr::null(), 3, ptr::null_mut()) };
        if status != 0 { return Err("network authorization was denied or cancelled"); }
        Ok(auth)
    }
}

struct Owned(Ref);
impl Drop for Owned { fn drop(&mut self) { unsafe { CFRelease(self.0) } } }

fn cf_string(value: &str) -> Result<Owned, &'static str> {
    let input = CString::new(value).map_err(|_| "invalid preferences string")?;
    let value = unsafe { CFStringCreateWithCString(ptr::null(), input.as_ptr(), UTF8) };
    if value.is_null() { return Err("cannot allocate preferences string") }
    Ok(Owned(value))
}

fn parse_dictionary(bytes: &[u8]) -> Result<Owned, &'static str> {
    if bytes.len() > 1024 * 1024 { return Err("proxy snapshot too large") }
    unsafe {
        let data = CFDataCreate(ptr::null(), bytes.as_ptr(), bytes.len() as isize);
        if data.is_null() { return Err("cannot allocate proxy snapshot") }
        let data = Owned(data);
        let value = CFPropertyListCreateWithData(ptr::null(), data.0, 0, ptr::null_mut(), ptr::null_mut());
        if value.is_null() { return Err("invalid proxy snapshot") }
        let value = Owned(value);
        if CFGetTypeID(value.0) != CFDictionaryGetTypeID() { return Err("proxy snapshot is not a dictionary") }
        Ok(value)
    }
}

fn serialize(value: Ref) -> Result<Vec<u8>, &'static str> {
    unsafe {
        let data = CFPropertyListCreateData(ptr::null(), value, BINARY_PLIST, 0, ptr::null_mut());
        if data.is_null() { return Err("cannot serialize preferences") }
        let data = Owned(data);
        let length = CFDataGetLength(data.0);
        if !(0..=1024 * 1024).contains(&length) { return Err("invalid preferences size") }
        let bytes = CFDataGetBytePtr(data.0);
        if bytes.is_null() && length != 0 { return Err("invalid preferences data") }
        Ok(if length == 0 { Vec::new() } else { std::slice::from_raw_parts(bytes, length as usize).to_vec() })
    }
}

fn equal_plist(a: Option<&[u8]>, b: Option<&[u8]>) -> Result<bool, &'static str> {
    match (a, b) {
        (None, None) => Ok(true),
        (Some(a), Some(b)) => {
            let a = parse_dictionary(a)?;
            let b = parse_dictionary(b)?;
            Ok(unsafe { CFEqual(a.0, b.0) != 0 })
        }
        _ => Ok(false),
    }
}

/// Owns a locked preferences session. Drop never commits changes.
pub struct Transaction { prefs: Owned, isolated: bool, locked: bool, _authorization: Option<Authorization> }

#[derive(Debug, PartialEq, Eq)]
pub enum Restore { AlreadyRestored, Staged, Conflict }

impl Transaction {
    /// `isolated_path` is for tests; `None` opens the system configuration.
    pub fn open(isolated_path: Option<&Path>) -> Result<Self, &'static str> {
        let name = cf_string("PrismRoute")?;
        let path = isolated_path.map(|p| p.to_str().ok_or("invalid preferences path")).transpose()?.map(cf_string).transpose()?;
        if isolated_path.is_some_and(|p| !p.is_absolute()) { return Err("preferences path must be absolute") }
        let prefs = unsafe { SCPreferencesCreate(ptr::null(), name.0, path.as_ref().map_or(ptr::null(), |s| s.0)) };
        if prefs.is_null() { return Err("cannot open network preferences") }
        let prefs = Owned(prefs);
        // Non-blocking: never hang while another process holds the lock.
        if unsafe { SCPreferencesLock(prefs.0, 0) } == 0 {
            #[cfg(test)]
            unsafe { eprintln!("SCPreferencesLock: {}", std::ffi::CStr::from_ptr(SCErrorString(SCError())).to_string_lossy()); }
            return Err("cannot lock network preferences");
        }
        Ok(Self { prefs, isolated: isolated_path.is_some(), locked: true, _authorization: None })
    }

    pub fn open_authorized() -> Result<Self, &'static str> {
        // A separately installed privileged guard must recover without a GUI
        // prompt after its client crashes. Never use this path for an ordinary
        // process: that process continues to use interactive authorization.
        if unsafe { libc::geteuid() } == 0 { Self::open(None) }
        else { Self::open_authorized_at(None) }
    }

    fn open_authorized_at(isolated_path: Option<&Path>) -> Result<Self, &'static str> {
        if isolated_path.is_some_and(|p| !p.is_absolute()) { return Err("preferences path must be absolute"); }
        let auth = Authorization::request()?;
        let name = cf_string("PrismRoute")?;
        let path = isolated_path.map(|p| p.to_str().ok_or("invalid preferences path")).transpose()?.map(cf_string).transpose()?;
        let prefs = unsafe { SCPreferencesCreateWithAuthorization(ptr::null(), name.0, path.as_ref().map_or(ptr::null(), |s| s.0), auth.0) };
        if prefs.is_null() { return Err("cannot open authorized network preferences"); }
        let prefs = Owned(prefs);
        if unsafe { SCPreferencesLock(prefs.0, 0) } == 0 {
            #[cfg(test)]
            unsafe { eprintln!("authorized SCPreferencesLock: {}", std::ffi::CStr::from_ptr(SCErrorString(SCError())).to_string_lossy()); }
            return Err("cannot lock network preferences");
        }
        Ok(Self { prefs, isolated: isolated_path.is_some(), locked: true, _authorization: Some(auth) })
    }

    #[cfg(test)]
    fn open_isolated_unlocked(path: &Path) -> Result<Self, &'static str> {
        let name = cf_string("PrismRoute isolated test")?;
        let path = cf_string(path.to_str().ok_or("invalid preferences path")?)?;
        let prefs = unsafe { SCPreferencesCreate(ptr::null(), name.0, path.0) };
        if prefs.is_null() { return Err("cannot open isolated preferences") }
        Ok(Self { prefs: Owned(prefs), isolated: true, locked: false, _authorization: None })
    }

    pub fn get(&self, path: &str) -> Result<Option<Vec<u8>>, &'static str> {
        let path = cf_string(path)?;
        let value = unsafe { SCPreferencesPathGetValue(self.prefs.0, path.0) };
        if value.is_null() { return Ok(None) }
        if unsafe { CFGetTypeID(value) != CFDictionaryGetTypeID() } { return Err("preferences value is not a dictionary") }
        Ok(Some(serialize(value)?))
    }

    fn stage(&self, path: &str, value: Option<&[u8]>) -> Result<(), &'static str> {
        let key = cf_string(path)?;
        let success = match value {
            Some(bytes) => {
                let value = parse_dictionary(bytes)?;
                unsafe { SCPreferencesPathSetValue(self.prefs.0, key.0, value.0) }
            }
            None => unsafe { SCPreferencesPathRemoveValue(self.prefs.0, key.0) },
        };
        if success == 0 { return Err("cannot stage network preferences") }
        Ok(())
    }

    /// Compare before staging so edits made by another app are not overwritten.
    pub fn stage_if_unchanged(&self, path: &str, expected: Option<&[u8]>, next: Option<&[u8]>) -> Result<bool, &'static str> {
        let current = self.get(path)?;
        if !equal_plist(current.as_deref(), expected)? { return Ok(false) }
        if !equal_plist(current.as_deref(), next)? { self.stage(path, next)?; }
        Ok(true)
    }

    pub fn restore(&self, path: &str, before: Option<&[u8]>, applied: Option<&[u8]>) -> Result<Restore, &'static str> {
        let current = self.get(path)?;
        if equal_plist(current.as_deref(), before)? { return Ok(Restore::AlreadyRestored) }
        if !equal_plist(current.as_deref(), applied)? { return Ok(Restore::Conflict) }
        self.stage(path, before)?;
        Ok(Restore::Staged)
    }

    /// Commit all staged values. Applying live changes is a separate fallible step.
    pub fn commit(&self) -> Result<(), &'static str> {
        if unsafe { SCPreferencesCommitChanges(self.prefs.0) } == 0 { return Err("cannot commit network preferences") }
        Ok(())
    }

    pub fn apply_live(&self) -> Result<(), &'static str> {
        if self.isolated { return Err("cannot apply isolated preferences to the system") }
        if unsafe { SCPreferencesApplyChanges(self.prefs.0) } == 0 { return Err("cannot apply network preferences") }
        Ok(())
    }

    /// Refresh after commit before verifying persisted settings.
    pub fn synchronize(&self) { unsafe { SCPreferencesSynchronize(self.prefs.0) } }
}

impl Drop for Transaction {
    fn drop(&mut self) { if self.locked { unsafe { SCPreferencesUnlock(self.prefs.0); } } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const OLD: &[u8] = &[98,112,108,105,115,116,48,48,209,1,2,90,72,84,84,80,69,110,97,98,108,101,16,0,8,11,22,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,24];
    const NEW: &[u8] = &[98,112,108,105,115,116,48,48,211,1,2,3,4,5,6,90,72,84,84,80,69,110,97,98,108,101,88,72,84,84,80,80,111,114,116,89,72,84,84,80,80,114,111,120,121,16,1,17,30,210,89,49,50,55,46,48,46,48,46,49,8,15,26,35,45,47,50,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,60];

    #[test]
    fn isolated_staging_conflict_and_restore_without_commit() {
        let dir = std::env::temp_dir().join(format!("prism-proxy-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.join("preferences.plist");
        let path = "/NetworkServices/Test/Proxies";
        {
            let tx = Transaction::open_isolated_unlocked(&file).unwrap();
            assert!(tx.apply_live().is_err());
            assert!(tx.stage_if_unchanged(path, None, Some(OLD)).unwrap());
            let before = tx.get(path).unwrap().unwrap();
            assert!(equal_plist(Some(&before), Some(OLD)).unwrap());
            assert!(tx.stage_if_unchanged(path, Some(&before), Some(NEW)).unwrap());
            assert_eq!(tx.restore(path, Some(OLD), Some(OLD)).unwrap(), Restore::Conflict);
            assert_eq!(tx.restore(path, Some(OLD), Some(NEW)).unwrap(), Restore::Staged);
            assert_eq!(tx.restore(path, Some(OLD), Some(NEW)).unwrap(), Restore::AlreadyRestored);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Manual test: requests authorization and only commits a private preferences file.
    /// Never applies the changes to the system network configuration.
    #[test]
    #[ignore = "requires interactive macOS authorization"]
    fn isolated_authorized_commit_without_network_apply() {
        let dir = std::env::temp_dir().join(format!("prism-proxy-authorized-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.join("preferences.plist");
        let key = "/NetworkServices/Test/Proxies";
        {
            let tx = Transaction::open_authorized_at(Some(&file)).expect("authorization or isolated lock failed");
            assert!(tx.stage_if_unchanged(key, None, Some(OLD)).unwrap());
            tx.commit().expect("isolated commit failed");
            assert!(tx.apply_live().is_err());
        }
        {
            let tx = Transaction::open_isolated_unlocked(&file).unwrap();
            let current = tx.get(key).unwrap();
            assert!(equal_plist(current.as_deref(), Some(OLD)).unwrap());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires interactive macOS authorization"]
    fn authorized_live_lock_without_writes() {
        let snapshots = crate::sysproxy_macos_read::service_snapshots().expect("read services");
        let tx = Transaction::open_authorized().expect("authorization or live lock failed");
        let mut tested = 0;
        for service in snapshots {
            let Some(before) = service.configuration else { continue };
            let path = format!("/NetworkServices/{}/Proxies", service.service_id);
            let current = tx.get(&path).expect("read service path");
            assert!(equal_plist(current.as_deref(), Some(&before)).unwrap(), "service snapshot differs from preferences path");
            tested += 1;
        }
        assert!(tested > 0, "no configured proxy dictionaries in current location");
    }
}
