//! First-install filesystem primitive, not an installer entry point.
//!
//! The future privileged installer must authenticate itself and independently
//! verify its payload, obtain the guard lock, reject existing backup state,
//! manage and verify launchd services, and decide whether rollback is safe.
//! None of those responsibilities are provided here. Unexpected termination or
//! power loss can leave files and requires separate recovery before retrying.
use std::{ffi::{CStr, CString}, fs::File, io::{self, Read, Write}, os::fd::{AsRawFd, FromRawFd}, os::unix::fs::MetadataExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirKind { Helpers, Daemons, State }
#[derive(Clone, Copy)]
pub(crate) enum Slot { Guard, Bridge, RecoveryPlist, BridgePlist, ClientPolicy }
impl Slot {
    fn name(self) -> &'static CStr {
        match self {
            Self::Guard => c"dev.prismroute.proxy-guard",
            Self::Bridge => c"dev.prismroute.proxy-bridge",
            Self::RecoveryPlist => c"dev.prismroute.proxy-recovery.plist",
            Self::BridgePlist => c"dev.prismroute.proxy-bridge.plist",
            Self::ClientPolicy => c"client-cdhash",
        }
    }
    fn kind(self) -> DirKind {
        match self { Self::Guard | Self::Bridge => DirKind::Helpers,
            Self::RecoveryPlist | Self::BridgePlist => DirKind::Daemons, Self::ClientPolicy => DirKind::State }
    }
    fn mode(self) -> libc::mode_t {
        match self { Self::Guard | Self::Bridge => 0o755,
            Self::RecoveryPlist | Self::BridgePlist => 0o644, Self::ClientPolicy => 0o600 }
    }
}

pub(crate) struct Directory { file: File, kind: DirKind, owner: u32 }

fn open_child(parent: &File, name: &CStr, owner: u32, private: bool) -> io::Result<File> {
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if raw < 0 { return Err(io::Error::last_os_error()); }
    let file = unsafe { File::from_raw_fd(raw) };
    let meta = file.metadata()?;
    let prohibited = if private { 0o077 } else { 0o022 };
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & prohibited != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "untrusted installation directory"));
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
fn open_or_create_child(parent: &File, name: &CStr, private: bool) -> io::Result<File> {
    let mode = if private { 0o700 } else { 0o755 };
    let created = if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } == 0 {
        true
    } else {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists { return Err(error); }
        false
    };
    let file = open_child(parent, name, 0, private)?;
    if created {
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 { return Err(io::Error::last_os_error()); }
        parent.sync_all()?;
    }
    Ok(file)
}

impl Directory {
    /// Read one fixed, root-protected installation file. Never follow links or
    /// accept an unexpected owner, permission, type, link count or size.
    pub(crate) fn read_slot(&self, slot: Slot) -> io::Result<Vec<u8>> {
        if slot.kind() != self.kind { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid installation slot")); }
        let raw = unsafe { libc::openat(self.file.as_raw_fd(), slot.name().as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if raw < 0 { return Err(io::Error::last_os_error()); }
        let file = unsafe { File::from_raw_fd(raw) };
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != self.owner || meta.nlink() != 1 || meta.mode() & 0o7777 != slot.mode() as u32
            || meta.len() == 0 || meta.len() > 128 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "untrusted installed file"));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.take(128 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != meta.len() { return Err(io::Error::other("installed file changed while reading")); }
        Ok(bytes)
    }

    /// Atomic replacement of a fixed file only if its current contents match
    /// the expected snapshot. On ambiguous errors the backup is left intact.
    pub(crate) fn replace_slot(&self, slot: Slot, expected: &[u8], replacement: &[u8]) -> io::Result<()> {
        if replacement.is_empty() || replacement.len() > 128 * 1024 * 1024 || self.read_slot(slot)? != expected {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "installed file changed during update"));
        }
        let name = CString::new(format!(".prism-update-{}", uuid::Uuid::new_v4().simple())).unwrap();
        let raw = unsafe { libc::openat(self.file.as_raw_fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, slot.mode() as libc::c_uint) };
        if raw < 0 { return Err(io::Error::last_os_error()); }
        let temp = Temp { dir: &self.file, name };
        let mut file = unsafe { File::from_raw_fd(raw) };
        if unsafe { libc::fchmod(file.as_raw_fd(), slot.mode()) } != 0 { return Err(io::Error::last_os_error()); }
        file.write_all(replacement)?;
        file.sync_all()?;
        if self.read_slot(slot)? != expected { return Err(io::Error::new(io::ErrorKind::InvalidData, "installed file changed during update")); }
        if unsafe { libc::renameat(self.file.as_raw_fd(), temp.name.as_ptr(), self.file.as_raw_fd(), slot.name().as_ptr()) } != 0 { return Err(io::Error::last_os_error()); }
        self.file.sync_all()
    }

    /// Retain copies in a new private root-owned directory. No installed file
    /// or service is touched until all copies are fully written and synced.
    pub(crate) fn retain_backup(&self, entries: &[(Slot, &[u8])]) -> io::Result<String> {
        if self.kind != DirKind::State || entries.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid backup")); }
        let name = format!("previous-{}", uuid::Uuid::new_v4().simple());
        let c_name = CString::new(name.as_str()).unwrap();
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 { return Err(io::Error::last_os_error()); }
        let dir = open_child(&self.file, &c_name, self.owner, true)?;
        for (slot, bytes) in entries {
            if bytes.is_empty() || bytes.len() > 128 * 1024 * 1024 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid backup contents")); }
            let raw = unsafe { libc::openat(dir.as_raw_fd(), slot.name().as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
            if raw < 0 { return Err(io::Error::last_os_error()); }
            let mut file = unsafe { File::from_raw_fd(raw) };
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 { return Err(io::Error::last_os_error()); }
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        dir.sync_all()?;
        self.file.sync_all()?;
        Ok(name)
    }
    /// Existing paths only. A separate secure provisioner is needed if any
    /// directory is absent. No path or expected owner comes from the caller.
    #[cfg(target_os = "macos")]
    pub(crate) fn system_directories() -> io::Result<(Self, Self, Self)> {
        let root = File::open("/")?;
        let root_meta = root.metadata()?;
        if !root_meta.is_dir() || root_meta.uid() != 0 || root_meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "untrusted root directory"));
        }
        let library = open_child(&root, c"Library", 0, false)?;
        let helpers = open_child(&library, c"PrivilegedHelperTools", 0, false)?;
        let daemons = open_child(&library, c"LaunchDaemons", 0, false)?;
        let private = open_child(&root, c"private", 0, false)?;
        let var = open_child(&private, c"var", 0, false)?;
        let db = open_child(&var, c"db", 0, false)?;
        let state = open_child(&db, c"dev.prismroute", 0, true)?;
        Ok((Self { file: helpers, kind: DirKind::Helpers, owner: 0 }, Self { file: daemons, kind: DirKind::Daemons, owner: 0 }, Self { file: state, kind: DirKind::State, owner: 0 }))
    }

    /// Provision only the fixed root-owned directories needed by first install.
    /// Existing directories are never chmodded and must pass the same checks.
    #[cfg(target_os = "macos")]
    pub(crate) fn provision_system_directories() -> io::Result<(Self, Self, Self)> {
        if unsafe { libc::geteuid() } != 0 { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "administrator authorization required")); }
        let root = File::open("/")?;
        let meta = root.metadata()?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "untrusted root directory"));
        }
        let library = open_child(&root, c"Library", 0, false)?;
        let helpers = open_or_create_child(&library, c"PrivilegedHelperTools", false)?;
        let daemons = open_child(&library, c"LaunchDaemons", 0, false)?;
        let private = open_child(&root, c"private", 0, false)?;
        let var = open_child(&private, c"var", 0, false)?;
        let db = open_child(&var, c"db", 0, false)?;
        let state = open_or_create_child(&db, c"dev.prismroute", true)?;
        let raw = unsafe { libc::openat(state.as_raw_fd(), c"guard.lock".as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        if raw >= 0 {
            let file = unsafe { File::from_raw_fd(raw) };
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 { return Err(io::Error::last_os_error()); }
            file.sync_all()?;
            state.sync_all()?;
        } else if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
            return Err(io::Error::last_os_error());
        }
        Ok((Self { file: helpers, kind: DirKind::Helpers, owner: 0 }, Self { file: daemons, kind: DirKind::Daemons, owner: 0 }, Self { file: state, kind: DirKind::State, owner: 0 }))
    }
}

/// Holds the same exclusive lock used by the running guard for its complete
/// lifetime. The file must already exist; creation/provisioning is separate.
/// Keep the transaction borrowing this lock until every service start, verify,
/// or rollback command has returned and no child operation can still mutate
/// launchd state. A crash releases the lock and needs independent recovery.
pub(crate) struct GuardLock { _file: File }
impl GuardLock {
    pub(crate) fn acquire(state: &Directory) -> io::Result<Self> {
        if state.kind != DirKind::State { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid guard state directory")); }
        let raw = unsafe { libc::openat(state.file.as_raw_fd(), c"guard.lock".as_ptr(), libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if raw < 0 { return Err(io::Error::last_os_error()); }
        let lock = unsafe { File::from_raw_fd(raw) };
        let meta = lock.metadata()?;
        if !meta.is_file() || meta.uid() != state.owner || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "untrusted guard lock"));
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Err(io::Error::last_os_error()); }
        // Refuse a changed path even if we successfully locked the old inode.
        let mut current: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(state.file.as_raw_fd(), c"guard.lock".as_ptr(), &mut current, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if current.st_dev as u64 != meta.dev() || current.st_ino as u64 != meta.ino()
            || current.st_mode & libc::S_IFMT != libc::S_IFREG || current.st_nlink != 1 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "guard lock path changed"));
        }
        let mut backup: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(state.file.as_raw_fd(), c"proxy-backup.json".as_ptr(), &mut backup, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "proxy recovery is required before installation"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound { return Err(error); }
        Ok(Self { _file: lock })
    }
}

struct Published { dir: File, name: &'static CStr, device: u64, inode: u64 }
fn unlink_matching(entry: &Published) -> io::Result<()> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let status = unsafe { libc::fstatat(entry.dir.as_raw_fd(), entry.name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    if status != 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(error) };
    }
    if stat.st_dev as u64 != entry.device || stat.st_ino as u64 != entry.inode || stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "installation file changed; retained for inspection"));
    }
    if unsafe { libc::unlinkat(entry.dir.as_raw_fd(), entry.name.as_ptr(), 0) } != 0 { return Err(io::Error::last_os_error()); }
    entry.dir.sync_all()
}

struct Temp<'a> { dir: &'a File, name: CString }
impl Drop for Temp<'_> {
    fn drop(&mut self) { unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0); } }
}

/// Tracks only files created by this operation. Callers must establish that no
/// launchd service can be using them before rollback. This type does not make
/// that determination or clean up after SIGKILL or power loss.
pub(crate) struct Transaction<'lock> { published: Vec<Published>, committed: bool, failed: bool, _lock: &'lock GuardLock }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step { BeforeLink, AfterLink }
impl<'lock> Transaction<'lock> {
    pub(crate) fn new(lock: &'lock GuardLock) -> Self { Self { published: Vec::new(), committed: false, failed: false, _lock: lock } }
    pub(crate) fn publish(&mut self, dir: &Directory, slot: Slot, bytes: &[u8]) -> io::Result<()> {
        if self.failed { return Err(io::Error::other("installation transaction has failed")); }
        let result = self.publish_inner(dir, slot, bytes, |_| Ok(()));
        if result.is_err() { self.failed = true; }
        result
    }
    fn publish_inner(&mut self, dir: &Directory, slot: Slot, bytes: &[u8], mut step: impl FnMut(Step) -> io::Result<()>) -> io::Result<()> {
        if self.committed || slot.kind() != dir.kind || bytes.is_empty() || bytes.len() > 128 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid installation publication"));
        }
        let name = CString::new(format!(".prism-install-{}", uuid::Uuid::new_v4().simple())).unwrap();
        let raw = unsafe { libc::openat(dir.file.as_raw_fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, slot.mode() as libc::c_uint) };
        if raw < 0 { return Err(io::Error::last_os_error()); }
        let temp = Temp { dir: &dir.file, name };
        let mut file = unsafe { File::from_raw_fd(raw) };
        if unsafe { libc::fchmod(file.as_raw_fd(), slot.mode()) } != 0 { return Err(io::Error::last_os_error()); }
        file.write_all(bytes)?;
        file.sync_all()?;
        let meta = file.metadata()?;
        // Record before link: even an error after publication can be rolled back.
        self.published.push(Published { dir: dir.file.try_clone()?, name: slot.name(), device: meta.dev(), inode: meta.ino() });
        if let Err(error) = step(Step::BeforeLink) { self.published.pop(); return Err(error); }
        if unsafe { libc::linkat(dir.file.as_raw_fd(), temp.name.as_ptr(), dir.file.as_raw_fd(), slot.name().as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            self.published.pop(); // Failed link did not publish our inode.
            return Err(error);
        }
        step(Step::AfterLink)?;
        if unsafe { libc::unlinkat(dir.file.as_raw_fd(), temp.name.as_ptr(), 0) } != 0 { return Err(io::Error::last_os_error()); }
        dir.file.sync_all()?;
        Ok(())
    }
    pub(crate) fn rollback(&mut self) -> io::Result<()> {
        if self.committed { return Err(io::Error::other("committed installation cannot be rolled back here")); }
        let mut error = None;
        for entry in self.published.iter().rev() {
            if let Err(e) = unlink_matching(entry) { if error.is_none() { error = Some(e); } }
        }
        if let Some(error) = error { return Err(error); }
        self.published.clear();
        Ok(())
    }
    pub(crate) fn commit(&mut self) -> io::Result<()> {
        if self.failed || self.committed { return Err(io::Error::other("installation transaction cannot be committed")); }
        self.committed = true;
        Ok(())
    }
}
// Deliberately no rollback in Drop: files must be retained if an interrupted
// caller cannot first prove that launchd has stopped using them.

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::{PermissionsExt, symlink}};
    fn fixture() -> (std::path::PathBuf, Directory, Directory, GuardLock) {
        let path = std::env::temp_dir().join(format!("prism-install-fs-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(&path).unwrap();
        let owner = unsafe { libc::geteuid() };
        let state_path = path.join(".state");
        fs::create_dir(&state_path).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(state_path.join("guard.lock"), b"").unwrap();
        fs::set_permissions(state_path.join("guard.lock"), fs::Permissions::from_mode(0o600)).unwrap();
        let state = Directory { file: File::open(&state_path).unwrap(), kind: DirKind::State, owner };
        let guard_lock = GuardLock::acquire(&state).unwrap();
        (path, Directory { file, kind: DirKind::Helpers, owner }, state, guard_lock)
    }
    #[test]
    fn first_install_commits_and_rollback_removes_own_files() {
        let (path, directory, _state, lock) = fixture();
        let guard = path.join("dev.prismroute.proxy-guard");
        let bridge = path.join("dev.prismroute.proxy-bridge");
        let mut tx = Transaction::new(&lock);
        tx.publish(&directory, Slot::Guard, b"guard").unwrap();
        tx.publish(&directory, Slot::Bridge, b"bridge").unwrap();
        assert_eq!(fs::read(&guard).unwrap(), b"guard");
        assert_eq!(fs::metadata(&bridge).unwrap().mode() & 0o777, 0o755);
        tx.rollback().unwrap();
        assert!(!guard.exists() && !bridge.exists());
        let mut tx = Transaction::new(&lock);
        tx.publish(&directory, Slot::Guard, b"guard").unwrap();
        tx.commit().unwrap();
        assert!(tx.rollback().is_err());
        assert_eq!(fs::read(&guard).unwrap(), b"guard");
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn update_preserves_previous_files_and_refuses_unexpected_replacement() {
        let (path, directory, state, lock) = fixture();
        let mut tx = Transaction::new(&lock);
        tx.publish(&directory, Slot::Guard, b"old guard").unwrap();
        tx.publish(&directory, Slot::Bridge, b"old bridge").unwrap();
        tx.publish(&state, Slot::ClientPolicy, b"old policy").unwrap();
        tx.commit().unwrap();
        let backup = state.retain_backup(&[(Slot::Guard, b"old guard"), (Slot::Bridge, b"old bridge"), (Slot::ClientPolicy, b"old policy")]).unwrap();
        assert_eq!(fs::read(path.join(".state").join(&backup).join("dev.prismroute.proxy-guard")).unwrap(), b"old guard");
        assert!(directory.replace_slot(Slot::Guard, b"unexpected", b"new guard").is_err());
        assert_eq!(directory.read_slot(Slot::Guard).unwrap(), b"old guard");
        directory.replace_slot(Slot::Guard, b"old guard", b"new guard").unwrap();
        assert_eq!(directory.read_slot(Slot::Guard).unwrap(), b"new guard");
        directory.replace_slot(Slot::Guard, b"new guard", b"old guard").unwrap();
        assert_eq!(directory.read_slot(Slot::Guard).unwrap(), b"old guard");
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn refuses_existing_files_and_never_removes_a_replacement() {
        let (path, directory, _state, lock) = fixture();
        let guard = path.join("dev.prismroute.proxy-guard");
        let bridge = path.join("dev.prismroute.proxy-bridge");
        fs::write(&bridge, b"other").unwrap();
        let mut tx = Transaction::new(&lock);
        tx.publish(&directory, Slot::Guard, b"guard").unwrap();
        assert!(tx.publish(&directory, Slot::Bridge, b"bridge").is_err());
        assert!(tx.commit().is_err());
        tx.rollback().unwrap(); // Existing destination was never ours.
        assert!(!guard.exists());
        assert_eq!(fs::read(&bridge).unwrap(), b"other");
        let mut tx = Transaction::new(&lock);
        tx.publish(&directory, Slot::Guard, b"guard").unwrap();
        fs::remove_file(&guard).unwrap();
        symlink(&bridge, &guard).unwrap();
        assert!(tx.rollback().is_err());
        assert!(fs::symlink_metadata(&guard).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&bridge).unwrap(), b"other");
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn rejects_untrusted_directories_and_wrong_slots() {
        let (path, directory, _state, lock) = fixture();
        let child = path.join("child");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o777)).unwrap();
        let owner = unsafe { libc::geteuid() };
        assert!(open_child(&directory.file, c"child", owner, false).is_err());
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_child(&directory.file, c"child", owner, false).is_ok());
        symlink(&child, path.join("link")).unwrap();
        assert!(open_child(&directory.file, c"link", owner, false).is_err());
        let mut tx = Transaction::new(&lock);
        assert!(tx.publish(&directory, Slot::ClientPolicy, b"policy").is_err());
        assert!(tx.publish(&directory, Slot::Guard, b"").is_err());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn interrupted_publication_and_failed_rollback_are_reported() {
        for fail_at in [Step::BeforeLink, Step::AfterLink] {
            let (path, directory, _state, lock) = fixture();
            let mut tx = Transaction::new(&lock);
            tx.publish(&directory, Slot::Bridge, b"bridge").unwrap();
            let result = tx.publish_inner(&directory, Slot::Guard, b"guard", |step| {
                if step == fail_at { Err(io::Error::other("injected interruption")) } else { Ok(()) }
            });
            assert!(result.is_err());
            tx.rollback().unwrap();
            assert_eq!(fs::read_dir(&path).unwrap().count(), 1); // state directory only
            fs::remove_dir_all(path).unwrap();
        }
        let (path, directory, _state, lock) = fixture();
        let guard = path.join("dev.prismroute.proxy-guard");
        let mut tx = Transaction::new(&lock);
        tx.publish(&directory, Slot::Guard, b"guard").unwrap();
        fs::remove_file(&guard).unwrap();
        fs::create_dir(&guard).unwrap();
        assert!(tx.rollback().is_err());
        assert!(guard.is_dir()); // Caller must report unresolved cleanup.
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn lock_is_exclusive_and_backups_block_installation() {
        let (path, directory, state, lock) = fixture();
        assert!(GuardLock::acquire(&directory).is_err());
        assert!(GuardLock::acquire(&state).is_err());
        let tx = Transaction::new(&lock);
        assert!(GuardLock::acquire(&state).is_err());
        drop(tx);
        assert!(GuardLock::acquire(&state).is_err());
        drop(lock);
        let backup = path.join(".state/proxy-backup.json");
        fs::write(&backup, b"preserve").unwrap();
        assert!(GuardLock::acquire(&state).is_err());
        assert_eq!(fs::read(&backup).unwrap(), b"preserve");
        fs::remove_file(&backup).unwrap();
        symlink("nonexistent", &backup).unwrap();
        assert!(GuardLock::acquire(&state).is_err());
        fs::remove_file(&backup).unwrap();
        let next = GuardLock::acquire(&state).unwrap();
        drop(next);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn rejects_untrusted_guard_lock_files() {
        let (path, _directory, state, lock) = fixture();
        drop(lock);
        let lock_path = path.join(".state/guard.lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(GuardLock::acquire(&state).is_err());
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&lock_path, path.join(".state/other")).unwrap();
        assert!(GuardLock::acquire(&state).is_err());
        fs::remove_file(path.join(".state/other")).unwrap();
        fs::remove_file(&lock_path).unwrap();
        symlink("missing", &lock_path).unwrap();
        assert!(GuardLock::acquire(&state).is_err());
        fs::remove_dir_all(path).unwrap();
    }
}
