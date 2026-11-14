//! Isolated recovery model. It is not connected to SystemConfiguration or the UI.
//!
//! A real journal backend MUST atomically publish and fsync its data and directory,
//! securely validate ownership and paths, and guarantee that a successful call is
//! durable across power loss. Likewise, a real network backend must perform its
//! compare-and-commit under the platform transaction lock and verify both persistent
//! and effective settings. The test backend below simulates these contracts; it does
//! not establish that the operating system or an actual helper satisfies them.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

type Fields = BTreeMap<String, Value>;
type Snapshot = BTreeMap<String, Fields>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Group {
    service: String,
    before: BTreeMap<String, Option<Value>>,
    applied: BTreeMap<String, Option<Value>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase { Prepared, Committed, Applied }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Journal { version: u8, phase: Phase, groups: Vec<Group> }

impl Journal {
    fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 || self.groups.is_empty() || self.groups.len() > 1024 { return Err("invalid journal"); }
        let mut seen = std::collections::BTreeSet::new();
        for g in &self.groups {
            if g.service.is_empty() || g.service.len() > 256 || g.before.is_empty()
                || g.before.len() > 256 || g.before.keys().ne(g.applied.keys()) {
                return Err("invalid group");
            }
            for key in g.before.keys() {
                if key.is_empty() || key.len() > 256 || !seen.insert((g.service.clone(), key.clone())) {
                    return Err("duplicate or invalid field");
                }
            }
        }
        Ok(())
    }
}

/// Calls may fail after taking effect. A successful publish/update/clear is durable.
/// A publish must never replace an existing journal, even under concurrent callers.
trait JournalStore {
    fn load(&mut self) -> Result<Option<Journal>, &'static str>;
    fn publish(&mut self, journal: &Journal) -> Result<(), &'static str>;
    fn update(&mut self, journal: &Journal) -> Result<(), &'static str>;
    fn clear(&mut self) -> Result<(), &'static str>;
}

/// Experimental filesystem store for an already-existing private directory.
/// The parent path still needs secure provisioning and independent review before
/// a privileged helper can rely on it. It is not connected to the application.
#[cfg(unix)]
struct FileJournal { dir: std::fs::File, _lock: std::fs::File }

#[cfg(unix)]
impl FileJournal {
    fn new(dir: &std::path::Path) -> Result<Self, &'static str> {
        use std::os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{MetadataExt, PermissionsExt}}};
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|_| "invalid journal directory")?;
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 { return Err("cannot open journal directory"); }
        let dir = unsafe { std::fs::File::from_raw_fd(fd) };
        let m = dir.metadata().map_err(|_| "cannot inspect journal directory")?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o077 != 0 {
            return Err("insecure journal directory");
        }
        let lock_fd = unsafe { libc::openat(dir.as_raw_fd(), c".journal-lock".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        if lock_fd < 0 { return Err("cannot open journal lock"); }
        let lock = unsafe { std::fs::File::from_raw_fd(lock_fd) };
        let m = lock.metadata().map_err(|_| "cannot inspect journal lock")?;
        if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.nlink() != 1
            || m.permissions().mode() & 0o077 != 0 { return Err("insecure journal lock"); }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("journal already in use");
        }
        Ok(Self { dir, _lock: lock })
    }

    fn write(&self, journal: &Journal, initial: bool) -> Result<(), &'static str> {
        use std::{io::Write, os::fd::{AsRawFd, FromRawFd}};
        journal.validate()?;
        let bytes = serde_json::to_vec(journal).map_err(|_| "serialize journal")?;
        if bytes.len() > 1024 * 1024 { return Err("journal too large"); }
        let temp = std::ffi::CString::new(format!(".journal-{}", uuid::Uuid::new_v4())).map_err(|_| "invalid temporary name")?;
        let dir = self.dir.as_raw_fd();
        let fd = unsafe { libc::openat(dir, temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        if fd < 0 { return Err("create journal"); }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let result = (|| -> Result<(), &'static str> {
            file.write_all(&bytes).map_err(|_| "write journal")?;
            file.sync_all().map_err(|_| "sync journal")?;
            // macOS fsync alone need not flush a drive's volatile write cache.
            #[cfg(target_os = "macos")]
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } != 0 {
                return Err("fully sync journal");
            }
            if initial {
                if unsafe { libc::linkat(dir, temp.as_ptr(), dir, c"proxy-journal.json".as_ptr(), 0) } != 0 {
                    return Err("publish journal");
                }
            } else {
                // Updates only follow a verified existing journal in a private directory.
                if self.load_file()?.is_none() { return Err("journal missing"); }
                if unsafe { libc::renameat(dir, temp.as_ptr(), dir, c"proxy-journal.json".as_ptr()) } != 0 {
                    return Err("replace journal");
                }
            }
            self.dir.sync_all().map_err(|_| "sync directory")?;
            Ok(())
        })();
        // With a hard-link publish the temporary link remains until this cleanup.
        // A failed unlink does not make publication safe to report as successful.
        let unlink = unsafe { libc::unlinkat(dir, temp.as_ptr(), 0) };
        if result.is_ok() && initial && unlink != 0 { return Err("remove temporary journal"); }
        if result.is_ok() && initial { self.dir.sync_all().map_err(|_| "sync directory")?; }
        result
    }

    fn load_file(&self) -> Result<Option<Journal>, &'static str> {
        use std::{io::Read, os::{fd::{AsRawFd, FromRawFd}, unix::fs::{MetadataExt, PermissionsExt}}};
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), c"proxy-journal.json".as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound { return Ok(None); }
            return Err("open journal");
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut m = file.metadata().map_err(|_| "inspect journal")?;
        if !m.is_file() || m.uid() != unsafe { libc::geteuid() }
            || m.permissions().mode() & 0o077 != 0 || m.len() > 1024 * 1024 {
            return Err("insecure journal");
        }
        if m.nlink() != 1 {
            // A crash can leave the temporary hard link created during atomic
            // publication. Remove only our UUID-named links to this same inode.
            self.remove_published_temp_links(m.dev(), m.ino())?;
            m = file.metadata().map_err(|_| "inspect journal")?;
            if m.nlink() != 1 { return Err("insecure journal links"); }
        }
        let mut bytes = Vec::new();
        (&mut file).take(1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| "read journal")?;
        if bytes.len() > 1024 * 1024 { return Err("journal too large"); }
        let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| "invalid journal")?;
        journal.validate()?;
        Ok(Some(journal))
    }

    fn remove_published_temp_links(&self, device: u64, inode: u64) -> Result<(), &'static str> {
        use std::os::fd::AsRawFd;
        // fdopendir owns its fd. Use a distinct descriptor and keep operations
        // anchored to the already-validated directory, not its replaceable path.
        let fd = unsafe { libc::fcntl(self.dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 { return Err("duplicate journal directory"); }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe { libc::close(fd); }
            return Err("read journal directory");
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }
        let stream = Directory(stream);
        let mut removed = false;
        unsafe { libc::rewinddir(stream.0); }
        loop {
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() { break; }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            let Ok(text) = name.to_str() else { continue };
            let Some(suffix) = text.strip_prefix(".journal-") else { continue };
            if uuid::Uuid::parse_str(suffix).is_err() { continue; }
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(self.dir.as_raw_fd(), name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
                return Err("inspect temporary journal");
            }
            if stat.st_dev as u64 == device && stat.st_ino as u64 == inode {
                if unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err("remove temporary journal");
                }
                removed = true;
            }
        }
        if removed { self.dir.sync_all().map_err(|_| "sync directory")?; }
        Ok(())
    }
}

#[cfg(unix)]
impl JournalStore for FileJournal {
    fn load(&mut self) -> Result<Option<Journal>, &'static str> { self.load_file() }
    fn publish(&mut self, journal: &Journal) -> Result<(), &'static str> { self.write(journal, true) }
    fn update(&mut self, journal: &Journal) -> Result<(), &'static str> { self.write(journal, false) }
    fn clear(&mut self) -> Result<(), &'static str> {
        use std::os::fd::AsRawFd;
        if self.load_file()?.is_none() { return Err("journal missing"); }
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), c"proxy-journal.json".as_ptr(), 0) } != 0 { return Err("remove journal"); }
        self.dir.sync_all().map_err(|_| "sync directory")?;
        Ok(())
    }
}

/// `commit_if_unchanged` must compare and commit atomically under the platform lock.
/// `verify` must inspect both persisted and effective settings; errors fail closed.
trait Backend {
    fn snapshot(&mut self) -> Result<Snapshot, &'static str>;
    fn commit_if_unchanged(&mut self, old: &Snapshot, new: &Snapshot) -> Result<(), &'static str>;
    fn apply(&mut self) -> Result<(), &'static str>;
    fn verify(&mut self, journal: &Journal, restored: bool) -> Result<bool, &'static str>;
}

fn matches(fields: &Fields, desired: &BTreeMap<String, Option<Value>>) -> bool {
    desired.iter().all(|(k, v)| fields.get(k) == v.as_ref())
}

fn merge(fields: &mut Fields, desired: &BTreeMap<String, Option<Value>>) {
    for (key, value) in desired {
        match value {
            Some(value) => { fields.insert(key.clone(), value.clone()); }
            None => { fields.remove(key); }
        }
    }
}

/// Commit is never attempted until a complete recovery journal is durable.
fn activate(store: &mut impl JournalStore, backend: &mut impl Backend, mut journal: Journal) -> Result<(), &'static str> {
    journal.validate()?;
    journal.phase = Phase::Prepared;
    let before = backend.snapshot()?;
    let mut after = before.clone();
    for group in &journal.groups {
        let fields = after.get_mut(&group.service).ok_or("service missing")?;
        if !matches(fields, &group.before) { return Err("snapshot changed"); }
        merge(fields, &group.applied);
    }
    store.publish(&journal)?;
    backend.commit_if_unchanged(&before, &after)?;
    journal.phase = Phase::Committed;
    store.update(&journal)?;
    backend.apply()?;
    journal.phase = Phase::Applied;
    store.update(&journal)?;
    if !backend.verify(&journal, false)? { return Err("activation not verified"); }
    Ok(())
}

/// Recovery ignores phase: interruption may have occurred before or after any write.
/// Foreign edits are retained and do not prevent recovery of independent safe groups.
fn recover(store: &mut impl JournalStore, backend: &mut impl Backend) -> Result<(), &'static str> {
    let journal = store.load()?.ok_or("journal missing")?;
    journal.validate()?;
    let current = backend.snapshot()?;
    let mut restored = current.clone();
    let mut conflict = false;
    for group in &journal.groups {
        let Some(fields) = restored.get_mut(&group.service) else { conflict = true; continue };
        if matches(fields, &group.before) { continue; }
        if matches(fields, &group.applied) { merge(fields, &group.before); }
        else { conflict = true; }
    }
    if restored != current { backend.commit_if_unchanged(&current, &restored)?; }
    // Even an already-restored persistent snapshot may still need to be applied.
    backend.apply()?;
    if conflict || !backend.verify(&journal, true)? { return Err("recovery requires attention"); }
    store.clear()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Default)]
    struct Disk { durable: Option<Journal>, fail: Option<(&'static str, bool)> }
    impl Disk {
        fn step(&mut self, name: &'static str, mutation: impl FnOnce(&mut Self)) -> Result<(), &'static str> {
            let fail = if self.fail.is_some_and(|(at, _)| at == name) { self.fail.take() } else { None };
            if fail.is_some_and(|(_, after)| !after) { return Err("injected disk error"); }
            mutation(self);
            if fail.is_some() { Err("injected disk error") } else { Ok(()) }
        }
    }
    impl JournalStore for Disk {
        fn load(&mut self) -> Result<Option<Journal>, &'static str> { Ok(self.durable.clone()) }
        fn publish(&mut self, journal: &Journal) -> Result<(), &'static str> {
            if self.durable.is_some() { return Err("journal exists"); }
            self.step("publish", |s| s.durable = Some(journal.clone()))
        }
        fn update(&mut self, journal: &Journal) -> Result<(), &'static str> {
            if self.durable.is_none() { return Err("journal missing"); }
            let name = if journal.phase == Phase::Committed { "committed" } else { "applied" };
            self.step(name, |s| s.durable = Some(journal.clone()))
        }
        fn clear(&mut self) -> Result<(), &'static str> { self.step("clear", |s| s.durable = None) }
    }

    struct Network { persistent: Snapshot, effective: Snapshot, fail: Option<(&'static str, bool)> }
    impl Network {
        fn step(&mut self, name: &'static str, mutation: impl FnOnce(&mut Self)) -> Result<(), &'static str> {
            let fail = if self.fail.is_some_and(|(at, _)| at == name) { self.fail.take() } else { None };
            if fail.is_some_and(|(_, after)| !after) { return Err("injected network error"); }
            mutation(self);
            if fail.is_some() { Err("injected network error") } else { Ok(()) }
        }
    }
    impl Backend for Network {
        fn snapshot(&mut self) -> Result<Snapshot, &'static str> { Ok(self.persistent.clone()) }
        fn commit_if_unchanged(&mut self, old: &Snapshot, new: &Snapshot) -> Result<(), &'static str> {
            if &self.persistent != old { return Err("concurrent edit"); }
            self.step("commit", |s| s.persistent = new.clone())
        }
        fn apply(&mut self) -> Result<(), &'static str> { self.step("apply", |s| s.effective = s.persistent.clone()) }
        fn verify(&mut self, journal: &Journal, restored: bool) -> Result<bool, &'static str> {
            self.step("verify", |_| {})?;
            Ok(journal.groups.iter().all(|g| {
                let wanted = if restored { &g.before } else { &g.applied };
                self.persistent.get(&g.service).is_some_and(|f| matches(f, wanted))
                    && self.effective.get(&g.service).is_some_and(|f| matches(f, wanted))
            }))
        }
    }

    fn setup() -> (Disk, Network, Journal, Snapshot) {
        let original = BTreeMap::from([("wifi".into(), BTreeMap::from([
            ("http".into(), json!("old")), ("https".into(), json!("old-secure")),
            ("other".into(), json!(1)),
        ]))]);
        let group = |name: &str, before: Value| Group {
            service: "wifi".into(),
            before: BTreeMap::from([(name.into(), Some(before))]),
            applied: BTreeMap::from([(name.into(), Some(json!("127.0.0.1:7890")))]),
        };
        let journal = Journal { version: 1, phase: Phase::Prepared, groups: vec![
            group("http", json!("old")), group("https", json!("old-secure")),
        ] };
        let network = Network { persistent: original.clone(), effective: original.clone(), fail: None };
        (Disk::default(), network, journal, original)
    }

    #[test]
    fn recovers_after_failures_before_and_after_each_activation_step() {
        for (where_, after) in [
            ("publish", false), ("publish", true), ("commit", false), ("commit", true),
            ("committed", false), ("committed", true), ("apply", false), ("apply", true),
            ("applied", false), ("applied", true), ("verify", false), ("verify", true),
        ] {
            let (mut disk, mut net, plan, original) = setup();
            if ["publish", "committed", "applied"].contains(&where_) { disk.fail = Some((where_, after)); }
            else { net.fail = Some((where_, after)); }
            assert!(activate(&mut disk, &mut net, plan).is_err(), "{where_}/{after}");
            if disk.durable.is_none() {
                assert_eq!(net.persistent, original, "no journal before writes: {where_}/{after}");
                assert_eq!(net.effective, original);
            } else {
                // A fresh engine uses only the durable journal and actual settings.
                recover(&mut disk, &mut net).unwrap();
                assert_eq!(net.persistent, original, "{where_}/{after}");
                assert_eq!(net.effective, original, "{where_}/{after}");
                assert!(disk.durable.is_none());
            }
        }
    }

    #[test]
    fn preserves_other_edits_and_restores_independent_groups() {
        let (mut disk, mut net, plan, _) = setup();
        activate(&mut disk, &mut net, plan).unwrap();
        net.persistent.get_mut("wifi").unwrap().insert("http".into(), json!("other-proxy"));
        net.persistent.get_mut("wifi").unwrap().insert("other".into(), json!(2));
        assert!(recover(&mut disk, &mut net).is_err());
        assert_eq!(net.persistent["wifi"]["http"], json!("other-proxy"));
        assert_eq!(net.persistent["wifi"]["https"], json!("old-secure"));
        assert_eq!(net.persistent["wifi"]["other"], json!(2));
        assert!(disk.durable.is_some(), "conflict retains recovery data");
    }

    #[test]
    fn recovery_failures_are_retryable_and_do_not_drop_the_journal() {
        for (where_, after) in [("commit", false), ("commit", true), ("apply", false), ("apply", true), ("verify", false)] {
            let (mut disk, mut net, plan, original) = setup();
            activate(&mut disk, &mut net, plan).unwrap();
            net.fail = Some((where_, after));
            assert!(recover(&mut disk, &mut net).is_err(), "{where_}/{after}");
            assert!(disk.durable.is_some());
            recover(&mut disk, &mut net).unwrap();
            assert_eq!(net.persistent, original);
            assert_eq!(net.effective, original);
        }
    }

    #[test]
    fn a_duplicate_journal_never_overwrites_recovery_data() {
        let (mut disk, mut net, plan, _) = setup();
        activate(&mut disk, &mut net, plan.clone()).unwrap();
        let saved = disk.durable.clone();
        assert!(disk.publish(&plan).is_err());
        assert_eq!(disk.durable, saved);
    }

    #[test]
    fn journal_removal_failure_cannot_leave_a_live_owned_proxy() {
        for after in [false, true] {
            let (mut disk, mut net, plan, original) = setup();
            activate(&mut disk, &mut net, plan).unwrap();
            disk.fail = Some(("clear", after));
            assert!(recover(&mut disk, &mut net).is_err());
            assert_eq!(net.persistent, original);
            assert_eq!(net.effective, original);
            if after {
                assert!(disk.durable.is_none(), "the removal may have succeeded despite an error");
            } else {
                assert!(disk.durable.is_some());
                recover(&mut disk, &mut net).unwrap();
            }
        }
    }

    #[test]
    fn malformed_or_overlapping_groups_never_change_the_network() {
        let (mut disk, mut net, mut plan, original) = setup();
        plan.groups.push(plan.groups[0].clone());
        assert!(activate(&mut disk, &mut net, plan).is_err());
        assert!(disk.durable.is_none());
        assert_eq!(net.persistent, original);
        assert_eq!(net.effective, original);
    }

    #[test]
    fn oversized_journal_is_rejected_before_publication() {
        let (mut disk, mut net, mut plan, original) = setup();
        plan.groups[0].service = "x".repeat(257);
        assert!(activate(&mut disk, &mut net, plan).is_err());
        assert!(disk.durable.is_none());
        assert_eq!(net.persistent, original);
        assert_eq!(net.effective, original);

        let (_, _, mut plan, _) = setup();
        plan.groups = vec![plan.groups[0].clone(); 1025];
        assert!(plan.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_journal_survives_reopen_and_never_replaces_existing_data() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("prism-journal-model-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (_, mut net, plan, original) = setup();
        let mut store = FileJournal::new(&dir).unwrap();
        activate(&mut store, &mut net, plan.clone()).unwrap();
        assert!(store.publish(&plan).is_err());
        drop(store);
        let mut reopened = FileJournal::new(&dir).unwrap();
        assert_eq!(reopened.load().unwrap().unwrap().phase, Phase::Applied);
        recover(&mut reopened, &mut net).unwrap();
        assert_eq!(net.persistent, original);
        assert_eq!(net.effective, original);
        assert!(reopened.load().unwrap().is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_is_exclusive_and_refuses_unsafe_or_corrupt_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("prism-journal-safety-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = FileJournal::new(&dir).unwrap();
        assert!(FileJournal::new(&dir).is_err(), "a second process must not operate concurrently");
        let (_, _, plan, _) = setup();
        store.publish(&plan).unwrap();
        let path = dir.join("proxy-journal.json");
        std::fs::hard_link(&path, dir.join("second-link")).unwrap();
        assert!(store.load().is_err(), "a multiply-linked journal is unsafe");
        std::fs::remove_file(dir.join("second-link")).unwrap();
        // Simulate process death after atomic publication but before temporary
        // link cleanup; recovery must keep and read the published journal.
        for _ in 0..2 {
            let temp = dir.join(format!(".journal-{}", uuid::Uuid::new_v4()));
            std::fs::hard_link(&path, &temp).unwrap();
            assert!(store.load().unwrap().is_some());
            assert!(!temp.exists());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load().is_err(), "an exposed journal is unsafe");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"not valid json").unwrap();
        assert!(store.load().is_err(), "corrupt recovery data must not be ignored");
        std::fs::remove_file(&path).unwrap();
        symlink(dir.join("missing"), &path).unwrap();
        assert!(store.load().is_err(), "a symlink must not be read as a journal");
        std::fs::remove_file(&path).unwrap();
        drop(store);
        assert!(FileJournal::new(&dir).is_ok(), "the lock is released when the holder exits");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_operations_remain_anchored_if_directory_path_is_replaced() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = std::env::temp_dir().join(format!("prism-journal-anchor-{}", uuid::Uuid::new_v4()));
        let dir = base.join("journal");
        let moved = base.join("moved");
        let decoy = base.join("decoy");
        std::fs::create_dir(&base).unwrap();
        for path in [&dir, &decoy] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut store = FileJournal::new(&dir).unwrap();
        std::fs::rename(&dir, &moved).unwrap();
        symlink(&decoy, &dir).unwrap();
        let (_, _, plan, _) = setup();
        store.publish(&plan).unwrap();
        assert!(moved.join("proxy-journal.json").is_file());
        assert!(!decoy.join("proxy-journal.json").exists());
        assert!(FileJournal::new(&dir).is_err(), "the journal directory itself cannot be a symlink");
        assert!(store.load().unwrap().is_some());
        drop(store);
        std::fs::remove_dir_all(base).unwrap();
    }
}
