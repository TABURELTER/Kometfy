//! Read-only installer preflight. Verified bytes are owned snapshots; a path
//! must never be reopened later on the assumption it still contains them.
//! This module does not authorize, install, register, or update a helper.
//! A privileged installer must independently enforce its own trusted policy.
use sha2::{Digest, Sha256};

const MAX_HELPER_SIZE: u64 = 128 * 1024 * 1024;

pub(crate) struct VerifiedPayload {
    pub(crate) guard: Vec<u8>,
    pub(crate) bridge: Vec<u8>,
}

fn valid_pin(pin: &str) -> bool {
    pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit())
}

fn verify_bytes(bytes: &[u8], pin: &str) -> Result<(), &'static str> {
    if !valid_pin(pin) { return Err("missing or invalid helper build pin"); }
    if bytes.is_empty() || bytes.len() as u64 > MAX_HELPER_SIZE { return Err("invalid helper size"); }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(pin) { return Err("helper does not match the build pin"); }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn read_verified(path: &std::path::Path, pin: &str) -> Result<Vec<u8>, String> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::{MetadataExt, OpenOptionsExt}};
    if !valid_pin(pin) { return Err("missing or invalid helper build pin".into()); }
    // The final component cannot be a symlink. Ancestors may change, but that
    // cannot replace the opened file descriptor or its verified byte snapshot.
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path).map_err(|_| "cannot open bundled helper".to_string())?;
    let meta = file.metadata().map_err(|_| "cannot inspect bundled helper".to_string())?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() == 0 || meta.len() > MAX_HELPER_SIZE {
        return Err("invalid bundled helper".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_HELPER_SIZE + 1).read_to_end(&mut bytes).map_err(|_| "cannot read bundled helper".to_string())?;
    verify_bytes(&bytes, pin).map_err(str::to_owned)?;
    Ok(bytes)
}

#[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
impl VerifiedPayload {
    /// Build pins come from the executable, never from the frontend or disk.
    /// An absent pin is an error, not permission to use an unverified helper.
    pub(crate) fn read_bundled(guard: &std::path::Path, bridge: &std::path::Path) -> Result<Self, String> {
        let guard_pin = option_env!("PRISM_GUARD_SHA256").ok_or("guard build pin is not configured")?;
        let bridge_pin = option_env!("PRISM_BRIDGE_SHA256").ok_or("bridge build pin is not configured")?;
        Ok(Self { guard: read_verified(guard, guard_pin)?, bridge: read_verified(bridge, bridge_pin)? })
    }
}

#[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
pub(crate) fn preflight_current_bundle() -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|_| "cannot locate application".to_string())?;
    let parent = executable.parent().ok_or("cannot locate application directory")?;
    let payload = VerifiedPayload::read_bundled(&parent.join("prismroute-macos-proxy-guard"), &parent.join("prismroute-macos-proxy-bridge"))?;
    // These snapshots prove only what was read at this instant. They are not
    // authorization, an installation, or proof that installed files match.
    drop(payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    #[test]
    fn requires_an_exact_build_pin_and_complete_bytes() {
        assert!(verify_bytes(b"abc", ABC).is_ok());
        assert!(verify_bytes(b"abc", &ABC.to_uppercase()).is_ok());
        for (bytes, pin) in [(&b"abd"[..], ABC), (&b""[..], ABC), (&b"abc"[..], ""), (&b"abc"[..], "not-a-digest")] {
            assert!(verify_bytes(bytes, pin).is_err());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_symlinks_and_changed_files_but_keeps_verified_snapshot() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("prism-payload-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("helper");
        let link = dir.join("link");
        std::fs::write(&file, b"abc").unwrap();
        symlink(&file, &link).unwrap();
        assert!(read_verified(&link, ABC).is_err());
        let snapshot = read_verified(&file, ABC).unwrap();
        std::fs::write(&file, b"abd").unwrap();
        assert_eq!(snapshot, b"abc");
        assert!(read_verified(&file, ABC).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
