//! Fail closed until a platform-specific proxy implementation can restore all prior settings.
use std::path::Path;
use crate::error::{Error, Result};

pub fn is_active_for(_: &str) -> bool { false }
pub fn enable(_: &str, _: &str, _: &Path) -> Result<()> {
    Err(Error::msg("System proxy is not yet supported on this platform"))
}
pub fn disable(backup: &Path, _: &str) -> Result<()> {
    // This preview cannot safely interpret or restore a macOS proxy backup.
    // Never report success if a future or interrupted build has left one behind.
    match std::fs::symlink_metadata(backup) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(Error::msg("System proxy recovery is unavailable in this preview; the backup has been retained")),
    }
}
pub fn recover(_: &Path, _: &str) {}
