//! "Reset all settings": the way out when the configs are broken and Kometfy will not connect, or will not start.
//!
//! A reset is asked for, then done at the next start before anything reads the files (`--reset-settings` asks for
//! it too): doing it while the app runs would race with the writes the app makes on its way out. It deletes the
//! settings, subscriptions, chains and cached remote settings, and keeps what is slow or useful to get back: the
//! downloaded core, the logs and the local statistics.

use std::{fs, io, path::Path};

/// A file in the data folder: its presence means "reset at the next start".
pub const MARKER: &str = "reset-requested";

/// Kept by a reset: the downloaded core (names it by folder), the logs (`app.log`, `app.log.1`...), the local
/// statistics, the dev API's address and the single-instance lock of a running copy.
fn kept(name: &str) -> bool {
    name == "core" || name.starts_with("app.log") || matches!(name, "metrics.json" | "dev-api.json" | "instance.lock")
}

pub fn request(root: &Path) -> io::Result<()> {
    fs::create_dir_all(root)?;
    fs::write(root.join(MARKER), b"1")
}

/// Deletes everything in `root` a reset does not keep. Returns the names it removed.
pub fn wipe(root: &Path) -> io::Result<Vec<String>> {
    let mut removed = Vec::new();
    let Ok(entries) = fs::read_dir(root) else { return Ok(removed) };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if kept(&name) || name == MARKER {
            continue;
        }
        let path = e.path();
        let done = if path.is_dir() { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
        match done {
            Ok(()) => removed.push(name),
            Err(err) => tracing::warn!("reset: could not remove {name}: {err}"),
        }
    }
    // the marker goes last: a reset cut short by a crash is done again at the next start
    let _ = fs::remove_file(root.join(MARKER));
    Ok(removed)
}

/// At the start, before the manager reads anything: does what was asked. True when a reset was done.
pub fn apply_if_requested(root: &Path) -> bool {
    if !root.join(MARKER).exists() {
        return false;
    }
    let removed = wipe(root).unwrap_or_default();
    #[cfg(windows)]
    let _ = crate::launch::set_autostart(false);
    tracing::info!("reset: all settings were reset ({} entries removed)", removed.len());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kometfy-reset-{tag}-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_reset_removes_the_settings_and_keeps_the_core_and_the_logs() {
        let d = dir("keep");
        for f in ["settings.json", "chains.json", "remote.json", "session.lock", "link-auth.json", "app.log", "app.log.1", "metrics.json"] {
            fs::write(d.join(f), "x").unwrap();
        }
        for sub in ["core", "profiles", "runtime"] {
            fs::create_dir_all(d.join(sub)).unwrap();
            fs::write(d.join(sub).join("f"), "x").unwrap();
        }
        request(&d).unwrap();
        assert!(apply_if_requested(&d));
        let mut left: Vec<String> = fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["app.log", "app.log.1", "core", "metrics.json"]);
        assert!(d.join("core").join("f").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_is_removed_without_a_request() {
        let d = dir("none");
        fs::write(d.join("settings.json"), "x").unwrap();
        assert!(!apply_if_requested(&d));
        assert!(d.join("settings.json").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_folder_is_not_an_error() {
        let d = std::env::temp_dir().join("kometfy-reset-missing-folder");
        assert!(wipe(&d).unwrap().is_empty());
        assert!(!apply_if_requested(&d));
    }
}
