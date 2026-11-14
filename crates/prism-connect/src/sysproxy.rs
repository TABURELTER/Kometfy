//! Windows system proxy (WinINET registry) with crash-safe backup/restore.

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use winreg::{
    enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD},
    RegKey, RegValue,
};

use crate::{error::Result, util::write_atomic};

const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub enable: Option<u32>,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub pac: Option<String>,
}

pub fn read() -> Snapshot {
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(KEY, KEY_READ) else {
        return Snapshot::default();
    };
    Snapshot {
        enable: key.get_value("ProxyEnable").ok(),
        server: key.get_value("ProxyServer").ok(),
        bypass: key.get_value("ProxyOverride").ok(),
        pac: key.get_value("AutoConfigURL").ok(),
    }
}

/// True when the registry currently points at `server`.
pub fn is_active_for(server: &str) -> bool {
    let s = read();
    s.enable == Some(1) && s.server.as_deref() == Some(server)
}

fn notify() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

fn set_dword(key: &RegKey, name: &str, v: Option<u32>) -> std::io::Result<()> {
    match v {
        Some(n) => key.set_raw_value(
            name,
            &RegValue {
                vtype: REG_DWORD,
                bytes: n.to_le_bytes().to_vec(),
            },
        ),
        None => ignore_missing(key.delete_value(name)),
    }
}

fn set_str(key: &RegKey, name: &str, v: &Option<String>) -> std::io::Result<()> {
    match v {
        Some(s) => key.set_value(name, s),
        None => ignore_missing(key.delete_value(name)),
    }
}

fn ignore_missing(r: std::io::Result<()>) -> std::io::Result<()> {
    match r {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn apply(snap: &Snapshot) -> Result<()> {
    let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE)?;
    set_dword(&key, "ProxyEnable", snap.enable)?;
    set_str(&key, "ProxyServer", &snap.server)?;
    set_str(&key, "ProxyOverride", &snap.bypass)?;
    set_str(&key, "AutoConfigURL", &snap.pac)?;
    notify();
    Ok(())
}

/// Point Windows at `server` (host:port). The original settings are saved once and restored by
/// [`disable`]; an active PAC script is suspended meanwhile, because it would win over a manual proxy.
pub fn enable(server: &str, bypass: &str, backup: &Path) -> Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var_os("PRISM_UI_PREVIEW_DIR").is_some() {
        return Err(crate::error::Error::msg("System proxy is disabled in the isolated UI preview"));
    }
    let cur = read();
    if !backup.exists() && !is_active_for(server) {
        write_atomic(backup, serde_json::to_string_pretty(&cur)?.as_bytes())?;
    }
    apply(&Snapshot {
        enable: Some(1),
        server: Some(server.to_string()),
        bypass: Some(bypass.to_string()),
        pac: None,
    })
}

/// Restore what was there before [`enable`]. Without a backup it only switches off a proxy that
/// points at `ours`, so a foreign proxy configuration is never touched.
pub fn disable(backup: &Path, ours: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var_os("PRISM_UI_PREVIEW_DIR").is_some() { return Ok(()); }
    if let Some(snap) = fs::read_to_string(backup)
        .ok()
        .and_then(|t| serde_json::from_str::<Snapshot>(&t).ok())
    {
        apply(&snap)?;
        let _ = fs::remove_file(backup);
        return Ok(());
    }
    if is_active_for(ours) {
        let cur = read();
        apply(&Snapshot {
            enable: Some(0),
            ..cur
        })?;
    }
    Ok(())
}

/// Called at startup: a leftover backup means the previous run died with the proxy still set.
pub fn recover(backup: &Path, ours: &str) {
    if backup.exists() {
        let _ = disable(backup, ours);
    }
}
