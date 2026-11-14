//! Identity of this PC for subscription providers (the HWID device limit of Remnawave, Happ, v2RayTun).
//!
//! The provider gets a stable id for this installation of Windows and nothing else about the
//! machine but the OS version and the model name. The id is a hash with an app-specific salt, so the
//! Windows `MachineGuid` itself is never sent and the id cannot be matched against other programs'.

use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(windows)]
use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

const SALT: &str = "prismroute-hwid-v1:";

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    /// 32 hex characters (providers accept `[a-zA-Z0-9=-]{10,64}`).
    pub hwid: String,
    pub os: &'static str,
    /// `10.0.26300`
    pub os_version: String,
    /// Maker and product name from the BIOS, `ASUS TUF Gaming A15`. Empty when unknown.
    pub model: String,
}

#[cfg(windows)]
fn reg_string(path: &str, name: &str) -> Option<String> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(path)
        .ok()?
        .get_value::<String, _>(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(windows)]
fn reg_dword(path: &str, name: &str) -> Option<u32> {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(path).ok()?.get_value::<u32, _>(name).ok()
}

/// Stable id for one seed string; the seed is the Windows machine GUID.
pub fn derive_hwid(seed: &str) -> String {
    let digest = Sha256::digest(format!("{SALT}{}", seed.trim().to_lowercase()).as_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// Header values must be plain visible ASCII.
#[cfg_attr(not(any(windows, target_os = "macos", target_os = "android", test)), allow(dead_code))]
fn header_safe(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(windows)]
fn machine_seed() -> String {
    reg_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
        // a Windows without the value is very rare; the computer name is stable enough then
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown-machine".into())
}

pub fn hwid() -> String {
    derive_hwid(&machine_seed())
}

#[cfg(windows)]
pub fn info() -> Device {
    let nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let major = reg_dword(nt, "CurrentMajorVersionNumber").unwrap_or(10);
    let minor = reg_dword(nt, "CurrentMinorVersionNumber").unwrap_or(0);
    let build = reg_string(nt, "CurrentBuildNumber").unwrap_or_else(|| "0".into());
    let bios = r"HARDWARE\DESCRIPTION\System\BIOS";
    let maker = reg_string(bios, "SystemManufacturer").unwrap_or_default();
    let product = reg_string(bios, "SystemProductName").unwrap_or_default();
    // "System manufacturer / System Product Name" is what boards without a vendor profile report
    let junk = |s: &str| s.is_empty() || s.eq_ignore_ascii_case("system manufacturer") || s.eq_ignore_ascii_case("system product name") || s.eq_ignore_ascii_case("to be filled by o.e.m.");
    let model = [maker, product]
        .into_iter()
        .filter(|p| !junk(p))
        .collect::<Vec<_>>()
        .join(" ");
    Device {
        hwid: hwid(),
        os: "Windows",
        os_version: format!("{major}.{minor}.{build}"),
        model: header_safe(&model, 64),
    }
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    if !output.status.success() { return None; }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(target_os = "macos")]
fn machine_seed() -> String {
    use std::sync::OnceLock;
    static SEED: OnceLock<String> = OnceLock::new();
    SEED.get_or_init(|| {
        command_output("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])
            .and_then(|s| s.lines().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                if key.trim() != "\"IOPlatformUUID\"" { return None; }
                let value = value.trim().trim_matches('"');
                (!value.is_empty()).then(|| value.to_owned())
            }))
            .or_else(|| command_output("/usr/sbin/scutil", &["--get", "LocalHostName"]))
            .unwrap_or_else(|| "unknown-machine".into())
    }).clone()
}

#[cfg(target_os = "macos")]
pub fn info() -> Device {
    Device {
        hwid: hwid(),
        os: "macOS",
        os_version: command_output("/usr/bin/sw_vers", &["-productVersion"]).unwrap_or_default(),
        model: header_safe(&command_output("/usr/sbin/sysctl", &["-n", "hw.model"]).unwrap_or_default(), 64),
    }
}

/// What the Android app knows and this crate cannot read: the system's id for this app on this device
/// (`Settings.Secure.ANDROID_ID`), the Android version and the maker and model.
#[cfg(target_os = "android")]
static ANDROID: std::sync::OnceLock<(String, String, String)> = std::sync::OnceLock::new();

/// Called once by the Android app at start, before any subscription is fetched. Without it every
/// Android device would send the same id.
#[cfg(target_os = "android")]
pub fn set_android(id: &str, os_version: &str, model: &str) {
    let _ = ANDROID.set((id.trim().to_string(), header_safe(os_version, 32), header_safe(model, 64)));
}

#[cfg(target_os = "android")]
fn machine_seed() -> String {
    ANDROID
        .get()
        .map(|(id, _, _)| id.clone())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "unknown-machine".into())
}

#[cfg(target_os = "android")]
pub fn info() -> Device {
    let (_, os_version, model) = ANDROID.get().cloned().unwrap_or_default();
    Device { hwid: hwid(), os: "Android", os_version, model }
}

/// Linux reads `machine-id`.
#[cfg(not(any(windows, target_os = "macos", target_os = "android")))]
fn machine_seed() -> String {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-machine".into())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "android")))]
pub fn info() -> Device {
    Device { hwid: hwid(), os: "Linux", os_version: String::new(), model: String::new() }
}

/// The languages and the region of the person at this PC, as Windows keeps them for the user: the
/// interface languages, the regional format, the home location (`region:XX`) and the keyboard
/// layouts. The UI reads it to tell who it talks to; nothing of it leaves the computer.
#[cfg(windows)]
pub fn system_langs() -> Vec<String> {
    use winreg::{enums::HKEY_CURRENT_USER, types::FromRegValue};
    let cu = RegKey::predef(HKEY_CURRENT_USER);
    let mut out: Vec<String> = Vec::new();
    if let Ok(v) = cu.open_subkey(r"Control Panel\International\User Profile").and_then(|k| k.get_value::<Vec<String>, _>("Languages")) {
        out.extend(v);
    }
    if let Ok(v) = cu.open_subkey(r"Control Panel\International").and_then(|k| k.get_value::<String, _>("LocaleName")) {
        out.push(v);
    }
    if let Ok(v) = cu.open_subkey(r"Control Panel\International\Geo").and_then(|k| k.get_value::<String, _>("Name")) {
        out.push(format!("region:{v}"));
    }
    // keyboard layouts are ids like 00000419: the last four digits name the language
    if let Ok(k) = cu.open_subkey(r"Keyboard Layout\Preload") {
        for (_, v) in k.enum_values().flatten() {
            let id = String::from_reg_value(&v).unwrap_or_default().to_ascii_lowercase();
            let lang = match id.get(id.len().saturating_sub(4)..) {
                Some("0419") => "ru",
                Some("0422") => "uk",
                Some("0423") => "be",
                Some("043f") => "kk",
                _ => continue,
            };
            out.push(lang.to_string());
        }
    }
    out
}

#[cfg(not(windows))]
pub fn system_langs() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_stable_and_provider_safe() {
        let a = derive_hwid("AAAA-BBBB");
        assert_eq!(a, derive_hwid(" aaaa-bbbb "));
        assert_ne!(a, derive_hwid("aaaa-cccc"));
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!a.contains("aaaa"));
    }

    #[test]
    fn model_is_header_safe() {
        assert_eq!(header_safe("ASUS TUF™ A15\r\n", 64), "ASUS TUF? A15??");
        assert_eq!(header_safe("abcdef", 3), "abc");
    }

    #[test]
    fn this_pc_has_an_id() {
        let d = info();
        assert_eq!(d.hwid.len(), 32);
        #[cfg(windows)]
        assert!(d.os_version.starts_with("10."));
    }
}
