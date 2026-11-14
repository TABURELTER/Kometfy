//! Open a link in the program Windows picks for it (browser, Telegram, Happ).
//! Only a few schemes are allowed: the text can come from a subscription provider.

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

use crate::error::{Error, Result};

const SCHEMES: &[&str] = &["http://", "https://", "tg://", "happ://"];

pub fn allowed(url: &str) -> bool {
    let lower = url.to_lowercase();
    SCHEMES.iter().any(|s| lower.starts_with(s))
        && url.len() <= 4096
        && !url.chars().any(|c| c.is_control() || c == ' ' || c == '"')
}

pub fn open_url(url: &str) -> Result<()> {
    let url = url.trim();
    if !allowed(url) {
        return Err(Error::msg("this kind of link cannot be opened from the app"));
    }
    open_allowed(url)
}

#[cfg(windows)]
fn open_allowed(url: &str) -> Result<()> {
    let wide = |s: &str| -> Vec<u16> { std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect() };
    let (verb, target) = (wide("open"), wide(url));
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if (r as isize) > 32 {
        Ok(())
    } else {
        Err(Error::msg("no program on this PC opens this link"))
    }
}

#[cfg(target_os = "macos")]
fn open_allowed(url: &str) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/open").arg(url).status()?;
    if status.success() { Ok(()) } else { Err(Error::msg("no program on this Mac opens this link")) }
}

/// Android: the host app opens links through the system (an intent), not this crate.
#[cfg(not(any(windows, target_os = "macos")))]
fn open_allowed(_url: &str) -> Result<()> {
    Err(Error::msg("links are opened by the host app on this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_few_schemes_pass() {
        assert!(allowed("https://t.me/support"));
        assert!(allowed("HAPP://crypt4/abc+/="));
        assert!(allowed("tg://resolve?domain=x"));
        for bad in ["file:///C:/a.exe", "ms-msdt:/id", "javascript:alert(1)", "https://a b", "https://a\nb", "cmd.exe", ""] {
            assert!(!allowed(bad), "{bad}");
        }
    }
}
