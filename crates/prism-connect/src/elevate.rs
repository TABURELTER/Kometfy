//! UAC elevation helpers (TUN needs administrator rights).

#[cfg(windows)]
mod platform {
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
    UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
};

use crate::error::{Error, Result};

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Start this executable again with the `runas` verb. Ok means the UAC prompt was accepted and
/// the new process started; the caller should then exit.
pub fn relaunch_elevated(args: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    let (verb, file, params) = (wide("runas"), wide(exe.as_os_str()), wide(args));
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            if args.is_empty() { std::ptr::null() } else { params.as_ptr() },
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if (r as isize) > 32 {
        Ok(())
    } else {
        Err(Error::msg("administrator permission was not granted"))
    }
}
}

#[cfg(target_os = "macos")]
mod platform {
    use crate::error::{Error, Result};

    pub fn is_elevated() -> bool { unsafe { libc::geteuid() == 0 } }

    pub fn relaunch_elevated(_: &str) -> Result<()> {
        Err(Error::msg("Administrator relaunch is not available on macOS"))
    }
}

/// Android and Linux have no administrator prompt (on Android the system asks for the VPN permission).
#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use crate::error::{Error, Result};

    pub fn is_elevated() -> bool {
        false
    }

    pub fn relaunch_elevated(_: &str) -> Result<()> {
        Err(Error::msg("Administrator relaunch is not available on this platform"))
    }
}

pub use platform::*;
