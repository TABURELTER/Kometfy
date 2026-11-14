//! User-side launcher for the fixed, build-pinned privileged installer.
//! The installer uses Authorization Services; no password is passed here.
use std::{ffi::CString, os::unix::ffi::OsStrExt};

pub(crate) fn install_from_bundle() -> Result<(), String> {
    crate::macos_helper_payload::preflight_current_bundle()?;
    let executable = std::env::current_exe().map_err(|_| "cannot locate application".to_string())?;
    let parent = executable.parent().ok_or("cannot locate application directory")?;
    let installer = parent.join("prismroute-macos-installer");
    let pin = option_env!("PRISM_INSTALLER_SHA256").ok_or("installer build pin is not configured")?;
    // The launcher always uses this fixed sibling, never a UI-supplied path.
    let _verified = crate::macos_helper_payload::read_verified(&installer, pin)?;
    let path = CString::new(installer.as_os_str().as_bytes()).map_err(|_| "invalid installer path")?;
    let expected = CString::new(pin).map_err(|_| "invalid installer pin")?;
    let mut output = [0i8; 4096];
    unsafe extern "C" { fn prism_macos_install_helper(path: *const libc::c_char, expected: *const libc::c_char, output: *mut libc::c_char, capacity: libc::c_int) -> libc::c_int; }
    let status = unsafe { prism_macos_install_helper(path.as_ptr(), expected.as_ptr(), output.as_mut_ptr(), output.len() as _) };
    match status {
        0 => Ok(()),
        -2 => Err("administrator authorization was denied".into()),
        -3 => Err("could not launch the privileged installer".into()),
        -5 => Err("temporary privileged installer could not be removed; inspect /Library/PrivilegedHelperTools/dev.prismroute.installer before retrying".into()),
        _ => {
            let text = unsafe { std::ffi::CStr::from_ptr(output.as_ptr()) }.to_string_lossy();
            let reason = text.trim().strip_prefix("PRISM_INSTALL_ERROR: ").unwrap_or("installer did not complete");
            Err(reason.to_owned())
        }
    }
}
