//! "Administrator rights once, then never again".
//!
//! TUN needs an elevated process, and Windows asks for UAC on every elevated start. The way around
//! it that Windows itself provides: a scheduled task that runs this program with the highest
//! privileges. Creating the task needs one UAC approval (the installer does it). After that any
//! normal launch asks the task scheduler to start the elevated copy, and no prompt appears.
//!
//! Safety: the task runs whatever file sits at the registered path, so it is only registered for a
//! program under `Program Files` (writable by administrators only). A portable copy in a folder the
//! user can write to would let any user program gain admin rights through the task.

use std::{
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::Engine;
use winreg::{enums::HKEY_CURRENT_USER, RegKey};

use crate::{
    error::{Error, Result},
    util::CREATE_NO_WINDOW,
};

pub const TASK_NAME: &str = crate::channel::NOW.task;
/// Passed by the task so a launch that came from it never delegates again (no loops).
pub const VIA_TASK: &str = "--via-task";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = crate::channel::NOW.task;

fn exe() -> Result<PathBuf> {
    Ok(std::env::current_exe()?)
}

/// True when `exe` lives under `%ProgramFiles%` or `%ProgramFiles(x86)%`.
pub fn is_protected_location(exe: &Path) -> bool {
    ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .iter()
        .filter_map(std::env::var_os)
        .any(|root| exe.starts_with(root))
}

/// PowerShell `-EncodedCommand` payload: base64 of the UTF-16LE script. Avoids every quoting problem.
fn ps_encode(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn powershell(script: &str) -> Result<()> {
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &ps_encode(script)])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        let text = String::from_utf8_lossy(&out.stderr);
        Err(Error::msg(format!("task scheduler: {}", text.lines().find(|l| !l.trim().is_empty()).unwrap_or("failed").trim())))
    }
}

fn schtasks(args: &[&str]) -> bool {
    Command::new("schtasks.exe")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn install_script(exe: &Path) -> String {
    let quoted = exe.display().to_string().replace('\'', "''");
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $exe = '{quoted}'\n\
         $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name\n\
         $action = New-ScheduledTaskAction -Execute $exe -Argument '{VIA_TASK}' -WorkingDirectory (Split-Path $exe)\n\
         $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest\n\
         $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel\n\
         Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $action -Principal $principal -Settings $settings -Description 'Starts PrismRoute with administrator rights without a UAC prompt' -Force | Out-Null\n"
    )
}

static CACHE: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

/// Is the elevated-start task registered? Cached for a few seconds: this is asked on every state refresh.
pub fn task_installed() -> bool {
    let mut c = CACHE.lock().unwrap();
    if let Some((at, v)) = *c {
        if at.elapsed() < Duration::from_secs(20) {
            return v;
        }
    }
    let v = schtasks(&["/query", "/tn", TASK_NAME]);
    *c = Some((Instant::now(), v));
    v
}

fn forget_cache() {
    *CACHE.lock().unwrap() = None;
}

/// Like `task_installed` but ignores the cache: another (elevated) process may just have changed it.
pub fn task_installed_fresh() -> bool {
    forget_cache();
    task_installed()
}

/// Register the task. Must run elevated (the installer, or `--install-tasks` after one UAC prompt).
pub fn install_task() -> Result<()> {
    let exe = exe()?;
    if !is_protected_location(&exe) && std::env::var_os("PRISM_ALLOW_UNPROTECTED_TASK").is_none() {
        return Err(Error::msg(
            "the program is not in Program Files: a task for a folder you can write to would let any program of yours gain admin rights",
        ));
    }
    powershell(&install_script(&exe))?;
    forget_cache();
    Ok(())
}

pub fn remove_task() -> Result<()> {
    let _ = set_autostart(false);
    let r = schtasks(&["/delete", "/tn", TASK_NAME, "/f"]);
    forget_cache();
    if r || !schtasks(&["/query", "/tn", TASK_NAME]) {
        Ok(())
    } else {
        Err(Error::msg("could not remove the scheduled task (administrator rights needed)"))
    }
}

/// Ask the task scheduler to start the elevated copy. The caller exits afterwards.
pub fn run_task() -> Result<()> {
    if schtasks(&["/run", "/tn", TASK_NAME]) {
        Ok(())
    } else {
        forget_cache();
        Err(Error::msg("could not start the elevated task"))
    }
}

// ---------------------------------------------------------------- hand-over of arguments

/// `schtasks /run` cannot pass arguments, so the intent (`--connect`, `--hidden`...) goes through a file.
pub fn stash_args(dir: &Path, args: &[String]) {
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join("launch.args"), args.join("\n"));
}

/// Read and delete what `stash_args` left. Ignored when older than ten minutes (a stale leftover): on a cold start
/// of Windows the task can start a minute or more after the Run entry, and a lost `--hidden` showed the window.
pub fn take_args(dir: &Path) -> Vec<String> {
    let f = dir.join("launch.args");
    let fresh = std::fs::metadata(&f)
        .and_then(|m| m.modified())
        .is_ok_and(|t| t.elapsed().is_ok_and(|e| e < Duration::from_secs(600)));
    let text = if fresh { std::fs::read_to_string(&f).unwrap_or_default() } else { String::new() };
    let _ = std::fs::remove_file(&f);
    text.lines().map(str::trim).filter(|l| l.starts_with("--")).map(String::from).collect()
}

// ---------------------------------------------------------------- start with Windows (no admin needed)

pub fn autostart_enabled() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(RUN_VALUE))
        .is_ok()
}

/// A per-user Run entry. The program started by it delegates to the task, so it still ends up elevated.
pub fn set_autostart(on: bool) -> Result<()> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY)?;
    if on {
        key.set_value(RUN_VALUE, &format!("\"{}\" --hidden", exe()?.display()))?;
    } else {
        let _ = key.delete_value(RUN_VALUE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_command_is_utf16le_base64() {
        // "A" -> 41 00 -> QQA=
        assert_eq!(ps_encode("A"), "QQA=");
    }

    #[test]
    fn script_escapes_quotes_in_the_path() {
        let s = install_script(Path::new(r"C:\Program Files\O'Neil\prismroute.exe"));
        assert!(s.contains(r"$exe = 'C:\Program Files\O''Neil\prismroute.exe'"));
        assert!(s.contains("-RunLevel Highest"));
    }

    #[test]
    fn only_program_files_is_protected() {
        std::env::set_var("ProgramFiles", r"C:\Program Files");
        assert!(is_protected_location(Path::new(r"C:\Program Files\PrismRoute\prismroute.exe")));
        assert!(!is_protected_location(Path::new(r"C:\Users\me\Downloads\prismroute.exe")));
        assert!(!is_protected_location(Path::new(r"C:\Program Files Evil\prismroute.exe")));
    }

    #[test]
    fn args_roundtrip_and_stale_files_are_ignored() {
        let dir = std::env::temp_dir().join(format!("prism-launch-{}", std::process::id()));
        stash_args(&dir, &["--connect".into(), "rm -rf".into(), "--hidden".into()]);
        assert_eq!(take_args(&dir), vec!["--connect", "--hidden"]);
        assert!(take_args(&dir).is_empty(), "consumed once");
        let _ = std::fs::remove_dir_all(dir);
    }
}
