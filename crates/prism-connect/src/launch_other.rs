//! Windows scheduled tasks and registry autostart are unavailable on this platform.
use std::path::Path;
use crate::error::{Error, Result};

pub const VIA_TASK: &str = "--via-task";
pub fn is_protected_location(_: &Path) -> bool { false }
pub fn task_installed() -> bool { false }
pub fn task_installed_fresh() -> bool { false }
pub fn install_task() -> Result<()> { Err(Error::msg("Administrator-once setup is only available on Windows")) }
pub fn remove_task() -> Result<()> { Err(Error::msg("Administrator-once setup is only available on Windows")) }
pub fn run_task() -> Result<()> { Err(Error::msg("Administrator-once setup is only available on Windows")) }
pub fn stash_args(_: &Path, _: &[String]) {}
pub fn take_args(_: &Path) -> Vec<String> { Vec::new() }
pub fn autostart_enabled() -> bool { false }
pub fn set_autostart(_: bool) -> Result<()> { Err(Error::msg("Autostart is not yet available on this platform")) }
