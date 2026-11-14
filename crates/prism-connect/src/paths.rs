use std::{fs, path::PathBuf};

use crate::error::Result;

/// Data directory layout. `root` is supplied by the host app (Tauri app-data dir).
#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn core_dir(&self) -> PathBuf {
        self.root.join("core")
    }
    pub fn core_bin(&self) -> PathBuf {
        self.core_dir().join(if cfg!(windows) { "mihomo.exe" } else { "mihomo" })
    }
    /// The Xray helper core (`xray.exe`) lives apart from mihomo.
    pub fn xray_dir(&self) -> PathBuf {
        self.core_dir().join("xray")
    }
    pub fn xray_bin(&self) -> PathBuf {
        self.xray_dir().join(if cfg!(windows) { "xray.exe" } else { "xray" })
    }
    /// Config for the Xray process, generated like `runtime/config.yaml`.
    pub fn xray_config(&self) -> PathBuf {
        self.runtime_dir().join("xray.json")
    }
    /// mihomo home dir (`-d`): config, geodata, cache.db.
    /// Zapret's unpacked release (see `zapret`).
    pub fn zapret_dir(&self) -> PathBuf {
        self.root.join("zapret")
    }
    pub fn runtime_dir(&self) -> PathBuf {
        self.root.join("runtime")
    }
    pub fn runtime_config(&self) -> PathBuf {
        self.runtime_dir().join("config.yaml")
    }
    pub fn profiles_dir(&self) -> PathBuf {
        self.root.join("profiles")
    }
    pub fn profiles_index(&self) -> PathBuf {
        self.profiles_dir().join("index.json")
    }
    pub fn settings_file(&self) -> PathBuf {
        self.root.join("settings.json")
    }
    pub fn chains_file(&self) -> PathBuf {
        self.root.join("chains.json")
    }
    pub fn rules_file(&self) -> PathBuf {
        self.root.join("rules.json")
    }
    pub fn sysproxy_backup(&self) -> PathBuf {
        self.root.join("sysproxy_backup.json")
    }
    pub fn ensure(&self) -> Result<()> {
        for d in [
            self.root.clone(),
            self.core_dir(),
            self.runtime_dir(),
            self.profiles_dir(),
        ] {
            fs::create_dir_all(d)?;
        }
        Ok(())
    }
}
