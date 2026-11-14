//! Find an existing mihomo core and its geodata on this machine, so first run needs no download.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    mihomo as core,
    error::{Error, Result},
    paths::Paths,
    util::write_atomic,
};

const GEO_FILES: &[&str] = &["geoip.dat", "geosite.dat", "Country.mmdb", "ASN.mmdb"];

#[derive(Debug, Clone, Serialize)]
pub struct CoreCandidate {
    pub path: String,
    pub label: String,
    pub version: Option<String>,
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

pub fn candidates(paths: &Paths) -> Vec<CoreCandidate> {
    let mut list: Vec<(PathBuf, &str)> = Vec::new();
    if let Some(pf) = env_dir("ProgramFiles") {
        list.push((pf.join("Clash Verge").join("verge-mihomo.exe"), "Clash Verge"));
        list.push((pf.join("Clash Verge").join("verge-mihomo-alpha.exe"), "Clash Verge (alpha)"));
    }
    if let Some(la) = env_dir("LOCALAPPDATA") {
        list.push((la.join("Programs").join("Clash Verge").join("verge-mihomo.exe"), "Clash Verge"));
    }
    list.push((paths.core_bin(), "Kometfy"));
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let names = if cfg!(windows) { ["mihomo.exe", "clash-meta.exe"] } else { ["mihomo", "clash-meta"] };
            for exe in names {
                list.push((dir.join(exe), "PATH"));
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    list.into_iter()
        .filter(|(p, _)| p.is_file())
        .filter(|(p, _)| seen.insert(fs::canonicalize(p).unwrap_or_else(|_| p.clone())))
        .map(|(p, label)| CoreCandidate {
            version: core::version(&p),
            path: p.display().to_string(),
            label: label.to_string(),
        })
        .collect()
}

fn geodata_dirs(bin: &Path, paths: &Paths) -> Vec<PathBuf> {
    let mut dirs = vec![paths.core_dir()];
    if let Some(parent) = bin.parent() {
        dirs.push(parent.to_path_buf());
        dirs.push(parent.join("resources"));
    }
    if let Some(pf) = env_dir("ProgramFiles") {
        dirs.push(pf.join("Clash Verge").join("resources"));
    }
    if let Some(la) = env_dir("LOCALAPPDATA") {
        dirs.push(la.join("Programs").join("Clash Verge").join("resources"));
    }
    dirs
}

/// Copy any missing geodata files into the runtime dir. Returns the names still missing.
pub fn ensure_geodata(bin: &Path, paths: &Paths) -> Vec<String> {
    let runtime = paths.runtime_dir();
    let _ = fs::create_dir_all(&runtime);
    let dirs = geodata_dirs(bin, paths);
    let mut missing = Vec::new();
    for name in GEO_FILES {
        let dst = runtime.join(name);
        if dst.is_file() {
            continue;
        }
        let found = dirs.iter().map(|d| d.join(name)).find(|p| p.is_file());
        match found {
            Some(src) if fs::copy(&src, &dst).is_ok() => {}
            _ => missing.push((*name).to_string()),
        }
    }
    missing
}

/// Copy a core executable into the app's own data dir (so Clash Verge updates can't break us).
pub fn install_core(paths: &Paths, from: &Path) -> Result<PathBuf> {
    if !from.is_file() {
        return Err(Error::msg("core file not found"));
    }
    let version = core::version(from).ok_or_else(|| Error::msg("that file does not look like mihomo"))?;
    tracing::info!("installing core {version} from {}", from.display());
    let dst = paths.core_bin();
    fs::create_dir_all(paths.core_dir())?;
    let tmp = dst.with_extension("exe.part");
    fs::copy(from, &tmp)?;
    write_marker(paths, &version)?;
    fs::rename(&tmp, &dst)?;
    ensure_geodata(&dst, paths);
    // geodata next to the source (e.g. Clash Verge's resources) also counts
    ensure_geodata(from, paths);
    Ok(dst)
}

fn write_marker(paths: &Paths, version: &str) -> Result<()> {
    write_atomic(&paths.core_dir().join("core-version.txt"), version.as_bytes())
}
