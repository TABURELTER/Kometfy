//! Download the mihomo core from its official GitHub release, verify it and install it.
//! Only ever started by the user (a button in the app); nothing is fetched in the background.

use std::{io::Read, path::PathBuf, time::Duration};

use futures_util::StreamExt;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    mihomo,
    paths::Paths,
    util::write_atomic,
    xray,
};

const API: &str = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest";
const XRAY_API: &str = "https://api.github.com/repos/XTLS/Xray-core/releases/latest";
/// The one Windows build the app installs for Xray (x64).
#[cfg(windows)]
const XRAY_ASSET: &str = "Xray-windows-64.zip";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const XRAY_ASSET: &str = "Xray-macos-arm64-v8a.zip";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const XRAY_ASSET: &str = "Xray-macos-64.zip";
#[cfg(not(any(windows, target_os = "macos")))]
const XRAY_ASSET: &str = "unsupported";

/// The two cores the app can download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Mihomo,
    Xray,
}
const GEO_BASE: &str = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest";
const MAX_CORE_BYTES: u64 = 120 * 1024 * 1024;
const MAX_APP_BYTES: u64 = 300 * 1024 * 1024;
const MAX_GEO_BYTES: u64 = 80 * 1024 * 1024;
const UA: &str = concat!("Kometfy/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub url: String,
    pub size: u64,
    /// Lowercase hex SHA-256 as published by GitHub for the asset.
    pub sha256: Option<String>,
}

/// `mihomo-windows-amd64-v1.19.33.zip`, but not the `-compatible`, `-go120` or `-v3-` builds.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn is_plain_amd64(name: &str) -> bool {
    let Some(ver) = name
        .strip_prefix("mihomo-windows-amd64-v")
        .and_then(|r| r.strip_suffix(".zip"))
    else {
        return false;
    };
    ver.chars().next().is_some_and(|c| c.is_ascii_digit()) && ver.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Pick the right Windows asset out of the GitHub "latest release" JSON.
pub fn pick_asset(release: &Value) -> Option<Release> {
    #[cfg(windows)]
    return pick(release, is_plain_amd64);
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return pick(release, |n| is_plain_macos(n, "arm64"));
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return pick(release, |n| is_plain_macos(n, "amd64"));
    #[allow(unreachable_code)]
    {
        let _ = release;
        None
    }
}

#[cfg(any(test, target_os = "macos"))]
fn is_plain_macos(name: &str, arch: &str) -> bool {
    let prefix = format!("mihomo-darwin-{arch}-v");
    name.strip_prefix(&prefix).and_then(|s| s.strip_suffix(".gz"))
        .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// Same for Xray: `Xray-windows-64.zip`, not the 32-bit, ARM or `.dgst` files.
pub fn pick_xray_asset(release: &Value) -> Option<Release> {
    pick(release, |n| n == XRAY_ASSET)
}

fn pick(release: &Value, wanted: impl Fn(&str) -> bool) -> Option<Release> {
    let tag = release.get("tag_name")?.as_str()?.to_string();
    let asset = release
        .get("assets")?
        .as_array()?
        .iter()
        .find(|a| a.get("name").and_then(Value::as_str).is_some_and(&wanted))?;
    Some(Release {
        tag,
        url: asset.get("browser_download_url")?.as_str()?.to_string(),
        size: asset.get("size").and_then(Value::as_u64).unwrap_or(0),
        sha256: asset
            .get("digest")
            .and_then(Value::as_str)
            .and_then(|d| d.strip_prefix("sha256:"))
            .map(str::to_lowercase),
    })
}

/// A client for GitHub: our user agent (GitHub refuses requests without one), direct or through `proxy`.
pub(crate) fn client(proxy: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(UA)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300));
    b = match proxy {
        Some(p) => b.proxy(reqwest::Proxy::all(p)?),
        None => b.no_proxy(),
    };
    Ok(b.build()?)
}

pub async fn latest(proxy: Option<&str>) -> Result<Release> {
    latest_of(Kind::Mihomo, proxy).await
}

pub async fn latest_of(kind: Kind, proxy: Option<&str>) -> Result<Release> {
    let (api, name) = match kind {
        Kind::Mihomo => (API, "mihomo"),
        Kind::Xray => (XRAY_API, "Xray"),
    };
    let resp = client(proxy)?
        .get(api)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(Error::msg(format!("GitHub answered {}", resp.status())));
    }
    let json: Value = resp.json().await?;
    let found = match kind {
        Kind::Mihomo => pick_asset(&json),
        Kind::Xray => pick_xray_asset(&json),
    };
    found.ok_or_else(|| Error::msg(format!("the latest {name} release has no build for this platform")))
}

/// A release of the app itself, as the Tauri updater's `latest.json` announces it.
#[derive(Debug, Clone, Serialize)]
pub struct AppRelease {
    pub version: String,
    pub notes: String,
    /// The installers by platform key (`windows-x86_64`, `macos-dmg`, `android-apk`): the address and the minisign
    /// signature, which the app checks against its updater key before it opens the file.
    #[serde(skip)]
    pub files: std::collections::BTreeMap<String, (String, String)>,
}

/// Reads a `latest.json` (`{"version": "0.2.6", "notes": "…", "platforms": {…}}`).
pub async fn app_release(url: &str, proxy: Option<&str>) -> Result<AppRelease> {
    let resp = client(proxy)?.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(Error::msg(format!("{url} answered {}", resp.status())));
    }
    parse_app_release(&resp.json().await?)
}

fn parse_app_release(json: &Value) -> Result<AppRelease> {
    let version = json["version"].as_str().unwrap_or_default().trim().trim_start_matches('v').to_string();
    if version.is_empty() {
        return Err(Error::msg("latest.json has no version"));
    }
    let files = json["platforms"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k.clone(), (v["url"].as_str()?.to_string(), v["signature"].as_str()?.to_string()))))
        .collect();
    Ok(AppRelease { version, notes: json["notes"].as_str().unwrap_or_default().trim().to_string(), files })
}

/// An installer of the app (a DMG, an APK); the caller checks its signature.
pub async fn download_app(url: &str, proxy: Option<&str>, progress: &(dyn Fn(u64, u64) + Send + Sync)) -> Result<Vec<u8>> {
    fetch(url, proxy, MAX_APP_BYTES, progress).await
}

/// `v1.19.34` is newer than `v1.19.33`. A version that is not a plain number list (an alpha
/// build) is never reported as outdated: whoever runs it chose it.
pub fn is_newer(installed: &str, latest: &str) -> bool {
    fn nums(v: &str) -> Option<Vec<u32>> {
        v.trim().trim_start_matches('v').split('.').map(|p| p.parse().ok()).collect()
    }
    match (nums(installed), nums(latest)) {
        (Some(a), Some(b)) => b > a,
        _ => false,
    }
}

async fn fetch(url: &str, proxy: Option<&str>, limit: u64, progress: &(dyn Fn(u64, u64) + Send + Sync)) -> Result<Vec<u8>> {
    let resp = client(proxy)?.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(Error::msg(format!("download failed: {}", resp.status())));
    }
    let total = resp.content_length().unwrap_or(0);
    if total > limit {
        return Err(Error::msg("the file is larger than expected, refusing to download it"));
    }
    let mut out = Vec::with_capacity(total as usize);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
        if out.len() as u64 > limit {
            return Err(Error::msg("the file is larger than expected, refusing to download it"));
        }
        progress(out.len() as u64, total);
    }
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Download the release zip and check it against the digest GitHub publishes.
pub async fn download(rel: &Release, proxy: Option<&str>, progress: impl Fn(u64, u64) + Send + Sync) -> Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    if rel.sha256.is_none() {
        return Err(Error::msg("the release has no published SHA-256 checksum; refusing to install"));
    }
    let bytes = fetch(&rel.url, proxy, MAX_CORE_BYTES, &progress).await?;
    if let Some(want) = &rel.sha256 {
        let got = sha256_hex(&bytes);
        if &got != want {
            return Err(Error::msg("the downloaded core does not match its published checksum, nothing was installed"));
        }
    }
    Ok(bytes)
}

/// The single `.exe` inside the release zip.
pub fn extract_exe(zip_bytes: &[u8]) -> Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    if zip_bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = flate2::read::GzDecoder::new(zip_bytes).take(MAX_CORE_BYTES * 2 + 1);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_CORE_BYTES * 2 { return Err(Error::msg("expanded core is too large")); }
        return Ok(buf);
    }
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).map_err(|e| Error::msg(format!("bad zip: {e}")))?;
    for i in 0..archive.len() {
        let f = archive.by_index(i).map_err(|e| Error::msg(format!("bad zip: {e}")))?;
        let name = f.name().to_lowercase();
        let wanted = if cfg!(windows) { name.ends_with(".exe") } else { name == "xray" };
        if wanted && f.size() < MAX_CORE_BYTES * 2 {
            let mut buf = Vec::with_capacity(f.size() as usize);
            f.take(MAX_CORE_BYTES * 2 + 1).read_to_end(&mut buf)?;
            if buf.len() as u64 > MAX_CORE_BYTES * 2 { return Err(Error::msg("expanded core is too large")); }
            return Ok(buf);
        }
    }
    Err(Error::msg("the archive does not contain the expected executable"))
}

fn valid_executable(exe: &[u8]) -> bool {
    if exe.len() < 1024 * 1024 { return false; }
    #[cfg(windows)]
    return exe.starts_with(b"MZ");
    #[cfg(target_os = "macos")]
    return exe.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]);
    #[allow(unreachable_code)]
    false
}

fn make_executable(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Put the executable in the app's core folder, but only if it really is mihomo.
pub fn install(paths: &Paths, exe: &[u8]) -> Result<PathBuf> {
    if !valid_executable(exe) {
        return Err(Error::msg("the downloaded file is not a valid platform executable"));
    }
    std::fs::create_dir_all(paths.core_dir())?;
    let part = paths.core_dir().join("mihomo.exe.part");
    std::fs::write(&part, exe)?;
    make_executable(&part)?;
    let Some(version) = mihomo::version(&part) else {
        let _ = std::fs::remove_file(&part);
        return Err(Error::msg("the downloaded file does not look like mihomo, nothing was installed"));
    };
    let dst = paths.core_bin();
    std::fs::rename(&part, &dst)?;
    write_atomic(&paths.core_dir().join("core-version.txt"), version.as_bytes())?;
    Ok(dst)
}

/// Put `xray.exe` in the app's own folder, but only if it really is Xray.
pub fn install_xray(paths: &Paths, exe: &[u8]) -> Result<PathBuf> {
    if !valid_executable(exe) {
        return Err(Error::msg("the downloaded file is not a valid platform executable"));
    }
    std::fs::create_dir_all(paths.xray_dir())?;
    let dst = paths.xray_bin();
    let part = dst.with_extension("exe.part");
    std::fs::write(&part, exe)?;
    make_executable(&part)?;
    let Some(version) = xray::version(&part) else {
        let _ = std::fs::remove_file(&part);
        return Err(Error::msg("the downloaded file does not look like Xray, nothing was installed"));
    };
    std::fs::rename(&part, &dst)?;
    write_atomic(&paths.xray_dir().join("core-version.txt"), version.as_bytes())?;
    Ok(dst)
}

/// Best effort: the geo databases mihomo wants next to its config. Returns the names that failed.
pub async fn download_geodata(paths: &Paths, proxy: Option<&str>) -> Vec<String> {
    let mut failed = Vec::new();
    for (remote, local) in [("geoip.dat", "geoip.dat"), ("geosite.dat", "geosite.dat"), ("country.mmdb", "Country.mmdb")] {
        let dst = paths.runtime_dir().join(local);
        if dst.is_file() {
            continue;
        }
        let ok = match fetch(&format!("{GEO_BASE}/{remote}"), proxy, MAX_GEO_BYTES, &|_, _| {}).await {
            Ok(b) if b.len() > 1024 => write_atomic(&dst, &b).is_ok(),
            _ => false,
        };
        if !ok {
            failed.push(local.to_string());
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    #[test]
    fn latest_json_gives_the_version_and_the_signed_installers() {
        let j = serde_json::json!({
            "version": "v0.2.6", "notes": " New window ",
            "platforms": {
                "windows-x86_64": {"signature": "c2ln", "url": "https://x/setup.exe"},
                "android-apk": {"signature": "YXBr", "url": "https://x/app.apk"},
                "broken": {"url": "https://x/no-signature"}
            }
        });
        let r = super::parse_app_release(&j).unwrap();
        assert_eq!((r.version.as_str(), r.notes.as_str()), ("0.2.6", "New window"));
        assert_eq!(r.files["android-apk"], ("https://x/app.apk".to_string(), "YXBr".to_string()));
        assert!(r.files.contains_key("windows-x86_64") && !r.files.contains_key("broken"));
        assert!(super::parse_app_release(&serde_json::json!({"notes": "x"})).is_err());
    }

    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[cfg(windows)]
    #[test]
    fn picks_the_plain_windows_build() {
        let rel = json!({
            "tag_name": "v1.19.33",
            "assets": [
                {"name": "mihomo-linux-amd64-v1.19.33.gz", "browser_download_url": "https://x/linux", "size": 1},
                {"name": "mihomo-windows-amd64-compatible-v1.19.33.zip", "browser_download_url": "https://x/compat", "size": 2},
                {"name": "mihomo-windows-amd64-v3-v1.19.33.zip", "browser_download_url": "https://x/v3", "size": 3},
                {"name": "mihomo-windows-amd64-go120-v1.19.33.zip", "browser_download_url": "https://x/go120", "size": 4},
                {"name": "mihomo-windows-amd64-v1.19.33.zip", "browser_download_url": "https://x/ok", "size": 13_000_000, "digest": "sha256:ABCDEF"},
            ]
        });
        let r = pick_asset(&rel).unwrap();
        assert_eq!(r.tag, "v1.19.33");
        assert_eq!(r.url, "https://x/ok");
        assert_eq!(r.sha256.as_deref(), Some("abcdef"));
        assert!(pick_asset(&json!({"tag_name": "v1", "assets": []})).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn picks_the_xray_windows_x64_zip() {
        let rel = json!({
            "tag_name": "v26.10.31",
            "assets": [
                {"name": "Xray-windows-32.zip", "browser_download_url": "https://x/32", "size": 1},
                {"name": "Xray-windows-64.zip.dgst", "browser_download_url": "https://x/dgst", "size": 299},
                {"name": "Xray-windows-arm64-v8a.zip", "browser_download_url": "https://x/arm", "size": 2},
                {"name": "Xray-windows-64.zip", "browser_download_url": "https://x/64", "size": 16_623_726,
                 "digest": "sha256:2E04A9995A6F2AD1B28C0BB25C708ECB2695E43A1C9C7889C4B6AC2B48CF7A6A"},
            ]
        });
        let r = pick_xray_asset(&rel).unwrap();
        assert_eq!((r.tag.as_str(), r.url.as_str()), ("v26.10.31", "https://x/64"));
        assert_eq!(r.sha256.as_deref(), Some("2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a"));
        assert!(pick_asset(&rel).is_none(), "an Xray release has no mihomo build");
    }

    #[test]
    fn newer_means_a_bigger_number() {
        assert!(is_newer("v1.19.33", "v1.19.34"));
        assert!(is_newer("v26.9.30", "v26.10.31"));
        assert!(!is_newer("v26.10.31", "v26.10.31"));
        assert!(!is_newer("v1.20.0", "v1.19.99"));
        assert!(!is_newer("alpha-abc123", "v1.19.34"), "an alpha build is the user's choice");
    }

    #[test]
    fn a_program_that_is_not_xray_is_never_installed() {
        let dir = std::env::temp_dir().join(format!("prism-coredl-xray-{}", std::process::id()));
        let paths = Paths::new(dir.clone());
        paths.ensure().unwrap();
        assert!(install_xray(&paths, b"MZ tiny").is_err());
        let mut big = vec![0u8; 2 * 1024 * 1024];
        big[0] = b'M';
        big[1] = b'Z';
        assert!(install_xray(&paths, &big).is_err());
        assert!(!paths.xray_bin().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn extracts_the_exe_from_a_zip() {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default();
            z.start_file("README.txt", opts).unwrap();
            z.write_all(b"hi").unwrap();
            z.start_file("mihomo-windows-amd64.exe", opts).unwrap();
            z.write_all(b"MZ-fake-binary").unwrap();
            z.finish().unwrap();
        }
        assert_eq!(extract_exe(buf.get_ref()).unwrap(), b"MZ-fake-binary");
        assert!(extract_exe(b"not a zip").is_err());
    }

    #[test]
    fn junk_is_never_installed() {
        let dir = std::env::temp_dir().join(format!("prism-coredl-{}", std::process::id()));
        let paths = Paths::new(dir.clone());
        paths.ensure().unwrap();
        assert!(install(&paths, b"MZ tiny").is_err());
        let mut big = vec![0u8; 2 * 1024 * 1024];
        big[0] = b'M';
        big[1] = b'Z';
        assert!(install(&paths, &big).is_err(), "a program that is not mihomo must be rejected");
        assert!(!paths.core_bin().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn matches_only_plain_macos_assets() {
        assert!(is_plain_macos("mihomo-darwin-arm64-v1.19.33.gz", "arm64"));
        assert!(is_plain_macos("mihomo-darwin-amd64-v1.19.33.gz", "amd64"));
        assert!(!is_plain_macos("mihomo-darwin-arm64-go124-v1.19.33.gz", "arm64"));
        assert!(!is_plain_macos("mihomo-darwin-amd64-v3-v1.19.33.gz", "amd64"));
    }
}
