//! Orchestration: settings, profiles, chains, the core process and traffic capture.

use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::{
    chain::{self, Chain, ChainStore, CHAINS_GROUP},
    config::{self, BuildInfo, NodeInfo, RuleIssue},
    controller::{self, Controller},
    coredl::{self, Kind},
    device, diagnostics,
    discover::{self, CoreCandidate},
    dpi::Dpi,
    elevate,
    error::{Error, Result},
    happ,
    lan::{self, Lan},
    launch, logfile,
    metrics::{self, Metrics, Sampler, Stage},
    mihomo::{self, Core, LineSink},
    opener,
    paths::Paths,
    profiles::{new_id, ProfileMeta, ProfileStore},
    rules::{RuleStore, UserRule},
    settings::{Bypass, Method, Settings, XrayMode},
    subscription, sysproxy,
    xray,
    xray_conf::{self, XrayRun},
};
#[cfg(windows)]
use crate::util::CREATE_NO_WINDOW;

/// Host callback used to push events (`state`, `traffic`, `core-logs`) to the UI.
pub type Emitter = Arc<dyn Fn(&str, Value) + Send + Sync>;

const LOG_RING: usize = 500;
/// How many bypass strategies the search tries at once where the engine is a proxy (Android, macOS).
const SIDE_BY_SIDE: usize = 4;
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
const CONFLICT_PROCESSES: &[(&str, &str)] = &[
    ("clash-verge.exe", "Clash Verge"),
    ("verge-mihomo.exe", "Clash Verge core"),
    ("verge-mihomo-alpha.exe", "Clash Verge core"),
    ("clash for windows.exe", "Clash for Windows"),
    ("flclash.exe", "FlClash"),
    ("v2rayn.exe", "v2rayN"),
    ("nekoray.exe", "NekoRay"),
    ("nekobox.exe", "NekoBox"),
    ("throne.exe", "Throne"),
    ("hiddify.exe", "Hiddify"),
    ("sing-box.exe", "sing-box"),
    ("xray.exe", "Xray"),
    ("mihomo.exe", "mihomo"),
];

#[derive(Debug, Clone, Serialize)]
pub struct CoreInfo {
    pub running: bool,
    pub pid: Option<u32>,
    pub version: Option<String>,
    pub path: Option<String>,
    pub missing: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchInfo {
    pub task: bool,
    pub autostart: bool,
    pub installable: bool,
}

/// The Xray helper core as the UI sees it.
#[derive(Debug, Clone, Serialize)]
pub struct XrayInfo {
    pub installed: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub running: bool,
    /// Servers that Xray runs right now, and how many of them have their TLS handshake cut up.
    pub nodes: usize,
    pub dpi_nodes: usize,
    /// DPI bypass in force and who ordered it: `manual` (Settings) or `subscription`.
    pub dpi: Option<Dpi>,
    pub dpi_source: String,
    /// Why Xray is not doing what was asked: `missing`, or `failed: <reason>`.
    pub issue: Option<String>,
    /// Server name -> protocol in the profile, for the servers Xray runs (mihomo only sees SOCKS5).
    pub kinds: BTreeMap<String, String>,
    /// Servers Xray could not take over, "name: reason".
    pub skipped: Vec<String>,
    /// The installed core knows the `fragment` mask (older ones use a deprecated outbound).
    pub fragment_mask: bool,
}

/// Result of asking GitHub for the newest version of a core.
#[derive(Debug, Clone, Serialize)]
pub struct CoreUpdate {
    pub kind: &'static str,
    pub installed: Option<String>,
    pub latest: String,
    pub newer: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppState {
    pub platform: &'static str,
    pub recovery_required: bool,
    pub core: CoreInfo,
    pub xray: XrayInfo,
    /// This PC's addresses: what other devices type as the proxy host, and which sources are the PC itself.
    pub lan: Lan,
    pub elevated: bool,
    /// Admin-once setup: the elevated-start task exists, start with Windows is on, the app sits where a task is allowed.
    pub launch: LaunchInfo,
    pub settings: Settings,
    /// Traffic capture is really on (system proxy set / TUN adapter up).
    pub connected: bool,
    pub sysproxy: bool,
    pub tun: bool,
    pub profile: Option<ProfileMeta>,
    pub profiles: Vec<ProfileMeta>,
    pub chains: Vec<Chain>,
    pub chain_exits: Vec<String>,
    pub broken_chains: Vec<String>,
    /// Selector groups that carry the default route (the UI follows them to find the active node).
    pub main_groups: Vec<String>,
    /// Kometfy's remote settings and the ads to show (checked; see `remote`).
    pub remote: crate::remote::RemoteDoc,
    pub rules: Vec<UserRule>,
    pub rule_issues: Vec<RuleIssue>,
    /// How many entries at the top of the core's rule list are ours (bypass + user rules + LAN).
    pub injected_rules: usize,
    pub data_dir: String,
    pub candidates: Vec<CoreCandidate>,
    pub geodata_missing: Vec<String>,
    pub last_error: Option<String>,
    pub tg: TgState,
    pub zapret: ZapretState,
}

/// The auto-search for a Zapret strategy: which one is being tried.
#[derive(Debug, Clone, Serialize)]
pub struct ZapretProgress {
    pub done: usize,
    pub total: usize,
    pub name: String,
}

/// Zapret as the UI sees it.
#[derive(Debug, Clone, Serialize)]
pub struct ZapretState {
    /// Windows only for now (WinDivert).
    pub supported: bool,
    pub installed: bool,
    pub version: Option<String>,
    pub running: bool,
    /// Turned on, but waiting while the VPN is on.
    pub paused: bool,
    pub strategy: String,
    pub strategies: Vec<String>,
    pub error: Option<String>,
    pub finding: Option<ZapretProgress>,
}

/// The Telegram bridge as the UI sees it.
#[derive(Debug, Clone, Serialize)]
pub struct TgState {
    pub running: bool,
    pub port: u16,
    /// `tg://proxy?...`: opens Telegram's "add proxy" dialog filled in. None until a secret exists.
    pub link: Option<String>,
    pub error: Option<String>,
    /// Telegram keeps coming with an old link: it should be applied again.
    pub stale_link: bool,
}

pub struct Manager {
    pub paths: Paths,
    settings: RwLock<Settings>,
    profiles: Mutex<ProfileStore>,
    chains: Mutex<ChainStore>,
    rules: Mutex<RuleStore>,
    core: Core,
    /// The Xray helper process (see `xray`). Its output joins the core log.
    xray: Core,
    /// What the helper runs now. Some while it is wanted, even after the process died: that is
    /// how the monitor knows to bring it back.
    xray_run: Mutex<Option<XrayRunning>>,
    xray_issue: Mutex<Option<String>>,
    xray_revivals: Mutex<VecDeque<Instant>>,
    xray_version_cache: Mutex<Option<(PathBuf, Option<String>)>>,
    http: reqwest::Client,
    stream_http: reqwest::Client,
    emit: Emitter,
    /// Serializes every operation that changes the core or the capture state.
    op: tokio::sync::Mutex<()>,
    log_ring: Arc<Mutex<VecDeque<String>>>,
    stream_tasks: Mutex<Vec<JoinHandle<()>>>,
    monitor: Mutex<Option<JoinHandle<()>>>,
    build_info: Mutex<BuildInfo>,
    tun_on: AtomicBool,
    expected_running: AtomicBool,
    #[cfg(target_os = "macos")]
    recovery_required: AtomicBool,
    /// A legacy backup is outside the guard's journal and cannot be cleared by
    /// a successful guard response, even if the file later disappears.
    #[cfg(target_os = "macos")]
    legacy_recovery_required: AtomicBool,
    #[cfg(target_os = "macos")]
    proxy_guard: Mutex<Option<Arc<crate::macos_proxy_session::GuardSession>>>,
    /// Exact supervised core instance for which the guard was enabled.
    #[cfg(target_os = "macos")]
    proxy_guard_core: Mutex<Option<crate::mihomo::CoreIdentity>>,
    /// Network location whose services were configured by the active guard.
    #[cfg(target_os = "macos")]
    proxy_location: Mutex<Option<String>>,
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    tun_guard: Mutex<Option<Arc<crate::macos_proxy_session::GuardSession>>>,
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    tun_device: Mutex<Option<String>>,
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    proxy_guard_prepare: tokio::sync::Mutex<()>,
    #[cfg(target_os = "macos")]
    handoff: Mutex<Option<(bool, bool)>>,
    last_error: Mutex<Option<String>>,
    version_cache: Mutex<Option<(PathBuf, Option<String>)>>,
    /// `mihomo -v` is run for every candidate; remember the answer for a while.
    candidates_cache: Mutex<Option<(std::time::Instant, Vec<CoreCandidate>)>>,
    /// Adapters change rarely and listing them is not free: look again after a few seconds.
    lan_cache: Mutex<Option<(std::time::Instant, Lan)>>,
    geodata_missing: Mutex<Vec<String>>,
    /// Local statistics (see `metrics`); only the day's totals leave the device, and only with the user's consent
    /// (see `remote`).
    metrics: Arc<Metrics>,
    /// Kometfy's backend: remote settings and ads; statistics and remote tests with consent.
    remote: crate::remote::Remote,
    sampler: Sampler,
    last_sample: Mutex<Instant>,
    /// Android: the host's VPN service, set once at start (see `android`).
    #[cfg(target_os = "android")]
    android: Mutex<Option<Arc<dyn crate::android::AndroidVpn>>>,
    tg: Mutex<Option<crate::tgbridge::Bridge>>,
    tg_error: Mutex<Option<String>>,
    /// Zapret's winws: hidden, killed with us, its output in the core log.
    zapret: Core,
    /// winws's own last lines: what it said when it quit.
    zapret_out: Arc<Mutex<VecDeque<String>>>,
    zapret_error: Mutex<Option<String>>,
    zapret_find: Mutex<Option<ZapretProgress>>,
    /// The DPI engine was started and should be running: the monitor brings it back when it exits on its own (a
    /// phone's battery saver kills it, or it crashes). Cleared whenever it is stopped on purpose.
    dpi_alive: AtomicBool,
    /// The bigger ad list is being downloaded.
    ads_more_busy: AtomicBool,
}

/// The Xray process as it was started: enough to compare with a new config and to start it again.
struct XrayRunning {
    bin: PathBuf,
    port: u16,
    secret: String,
    json: String,
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// A loopback port nobody listens on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(17_899)
}

/// Which DPI bypass is in force: the user's own order wins, otherwise the subscription's.
/// Xray `off` means none at all.
fn pick_dpi(s: &Settings, profile: Option<&ProfileMeta>) -> Option<(Dpi, &'static str)> {
    if s.xray.mode == XrayMode::Off {
        return None;
    }
    if s.dpi.enabled {
        return Some((s.dpi.spec(), "manual"));
    }
    if s.dpi.follow_subscription {
        return profile.and_then(|p| p.dpi.clone()).map(|d| (d, "subscription"));
    }
    None
}

/// `Windows 11 10.0.26300 x86_64` for the diagnostic report.
fn os_line() -> String {
    #[cfg(any(windows, target_os = "macos"))]
    {
        let d = device::info();
        format!("{} {} {}", d.os, d.os_version, std::env::consts::ARCH)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Wait until something listens on the loopback `port`, or the process is gone.
async fn wait_listening(port: u16, alive: impl Fn() -> bool, total: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < total && alive() {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn parse_log(line: &str) -> Value {
    let get = |key: &str| -> Option<String> {
        let pat = format!("{key}=");
        let i = line.find(&pat)?;
        let rest = &line[i + pat.len()..];
        if let Some(r) = rest.strip_prefix('"') {
            let (mut out, mut esc) = (String::new(), false);
            for c in r.chars() {
                if esc {
                    out.push(c);
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    break;
                } else {
                    out.push(c);
                }
            }
            Some(out)
        } else {
            rest.split_whitespace().next().map(String::from)
        }
    };
    json!({
        "level": get("level").unwrap_or_else(|| "info".into()),
        "msg": get("msg").unwrap_or_else(|| line.to_string()),
        "time": get("time").unwrap_or_default(),
    })
}

/// Traffic goes through a VPN server now. In the free mode the core may capture traffic too, but only
/// to filter it: everything stays direct.
fn vpn_on(s: &Settings) -> bool {
    s.connected && s.app_mode != crate::settings::AppMode::FreeAntiDpi
}

/// May the free tools run now: always beside a VPN mode, and in the free mode while its main switch is on.
fn tools_allowed(s: &Settings) -> bool {
    s.app_mode != crate::settings::AppMode::FreeAntiDpi || s.free_on
}

/// Not Android: there the app is outside its own tunnel, so its own connections always leave directly.
fn android_less() -> bool {
    !cfg!(target_os = "android")
}

/// The app's mode as the backend names it.
fn mode_name(s: &Settings) -> &'static str {
    match s.app_mode {
        crate::settings::AppMode::FreeAntiDpi => "free",
        crate::settings::AppMode::SmartHybridVpn => "smart",
        _ => "vpn",
    }
}

fn config_fingerprint(s: &Settings) -> Value {
    json!([
        s.tun, s.dns, s.bypass, s.ipv6, s.log_level, s.unified_delay, s.tcp_concurrent,
        s.find_process_mode, s.mode, s.xray, s.dpi, s.adblock, s.app_mode, s.ai_access, s.games_dns
    ])
}

/// Check the current profile before moving an explicitly selected chain to it.
fn rebind_chain_to_profile(chain: &Chain, active: &str, yaml: &str, settings: &Settings) -> Result<Chain> {
    let mut rebound = chain.clone();
    rebound.profile = Some(active.to_owned());
    let candidate = config::build(Some(yaml), Some(active), settings, &[rebound.clone()], false)?;
    if !candidate.info.chain_exits.contains(&chain::exit_name(chain)) {
        return Err(Error::msg("one or more chain servers are missing from the active profile"));
    }
    Ok(rebound)
}

#[cfg(target_os = "macos")]
async fn verify_macos_proxy_listener(port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let check = async {
        let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response != [5, 0] { return Err(std::io::Error::other("unexpected SOCKS response")); }
        Ok::<(), std::io::Error>(())
    };
    match tokio::time::timeout(Duration::from_secs(2), check).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(Error::msg(format!("local proxy on port {port} is not ready"))),
    }
}

impl Manager {
    pub fn new(root: PathBuf, emit: Emitter) -> Result<Arc<Self>> {
        let paths = Paths::new(root);
        paths.ensure()?;
        let remote = crate::remote::Remote::new(paths.root.join("remote.json"));
        let mut settings = Settings::load(&paths.settings_file());
        if settings.secret.is_empty() {
            settings.secret = uuid::Uuid::new_v4().simple().to_string();
            settings.save(&paths.settings_file())?;
        }
        // a previous run that died with the system proxy set leaves a backup behind
        #[cfg(not(target_os = "macos"))]
        sysproxy::recover(&paths.sysproxy_backup(), &settings.proxy_addr());
        #[cfg(target_os = "macos")]
        let recovery_required = !matches!(std::fs::symlink_metadata(paths.sysproxy_backup()), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
        settings.connected = false;
        let profiles = ProfileStore::load(&paths);
        let chains = ChainStore::load(&paths);
        let mut rules = RuleStore::load(&paths);
        // the old "always direct" lists in Settings became ordinary rules
        if !RuleStore::exists(&paths) && !settings.bypass.is_empty() {
            let direct = |kind: &str, value: &String| UserRule {
                enabled: true,
                kind: kind.into(),
                value: value.clone(),
                target: "DIRECT".into(),
                no_resolve: kind.starts_with("IP-CIDR"),
                ..Default::default()
            };
            let b = &settings.bypass;
            let migrated: Vec<UserRule> = b
                .processes
                .iter()
                .map(|v| direct("PROCESS-NAME", v))
                .chain(b.domains.iter().map(|v| direct("DOMAIN-SUFFIX", v)))
                .chain(b.cidrs.iter().map(|v| direct("IP-CIDR", v)))
                .filter_map(|r| r.normalize().ok())
                .collect();
            if rules.replace(migrated).is_ok() {
                settings.bypass = Bypass::default();
                let _ = settings.save(&paths.settings_file());
            }
        }
        let metrics = Arc::new(Metrics::open(metrics::file_in(&paths.root), settings.metrics));
        metrics.start_session();
        Ok(Arc::new(Self {
            paths,
            settings: RwLock::new(settings),
            profiles: Mutex::new(profiles),
            chains: Mutex::new(chains),
            rules: Mutex::new(rules),
            core: Core::default(),
            xray: Core::default(),
            xray_run: Mutex::new(None),
            xray_issue: Mutex::new(None),
            xray_revivals: Mutex::new(VecDeque::new()),
            xray_version_cache: Mutex::new(None),
            http: controller::http_client(),
            stream_http: controller::stream_client(),
            emit,
            op: tokio::sync::Mutex::new(()),
            log_ring: Arc::new(Mutex::new(VecDeque::new())),
            stream_tasks: Mutex::new(Vec::new()),
            monitor: Mutex::new(None),
            build_info: Mutex::new(BuildInfo::default()),
            tun_on: AtomicBool::new(false),
            expected_running: AtomicBool::new(false),
            #[cfg(target_os = "macos")]
            recovery_required: AtomicBool::new(recovery_required),
            #[cfg(target_os = "macos")]
            legacy_recovery_required: AtomicBool::new(recovery_required),
            #[cfg(target_os = "macos")]
            proxy_guard: Mutex::new(None),
            #[cfg(target_os = "macos")]
            proxy_guard_core: Mutex::new(None),
            #[cfg(target_os = "macos")]
            proxy_location: Mutex::new(None),
            #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
            tun_guard: Mutex::new(None),
            #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
            tun_device: Mutex::new(None),
            #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
            proxy_guard_prepare: tokio::sync::Mutex::new(()),
            #[cfg(target_os = "macos")]
            handoff: Mutex::new(None),
            last_error: Mutex::new(None),
            version_cache: Mutex::new(None),
            candidates_cache: Mutex::new(None),
            lan_cache: Mutex::new(None),
            geodata_missing: Mutex::new(Vec::new()),
            metrics,
            remote,
            sampler: Sampler::default(),
            last_sample: Mutex::new(Instant::now()),
            #[cfg(target_os = "android")]
            android: Mutex::new(None),
            tg: Mutex::new(None),
            tg_error: Mutex::new(None),
            zapret: Core::default(),
            dpi_alive: AtomicBool::new(false),
            zapret_out: Arc::new(Mutex::new(VecDeque::new())),
            zapret_error: Mutex::new(None),
            zapret_find: Mutex::new(None),
            ads_more_busy: AtomicBool::new(false),
        }))
    }

    // ---------------------------------------------------------------- helpers

    /// The settings as they apply now. Without a VPN key only the free tools exist, whatever mode is stored (the
    /// Home shows the same): a fresh install, whose stored mode is smart, would otherwise keep the bypass paused
    /// "while the VPN is on" with no VPN at all. The stored choice applies again once a key is added.
    fn settings(&self) -> Settings {
        let mut s = self.settings.read().unwrap().clone();
        if self.profiles.lock().unwrap().items().is_empty() {
            s.app_mode = crate::settings::AppMode::FreeAntiDpi;
        }
        // macOS: the free mode captures with the system proxy. In the TUN the DPI engine's own connections come back
        // in, and mihomo sees no process names there to send them out (measured 2026-11-14: YouTube and Discord
        // dead in a loop); the free mode needs no TUN, Telegram has its own bridge.
        #[cfg(target_os = "macos")]
        if s.app_mode == crate::settings::AppMode::FreeAntiDpi && s.method == Method::Tun {
            s.method = Method::SystemProxy;
        }
        s
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Android: hand over the host's VPN service. Connecting is not possible before this.
    #[cfg(target_os = "android")]
    pub fn set_android_vpn(&self, vpn: Arc<dyn crate::android::AndroidVpn>) {
        *self.android.lock().unwrap() = Some(vpn);
    }

    fn save_settings(&self) -> Result<()> {
        self.settings().save(&self.paths.settings_file())
    }

    fn controller(&self) -> Controller {
        let s = self.settings.read().unwrap();
        Controller::new(self.http.clone(), s.controller_port, s.secret.clone())
    }

    fn running(&self) -> bool {
        self.core.pid().is_some()
    }

    fn resolve_core(&self) -> Result<PathBuf> {
        if let Some(p) = self.settings.read().unwrap().core_path.clone() {
            let p = PathBuf::from(p);
            if p.is_file() {
                return Ok(p);
            }
        }
        let own = self.paths.core_bin();
        if own.is_file() {
            return Ok(own);
        }
        Err(Error::CoreMissing)
    }

    fn cached_version(&self, bin: &PathBuf) -> Option<String> {
        let mut g = self.version_cache.lock().unwrap();
        if let Some((p, v)) = g.as_ref() {
            if p == bin {
                return v.clone();
            }
        }
        let v = mihomo::version(bin);
        *g = Some((bin.clone(), v.clone()));
        v
    }

    fn cached_candidates(&self) -> Vec<CoreCandidate> {
        let mut g = self.candidates_cache.lock().unwrap();
        if let Some((at, list)) = g.as_ref() {
            if at.elapsed() < Duration::from_secs(30) {
                return list.clone();
            }
        }
        let list = discover::candidates(&self.paths);
        *g = Some((std::time::Instant::now(), list.clone()));
        list
    }

    // ---------------------------------------------------------------- Xray helper core

    fn resolve_xray(&self) -> Option<PathBuf> {
        if let Some(p) = self.settings.read().unwrap().xray.path.clone() {
            let p = PathBuf::from(p);
            if p.is_file() {
                return Some(p);
            }
        }
        let own = self.paths.xray_bin();
        own.is_file().then_some(own)
    }

    fn cached_xray_version(&self, bin: &PathBuf) -> Option<String> {
        let mut g = self.xray_version_cache.lock().unwrap();
        if let Some((p, v)) = g.as_ref() {
            if p == bin {
                return v.clone();
            }
        }
        let v = xray::version(bin);
        *g = Some((bin.clone(), v.clone()));
        v
    }

    fn set_xray_issue(&self, issue: Option<String>) {
        *self.xray_issue.lock().unwrap() = issue;
    }

    /// Xray's output goes to the same log as the core's, in the same shape.
    fn xray_sink(&self) -> LineSink {
        let inner = self.sink();
        Arc::new(move |line: String| inner(xray::log_line(&line)))
    }

    /// DPI bypass in force for the active profile, and who asked for it.
    fn effective_dpi(&self, s: &Settings) -> Option<(Dpi, &'static str)> {
        let store = self.profiles.lock().unwrap();
        pick_dpi(s, s.active_profile.as_deref().and_then(|id| store.get(id)))
    }

    /// Port and password of the private listener. A running helper keeps its own, so a reload
    /// that changes nothing for Xray produces the very same config.
    fn xray_endpoint(&self) -> (u16, String) {
        if self.xray.pid().is_some() {
            if let Some(r) = self.xray_run.lock().unwrap().as_ref() {
                return (r.port, r.secret.clone());
            }
        }
        (free_port(), uuid::Uuid::new_v4().simple().to_string())
    }

    /// What the config builder needs to hand servers to Xray, or None when Xray has nothing to
    /// do (or is not installed, which is then reported as the issue).
    fn xray_plan_input(&self, s: &Settings, refused: &BTreeMap<String, String>) -> Option<XrayRun> {
        let dpi = self.effective_dpi(s).map(|(d, _)| d);
        let wanted = match s.xray.mode {
            XrayMode::Off => false,
            XrayMode::All => true,
            XrayMode::Auto => dpi.is_some(),
        };
        if !wanted {
            self.set_xray_issue(None);
            return None;
        }
        let Some(bin) = self.resolve_xray() else {
            self.set_xray_issue(Some("missing".into()));
            return None;
        };
        let (port, secret) = self.xray_endpoint();
        Some(XrayRun {
            mode: s.xray.mode,
            dpi,
            core: self.cached_xray_version(&bin).as_deref().and_then(xray::version_tuple),
            port,
            secret,
            log_level: s.log_level.clone(),
            exe_name: bin.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "xray.exe".into()),
            refused: refused.clone(),
        })
    }

    fn stop_xray(&self) {
        self.xray.stop();
        *self.xray_run.lock().unwrap() = None;
    }

    async fn spawn_xray(&self, bin: &Path, port: u16) -> Result<()> {
        self.xray.spawn(xray::command(bin, &self.paths.xray_config()), self.xray_sink())?;
        if !wait_listening(port, || self.xray.pid().is_some(), Duration::from_secs(8)).await {
            let tail = self.log_tail(6);
            self.xray.stop();
            return Err(Error::msg(if tail.is_empty() {
                "Xray did not start listening".to_string()
            } else {
                mihomo::summarize_error(&tail)
            }));
        }
        Ok(())
    }

    /// Make the helper match the config just built: start it, replace it, or stop it when no
    /// server needs it any more. The config is checked by Xray itself before anything is touched.
    async fn sync_xray_locked(&self, built: &config::Built) -> Result<()> {
        let Some(x) = built.xray.as_ref() else {
            self.stop_xray();
            return Ok(());
        };
        let bin = self.resolve_xray().ok_or_else(|| Error::msg("the Xray core is not installed"))?;
        if let Some(r) = self.xray_run.lock().unwrap().as_ref() {
            if r.bin == bin && r.json == x.json && self.xray.pid().is_some() {
                return Ok(());
            }
        }
        let cfg = self.paths.xray_config();
        crate::util::write_atomic(&cfg, x.json.as_bytes())?;
        let (b, c) = (bin.clone(), cfg.clone());
        tokio::task::spawn_blocking(move || xray::validate(&b, &c))
            .await
            .map_err(|e| Error::msg(e.to_string()))??;
        self.stop_xray();
        self.spawn_xray(&bin, x.port).await?;
        info!("xray started: {} servers", x.nodes);
        *self.xray_run.lock().unwrap() = Some(XrayRunning {
            bin,
            port: x.port,
            secret: x.secret.clone(),
            json: x.json.clone(),
        });
        self.set_xray_issue(None);
        Ok(())
    }

    /// The helper died while it was wanted: start it again with the same config, but not in a
    /// loop. Servers behind it do not work in the meantime, the others do.
    async fn revive_xray(self: &Arc<Self>) {
        let _g = self.op.lock().await;
        if self.xray.pid().is_some() || !self.expected_running.load(SeqCst) {
            return;
        }
        let Some((bin, port)) = self.xray_run.lock().unwrap().as_ref().map(|r| (r.bin.clone(), r.port)) else {
            return;
        };
        let tail = self.log_tail(4);
        warn!("xray exited unexpectedly\n{tail}");
        self.metrics.count(&format!("{}.xray", metrics::name::CORE_EXIT));
        self.metrics.event("core_exit", "xray");
        let recent = {
            let mut q = self.xray_revivals.lock().unwrap();
            q.retain(|t| t.elapsed() < Duration::from_secs(60));
            q.push_back(Instant::now());
            q.len()
        };
        let result = if recent > 3 {
            Err(Error::msg("it keeps stopping"))
        } else {
            self.spawn_xray(&bin, port).await
        };
        if let Err(e) = result {
            self.stop_xray();
            self.set_xray_issue(Some(format!("failed: {e}")));
            self.set_error(format!("Xray stopped unexpectedly. {e}"));
        }
        self.emit_state();
    }

    fn cached_lan(&self, skip: &str) -> Lan {
        let mut g = self.lan_cache.lock().unwrap();
        if let Some((at, lan)) = g.as_ref() {
            if at.elapsed() < Duration::from_secs(10) {
                return lan.clone();
            }
        }
        let lan = lan::scan(skip);
        *g = Some((std::time::Instant::now(), lan.clone()));
        lan
    }

    fn set_error(&self, e: impl ToString) {
        *self.last_error.lock().unwrap() = Some(e.to_string());
    }

    fn log_tail(&self, n: usize) -> String {
        let r = self.log_ring.lock().unwrap();
        r.iter().rev().take(n).rev().cloned().collect::<Vec<_>>().join("\n")
    }

    /// The core's log lines go to the ring and to the window. A busy core logs every connection, and on Android
    /// every event is a call into the WebView on its main thread: lines go out together, one event (`core-logs`,
    /// a list) at most every 300 ms, instead of one call per line.
    fn sink(&self) -> LineSink {
        let ring = self.log_ring.clone();
        let emit = self.emit.clone();
        let pending: Arc<Mutex<Vec<Value>>> = Arc::default();
        Arc::new(move |line: String| {
            {
                let mut r = ring.lock().unwrap();
                r.push_back(line.clone());
                while r.len() > LOG_RING {
                    r.pop_front();
                }
            }
            let first = {
                let mut p = pending.lock().unwrap();
                p.push(parse_log(&line));
                p.len() == 1
            };
            if !first {
                return;
            }
            let (pending, emit) = (pending.clone(), emit.clone());
            let flush = move || {
                let lines = std::mem::take(&mut *pending.lock().unwrap());
                if !lines.is_empty() {
                    emit("core-logs", Value::Array(lines));
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(rt) => {
                    rt.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        flush();
                    });
                }
                Err(_) => flush(),
            }
        })
    }

    pub fn state(&self) -> AppState {
        let settings = self.settings();
        let pid = self.core.pid();
        let bin = self.resolve_core().ok();
        let missing = bin.is_none();
        #[cfg(target_os = "macos")]
        let sysproxy_on = crate::sysproxy_macos::is_active_for(&settings.proxy_addr());
        #[cfg(not(target_os = "macos"))]
        let sysproxy_on = sysproxy::is_active_for(&settings.proxy_addr());
        let tun = self.tun_on.load(SeqCst);
        #[cfg(target_os = "android")]
        let method = Method::Tun;
        #[cfg(not(target_os = "android"))]
        let method = settings.method;
        let connected = pid.is_some()
            && settings.connected
            && match method {
                Method::Tun => tun,
                Method::SystemProxy => sysproxy_on,
            };
        let profiles = self.profiles.lock().unwrap().items().to_vec();
        let profile = settings
            .active_profile
            .as_deref()
            .and_then(|id| profiles.iter().find(|p| p.id == id).cloned());
        let info = self.build_info.lock().unwrap().clone();
        let mut safe = settings.clone();
        safe.secret = String::new();
        // on Android the connection is always the tunnel of the VPN service
        #[cfg(target_os = "android")]
        {
            safe.method = Method::Tun;
        }
        let dpi = pick_dpi(&settings, profile.as_ref());
        let xray_bin = self.resolve_xray();
        let xray_version = xray_bin.as_ref().and_then(|b| self.cached_xray_version(b));
        let xray = XrayInfo {
            installed: xray_bin.is_some(),
            fragment_mask: xray_conf::core_has_fragment_mask(xray_version.as_deref()),
            version: xray_version,
            path: xray_bin.as_ref().map(|b| b.display().to_string()),
            running: self.xray.pid().is_some(),
            nodes: info.xray_kinds.len(),
            dpi_nodes: info.xray_dpi_nodes,
            dpi_source: dpi.as_ref().map(|(_, s)| s.to_string()).unwrap_or_default(),
            dpi: dpi.map(|(d, _)| d),
            // a leftover complaint means nothing once Xray is switched off
            issue: (settings.xray.mode != XrayMode::Off).then(|| self.xray_issue.lock().unwrap().clone()).flatten(),
            kinds: info.xray_kinds.clone(),
            skipped: info.xray_skipped.clone(),
        };
        let tg_stale = self.tg.lock().unwrap().as_ref().map(|b| b.stale_link());
        AppState {
            platform: std::env::consts::OS,
            recovery_required: {
                #[cfg(target_os = "macos")]
                { self.recovery_required.load(SeqCst) }
                #[cfg(not(target_os = "macos"))]
                { false }
            },
            core: CoreInfo {
                running: pid.is_some(),
                pid,
                version: bin.as_ref().and_then(|b| self.cached_version(b)),
                path: bin.as_ref().map(|b| b.display().to_string()),
                missing,
            },
            xray,
            lan: self.cached_lan(&settings.tun.device),
            // Android needs no administrator rights: the system asks for the VPN permission instead
            elevated: cfg!(target_os = "android") || elevate::is_elevated(),
            launch: LaunchInfo {
                task: launch::task_installed(),
                autostart: launch::autostart_enabled(),
                installable: std::env::current_exe().is_ok_and(|e| launch::is_protected_location(&e)),
            },
            settings: safe,
            connected,
            sysproxy: sysproxy_on,
            tun,
            profile,
            profiles,
            chains: self.chains.lock().unwrap().items().to_vec(),
            chain_exits: info.chain_exits,
            broken_chains: info.broken_chains,
            main_groups: info.main_groups,
            remote: self.remote.doc(),
            rules: self.rules.lock().unwrap().items().to_vec(),
            rule_issues: info.rule_issues,
            injected_rules: info.injected_rules,
            data_dir: self.paths.root.display().to_string(),
            candidates: if missing { self.cached_candidates() } else { vec![] },
            geodata_missing: self.geodata_missing.lock().unwrap().clone(),
            last_error: self.last_error.lock().unwrap().clone(),
            tg: TgState {
                // one lock: a guard taken twice in one statement deadlocks
                running: tg_stale.is_some(),
                stale_link: tg_stale == Some(true),
                port: settings.tg.port,
                link: (!settings.tg.secret.is_empty()).then(|| crate::tgbridge::link(settings.tg.port, &settings.tg.secret)),
                error: self.tg_error.lock().unwrap().clone(),
            },
            zapret: {
                let dir = self.paths.zapret_dir();
                let version = crate::zapret::version(&dir);
                let engine = self.dpi_engine().is_some();
                ZapretState {
                    supported: cfg!(windows) || engine,
                    installed: if cfg!(windows) { version.is_some() } else { engine },
                    strategies: if cfg!(windows) {
                        if version.is_some() { crate::zapret::names(&dir) } else { vec![] }
                    } else if engine {
                        crate::byedpi::names()
                    } else {
                        vec![]
                    },
                    version: if cfg!(windows) { version } else { engine.then(|| crate::byedpi::VERSION.to_string()) },
                    running: self.zapret.pid().is_some(),
                    paused: settings.zapret.enabled && vpn_on(&settings) && self.zapret.pid().is_none(),
                    // the one that runs: a name this platform lacks (Windows' "general" on a fresh phone) runs the first
                    // none until one is chosen that this platform has; the first start picks it
                    strategy: if self.strategy_chosen() { settings.zapret.strategy.clone() } else { String::new() },
                    error: self.zapret_error.lock().unwrap().clone(),
                    finding: self.zapret_find.lock().unwrap().clone(),
                }
            },
        }
    }

    pub fn emit_state(&self) {
        let v = serde_json::to_value(self.state()).unwrap_or(Value::Null);
        (self.emit)("state", v);
    }

    /// Facts for a bug report: versions, settings without secrets, statistics and the tails of
    /// the logs, scrubbed of addresses and names. Saved to a file; the app sends it nowhere.
    pub fn diagnostic_report(&self) -> Result<diagnostics::Report> {
        let st = self.state();
        let s = &st.settings;
        let yn = |b: bool| if b { "yes" } else { "no" };
        let app = format!(
            "Kometfy {}\nSystem: {}\nAdministrator: {}\nLanguage: {}, theme: {}",
            env!("CARGO_PKG_VERSION"),
            os_line(),
            yn(st.elevated),
            s.lang,
            s.theme
        );
        let cores = format!(
            "mihomo: {} (running: {}, own path: {})\nXray: {} (running: {}, servers it runs: {}){}",
            st.core.version.as_deref().unwrap_or("not found"),
            yn(st.core.running),
            yn(s.core_path.is_some()),
            st.xray.version.as_deref().unwrap_or("not installed"),
            yn(st.xray.running),
            st.xray.nodes,
            st.xray.issue.as_deref().map(|i| format!("\nXray issue: {}", diagnostics::scrub(i))).unwrap_or_default()
        );
        let settings = format!(
            "Capture: {:?}, mode: {}\nPorts: mixed {}, controller {}\nOther devices may connect: {}, IPv6: {}\nTUN: stack {}, MTU {}, auto-route {}, strict route {}, DNS hijack {}\nDNS: {}, overrides the profile: {}\nXray: {:?}, DPI bypass: {} (follows the subscription: {})\nAuto-connect: {}, core starts with the app: {}, close to tray: {}\nIP check: {}, update check: {}, device id sent: {}, local statistics: {}\nOwn rules: {} ({} with problems), chains: {} ({} broken)",
            s.method,
            s.mode.as_str(),
            s.mixed_port,
            s.controller_port,
            yn(s.allow_lan),
            yn(s.ipv6),
            s.tun.stack,
            s.tun.mtu,
            yn(s.tun.auto_route),
            yn(s.tun.strict_route),
            yn(s.tun.dns_hijack),
            s.dns.enhanced_mode,
            yn(s.dns.override_profile),
            s.xray.mode,
            yn(s.dpi.enabled),
            yn(s.dpi.follow_subscription),
            yn(s.auto_connect),
            yn(s.auto_start_core),
            yn(s.close_to_tray),
            yn(s.ip_check),
            yn(s.check_updates),
            yn(s.hwid),
            yn(s.metrics),
            st.rules.len(),
            st.rule_issues.len(),
            st.chains.len(),
            st.broken_chains.len()
        );
        let profile = match &st.profile {
            Some(p) => format!(
                "Active: source {:?}, servers {}, updated {}, refresh every {} h, provider counts devices: {}, has an announcement: {}, has a DPI instruction: {}\nProfiles in total: {}",
                p.source,
                p.nodes,
                p.updated_at.as_deref().unwrap_or("never"),
                p.interval_hours,
                yn(p.hwid_active),
                yn(p.announce.is_some()),
                yn(p.dpi.is_some()),
                st.profiles.len()
            ),
            None => format!("No active profile (profiles in total: {})", st.profiles.len()),
        };
        let state = format!(
            "Connected: {}, system proxy on: {}, TUN on: {}\nLast error: {}",
            yn(st.connected),
            yn(st.sysproxy),
            yn(st.tun),
            st.last_error.as_deref().map(diagnostics::scrub).unwrap_or_else(|| "none".into())
        );
        let core_lines: Vec<String> = self.log_ring.lock().unwrap().iter().rev().take(80).rev().cloned().collect();
        let app_log = logfile::tail(&self.paths.root.join("app.log"), 150).join("\n");
        let sections = [
            ("App", app),
            ("Cores", cores),
            ("Settings (no secrets)", settings),
            ("Profile", profile),
            ("State", state),
            ("Statistics (kept on this PC only)", diagnostics::metrics_text(&self.metrics.summary(30))),
            ("Core log (last 80 lines; lines that name sites are left out)", diagnostics::core_log(&core_lines)),
            ("App log (last 150 lines)", diagnostics::scrub(&app_log)),
        ];
        let text = diagnostics::assemble(&sections);
        let path = diagnostics::save(&self.paths.root.join("diagnostics"), &text)?;
        Ok(diagnostics::Report { path: path.display().to_string(), text })
    }

    // ---------------------------------------------------------------- lifecycle

    /// App start: begin crash monitoring, then auto-connect / auto-start per settings.
    pub async fn startup(self: &Arc<Self>, connect_now: bool) {
        self.spawn_monitor();
        self.spawn_remote();
        #[cfg(target_os = "macos")]
        if self.recovery_required.load(SeqCst) && self.retry_proxy_recovery().await.is_err() {
            self.emit_state();
            return;
        }
        let s = self.settings();
        if s.tg.enabled && tools_allowed(&s) {
            if let Err(e) = self.start_tg().await {
                warn!("telegram bridge: {e}");
            }
        }
        // the free mode was chosen on purpose: do not bring the VPN up behind the user's back
        let auto = s.auto_connect && (s.app_mode != crate::settings::AppMode::FreeAntiDpi || s.adblock || s.ai_access || s.games_dns);
        let result = if connect_now || auto {
            self.connect().await
        } else if s.auto_start_core && self.resolve_core().is_ok() {
            self.start_core().await
        } else {
            Ok(())
        };
        if let Err(e) = result {
            warn!("startup: {e}");
            self.set_error(e);
        }
        // Zapret needs administrator rights and a whole install; it waits while the VPN is on
        self.resume_zapret().await;
        self.reroute_dpi().await;
        self.emit_state();
    }

    pub fn settings_snapshot(&self) -> Settings {
        self.settings()
    }

    // ---------------------------------------------------------------- Kometfy's backend

    /// Every ten minutes (the first time shortly after start): see `remote_tick`.
    fn spawn_remote(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            loop {
                me.remote_tick().await;
                tokio::time::sleep(Duration::from_secs(600)).await;
            }
        });
    }

    /// Kometfy's backend (docs/BACKEND.md). For everyone: the remote settings and ads, every few hours. Only with
    /// the consents of the welcome screen: the day's statistics and the ads' counts, and the remote tests of the
    /// backend and of the VPN provider (the addresses its subscription sent).
    pub async fn remote_tick(self: &Arc<Self>) {
        use crate::remote::{CONFIG_EVERY, STATS_EVERY, TASKS_EVERY};
        let s = self.settings();
        let Some(base) = crate::remote::base_url(&s.backend_url) else { return };
        let platform = std::env::consts::OS;
        self.remote.set_seed(&s.install_id);
        if self.remote.due("config", CONFIG_EVERY) {
            let before = self.remote.doc().settings;
            match self.remote.refresh(&base, platform).await {
                Ok(true) => {
                    let after = self.remote.doc().settings;
                    // new lists reach a running core and a running Telegram bridge at once
                    let free = s.app_mode == crate::settings::AppMode::FreeAntiDpi;
                    let lists = (s.games_dns && before.game_sites != after.game_sites) || (free && s.ai_access && before.ai_sites != after.ai_sites);
                    if lists && self.running() {
                        let _g = self.op.lock().await;
                        if let Err(e) = self.reload_locked().await {
                            warn!("remote lists: {e}");
                        }
                    }
                    if before.tg_domains != after.tg_domains && self.tg.lock().unwrap().is_some() {
                        if let Err(e) = self.start_tg().await {
                            warn!("telegram bridge: {e}");
                        }
                    }
                    self.emit_state();
                }
                Ok(false) => {}
                // visible in the log: a silent failure here once hid a DNS that answered nothing for the backend
                Err(e) => warn!("remote settings: {e}"),
            }
        }
        // the ads' counts carry no id of the device: their own consent, no install id needed
        if s.consent_ads {
            if let Err(e) = self.remote.send_ads(&base, platform).await {
                debug!("ad counts: {e}");
            }
        }
        if s.install_id.is_empty() {
            return;
        }
        let stats_due = s.consent_stats && self.remote.due("stats", STATS_EVERY);
        let tasks_due = s.consent_tests && self.remote.due("tasks", TASKS_EVERY);
        // the link and the SIM's operator only with the consent to share the network
        let net = if (stats_due || tasks_due) && s.consent_network { self.net_info(&s).await } else { Value::Null };
        if stats_due {
            if let Err(e) = self.remote.send_stats(&base, &self.stats_bodies(&s, &net)).await {
                debug!("statistics: {e}");
            }
        }
        if tasks_due {
            self.remote.tasks_done();
            let mode = mode_name(&s);
            let query = [
                ("n", net["type"].as_str().unwrap_or("").to_string()),
                ("c", net["carrier"].as_str().unwrap_or("").to_string()),
                ("r", net["routed"].as_str().unwrap_or("direct").to_string()),
                ("m", mode.to_string()),
            ];
            let mut channels = vec![crate::remote::Channel { tasks: format!("{base}/v1/tasks"), reports: format!("{base}/v1/reports"), provider: false }];
            if let Some(p) = &self.state().profile {
                if let (Some(t), Some(r)) = (&p.tasks_url, &p.reports_url) {
                    channels.push(crate::remote::Channel { tasks: t.clone(), reports: r.clone(), provider: true });
                }
            }
            let version = env!("CARGO_PKG_VERSION");
            for ch in channels {
                let install = if ch.provider { crate::remote::provider_install_id(&s.install_id, &ch.tasks) } else { s.install_id.clone() };
                let tasks = match self.remote.tasks(&ch, &install, platform, version, &query).await {
                    Ok(t) => t,
                    Err(e) => {
                        debug!("remote tests: {e}");
                        continue;
                    }
                };
                for t in tasks {
                    info!("remote test {} ({})", t.id, t.kind);
                    let result = self.run_task(&t, ch.provider).await;
                    let body = json!({ "task": t.id, "install": install, "platform": platform, "version": version, "mode": mode, "net": net, "result": result });
                    if let Err(e) = self.remote.report(&ch, &body).await {
                        debug!("remote test report: {e}");
                    }
                }
            }
        }
    }

    /// The network this device is on, for the statistics and the remote tests: the link (wifi, cellular, ethernet,
    /// other; "" when it cannot tell), the SIM's operator on a phone's mobile link, and whether the backend calls go
    /// through the VPN (on a desktop with the tunnel on; the Android app is outside its own tunnel), since then the
    /// backend sees the VPN server's network and not the person's.
    async fn net_info(&self, s: &Settings) -> Value {
        #[cfg(target_os = "android")]
        let (kind, carrier) = {
            let android = self.android.lock().unwrap().clone();
            match android {
                Some(a) => a.network().await.unwrap_or_default(),
                None => Default::default(),
            }
        };
        #[cfg(not(target_os = "android"))]
        let (kind, carrier) = (tokio::task::spawn_blocking(crate::probes::net_type).await.unwrap_or("").to_string(), String::new());
        let routed = if android_less() && self.tun_on.load(SeqCst) && self.running() && vpn_on(s) { "vpn" } else { "direct" };
        json!({ "type": kind, "carrier": carrier, "routed": routed })
    }

    /// The statistics the user agreed to send: yesterday's final totals and today's so far, the network, and the
    /// subscriptions by their providers' names (never a name the user gave one).
    fn stats_bodies(&self, s: &Settings, net: &Value) -> Vec<Value> {
        let mode = mode_name(s);
        let (count, names) = {
            let store = self.profiles.lock().unwrap();
            let subs: Vec<&ProfileMeta> = store.items().iter().filter(|p| p.url.is_some()).collect();
            let names: Vec<String> = subs
                .iter()
                .filter_map(|p| p.remote_title.clone().or_else(|| (!p.name_custom).then(|| p.name.clone())))
                .map(|n| n.chars().filter(|c| !c.is_control()).take(40).collect::<String>().trim().to_string())
                .filter(|n| n.chars().count() >= 2)
                .take(10)
                .collect();
            (subs.len(), names)
        };
        // the system, the memory and the load beyond the old P95s were added to the statistics' description in the
        // consent's revision 3: an install that agreed to an older text sends them only once it has seen the new one
        let described = s.consent_rev >= 3;
        let device = json!({
            "os_version": crate::device::info().os_version,
            "ram_gb": crate::device::ram_gb(),
            "cores": std::thread::available_parallelism().map_or(1, |n| n.get()),
        });
        [crate::remote::yesterday(), crate::remote::today()]
            .into_iter()
            .filter_map(|day| {
                let d = self.metrics.day_totals(&day)?;
                let c = |k: &str| d.counts.get(k).copied().unwrap_or(0);
                let failed = |kind: &str| c(&format!("{}.{kind}", crate::metrics::name::CONNECT_FAILED));
                Some(json!({
                    "install": s.install_id,
                    "platform": std::env::consts::OS,
                    "version": env!("CARGO_PKG_VERSION"),
                    "day": day,
                    "mode": mode,
                    "counts": {
                        "connects": c(crate::metrics::name::CONNECT_ATTEMPTS),
                        "connect_ok": c(crate::metrics::name::CONNECT_OK),
                        "fail_app": failed("app"),
                        "fail_core": failed("core"),
                        "fail_network": failed("network"),
                        "fail_subscription": failed("subscription"),
                        "crashes": c(crate::metrics::name::APP_CRASH),
                    },
                    "cpu_p95": d.cpu_p95,
                    "mem_p95": d.mem_p95,
                    "cpu_p50": if described { json!(d.cpu_p50) } else { Value::Null },
                    "mem_p50": if described { json!(d.mem_p50) } else { Value::Null },
                    "core_mem_p95": if described { json!(d.core_mem_p95) } else { Value::Null },
                    "start_ms": if described { json!(d.start_ms) } else { Value::Null },
                    // what the app runs on, to see how heavy it is there: the system's version, memory as a size
                    // class and processor cores; never the model or anything that names the device
                    "device": if described { device.clone() } else { Value::Null },
                    "net": if s.consent_network { net.clone() } else { Value::Null },
                    "subs": if s.consent_subs { json!({ "count": count, "names": names }) } else { Value::Null },
                }))
            })
            .collect()
    }

    /// A new consent need not wait for the next ten-minute tick. This only sends the agreed statistics, and
    /// checks the current choices again after network detection so a changed consent is not taken from a stale copy.
    fn spawn_initial_stats(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let initial = me.settings();
            if !initial.consent_stats || initial.install_id.is_empty() {
                return;
            }
            let Some(base) = crate::remote::base_url(&initial.backend_url) else { return };
            let net = if initial.consent_network { me.net_info(&initial).await } else { Value::Null };
            let current = me.settings();
            if !current.consent_stats || current.install_id != initial.install_id || current.backend_url != initial.backend_url {
                return;
            }
            let net = if initial.consent_network && current.consent_network { net } else { Value::Null };
            if let Err(e) = me.remote.send_stats(&base, &me.stats_bodies(&current, &net)).await {
                debug!("statistics: {e}");
            }
        });
    }

    /// One remote test, run on this device's own network. What comes back never names a server's address, a
    /// site the user opened, a link or a key.
    async fn run_task(self: &Arc<Self>, t: &crate::remote::Task, provider: bool) -> Value {
        let list = |k: &str, max: usize, ok: &dyn Fn(&str) -> Option<String>| -> Vec<String> {
            t.params[k].as_array().into_iter().flatten().filter_map(Value::as_str).filter_map(ok).take(max).collect()
        };
        // through the desktop's tunnel a check measures the VPN, not the person's network
        let tunnelled = android_less() && self.tun_on.load(SeqCst) && self.running();
        match t.kind.as_str() {
            "probe" => self.task_probe(&t.params).await,
            "dns" if tunnelled => json!({ "skipped": "tunnel" }),
            "dns" => crate::probes::dns(self.remote.http(), &list("domains", 30, &crate::zapret::clean_domain)).await,
            "tcp" => {
                let target = |x: &str| {
                    let (host, port) = x.rsplit_once(':')?;
                    (port.parse::<u16>().ok()? > 0 && (crate::zapret::clean_domain(host).is_some() || host.parse::<std::net::Ipv4Addr>().is_ok())).then(|| x.to_lowercase())
                };
                let mut r = crate::probes::tcp(&list("targets", 30, &target)).await;
                r["context"] = json!({ "tunnel": tunnelled });
                r
            }
            "speed" => self.task_speed(&t.params).await,
            "subscription" => {
                let url = t.params["url"].as_str().filter(|u| (u.starts_with("https://") || u.starts_with("http://")) && u.len() <= 2000);
                let Some(url) = url else { return json!({ "error": "bad url" }) };
                let max = t.params["max"].as_u64().unwrap_or(30).clamp(1, 50) as usize;
                let test_url = t.params["test_url"].as_str().filter(|u| u.starts_with("https://")).unwrap_or("https://www.gstatic.com/generate_204");
                // the core of its own runs only where its connections go out directly, not into the desktop's tunnel
                let core = if tunnelled { None } else { self.resolve_core().ok() };
                let work = self.paths.runtime_dir().join(format!("probe-{}", uuid::Uuid::new_v4()));
                let mut r = crate::probes::subscription(url, max, test_url, core, work).await;
                r["context"] = json!({ "tunnel": tunnelled });
                r
            }
            // picks the strategy that works here, and keeps it: the same as "Pick automatically"
            "dpi" => match self.zapret_find().await {
                Ok(best) => json!({ "best": best }),
                Err(e) => json!({ "error": e.to_string() }),
            },
            "report" => match self.diagnostic_report() {
                Ok(r) => json!({ "text": r.text.chars().take(60_000).collect::<String>() }),
                Err(e) => json!({ "error": e.to_string() }),
            },
            // the provider's own servers only, and only on its own channel
            "delay" if provider => self.task_delay(&t.params).await,
            _ => json!({ "error": "unsupported task" }),
        }
    }

    /// Sites opened directly, through the bypass and through the VPN: answered or not, in how many ms.
    async fn task_probe(&self, p: &Value) -> Value {
        let s = self.settings();
        let sites: Vec<String> = p["sites"].as_array().into_iter().flatten().filter_map(Value::as_str).filter_map(crate::zapret::clean_domain).take(30).collect();
        let via = p["via"].as_str().unwrap_or("all");
        let want = |r: &str| via == "all" || via == r;
        let vpn = vpn_on(&s) && self.running();
        let dpi = self.zapret.pid().is_some();
        // on Windows the bypass (winws) works on direct connections themselves: with it on, a direct try is a
        // try through the bypass, and a plain direct one cannot be made
        let windows_dpi = cfg!(windows) && dpi;
        let group = self.build_info.lock().unwrap().main_groups.first().cloned();
        let mut out = Vec::new();
        for site in &sites {
            let mut r = json!({ "site": site });
            if want("direct") && !windows_dpi && !vpn {
                r["direct"] = crate::probes::site(site, None).await;
            }
            if want("dpi") && dpi {
                let via = (!cfg!(windows)).then(|| format!("socks5://127.0.0.1:{}", crate::byedpi::PORT));
                r["dpi"] = crate::probes::site(site, via.as_deref()).await;
            }
            if want("vpn") && vpn {
                if let Some(g) = &group {
                    let path = format!(
                        "/proxies/{}/delay?url={}&timeout=6000",
                        utf8_percent_encode(g, NON_ALPHANUMERIC),
                        utf8_percent_encode(&format!("https://{site}/"), NON_ALPHANUMERIC)
                    );
                    let ms = self.ctl("GET", &path, None).await.ok().and_then(|v| v["delay"].as_u64());
                    let ok = ms.is_some_and(|m| m > 0);
                    r["vpn"] = if ok { json!({ "ok": true, "ms": ms }) } else { json!({ "ok": false, "ms": 6000, "stage": "timeout" }) };
                }
            }
            out.push(r);
        }
        json!({ "context": { "vpn": vpn, "dpi": dpi, "mode": s.app_mode }, "sites": out })
    }

    /// A download's speed directly, through the bypass and through the VPN. Not on a mobile link unless the task
    /// allows it: it costs the person's traffic.
    async fn task_speed(&self, p: &Value) -> Value {
        let s = self.settings();
        let net = self.net_info(&s).await;
        if net["type"] == "cellular" && !p["cellular"].as_bool().unwrap_or(false) {
            return json!({ "skipped": "cellular" });
        }
        let mb = p["mb"].as_u64().unwrap_or(10).clamp(1, 50);
        let url = p["url"].as_str().filter(|u| u.starts_with("https://") && u.len() <= 500).map(str::to_string).unwrap_or_else(|| format!("https://speed.cloudflare.com/__down?bytes={}", mb * 1_000_000));
        let via = p["via"].as_str().unwrap_or("all");
        let want = |r: &str| via == "all" || via == r;
        let vpn = vpn_on(&s) && self.running();
        let dpi = self.zapret.pid().is_some();
        let windows_dpi = cfg!(windows) && dpi;
        let max = mb * 1_000_000;
        let mut routes = serde_json::Map::new();
        // a direct download is one that leaves past the tunnel: on Android always (the app is outside its own
        // tunnel), on a desktop only without the tunnel and with the bypass off on Windows (it works on direct
        // connections there)
        if want("direct") && !windows_dpi && !(android_less() && self.tun_on.load(SeqCst) && vpn) {
            routes.insert("direct".into(), crate::probes::download(&url, None, max).await);
        }
        if want("dpi") && dpi {
            let proxy = (!cfg!(windows)).then(|| format!("socks5h://127.0.0.1:{}", crate::byedpi::PORT));
            routes.insert("dpi".into(), crate::probes::download(&url, proxy.as_deref(), max).await);
        }
        if want("vpn") && vpn {
            let proxy = format!("http://127.0.0.1:{}", s.mixed_port);
            routes.insert("vpn".into(), crate::probes::download(&url, Some(&proxy), max).await);
        }
        json!({ "routes": routes, "context": { "vpn": vpn, "dpi": dpi } })
    }

    /// The provider's servers (by their names in its own subscription), each tested through the core.
    async fn task_delay(&self, p: &Value) -> Value {
        if !self.running() {
            return json!({ "error": "the core is not running" });
        }
        let s = self.settings();
        let mut names: Vec<String> = p["servers"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
        // the guard must not live across the request below
        let group = self.build_info.lock().unwrap().main_groups.first().cloned();
        if names.is_empty() {
            if let Some(g) = group {
                let path = format!("/proxies/{}", utf8_percent_encode(&g, NON_ALPHANUMERIC));
                if let Ok(v) = self.ctl("GET", &path, None).await {
                    names = v["all"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
                }
            }
        }
        let mut out = Vec::new();
        for n in names.into_iter().take(50) {
            let path = format!(
                "/proxies/{}/delay?url={}&timeout={}",
                utf8_percent_encode(&n, NON_ALPHANUMERIC),
                utf8_percent_encode(&s.delay_url, NON_ALPHANUMERIC),
                s.delay_timeout_ms
            );
            let ms = self.ctl("GET", &path, None).await.ok().and_then(|v| v["delay"].as_u64()).unwrap_or(0);
            out.push(json!({ "name": n, "ms": ms }));
        }
        json!({ "servers": out })
    }

    /// A development build checks the backend now instead of in up to six hours (`POST /v1/remote`).
    pub async fn remote_now(self: &Arc<Self>) {
        self.remote.force();
        self.remote_tick().await;
    }

    /// The UI showed or a person pressed an ad: counted only with the consent to the ads' counts.
    pub fn ad_event(&self, id: &str, click: bool) {
        if self.settings().consent_ads {
            self.remote.count_ad(id, click);
        }
    }

    /// Stop the core and give up the ports before another process (elevated relaunch) takes over.
    /// Returns whether the user was connected, so a cancelled relaunch can restore that.
    pub async fn release(self: &Arc<Self>) -> Result<bool> {
        let _g = self.op.lock().await;
        #[cfg(target_os = "macos")]
        if self.handoff_prepared() { return Err(Error::msg("an exit or update is already in progress")); }
        let was_connected = self.settings().connected;
        #[cfg(target_os = "macos")]
        let was_running = self.running();
        self.stop_core_locked().await?;
        #[cfg(target_os = "macos")]
        { *self.handoff.lock().unwrap() = Some((was_connected, was_running)); }
        self.emit_state();
        Ok(was_connected)
    }

    /// Cancel a prepared update or relaunch and return the state to restore.
    #[cfg(target_os = "macos")]
    pub async fn cancel_handoff(&self) -> Option<(bool, bool)> {
        let _g = self.op.lock().await;
        self.handoff.lock().unwrap().take()
    }

    #[cfg(target_os = "macos")]
    pub fn handoff_prepared(&self) -> bool { self.handoff.lock().unwrap().is_some() }

    /// Attach only after the launcher authenticates the privileged endpoint.
    /// This does not enable capture while the preview gate is in place.
    #[cfg(target_os = "macos")]
    pub(crate) async fn attach_proxy_guard(&self, guard: Arc<crate::macos_proxy_session::GuardSession>) -> Result<()> {
        let _operation = self.op.lock().await;
        if self.handoff_prepared() || self.recovery_required.load(SeqCst) {
            return Err(Error::msg("proxy recovery or app exit is in progress"));
        }
        if !matches!(std::fs::symlink_metadata(self.paths.sysproxy_backup()), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
            self.legacy_recovery_required.store(true, SeqCst);
            self.recovery_required.store(true, SeqCst);
            return Err(Error::msg("legacy proxy recovery is required"));
        }
        let mut slot = self.proxy_guard.lock().map_err(|_| Error::msg("proxy guard state unavailable"))?;
        if slot.is_some() { return Err(Error::msg("proxy guard is already attached")); }
        *slot = Some(guard);
        Ok(())
    }

    /// Prepare an authenticated guard session. This is deliberately separate
    /// from the preview connect gate and cannot by itself change the proxy.
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    pub async fn prepare_macos_proxy_guard(&self) -> Result<()> {
        let _prepare = self.proxy_guard_prepare.lock().await;
        if self.handoff_prepared() || self.recovery_required.load(SeqCst) {
            return Err(Error::msg("proxy recovery or app exit is in progress"));
        }
        if self.proxy_guard.lock().map_err(|_| Error::msg("proxy guard state unavailable"))?.is_some() {
            return Ok(());
        }
        let guard = tokio::task::spawn_blocking(|| {
            crate::macos_helper_payload::preflight_current_bundle()?;
            // First use installs only the app's fixed, build-pinned helper.
            // An interrupted or partial installation must be repaired rather
            // than overwritten or silently accepted.
            let installed = |path: &str| -> std::result::Result<bool, String> {
                match std::fs::symlink_metadata(path) {
                    Ok(meta) if meta.file_type().is_file() => Ok(true),
                    Ok(_) => Err("invalid installed macOS helper".into()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(_) => Err("cannot inspect installed macOS helper".into()),
                }
            };
            let guard_installed = installed("/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard")?;
            let bridge_installed = installed("/Library/PrivilegedHelperTools/dev.prismroute.proxy-bridge")?;
            match (guard_installed, bridge_installed) {
                (false, false) => crate::macos_installer_client::install_from_bundle()?,
                (true, true) => {
                    let guard_pin = option_env!("PRISM_GUARD_SHA256").ok_or("guard build pin is not configured")?;
                    let bridge_pin = option_env!("PRISM_BRIDGE_SHA256").ok_or("bridge build pin is not configured")?;
                    let guard_matches = crate::macos_helper_payload::read_verified(
                        std::path::Path::new("/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard"), guard_pin,
                    ).is_ok();
                    let bridge_matches = crate::macos_helper_payload::read_verified(
                        std::path::Path::new("/Library/PrivilegedHelperTools/dev.prismroute.proxy-bridge"), bridge_pin,
                    ).is_ok();
                    if !guard_matches || !bridge_matches || !crate::macos_proxy_session::GuardSession::native_peer_ready()? {
                        crate::macos_installer_client::install_from_bundle()?;
                    }
                },
                _ => return Err("macOS helper installation is incomplete; repair is required".into()),
            }
            crate::macos_proxy_session::GuardSession::open_native(Duration::from_secs(10))
        })
            .await.map_err(|e| Error::msg(format!("proxy guard launch failed: {e}")))?
            .map_err(Error::msg)?;
        self.attach_proxy_guard(Arc::new(guard)).await
    }

    #[cfg(target_os = "macos")]
    fn ensure_macos_preview_can_connect(&self) -> Result<()> {
        // Actual capture is permitted only in an explicitly opted-in local
        // integration build. Ordinary macOS builds retain the preview gate.
        if self.recovery_required.load(SeqCst) { return Err(Error::msg("system proxy recovery is required")); }
        if self.handoff_prepared() { return Err(Error::msg("an exit or update is in progress")); }
        #[cfg(feature = "macos-proxy-integration-preview")]
        if self.settings().method == Method::SystemProxy { return Ok(()); }
        #[cfg(feature = "macos-tun-integration")]
        if self.settings().method == Method::Tun { return Ok(()); }
        Err(Error::msg("connection is not available in the macOS preview"))
    }

    /// Restore the system proxy before anything stops the listener. macOS failures keep
    /// the core alive and leave the recovery error visible; Windows retains its prior behavior.
    async fn restore_proxy_for_stop(&self) -> Result<()> {
        let backup = self.paths.sysproxy_backup();
        let addr = self.settings().proxy_addr();
        #[cfg(target_os = "macos")]
        {
            let guard = self.proxy_guard.lock().map_err(|_| Error::msg("proxy guard state unavailable"))?.clone();
            if let Some(guard) = guard {
                if self.legacy_recovery_required.load(SeqCst)
                    || !matches!(std::fs::symlink_metadata(&backup), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
                    let e = Error::msg("legacy proxy recovery is required; the backup was retained");
                    self.legacy_recovery_required.store(true, SeqCst);
                    self.recovery_required.store(true, SeqCst);
                    self.set_error(format!("System proxy recovery required: {e}"));
                    self.emit_state();
                    return Err(e);
                }
                let result = tokio::task::spawn_blocking(move || guard.restore()).await
                    .map_err(|e| Error::msg(format!("proxy recovery failed: {e}")))
                    .and_then(|result| result.map_err(Error::msg));
                return match result {
                    Ok(()) => {
                        if let Ok(mut owner) = self.proxy_guard_core.lock() { *owner = None; }
                        if let Ok(mut location) = self.proxy_location.lock() { *location = None; }
                        if self.recovery_required.swap(false, SeqCst) { *self.last_error.lock().unwrap() = None; }
                        Ok(())
                    }
                    Err(e) => {
                        self.recovery_required.store(true, SeqCst);
                        self.set_error(format!("System proxy recovery required: {e}"));
                        self.emit_state();
                        Err(e)
                    }
                };
            }
            // This preview has no platform recovery implementation. Once an incomplete
            // recovery has been observed, deleting its backup is not proof that the system
            // settings are safe. Keep the failure visible until a verified recovery exists.
            if self.recovery_required.load(SeqCst) {
                let e = Error::msg("System proxy recovery is unavailable in this preview; verify the macOS network settings");
                self.set_error(format!("System proxy recovery required: {e}"));
                self.emit_state();
                return Err(e);
            }
            let result = tokio::task::spawn_blocking(move || sysproxy::disable(&backup, &addr))
                .await.map_err(|e| Error::msg(format!("proxy recovery failed: {e}")))
                .and_then(|r| r);
            match result {
                Ok(()) => {
                    if self.recovery_required.swap(false, SeqCst) { *self.last_error.lock().unwrap() = None; }
                    Ok(())
                }
                Err(e) => {
                    self.recovery_required.store(true, SeqCst);
                    self.set_error(format!("System proxy recovery required: {e}"));
                    self.emit_state();
                    Err(e)
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        { let _ = sysproxy::disable(&backup, &addr); Ok(()) }
    }

    /// Retry recovery without stopping a still-running core.
    pub async fn retry_proxy_recovery(&self) -> Result<()> {
        let _g = self.op.lock().await;
        let result = self.restore_proxy_for_stop().await;
        self.emit_state();
        result
    }

    /// Cleanup on app exit: never leave a dead system proxy or an orphaned core behind.
    pub fn shutdown(&self) {
        self.expected_running.store(false, SeqCst);
        #[cfg(not(target_os = "macos"))]
        {
        let s = self.settings();
        let _ = sysproxy::disable(&self.paths.sysproxy_backup(), &s.proxy_addr());
        }
        #[cfg(target_os = "macos")]
        if !self.handoff_prepared() {
            warn!("app exited without guarded proxy recovery; recovery on next start may be required");
        }
        self.abort_streams();
        if let Some(h) = self.monitor.lock().unwrap().take() {
            h.abort();
        }
        self.tg.lock().unwrap().take();
        self.stop_dpi();
        self.core.stop();
        self.stop_xray();
        // leaving on purpose: no marker is left for the next start to count as a crash
        self.metrics.end_session();
    }

    fn abort_streams(&self) {
        for h in self.stream_tasks.lock().unwrap().drain(..) {
            h.abort();
        }
    }

    /// Every half a minute: memory and processor load of the app and of the cores, and a write of the statistics.
    /// On Windows the app counts with the WebView2 processes of its window (its drawing happens there); on
    /// Android the WebView's page process belongs to another user and cannot be read, but the drawing itself
    /// (the GPU and compositor threads) runs inside the app's own process.
    fn sample_resources(&self) {
        {
            let mut last = self.last_sample.lock().unwrap();
            if last.elapsed() < Duration::from_secs(30) {
                return;
            }
            *last = Instant::now();
        }
        let (core, xray) = (self.core.pid(), self.xray.pid());
        #[allow(unused_mut)]
        let mut app = vec![std::process::id()];
        #[cfg(windows)]
        app.extend(crate::metrics::descendants(std::process::id()).into_iter().filter(|p| Some(*p) != core && Some(*p) != xray));
        self.sampler.take(&self.metrics, "app", &app);
        if let Some(pid) = core {
            self.sampler.take(&self.metrics, "core", &[pid]);
        }
        if let Some(pid) = xray {
            self.sampler.take(&self.metrics, "xray", &[pid]);
        }
        self.metrics.flush();
    }

    fn spawn_monitor(self: &Arc<Self>) {
        let mut slot = self.monitor.lock().unwrap();
        if slot.is_some() {
            return;
        }
        let me = self.clone();
        *slot = Some(tokio::spawn(async move {
            #[cfg(target_os = "macos")]
            let mut proxy_ticks = 0u8;
            #[cfg(target_os = "macos")]
            let mut proxy_failures = 0u8;
            loop {
                #[cfg(target_os = "macos")]
                tokio::time::sleep(Duration::from_millis(250)).await;
                #[cfg(not(target_os = "macos"))]
                tokio::time::sleep(Duration::from_secs(2)).await;
                #[cfg(target_os = "macos")]
                let orphaned_proxy = !me.recovery_required.load(SeqCst) && me.proxy_guard_orphaned();
                #[cfg(not(target_os = "macos"))]
                let orphaned_proxy = false;
                if orphaned_proxy || (me.expected_running.load(SeqCst) && me.core.pid().is_none()) {
                    me.handle_core_exit().await;
                } else if me.expected_running.load(SeqCst) && me.xray.pid().is_none() && me.xray_run.lock().unwrap().is_some() {
                    me.revive_xray().await;
                }
                if me.dpi_alive.load(SeqCst) && me.zapret.pid().is_none() && me.zapret_find.lock().unwrap().is_none() {
                    me.revive_dpi().await;
                }
                me.sample_resources();
                #[cfg(target_os = "macos")]
                {
                    proxy_ticks += 1;
                    if proxy_ticks >= 8 {
                        proxy_ticks = 0;
                        proxy_failures = me.poll_macos_proxy_integrity(proxy_failures).await;
                    }
                }
            }
        }));
    }

    /// A user or macOS can change network locations, services, bypass rules or
    /// effective proxy settings while the core remains alive. Never continue
    /// reporting an active capture after those settings stop matching ours.
    #[cfg(target_os = "macos")]
    async fn poll_macos_proxy_integrity(&self, failures: u8) -> u8 {
        // Never inspect during a deliberate connect, disconnect or settings
        // update. Recheck under the operation lock before taking action.
        let Ok(_operation) = self.op.try_lock() else { return 0 };
        let settings = self.settings();
        if !settings.connected || settings.method != Method::SystemProxy || self.recovery_required.load(SeqCst) {
            return 0;
        }
        let expected = self.proxy_location.lock().ok().and_then(|location| location.clone());
        let server = settings.proxy_addr();
        let bypass = settings.sysproxy_bypass;
        let check = tokio::task::spawn_blocking(move || {
            expected.is_some_and(|expected| {
                crate::sysproxy_macos_read::current_location_id().is_ok_and(|current| current == expected)
                    && crate::sysproxy_macos::active_configuration_matches(&server, &bypass)
            })
        });
        let healthy = matches!(tokio::time::timeout(Duration::from_secs(5), check).await, Ok(Ok(true)));
        if healthy { return 0; }
        // Require two independent observations to tolerate transient reads
        // while macOS propagates a network settings change.
        if failures == 0 { return 1; }
        self.settings.write().unwrap().connected = false;
        let restore = self.restore_proxy_for_stop().await;
        let _ = self.save_settings();
        match restore {
            Ok(()) => self.set_error("System proxy stopped because network settings changed; reconnect to continue"),
            Err(error) => self.set_error(format!("System proxy recovery required after network settings changed: {error}")),
        }
        self.emit_state();
        0
    }

    /// A live replacement is not the owner of an older proxy capture. Busy
    /// guard requests are rechecked after completion instead of blocking here.
    #[cfg(target_os = "macos")]
    fn proxy_guard_orphaned(&self) -> bool {
        use crate::macos_proxy_client::State;
        let guard = match self.proxy_guard.lock() { Ok(slot) => slot.clone(), Err(_) => return true };
        let Some(guard) = guard else { return false };
        match guard.try_state() {
            Ok(Some(State::Active(_) | State::Uncertain)) | Err(_) => {},
            Ok(_) => return false,
        }
        match self.proxy_guard_core.lock() {
            Ok(owner) => owner.as_ref().is_none_or(|identity| !self.core.identity_is_running(identity)),
            Err(_) => true,
        }
    }

    async fn handle_core_exit(self: &Arc<Self>) {
        let _g = self.op.lock().await;
        let running = self.core.pid().is_some();
        #[cfg(target_os = "macos")]
        let orphaned_proxy = !self.recovery_required.load(SeqCst) && self.proxy_guard_orphaned();
        #[cfg(not(target_os = "macos"))]
        let orphaned_proxy = false;
        if running && !orphaned_proxy { return; }
        if !running && !self.expected_running.swap(false, SeqCst) && !orphaned_proxy { return; }
        let tail = self.log_tail(6);
        if !running {
            warn!("core exited unexpectedly\n{tail}");
            self.metrics.count(&format!("{}.mihomo", metrics::name::CORE_EXIT));
            self.metrics.event("core_exit", "mihomo");
            self.abort_streams();
            self.stop_xray();
            self.tun_on.store(false, SeqCst);
            #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
            if let Err(error) = self.close_macos_tun_guard().await {
                warn!("could not close TUN helper after core exit: {error}");
            }
        }
        let restore = self.restore_proxy_for_stop().await;
        self.settings.write().unwrap().connected = false;
        let _ = self.save_settings();
        self.resume_zapret().await;
        #[cfg(target_os = "android")]
        if !running {
            let vpn = self.android.lock().unwrap().clone();
            if let Some(vpn) = vpn {
                let _ = vpn.stop().await;
            }
        }
        if let Err(e) = restore {
            self.set_error(format!("Core stopped unexpectedly; system proxy recovery required: {e}"));
        } else if running {
            self.set_error("System proxy was restored because its core instance changed");
        } else {
            self.set_error(format!("Core stopped unexpectedly. {}", mihomo::summarize_error(&tail)));
        }
        self.emit_state();
    }

    fn spawn_streams(self: &Arc<Self>) {
        self.abort_streams();
        let me = self.clone();
        let h = tokio::spawn(async move {
            while me.core.pid().is_some() {
                let emit = me.emit.clone();
                let ctl = me.controller();
                let _ = ctl
                    .stream(&me.stream_http, "/traffic", move |line| {
                        if let Ok(v) = serde_json::from_str::<Value>(line) {
                            emit("traffic", v);
                        }
                    })
                    .await;
                tokio::time::sleep(Duration::from_millis(800)).await;
            }
        });
        self.stream_tasks.lock().unwrap().push(h);
    }

    // ---------------------------------------------------------------- config & core

    /// `with_xray: false` builds the config for mihomo alone (the fallback when Xray fails).
    /// Windows may reserve blocks of ports at any start of the system (Hyper-V, WSL and Docker take them from the
    /// dynamic range, which can begin at 1024): a port the core listened on yesterday is refused today with "an
    /// attempt was made to access a socket in a way forbidden by its access permissions", and without its
    /// controller the app cannot drive the core at all. Before the core starts, such a port is swapped for one the
    /// system hands out, and the settings keep it. A port another program holds is left as it is: that conflict is
    /// shown to the user, not hidden.
    fn swap_reserved_ports(&self) {
        let (mixed, controller) = {
            let s = self.settings.read().unwrap();
            (s.mixed_port, s.controller_port)
        };
        // the listeners stay open until both ports are picked, so the two never get the same one
        let mut held = Vec::new();
        let mut pick = |port: u16| -> Option<u16> {
            match std::net::TcpListener::bind(("127.0.0.1", port)) {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
                    let p = l.local_addr().ok()?.port();
                    held.push(l);
                    Some(p)
                }
                _ => None,
            }
        };
        let (new_controller, new_mixed) = (pick(controller), pick(mixed));
        if new_controller.is_none() && new_mixed.is_none() {
            return;
        }
        {
            let mut s = self.settings.write().unwrap();
            if let Some(p) = new_controller {
                warn!("port {controller} is reserved by the system; the core's controller moves to {p}");
                s.controller_port = p;
            }
            if let Some(p) = new_mixed {
                warn!("port {mixed} is reserved by the system; the proxy moves to {p}");
                s.mixed_port = p;
            }
        }
        drop(held);
        if let Err(e) = self.save_settings() {
            warn!("the new ports are used but not saved: {e}");
        }
    }

    fn build_config(&self, with_xray: bool, refused: &BTreeMap<String, String>) -> Result<config::Built> {
        let s = self.settings();
        // the free mode uses the core only to filter (ads now, the DPI engine later): no profile, no VPN
        let free = s.app_mode == crate::settings::AppMode::FreeAntiDpi;
        let active = if free { None } else { s.active_profile.clone() };
        let yaml = active.as_deref().and_then(|id| self.profiles.lock().unwrap().read(id).ok());
        let chains = self.chains.lock().unwrap().items().to_vec();
        let rules = self.rules.lock().unwrap().items().to_vec();
        let run = if with_xray && !free { self.xray_plan_input(&s, refused) } else { None };
        let mut built = config::build_all(
            yaml.as_deref(),
            active.as_deref(),
            &s,
            &chains,
            &rules,
            self.tun_on.load(SeqCst),
            run.as_ref(),
        )?;
        if s.adblock && self.ads_more_file().is_file() {
            built.yaml = config::with_more_ads(&built.yaml)?;
        }
        // "Games": Roblox's pictures found, Supercell's games through the gaming DNS, direct, in every mode
        if s.games_dns {
            built.yaml = config::with_games(&built.yaml, &self.remote.doc().settings.game_sites, &crate::builtin::get().games_dns)?;
        }
        // AI services through the public AI proxy, in the free mode only: with a VPN they go through the VPN
        if free && s.ai_access {
            built.yaml = config::with_ai(&built.yaml, &self.remote.doc().settings.ai_sites, &crate::builtin::get().ai_proxies)?;
        }
        // the DPI engine (Android, macOS) gets YouTube, Discord and the user's sites in the free mode
        if free && !cfg!(windows) && self.zapret.pid().is_some() {
            let sites: Vec<String> = crate::byedpi::SITES.iter().map(|d| d.to_string()).chain(s.zapret.domains.iter().cloned()).collect();
            built.yaml = config::with_dpi(&built.yaml, crate::byedpi::PORT, &sites)?;
        }
        Ok(built)
    }

    /// The bigger ad list, packed by the core (see [`config::ADS_MORE`]).
    fn ads_more_file(&self) -> PathBuf {
        self.paths.runtime_dir().join("ruleset").join(format!("{}.mrs", config::ADS_MORE))
    }

    /// Download the bigger ad list when it is missing or older than half a day, have the core pack it, and
    /// let the running core read it: a new rule set needs a reload, a refreshed one only a provider update.
    fn spawn_ads_more(self: &Arc<Self>) {
        let file = self.ads_more_file();
        let fresh = file.metadata().and_then(|m| m.modified()).is_ok_and(|t| t.elapsed().unwrap_or_default() < Duration::from_secs(12 * 3600));
        if fresh || self.ads_more_busy.swap(true, SeqCst) {
            return;
        }
        let m = self.clone();
        tokio::spawn(async move {
            let had = file.is_file();
            let got = m.fetch_ads_more(&file).await;
            m.ads_more_busy.store(false, SeqCst);
            let n = match got {
                Ok(n) => n,
                Err(e) => return warn!("adblock: the bigger list did not download: {e}"),
            };
            info!("adblock: {n} more domains from HaGeZi's list");
            if !m.running() || !m.settings().adblock {
                return;
            }
            let r = if had {
                m.controller().request("PUT", &format!("/providers/rules/{}", config::ADS_MORE), None).await.map(drop)
            } else {
                let _g = m.op.lock().await;
                m.reload_locked().await
            };
            if let Err(e) = r {
                warn!("adblock: {e}");
            }
        });
    }

    async fn fetch_ads_more(&self, file: &std::path::Path) -> Result<usize> {
        let text = self.http.get(config::ADS_MORE_URL).timeout(Duration::from_secs(90)).send().await?.error_for_status()?.text().await?;
        let mut list = String::with_capacity(text.len() + text.len() / 8);
        let mut n = 0;
        // one plain name per line, its subdomains included
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            if crate::zapret::clean_domain(line).as_deref() == Some(line) {
                list.push_str("+.");
                list.push_str(line);
                list.push('\n');
                n += 1;
            }
        }
        if n < 1000 {
            return Err(Error::msg("the list came back nearly empty"));
        }
        let dir = file.parent().ok_or_else(|| Error::msg("no folder for the list"))?;
        std::fs::create_dir_all(dir)?;
        let txt = dir.join(format!("{}.txt", config::ADS_MORE));
        let part = dir.join(format!("{}.part", config::ADS_MORE));
        crate::util::write_atomic(&txt, list.as_bytes())?;
        let mut cmd = tokio::process::Command::new(self.resolve_core()?);
        cmd.args(["convert-ruleset", "domain", "text"]).arg(&txt).arg(&part);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let out = cmd.output().await;
        let _ = std::fs::remove_file(&txt);
        let out = out?;
        if !out.status.success() || !part.is_file() {
            return Err(Error::msg(format!("the core did not pack the list: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        std::fs::rename(&part, file)?;
        Ok(n)
    }

    /// The DPI engine bundled with this build: byedpi on Android (next to the core) and macOS (inside the
    /// app). Windows uses Zapret instead.
    fn dpi_engine(&self) -> Option<PathBuf> {
        #[cfg(target_os = "android")]
        let bin = self.settings().core_path.map(PathBuf::from).and_then(|core| core.parent().map(|d| d.join("libbyedpi.so")));
        #[cfg(target_os = "macos")]
        let bin = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|d| d.join("byedpi")));
        #[cfg(not(any(target_os = "android", target_os = "macos")))]
        let bin: Option<PathBuf> = None;
        bin.filter(|p| p.is_file())
    }

    /// Is the bypass ready to run: Zapret downloaded (Windows) or the engine bundled (Android, macOS).
    fn dpi_installed(&self) -> bool {
        if cfg!(windows) { crate::zapret::version(&self.paths.zapret_dir()).is_some() } else { self.dpi_engine().is_some() }
    }

    fn dpi_strategies(&self) -> Vec<crate::zapret::Strategy> {
        if cfg!(windows) {
            crate::zapret::strategies(&self.paths.zapret_dir(), self.settings().zapret.game_filter)
        } else if self.dpi_engine().is_some() {
            crate::byedpi::strategies()
        } else {
            vec![]
        }
    }

    /// The bypass on or off, and on Android and macOS the core's route to the engine with it.
    pub async fn set_dpi(self: &Arc<Self>, on: bool) -> Result<()> {
        let before = self.zapret.pid().is_some();
        let r = self.set_zapret(on).await;
        // a new strategy restarts the engine on the same port: the core's route only changes when it comes or goes
        if before != self.zapret.pid().is_some() {
            self.reroute_dpi().await;
        }
        r
    }

    /// The free mode's big button. On: the tools the user chose start, the Telegram bridge first (so it is on and
    /// remembered if the DPI engine then needs administrator rights), then the DPI engine, then the core when its
    /// filters or, off Windows, the engine need it. Off: all of them stop, and the choices stay as they were, so the
    /// next press brings back exactly what was chosen.
    pub async fn set_free(self: &Arc<Self>, on: bool) -> Result<()> {
        {
            let mut s = self.settings.write().unwrap();
            s.free_on = on;
            if s.tg.secret.is_empty() {
                s.tg.secret = crate::tgbridge::new_secret();
            }
        }
        self.save_settings()?;
        let s = self.settings();
        if !on {
            self.tg.lock().unwrap().take();
            *self.tg_error.lock().unwrap() = None;
            self.stop_dpi();
            let r = if s.connected { self.disconnect().await } else { Ok(()) };
            self.emit_state();
            return r;
        }
        if s.tg.enabled {
            if let Err(e) = self.start_tg().await {
                warn!("telegram bridge: {e}");
            }
        }
        let dpi = s.zapret.enabled && self.dpi_installed();
        let engine = if dpi { self.set_dpi(true).await } else { Ok(()) };
        // administrator rights: the app restarts elevated and its start brings the rest up
        if matches!(engine, Err(Error::NeedAdmin)) {
            self.emit_state();
            return engine;
        }
        // a strategy that failed still leaves the filters (ads, AI, games) to run
        let need_core = s.adblock || s.ai_access || s.games_dns || (dpi && engine.is_ok() && !cfg!(windows));
        let core = if need_core && !self.settings().connected { self.connect().await } else { Ok(()) };
        self.emit_state();
        engine.and(core)
    }

    /// The auto-search, then the core's route to the engine that won.
    pub async fn find_dpi(self: &Arc<Self>) -> Result<String> {
        let before = self.zapret.pid().is_some();
        let r = self.zapret_find().await;
        if before != self.zapret.pid().is_some() {
            self.reroute_dpi().await;
        }
        r
    }

    /// Android and macOS: the engine came or went while the free mode captures traffic: the core's config
    /// follows (the route to the engine is in it only while the engine runs).
    async fn reroute_dpi(self: &Arc<Self>) {
        let s = self.settings();
        if cfg!(windows) || !s.connected || vpn_on(&s) {
            return;
        }
        let _g = self.op.lock().await;
        if let Err(e) = self.reload_locked().await {
            warn!("dpi route: {e}");
        }
    }

    /// The config with the Xray helper brought up to match it.
    ///
    /// The core checks the whole config and one server it dislikes spoils it for all. It names that
    /// server, so the server is left to mihomo and the rest is tried again. When Xray cannot do
    /// its part at all, the config is built for mihomo alone: the connection works, the issue is
    /// shown.
    async fn build_and_sync_xray(&self) -> Result<config::Built> {
        let mut refused: BTreeMap<String, String> = BTreeMap::new();
        for _ in 0..10 {
            let built = self.build_config(true, &refused)?;
            if built.xray.is_none() && self.xray_run.lock().unwrap().is_none() {
                return Ok(built);
            }
            let err = match self.sync_xray_locked(&built).await {
                Ok(()) => return Ok(built),
                Err(e) => e.to_string(),
            };
            let culprit = built
                .xray
                .as_ref()
                .and_then(|x| x.tags.get(&xray::failing_tag(&err)?).cloned())
                .filter(|name| !refused.contains_key(name));
            let Some(name) = culprit else {
                warn!("xray: {err}");
                self.stop_xray();
                self.set_xray_issue(Some(format!("failed: {err}")));
                return self.build_config(false, &refused);
            };
            warn!("xray refused “{name}”: {err}");
            refused.insert(name, err);
        }
        self.stop_xray();
        self.set_xray_issue(Some("failed: Xray turned down too many servers".into()));
        self.build_config(false, &refused)
    }

    async fn validate(&self, bin: &Path, cfg: &Path) -> Result<()> {
        let (b, h, c) = (bin.to_path_buf(), self.paths.runtime_dir(), cfg.to_path_buf());
        tokio::task::spawn_blocking(move || mihomo::validate(&b, &h, &c))
            .await
            .map_err(|e| Error::msg(e.to_string()))?
    }

    async fn start_core_locked(self: &Arc<Self>) -> Result<()> {
        #[cfg(target_os = "macos")]
        if self.handoff_prepared() || self.recovery_required.load(SeqCst) {
            return Err(Error::msg("proxy recovery or app exit is in progress"));
        }
        if self.running() {
            return Ok(());
        }
        let bin = self.resolve_core()?;
        *self.geodata_missing.lock().unwrap() = discover::ensure_geodata(&bin, &self.paths);
        self.log_ring.lock().unwrap().clear();
        self.stop_xray();
        self.swap_reserved_ports();
        let built = self.build_and_sync_xray().await?;
        let r = self.launch_mihomo(&bin, &built).await;
        if r.is_err() {
            self.stop_xray();
        }
        r
    }

    /// Write the config, check it with the core, start the core and wait for its controller.
    async fn launch_mihomo(self: &Arc<Self>, bin: &Path, built: &config::Built) -> Result<()> {
        let cfg = self.paths.runtime_config();
        crate::util::write_atomic(&cfg, built.yaml.as_bytes())?;
        self.validate(bin, &cfg).await?;
        *self.build_info.lock().unwrap() = built.info.clone();
        let pid = self.core.start(bin, &self.paths.runtime_dir(), &cfg, self.sink())?;
        info!("mihomo started, pid {pid}");
        // generous: the core downloads rule/proxy providers before it opens the controller
        if !self.controller().wait_ready(Duration::from_secs(40)).await {
            let tail = self.log_tail(8);
            self.core.stop();
            return Err(Error::msg(if tail.is_empty() {
                "core did not become ready".to_string()
            } else {
                mihomo::summarize_error(&tail)
            }));
        }
        self.expected_running.store(true, SeqCst);
        self.spawn_streams();
        *self.last_error.lock().unwrap() = None;
        Ok(())
    }

    /// Android: bring the connection up. The tunnel lives only while the core holds its descriptor, so
    /// the service opens the tunnel first and the core starts after it; a core that already runs
    /// without a tunnel (to browse servers) is replaced.
    #[cfg(target_os = "android")]
    async fn connect_android_locked(self: &Arc<Self>) -> Result<()> {
        let vpn = self
            .android
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::msg("the VPN service is not available"))?;
        let bin = self.resolve_core()?;
        if self.running() {
            self.stop_core_locked().await?;
        }
        self.log_ring.lock().unwrap().clear();
        self.tun_on.store(true, SeqCst);
        self.swap_reserved_ports();
        let result: Result<()> = async {
            // Xray is not part of the Android app (yet): mihomo runs every server
            let built = self.build_config(false, &BTreeMap::new())?;
            let s = self.settings();
            // the free mode: the tunnel takes only what the core works on (see config::fake_ip_only_for_core)
            let only = if s.app_mode == crate::settings::AppMode::FreeAntiDpi { config::fake_ip_only_for_core(&built.yaml)? } else { None };
            let fd = vpn
                .establish(crate::android::VpnParams { mtu: config::ANDROID_MTU, address: "198.18.0.1".into(), prefix: 30, dns: "198.18.0.2".into(), split: only.is_some() })
                .await?;
            let yaml = config::configure_android_tun(only.as_deref().unwrap_or(&built.yaml), fd)?;
            let cfg = self.paths.runtime_config();
            crate::util::write_atomic(&cfg, yaml.as_bytes())?;
            self.validate(&bin, &cfg).await?;
            *self.build_info.lock().unwrap() = built.info.clone();
            let pid = self.core.start_with_fd(&bin, &self.paths.runtime_dir(), &cfg, self.sink(), fd)?;
            info!("mihomo started with the VPN tunnel, pid {pid}");
            if !self.controller().wait_ready(Duration::from_secs(40)).await {
                let tail = self.log_tail(8);
                return Err(Error::msg(if tail.is_empty() { "core did not become ready".to_string() } else { mihomo::summarize_error(&tail) }));
            }
            self.expected_running.store(true, SeqCst);
            self.spawn_streams();
            Ok(())
        }
        .await;
        if result.is_err() {
            self.core.stop();
            self.tun_on.store(false, SeqCst);
            let _ = vpn.stop().await;
        }
        result
    }

    /// Android: close the tunnel (stopping the core is what closes it) and start the plain core again, so
    /// the servers stay visible and testable.
    #[cfg(target_os = "android")]
    async fn disconnect_android_locked(self: &Arc<Self>) -> Result<()> {
        self.stop_core_locked().await?;
        let vpn = self.android.lock().unwrap().clone();
        if let Some(vpn) = vpn {
            let _ = vpn.stop().await;
        }
        if self.settings().auto_start_core {
            if let Err(e) = self.start_core_locked().await {
                self.set_error(&e);
            }
        }
        Ok(())
    }

    /// Start a fresh core with an authenticated, preconfigured utun. Routing
    /// is activated only after the controller is ready. The public connect
    /// gate remains closed until the complete path is validated on macOS.
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    async fn start_macos_tun_locked(self: &Arc<Self>) -> Result<()> {
        use std::os::fd::AsFd;
        if self.running() { self.stop_core_locked().await?; }
        self.restore_proxy_for_stop().await?;
        // Proxy and TUN sessions both hold the guard's exclusive lock.
        let old = self.proxy_guard.lock().map_err(|_| Error::msg("proxy guard state unavailable"))?.clone();
        if let Some(guard) = old {
            tokio::task::spawn_blocking(move || guard.shutdown()).await
                .map_err(|e| Error::msg(format!("cannot close proxy guard: {e}")))?.map_err(Error::msg)?;
            *self.proxy_guard.lock().map_err(|_| Error::msg("proxy guard state unavailable"))? = None;
        }
        let bin = self.resolve_core()?;
        *self.geodata_missing.lock().unwrap() = discover::ensure_geodata(&bin, &self.paths);
        self.log_ring.lock().unwrap().clear();
        self.stop_xray();
        self.tun_on.store(true, SeqCst);
        self.swap_reserved_ports();
        let result = async {
            let built = self.build_and_sync_xray().await?;
            // Xray is a separate process and cannot use mihomo's physical
            // interface binding. Its outbound traffic could loop into TUN.
            if built.xray.is_some() { return Err(Error::msg("TUN cannot use the Xray sidecar on macOS yet")); }
            let outbound = tokio::task::spawn_blocking(crate::tun_macos::default_outbound_interface)
                .await.map_err(|_| Error::msg("cannot inspect the default outbound interface"))??;
            // Remember network properties before installing any capture
            // routes, so changes during startup are detected as well.
            let network = tokio::task::spawn_blocking(crate::tun_macos::tun_network_snapshot)
                .await.map_err(|_| Error::msg("cannot inspect network settings"))??;
            let yaml = config::configure_preopened_tun(&built.yaml, mihomo::MACOS_TUN_CORE_FD,
                crate::tun_macos_interface::TunInterfacePlan::experimental_ipv4())?;
            let yaml = config::bind_macos_tun_outbound(&yaml, &outbound)?;
            let cfg = self.paths.runtime_config();
            crate::util::write_atomic(&cfg, yaml.as_bytes())?;
            self.validate(&bin, &cfg).await?;
            let (core_channel, helper_channel) = std::os::unix::net::UnixStream::pair()?;
            let guard = tokio::task::spawn_blocking(move || {
                crate::macos_helper_payload::preflight_current_bundle()?;
                crate::macos_proxy_session::GuardSession::open_native_tun(Duration::from_secs(10), helper_channel.as_fd())
            }).await.map_err(|e| Error::msg(format!("TUN authorization failed: {e}")))?.map_err(Error::msg)?;
            let guard = Arc::new(guard);
            *self.tun_guard.lock().map_err(|_| Error::msg("TUN guard state unavailable"))? = Some(guard.clone());
            let manager = self.clone();
            let sink = self.sink();
            let mut command = std::process::Command::new(&bin);
            command.arg("-d").arg(self.paths.runtime_dir()).arg("-f").arg(&cfg);
            let (pid, name) = tokio::task::spawn_blocking(move || {
                crate::tun_macos_handoff::start(&manager.core, &guard, command, sink, core_channel)
            }).await.map_err(|e| Error::msg(format!("TUN startup failed: {e}")))?.map_err(Error::msg)?;
            *self.tun_device.lock().map_err(|_| Error::msg("TUN device state unavailable"))? = Some(name.clone());
            info!("mihomo started with {name}, pid {pid}");
            if !self.controller().wait_ready(Duration::from_secs(40)).await {
                return Err(Error::msg(format!("core did not become ready: {}", mihomo::summarize_error(&self.log_tail(8)))));
            }
            let guard = self.tun_guard.lock().map_err(|_| Error::msg("TUN guard state unavailable"))?.clone()
                .ok_or_else(|| Error::msg("TUN guard disappeared"))?;
            let watch_guard = guard.clone();
            let activation = tokio::task::spawn_blocking(move || guard.activate_tun()).await
                .map_err(|e| Error::msg(format!("TUN route activation failed: {e}")))?;
            if let Err(error) = &activation {
                // Only fixed categories are logged: the guard never needs to
                // expose DNS addresses, profile contents or credentials here.
                let stage = match error.as_str() {
                    "IPv6 is active; IPv4-only TUN cannot be enabled safely" => "ipv6_unsupported",
                    "System DNS includes an unsupported or unavailable resolver" => "dns_unsupported",
                    "Could not add TUN routes; another VPN or route may be active" => "route_failed",
                    _ => "guard_channel_failed",
                };
                warn!(stage, "macOS TUN activation failed");
            }
            activation.map_err(Error::msg)?;
            *self.build_info.lock().unwrap() = built.info;
            self.expected_running.store(true, SeqCst);
            self.spawn_streams();
            self.spawn_macos_tun_watch(watch_guard, outbound, network);
            *self.last_error.lock().unwrap() = None;
            Ok(())
        }.await;
        if result.is_err() {
            self.expected_running.store(false, SeqCst);
            self.core.stop();
            self.stop_xray();
            self.tun_on.store(false, SeqCst);
            if let Err(cleanup) = self.close_macos_tun_guard().await {
                return Err(Error::msg(format!("{}; TUN cleanup failed: {cleanup}", result.unwrap_err())));
            }
        }
        result
    }

    /// The core must be stopped first. The guard holds another descriptor so
    /// the utun name cannot be reused; its shutdown closes the last copy.
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    async fn close_macos_tun_guard(&self) -> Result<()> {
        let guard = self.tun_guard.lock().map_err(|_| Error::msg("TUN guard state unavailable"))?.clone();
        let device = self.tun_device.lock().map_err(|_| Error::msg("TUN device state unavailable"))?.clone();
        let mut shutdown_error = None;
        if let Some(guard) = guard {
            shutdown_error = match tokio::task::spawn_blocking(move || guard.shutdown()).await {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(error) => Some(format!("cannot close TUN guard: {error}")),
            };
            // Closing the channel also makes the guard exit on EOF if a
            // shutdown acknowledgement was lost.
            *self.tun_guard.lock().map_err(|_| Error::msg("TUN guard state unavailable"))? = None;
        }
        if let Some(device) = device {
            let deadline = Instant::now() + Duration::from_secs(5);
            while crate::tun_macos::interface_exists(&device) {
                if Instant::now() >= deadline {
                    return Err(Error::msg(format!("TUN interface {device} is still present; routes may need recovery")));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            *self.tun_device.lock().map_err(|_| Error::msg("TUN device state unavailable"))? = None;
            // Once the interface is gone, a lost shutdown acknowledgement
            // cannot leave this interface's routes active.
            return Ok(());
        }
        if let Some(error) = shutdown_error { return Err(Error::msg(error)); }
        Ok(())
    }

    /// If the authenticated helper disappears while the GUI and core live,
    /// tear down the core and interface instead of claiming TUN is connected.
    #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
    fn spawn_macos_tun_watch(self: &Arc<Self>, guard: Arc<crate::macos_proxy_session::GuardSession>, outbound: String, network: crate::tun_macos::TunNetworkSnapshot) {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if !manager.tun_on.load(SeqCst) { return; }
                let current = manager.tun_guard.lock().ok().and_then(|slot| slot.clone());
                if !current.as_ref().is_some_and(|value| Arc::ptr_eq(value, &guard)) { return; }
                let ping = guard.clone();
                let helper_ok = matches!(tokio::task::spawn_blocking(move || ping.check_tun_session()).await, Ok(Ok(())));
                let route_ok = if helper_ok {
                    matches!(tokio::task::spawn_blocking(crate::tun_macos::default_outbound_interface).await,
                        Ok(Ok(current)) if current == outbound)
                } else { false };
                let network_ok = if route_ok {
                    matches!(tokio::task::spawn_blocking(crate::tun_macos::tun_network_snapshot).await,
                        Ok(Ok(current)) if current == network)
                } else { false };
                if helper_ok && route_ok && network_ok { continue; }
                let _operation = manager.op.lock().await;
                let current = manager.tun_guard.lock().ok().and_then(|slot| slot.clone());
                if !manager.tun_on.load(SeqCst) || !current.as_ref().is_some_and(|value| Arc::ptr_eq(value, &guard)) { return; }
                manager.expected_running.store(false, SeqCst);
                manager.abort_streams();
                manager.core.stop();
                manager.stop_xray();
                manager.tun_on.store(false, SeqCst);
                manager.settings.write().unwrap().connected = false;
                let cleanup = manager.close_macos_tun_guard().await;
                let _ = manager.save_settings();
                match cleanup {
                    Ok(()) if !helper_ok => manager.set_error("TUN stopped because its system helper disconnected"),
                    Ok(()) => manager.set_error("TUN stopped because network settings changed; reconnect to continue"),
                    Err(error) => manager.set_error(format!("TUN helper disconnected and cleanup failed: {error}")),
                }
                manager.emit_state();
                return;
            }
        });
    }

    async fn stop_core_locked(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        if self.handoff_prepared() { return Err(Error::msg("an exit or update is in progress")); }
        self.restore_proxy_for_stop().await?;
        self.expected_running.store(false, SeqCst);
        self.abort_streams();
        self.core.stop();
        #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
        self.close_macos_tun_guard().await?;
        self.stop_xray();
        self.tun_on.store(false, SeqCst);
        self.settings.write().unwrap().connected = false;
        let _ = self.save_settings();
        Ok(())
    }

    pub async fn start_core(self: &Arc<Self>) -> Result<()> {
        let _g = self.op.lock().await;
        let r = self.start_core_locked().await;
        if let Err(e) = &r {
            self.set_error(e);
        }
        self.emit_state();
        r
    }

    pub async fn stop_core(self: &Arc<Self>) -> Result<()> {
        let _g = self.op.lock().await;
        self.stop_core_locked().await?;
        self.resume_zapret().await;
        self.emit_state();
        Ok(())
    }

    async fn restart_locked(self: &Arc<Self>) -> Result<()> {
        let was_connected = self.settings().connected;
        self.stop_core_locked().await?;
        #[cfg(all(target_os = "macos", feature = "macos-tun-integration"))]
        if was_connected && self.settings().method == Method::Tun {
            self.start_macos_tun_locked().await?;
            self.settings.write().unwrap().connected = true;
            self.save_settings()?;
            return Ok(());
        }
        self.start_core_locked().await?;
        if was_connected {
            self.apply_method_locked().await?;
            self.settings.write().unwrap().connected = true;
            self.save_settings()?;
        }
        Ok(())
    }

    pub async fn restart_core(self: &Arc<Self>) -> Result<()> {
        let _g = self.op.lock().await;
        let r = self.restart_locked().await;
        if let Err(e) = &r {
            self.set_error(e);
        }
        self.emit_state();
        r
    }

    /// Hot-apply the current profile/settings/chains without dropping the core.
    async fn reload_locked(self: &Arc<Self>) -> Result<()> {
        if !self.running() {
            return Ok(());
        }
        let began = Instant::now();
        let r = self.reload_inner().await;
        match &r {
            Ok(()) => {
                // in the log, so a network hiccup can be set against what the app did at that moment
                info!("core config reloaded in {} ms", began.elapsed().as_millis());
                self.metrics.count(metrics::name::RELOAD_OK);
                self.metrics.millis(metrics::name::RELOAD_MS, began.elapsed());
            }
            Err(e) => self.metrics.failed(metrics::name::RELOAD_FAILED, metrics::classify(Stage::Start, e)),
        }
        r
    }

    async fn reload_inner(self: &Arc<Self>) -> Result<()> {
        if !self.running() {
            return Ok(());
        }
        // A reload would discard the inherited TUN descriptor. Restart the
        // supervised core and reauthorize its replacement instead.
        #[cfg(all(target_os = "macos", feature = "macos-tun-integration"))]
        if self.tun_on.load(SeqCst) { return self.restart_locked().await; }
        // Android too: the core holds the tunnel as a descriptor it was handed at start, and a reloaded config
        // would open that number again after it is gone, leaving the tunnel unread. Connect afresh instead.
        #[cfg(target_os = "android")]
        if self.tun_on.load(SeqCst) { return self.connect_android_locked().await; }
        let bin = self.resolve_core()?;
        let next = self.paths.runtime_dir().join("config.next.yaml");
        // mihomo is asked first: a config it refuses must leave the Xray helper alone, or the
        // helper would no longer match the config the core keeps running
        let probe = self.build_config(true, &BTreeMap::new())?;
        crate::util::write_atomic(&next, probe.yaml.as_bytes())?;
        self.validate(&bin, &next).await?;
        // then Xray: the new mihomo config points at its listener
        let built = self.build_and_sync_xray().await?;
        if built.yaml != probe.yaml {
            // the core turned a server down, so some servers are back to their own form
            crate::util::write_atomic(&next, built.yaml.as_bytes())?;
            self.validate(&bin, &next).await?;
        }
        let cfg = self.paths.runtime_config();
        crate::util::write_atomic(&cfg, built.yaml.as_bytes())?;
        let _ = std::fs::remove_file(&next);
        self.controller()
            .request(
                "PUT",
                "/configs?force=true",
                Some(json!({ "path": cfg.to_string_lossy(), "payload": "" })),
            )
            .await?;
        *self.build_info.lock().unwrap() = built.info;
        *self.last_error.lock().unwrap() = None;
        Ok(())
    }

    // ---------------------------------------------------------------- capture (system proxy / TUN)

    async fn set_tun_locked(&self, on: bool) -> Result<()> {
        #[cfg(target_os = "macos")]
        if on {
            let device = self.settings().tun.device;
            crate::tun_macos::validate_device(&device)?;
            if crate::tun_macos::interface_exists(&device) {
                return Err(Error::msg(format!("TUN interface '{device}' already exists")));
            }
        }
        #[cfg(not(windows))]
        if on {
            return Err(Error::msg("TUN is not yet supported on this platform"));
        }
        let ctl = self.controller();
        let began = Instant::now();
        ctl.request("PATCH", "/configs", Some(json!({ "tun": { "enable": on } })))
            .await?;
        if on {
            let device = self.settings().tun.device;
            if !wait_adapter(&device, Duration::from_secs(8)).await {
                let _ = ctl
                    .request("PATCH", "/configs", Some(json!({ "tun": { "enable": false } })))
                    .await;
                let tail = self.log_tail(10);
                let why = mihomo::summarize_error(&tail);
                self.metrics.count(metrics::name::TUN_FAILED);
                return Err(Error::msg(format!("TUN adapter '{device}' did not start. {why}")));
            }
            self.metrics.millis(metrics::name::TUN_MS, began.elapsed());
        }
        self.tun_on.store(on, SeqCst);
        Ok(())
    }

    async fn apply_method_locked(&self) -> Result<()> {
        let s = self.settings();
        match s.method {
            Method::Tun => {
                #[cfg(target_os = "macos")]
                return Err(Error::msg("macOS TUN requires a fresh supervised core"));
                #[cfg(not(target_os = "macos"))]
                {
                if !elevate::is_elevated() {
                    return Err(Error::NeedAdmin);
                }
                let _ = sysproxy::disable(&self.paths.sysproxy_backup(), &s.proxy_addr());
                self.set_tun_locked(true).await?;
                }
            }
            Method::SystemProxy => {
                if self.tun_on.load(SeqCst) {
                    self.set_tun_locked(false).await?;
                }
                #[cfg(target_os = "macos")]
                {
                    let guard = self.proxy_guard.lock().map_err(|_| Error::msg("proxy guard state unavailable"))?
                        .clone().ok_or_else(|| Error::msg("proxy guard is not available"))?;
                    let identity = self.core.live_identity().ok_or_else(|| Error::msg("core is not running"))?;
                    // A ready controller does not imply that mihomo managed to
                    // bind its mixed port. Do not change system settings until
                    // a local SOCKS handshake succeeds and the same core is
                    // still alive. This is a readiness check, not proof that a
                    // competing local process cannot own the port.
                    verify_macos_proxy_listener(s.mixed_port).await?;
                    if !self.core.identity_is_running(&identity) {
                        return Err(Error::msg("core stopped while checking its proxy listener"));
                    }
                    let location = crate::sysproxy_macos_read::current_location_id().map_err(Error::msg)?;
                    *self.proxy_guard_core.lock().map_err(|_| Error::msg("proxy core identity unavailable"))? = Some(identity);
                    let port = s.mixed_port;
                    let bypass = s.sysproxy_bypass.clone();
                    let joined = tokio::task::spawn_blocking(move || {
                        let result = guard.enable(port, &bypass);
                        (result, guard.state())
                    }).await;
                    let (result, state) = match joined {
                        Ok(result) => result,
                        Err(e) => {
                            self.recovery_required.store(true, SeqCst);
                            return Err(Error::msg(format!("proxy guard failed: {e}")));
                        }
                    };
                    if result.is_err() && !matches!(state, Ok(crate::macos_proxy_client::State::Idle)) {
                        self.recovery_required.store(true, SeqCst);
                    } else if result.is_err() {
                        if let Ok(mut owner) = self.proxy_guard_core.lock() { *owner = None; }
                    }
                    result.map_err(Error::msg)?;
                    if !crate::sysproxy_macos_read::current_location_id().is_ok_and(|current| current == location) {
                        self.restore_proxy_for_stop().await?;
                        return Err(Error::msg("network location changed while enabling system proxy"));
                    }
                    *self.proxy_location.lock().map_err(|_| Error::msg("proxy location state unavailable"))? = Some(location);
                }
                #[cfg(not(target_os = "macos"))]
                sysproxy::enable(&s.proxy_addr(), &s.sysproxy_bypass, &self.paths.sysproxy_backup())?;
            }
        }
        Ok(())
    }

    pub async fn connect(self: &Arc<Self>) -> Result<()> {
        let began = Instant::now();
        // set once the core runs and only the capture (system proxy / TUN) is left
        let capturing = AtomicBool::new(false);
        #[allow(unreachable_code)]
        let r = async {
            // Authorization can show a system dialog and attaching the guard
            // acquires `op`. Do this before taking that lock, then check the
            // connection state again under the lock below. The preview gate
            // still prevents authorization and capture in unverified builds.
            #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
            {
                self.ensure_macos_preview_can_connect()?;
                if matches!(self.settings().method, Method::SystemProxy | Method::Tun) {
                    self.prepare_macos_proxy_guard().await?;
                }
            }
            let _g = self.op.lock().await;
            #[cfg(target_os = "macos")]
            self.ensure_macos_preview_can_connect()?;
            #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
            if self.settings().method == Method::Tun {
                self.start_macos_tun_locked().await?;
                self.settings.write().unwrap().connected = true;
                if let Err(error) = self.save_settings() {
                    self.stop_core_locked().await?;
                    return Err(error);
                }
                return Ok(());
            }
            #[cfg(target_os = "android")]
            {
                self.connect_android_locked().await?;
                capturing.store(true, SeqCst);
                self.settings.write().unwrap().connected = true;
                self.save_settings()?;
                *self.last_error.lock().unwrap() = None;
                return Ok(());
            }
            #[cfg(not(windows))]
            if self.settings().method == Method::Tun {
                return Err(Error::msg("TUN is not yet supported on this platform"));
            }
            if self.settings().method == Method::Tun && !elevate::is_elevated() {
                return Err(Error::NeedAdmin);
            }
            self.start_core_locked().await?;
            capturing.store(true, SeqCst);
            self.apply_method_locked().await?;
            self.settings.write().unwrap().connected = true;
            self.save_settings()?;
            *self.last_error.lock().unwrap() = None;
            Ok(())
        }
        .await;
        self.metrics.count(metrics::name::CONNECT_ATTEMPTS);
        match &r {
            Ok(()) => {
                self.pause_zapret();
                if self.settings().adblock {
                    self.spawn_ads_more();
                }
                self.metrics.count(metrics::name::CONNECT_OK);
                self.metrics.millis(metrics::name::CONNECT_MS, began.elapsed());
            }
            Err(e) => {
                let stage = if capturing.load(SeqCst) { Stage::Capture } else { Stage::Start };
                self.metrics.failed(metrics::name::CONNECT_FAILED, metrics::classify(stage, e));
            }
        }
        if let Err(e) = &r {
            if !matches!(e, Error::NeedAdmin) {
                self.set_error(e);
            }
        }
        self.emit_state();
        r
    }

    #[cfg_attr(target_os = "android", allow(unreachable_code))]
    pub async fn disconnect(self: &Arc<Self>) -> Result<()> {
        let _g = self.op.lock().await;
        #[cfg(target_os = "android")]
        {
            self.disconnect_android_locked().await?;
            self.emit_state();
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        if self.handoff_prepared() { return Err(Error::msg("an exit or update is in progress")); }
        #[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
        if self.tun_on.load(SeqCst) {
            self.stop_core_locked().await?;
            self.emit_state();
            return Ok(());
        }
        if self.running() && self.tun_on.load(SeqCst) {
            let _ = self.set_tun_locked(false).await;
        }
        self.restore_proxy_for_stop().await?;
        self.settings.write().unwrap().connected = false;
        self.save_settings()?;
        self.resume_zapret().await;
        self.emit_state();
        Ok(())
    }

    // ---------------------------------------------------------------- telegram bridge

    /// Turn the local Telegram proxy on or off and remember the choice.
    pub async fn set_tg_bridge(&self, on: bool) -> Result<()> {
        {
            let mut s = self.settings.write().unwrap();
            if s.tg.secret.is_empty() {
                s.tg.secret = crate::tgbridge::new_secret();
            }
            s.tg.enabled = on;
        }
        if let Err(e) = self.save_settings() {
            warn!("telegram bridge: settings not saved to {}: {e}", self.paths.settings_file().display());
            return Err(e);
        }
        info!("telegram bridge {}: saved to {}", if on { "on" } else { "off" }, self.paths.settings_file().display());
        // chosen while the free mode's main switch is off: it starts with the switch
        let r = if on && !tools_allowed(&self.settings()) {
            Ok(())
        } else if on {
            self.start_tg().await
        } else {
            self.tg.lock().unwrap().take();
            *self.tg_error.lock().unwrap() = None;
            Ok(())
        };
        self.emit_state();
        r
    }

    /// Ask Telegram for an answer through the running bridge, as Telegram Desktop would. Milliseconds.
    pub async fn tg_check(&self) -> Result<u64> {
        let t = self.settings().tg;
        if self.tg.lock().unwrap().is_none() {
            return Err(Error::msg("the Telegram accelerator is off"));
        }
        let took = crate::tgbridge::self_test(t.port, &t.secret).await?;
        Ok(took.as_millis() as u64)
    }

    async fn start_tg(&self) -> Result<()> {
        // a bridge chosen before it ever ran (a fresh install's default) has no secret yet: make it now
        let fresh = {
            let mut s = self.settings.write().unwrap();
            let fresh = s.tg.secret.is_empty();
            if fresh {
                s.tg.secret = crate::tgbridge::new_secret();
            }
            fresh
        };
        if fresh {
            self.save_settings()?;
        }
        let t = self.settings().tg;
        // the user's own domains first, then the project's from the backend (the built-in one comes last)
        let mut domains = t.cf_domains.clone();
        for d in self.remote.doc().settings.tg_domains {
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
        if self.tg.lock().unwrap().as_ref().is_some_and(|b| b.port == t.port && b.secret == t.secret && b.cf_domains == domains) {
            return Ok(());
        }
        self.tg.lock().unwrap().take();
        match crate::tgbridge::Bridge::start(t.port, &t.secret, &domains).await {
            Ok(b) => {
                *self.tg.lock().unwrap() = Some(b);
                *self.tg_error.lock().unwrap() = None;
                Ok(())
            }
            Err(e) => {
                *self.tg_error.lock().unwrap() = Some(e.to_string());
                Err(e)
            }
        }
    }

    // ---------------------------------------------------------------- zapret

    /// Download the newest Zapret release and unpack it. A running winws is stopped for the swap and started again.
    pub async fn zapret_install(&self) -> Result<()> {
        if !cfg!(windows) {
            return Err(Error::msg("the DPI engine is built into this app"));
        }
        // straight to GitHub first; while connected it may only be reachable through our own proxy
        let via = self.running().then(|| format!("http://127.0.0.1:{}", self.settings().mixed_port));
        let rel = match crate::zapret::latest(None).await {
            Ok(r) => r,
            Err(direct) => match &via {
                Some(p) => crate::zapret::latest(Some(p)).await.map_err(|_| direct)?,
                None => return Err(direct),
            },
        };
        let zip = match crate::zapret::download(&rel, None).await {
            Ok(z) => z,
            Err(direct) => match &via {
                Some(p) => crate::zapret::download(&rel, Some(p)).await.map_err(|_| direct)?,
                None => return Err(direct),
            },
        };
        let was = self.zapret.pid().is_some();
        self.stop_dpi();
        let (dir, tag) = (self.paths.zapret_dir(), rel.tag.clone());
        tokio::task::spawn_blocking(move || crate::zapret::unpack(&zip, &dir, &tag))
            .await
            .map_err(|e| Error::msg(e.to_string()))??;
        info!("zapret {} installed", rel.tag);
        if was {
            let _ = self.set_zapret(true).await;
        }
        self.emit_state();
        Ok(())
    }

    fn zapret_strategy(&self, name: &str) -> Result<crate::zapret::Strategy> {
        let all = self.dpi_strategies();
        all.iter()
            .find(|x| x.name == name)
            .or(all.first())
            .cloned()
            .ok_or_else(|| Error::msg("Zapret is not installed"))
    }

    /// Start winws with a strategy, replacing one that runs. WinDivert is a driver: administrator rights are needed.
    async fn start_zapret_with(&self, strat: &crate::zapret::Strategy) -> Result<()> {
        if !cfg!(windows) {
            return self.start_engine(strat).await;
        }
        if !elevate::is_elevated() {
            return Err(Error::NeedAdmin);
        }
        let dir = self.paths.zapret_dir();
        crate::zapret::write_user_lists(&dir, &self.settings().zapret.domains)?;
        self.stop_dpi();
        let bin = dir.join("bin");
        let mut cmd = std::process::Command::new(bin.join("winws.exe"));
        cmd.args(&strat.args).current_dir(&bin);
        let inner = self.sink();
        let out = self.zapret_out.clone();
        out.lock().unwrap().clear();
        self.zapret.spawn(
            cmd,
            Arc::new(move |line: String| {
                {
                    let mut o = out.lock().unwrap();
                    o.push_back(line.clone());
                    while o.len() > 20 {
                        o.pop_front();
                    }
                }
                inner(format!("zapret: {line}"))
            }),
        )?;
        // winws quits at once when the driver cannot be opened: give it a moment, then look
        tokio::time::sleep(Duration::from_millis(700)).await;
        if self.zapret.pid().is_none() {
            let said: Vec<String> = self.zapret_out.lock().unwrap().iter().rev().take(3).rev().cloned().collect();
            let why = if said.is_empty() {
                "winws closed at once without a word; its files may be damaged, press Update".to_string()
            } else {
                said.join(" / ")
            };
            warn!("zapret: winws stopped right after the start: {why}");
            return Err(Error::msg(format!("Zapret stopped right after the start: {why}")));
        }
        info!("zapret runs strategy {}", strat.name);
        self.dpi_alive.store(true, SeqCst);
        Ok(())
    }

    /// Start the DPI engine (Android, macOS) with a strategy, replacing one that runs.
    async fn start_engine(&self, strat: &crate::zapret::Strategy) -> Result<()> {
        let bin = self.dpi_engine().ok_or_else(|| Error::msg("the DPI engine is not part of this build"))?;
        self.stop_dpi();
        let mut cmd = std::process::Command::new(&bin);
        cmd.args(crate::byedpi::command_args(strat));
        let inner = self.sink();
        self.zapret.spawn(cmd, Arc::new(move |line: String| inner(format!("byedpi: {line}"))))?;
        // a bad argument or a taken port makes it quit at once
        tokio::time::sleep(Duration::from_millis(300)).await;
        if self.zapret.pid().is_none() {
            return Err(Error::msg("the DPI engine stopped right after the start"));
        }
        info!("byedpi runs strategy {}", strat.name);
        self.dpi_alive.store(true, SeqCst);
        Ok(())
    }

    /// Turn the free bypass on (with the chosen strategy) or off, and remember the choice.
    pub async fn set_zapret(&self, on: bool) -> Result<()> {
        if self.zapret_find.lock().unwrap().is_some() {
            return Err(Error::msg("a strategy is being chosen right now"));
        }
        let r = if on && (vpn_on(&self.settings()) || !tools_allowed(&self.settings())) {
            // Zapret waits while the VPN is on (see pause_zapret) and starts when it goes off, and in the free mode
            // it waits for the main switch
            Ok(())
        } else if on && !self.strategy_chosen() {
            // never chosen, or a name this platform does not have (Windows' "general" on a phone that came from
            // 1.0.0): try them now and keep the one that gets YouTube's video and Discord through
            self.zapret_find().await.map(|_| ())
        } else if on {
            let name = self.settings().zapret.strategy;
            match self.zapret_strategy(&name) {
                Ok(strat) => self.start_zapret_with(&strat).await,
                Err(e) => Err(e),
            }
        } else {
            self.stop_dpi();
            Ok(())
        };
        *self.zapret_error.lock().unwrap() = r.as_ref().err().filter(|e| !matches!(e, Error::NeedAdmin)).map(|e| e.to_string());
        if r.is_ok() || (on && matches!(r, Err(Error::NeedAdmin))) {
            self.settings.write().unwrap().zapret.enabled = on;
            self.save_settings()?;
        }
        self.emit_state();
        r
    }

    /// Zapret and the VPN do not mix: winws would bend traffic the VPN already carries, and through the
    /// VPN it is not needed. It waits while the VPN is on; the choice stays remembered.
    /// Is the stored strategy one this platform has (a Zapret release on Windows, byedpi's list elsewhere)?
    fn strategy_chosen(&self) -> bool {
        let name = self.settings().zapret.strategy;
        !name.is_empty() && self.dpi_strategies().iter().any(|x| x.name == name)
    }

    /// Stop the DPI engine on purpose: the monitor does not bring it back.
    fn stop_dpi(&self) {
        self.dpi_alive.store(false, SeqCst);
        self.zapret.stop();
    }

    /// The DPI engine exited on its own while it should run (Android's and MIUI's battery savers kill child
    /// processes): start it again with the same strategy. An engine that dies right after its start is left down
    /// with its error, so a broken one is not restarted in a loop.
    async fn revive_dpi(&self) {
        warn!("the DPI engine exited on its own; starting it again");
        self.dpi_alive.store(false, SeqCst);
        let name = self.settings().zapret.strategy;
        let r = match self.zapret_strategy(&name) {
            Ok(strat) => self.start_zapret_with(&strat).await,
            Err(e) => Err(e),
        };
        if let Err(e) = &r {
            warn!("the DPI engine did not come back: {e}");
            *self.zapret_error.lock().unwrap() = Some(e.to_string());
        }
        self.emit_state();
    }

    fn pause_zapret(&self) {
        if vpn_on(&self.settings()) && self.zapret.pid().is_some() {
            self.stop_dpi();
            info!("zapret waits while the VPN is on");
        }
    }

    /// Start Zapret again when it is wanted and the VPN is off. Needs administrator rights and a whole install.
    async fn resume_zapret(&self) {
        let s = self.settings();
        if s.zapret.enabled
            && !vpn_on(&s)
            && tools_allowed(&s)
            && self.zapret.pid().is_none()
            && (!cfg!(windows) || elevate::is_elevated())
            && self.dpi_installed()
        {
            if let Err(e) = self.set_zapret(true).await {
                warn!("zapret: {e}");
            }
        }
    }

    /// Try the strategies one by one and keep the first that opens Discord and YouTube's video servers.
    /// The VPN must be off: through it every strategy would look fine.
    pub async fn zapret_find(&self) -> Result<String> {
        if vpn_on(&self.settings()) {
            return Err(Error::msg("turn the VPN off first: through it every strategy looks like it works"));
        }
        if cfg!(windows) && !elevate::is_elevated() {
            return Err(Error::NeedAdmin);
        }
        {
            let mut f = self.zapret_find.lock().unwrap();
            if f.is_some() {
                return Err(Error::msg("a strategy is being chosen right now"));
            }
            *f = Some(ZapretProgress { done: 0, total: 0, name: String::new() });
        }
        let mut all = self.dpi_strategies();
        // the strategy in use goes first: when it still works, the search is over in seconds
        let saved = self.settings().zapret.strategy;
        if let Some(i) = all.iter().position(|x| x.name == saved) {
            let first = all.remove(i);
            all.insert(0, first);
        }
        // the user's own sites are checked too: what they want to open should open
        let sites = self.settings().zapret.domains;
        // round two re-checks the best few: the provider's filter wavers, and one lucky round should not win
        const FINALISTS: usize = 3;
        // winws takes every connection of the system, so Windows tries one strategy at a time; byedpi is a proxy,
        // so a few engines on ports of their own are tried side by side (four at a time: 3 times faster on the
        // Mac, with the same scores; examples/dpi_bench.rs)
        let at_once = if cfg!(windows) { 1 } else { SIDE_BY_SIDE };
        let total = all.len() + FINALISTS;
        let mut found = None;
        let mut scored: Vec<(crate::zapret::Probe, crate::zapret::Strategy)> = Vec::new();
        let mut video = None;
        let mut done = 0;
        'search: for batch in all.chunks(at_once) {
            let got = self.probe_batch(batch, done, total, &mut video, &sites).await;
            done += batch.len();
            for (strat, got) in batch.iter().zip(got) {
                let Some(got) = got else { continue };
                // a perfect one ends the search
                if got.all() {
                    found = Some(strat.clone());
                    break 'search;
                }
                if got.youtube > 0 {
                    scored.push((got, strat.clone()));
                }
            }
            if cfg!(windows) {
                self.stop_dpi();
            }
        }
        // winws already runs the perfect one; elsewhere its engine of the search is gone, the real one takes it
        let mut found = match found {
            Some(strat) if !cfg!(windows) => self.start_zapret_with(&strat).await.is_ok().then_some(strat.name),
            other => other.map(|s| s.name),
        };
        // none got everything through every time: the best few once more, and the best sum wins
        if found.is_none() {
            scored.sort_by(|a, b| if a.0.beats(&b.0) { std::cmp::Ordering::Less } else if b.0.beats(&a.0) { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal });
            scored.truncate(FINALISTS);
            let (firsts, finalists): (Vec<_>, Vec<_>) = scored.into_iter().unzip();
            let mut again = Vec::new();
            for batch in finalists.chunks(at_once) {
                again.extend(self.probe_batch(batch, done, total, &mut video, &sites).await);
                done += batch.len();
                if cfg!(windows) {
                    self.stop_dpi();
                }
            }
            let mut best: Option<(crate::zapret::Probe, crate::zapret::Strategy)> = None;
            for ((first, strat), again) in firsts.into_iter().zip(finalists).zip(again) {
                let sum = first.plus(again.unwrap_or_default());
                if best.as_ref().is_none_or(|(b, _)| sum.beats(b)) {
                    best = Some((sum, strat));
                }
            }
            if let Some((got, strat)) = best {
                if self.start_zapret_with(&strat).await.is_ok() {
                    info!("zapret: best strategy {} over two rounds (YouTube {}/{}, Discord {}/{}, own sites {}/{})", strat.name, got.youtube, got.youtube_of, got.discord, got.discord_of, got.sites, got.sites_of);
                    found = Some(strat.name);
                }
            }
        }
        *self.zapret_find.lock().unwrap() = None;
        let r = match found {
            Some(name) => {
                {
                    let mut g = self.settings.write().unwrap();
                    g.zapret.strategy = name.clone();
                    g.zapret.enabled = true;
                }
                self.save_settings()?;
                *self.zapret_error.lock().unwrap() = None;
                info!("zapret: strategy {name} works");
                Ok(name)
            }
            None => {
                let msg = if total == 0 { "Zapret is not installed" } else { "none of the strategies got Discord and YouTube video through; the provider blocks them in another way. Smart mode helps here" };
                *self.zapret_error.lock().unwrap() = Some(msg.to_string());
                Err(Error::msg(msg))
            }
        };
        self.emit_state();
        r
    }

    /// Probe a few strategies; None for one that does not start. On Windows (one at a time) winws runs the
    /// strategy and is left running. Elsewhere each strategy gets an engine of its own on a port of its own,
    /// probed through it the way the core will send the sites to it, and stopped after: the engine in use stays.
    async fn probe_batch(&self, batch: &[crate::zapret::Strategy], step: usize, total: usize, video: &mut Option<String>, sites: &[String]) -> Vec<Option<crate::zapret::Probe>> {
        let names: Vec<&str> = batch.iter().map(|s| s.name.as_str()).collect();
        *self.zapret_find.lock().unwrap() = Some(ZapretProgress { done: step, total, name: names.join(", ") });
        self.emit_state();
        let got: Vec<Option<crate::zapret::Probe>> = if cfg!(windows) {
            let mut out = Vec::new();
            for strat in batch {
                out.push(match self.start_zapret_with(strat).await {
                    Ok(()) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        Some(crate::zapret::probe(video, None, sites).await)
                    }
                    Err(_) => None,
                });
            }
            out
        } else {
            let Some(bin) = self.dpi_engine() else { return vec![None; batch.len()] };
            let runs = batch.iter().enumerate().map(|(i, strat)| {
                let (bin, mut node) = (bin.clone(), video.clone());
                let port = crate::byedpi::PORT + 1 + i as u16;
                async move {
                    let mut child = tokio::process::Command::new(&bin)
                        .args(crate::byedpi::command_args_on(strat, port))
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .spawn()
                        .ok()?;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    // a bad argument or a taken port makes it quit at once
                    if !matches!(child.try_wait(), Ok(None)) {
                        warn!("zapret: the engine for {} did not start on port {port}", strat.name);
                        return None;
                    }
                    let got = crate::zapret::probe(&mut node, Some(&format!("socks5h://127.0.0.1:{port}")), sites).await;
                    let _ = child.kill().await;
                    Some((got, node))
                }
            });
            let mut out = Vec::new();
            for r in futures_util::future::join_all(runs).await {
                out.push(r.map(|(got, node)| {
                    if video.is_none() {
                        *video = node;
                    }
                    got
                }));
            }
            out
        };
        for (strat, got) in batch.iter().zip(&got) {
            if let Some(got) = got {
                info!("zapret: {}: YouTube {}/{}, Discord {}/{}, own sites {}/{}", strat.name, got.youtube, got.youtube_of, got.discord, got.discord_of, got.sites, got.sites_of);
            }
        }
        got
    }

    /// The strategy, the user's own sites and the game filter. A running winws starts again with them.
    pub async fn zapret_configure(&self, strategy: Option<String>, domains: Option<Vec<String>>, game_filter: Option<bool>) -> Result<()> {
        {
            let mut g = self.settings.write().unwrap();
            if let Some(name) = strategy {
                g.zapret.strategy = name;
            }
            if let Some(list) = domains {
                let mut clean: Vec<String> = list.iter().filter_map(|d| crate::zapret::clean_domain(d)).collect();
                clean.sort();
                clean.dedup();
                clean.truncate(1000);
                g.zapret.domains = clean;
            }
            if let Some(on) = game_filter {
                g.zapret.game_filter = on;
            }
        }
        self.save_settings()?;
        let dir = self.paths.zapret_dir();
        if cfg!(windows) && crate::zapret::version(&dir).is_some() {
            crate::zapret::write_user_lists(&dir, &self.settings().zapret.domains)?;
        }
        let r = if self.zapret.pid().is_some() { self.set_zapret(true).await } else { Ok(()) };
        self.emit_state();
        r
    }

    // ---------------------------------------------------------------- settings

    pub async fn update_settings(self: &Arc<Self>, patch: Value) -> Result<()> {
        let _g = self.op.lock().await;
        #[cfg(target_os = "macos")]
        if self.handoff_prepared() || self.recovery_required.load(SeqCst) {
            return Err(Error::msg("proxy recovery or app exit is in progress"));
        }
        let (old, new) = {
            let mut g = self.settings.write().unwrap();
            let old = g.clone();
            let mut next = old.clone();
            next.apply_patch(patch)?;
            // The first-run marker is internal: patches may not turn it on or reset completed onboarding.
            next.consent_fresh = old.consent_fresh && !next.onboarded;
            #[cfg(target_os = "macos")]
            if next.connected != old.connected { return Err(Error::msg("use connect or disconnect to change connection state")); }
            // Switching capture methods requires the current helper session
            // and its interface to be closed first.
            #[cfg(target_os = "macos")]
            if old.connected && old.method != next.method {
                return Err(Error::msg("disconnect before switching capture methods on macOS"));
            }
            next.dpi.normalize()?;
            // Cloudflare domains for the Telegram bridge: plain host names only, each once
            let mut cf: Vec<String> = next.tg.cf_domains.iter().filter_map(|d| crate::zapret::clean_domain(d)).collect();
            cf.dedup();
            cf.truncate(10);
            next.tg.cf_domains = cf;
            if next.mixed_port == 0 || next.controller_port == 0 || next.mixed_port == next.controller_port {
                return Err(Error::msg("ports must be non-zero and different"));
            }
            if next.secret.is_empty() {
                next.secret = old.secret.clone();
            }
            // the install id is made here, never taken from outside: with the first consent it appears, with the
            // last it goes (a later consent starts a new one)
            next.install_id = old.install_id.clone();
            if !next.consent_stats && !next.consent_tests {
                next.install_id.clear();
            } else if next.install_id.is_empty() {
                next.install_id = uuid::Uuid::new_v4().to_string();
            }
            // the day's totals come from the local statistics
            if next.consent_stats && !old.consent_stats {
                next.metrics = true;
            }
            // the network and the subscriptions go only with the statistics they belong to
            if !next.consent_stats {
                next.consent_network = false;
                next.consent_subs = false;
            }
            if !next.backend_url.trim().is_empty() && crate::remote::base_url(&next.backend_url).is_none() {
                return Err(Error::msg("backend_url: https, or http to this device"));
            }
            // the UI never receives the secret, so a blank value means "unchanged"
            *g = next.clone();
            (old, next)
        };
        new.save(&self.paths.settings_file())?;
        self.metrics.set_on(new.metrics);
        if !old.consent_stats && new.consent_stats {
            // A new install can report itself immediately even before it records its first measurement.
            self.metrics.ensure_today();
            self.spawn_initial_stats();
        }
        // a running Telegram bridge picks up new Cloudflare domains at once
        if old.tg.cf_domains != new.tg.cf_domains && self.tg.lock().unwrap().is_some() {
            if let Err(e) = self.start_tg().await {
                warn!("telegram bridge: {e}");
            }
        }

        // Switching a live connection to TUN needs elevation. Keep the choice, drop the current
        // capture (so the screen tells the truth) and let the UI offer the elevated restart.
        #[cfg(not(target_os = "macos"))]
        if new.method == Method::Tun && old.method != Method::Tun && old.connected && !elevate::is_elevated() {
            let _ = sysproxy::disable(&self.paths.sysproxy_backup(), &old.proxy_addr());
            self.settings.write().unwrap().connected = false;
            self.save_settings()?;
            self.emit_state();
            return Err(Error::NeedAdmin);
        }

        if self.running() {
            let needs_restart = old.mixed_port != new.mixed_port
                || old.controller_port != new.controller_port
                || old.core_path != new.core_path
                || old.allow_lan != new.allow_lan;
            let mode_only = old.mode != new.mode
                && config_fingerprint(&Settings { mode: old.mode, ..new.clone() }) == config_fingerprint(&old);
            let r: Result<()> = async {
                // A guard session accepts only one activation at a time. Give
                // the existing settings back before applying a changed bypass
                // list; a failed reactivation must not leave UI reporting a
                // connected proxy which is no longer configured.
                #[cfg(target_os = "macos")]
                let reconfigure_proxy = old.connected && old.method == Method::SystemProxy
                    && new.method == Method::SystemProxy && old.sysproxy_bypass != new.sysproxy_bypass
                    && !needs_restart;
                #[cfg(target_os = "macos")]
                if reconfigure_proxy {
                    self.restore_proxy_for_stop().await?;
                    self.settings.write().unwrap().connected = false;
                    self.save_settings()?;
                }
                if needs_restart {
                    self.restart_locked().await?;
                } else if mode_only {
                    self.controller()
                        .request("PATCH", "/configs", Some(json!({ "mode": new.mode.as_str() })))
                        .await?;
                } else if config_fingerprint(&old) != config_fingerprint(&new) {
                    self.reload_locked().await?;
                }
                if new.adblock && !old.adblock {
                    self.spawn_ads_more();
                }
                if new.connected
                    && (old.method != new.method || old.sysproxy_bypass != new.sysproxy_bypass)
                    && !needs_restart
                    && (cfg!(not(target_os = "macos")) || new.method == Method::SystemProxy)
                {
                    self.apply_method_locked().await?;
                    #[cfg(target_os = "macos")]
                    if reconfigure_proxy {
                        self.settings.write().unwrap().connected = true;
                        self.save_settings()?;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = r {
                self.set_error(&e);
                self.emit_state();
                return Err(e);
            }
        }
        self.emit_state();
        Ok(())
    }

    // ---------------------------------------------------------------- core install

    pub async fn install_core(self: &Arc<Self>, from: Option<String>) -> Result<()> {
        let _g = self.op.lock().await;
        let src = match from {
            Some(p) => PathBuf::from(p),
            None => self
                .cached_candidates()
                .into_iter()
                .find(|c| c.label != "Kometfy")
                .map(|c| PathBuf::from(c.path))
                .ok_or_else(|| Error::msg("no mihomo core found on this PC"))?,
        };
        let dst = self.paths.core_bin();
        if src != dst {
            self.stop_core_locked().await?;
            discover::install_core(&self.paths, &src)?;
        }
        self.settings.write().unwrap().core_path = None;
        self.save_settings()?;
        *self.version_cache.lock().unwrap() = None;
        let auto = self.settings().auto_start_core;
        if auto {
            if let Err(e) = self.start_core_locked().await {
                self.set_error(&e);
            }
        }
        self.emit_state();
        Ok(())
    }

    /// Download the official mihomo release, verify it and install it. Emits `core-download` progress.
    pub async fn download_core(self: &Arc<Self>) -> Result<String> {
        let _g = self.op.lock().await;
        // while connected, GitHub may only be reachable through our own proxy
        let via = self
            .running()
            .then(|| format!("http://127.0.0.1:{}", self.settings().mixed_port));
        let rel = match coredl::latest(None).await {
            Ok(r) => r,
            Err(direct) => match &via {
                Some(p) => coredl::latest(Some(p)).await.map_err(|_| direct)?,
                None => return Err(direct),
            },
        };
        let emit = self.emit.clone();
        let tag = rel.tag.clone();
        let progress = move |done: u64, total: u64| {
            emit("core-download", serde_json::json!({ "done": done, "total": total, "tag": tag }));
        };
        let zip = match coredl::download(&rel, None, &progress).await {
            Ok(z) => z,
            Err(direct) => match &via {
                Some(p) => coredl::download(&rel, Some(p), &progress).await.map_err(|_| direct)?,
                None => return Err(direct),
            },
        };
        let exe = coredl::extract_exe(&zip)?;
        self.stop_core_locked().await?;
        coredl::install(&self.paths, &exe)?;
        let failed = coredl::download_geodata(&self.paths, via.as_deref()).await;
        if !failed.is_empty() {
            tracing::warn!("geodata not downloaded: {failed:?} (mihomo fetches them itself on first start)");
        }
        self.settings.write().unwrap().core_path = None;
        self.save_settings()?;
        *self.version_cache.lock().unwrap() = None;
        if self.settings().auto_start_core {
            if let Err(e) = self.start_core_locked().await {
                self.set_error(&e);
            }
        }
        self.emit_state();
        Ok(rel.tag)
    }

    // ---------------------------------------------------------------- Xray install

    /// Where GitHub can be reached while connected: through our own proxy.
    fn download_proxy(&self) -> Option<String> {
        self.running().then(|| format!("http://127.0.0.1:{}", self.settings().mixed_port))
    }

    /// The newest release of the app from the first of `feeds` that answers (a Tauri `latest.json`): directly, then
    /// through our own core when the site or GitHub is blocked.
    pub async fn app_latest(self: &Arc<Self>, feeds: &[&str]) -> Result<coredl::AppRelease> {
        let via = self.download_proxy();
        let mut last = Error::msg("no address to check");
        for url in feeds {
            for proxy in std::iter::once(None).chain(via.as_deref().map(Some)) {
                match coredl::app_release(url, proxy).await {
                    Ok(r) => return Ok(r),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// Downloads an installer of the app, directly and then through our own core when that is blocked.
    pub async fn app_download(self: &Arc<Self>, url: &str, progress: impl Fn(u64, u64) + Send + Sync) -> Result<Vec<u8>> {
        match coredl::download_app(url, None, &progress).await {
            Ok(b) => Ok(b),
            Err(direct) => match self.download_proxy() {
                Some(p) => coredl::download_app(url, Some(&p), &progress).await.map_err(|_| direct),
                None => Err(direct),
            },
        }
    }

    /// Newest version of a core on GitHub next to the installed one.
    pub async fn core_latest(self: &Arc<Self>, kind: Kind) -> Result<CoreUpdate> {
        let via = self.download_proxy();
        let rel = match coredl::latest_of(kind, None).await {
            Ok(r) => r,
            Err(direct) => match &via {
                Some(p) => coredl::latest_of(kind, Some(p)).await.map_err(|_| direct)?,
                None => return Err(direct),
            },
        };
        let installed = match kind {
            Kind::Mihomo => self.resolve_core().ok().and_then(|b| self.cached_version(&b)),
            Kind::Xray => self.resolve_xray().and_then(|b| self.cached_xray_version(&b)),
        };
        let newer = installed.as_deref().is_none_or(|i| coredl::is_newer(i, &rel.tag));
        Ok(CoreUpdate {
            kind: if kind == Kind::Mihomo { "mihomo" } else { "xray" },
            installed,
            latest: rel.tag,
            newer,
        })
    }

    /// The helper may have been waiting for its program: bring it up now.
    async fn after_xray_install(self: &Arc<Self>) {
        *self.xray_version_cache.lock().unwrap() = None;
        self.set_xray_issue(None);
        if self.running() {
            if let Err(e) = self.reload_locked().await {
                self.set_error(&e);
            }
        }
        self.emit_state();
    }

    /// Download the official Xray release, verify it and install it. Emits `core-download` progress.
    pub async fn download_xray(self: &Arc<Self>) -> Result<String> {
        let _g = self.op.lock().await;
        let via = self.download_proxy();
        let rel = match coredl::latest_of(Kind::Xray, None).await {
            Ok(r) => r,
            Err(direct) => match &via {
                Some(p) => coredl::latest_of(Kind::Xray, Some(p)).await.map_err(|_| direct)?,
                None => return Err(direct),
            },
        };
        let emit = self.emit.clone();
        let tag = rel.tag.clone();
        let progress = move |done: u64, total: u64| {
            emit("core-download", json!({ "done": done, "total": total, "tag": tag, "kind": "xray" }));
        };
        let zip = match coredl::download(&rel, None, &progress).await {
            Ok(z) => z,
            Err(direct) => match &via {
                Some(p) => coredl::download(&rel, Some(p), &progress).await.map_err(|_| direct)?,
                None => return Err(direct),
            },
        };
        let exe = coredl::extract_exe(&zip)?;
        // the running helper holds xray.exe open: stop it, the reload below starts it again
        self.stop_xray();
        if let Err(e) = coredl::install_xray(&self.paths, &exe) {
            self.after_xray_install().await;
            return Err(e);
        }
        self.settings.write().unwrap().xray.path = None;
        self.save_settings()?;
        self.after_xray_install().await;
        Ok(rel.tag)
    }

    /// Use an `xray.exe` the user points to: it is copied into the app folder.
    pub async fn install_xray(self: &Arc<Self>, from: String) -> Result<()> {
        let _g = self.op.lock().await;
        let src = PathBuf::from(from);
        if !src.is_file() {
            return Err(Error::msg("core file not found"));
        }
        if src != self.paths.xray_bin() {
            let exe = std::fs::read(&src)?;
            self.stop_xray();
            if let Err(e) = coredl::install_xray(&self.paths, &exe) {
                self.after_xray_install().await;
                return Err(e);
            }
        }
        self.settings.write().unwrap().xray.path = None;
        self.save_settings()?;
        self.after_xray_install().await;
        Ok(())
    }

    // ---------------------------------------------------------------- profiles

    /// Download a subscription. The device id goes along unless the user switched that off.
    async fn fetch_subscription(&self, url: &str) -> Result<subscription::Fetched> {
        let r = self.fetch_subscription_inner(url).await;
        match &r {
            Ok(_) => self.metrics.count(metrics::name::SUB_OK),
            Err(e) => self.metrics.failed(metrics::name::SUB_FAILED, metrics::classify(Stage::Subscription, e)),
        }
        r
    }

    async fn fetch_subscription_inner(&self, url: &str) -> Result<subscription::Fetched> {
        let s = self.settings();
        let device = s.hwid.then(device::info);
        match subscription::fetch(url, None, device.as_ref()).await {
            Ok(f) => Ok(f),
            // the provider answered (device limit, id required): asking again through a proxy changes nothing
            Err(direct) if self.running() && !direct.to_string().starts_with("HWID_") => {
                let via = format!("http://127.0.0.1:{}", s.mixed_port);
                subscription::fetch(url, Some(&via), device.as_ref()).await.map_err(|_| direct)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn import_profile(self: &Arc<Self>, input: &str, name: Option<String>) -> Result<ProfileMeta> {
        let unwrapped = happ::unwrap(input.trim())?;
        let text = unwrapped.as_deref().unwrap_or(input).trim();
        if text.is_empty() {
            return Err(Error::msg("nothing to import"));
        }
        let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
        let is_url = !text.contains('\n') && (text.starts_with("http://") || text.starts_with("https://"));
        let now = chrono::Utc::now().to_rfc3339();
        let (meta, yaml) = if is_url {
            let f = self.fetch_subscription(text).await?;
            let norm = subscription::normalize(&f.body)?;
            let fallback = url::Url::parse(text)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_else(|| "Subscription".into());
            let remote_title = f.title.clone().or_else(|| f.filename.clone());
            let mut meta = ProfileMeta {
                id: new_id(),
                name: name.clone().or_else(|| remote_title.clone()).unwrap_or(fallback),
                url: Some(text.to_string()),
                source: norm.source,
                nodes: norm.nodes,
                updated_at: Some(now),
                interval_hours: f.interval_hours.unwrap_or(24),
                usage: f.usage,
                announce: None,
                support_url: None,
                web_url: None,
                dpi: None,
                hwid_active: false,
                tasks_url: None,
                reports_url: None,
                remote_title: None,
                name_custom: name.is_some(),
            };
            meta.apply_meta(f.meta, remote_title);
            (meta, norm.yaml)
        } else {
            let norm = subscription::normalize(text)?;
            let count = self.profiles.lock().unwrap().items().len() + 1;
            let meta = ProfileMeta {
                id: new_id(),
                name: name.clone().unwrap_or_else(|| format!("Profile {count}")),
                url: None,
                source: norm.source,
                nodes: norm.nodes,
                updated_at: Some(now),
                interval_hours: 0,
                usage: None,
                announce: None,
                support_url: None,
                web_url: None,
                dpi: None,
                hwid_active: false,
                tasks_url: None,
                reports_url: None,
                remote_title: None,
                name_custom: name.is_some(),
            };
            (meta, norm.yaml)
        };
        // make sure the result can become a runtime config
        config::build(Some(&yaml), None, &self.settings(), &[], false)?;
        let first = {
            let mut store = self.profiles.lock().unwrap();
            store.add(meta.clone(), &yaml)?;
            self.settings.read().unwrap().active_profile.is_none()
        };
        if first {
            self.select_profile(&meta.id).await?;
        } else {
            self.emit_state();
        }
        Ok(meta)
    }

    pub async fn select_profile(self: &Arc<Self>, id: &str) -> Result<()> {
        let _g = self.op.lock().await;
        if self.profiles.lock().unwrap().get(id).is_none() {
            return Err(Error::msg("profile not found"));
        }
        let previous = self.settings.write().unwrap().active_profile.replace(id.to_string());
        let r = self.reload_locked().await;
        if let Err(e) = &r {
            self.settings.write().unwrap().active_profile = previous;
            self.set_error(e);
        }
        self.save_settings()?;
        self.emit_state();
        r
    }

    pub async fn update_profile(self: &Arc<Self>, id: &str) -> Result<ProfileMeta> {
        let url = {
            let store = self.profiles.lock().unwrap();
            let p = store.get(id).ok_or_else(|| Error::msg("profile not found"))?;
            p.url.clone().ok_or_else(|| Error::msg("local profiles have nothing to update"))?
        };
        let f = self.fetch_subscription(&url).await?;
        let norm = subscription::normalize(&f.body)?;
        config::build(Some(&norm.yaml), None, &self.settings(), &[], false)?;
        let remote_title = f.title.clone().or_else(|| f.filename.clone());
        let (meta, changed) = {
            let mut store = self.profiles.lock().unwrap();
            // many panels answer with identical content; skip the disk write and the core reload then
            let changed = store.read(id).map(|old| old != norm.yaml).unwrap_or(true);
            if changed {
                store.write(id, &norm.yaml)?;
            }
            let p = store.get_mut(id).ok_or_else(|| Error::msg("profile not found"))?;
            p.nodes = norm.nodes;
            p.source = norm.source;
            p.usage = f.usage.or(p.usage.take());
            p.updated_at = Some(chrono::Utc::now().to_rfc3339());
            // a new DPI instruction changes how the servers are run, so it needs a reload as well
            let old_dpi = p.dpi.clone();
            p.apply_meta(f.meta, remote_title);
            let changed = changed || old_dpi != p.dpi;
            let out = p.clone();
            store.save_index()?;
            (out, changed)
        };
        if changed && self.settings().active_profile.as_deref() == Some(id) {
            let _g = self.op.lock().await;
            if let Err(e) = self.reload_locked().await {
                self.set_error(&e);
            }
        }
        self.emit_state();
        Ok(meta)
    }

    /// Refresh every remote profile that is due (or all of them when `force`).
    pub async fn update_all_profiles(self: &Arc<Self>, force: bool) -> Vec<String> {
        let due: Vec<(String, String)> = {
            let store = self.profiles.lock().unwrap();
            store
                .items()
                .iter()
                .filter(|p| p.url.is_some())
                .filter(|p| {
                    force
                        || p.interval_hours > 0
                            && p.updated_at
                                .as_deref()
                                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                                .is_none_or(|t| {
                                    chrono::Utc::now().signed_duration_since(t).num_hours()
                                        >= p.interval_hours as i64
                                })
                })
                .map(|p| (p.id.clone(), p.name.clone()))
                .collect()
        };
        let mut failed = Vec::new();
        for (id, name) in due {
            match self.update_profile(&id).await {
                Ok(_) => info!("subscription updated"),
                Err(e) => {
                    // scrubbed: an error can carry the subscription link
                    warn!("subscription update failed: {}", crate::diagnostics::scrub(&e.to_string()));
                    failed.push(format!("{name}: {e}"));
                }
            }
        }
        failed
    }

    pub async fn remove_profile(self: &Arc<Self>, id: &str) -> Result<()> {
        let _g = self.op.lock().await;
        self.profiles.lock().unwrap().remove(id)?;
        let was_active = self.settings().active_profile.as_deref() == Some(id);
        if was_active {
            let next = self.profiles.lock().unwrap().items().first().map(|p| p.id.clone());
            self.settings.write().unwrap().active_profile = next;
            self.save_settings()?;
            if let Err(e) = self.reload_locked().await {
                self.set_error(&e);
            }
        }
        self.emit_state();
        Ok(())
    }

    /// A name the user types is theirs: a rename on the provider's side no longer replaces it.
    /// Typing the provider's own name hands the profile back to the provider.
    pub fn rename_profile(&self, id: &str, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::msg("name cannot be empty"));
        }
        {
            let mut store = self.profiles.lock().unwrap();
            let p = store.get_mut(id).ok_or_else(|| Error::msg("profile not found"))?;
            p.name = name.to_string();
            p.name_custom = p.remote_title.as_deref() != Some(name);
            store.save_index()?;
        }
        self.emit_state();
        Ok(())
    }

    /// Back to the name the provider gave the subscription (and follow its renames again).
    pub fn reset_profile_name(&self, id: &str) -> Result<()> {
        {
            let mut store = self.profiles.lock().unwrap();
            let p = store.get_mut(id).ok_or_else(|| Error::msg("profile not found"))?;
            let title = p
                .remote_title
                .clone()
                .ok_or_else(|| Error::msg("the provider has not named this subscription"))?;
            p.name = title;
            p.name_custom = false;
            store.save_index()?;
        }
        self.emit_state();
        Ok(())
    }

    /// `happ://crypt4/...` for a subscription: the address is hidden inside the link.
    pub fn profile_happ_link(&self, id: &str) -> Result<String> {
        let url = {
            let store = self.profiles.lock().unwrap();
            let p = store.get(id).ok_or_else(|| Error::msg("profile not found"))?;
            p.url.clone().ok_or_else(|| Error::msg("only a subscription link can be encrypted"))?
        };
        happ::crypt4(&url)
    }

    /// Open a link from the UI (support page, Happ) in the program Windows picks for it.
    pub fn open_link(&self, url: &str) -> Result<()> {
        opener::open_url(url)
    }

    /// This PC as the provider of a subscription sees it.
    pub fn device(&self) -> device::Device {
        device::info()
    }

    pub fn read_profile(&self, id: &str) -> Result<String> {
        self.profiles.lock().unwrap().read(id)
    }

    pub async fn write_profile(self: &Arc<Self>, id: &str, text: &str) -> Result<()> {
        config::build(Some(text), None, &self.settings(), &[], false)?;
        let old = self.profiles.lock().unwrap().read(id)?;
        let nodes = config::list_nodes(text).len();
        {
            let mut store = self.profiles.lock().unwrap();
            store.write(id, text)?;
            if let Some(p) = store.get_mut(id) {
                p.nodes = nodes;
            }
            store.save_index()?;
        }
        if self.settings().active_profile.as_deref() == Some(id) {
            let _g = self.op.lock().await;
            if let Err(e) = self.reload_locked().await {
                let _ = self.profiles.lock().unwrap().write(id, &old);
                self.emit_state();
                return Err(e);
            }
        }
        self.emit_state();
        Ok(())
    }

    pub fn profile_nodes(&self, id: &str) -> Result<Vec<NodeInfo>> {
        Ok(config::list_nodes(&self.profiles.lock().unwrap().read(id)?))
    }

    // ---------------------------------------------------------------- rules

    /// After an edit: hot-reload when the core runs, otherwise prove the core would accept the config.
    async fn apply_config_locked(self: &Arc<Self>) -> Result<()> {
        if self.running() {
            return self.reload_locked().await;
        }
        let Ok(bin) = self.resolve_core() else {
            return Ok(());
        };
        discover::ensure_geodata(&bin, &self.paths);
        let built = self.build_config(true, &BTreeMap::new())?;
        let next = self.paths.runtime_dir().join("config.next.yaml");
        crate::util::write_atomic(&next, built.yaml.as_bytes())?;
        let r = self.validate(&bin, &next).await;
        let _ = std::fs::remove_file(&next);
        *self.build_info.lock().unwrap() = built.info;
        r
    }

    /// Replace the user's rule list. A list the core refuses is rolled back, so a typo in a regex
    /// can never leave the app without a working config.
    pub async fn set_rules(self: &Arc<Self>, list: Vec<UserRule>) -> Result<Vec<UserRule>> {
        let _g = self.op.lock().await;
        let previous = self.rules.lock().unwrap().items().to_vec();
        let saved = self.rules.lock().unwrap().replace(list)?;
        if let Err(e) = self.apply_config_locked().await {
            let _ = self.rules.lock().unwrap().replace(previous);
            let _ = self.apply_config_locked().await;
            self.emit_state();
            return Err(e);
        }
        self.emit_state();
        Ok(saved)
    }

    // ---------------------------------------------------------------- chains

    pub async fn save_chain(self: &Arc<Self>, mut c: Chain) -> Result<Chain> {
        let _g = self.op.lock().await;
        if c.profile.is_none() {
            c.profile = self.settings().active_profile;
        }
        let saved = self.chains.lock().unwrap().save(c)?;
        if let Err(e) = self.reload_locked().await {
            self.set_error(&e);
        }
        self.emit_state();
        Ok(saved)
    }

    pub async fn remove_chain(self: &Arc<Self>, id: &str) -> Result<()> {
        let _g = self.op.lock().await;
        self.chains.lock().unwrap().remove(id)?;
        if let Err(e) = self.reload_locked().await {
            self.set_error(&e);
        }
        self.emit_state();
        Ok(())
    }

    /// Route default traffic through the chain: pick it in the chains group and point the main
    /// selector groups (and GLOBAL) at that group.
    pub async fn activate_chain(self: &Arc<Self>, id: &str) -> Result<()> {
        let _operation = self.op.lock().await;
        let chain = self
            .chains
            .lock()
            .unwrap()
            .items()
            .iter()
            .find(|c| c.id == id)
            .cloned()
            .ok_or_else(|| Error::msg("chain not found"))?;
        let exit = chain::exit_name(&chain);
        if !self.running() {
            return Err(Error::msg("start the core first"));
        }
        // A subscription may have been removed and reimported with a new ID,
        // while the saved chain still references its previous profile. Rebind
        // only on the user's explicit activation and only after confirming the
        // current profile contains every hop. Never change an unrelated chain.
        let settings = self.settings();
        if chain.profile.is_some() && chain.profile != settings.active_profile {
            let active = settings.active_profile.as_deref().ok_or_else(|| Error::msg("select a profile first"))?;
            let yaml = self.profiles.lock().unwrap().read(active)?;
            let rebound = rebind_chain_to_profile(&chain, active, &yaml, &settings)?;
            self.chains.lock().unwrap().save(rebound.clone())?;
            if let Err(error) = self.reload_locked().await {
                let restored = self.chains.lock().unwrap().save(chain.clone());
                if let Err(restore_error) = restored {
                    return Err(Error::msg(format!("could not activate chain: {error}; could not restore saved chain: {restore_error}")));
                }
                let _ = self.reload_locked().await;
                self.emit_state();
                return Err(Error::msg(format!("could not activate chain: {error}")));
            }
        }
        let mut info = self.build_info.lock().unwrap().clone();
        // A prior save may have left the running core on an older config.
        // Surface its real reload error instead of misreporting a missing server.
        if !info.chain_exits.contains(&exit) {
            self.reload_locked().await.map_err(|error| Error::msg(format!("could not apply chain configuration: {error}")))?;
            info = self.build_info.lock().unwrap().clone();
        }
        if !info.chain_exits.contains(&exit) {
            return Err(Error::msg(
                "this chain is not active in the current profile (a node is missing or it needs at least two hops)",
            ));
        }
        let ctl = self.controller();
        ctl.request("PUT", &format!("/proxies/{}", enc(CHAINS_GROUP)), Some(json!({ "name": exit })))
            .await?;
        for g in &info.main_groups {
            ctl.request("PUT", &format!("/proxies/{}", enc(g)), Some(json!({ "name": CHAINS_GROUP })))
                .await?;
        }
        let _ = ctl
            .request("PUT", "/proxies/GLOBAL", Some(json!({ "name": CHAINS_GROUP })))
            .await;
        Ok(())
    }

    // ---------------------------------------------------------------- misc

    /// Guarded pass-through to the controller for the UI (proxies, delay tests, connections...).
    pub async fn ctl(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        const ALLOWED: &[&str] = &[
            "/version", "/proxies", "/group", "/connections", "/rules", "/providers", "/dns", "/configs", "/memory",
        ];
        let method = method.to_uppercase();
        let route = path.split('?').next().unwrap_or(path);
        #[cfg(target_os = "macos")]
        if route == "/configs" && method != "GET" {
            return Err(Error::msg("controller configuration changes are unavailable in the macOS preview"));
        }
        let allowed = ALLOWED.iter().any(|p| route == *p || route.starts_with(&format!("{p}/")));
        if !allowed || path.contains("..") || (route == "/configs" && method != "GET" && method != "PATCH") {
            return Err(Error::msg("controller path is not allowed"));
        }
        if !self.running() {
            return Err(Error::msg("core is not running"));
        }
        self.controller().request(&method, path, body).await
    }

    pub async fn ip_info(&self) -> Result<Value> {
        let s = self.settings();
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Kometfy");
        b = if self.running() && s.connected {
            b.proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", s.mixed_port))?)
        } else {
            b.no_proxy()
        };
        let v: Value = b.build()?.get("https://ipwho.is/").send().await?.json().await?;
        if v.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(Error::msg("IP lookup service refused the request"));
        }
        let g = |p: &str| v.pointer(p).cloned().unwrap_or(Value::Null);
        Ok(json!({
            "ip": g("/ip"), "country": g("/country"), "country_code": g("/country_code"),
            "city": g("/city"), "isp": g("/connection/isp"), "flag": g("/flag/emoji"),
        }))
    }

    /// Other proxy/VPN clients that may fight over the system proxy or routes.
    pub async fn detect_conflicts(&self) -> Vec<String> {
        #[cfg(not(windows))]
        return Vec::new();
        #[cfg(windows)]
        {
        let own = [self.core.pid(), self.xray.pid()];
        let out = tokio::process::Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .await;
        let Ok(out) = out else { return vec![] };
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let mut found: Vec<String> = Vec::new();
        for line in text.lines() {
            let mut cols = line.split("\",\"").map(|c| c.trim_matches('"'));
            let (Some(name), Some(pid)) = (cols.next(), cols.next()) else { continue };
            let lname = name.to_lowercase();
            if let Some((_, label)) = CONFLICT_PROCESSES.iter().find(|(n, _)| *n == lname) {
                if own.iter().flatten().any(|p| pid.trim() == p.to_string()) {
                    continue;
                }
                // our own cores (in the data folder or beside the app), even when the pid moved on since `own` was read
                if pid.trim().parse().ok().and_then(process_path).is_some_and(|p| self.is_own_program(&p)) {
                    continue;
                }
                if !found.iter().any(|f| f == label) {
                    found.push((*label).to_string());
                }
            }
        }
        found
        }
    }

    #[cfg(windows)]
    fn is_own_program(&self, path: &std::path::Path) -> bool {
        let lower = |p: &std::path::Path| p.to_string_lossy().to_lowercase();
        let path = lower(path);
        let beside_app = std::env::current_exe().ok().and_then(|e| e.parent().map(lower));
        path.starts_with(&lower(&self.paths.root)) || beside_app.is_some_and(|d| path.starts_with(&d))
    }

    pub fn open_data_dir(&self) {
        #[cfg(windows)]
        let _ = std::process::Command::new("explorer").arg(&self.paths.root).spawn();
        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open").arg(&self.paths.root).spawn();
    }

    pub fn clear_error(&self) {
        #[cfg(target_os = "macos")]
        if self.recovery_required.load(SeqCst) { return; }
        *self.last_error.lock().unwrap() = None;
        self.emit_state();
    }

    pub fn log_history(&self) -> Vec<Value> {
        self.log_ring.lock().unwrap().iter().map(|l| parse_log(l)).collect()
    }
}

/// The full path of a running program; None when it is gone or cannot be asked.
#[cfg(windows)]
fn process_path(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0;
        CloseHandle(h);
        ok.then(|| std::ffi::OsString::from_wide(&buf[..len as usize]).into())
    }
}

/// Is there a network adapter with this name? (`netsh` is locale-independent for the name column.)
async fn adapter_exists(name: &str) -> bool {
    #[cfg(target_os = "macos")]
    { crate::tun_macos::interface_exists(name) }
    #[cfg(not(any(windows, target_os = "macos")))]
    { let _ = name; false }
    #[cfg(windows)]
    {
    let out = tokio::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .await;
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .any(|l| l.trim_end().ends_with(name)),
        Err(_) => false,
    }
    }
}

async fn wait_adapter(name: &str, total: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < total {
        if adapter_exists(name).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_run_marker_cannot_be_reenabled_by_a_settings_patch() {
        let dir = std::env::temp_dir().join(format!("kometfy-consent-marker-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let manager = Manager::new(dir.clone(), Arc::new(|_, _| {})).unwrap();
        assert!(manager.settings().consent_fresh);
        manager.update_settings(json!({ "onboarded": true })).await.unwrap();
        assert!(!manager.settings().consent_fresh);
        manager.update_settings(json!({ "onboarded": false, "consent_fresh": true })).await.unwrap();
        assert!(!manager.settings().consent_fresh);
        drop(manager);
        assert!(!Settings::load(&dir.join("settings.json")).consent_fresh);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn newly_consented_install_is_reported_without_waiting_for_the_periodic_tick() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = std::env::temp_dir().join(format!("kometfy-first-stats-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let manager = Manager::new(dir.clone(), Arc::new(|_, _| {})).unwrap();
        manager.metrics.clear(); // A fresh install may have no daily samples yet.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        manager.update_settings(json!({ "backend_url": base })).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept()).await.is_err());

        manager.update_settings(json!({ "consent_stats": true })).await.unwrap();
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await.unwrap().unwrap();
        let mut request = Vec::new();
        let (header_end, body_len) = loop {
            let mut buf = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf)).await.unwrap().unwrap();
            assert!(n > 0, "request closed before the body arrived");
            request.extend_from_slice(&buf[..n]);
            if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                let head = std::str::from_utf8(&request[..end]).unwrap();
                let len = head.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                }).unwrap();
                if request.len() >= end + 4 + len {
                    break (end + 4, len);
                }
            }
        };
        let head = std::str::from_utf8(&request[..header_end]).unwrap();
        assert!(head.starts_with("POST /v1/stats "), "{head}");
        let body: Value = serde_json::from_slice(&request[header_end..header_end + body_len]).unwrap();
        assert_eq!(body["day"], crate::remote::today());
        assert_eq!(body["counts"]["connects"], 0);
        assert_eq!(body["counts"]["connect_ok"], 0);
        assert_eq!(body["install"], manager.settings().install_id);
        assert!(body["net"].is_null() && body["subs"].is_null());
        socket.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn selecting_chain_from_old_profile_rebinds_only_if_all_hops_exist() {
        let chain = Chain { id: "old-chain".into(), name: "ru -> bit usa".into(),
            hops: vec!["entry".into(), "exit".into()], profile: Some("removed-profile".into()) };
        let yaml = "proxies:\n  - {name: entry, type: vless, server: example.com, port: 443}\n  - {name: exit, type: mieru, server: example.net, port: 443}\n";
        let rebound = rebind_chain_to_profile(&chain, "current-profile", yaml, &Settings::default()).unwrap();
        assert_eq!(rebound.profile.as_deref(), Some("current-profile"));
        assert_eq!(chain.profile.as_deref(), Some("removed-profile"));
        let missing = "proxies:\n  - {name: entry, type: vless, server: example.com, port: 443}\n";
        assert!(rebind_chain_to_profile(&chain, "current-profile", missing, &Settings::default()).is_err());
    }

    #[tokio::test]
    async fn the_telegram_bridge_is_remembered() {
        let dir = std::env::temp_dir().join(format!("kometfy-tg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let manager = Manager::new(dir.clone(), Arc::new(|_, _| {})).unwrap();
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        manager.settings.write().unwrap().tg.port = port;
        // the free mode's main switch on, so the bridge starts as soon as it is chosen
        manager.settings.write().unwrap().free_on = true;
        manager.set_tg_bridge(true).await.unwrap();
        let saved = Settings::load(&dir.join("settings.json"));
        assert!(saved.tg.enabled && saved.tg.secret.len() == 32, "{:?}", saved.tg);
        assert!(manager.state().tg.running);
        manager.set_tg_bridge(false).await.unwrap();
        assert!(!Settings::load(&dir.join("settings.json")).tg.enabled);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The big button of the free mode runs what the Tools page chose and never changes those choices: switched off
    /// and on again it brings back exactly the same tools, and a tool chosen while it is off waits for it.
    #[tokio::test]
    async fn the_free_switch_keeps_the_users_choices() {
        let dir = std::env::temp_dir().join(format!("kometfy-free-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let m = Manager::new(dir.clone(), Arc::new(|_, _| {})).unwrap();
        {
            let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let mut s = m.settings.write().unwrap();
            s.tg.port = probe.local_addr().unwrap().port();
            // only the bridge: the filters would need a core, which tests do not have
            (s.adblock, s.ai_access, s.games_dns, s.zapret.enabled) = (false, false, false, false);
        }
        // a fresh install: the bridge is chosen, but nothing runs before the press
        assert!(!m.settings().free_on && m.settings().tg.enabled && m.settings().zapret.strategy.is_empty());
        m.set_tg_bridge(true).await.unwrap();
        assert!(!m.state().tg.running, "chosen while the switch is off: it waits");
        m.set_free(true).await.unwrap();
        assert!(m.state().tg.running);
        m.set_free(false).await.unwrap();
        assert!(!m.state().tg.running);
        assert!(m.settings().tg.enabled, "the button must not undo the choice");
        m.set_tg_bridge(false).await.unwrap();
        m.set_free(true).await.unwrap();
        assert!(!m.state().tg.running, "switched off on the Tools page: the button must not bring it back");
        m.set_free(false).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    fn test_manager() -> (Arc<Manager>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("prism-lifecycle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let manager = Manager::new(dir.clone(), Arc::new(|_, _| {})).unwrap();
        (manager, dir)
    }

    /// A fresh install stores the smart mode, but with no key the free tools are all there is: the bypass must
    /// not wait "while the VPN is on". The first key brings the stored mode back.
    #[tokio::test]
    async fn no_key_means_the_free_mode() {
        use crate::settings::AppMode;
        let dir = std::env::temp_dir().join(format!("kometfy-mode-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let m = Manager::new(dir.clone(), Arc::new(|_, _| {})).unwrap();
        assert_eq!(m.settings.read().unwrap().app_mode, AppMode::SmartHybridVpn);
        assert_eq!(m.settings().app_mode, AppMode::FreeAntiDpi);
        m.import_profile("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=tcp#t", None).await.unwrap();
        assert_eq!(m.settings().app_mode, AppMode::SmartHybridVpn);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn proxy_readiness_rejects_a_non_socks_listener() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(b"no").await.unwrap();
        });
        assert!(verify_macos_proxy_listener(port).await.is_err());
        server.await.unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn changing_bypass_restores_proxy_before_reactivating_it() {
        use std::{io::BufReader, os::unix::net::UnixStream, sync::mpsc, thread};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use crate::{macos_proxy_guard::{self, Backend}, macos_proxy_session::GuardSession};
        struct Fake(mpsc::Sender<String>);
        impl Backend for Fake {
            fn recover_previous(&mut self) -> std::result::Result<(), String> { Ok(()) }
            fn enable(&mut self, _: u16, bypass: &str) -> std::result::Result<(), String> {
                self.0.send(format!("enable:{bypass}")).unwrap(); Ok(())
            }
            fn restore(&mut self, _: u16) -> std::result::Result<(), String> {
                self.0.send("restore".into()).unwrap(); Ok(())
            }
        }
        let (app, peer) = UnixStream::pair().unwrap();
        let (events, observed) = mpsc::channel();
        let task = thread::spawn(move || {
            macos_proxy_guard::serve(&mut BufReader::new(peer.try_clone().unwrap()), &mut &peer, &mut Fake(events)).unwrap();
        });
        let guard = Arc::new(GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap());
        let (manager, dir) = test_manager();
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        manager.settings.write().unwrap().mixed_port = listener.local_addr().unwrap().port();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
        });
        manager.attach_proxy_guard(guard.clone()).await.unwrap();
        let identity = manager.core.test_start_inert_child();
        *manager.proxy_guard_core.lock().unwrap() = Some(identity);
        guard.enable(manager.settings().mixed_port, "old.local").unwrap();
        { let mut settings = manager.settings.write().unwrap(); settings.connected = true; settings.sysproxy_bypass = "old.local".into(); }
        manager.update_settings(json!({"sysproxy_bypass":"new.local"})).await.unwrap();
        assert!(manager.settings().connected);
        assert_eq!(observed.try_iter().collect::<Vec<_>>(), ["enable:old.local", "restore", "enable:new.local"]);
        proxy.await.unwrap();
        guard.shutdown().unwrap();
        manager.core.stop();
        task.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn changing_to_unavailable_tun_preserves_live_proxy_selection() {
        let (manager, dir) = test_manager();
        { let mut settings = manager.settings.write().unwrap(); settings.connected = true; settings.method = Method::SystemProxy; }
        assert!(manager.update_settings(json!({"method":"tun"})).await.is_err());
        assert_eq!(manager.settings().method, Method::SystemProxy);
        assert!(manager.settings().connected);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn failed_recovery_blocks_stopping_and_handoff_until_retried() {
        let (manager, dir) = test_manager();
        let backup = manager.paths.sysproxy_backup();
        std::fs::write(&backup, b"existing backup").unwrap();
        assert!(manager.stop_core().await.is_err());
        assert!(manager.state().recovery_required);
        assert!(manager.release().await.is_err());
        assert!(!manager.handoff_prepared());
        assert!(manager.start_core().await.is_err());
        assert!(backup.is_file(), "failed recovery must preserve the backup");
        std::fs::remove_file(&backup).unwrap();
        assert!(manager.retry_proxy_recovery().await.is_err(), "deleting a backup is not recovery");
        assert!(manager.state().recovery_required);
        assert!(!manager.handoff_prepared());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn prepared_handoff_blocks_new_core_start_until_cancelled() {
        let (manager, dir) = test_manager();
        assert!(!manager.release().await.unwrap());
        assert!(manager.handoff_prepared());
        assert!(manager.start_core().await.is_err());
        assert!(manager.release().await.is_err());
        assert_eq!(manager.cancel_handoff().await, Some((false, false)));
        assert!(!manager.handoff_prepared());
        assert!(manager.release().await.is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn startup_with_backup_blocks_auto_start_and_keeps_error_visible() {
        let dir = std::env::temp_dir().join(format!("prism-lifecycle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let backup = dir.join("sysproxy_backup.json");
        std::fs::write(&backup, b"unfinished recovery").unwrap();
        let manager = Manager::new(dir.clone(), Arc::new(|_, _| {})).unwrap();
        manager.startup(true).await;
        let state = manager.state();
        assert!(state.recovery_required);
        assert!(!state.core.running);
        assert!(state.last_error.as_deref().is_some_and(|e| e.contains("recovery")));
        manager.clear_error();
        assert!(manager.state().last_error.is_some());
        assert!(manager.connect().await.is_err());
        assert!(manager.update_settings(serde_json::json!({"mixed_port": 12345})).await.is_err());
        assert!(backup.is_file());
        manager.monitor.lock().unwrap().take().unwrap().abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn attached_guard_retries_failed_recovery_without_opening_preview_gate() {
        use std::{io::BufReader, os::unix::net::UnixStream, thread};
        use crate::{macos_proxy_guard::{self, Backend}, macos_proxy_session::GuardSession};
        struct Fake { failures: usize }
        impl Backend for Fake {
            fn recover_previous(&mut self) -> std::result::Result<(), String> { Ok(()) }
            fn enable(&mut self, _: u16, _: &str) -> std::result::Result<(), String> { Ok(()) }
            fn restore(&mut self, _: u16) -> std::result::Result<(), String> {
                if self.failures > 0 { self.failures -= 1; Err("injected failure".into()) } else { Ok(()) }
            }
        }
        let (app, peer) = UnixStream::pair().unwrap();
        let task = thread::spawn(move || {
            let mut fake = Fake { failures: 1 };
            macos_proxy_guard::serve(&mut BufReader::new(peer.try_clone().unwrap()), &mut &peer, &mut fake).unwrap();
        });
        let guard = Arc::new(GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap());
        let (manager, dir) = test_manager();
        manager.attach_proxy_guard(guard.clone()).await.unwrap();
        assert!(manager.connect().await.is_err(), "unverified guard must not open the preview gate");
        guard.enable(7890, "localhost;<local>").unwrap();
        assert!(manager.stop_core().await.is_err());
        assert!(manager.state().recovery_required);
        manager.retry_proxy_recovery().await.unwrap();
        assert!(!manager.state().recovery_required);
        guard.shutdown().unwrap();
        task.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn monitor_restores_orphaned_proxy_even_without_expected_running_flag() {
        use std::{io::BufReader, os::unix::net::UnixStream, sync::mpsc, thread};
        use crate::{macos_proxy_guard::{self, Backend}, macos_proxy_session::GuardSession, macos_proxy_client::State};
        struct Fake(mpsc::Sender<&'static str>);
        impl Backend for Fake {
            fn recover_previous(&mut self) -> std::result::Result<(), String> { Ok(()) }
            fn enable(&mut self, _: u16, _: &str) -> std::result::Result<(), String> { Ok(()) }
            fn restore(&mut self, _: u16) -> std::result::Result<(), String> { self.0.send("restore").unwrap(); Ok(()) }
        }
        let (app, peer) = UnixStream::pair().unwrap();
        let (events, observed) = mpsc::channel();
        let task = thread::spawn(move || {
            let mut fake = Fake(events);
            macos_proxy_guard::serve(&mut BufReader::new(peer.try_clone().unwrap()), &mut &peer, &mut fake).unwrap();
        });
        let guard = Arc::new(GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap());
        let (manager, dir) = test_manager();
        manager.attach_proxy_guard(guard.clone()).await.unwrap();
        guard.enable(7890, "").unwrap();
        manager.settings.write().unwrap().connected = true;
        assert!(!manager.expected_running.load(SeqCst));
        manager.spawn_monitor();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if guard.try_state().unwrap() == Some(State::Idle) && !manager.settings().connected { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.unwrap();
        assert_eq!(observed.try_recv().unwrap(), "restore");
        assert!(!manager.settings().connected);
        assert!(!manager.recovery_required.load(SeqCst));
        assert!(manager.connect().await.is_err(), "preview gate remains closed");
        manager.monitor.lock().unwrap().take().unwrap().abort();
        guard.shutdown().unwrap();
        task.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn orphaned_proxy_recovery_failure_stays_visible_and_can_be_retried() {
        use std::{io::BufReader, os::unix::net::UnixStream, thread};
        use crate::{macos_proxy_guard::{self, Backend}, macos_proxy_session::GuardSession};
        struct Fake(bool);
        impl Backend for Fake {
            fn recover_previous(&mut self) -> std::result::Result<(), String> { Ok(()) }
            fn enable(&mut self, _: u16, _: &str) -> std::result::Result<(), String> { Ok(()) }
            fn restore(&mut self, _: u16) -> std::result::Result<(), String> {
                if self.0 { self.0 = false; Err("injected failure".into()) } else { Ok(()) }
            }
        }
        let (app, peer) = UnixStream::pair().unwrap();
        let task = thread::spawn(move || {
            let mut fake = Fake(true);
            macos_proxy_guard::serve(&mut BufReader::new(peer.try_clone().unwrap()), &mut &peer, &mut fake).unwrap();
        });
        let guard = Arc::new(GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap());
        let (manager, dir) = test_manager();
        manager.attach_proxy_guard(guard.clone()).await.unwrap();
        guard.enable(7890, "").unwrap();
        manager.handle_core_exit().await;
        assert!(manager.state().recovery_required);
        assert!(manager.state().last_error.as_deref().is_some_and(|error| error.contains("recovery")));
        manager.retry_proxy_recovery().await.unwrap();
        assert!(!manager.state().recovery_required);
        guard.shutdown().unwrap();
        task.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn replaced_core_restores_old_proxy_without_stopping_replacement() {
        use std::{io::BufReader, os::unix::net::UnixStream, thread};
        use crate::{macos_proxy_guard::{self, Backend}, macos_proxy_session::GuardSession, macos_proxy_client::State};
        struct Fake;
        impl Backend for Fake {
            fn recover_previous(&mut self) -> std::result::Result<(), String> { Ok(()) }
            fn enable(&mut self, _: u16, _: &str) -> std::result::Result<(), String> { Ok(()) }
            fn restore(&mut self, _: u16) -> std::result::Result<(), String> { Ok(()) }
        }
        let (app, peer) = UnixStream::pair().unwrap();
        let task = thread::spawn(move || {
            let mut fake = Fake;
            macos_proxy_guard::serve(&mut BufReader::new(peer.try_clone().unwrap()), &mut &peer, &mut fake).unwrap();
        });
        let guard = Arc::new(GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap());
        let (manager, dir) = test_manager();
        manager.attach_proxy_guard(guard.clone()).await.unwrap();
        let original = manager.core.test_start_inert_child();
        *manager.proxy_guard_core.lock().unwrap() = Some(original.clone());
        guard.enable(7890, "").unwrap();
        manager.settings.write().unwrap().connected = true;
        manager.expected_running.store(true, SeqCst);
        assert!(manager.core.stop_if_identity(&original));
        let replacement = manager.core.test_start_inert_child();
        manager.handle_core_exit().await;
        assert_eq!(guard.state().unwrap(), State::Idle);
        assert!(manager.core.identity_is_running(&replacement));
        assert!(!manager.settings().connected);
        assert!(manager.expected_running.load(SeqCst));
        guard.shutdown().unwrap();
        task.join().unwrap();
        assert!(manager.core.stop_if_identity(&replacement));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn guard_cannot_mask_a_late_legacy_backup() {
        use std::os::unix::net::UnixStream;
        let (manager, dir) = test_manager();
        std::fs::write(manager.paths.sysproxy_backup(), b"legacy backup").unwrap();
        let (app, _peer) = UnixStream::pair().unwrap();
        let guard = Arc::new(crate::macos_proxy_session::GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap());
        assert!(manager.attach_proxy_guard(guard).await.is_err());
        assert!(manager.state().recovery_required);
        std::fs::remove_file(manager.paths.sysproxy_backup()).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn deleting_legacy_backup_after_attach_does_not_clear_recovery() {
        use std::os::unix::net::UnixStream;
        let (manager, dir) = test_manager();
        let (app, _peer) = UnixStream::pair().unwrap();
        let guard = Arc::new(crate::macos_proxy_session::GuardSession::from_authenticated_stream(app, Duration::from_secs(2)).unwrap());
        manager.attach_proxy_guard(guard).await.unwrap();
        std::fs::write(manager.paths.sysproxy_backup(), b"legacy backup").unwrap();
        assert!(manager.retry_proxy_recovery().await.is_err());
        std::fs::remove_file(manager.paths.sysproxy_backup()).unwrap();
        assert!(manager.retry_proxy_recovery().await.is_err());
        assert!(manager.state().recovery_required);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn log_line_parsed() {
        let v = parse_log(r#"time="2026-11-05T10:00:00+03:00" level=warning msg="dial \"x\" failed""#);
        assert_eq!(v["level"], "warning");
        assert_eq!(v["msg"], "dial \"x\" failed");
    }

    #[test]
    fn plain_line_falls_back() {
        let v = parse_log("hello");
        assert_eq!(v["msg"], "hello");
        assert_eq!(v["level"], "info");
    }
}
