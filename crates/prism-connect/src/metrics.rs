//! Local statistics: how fast and how reliably PrismRoute works on this PC.
//!
//! Nothing here leaves the computer. Operations are not logged one by one: each one only bumps a
//! counter or a histogram bucket of the current day, and days older than `KEEP_DAYS` are dropped,
//! so the file stays a few tens of kilobytes however long the app runs.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{error::Error, util::write_atomic};

/// Days of daily aggregates that are kept.
pub const KEEP_DAYS: usize = 90;
/// Notable events (a failure, a core exit) kept for the diagnostic report: a kind and a short code, never free text.
const RECENT_MAX: usize = 40;

/// Names of the counters and histograms. A histogram name may carry a `.label` (`working_set_mb.core`).
pub mod name {
    pub const APP_START: &str = "app_start";
    pub const APP_CRASH: &str = "app_crash_count";
    pub const UNCLEAN_EXIT: &str = "unclean_exit_count";
    pub const CORE_EXIT: &str = "core_unexpected_exit";
    pub const CONNECT_ATTEMPTS: &str = "connect_attempts";
    pub const CONNECT_OK: &str = "connect_ok";
    pub const CONNECT_FAILED: &str = "connect_failed";
    pub const TUN_FAILED: &str = "tun_start_failed";
    pub const RELOAD_OK: &str = "config_reload_ok";
    pub const RELOAD_FAILED: &str = "config_reload_failed";
    pub const SUB_OK: &str = "subscription_update_ok";
    pub const SUB_FAILED: &str = "subscription_update_failed";
    pub const APP_START_MS: &str = "app_start_duration_ms";
    pub const CONNECT_MS: &str = "connect_duration_ms";
    pub const TUN_MS: &str = "tun_start_duration_ms";
    pub const RELOAD_MS: &str = "config_reload_duration_ms";
    pub const MEMORY_MB: &str = "working_set_mb";
    /// Processor load as `top` shows it: one core fully busy is 100. (The old `cpu_percent` was a share of the
    /// whole machine, so an app burning a whole core of eight read as 12%.)
    pub const CPU_PCT: &str = "cpu_core_percent";
}

// Upper bounds of the histogram buckets (a last bucket takes everything above).
const MS: &[f64] = &[50.0, 100.0, 250.0, 500.0, 1_000.0, 2_000.0, 3_000.0, 5_000.0, 8_000.0, 15_000.0, 30_000.0];
const MB: &[f64] = &[50.0, 100.0, 150.0, 200.0, 300.0, 400.0, 600.0, 800.0, 1_200.0, 2_000.0];
const PCT: &[f64] = &[1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 60.0, 80.0, 100.0, 150.0, 200.0, 300.0, 400.0];

fn bounds(key: &str) -> &'static [f64] {
    if key.starts_with(name::MEMORY_MB) {
        MB
    } else if key.starts_with(name::CPU_PCT) {
        PCT
    } else {
        MS
    }
}

/// Counts of samples per bucket, plus what is needed for the average and the maximum.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hist {
    pub n: u64,
    pub sum: f64,
    pub max: f64,
    /// `bounds.len() + 1` counts; the last one is "above the last bound".
    pub b: Vec<u64>,
}

impl Hist {
    fn add(&mut self, bounds: &[f64], v: f64) {
        if !v.is_finite() || v < 0.0 {
            return;
        }
        self.b.resize(bounds.len() + 1, 0);
        let i = bounds.iter().position(|&u| v <= u).unwrap_or(bounds.len());
        self.b[i] += 1;
        self.n += 1;
        self.sum += v;
        self.max = self.max.max(v);
    }

    fn merge(&mut self, o: &Hist) {
        if self.b.len() < o.b.len() {
            self.b.resize(o.b.len(), 0);
        }
        for (a, b) in self.b.iter_mut().zip(&o.b) {
            *a += b;
        }
        self.n += o.n;
        self.sum += o.sum;
        self.max = self.max.max(o.max);
    }

    /// The value below which the share `q` (0..1) of the samples lie, estimated inside the bucket.
    fn quantile(&self, bounds: &[f64], q: f64) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        let want = q * self.n as f64;
        let mut seen = 0.0;
        for (i, &c) in self.b.iter().enumerate() {
            let c = c as f64;
            if c > 0.0 && seen + c >= want {
                let lo = if i == 0 { 0.0 } else { bounds.get(i - 1).copied().unwrap_or(self.max) };
                let hi = bounds.get(i).copied().unwrap_or(self.max).max(lo);
                return (lo + (hi - lo) * ((want - seen) / c).clamp(0.0, 1.0)).min(self.max);
            }
            seen += c;
        }
        self.max
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Day {
    #[serde(default)]
    counts: BTreeMap<String, u64>,
    #[serde(default)]
    hists: BTreeMap<String, Hist>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds.
    pub t: i64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    days: BTreeMap<String, Day>,
    #[serde(default)]
    recent: VecDeque<Event>,
}

fn prune(s: &mut Store) {
    while s.days.len() > KEEP_DAYS {
        s.days.pop_first();
    }
}

/// Why something failed. Only the first two count against PrismRoute's own reliability: somebody
/// else's server being down, a provider's refusal or the user's own choice are not its fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    /// A bug or a broken file/registry operation on this PC.
    App,
    /// mihomo or Xray: would not start, refused the config, died, or the TUN adapter did not come up.
    Core,
    /// The subscription: provider refused it, device limit, the file is not a profile.
    Subscription,
    /// Timeouts, DNS, refused or reset connections: the network between here and a remote server.
    Network,
    /// The user decided: administrator rights were not given, no core installed, input was invalid.
    User,
}

impl Fail {
    pub fn as_str(self) -> &'static str {
        match self {
            Fail::App => "app",
            Fail::Core => "core",
            Fail::Subscription => "subscription",
            Fail::Network => "network",
            Fail::User => "user",
        }
    }
}

/// Where an operation stopped; the same message means different things at different steps.
#[derive(Debug, Clone, Copy)]
pub enum Stage {
    /// Building the config, starting the core, waiting for its controller.
    Start,
    /// Turning on the system proxy or TUN.
    Capture,
    /// Downloading or reading a subscription.
    Subscription,
}

pub fn classify(stage: Stage, e: &Error) -> Fail {
    match e {
        Error::NeedAdmin | Error::CoreMissing => Fail::User,
        Error::Yaml(_) => Fail::Subscription,
        Error::Io(_) | Error::Json(_) => Fail::App,
        Error::Msg(m) => classify_text(stage, m),
    }
}

fn classify_text(stage: Stage, text: &str) -> Fail {
    let m = text.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| m.contains(w));
    if has(&[
        "timed out",
        "timeout",
        "dns error",
        "connection refused",
        "connection reset",
        "unreachable",
        "error sending request",
        "tls handshake",
        "certificate",
        "connection closed",
    ]) {
        return Fail::Network;
    }
    match stage {
        Stage::Subscription => Fail::Subscription,
        Stage::Start if has(&["subscription", "profile", "no servers"]) => Fail::Subscription,
        Stage::Start => Fail::Core,
        Stage::Capture if has(&["tun", "adapter"]) => Fail::Core,
        Stage::Capture => Fail::App,
    }
}

#[derive(Debug, Serialize)]
pub struct Stat {
    pub n: u64,
    pub avg: f64,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

#[derive(Debug, Default, Serialize)]
pub struct Reliability {
    pub attempts: u64,
    pub ok: u64,
    pub app: u64,
    pub core: u64,
    pub subscription: u64,
    pub network: u64,
    pub user: u64,
    /// Failures PrismRoute answers for (app + core), as a share of the attempts that nobody else
    /// decided: successes plus those failures. `None` until there is one.
    pub own_failure_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    /// Days asked for, and the first day that actually has data.
    pub days: usize,
    pub from: Option<String>,
    pub counts: BTreeMap<String, u64>,
    pub stats: BTreeMap<String, Stat>,
    pub reliability: Reliability,
    pub recent: Vec<Event>,
    /// The latest reading of every histogram since the app started (memory, processor): what is happening now,
    /// which the percentiles over days, mostly spent in the background, hide.
    pub now: BTreeMap<String, f64>,
}

pub struct Metrics {
    path: PathBuf,
    store: Mutex<Store>,
    dirty: AtomicBool,
    on: AtomicBool,
    latest: Mutex<BTreeMap<String, f64>>,
}

/// Where the panic hook leaves its note; it must not touch the store, whose lock the panic may hold.
static PANIC_MARK: OnceLock<PathBuf> = OnceLock::new();

impl Metrics {
    pub fn open(path: PathBuf, on: bool) -> Self {
        let mut store: Store = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        prune(&mut store);
        Self { path, store: Mutex::new(store), dirty: AtomicBool::new(false), on: AtomicBool::new(on), latest: Mutex::default() }
    }

    pub fn set_on(&self, on: bool) {
        self.on.store(on, SeqCst);
    }

    fn with_day(&self, f: impl FnOnce(&mut Day)) {
        if !self.on.load(SeqCst) {
            return;
        }
        let mut s = self.store.lock().unwrap();
        f(s.days.entry(Utc::now().format("%Y-%m-%d").to_string()).or_default());
        prune(&mut s);
        self.dirty.store(true, SeqCst);
    }

    pub fn count(&self, name: &str) {
        self.add(name, 1);
    }

    pub fn add(&self, name: &str, n: u64) {
        self.with_day(|d| *d.counts.entry(name.into()).or_default() += n);
    }

    pub fn observe(&self, name: &str, v: f64) {
        if v.is_finite() && v >= 0.0 {
            self.latest.lock().unwrap().insert(name.into(), v);
        }
        self.with_day(|d| d.hists.entry(name.into()).or_default().add(bounds(name), v));
    }

    pub fn millis(&self, name: &str, d: Duration) {
        self.observe(name, d.as_secs_f64() * 1000.0);
    }

    /// A failure of kind `kind` for the operation counted as `base` (`connect_failed.core`); the
    /// kind also goes to the recent events unless it was the user's own doing.
    pub fn failed(&self, base: &str, kind: Fail) {
        self.count(&format!("{base}.{}", kind.as_str()));
        if kind != Fail::User {
            self.event(base, kind.as_str());
        }
    }

    pub fn event(&self, kind: &str, detail: &str) {
        if !self.on.load(SeqCst) {
            return;
        }
        let mut s = self.store.lock().unwrap();
        s.recent.push_back(Event { t: Utc::now().timestamp(), kind: kind.into(), detail: detail.into() });
        while s.recent.len() > RECENT_MAX {
            s.recent.pop_front();
        }
        self.dirty.store(true, SeqCst);
    }

    /// Write the file if anything changed since the last time.
    pub fn flush(&self) {
        if !self.dirty.swap(false, SeqCst) {
            return;
        }
        let bytes = serde_json::to_vec(&*self.store.lock().unwrap());
        if let Ok(bytes) = bytes {
            let _ = write_atomic(&self.path, &bytes);
        }
    }

    pub fn clear(&self) {
        *self.store.lock().unwrap() = Store::default();
        self.dirty.store(false, SeqCst);
        let _ = std::fs::remove_file(&self.path);
    }

    fn marker(&self) -> PathBuf {
        self.path.with_file_name("session.lock")
    }

    /// A run leaves a marker while it lives. A marker found at start means the last run did not
    /// exit cleanly: with a panic noted in it that is a crash, otherwise the process was killed
    /// (power loss, Task Manager, a system shutdown), which is no proof of a bug.
    pub fn start_session(&self) {
        let marker = self.marker();
        if let Ok(old) = std::fs::read_to_string(&marker) {
            if old.contains("panic") {
                self.count(name::APP_CRASH);
                self.event("app_crash", "panic");
            } else {
                self.count(name::UNCLEAN_EXIT);
                self.event("unclean_exit", "");
            }
        }
        let _ = std::fs::write(&marker, "running");
        self.count(name::APP_START);
    }

    /// The app is leaving on purpose.
    pub fn end_session(&self) {
        let _ = std::fs::remove_file(self.marker());
        self.flush();
    }

    /// From now on a panic leaves a note in the session marker (and the usual message goes on).
    pub fn install_panic_hook(&self) {
        if PANIC_MARK.set(self.marker()).is_err() {
            return;
        }
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(path) = PANIC_MARK.get() {
                let _ = std::fs::write(path, "panic");
            }
            previous(info);
        }));
    }

    /// One day's counts and the app's 95th percentile of processor load and memory (`date` is YYYY-MM-DD in
    /// UTC), or None when nothing was counted that day.
    pub fn day_totals(&self, date: &str) -> Option<DayTotals> {
        let s = self.store.lock().unwrap();
        let d = s.days.get(date)?;
        let p95 = |name: &str| d.hists.get(name).filter(|h| h.n > 0).map(|h| h.quantile(bounds(name), 0.95));
        Some(DayTotals {
            counts: d.counts.clone(),
            cpu_p95: p95(&format!("{}.app", name::CPU_PCT)),
            mem_p95: p95(&format!("{}.app", name::MEMORY_MB)),
        })
    }

    pub fn summary(&self, days: usize) -> Summary {
        let s = self.store.lock().unwrap();
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut hists: BTreeMap<String, Hist> = BTreeMap::new();
        let mut from = None;
        for (date, day) in s.days.iter().rev().take(days.max(1)) {
            from = Some(date.clone());
            for (k, v) in &day.counts {
                *counts.entry(k.clone()).or_default() += v;
            }
            for (k, h) in &day.hists {
                hists.entry(k.clone()).or_default().merge(h);
            }
        }
        let stats = hists
            .iter()
            .filter(|(_, h)| h.n > 0)
            .map(|(k, h)| {
                let b = bounds(k);
                (k.clone(), Stat { n: h.n, avg: h.sum / h.n as f64, p50: h.quantile(b, 0.5), p95: h.quantile(b, 0.95), max: h.max })
            })
            .collect();
        let get = |k: &str| counts.get(k).copied().unwrap_or(0);
        let kind = |k: &str| get(&format!("{}.{k}", name::CONNECT_FAILED));
        let mut r = Reliability {
            attempts: get(name::CONNECT_ATTEMPTS),
            ok: get(name::CONNECT_OK),
            app: kind("app"),
            core: kind("core"),
            subscription: kind("subscription"),
            network: kind("network"),
            user: kind("user"),
            own_failure_pct: None,
        };
        let own = r.app + r.core;
        if r.ok + own > 0 {
            r.own_failure_pct = Some(own as f64 * 100.0 / (r.ok + own) as f64);
        }
        let now = self.latest.lock().unwrap().clone();
        Summary { days, from, counts, stats, reliability: r, recent: s.recent.iter().cloned().collect(), now }
    }
}

/// What [`Metrics::day_totals`] gives back.
#[derive(Debug, Clone, PartialEq)]
pub struct DayTotals {
    pub counts: BTreeMap<String, u64>,
    pub cpu_p95: Option<f64>,
    pub mem_p95: Option<f64>,
}

/// Memory and processor time of one process, as the system reports them.
pub struct ProcSample {
    pub working_set_mb: f64,
    pub cpu_secs: f64,
}

#[cfg(windows)]
pub fn sample_process(pid: u32) -> Option<ProcSample> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME},
        System::{
            ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        },
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut mem: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        let cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        mem.cb = cb;
        let got_mem = K32GetProcessMemoryInfo(h, &mut mem, cb) != 0;
        let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
            (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed());
        let got_times = GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) != 0;
        CloseHandle(h);
        if !got_mem || !got_times {
            return None;
        }
        // FILETIME counts 100 ns steps
        let secs = |f: FILETIME| (((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64) as f64 / 1e7;
        Some(ProcSample { working_set_mb: mem.WorkingSetSize as f64 / 1_048_576.0, cpu_secs: secs(kernel) + secs(user) })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn sample_process(pid: u32) -> Option<ProcSample> {
    let pages: f64 = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?.split_whitespace().nth(1)?.parse().ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // the command name sits in parentheses and may hold spaces: count the fields after the last ')'
    let rest: Vec<&str> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
    let ticks = rest.get(11)?.parse::<f64>().ok()? + rest.get(12)?.parse::<f64>().ok()?;
    let (hz, page) = unsafe { (libc::sysconf(libc::_SC_CLK_TCK) as f64, libc::sysconf(libc::_SC_PAGESIZE) as f64) };
    if hz <= 0.0 || page <= 0.0 {
        return None;
    }
    Some(ProcSample { working_set_mb: pages * page / 1_048_576.0, cpu_secs: ticks / hz })
}

/// shortcut: no reading on macOS yet, add one (`proc_pidinfo`) when its numbers are needed.
#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub fn sample_process(_pid: u32) -> Option<ProcSample> {
    None
}

/// The processes started by `pid`, their children and so on (on Windows the WebView2 browser, renderer and GPU
/// processes of the app's window, which do most of its drawing).
#[cfg(windows)]
pub fn descendants(pid: u32) -> Vec<u32> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS},
    };
    let mut pairs = Vec::new();
    // SAFETY: a snapshot handle read with its own entry type and closed once
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                pairs.push((e.th32ProcessID, e.th32ParentProcessID));
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    children_of(pid, &pairs)
}

/// Every process under `root` in a list of (pid, parent) pairs.
#[cfg_attr(not(windows), allow(dead_code))]
fn children_of(root: u32, pairs: &[(u32, u32)]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut todo = vec![root];
    while let Some(p) = todo.pop() {
        for &(child, parent) in pairs {
            if parent == p && child != root && !out.contains(&child) {
                out.push(child);
                todo.push(child);
            }
        }
    }
    out
}

/// Turns the processor time of processes into a load between two readings (one core fully busy is 100).
#[derive(Default)]
pub struct Sampler {
    last: Mutex<HashMap<u32, (Instant, f64)>>,
}

impl Sampler {
    /// Record memory and processor load of the processes `pids` together under `label` (`app`, `core`,
    /// `xray`). A process seen for the first time adds its memory but none of its past processor time.
    pub fn take(&self, metrics: &Metrics, label: &str, pids: &[u32]) {
        let now = Instant::now();
        let (mut mem, mut cpu, mut wall, mut seen) = (0.0, 0.0, 0.0f64, false);
        let mut last = self.last.lock().unwrap();
        if last.len() > 64 {
            last.clear();
        }
        for &pid in pids {
            let Some(s) = sample_process(pid) else { continue };
            seen = true;
            mem += s.working_set_mb;
            if let Some((then, before)) = last.insert(pid, (now, s.cpu_secs)) {
                cpu += (s.cpu_secs - before).max(0.0);
                wall = wall.max(now.duration_since(then).as_secs_f64());
            }
        }
        drop(last);
        if !seen {
            return;
        }
        metrics.observe(&format!("{}.{label}", name::MEMORY_MB), mem);
        if wall >= 1.0 {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get()) as f64;
            metrics.observe(&format!("{}.{label}", name::CPU_PCT), (cpu / wall * 100.0).min(cores * 100.0));
        }
    }
}

/// `dir/metrics.json` next to the other files of the app.
pub fn file_in(dir: &Path) -> PathBuf {
    dir.join("metrics.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("prism-metrics-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn children_are_found_at_every_depth_and_only_under_the_root() {
        // 10 is the app; 11 its WebView2 browser with 12 and 13 under it; 20 is someone else's
        let pairs = [(10, 1), (11, 10), (12, 11), (13, 11), (20, 1), (21, 20)];
        let mut got = children_of(10, &pairs);
        got.sort();
        assert_eq!(got, vec![11, 12, 13]);
        assert!(children_of(21, &pairs).is_empty());
    }

    #[test]
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    fn a_busy_process_reads_as_a_share_of_one_core_and_shows_now() {
        let dir = temp("cpu");
        let m = Metrics::open(file_in(&dir), true);
        let s = Sampler::default();
        let me = std::process::id();
        s.take(&m, "app", &[me]);
        let start = Instant::now();
        let mut x = 0u64;
        while start.elapsed() < Duration::from_millis(1100) {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        }
        std::hint::black_box(x);
        s.take(&m, "app", &[me]);
        let now = m.summary(1).now;
        let cpu = now.get(&format!("{}.app", name::CPU_PCT)).copied().unwrap_or(0.0);
        // one thread spinning for a second is most of one core, whatever the number of cores
        assert!(cpu > 50.0, "{cpu}");
        assert!(now.contains_key(&format!("{}.app", name::MEMORY_MB)));
    }

    #[test]
    fn percentiles_stay_inside_what_was_seen() {
        let mut h = Hist::default();
        for v in [120.0, 130.0, 140.0, 900.0, 1200.0] {
            h.add(MS, v);
        }
        let (p50, p95) = (h.quantile(MS, 0.5), h.quantile(MS, 0.95));
        assert!((100.0..=250.0).contains(&p50), "{p50}");
        assert!(p95 > p50 && p95 <= 1200.0, "{p95}");
        assert_eq!(h.max, 1200.0);
        assert_eq!(h.n, 5);
        // one sample: every percentile is that sample or below it
        let mut one = Hist::default();
        one.add(MS, 1200.0);
        assert!(one.quantile(MS, 0.5) <= 1200.0);
    }

    #[test]
    fn one_bad_value_does_not_poison_the_histogram() {
        let mut h = Hist::default();
        h.add(MS, f64::NAN);
        h.add(MS, -1.0);
        assert_eq!(h.n, 0);
        assert_eq!(h.quantile(MS, 0.95), 0.0);
    }

    #[test]
    fn failures_by_other_parties_do_not_count_against_reliability() {
        let dir = temp("rel");
        let m = Metrics::open(file_in(&dir), true);
        for _ in 0..8 {
            m.count(name::CONNECT_ATTEMPTS);
            m.count(name::CONNECT_OK);
        }
        for kind in [Fail::Core, Fail::Network, Fail::Network, Fail::Subscription, Fail::User] {
            m.count(name::CONNECT_ATTEMPTS);
            m.failed(name::CONNECT_FAILED, kind);
        }
        let r = m.summary(30).reliability;
        assert_eq!((r.attempts, r.ok, r.core, r.network, r.subscription, r.user), (13, 8, 1, 2, 1, 1));
        // 1 own failure out of 8 successes + 1: the two timeouts, the provider and the user are not counted
        let pct = r.own_failure_pct.unwrap();
        assert!((pct - 100.0 / 9.0).abs() < 1e-9, "{pct}");
        let s = m.summary(30);
        assert!(s.recent.iter().all(|e| e.detail != "user"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nothing_is_kept_when_statistics_are_off() {
        let dir = temp("off");
        let m = Metrics::open(file_in(&dir), false);
        m.count(name::CONNECT_OK);
        m.observe(name::CONNECT_MS, 100.0);
        m.event("x", "y");
        let s = m.summary(30);
        assert!(s.counts.is_empty() && s.stats.is_empty() && s.recent.is_empty());
        m.flush();
        assert!(!file_in(&dir).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_file_keeps_aggregates_not_operations() {
        let dir = temp("size");
        let m = Metrics::open(file_in(&dir), true);
        for i in 0..5_000 {
            m.millis(name::CONNECT_MS, Duration::from_millis(100 + i % 700));
            m.event("connect_failed", "network");
        }
        m.flush();
        let size = std::fs::metadata(file_in(&dir)).unwrap().len();
        assert!(size < 16 * 1024, "{size} bytes");
        let again = Metrics::open(file_in(&dir), true).summary(30);
        assert_eq!(again.stats[name::CONNECT_MS].n, 5_000);
        assert_eq!(again.recent.len(), RECENT_MAX);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn old_days_fall_out() {
        let mut s = Store::default();
        for i in 0..(KEEP_DAYS + 5) {
            s.days.insert(format!("2026-01-{i:03}"), Day::default());
        }
        prune(&mut s);
        assert_eq!(s.days.len(), KEEP_DAYS);
        assert!(!s.days.contains_key("2026-01-000"));
    }

    #[test]
    fn a_leftover_marker_is_a_crash_only_with_a_panic_in_it() {
        let dir = temp("session");
        let m = Metrics::open(file_in(&dir), true);
        m.start_session();
        assert_eq!(m.summary(30).counts.get(name::UNCLEAN_EXIT), None);
        // killed without a word
        let m = Metrics::open(file_in(&dir), true);
        m.start_session();
        m.flush();
        assert_eq!(m.summary(30).counts.get(name::UNCLEAN_EXIT), Some(&1));
        // a panic wrote its note, then the process died
        std::fs::write(dir.join("session.lock"), "panic").unwrap();
        let m = Metrics::open(file_in(&dir), true);
        m.start_session();
        assert_eq!(m.summary(30).counts.get(name::APP_CRASH), Some(&1));
        // a clean exit leaves nothing behind
        m.end_session();
        let m = Metrics::open(file_in(&dir), true);
        m.start_session();
        assert_eq!(m.summary(30).counts.get(name::APP_CRASH), Some(&1));
        assert_eq!(m.summary(30).counts.get(name::UNCLEAN_EXIT), Some(&1));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failures_are_told_apart() {
        let msg = |s: &str| Error::msg(s);
        assert_eq!(classify(Stage::Start, &Error::NeedAdmin), Fail::User);
        assert_eq!(classify(Stage::Start, &Error::CoreMissing), Fail::User);
        assert_eq!(classify(Stage::Start, &msg("core rejected the config: proxy 'a' unsupported")), Fail::Core);
        assert_eq!(classify(Stage::Start, &msg("core did not become ready")), Fail::Core);
        assert_eq!(classify(Stage::Start, &msg("dial tcp 1.2.3.4:443: i/o timeout")), Fail::Network);
        assert_eq!(classify(Stage::Start, &msg("the profile has no servers")), Fail::Subscription);
        assert_eq!(classify(Stage::Capture, &msg("TUN adapter 'PrismRoute' did not start.")), Fail::Core);
        assert_eq!(classify(Stage::Capture, &msg("could not write the registry")), Fail::App);
        assert_eq!(classify(Stage::Subscription, &msg("error sending request: dns error")), Fail::Network);
        assert_eq!(classify(Stage::Subscription, &msg("HTTP 403: device limit reached")), Fail::Subscription);
        assert_eq!(classify(Stage::Start, &Error::Io(std::io::Error::other("disk"))), Fail::App);
    }

    #[test]
    fn this_process_can_be_measured() {
        let me = sample_process(std::process::id());
        #[cfg(any(windows, target_os = "linux", target_os = "android"))]
        {
            let me = me.expect("own process");
            assert!(me.working_set_mb > 1.0 && me.cpu_secs >= 0.0);
            let m = Metrics::open(std::env::temp_dir().join(format!("prism-sampler-{}.json", std::process::id())), true);
            let s = Sampler::default();
            s.take(&m, "app", &[std::process::id()]);
            assert!(m.summary(1).stats.contains_key("working_set_mb.app"));
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        assert!(me.is_none());
    }
}
