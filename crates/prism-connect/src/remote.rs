//! Kometfy's backend (docs/BACKEND.md). For everyone: the remote settings and the ads, read now and then and
//! kept on disk. Only with the user's consent from the welcome screen: the day's statistics, the ads' shown and
//! pressed counts, and remote tests, fetched from Kometfy's backend and from the VPN provider (the addresses its
//! subscription sends) and answered with what this device found.
//!
//! Whatever comes back is checked here before it is used: lists only add to the built-in ones and are capped,
//! links must be https, and an ad is shown only in the shapes the app draws.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};


/// A line on Home for everyone, until a day or until closed (`id` changes for a new one).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Announcement {
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RemoteSettings {
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub announcement: Option<Announcement>,
    /// AI services sent through the AI proxy in the free mode, besides the built-in list.
    #[serde(default)]
    pub ai_sites: Vec<String>,
    /// Game domains for the gaming DNS, besides the built-in list.
    #[serde(default)]
    pub game_sites: Vec<String>,
    /// The project's Cloudflare domains for the Telegram bridge, after the user's own.
    #[serde(default)]
    pub tg_domains: Vec<String>,
}

/// An ad in the shapes the app draws (app/src/components/AdSlot.svelte). Picture fields hold full addresses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteAd {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cta: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub color: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<Banner>,
    pub url: String,
    #[serde(default = "one")]
    pub weight: u32,
    /// An A/B test's other variants (B, C, D), each a whole ad with its share of the shows in percent; this ad is
    /// variant A and takes the rest. The UI never sees them: `pick` keeps one variant per install.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<AdVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdVariant {
    pub key: String,
    pub share: u32,
    /// Its id is "<ad>.<key>", so its shows and presses are counted apart.
    pub ad: Box<RemoteAd>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Banner {
    pub wide: String,
    pub narrow: String,
}

fn one() -> u32 {
    1
}

/// What the backend sends at `GET /v1/config`, once checked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RemoteDoc {
    #[serde(default)]
    pub settings: RemoteSettings,
    #[serde(default)]
    pub ads: Vec<RemoteAd>,
}

/// A remote test as the backend (or the provider) hands it out.
#[derive(Debug, Clone, Deserialize)]
pub struct Task {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub params: Value,
}

/// Where tasks come from and reports go: Kometfy's backend or the VPN provider.
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    pub tasks: String,
    pub reports: String,
    /// The provider's channel: it may ask for its own servers' delays, and it gets an install id of its own.
    pub provider: bool,
}

#[derive(Default)]
struct State {
    doc: RemoteDoc,
    etag: Option<String>,
    /// When each piece last went out (or was fetched); None = not yet since start.
    config_at: Option<Instant>,
    stats_at: Option<Instant>,
    tasks_at: Option<Instant>,
    /// Shown and pressed per (day, ad), since the last report.
    ads: HashMap<(String, String), (u32, u32)>,
}

pub struct Remote {
    file: PathBuf,
    http: reqwest::Client,
    state: Mutex<State>,
    /// What picks an A/B variant: the install id once there is one, else a random one for this run (nothing is
    /// counted without the consent anyway).
    seed: Mutex<String>,
}

/// How often each piece goes: settings and ads for everyone, statistics and tests for those who agreed.
pub const CONFIG_EVERY: Duration = Duration::from_secs(6 * 3600);
pub const STATS_EVERY: Duration = Duration::from_secs(6 * 3600);
pub const TASKS_EVERY: Duration = Duration::from_secs(4 * 3600);

impl Remote {
    /// The copy kept on disk, so the ads and settings are there before the first answer (and offline).
    pub fn new(file: PathBuf) -> Self {
        let doc = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice::<RemoteDoc>(&b).ok()).unwrap_or_default();
        let http = reqwest::Client::builder()
            .no_proxy()
            // a DNS that answers nothing for the backend's name (AdGuard DNS, for one) no longer cuts the app off
            .dns_resolver(std::sync::Arc::new(crate::doh::Fallback))
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("Kometfy/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self { file, http, state: Mutex::new(State { doc, ..Default::default() }), seed: Mutex::new(uuid::Uuid::new_v4().to_string()) }
    }

    /// The settings and the ads as the UI shows them: one variant of each A/B test, the same every time.
    pub fn doc(&self) -> RemoteDoc {
        pick(&self.state.lock().unwrap().doc, &self.seed.lock().unwrap())
    }

    pub fn set_seed(&self, install: &str) {
        if !install.is_empty() {
            *self.seed.lock().unwrap() = install.to_string();
        }
    }

    /// The client the backend calls go through (direct, never through a proxy).
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn due(&self, what: &str, every: Duration) -> bool {
        let s = self.state.lock().unwrap();
        let at = match what {
            "config" => s.config_at,
            "stats" => s.stats_at,
            _ => s.tasks_at,
        };
        at.is_none_or(|t| t.elapsed() >= every)
    }

    fn mark(&self, what: &str) {
        let mut s = self.state.lock().unwrap();
        let now = Some(Instant::now());
        match what {
            "config" => s.config_at = now,
            "stats" => s.stats_at = now,
            _ => s.tasks_at = now,
        }
    }

    /// `GET /v1/config?p=<platform>` with the last ETag. Returns whether anything changed.
    pub async fn refresh(&self, base: &str, platform: &str) -> Result<bool> {
        self.mark("config");
        let etag = self.state.lock().unwrap().etag.clone();
        let mut req = self.http.get(format!("{base}/v1/config")).query(&[("p", platform)]);
        if let Some(e) = &etag {
            req = req.header("if-none-match", e);
        }
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(false);
        }
        if !resp.status().is_success() {
            return Err(Error::msg(format!("backend answered {}", resp.status())));
        }
        let etag = resp.headers().get("etag").and_then(|v| v.to_str().ok()).map(str::to_string);
        let raw: Value = resp.json().await?;
        let doc = checked(&raw, base);
        let mut s = self.state.lock().unwrap();
        s.etag = etag;
        if s.doc == doc {
            return Ok(false);
        }
        s.doc = doc.clone();
        drop(s);
        let _ = crate::util::write_atomic(&self.file, serde_json::to_vec_pretty(&doc)?.as_slice());
        Ok(true)
    }

    /// An ad was shown or pressed (the UI tells); counted until the next report. An A/B variant is "<ad>.<b|c|d>".
    pub fn count_ad(&self, id: &str, click: bool) {
        let (ad, variant) = id.split_once('.').unwrap_or((id, "a"));
        if ad.is_empty() || ad.len() > 40 || !ad.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || !matches!(variant, "a" | "b" | "c" | "d") {
            return;
        }
        let day = today();
        let mut s = self.state.lock().unwrap();
        if s.ads.len() > 200 {
            return;
        }
        let e = s.ads.entry((day, id.to_string())).or_default();
        if click {
            e.1 += 1;
        } else {
            e.0 += 1;
        }
    }

    /// `POST /v1/ads`: the counts since the last report, one request per day. Counts that did not get through
    /// are kept for the next time.
    pub async fn send_ads(&self, base: &str, platform: &str) -> Result<()> {
        let taken = std::mem::take(&mut self.state.lock().unwrap().ads);
        let mut by_day: HashMap<String, Vec<Value>> = HashMap::new();
        for ((day, ad), (imp, clk)) in &taken {
            by_day.entry(day.clone()).or_default().push(json!({ "ad": ad, "imp": imp, "clk": clk }));
        }
        for (day, items) in by_day {
            let sent = self.post(&format!("{base}/v1/ads"), &json!({ "platform": platform, "day": day, "items": items })).await;
            if let Err(e) = sent {
                let mut s = self.state.lock().unwrap();
                for ((d, ad), v) in taken.iter().filter(|((d, _), _)| *d == day) {
                    let e2 = s.ads.entry((d.clone(), ad.clone())).or_default();
                    e2.0 += v.0;
                    e2.1 += v.1;
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// `POST /v1/stats`: one body per day (yesterday's final totals and today's so far).
    pub async fn send_stats(&self, base: &str, bodies: &[Value]) -> Result<()> {
        self.mark("stats");
        for b in bodies {
            self.post(&format!("{base}/v1/stats"), b).await?;
        }
        Ok(())
    }

    /// The tasks a channel has for this install. `net`: the link, the mode, the SIM's operator and whether this
    /// request goes through the VPN, so a task aimed at an operator or a link finds its installs.
    pub async fn tasks(&self, ch: &Channel, install: &str, platform: &str, version: &str, net: &[(&str, String)]) -> Result<Vec<Task>> {
        let resp = self.http.get(&ch.tasks).query(&[("i", install), ("p", platform), ("v", version)]).query(net).send().await?;
        if !resp.status().is_success() {
            return Err(Error::msg(format!("tasks: {}", resp.status())));
        }
        let v: Value = resp.json().await?;
        let list: Vec<Task> = serde_json::from_value(v.get("tasks").cloned().unwrap_or(Value::Array(vec![]))).unwrap_or_default();
        // a handful per round: a test runs on the user's own network and time
        Ok(list.into_iter().filter(|t| !t.id.is_empty() && t.id.len() <= 80).take(5).collect())
    }

    pub fn tasks_done(&self) {
        self.mark("tasks");
    }

    /// Everything is due again at the next tick (the local control API's `POST /v1/remote`).
    pub fn force(&self) {
        let mut s = self.state.lock().unwrap();
        s.config_at = None;
        s.stats_at = None;
        s.tasks_at = None;
    }

    pub async fn report(&self, ch: &Channel, body: &Value) -> Result<()> {
        self.post(&ch.reports, body).await
    }

    async fn post(&self, url: &str, body: &Value) -> Result<()> {
        let resp = self.http.post(url).json(body).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::msg(format!("{url}: {}", resp.status())))
        }
    }
}

pub fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

pub fn yesterday() -> String {
    (chrono::Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string()
}

/// The backend's address from the settings: empty for the one the app build supplies (`builtin`, none in the open
/// core), else https, or http to this device (a local `wrangler dev`).
pub fn base_url(setting: &str) -> Option<String> {
    let own = setting.trim().is_empty().then(crate::builtin::backend);
    let s = own.as_deref().unwrap_or(setting).trim().trim_end_matches('/');
    let local = ["http://127.0.0.1:", "http://localhost:"].iter().any(|p| s.starts_with(p));
    (s.starts_with("https://") || local).then(|| s.to_string()).filter(|s| s.len() <= 200 && !s.contains(char::is_whitespace))
}

/// A stable 0–99 for a seed and an ad: which A/B variant this install sees.
fn bucket(seed: &str, ad: &str) -> u32 {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("{seed}:{ad}").as_bytes());
    ((u32::from(h[0]) << 8) | u32::from(h[1])) % 100
}

/// The doc with one variant of each A/B test: B, C, D by their shares, A for the rest.
pub fn pick(doc: &RemoteDoc, seed: &str) -> RemoteDoc {
    let ads = doc
        .ads
        .iter()
        .map(|a| {
            let b = bucket(seed, &a.id);
            let mut acc = 0;
            for v in &a.variants {
                acc += v.share;
                if b < acc {
                    let mut x = (*v.ad).clone();
                    x.weight = a.weight;
                    return x;
                }
            }
            RemoteAd { variants: vec![], ..a.clone() }
        })
        .collect();
    RemoteDoc { settings: doc.settings.clone(), ads }
}

/// An install id for the VPN provider's channel: derived from the install's own, different for every provider,
/// so the two channels cannot be matched by it.
pub fn provider_install_id(install: &str, provider_url: &str) -> String {
    use sha2::{Digest, Sha256};
    let host = reqwest::Url::parse(provider_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let h = Sha256::digest(format!("kometfy-provider:{host}:{install}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b).to_string()
}

/// The backend's answer, as far as the app can trust it.
pub fn checked(raw: &Value, base: &str) -> RemoteDoc {
    let s = raw.get("settings").cloned().unwrap_or(Value::Null);
    let domains = |key: &str, max: usize| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for d in s.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(|v| v.as_str()).filter_map(crate::zapret::clean_domain) {
            if out.len() < max && !out.contains(&d) {
                out.push(d);
            }
        }
        out
    };
    let https = |v: Option<&Value>| v.and_then(Value::as_str).filter(|u| u.starts_with("https://") && u.len() <= 500 && !u.contains(char::is_whitespace)).map(str::to_string);
    let text = |v: Option<&Value>, max: usize| v.and_then(Value::as_str).map(|t| t.chars().filter(|c| !c.is_control()).take(max).collect::<String>()).filter(|t| !t.trim().is_empty());
    let announcement = s.get("announcement").and_then(|a| {
        Some(Announcement {
            id: text(a.get("id"), 40)?,
            text: text(a.get("text"), 140)?,
            url: https(a.get("url")),
            until: text(a.get("until"), 10).filter(|d| d.len() == 10),
        })
    });
    let settings = RemoteSettings {
        support_url: https(s.get("support_url")),
        announcement,
        ai_sites: domains("ai_sites", 200),
        game_sites: domains("game_sites", 100),
        tg_domains: domains("tg_domains", 5),
    };
    let color = |v: Option<&Value>| v.and_then(Value::as_str).filter(|c| c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit())).map(str::to_string);
    let asset = |v: Option<&Value>| v.and_then(Value::as_str).filter(|k| k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit())).map(|k| format!("{base}/v1/assets/{k}"));
    let face = |a: &Value, id: String| -> Option<RemoteAd> {
        let banner = a.get("banner").and_then(|b| Some(Banner { wide: asset(b.get("wide"))?, narrow: asset(b.get("narrow"))? }));
        let button = a.get("button").filter(|b| b.is_object()).map(|b| {
            json!({
                "bg": color(b.get("bg")),
                "fg": color(b.get("fg")),
                "outline": b.get("outline").and_then(Value::as_bool).unwrap_or(false),
            })
        });
        Some(RemoteAd {
            id,
            name: text(a.get("name"), 40)?,
            text: text(a.get("text"), 90),
            promo: text(a.get("promo"), 24),
            cta: text(a.get("cta"), 20),
            icon: text(a.get("icon"), 20).filter(|i| i.chars().all(|c| c.is_ascii_lowercase() || c == '-')),
            color: color(a.get("color"))?,
            bg: asset(a.get("bg")),
            button,
            banner,
            url: https(a.get("url"))?,
            weight: a.get("weight").and_then(Value::as_u64).map(|w| w.clamp(1, 100) as u32).unwrap_or(1),
            variants: vec![],
        })
    };
    let ads = raw
        .get("ads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(20)
        .filter_map(|a| {
            let id = text(a.get("id"), 40).filter(|i| i.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))?;
            let mut ad = face(a, id.clone())?;
            // B, C, D with their shares; A keeps at least 1%
            let mut total = 0;
            for v in a.get("variants").and_then(Value::as_array).into_iter().flatten().take(3) {
                let key = v.get("key").and_then(Value::as_str).filter(|k| matches!(*k, "b" | "c" | "d"));
                let share = v.get("share").and_then(Value::as_u64).filter(|s| (1..=99).contains(s)).map(|s| s as u32);
                let (Some(key), Some(share)) = (key, share) else { continue };
                if total + share > 99 || ad.variants.iter().any(|x| x.key == key) {
                    continue;
                }
                if let Some(face) = face(v, format!("{id}.{key}")) {
                    total += share;
                    ad.variants.push(AdVariant { key: key.to_string(), share, ad: Box::new(face) });
                }
            }
            Some(ad)
        })
        .collect();
    RemoteDoc { settings, ads }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ab_test_shows_one_variant_per_install_by_its_share() {
        let ad = |text: &str| json!({ "name": "VPN", "text": text, "color": "#8f9bff", "url": "https://example.com/" });
        let mut a = ad("A");
        a["id"] = json!("vpn-1a2b3c");
        a["variants"] = json!([
            { "key": "b", "share": 30, "name": "VPN", "text": "B", "color": "#8f9bff", "url": "https://example.com/b" },
            { "key": "x", "share": 10, "name": "VPN", "text": "X", "color": "#8f9bff", "url": "https://example.com/x" },
            { "key": "c", "share": 90, "name": "VPN", "text": "C", "color": "#8f9bff", "url": "https://example.com/c" }
        ]);
        let doc = checked(&json!({ "ads": [a] }), "https://backend.example");
        // an unknown key and a share past 99% are left out
        assert_eq!(doc.ads[0].variants.iter().map(|v| v.key.as_str()).collect::<Vec<_>>(), ["b"]);
        let seen: Vec<String> = (0..1000).map(|i| pick(&doc, &format!("install-{i}")).ads[0].id.clone()).collect();
        let b = seen.iter().filter(|id| id.as_str() == "vpn-1a2b3c.b").count();
        assert!((240..360).contains(&b), "{b} of 1000 saw B");
        assert!(seen.iter().all(|id| id == "vpn-1a2b3c" || id == "vpn-1a2b3c.b"));
        // the same install, the same variant
        assert_eq!(pick(&doc, "one").ads[0].id, pick(&doc, "one").ads[0].id);
        assert!(pick(&doc, "one").ads[0].variants.is_empty());
    }

    #[test]
    fn only_what_the_app_can_trust_gets_through() {
        let key = "a".repeat(64);
        let raw = json!({
            "settings": {
                "support_url": "http://plain.example",
                "announcement": { "id": "a1", "text": "Новая версия", "url": "javascript:alert(1)" },
                "ai_sites": ["deepseek.com", "Not A Domain", "https://perplexity.ai/x", "deepseek.com"],
                "tg_domains": ["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"],
                "unknown": 1
            },
            "ads": [
                { "id": "ok-1", "name": "Звёздный", "color": "#8f9bff", "url": "https://example.com", "bg": key, "weight": 500 },
                { "id": "bad url", "name": "X", "color": "#000000", "url": "https://example.com" },
                { "id": "no-https", "name": "X", "color": "#000000", "url": "http://example.com" },
                { "id": "bad-color", "name": "X", "color": "red", "url": "https://example.com" }
            ]
        });
        let d = checked(&raw, "https://backend.example");
        assert_eq!(d.settings.support_url, None);
        let a = d.settings.announcement.unwrap();
        assert_eq!((a.id.as_str(), a.url), ("a1", None));
        assert_eq!(d.settings.ai_sites, vec!["deepseek.com", "perplexity.ai"]);
        assert_eq!(d.settings.tg_domains.len(), 5);
        assert_eq!(d.ads.len(), 1);
        assert_eq!(d.ads[0].bg.as_deref(), Some(format!("https://backend.example/v1/assets/{key}").as_str()));
        assert_eq!(d.ads[0].weight, 100);
    }

    #[test]
    fn the_backend_address_is_https_or_this_device() {
        assert_eq!(base_url("https://backend.example/").as_deref(), Some("https://backend.example"));
        assert_eq!(base_url("http://127.0.0.1:8787").as_deref(), Some("http://127.0.0.1:8787"));
        assert_eq!(base_url("http://evil.example"), None);
        assert_eq!(base_url("ftp://x"), None);
        // the open core has no backend of its own: nothing to talk to until an app build supplies one
        assert_eq!(base_url(""), None);
    }

    #[test]
    fn each_provider_gets_its_own_install_id() {
        let me = "6f1c3a9e-2b4d-4e8f-9a1b-3c5d7e9f1a2b";
        let a = provider_install_id(me, "https://vpn-a.example/tasks");
        let b = provider_install_id(me, "https://vpn-b.example/tasks");
        assert_ne!(a, b);
        assert_ne!(a, me);
        assert_eq!(a, provider_install_id(me, "https://vpn-a.example/other"));
        assert!(uuid::Uuid::parse_str(&a).unwrap().get_version_num() == 4);
    }

    #[test]
    fn ad_counts_add_up_per_day_and_ad() {
        let r = Remote::new(std::env::temp_dir().join("kometfy-remote-test.json"));
        r.count_ad("ad-1", false);
        r.count_ad("ad-1", false);
        r.count_ad("ad-1", true);
        r.count_ad("bad id!", false);
        let s = r.state.lock().unwrap();
        assert_eq!(s.ads.len(), 1);
        assert_eq!(s.ads.values().next(), Some(&(2, 1)));
    }
}
