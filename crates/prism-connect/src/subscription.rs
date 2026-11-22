//! Fetch and normalize subscriptions into a Clash/mihomo YAML profile.

use std::{collections::HashMap, time::Duration};

use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::{
    device::Device,
    dpi::Dpi,
    error::{Error, Result},
    links,
    util::{k, put, strs},
};

pub const USER_AGENT: &str = "clash-verge/v2.4.3 (Kometfy)";
pub const TEST_URL: &str = "https://www.gstatic.com/generate_204";

/// An announcement is one short line, as in Happ and v2RayTun.
pub const ANNOUNCE_MAX: usize = 200;

/// Settings a provider can send, either as HTTP headers or as `#key: value` lines in the body
/// (the Happ convention). Anything else is ignored.
const PARAM_KEYS: &[&str] = &[
    "profile-title",
    "profile-update-interval",
    "subscription-userinfo",
    "support-url",
    "profile-web-page-url",
    "announce",
    "fragmentation-enable",
    "fragmentation-packets",
    "fragmentation-length",
    "fragmentation-interval",
    "fragmentation-maxsplit",
    "x-hwid-active",
    "kometfy-tasks",
    "kometfy-reports",
];

type Params = HashMap<String, String>;

/// What a provider says about the subscription besides the servers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SubMeta {
    pub announce: Option<String>,
    pub support_url: Option<String>,
    pub web_url: Option<String>,
    pub dpi: Option<Dpi>,
    /// The provider counts devices (Remnawave sends `x-hwid-active`).
    pub hwid_active: bool,
    /// The provider's remote tests (Kometfy's own protocol, docs/BACKEND.md): where its tasks are fetched and
    /// where the reports go. https only, and used only when the user agreed to take part.
    pub tasks_url: Option<String>,
    pub reports_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Usage {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Clash,
    Links,
    WireGuard,
}

#[derive(Debug)]
pub struct Fetched {
    pub body: String,
    pub usage: Option<Usage>,
    pub filename: Option<String>,
    /// `profile-title` header (Remnawave, Marzban, ...): the name the panel gives the subscription.
    pub title: Option<String>,
    pub interval_hours: Option<u32>,
    pub meta: SubMeta,
}

#[derive(Debug)]
pub struct Normalized {
    pub yaml: String,
    pub source: Source,
    pub nodes: usize,
    pub warnings: Vec<String>,
}

/// Download a subscription. `proxy` routes the request through a local proxy (fallback path).
/// `device` is sent in the Remnawave / Happ headers so a provider can count devices.
pub async fn fetch(url: &str, proxy: Option<&str>, device: Option<&Device>) -> Result<Fetched> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(Error::msg("subscription URL must start with http:// or https://"));
    }
    let mut b = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(5));
    b = match proxy {
        Some(p) => b.proxy(reqwest::Proxy::all(p)?),
        None => b.no_proxy(),
    };
    let mut req = b.build()?.get(url);
    if let Some(d) = device {
        req = req
            .header("x-hwid", d.hwid.as_str())
            .header("x-device-os", d.os)
            .header("x-ver-os", d.os_version.as_str());
        if !d.model.is_empty() {
            req = req.header("x-device-model", d.model.as_str());
        }
    }
    let resp = req.send().await?;
    let status = resp.status();
    let h = resp.headers().clone();
    let mut params = header_params(&h);
    check_hwid(status.as_u16(), &h, &params)?;
    if !status.is_success() {
        return Err(Error::msg(format!("subscription server answered {status}")));
    }
    let filename = h
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_filename);
    let body = resp.text().await?;
    for (key, value) in body_params(&body) {
        params.entry(key).or_insert(value); // a header wins over the same line in the body
    }
    Ok(Fetched {
        usage: params.get("subscription-userinfo").and_then(|v| parse_usage(v)),
        title: params.get("profile-title").and_then(|v| parse_title(v)),
        interval_hours: params.get("profile-update-interval").and_then(|v| v.trim().parse::<u32>().ok()),
        meta: SubMeta::from_params(&params),
        filename,
        body,
    })
}

/// The settings of [`PARAM_KEYS`] that came as HTTP headers.
fn header_params(h: &HeaderMap) -> Params {
    PARAM_KEYS
        .iter()
        .filter_map(|key| {
            let v = h.get(*key)?.to_str().ok()?.trim();
            (!v.is_empty()).then(|| (key.to_string(), v.to_string()))
        })
        .collect()
}

fn is_true(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Remnawave answers a device over the limit with a placeholder instead of the servers, and a
/// provider that needs a device id answers 404 without one. Importing the placeholder would
/// replace good servers, so both are turned into errors the UI can explain.
fn check_hwid(status: u16, h: &HeaderMap, params: &Params) -> Result<()> {
    let flag = |name: &str| h.get(name).and_then(|v| v.to_str().ok()).is_some_and(is_true);
    if flag("x-hwid-max-devices-reached") || flag("x-hwid-limit") {
        let note = params.get("announce").and_then(|a| parse_announce(a)).unwrap_or_default();
        return Err(Error::msg(if note.is_empty() {
            "HWID_LIMIT".to_string()
        } else {
            format!("HWID_LIMIT: {note}")
        }));
    }
    if status == 404 && flag("x-hwid-not-supported") {
        return Err(Error::msg("HWID_REQUIRED"));
    }
    Ok(())
}

/// `#key: value` lines at the top of a body (also inside a base64 body, as Happ allows).
pub fn body_params(body: &str) -> Params {
    fn scan(text: &str, out: &mut Params) {
        for line in text.lines().take(200) {
            let Some(rest) = line.trim().strip_prefix('#') else { continue };
            let Some((key, value)) = rest.split_once(':') else { continue };
            let key = key.trim().to_lowercase();
            if PARAM_KEYS.contains(&key.as_str()) && !value.trim().is_empty() {
                out.entry(key).or_insert_with(|| value.trim().to_string());
            }
        }
    }
    let text = body.trim_start_matches('\u{feff}').trim();
    let mut out = Params::new();
    scan(text, &mut out);
    if !text.contains(['\n', ' ', ':']) {
        if let Some(decoded) = links::b64_decode_any(text).and_then(|b| String::from_utf8(b).ok()) {
            scan(&decoded, &mut out);
        }
    }
    out
}

/// `base64:UG9zUGFuZWw=` or plain / percent-encoded text.
fn parse_title(s: &str) -> Option<String> {
    let s = s.trim();
    let t = match s.strip_prefix("base64:") {
        Some(b) => String::from_utf8(links::b64_decode_any(b)?).ok()?,
        None => percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned(),
    };
    Some(t.trim().to_string()).filter(|t| !t.is_empty())
}

/// Announcement: plain text or `base64:...`, one line, at most [`ANNOUNCE_MAX`] characters.
/// `0` switches an announcement off.
fn parse_announce(s: &str) -> Option<String> {
    let s = s.trim();
    let raw = match s.strip_prefix("base64:") {
        Some(b) => String::from_utf8(links::b64_decode_any(b)?).ok()?,
        None => s.to_string(),
    };
    let line: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let line: String = line.chars().take(ANNOUNCE_MAX).collect();
    Some(line).filter(|l| !l.is_empty() && l != "0")
}

/// An https address the app itself talks to (not just shows).
fn https_link(s: &str) -> Option<String> {
    let s = s.trim();
    (s.to_lowercase().starts_with("https://") && s.len() <= 512 && !s.chars().any(|c| c.is_whitespace() || c.is_control())).then(|| s.to_string())
}

/// Links the UI may show and open: web pages and Telegram.
fn parse_page_link(s: &str) -> Option<String> {
    let s = s.trim();
    let ok = ["http://", "https://", "tg://"].iter().any(|p| s.to_lowercase().starts_with(p));
    (ok && s.len() <= 512 && !s.chars().any(|c| c.is_whitespace() || c.is_control())).then(|| s.to_string())
}

impl SubMeta {
    pub fn from_params(p: &Params) -> Self {
        Self {
            announce: p.get("announce").and_then(|v| parse_announce(v)),
            support_url: p.get("support-url").and_then(|v| parse_page_link(v)),
            web_url: p.get("profile-web-page-url").and_then(|v| parse_page_link(v)),
            dpi: Dpi::from_params(|key| p.get(key).cloned()),
            hwid_active: p.get("x-hwid-active").is_some_and(|v| is_true(v)),
            tasks_url: p.get("kometfy-tasks").and_then(|v| https_link(v)),
            reports_url: p.get("kometfy-reports").and_then(|v| https_link(v)),
        }
    }
}

/// `upload=1; download=2; total=3; expire=4`
pub fn parse_usage(s: &str) -> Option<Usage> {
    let mut u = Usage::default();
    let mut any = false;
    for part in s.split(';') {
        let Some((key, val)) = part.split_once('=') else {
            continue;
        };
        let val = val.trim();
        match key.trim() {
            "upload" => u.upload = val.parse().unwrap_or(0),
            "download" => u.download = val.parse().unwrap_or(0),
            "total" => u.total = val.parse().unwrap_or(0),
            "expire" => u.expire = val.parse::<i64>().ok().filter(|e| *e > 0),
            _ => continue,
        }
        any = true;
    }
    any.then_some(u)
}

fn parse_filename(s: &str) -> Option<String> {
    let lower = s.to_lowercase();
    if let Some(i) = lower.find("filename*=") {
        let v = s[i + 10..].split(';').next()?.trim();
        let v = v.split_once("''").map(|(_, b)| b).unwrap_or(v);
        let d = percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned();
        return Some(d.trim_matches('"').to_string()).filter(|x| !x.is_empty());
    }
    let i = lower.find("filename=")?;
    let v = s[i + 9..].split(';').next()?.trim().trim_matches('"');
    Some(v.to_string()).filter(|x| !x.is_empty())
}

fn count_proxies(root: &Mapping) -> usize {
    root.get("proxies")
        .and_then(Value::as_sequence)
        .map(Vec::len)
        .unwrap_or(0)
}

fn has_proxy_providers(root: &Mapping) -> bool {
    root.get("proxy-providers")
        .and_then(Value::as_mapping)
        .is_some_and(|m| !m.is_empty())
}

/// Turn whatever the user pasted or the server returned into a Clash profile.
pub fn normalize(body: &str) -> Result<Normalized> {
    normalize_depth(body, 0)
}

fn normalize_depth(body: &str, depth: u8) -> Result<Normalized> {
    let text = body.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err(Error::msg("empty profile"));
    }

    if links::looks_like_wireguard(text) {
        let m = links::parse_wireguard(text, "WireGuard").map_err(Error::msg)?;
        return from_proxies(vec![m], Source::WireGuard, vec![]);
    }

    if let Ok(Value::Mapping(root)) = serde_yaml::from_str::<Value>(text) {
        if root.contains_key("proxies") || root.contains_key("proxy-providers") {
            let nodes = count_proxies(&root);
            if nodes == 0 && !has_proxy_providers(&root) {
                return Err(Error::msg("subscription returned no servers"));
            }
            return Ok(Normalized {
                nodes,
                yaml: text.to_string(),
                source: Source::Clash,
                warnings: vec![],
            });
        }
    }

    let parsed = links::parse_links(text);
    if !parsed.proxies.is_empty() {
        return from_proxies(parsed.proxies, Source::Links, parsed.errors);
    }

    if depth == 0 {
        if let Some(decoded) = links::b64_decode_any(text).and_then(|b| String::from_utf8(b).ok()) {
            if decoded.contains("://") || decoded.contains("proxies:") {
                return normalize_depth(&decoded, 1);
            }
        }
    }

    if let Some(first) = parsed.errors.first() {
        return Err(Error::msg(format!("no usable servers found ({first})")));
    }
    Err(Error::msg(
        "unrecognized format: expected Clash YAML, share links, a base64 list or a WireGuard config",
    ))
}

fn from_proxies(proxies: Vec<Mapping>, source: Source, warnings: Vec<String>) -> Result<Normalized> {
    let nodes = proxies.len();
    Ok(Normalized {
        yaml: build_skeleton(proxies)?,
        source,
        nodes,
        warnings,
    })
}

/// Default selector + auto-test groups for a bare list of proxies.
pub fn default_groups(names: &[String]) -> Vec<Value> {
    let mut groups = Vec::new();

    let mut select = Mapping::new();
    put(&mut select, "name", "PROXY");
    put(&mut select, "type", "select");
    let mut members: Vec<String> = Vec::new();
    if names.len() > 1 {
        members.push("AUTO".into());
    }
    members.extend(names.iter().cloned());
    members.push("DIRECT".into());
    put(&mut select, "proxies", strs(members));
    groups.push(Value::Mapping(select));

    if names.len() > 1 {
        let mut auto = Mapping::new();
        put(&mut auto, "name", "AUTO");
        put(&mut auto, "type", "url-test");
        put(&mut auto, "url", TEST_URL);
        put(&mut auto, "interval", 300u64);
        put(&mut auto, "tolerance", 50u64);
        put(&mut auto, "proxies", strs(names.iter().cloned()));
        groups.push(Value::Mapping(auto));
    }
    groups
}

pub fn build_skeleton(proxies: Vec<Mapping>) -> Result<String> {
    let names: Vec<String> = proxies
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str).map(String::from))
        .collect();
    let mut root = Mapping::new();
    root.insert(
        k("proxies"),
        Value::Sequence(proxies.into_iter().map(Value::Mapping).collect()),
    );
    root.insert(k("proxy-groups"), Value::Sequence(default_groups(&names)));
    root.insert(k("rules"), strs(["MATCH,PROXY"]));
    Ok(serde_yaml::to_string(&Value::Mapping(root))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_header() {
        let u = parse_usage("upload=1; download=2; total=10; expire=1700000000").unwrap();
        assert_eq!((u.upload, u.download, u.total), (1, 2, 10));
        assert_eq!(u.expire, Some(1_700_000_000));
    }

    #[test]
    fn profile_title_header() {
        assert_eq!(parse_title("base64:Um9zUGFuZWw=").as_deref(), Some("RosPanel"));
        assert_eq!(parse_title("My%20Sub").as_deref(), Some("My Sub"));
        assert_eq!(parse_title("  ").as_deref(), None);
    }

    #[test]
    fn announce_forms() {
        assert_eq!(parse_announce("base64:SGFwcCB0aGUgYmVzdCE=").as_deref(), Some("Happ the best!"));
        assert_eq!(parse_announce("  Hello\n  world  ").as_deref(), Some("Hello world"));
        assert_eq!(parse_announce("0"), None);
        assert_eq!(parse_announce("   "), None);
        assert_eq!(parse_announce(&"я".repeat(300)).unwrap().chars().count(), ANNOUNCE_MAX);
    }

    #[test]
    fn only_web_and_telegram_links_are_kept() {
        assert!(parse_page_link("https://t.me/support").is_some());
        assert!(parse_page_link("tg://resolve?domain=x").is_some());
        assert!(parse_page_link("javascript:alert(1)").is_none());
        assert!(parse_page_link("file:///C:/Windows/system32/calc.exe").is_none());
        assert!(parse_page_link("https://a.example/with space").is_none());
    }

    #[test]
    fn body_lines_carry_the_same_settings() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let body = "#profile-title: Name VPN\n#announce: base64:SGFwcCB0aGUgYmVzdCE=\n#fragmentation-enable: 1\n#fragmentation-length: 50-100\nvless://x@y:1#a\n";
        let p = body_params(body);
        assert_eq!(p["profile-title"], "Name VPN");
        let m = SubMeta::from_params(&p);
        assert_eq!(m.announce.as_deref(), Some("Happ the best!"));
        assert_eq!(m.dpi.unwrap().length, "50-100");
        assert_eq!(body_params(&STANDARD.encode(body))["profile-title"], "Name VPN");
        assert!(body_params("# just a comment: yes\n#other: 1").is_empty());
    }

    #[test]
    fn headers_beat_nothing_and_hwid_problems_are_errors() {
        use reqwest::header::HeaderValue;
        let mut h = HeaderMap::new();
        h.insert("Announce", HeaderValue::from_static("base64:SGFwcCB0aGUgYmVzdCE="));
        h.insert("X-Hwid-Active", HeaderValue::from_static("true"));
        let p = header_params(&h);
        assert_eq!(p["announce"], "base64:SGFwcCB0aGUgYmVzdCE=");
        assert!(SubMeta::from_params(&p).hwid_active);
        assert!(check_hwid(200, &h, &p).is_ok(), "x-hwid-active alone is fine");

        h.insert("x-hwid-max-devices-reached", HeaderValue::from_static("true"));
        assert_eq!(check_hwid(200, &h, &p).unwrap_err().to_string(), "HWID_LIMIT: Happ the best!");

        let mut h = HeaderMap::new();
        h.insert("x-hwid-not-supported", HeaderValue::from_static("true"));
        assert_eq!(check_hwid(404, &h, &header_params(&h)).unwrap_err().to_string(), "HWID_REQUIRED");
        assert!(check_hwid(200, &h, &header_params(&h)).is_ok());
    }

    #[test]
    fn filename_utf8() {
        assert_eq!(
            parse_filename("attachment; filename*=UTF-8''My%20Sub").as_deref(),
            Some("My Sub")
        );
        assert_eq!(parse_filename("attachment; filename=\"abc\"").as_deref(), Some("abc"));
    }

    #[test]
    fn clash_yaml_kept_verbatim() {
        let y = "proxies:\n  - {name: a, type: socks5, server: 1.1.1.1, port: 1}\nrules: []\n";
        let n = normalize(y).unwrap();
        assert_eq!(n.source, Source::Clash);
        assert_eq!(n.nodes, 1);
        assert_eq!(n.yaml, y.trim());
    }

    #[test]
    fn base64_link_list() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let raw = "socks5://1.1.1.1:1080#a\nsocks5://2.2.2.2:1080#b\n";
        let n = normalize(&STANDARD.encode(raw)).unwrap();
        assert_eq!(n.source, Source::Links);
        assert_eq!(n.nodes, 2);
        assert!(n.yaml.contains("url-test"));
    }

    #[test]
    fn garbage_rejected() {
        assert!(normalize("hello world").is_err());
    }

    #[test]
    fn empty_clash_proxies_are_rejected() {
        assert!(normalize("proxies: []\nrules:\n  - MATCH,DIRECT\n").is_err());
        assert!(normalize("proxies:\nproxy-providers: {}\n").is_err());
        // A valid non-empty proxy-providers map is still allowed even without inline proxies.
        assert!(normalize("proxy-providers:\n  sub:\n    type: http\n    url: https://example.com/p.yaml\n").is_ok());
    }
}
