use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    dpi::Dpi,
    error::Result,
    util::write_atomic,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Rule => "rule",
            Mode::Global => "global",
            Mode::Direct => "direct",
        }
    }
}

/// How traffic reaches the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    #[default]
    SystemProxy,
    Tun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TunSettings {
    pub stack: String,
    pub device: String,
    pub auto_route: bool,
    pub strict_route: bool,
    pub mtu: u32,
    pub dns_hijack: bool,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            stack: "mixed".into(),
            device: default_tun_device().into(),
            auto_route: true,
            strict_route: false,
            mtu: 1500,
            dns_hijack: true,
        }
    }
}

/// macOS only accepts utun interface names. This default is a requested name,
/// not a guarantee that the interface is free; startup must still verify it.
fn default_tun_device() -> &'static str {
    if cfg!(target_os = "macos") { "utun1024" } else { "PrismTun" }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSettings {
    /// true: use the resolvers below; false: keep the profile's own `dns` section.
    pub override_profile: bool,
    pub enhanced_mode: String,
    pub fake_ip_range: String,
    pub nameserver: Vec<String>,
    pub default_nameserver: Vec<String>,
    pub proxy_server_nameserver: Vec<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            override_profile: true,
            enhanced_mode: "fake-ip".into(),
            fake_ip_range: "198.18.0.1/16".into(),
            nameserver: vec![
                "https://dns.google/dns-query".into(),
                "https://1.1.1.1/dns-query".into(),
            ],
            default_nameserver: vec!["8.8.8.8".into(), "1.1.1.1".into()],
            proxy_server_nameserver: vec!["https://1.1.1.1/dns-query".into()],
        }
    }
}

/// When servers are run by the Xray core instead of mihomo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XrayMode {
    /// Never. DPI bypass is ignored too.
    Off,
    /// Only the servers that need it: with DPI bypass on, those that start a TLS handshake.
    #[default]
    Auto,
    /// Every server Xray can run (VLESS, VMess, Trojan, Shadowsocks).
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct XraySettings {
    pub mode: XrayMode,
    /// Own xray.exe. None: the one in the app folder.
    pub path: Option<String>,
}

/// DPI bypass. `enabled` is the user's own order; otherwise the subscription decides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DpiSettings {
    pub enabled: bool,
    /// Obey the `fragmentation-*` instruction of a subscription when `enabled` is off.
    pub follow_subscription: bool,
    pub packets: String,
    pub length: String,
    pub interval: String,
    pub max_split: String,
}

impl Default for DpiSettings {
    fn default() -> Self {
        let d = Dpi::default();
        Self {
            enabled: false,
            follow_subscription: true,
            packets: d.packets,
            length: d.length,
            interval: d.interval,
            max_split: d.max_split,
        }
    }
}

impl DpiSettings {
    pub fn spec(&self) -> Dpi {
        Dpi {
            packets: self.packets.clone(),
            length: self.length.clone(),
            interval: self.interval.clone(),
            max_split: self.max_split.clone(),
        }
    }

    /// Validate the numbers and write them back canonically.
    pub fn normalize(&mut self) -> Result<()> {
        let d = self.spec().normalize()?;
        (self.packets, self.length, self.interval, self.max_split) = (d.packets, d.length, d.interval, d.max_split);
        Ok(())
    }
}

/// Traffic that always goes DIRECT, whatever the profile says.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Bypass {
    pub processes: Vec<String>,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
}

impl Bypass {
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.domains.is_empty() && self.cidrs.is_empty()
    }
}

/// What the big button does, in the words of the Home screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AppMode {
    /// No VPN: only the free tools (the Telegram bridge now, Zapret later). The IP stays the same.
    #[serde(rename = "FreeAntiDPI")]
    FreeAntiDpi,
    /// The VPN for what is blocked (the core's `rule` mode).
    #[default]
    #[serde(rename = "SmartHybridVPN")]
    SmartHybridVpn,
    /// Everything through the VPN (the core's `global` mode).
    #[serde(rename = "FullTunnelVPN")]
    FullTunnelVpn,
}

/// The free bypass for YouTube and Discord (see `zapret`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ZapretSettings {
    pub enabled: bool,
    /// The strategy file's name without `.bat`, as in the release: "general", "general (ALT2)".
    pub strategy: String,
    /// The user's own sites, cleaned: "example.com".
    pub domains: Vec<String>,
    /// Also games: TCP and UDP ports 1024-65535 for the addresses in the release's IP list.
    pub game_filter: bool,
}

impl Default for ZapretSettings {
    fn default() -> Self {
        // sites that often do not open in Russia, as in ByeByeDPI's own list; the user edits them
        let domains = ["facebook.com", "instagram.com", "t.me", "telegram.org", "whatsapp.com", "whatsapp.net"].map(String::from).to_vec();
        Self { enabled: false, strategy: "general".into(), domains, game_filter: false }
    }
}

/// The local Telegram proxy (see `tgbridge`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TgSettings {
    pub enabled: bool,
    pub port: u16,
    /// 32 hex characters, made on first use. It sits in the `tg://proxy` link anyway.
    pub secret: String,
    /// Base domains on Cloudflare (see docs/TELEGRAM_CF.md): where the provider blocks Telegram's own
    /// addresses, the bridge reaches data centre N as `kwsN.<domain>` through Cloudflare.
    pub cf_domains: Vec<String>,
}

impl Default for TgSettings {
    fn default() -> Self {
        Self { enabled: false, port: 1443, secret: String::new(), cf_domains: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub core_path: Option<String>,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub secret: String,
    pub allow_lan: bool,
    pub ipv6: bool,
    pub mode: Mode,
    pub log_level: String,
    pub method: Method,
    /// User intent: traffic capture (system proxy / TUN) is on.
    pub connected: bool,
    pub auto_connect: bool,
    pub auto_start_core: bool,
    pub unified_delay: bool,
    pub tcp_concurrent: bool,
    pub find_process_mode: String,
    pub delay_url: String,
    pub delay_timeout_ms: u32,
    pub sysproxy_bypass: String,
    pub tun: TunSettings,
    pub dns: DnsSettings,
    pub bypass: Bypass,
    pub active_profile: Option<String>,
    pub lang: String,
    pub theme: String,
    pub close_to_tray: bool,
    /// The main window in its compact size (a phone-like column) rather than its full one.
    pub window_compact: bool,
    pub ip_check: bool,
    /// Look for a new Kometfy version on GitHub (at start and every few hours).
    pub check_updates: bool,
    pub xray: XraySettings,
    pub dpi: DpiSettings,
    /// Send the device id (HWID) and the OS name when a subscription is downloaded.
    pub hwid: bool,
    /// Keep local statistics about connections, failures and resource use. They never leave this PC.
    pub metrics: bool,
    pub app_mode: AppMode,
    pub tg: TgSettings,
    pub zapret: ZapretSettings,
    /// Refuse connections to ad and tracker domains (the `category-ads-all` site list), wherever traffic
    /// goes through the core.
    pub adblock: bool,
    /// In the free mode, send AI services (ChatGPT, Claude, Gemini and others) through a free public proxy.
    pub ai_access: bool,
    /// Supercell's games (Brawl Stars and others) through a gaming DNS, direct, in every mode.
    pub games_dns: bool,
    /// The welcome screen has been through: it asks the questions below once.
    pub onboarded: bool,
    /// Which set of questions the user has answered: when the welcome screen asks something new, it shows again
    /// (see `CONSENT_REV`).
    pub consent_rev: u32,
    /// The user agreed to send anonymous statistics (the day's totals: connections, failures, version, platform,
    /// load) to Kometfy's backend. Nothing is sent without it.
    pub consent_stats: bool,
    /// With the statistics: the kind of network and its operator (Wi-Fi or mobile, the SIM's operator; the
    /// backend then also tells the operator from the request). Without it the backend learns no operator from
    /// the statistics.
    pub consent_network: bool,
    /// With the statistics: how many subscriptions and the names their providers gave them.
    pub consent_subs: bool,
    /// The ads' shown and pressed counts (no id of the device).
    pub consent_ads: bool,
    /// The user agreed to run network checks on request (Kometfy's backend and the VPN provider's own) and
    /// send what they found.
    pub consent_tests: bool,
    /// A random id made on this device the first time a consent is given; it names nothing but the install.
    pub install_id: String,
    /// Kometfy's backend (remote settings, ads, statistics, tests); empty = the built-in one. A development build
    /// may point it at a local `wrangler dev`: only https, or http to this device itself, is taken.
    pub backend_url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            core_path: None,
            mixed_port: 17897,
            controller_port: 19097,
            secret: String::new(),
            allow_lan: false,
            ipv6: false,
            mode: Mode::Rule,
            log_level: "info".into(),
            method: Method::SystemProxy,
            connected: false,
            auto_connect: false,
            auto_start_core: true,
            unified_delay: true,
            tcp_concurrent: true,
            find_process_mode: "always".into(),
            delay_url: "https://www.gstatic.com/generate_204".into(),
            delay_timeout_ms: 5000,
            sysproxy_bypass: "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>".into(),
            tun: TunSettings::default(),
            dns: DnsSettings::default(),
            bypass: Bypass::default(),
            active_profile: None,
            lang: "auto".into(),
            theme: "dark".into(),
            close_to_tray: true,
            window_compact: false,
            ip_check: true,
            check_updates: true,
            xray: XraySettings::default(),
            dpi: DpiSettings::default(),
            hwid: true,
            metrics: true,
            app_mode: AppMode::default(),
            tg: TgSettings::default(),
            zapret: ZapretSettings::default(),
            adblock: false,
            ai_access: false,
            games_dns: false,
            onboarded: false,
            consent_rev: 0,
            consent_stats: false,
            consent_network: false,
            consent_subs: false,
            consent_ads: false,
            consent_tests: false,
            install_id: String::new(),
            backend_url: String::new(),
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_atomic(path, serde_json::to_string_pretty(self)?.as_bytes())
    }

    /// Deep-merge a JSON patch into the settings.
    pub fn apply_patch(&mut self, patch: Value) -> Result<()> {
        let mut cur = serde_json::to_value(&*self)?;
        merge(&mut cur, patch);
        *self = serde_json::from_value(cur)?;
        Ok(())
    }

    pub fn proxy_addr(&self) -> String {
        format!("127.0.0.1:{}", self.mixed_port)
    }
}

fn merge(dst: &mut Value, src: Value) {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, v) in s {
                merge(d.entry(k).or_insert(Value::Null), v);
            }
        }
        (d, s) => *d = s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_default_matches_platform() {
        let actual = TunSettings::default().device;
        #[cfg(target_os = "macos")]
        assert_eq!(actual, "utun1024");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(actual, "PrismTun");
    }


    #[test]
    fn old_settings_files_get_the_new_sections() {
        let s: Settings = serde_json::from_str(r#"{"mixed_port": 1234, "tun": {"stack": "system"}}"#).unwrap();
        assert_eq!(s.mixed_port, 1234);
        assert_eq!(s.xray.mode, XrayMode::Auto);
        assert!(!s.dpi.enabled && s.dpi.follow_subscription && s.hwid);
        assert_eq!((s.app_mode, s.tg.port, s.tg.enabled), (AppMode::SmartHybridVpn, 1443, false));
        let s: Settings = serde_json::from_str(r#"{"app_mode": "FreeAntiDPI"}"#).unwrap();
        assert_eq!(s.app_mode, AppMode::FreeAntiDpi);
    }

    #[test]
    fn dpi_patch_is_validated_and_canonical() {
        let mut s = Settings::default();
        s.apply_patch(serde_json::json!({"dpi": {"enabled": true, "length": " 50 - 90 "}, "xray": {"mode": "all"}}))
            .unwrap();
        assert_eq!(s.xray.mode, XrayMode::All);
        s.dpi.normalize().unwrap();
        assert_eq!((s.dpi.length.as_str(), s.dpi.interval.as_str()), ("50-90", "10-20"));
        s.dpi.length = "abc".into();
        assert!(s.dpi.normalize().is_err());
    }

    #[test]
    fn patch_merges_nested() {
        let mut s = Settings::default();
        s.apply_patch(serde_json::json!({"tun": {"stack": "gvisor"}, "mode": "global"}))
            .unwrap();
        assert_eq!(s.tun.stack, "gvisor");
        assert_eq!(s.tun.device, default_tun_device());
        assert_eq!(s.mode, Mode::Global);
    }
}
