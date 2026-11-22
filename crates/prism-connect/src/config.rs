//! Runtime config builder: profile YAML + settings + chains -> mihomo `config.yaml`.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;
use serde_yaml::{Mapping, Value};

use crate::{
    chain::{self, Chain},
    error::{Error, Result},
    rules::UserRule,
    settings::Settings,
    subscription,
    util::{k, put, str_of, strs},
    xray_conf::{self, XrayRun},
};

/// Keys the app owns: whatever the profile says is dropped.
const OWNED_KEYS: &[&str] = &[
    "port",
    "socks-port",
    "redir-port",
    "tproxy-port",
    "mixed-port",
    "external-controller",
    "external-controller-tls",
    "external-controller-unix",
    "external-controller-pipe",
    "external-ui",
    "external-ui-name",
    "external-ui-url",
    "secret",
    "bind-address",
    "allow-lan",
    "authentication",
    "skip-auth-prefixes",
    "lan-allowed-ips",
    "lan-disallowed-ips",
    "tun",
];

const LAN_RULES: &[&str] = &[
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
];

const FAKE_IP_FILTER: &[&str] = &[
    "*.lan",
    "*.local",
    "*.localdomain",
    "+.home.arpa",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "time.*.com",
    "time.*.gov",
    "stun.*.*",
    "stun.*.*.*",
    "+.stun.*.*",
    "+.stun.*.*.*",
    "localhost.ptlogin2.qq.com",
    "WORKGROUP",
];

const SNIFFER_YAML: &str = "enable: true
sniff:
  HTTP:
    ports: [80, 8080-8880]
    override-destination: true
  TLS:
    ports: [443, 8443]
  QUIC:
    ports: [443, 8443]
skip-domain:
  - '+.push.apple.com'
";

#[derive(Debug, Clone, Default, Serialize)]
pub struct BuildInfo {
    /// Selector groups that carry the default route (chains are offered there).
    pub main_groups: Vec<String>,
    pub chain_exits: Vec<String>,
    pub broken_chains: Vec<String>,
    pub proxy_count: usize,
    /// Rules in front of the profile's own (always-direct lists + user rules + LAN): the UI skips
    /// this many entries of the core's rule list to show "rules from the profile".
    pub injected_rules: usize,
    /// User rules that were left out of the config, with the reason.
    pub rule_issues: Vec<RuleIssue>,
    /// Servers handed to Xray: name -> protocol in the profile (`vless`, `vmess`, `trojan`, `ss`).
    pub xray_kinds: BTreeMap<String, String>,
    /// Of those, how many get their TLS handshake cut up.
    pub xray_dpi_nodes: usize,
    /// Servers Xray should have run but cannot: "name: reason".
    pub xray_skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleIssue {
    pub id: String,
    pub reason: String,
}

/// The Xray side of a build: the config for the helper process and where it listens.
pub struct XrayBuilt {
    pub json: String,
    pub nodes: usize,
    pub port: u16,
    pub secret: String,
    /// Outbound tag in `json` -> server name (to tell which server the core objects to).
    pub tags: BTreeMap<String, String>,
}

pub struct Built {
    pub yaml: String,
    pub info: BuildInfo,
    pub xray: Option<XrayBuilt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub name: String,
    pub kind: String,
    pub server: String,
    pub port: u64,
}

fn parse_root(text: Option<&str>) -> Result<Mapping> {
    let Some(t) = text.filter(|t| !t.trim().is_empty()) else {
        return Ok(Mapping::new());
    };
    let mut v: Value = serde_yaml::from_str(t)?;
    v.apply_merge()?;
    match v {
        Value::Mapping(m) => Ok(m),
        _ => Err(Error::msg("profile root must be a YAML mapping")),
    }
}

fn ensure_seq(root: &mut Mapping, key: &str) {
    if !matches!(root.get(key), Some(Value::Sequence(_))) {
        root.insert(k(key), Value::Sequence(vec![]));
    }
}

fn names_of(root: &Mapping, key: &str) -> Vec<String> {
    root.get(key)
        .and_then(Value::as_sequence)
        .map(|s| {
            s.iter()
                .filter_map(|v| v.as_mapping().and_then(|m| str_of(m, "name")).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn seq_len(root: &Mapping, key: &str) -> usize {
    root.get(key).and_then(Value::as_sequence).map_or(0, Vec::len)
}

fn safe_rule_part(s: &str) -> bool {
    !s.trim().is_empty() && !s.contains([',', '\n', '\r'])
}

fn dns_block(s: &Settings, profile_dns: Option<&Mapping>) -> Mapping {
    if !s.dns.override_profile {
        if let Some(p) = profile_dns {
            let mut d = p.clone();
            put(&mut d, "enable", true);
            if !d.contains_key("enhanced-mode") {
                put(&mut d, "enhanced-mode", s.dns.enhanced_mode.as_str());
                if s.dns.enhanced_mode == "fake-ip" && !d.contains_key("fake-ip-range") {
                    put(&mut d, "fake-ip-range", s.dns.fake_ip_range.as_str());
                }
            }
            return d;
        }
    }
    let mut d = Mapping::new();
    put(&mut d, "enable", true);
    put(&mut d, "ipv6", s.ipv6);
    put(&mut d, "enhanced-mode", s.dns.enhanced_mode.as_str());
    if s.dns.enhanced_mode == "fake-ip" {
        put(&mut d, "fake-ip-range", s.dns.fake_ip_range.as_str());
        let mut filter: Vec<String> = FAKE_IP_FILTER.iter().map(|x| x.to_string()).collect();
        if let Some(extra) = profile_dns
            .and_then(|p| p.get("fake-ip-filter"))
            .and_then(Value::as_sequence)
        {
            filter.extend(extra.iter().filter_map(|v| v.as_str().map(String::from)));
        }
        put(&mut d, "fake-ip-filter", strs(filter));
    }
    put(&mut d, "default-nameserver", strs(s.dns.default_nameserver.clone()));
    put(&mut d, "nameserver", strs(s.dns.nameserver.clone()));
    if !s.dns.proxy_server_nameserver.is_empty() {
        put(
            &mut d,
            "proxy-server-nameserver",
            strs(s.dns.proxy_server_nameserver.clone()),
        );
    }
    if let Some(policy) = profile_dns.and_then(|p| p.get("nameserver-policy")) {
        d.insert(k("nameserver-policy"), policy.clone());
    }
    d
}

fn tun_block(s: &Settings, enable: bool) -> Mapping {
    let mut t = Mapping::new();
    put(&mut t, "enable", enable);
    put(&mut t, "stack", s.tun.stack.as_str());
    put(&mut t, "device", s.tun.device.as_str());
    put(&mut t, "auto-route", s.tun.auto_route);
    put(&mut t, "auto-detect-interface", true);
    put(&mut t, "strict-route", s.tun.strict_route);
    put(&mut t, "mtu", s.tun.mtu);
    if s.tun.dns_hijack {
        put(&mut t, "dns-hijack", strs(["any:53", "tcp://any:53"]));
    }
    t
}

/// Keep mihomo's own outbound sockets off the utun once the split routes are
/// installed. A profile-specified outbound binding must not override this.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn bind_macos_tun_outbound(yaml: &str, interface: &str) -> Result<String> {
    if !crate::tun_macos::valid_outbound_interface(interface) { return Err(Error::msg("invalid TUN outbound interface")); }
    let mut root = parse_root(Some(yaml))?;
    if let Some(providers) = root.get("proxy-providers") {
        let providers = providers.as_mapping().ok_or_else(|| Error::msg("invalid proxy providers"))?;
        // Provider contents may be downloaded or refreshed after startup and
        // can override the global interface binding. Refuse this mode until
        // their effective per-node settings can be checked continuously.
        if !providers.is_empty() {
            return Err(Error::msg("macOS TUN does not yet support external proxy providers; use an imported server list or system proxy"));
        }
    }
    if let Some(proxies) = root.get("proxies").and_then(Value::as_sequence) {
        for proxy in proxies.iter().filter_map(Value::as_mapping) {
            if let Some(binding) = proxy.get("interface-name") {
                let binding = binding.as_str().ok_or_else(|| Error::msg("invalid proxy outbound interface"))?;
                if !binding.is_empty() && binding != interface {
                    return Err(Error::msg("a proxy specifies a different outbound interface; TUN cannot be enabled safely"));
                }
            }
        }
    }
    put(&mut root, "interface-name", interface);
    let tun = root.get_mut("tun").and_then(Value::as_mapping_mut)
        .ok_or_else(|| Error::msg("missing TUN configuration"))?;
    if tun.get("enable").and_then(Value::as_bool) != Some(true) { return Err(Error::msg("TUN must be enabled")); }
    put(tun, "auto-detect-interface", false);
    Ok(serde_yaml::to_string(&root)?)
}

/// Prepare an experimental pre-opened macOS utun for a core inheriting this fd.
/// Interface setup must use the same plan. Routes and DNS remain unimplemented.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn configure_preopened_tun(
    yaml: &str,
    fd: i32,
    plan: crate::tun_macos_interface::TunInterfacePlan,
) -> Result<String> {
    if fd < 3 { return Err(Error::msg("invalid TUN descriptor")); }
    let mut root = parse_root(Some(yaml))?;
    // In mihomo 1.19.33, the utun IPv4 host is derived from dns.fake-ip-range
    // even when DNS interception is disabled, and its interface prefix is /30.
    // Preserve compatible user ranges, and reject conflicting ones rather
    // than silently change a user's fake-IP pool.
    let dns = root.entry(k("dns")).or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut().ok_or_else(|| Error::msg("invalid DNS configuration"))?;
    if let Some(range) = dns.get("fake-ip-range") {
        let range = range.as_str().ok_or_else(|| Error::msg("invalid fake-IP range"))?;
        if !range.is_empty() {
            let (host, prefix) = range.split_once('/').ok_or_else(|| Error::msg("invalid fake-IP range"))?;
            let host: std::net::Ipv4Addr = host.parse().map_err(|_| Error::msg("invalid fake-IP range"))?;
            let bits = prefix.parse::<u8>().map_err(|_| Error::msg("invalid fake-IP range"))?;
            if bits > 32 || bits.to_string() != prefix || host != plan.ipv4() {
                return Err(Error::msg("fake-IP range conflicts with experimental TUN interface"));
            }
        }
    } else {
        put(dns, "fake-ip-range", format!("{}/16", plan.ipv4()));
    }
    put(dns, "enable", true);
    let tun = root.get_mut("tun").and_then(Value::as_mapping_mut)
        .ok_or_else(|| Error::msg("missing TUN configuration"))?;
    if tun.get("enable").and_then(Value::as_bool) != Some(true) {
        return Err(Error::msg("TUN must be enabled before supplying a descriptor"));
    }
    // mihomo 1.19.33 ignores this YAML key and instead derives the IPv4 host
    // from dns.fake-ip-range. Reject it rather than give a false impression
    // that a caller-selected interface address is honored.
    if tun.contains_key("inet4-address") {
        return Err(Error::msg("explicit inet4-address is unsupported by experimental TUN"));
    }
    put(tun, "file-descriptor", fd);
    put(tun, "auto-route", false);
    put(tun, "auto-redirect", false);
    // The kernel default route remains on the physical interface; mihomo
    // must bind its outbound connections there to avoid recapturing itself.
    put(tun, "auto-detect-interface", true);
    put(tun, "strict-route", false);
    put(tun, "mtu", plan.mtu());
    // Unlike removing the key, explicit empty arrays override mihomo's
    // nonempty defaults. IPv6 capture is not part of this experiment.
    put(tun, "inet6-address", Vec::<String>::new());
    put(tun, "dns-mode", "disabled");
    put(tun, "dns-hijack", strs(["any:53", "tcp://any:53"]));
    Ok(serde_yaml::to_string(&root)?)
}

/// Android: the VPN service opened the tunnel and handed its descriptor to the core. The service's
/// builder owns the interface and the routes, and the app is kept out of the VPN, so the core's own
/// connections already leave by the real network: it must not set up routes or look for a default
/// interface (an app may not read the routing table on current Android).
/// The tunnel's MTU on Android. Big packets inside the tunnel never reach the network (the core's own connections
/// leave by the real one), and gvisor, the core's stack there, then handles a few big packets instead of many
/// small ones: a quarter less of the core's processor time per megabyte at the same speed (Huawei tablet, 84 Mbit/s:
/// 79 ms/MB against 100-115 at 1500). Clash Meta for Android and sing-box use 9000 too.
pub const ANDROID_MTU: u32 = 9000;

/// Android's free mode: the core hands fake addresses only to the names its rules do something with (the bypass
/// engine, the AI proxy, ad blocking) and real ones to every other name, so the tunnel can take only the fake
/// range and the rest of a phone's traffic never passes the core's network stack, which costs a phone's
/// processor for traffic the core would only send direct. A whitelist is safe with a whole-traffic tunnel too:
/// the core then finds the names in the connections, as before.
/// None when the rules do something with traffic it cannot tell by name (by address, port or app, a keyword, or
/// a catch-all that is not DIRECT): then the whole traffic has to go through the core.
pub fn fake_ip_only_for_core(yaml: &str) -> Result<Option<String>> {
    let mut root = parse_root(Some(yaml))?;
    let behavior = |name: &str| {
        root.get("rule-providers")
            .and_then(|p| p.get(name))
            .and_then(|p| p.get("behavior"))
            .and_then(Value::as_str)
            .unwrap_or("classical")
            .to_string()
    };
    let rules: Vec<String> = root.get("rules").and_then(Value::as_sequence).map(|r| r.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    let mut names: Vec<String> = Vec::new();
    let mut ends_direct = false;
    for rule in &rules {
        let parts: Vec<&str> = rule.split(',').map(str::trim).collect();
        let (kind, target) = match parts.first() {
            Some(&"MATCH") => {
                ends_direct = parts.get(1) == Some(&"DIRECT");
                break;
            }
            Some(&("AND" | "OR" | "NOT")) => (parts[0], parts.iter().rev().find(|p| !p.ends_with(')')).copied().unwrap_or("")),
            Some(k) => (*k, parts.get(2).copied().unwrap_or("")),
            None => continue,
        };
        if target == "DIRECT" {
            continue;
        }
        let mut terms: Vec<(String, String)> = Vec::new();
        if matches!(kind, "AND" | "OR" | "NOT") {
            // the names inside a logic rule; one with none (by port or network alone) needs the whole traffic
            let flat = rule.replace(['(', ')'], ",");
            let tokens: Vec<&str> = flat.split(',').map(str::trim).filter(|t| !t.is_empty()).collect();
            for w in tokens.windows(2) {
                if matches!(w[0], "DOMAIN" | "DOMAIN-SUFFIX" | "RULE-SET" | "GEOSITE") {
                    terms.push((w[0].to_string(), w[1].to_string()));
                }
            }
            if terms.is_empty() {
                return Ok(None);
            }
        } else {
            terms.push((kind.to_string(), parts.get(1).copied().unwrap_or("").to_string()));
        }
        for (kind, value) in terms {
            let name = match kind.as_str() {
                "DOMAIN" => value,
                "DOMAIN-SUFFIX" => format!("+.{value}"),
                "GEOSITE" => format!("geosite:{value}"),
                "RULE-SET" if behavior(&value) == "domain" => format!("rule-set:{value}"),
                _ => return Ok(None),
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    let Some(dns) = root.get_mut("dns").and_then(Value::as_mapping_mut) else { return Ok(None) };
    if !ends_direct || dns.get("enhanced-mode").and_then(Value::as_str) != Some("fake-ip") {
        return Ok(None);
    }
    put(dns, "fake-ip-filter-mode", "whitelist");
    put(dns, "fake-ip-filter", strs(names));
    Ok(Some(serde_yaml::to_string(&root)?))
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn configure_android_tun(yaml: &str, fd: i32) -> Result<String> {
    if fd < 3 {
        return Err(Error::msg("invalid TUN descriptor"));
    }
    let mut root = parse_root(Some(yaml))?;
    let dns = root
        .entry(k("dns"))
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .ok_or_else(|| Error::msg("invalid DNS configuration"))?;
    put(dns, "enable", true);
    if !dns.contains_key("fake-ip-range") {
        put(dns, "fake-ip-range", "198.18.0.1/16");
    }
    let tun = root
        .get_mut("tun")
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| Error::msg("missing TUN configuration"))?;
    tun.remove("device");
    put(tun, "enable", true);
    put(tun, "file-descriptor", fd);
    // the system and mixed stacks carry nothing over the service's descriptor (measured on Android 12)
    put(tun, "stack", "gvisor");
    put(tun, "mtu", ANDROID_MTU);
    put(tun, "auto-route", false);
    put(tun, "auto-redirect", false);
    put(tun, "auto-detect-interface", false);
    put(tun, "strict-route", false);
    put(tun, "inet6-address", Vec::<String>::new());
    put(tun, "dns-hijack", strs(["any:53", "tcp://any:53"]));
    // an app cannot read the process table of other apps on Android 10 and later
    put(&mut root, "find-process-mode", "off");
    Ok(serde_yaml::to_string(&root)?)
}

fn main_groups(root: &Mapping) -> Vec<String> {
    let groups: Vec<&Mapping> = root
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .map(|s| s.iter().filter_map(Value::as_mapping).collect())
        .unwrap_or_default();
    let is_select = |name: &str| {
        groups
            .iter()
            .any(|g| str_of(g, "name") == Some(name) && str_of(g, "type") == Some("select"))
    };
    let mut out: Vec<String> = Vec::new();
    if let Some(rules) = root.get("rules").and_then(Value::as_sequence) {
        for r in rules.iter().rev() {
            if let Some(rest) = r.as_str().and_then(|s| s.strip_prefix("MATCH,")) {
                let target = rest.split(',').next().unwrap_or("").trim();
                if is_select(target) {
                    out.push(target.to_string());
                }
                break;
            }
        }
    }
    if let Some(first) = groups.iter().find(|g| str_of(g, "type") == Some("select")) {
        if let Some(n) = str_of(first, "name") {
            if !out.iter().any(|o| o == n) {
                out.push(n.to_string());
            }
        }
    }
    out
}

fn resolve_target(
    t: &str,
    main: &[String],
    exits: &HashMap<String, String>,
    known: &HashSet<String>,
) -> std::result::Result<String, String> {
    match t {
        "@proxy" => main
            .first()
            .cloned()
            .ok_or_else(|| "this profile has no proxy group".to_string()),
        "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" => Ok(t.to_string()),
        _ if t.starts_with("@chain:") => exits
            .get(&t["@chain:".len()..])
            .cloned()
            .ok_or_else(|| "the chain is not active in this profile".to_string()),
        _ if known.contains(t) => Ok(t.to_string()),
        _ => Err(format!("“{t}” is not in this profile")),
    }
}

/// The name of the engine in the core's config.
pub const DPI_PROXY: &str = "DPI";

/// The free mode's DPI route (Android, macOS): `sites` (YouTube, Discord, the user's own) go to the local
/// engine at `port`, just above the final catch-all rule. YouTube's QUIC is refused, so the browser falls
/// back to TCP, which the engine can change. Plain domain rules: no geosite.dat needed.
pub fn with_dpi(yaml: &str, port: u16, sites: &[String]) -> Result<String> {
    let mut root: Mapping = serde_yaml::from_str(yaml)?;
    let mut proxy = Mapping::new();
    proxy.insert(k("name"), Value::from(DPI_PROXY));
    proxy.insert(k("type"), Value::from("socks5"));
    proxy.insert(k("server"), Value::from("127.0.0.1"));
    proxy.insert(k("port"), Value::from(port));
    // UDP too: the engine sends a fake before the video servers' QUIC (`-a1`)
    proxy.insert(k("udp"), Value::from(true));
    ensure_seq(&mut root, "proxies");
    ensure_seq(&mut root, "rules");
    if let Some(Value::Sequence(list)) = root.get_mut("proxies") {
        list.push(Value::Mapping(proxy));
    }
    add_rule_set(&mut root, "kometfy-youtube", YOUTUBE_LIST);
    add_rule_set(&mut root, "kometfy-discord", DISCORD_LIST);
    // QUIC to the video servers goes through the engine (a fake first); the rest of QUIC stays direct,
    // which the provider measured on 12 November 2026 let through while it cut the same sites' TLS
    let mut ours: Vec<Value> = vec![
        Value::from(format!("AND,((NETWORK,UDP),(DOMAIN-SUFFIX,googlevideo.com)),{DPI_PROXY}")),
        Value::from("AND,((NETWORK,UDP),(DST-PORT,443)),DIRECT"),
        Value::from(format!("RULE-SET,kometfy-youtube,{DPI_PROXY}")),
        Value::from(format!("RULE-SET,kometfy-discord,{DPI_PROXY}")),
    ];
    ours.extend(sites.iter().map(|d| Value::from(format!("DOMAIN-SUFFIX,{d},{DPI_PROXY}"))));
    if let Some(Value::Sequence(rules)) = root.get_mut("rules") {
        let at = match rules.last().and_then(Value::as_str) {
            Some(last) if last.starts_with("MATCH,") => rules.len() - 1,
            _ => rules.len(),
        };
        rules.splice(at..at, ours);
    }
    Ok(serde_yaml::to_string(&root)?)
}

/// Online games whose whole traffic goes direct in the smart mode, under the user's own rules (so a rule that sends
/// one through the VPN still wins). Their sign-in domains are on the lists of what is blocked while their game
/// servers are not, so a game's session came half through the VPN's address and half from the user's own, and the
/// game threw it out: Battlefield 6 with "UNKNOWN ERROR 0:85011S". Players in Russia do the same by hand (the VPN
/// for the EA app, the game itself outside it). Windows names; elsewhere they match nothing.
pub const GAME_PROCESSES: &[&str] = &[
    "bf6.exe",
    "bf2042.exe",
    "bf1.exe",
    "bfv.exe",
    "FC25.exe",
    "FC26.exe",
    "r5apex.exe",
    "r5apex_dx12.exe",
    "cs2.exe",
    "dota2.exe",
    "VALORANT-Win64-Shipping.exe",
    "FortniteClient-Win64-Shipping.exe",
    "TslGame.exe",
    "RainbowSix.exe",
    "cod.exe",
    "GTA5.exe",
    "GTA5_Enhanced.exe",
    "EscapeFromTarkov.exe",
    "RustClient.exe",
    "Overwatch.exe",
    "destiny2.exe",
    "Warframe.x64.exe",
    "DeadByDaylight-Win64-Shipping.exe",
];

/// Ad and tracker blocking: the domains of the community's `category-ads-all` list (MetaCubeX's build) are
/// refused. A rule set the core downloads by itself (and refreshes daily), so it works where geosite.dat
/// is missing, as on a phone. (roscomvpn's `category-ads` used before had shrunk to an empty file.)
pub const ADS_RULE: &str = "RULE-SET,kometfy-ads-all,REJECT";
const ADS_LIST: &str = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs";
/// The bigger list beside it: HaGeZi's Multi PRO mini (about 100 000 ad, tracker and malware domains, Russian
/// ad networks among them). The app downloads it and has the core pack it ([`with_more_ads`]).
pub const ADS_MORE: &str = "kometfy-ads-more";
pub const ADS_MORE_URL: &str = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.mini-onlydomains.txt";

/// Refuse the domains of the packed bigger list too, right below the first one. It is a file the app keeps
/// in `ruleset/` of the core's folder.
pub fn with_more_ads(yaml: &str) -> Result<String> {
    let mut root: Mapping = serde_yaml::from_str(yaml)?;
    if !matches!(root.get("rule-providers"), Some(Value::Mapping(_))) {
        root.insert(k("rule-providers"), Value::Mapping(Mapping::new()));
    }
    let mut set = Mapping::new();
    set.insert(k("type"), Value::from("file"));
    set.insert(k("behavior"), Value::from("domain"));
    set.insert(k("format"), Value::from("mrs"));
    set.insert(k("path"), Value::from(format!("./ruleset/{ADS_MORE}.mrs")));
    if let Some(Value::Mapping(sets)) = root.get_mut("rule-providers") {
        sets.insert(k(ADS_MORE), Value::Mapping(set));
    }
    if let Some(Value::Sequence(rules)) = root.get_mut("rules") {
        let at = rules.iter().position(|r| r.as_str() == Some(ADS_RULE)).map_or(0, |i| i + 1);
        rules.insert(at, Value::from(format!("RULE-SET,{ADS_MORE},REJECT")));
    }
    Ok(serde_yaml::to_string(&root)?)
}

/// The free route to AI services: a free public HTTP proxy, which lets through only the domains on its list (its full
/// PAC file; the short "free" one dropped the AI services on 20 November 2026 while the proxy still lets them through).
/// These are the AI ones of the full list, with Google's sign-in and the internal APIs its AI apps call, taken on
/// 20 November 2026: AI Studio broke without `*.clients6.google.com`, the account pages and three `-pa` APIs.
/// Left out on purpose though the list has them: `googleapis.com`, `gstatic.com`, `googleusercontent.com` and
/// `www.google.com` as a whole. Through one shared free proxy they would take YouTube's API, Android's Play services,
/// Chrome's updates and Google search (with its captchas for shared addresses). The backend's `ai_sites` adds names
/// without a release when a service needs more.
/// shortcut: a fixed copy of the proxy's list; read its PAC file at run time if the list changes often.
/// The proxies themselves come from the app build (`builtin::Builtin::ai_proxies`), not from this source.
const AI_GROUP: &str = "Kometfy AI";
pub const AI_SITES: [&str; 112] = [
    // OpenAI
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "oaistatsig.com", "sora.com", "livekit.cloud",
    "openai-api.arkoselabs.com", "openaicom.imgix.net", "featuregates.org", "statsig.com", "statsigapi.net",
    // Anthropic
    "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
    // Google: the AI apps and their APIs
    "gemini.google.com", "gemini.google", "aistudio.google.com", "google.dev", "generativelanguage.googleapis.com",
    "clients6.google.com", "aisandbox-pa.googleapis.com", "content-aisandbox-pa.googleapis.com",
    "cloudcode-pa.googleapis.com", "content-cloudcode-pa.googleapis.com", "notebooklm.google.com", "notebooklm.google",
    "notebook.google.com", "notebook.google", "notebooklm-pa.googleapis.com", "labs.google", "withgoogle.com",
    "jules.google.com", "bard.google.com", "proactivebackend-pa.googleapis.com", "robinfrontend-pa.googleapis.com",
    "appcatalyst.pa.googleapis.com", "developerprofiles-pa.googleapis.com", "subscriptionsfirstparty-pa.googleapis.com",
    "idx.google.com", "colab.research.google.com", "opal.google", "learning.google.com", "cloud.google.com",
    "console.cloud.google.com",
    // Google: the account they sign in with (a page through the proxy and its sign-in direct would not agree)
    "accounts.google.com", "ogs.google.com", "myaccount.google.com", "apis.google.com", "consent.google.com",
    "lh3.google.com",
    // xAI, Microsoft, GitHub
    "x.ai", "grok.com", "grokusercontent.com", "copilot.microsoft.com", "copilot.com", "sydney.bing.com",
    "edgeservices.bing.com", "speech.platform.bing.com", "login.live.com", "githubcopilot.com",
    "copilot-proxy.githubusercontent.com", "designer.microsoft.com", "designerapp.officeapps.live.com",
    "designerapp.osi.office.net",
    // editors and agents
    "cursor.com", "api2.cursor.sh", "api3.cursor.sh", "agent.api5.cursor.sh", "agentn.api5.cursor.sh",
    "agent.global.api5.cursor.sh", "agentn.global.api5.cursor.sh", "prod.authentication.cursor.sh", "codeium.com",
    "windsurf.com", "jetbrains.ai", "account.jetbrains.com", "api.app.prod.grazie.aws.intellij.net", "trae.ai",
    "traecdn.ai", "marscode.com", "marscoding.com", "trae-api-sg.mchost.guru", "kilo.ai", "kilocode.ai",
    "app.cline.bot", "docs.cline.bot", "factory.ai",
    // other AI services
    "deepl.com", "elevenlabs.io", "openrouter.ai", "groq.com", "cloud.cerebras.ai", "api.cerebras.ai", "genspark.ai",
    "manus.im", "t3.chat", "duck.ai", "recraft.ai", "jina.ai", "hedra.com", "lightning.ai", "reve.art", "app.reve.com",
    "assemblyai.com", "deepgram.com", "granola.ai", "granola.so", "granola.club", "openevidence.com",
    "ai-chat.bsg.brave.com",
];
/// Supercell's games through a gaming DNS: it answers
/// the names of the game servers with its own relays, which reach Supercell from Russia and Belarus, and every
/// other name as it is. Measured on 13 November 2026: Brawl Stars, Clash Royale, Clash of Clans and Squad
/// Busters get relays (port 9339 open); it speaks DoH (HTTP/2 only) and DoT, not plain DNS.
/// The DNS servers come from the app build (`builtin::Builtin::games_dns`), not from this source.
pub const GAME_SITES: [&str; 8] = [
    "brawlstarsgame.com", "brawlstars.com", "clashroyaleapp.com", "clashroyale.com", "clashofclans.com",
    "squadbustersgame.com", "haydaygame.com", "boombeachgame.com",
];

/// Roblox's pictures (game icons, the catalog, avatars: tr.rbxcdn.com and the rest of rbxcdn.com). Roblox's DNS gives
/// a resolver in Russia a chain of names with no address at its end, so the pictures stay grey, while the same CDN
/// answers a resolver abroad and its edges open fine from Russia. Asked through Google's DNS as if from Finland (EDNS
/// Client Subnet), the names get those edges. Measured from Russia on 16 November 2026: no address without the
/// subnet, an Akamai edge with it, and the icon loaded in 0.17 s. Only the name is resolved this way: Roblox's
/// traffic keeps its route (through the VPN where the mode sends it there).
const ROBLOX_CDN: &str = "+.rbxcdn.com";
const ROBLOX_DNS: &str = "https://dns.google/dns-query#ecs=95.216.0.0/24&ecs-override=true";

/// The "Games" switch. Roblox's pictures get a resolver that finds them ([`ROBLOX_CDN`]). With the gaming DNS from the
/// app build (`servers`), Supercell's games ask it for their names and their traffic goes direct (past a VPN, for
/// the lowest ping), right above the LAN rules: below the user's own rules and ad blocking, above a profile's rules.
/// It reaches the games whose names and traffic go through the core: on a phone, and with TUN on a computer.
pub fn with_games(yaml: &str, extra: &[String], servers: &[String]) -> Result<String> {
    let sites = merged(&GAME_SITES, extra);
    let mut root: Mapping = serde_yaml::from_str(yaml)?;
    let dns = root.entry(k("dns")).or_insert_with(|| Value::Mapping(Mapping::new()));
    if let Value::Mapping(dns) = dns {
        if !matches!(dns.get("nameserver-policy"), Some(Value::Mapping(_))) {
            dns.insert(k("nameserver-policy"), Value::Mapping(Mapping::new()));
        }
        if let Some(Value::Mapping(policy)) = dns.get_mut("nameserver-policy") {
            policy.insert(k(ROBLOX_CDN), Value::Sequence(vec![Value::from(ROBLOX_DNS)]));
            if !servers.is_empty() {
                for d in &sites {
                    policy.insert(k(&format!("+.{d}")), Value::Sequence(servers.iter().map(|s| Value::from(s.as_str())).collect()));
                }
            }
        }
    }
    if servers.is_empty() {
        return Ok(serde_yaml::to_string(&root)?);
    }
    if !matches!(root.get("rule-providers"), Some(Value::Mapping(_))) {
        root.insert(k("rule-providers"), Value::Mapping(Mapping::new()));
    }
    let mut set = Mapping::new();
    set.insert(k("type"), Value::from("inline"));
    set.insert(k("behavior"), Value::from("domain"));
    set.insert(k("payload"), Value::Sequence(sites.iter().map(|d| Value::from(format!("+.{d}"))).collect()));
    if let Some(Value::Mapping(sets)) = root.get_mut("rule-providers") {
        sets.insert(k("kometfy-games"), Value::Mapping(set));
    }
    ensure_seq(&mut root, "rules");
    if let Some(Value::Sequence(rules)) = root.get_mut("rules") {
        let at = rules.iter().position(|r| r.as_str() == Some(LAN_RULES[0])).unwrap_or(0);
        rules.insert(at, Value::from("RULE-SET,kometfy-games,DIRECT"));
    }
    Ok(serde_yaml::to_string(&root)?)
}

/// The rest of what the AI proxy carries, with the AI services: the services that closed for Russia (Notion, Canva,
/// Adobe, Figma, the antiviruses' updates...). Written from the proxy's full PAC by scripts/proxy-sites.mjs, less the
/// names that stay off a shared proxy (Google as a whole, Windows' updates, big CDNs, telemetry); one name per line,
/// each with the names under it.
const PROXY_SITES: &str = include_str!("proxy_sites.txt");

/// The names of [`PROXY_SITES`].
pub fn proxy_sites() -> impl Iterator<Item = &'static str> {
    PROXY_SITES.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The built-in list and the remote one (docs/BACKEND.md: it only adds), each name once.
fn merged(builtin: &[&str], extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(builtin.len() + extra.len());
    for d in builtin {
        if !out.iter().any(|o| o == d) {
            out.push(d.to_string());
        }
    }
    for d in extra {
        if !out.contains(d) {
            out.push(d.clone());
        }
    }
    out
}

/// What the proxy's list sends direct although it is under a name above (big downloads, a forum that refuses
/// data-centre addresses, Google's Antigravity, which the proxy's owner sends direct).
const AI_DIRECT: [&str; 3] = ["community.openai.com", "downloads.cursor.com", "antigravity.google"];

/// Send AI services through the AI proxy, just above the final catch-all rule (and above the free mode's
/// QUIC rule: their QUIC is refused, so browsers fall back to TCP, which an HTTP proxy carries).
/// `proxies`: the AI proxies as `host:port`; without them the YAML is left as it is.
pub fn with_ai(yaml: &str, extra: &[String], proxies: &[String]) -> Result<String> {
    let proxies: Vec<(String, &str, u16)> = proxies
        .iter()
        .filter_map(|p| p.rsplit_once(':'))
        .filter_map(|(host, port)| Some((host, port.parse().ok()?)))
        .enumerate()
        .map(|(i, (host, port))| (format!("{AI_GROUP} {}", i + 1), host, port))
        .collect();
    if proxies.is_empty() {
        return Ok(yaml.to_string());
    }
    let builtin: Vec<&str> = AI_SITES.iter().copied().chain(proxy_sites()).collect();
    let sites = merged(&builtin, extra);
    let mut root: Mapping = serde_yaml::from_str(yaml)?;
    ensure_seq(&mut root, "proxies");
    ensure_seq(&mut root, "proxy-groups");
    ensure_seq(&mut root, "rules");
    if let Some(Value::Sequence(list)) = root.get_mut("proxies") {
        for (name, server, port) in &proxies {
            let mut p = Mapping::new();
            p.insert(k("name"), Value::from(name.as_str()));
            p.insert(k("type"), Value::from("http"));
            p.insert(k("server"), Value::from(*server));
            p.insert(k("port"), Value::from(*port));
            list.push(Value::Mapping(p));
        }
    }
    if let Some(Value::Sequence(list)) = root.get_mut("proxy-groups") {
        let mut g = Mapping::new();
        g.insert(k("name"), Value::from(AI_GROUP));
        g.insert(k("type"), Value::from("fallback"));
        g.insert(k("proxies"), Value::Sequence(proxies.iter().map(|(n, _, _)| Value::from(n.as_str())).collect()));
        // a name on the proxy's list, so the check goes through
        g.insert(k("url"), Value::from("https://www.gstatic.com/generate_204"));
        g.insert(k("interval"), Value::from(600));
        list.push(Value::Mapping(g));
    }
    if !matches!(root.get("rule-providers"), Some(Value::Mapping(_))) {
        root.insert(k("rule-providers"), Value::Mapping(Mapping::new()));
    }
    let mut set = Mapping::new();
    set.insert(k("type"), Value::from("inline"));
    set.insert(k("behavior"), Value::from("domain"));
    set.insert(k("payload"), Value::Sequence(sites.iter().map(|d| Value::from(format!("+.{d}"))).collect()));
    if let Some(Value::Mapping(sets)) = root.get_mut("rule-providers") {
        sets.insert(k("kometfy-ai"), Value::Mapping(set));
    }
    let mut ours: Vec<Value> = AI_DIRECT.iter().map(|d| Value::from(format!("DOMAIN-SUFFIX,{d},DIRECT"))).collect();
    ours.push(Value::from("AND,((NETWORK,UDP),(RULE-SET,kometfy-ai)),REJECT"));
    ours.push(Value::from(format!("RULE-SET,kometfy-ai,{AI_GROUP}")));
    if let Some(Value::Sequence(rules)) = root.get_mut("rules") {
        let at = match rules.last().and_then(Value::as_str) {
            Some(last) if last.starts_with("MATCH,") => rules.len() - 1,
            _ => rules.len(),
        };
        rules.splice(at..at, ours);
    }
    Ok(serde_yaml::to_string(&root)?)
}
/// YouTube and Discord as rule sets, for the route to the DPI engine (with a spelled-out list beside them,
/// for the moment before the sets are downloaded).
const YOUTUBE_LIST: &str = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite/release/mihomo/youtube.mrs";
const DISCORD_LIST: &str = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.mrs";

/// A domain rule set (`.mrs`) the core fetches itself, under a name of ours so a profile's own sets stay apart.
fn add_rule_set(root: &mut Mapping, name: &str, url: &str) {
    if !matches!(root.get("rule-providers"), Some(Value::Mapping(_))) {
        root.insert(k("rule-providers"), Value::Mapping(Mapping::new()));
    }
    let mut set = Mapping::new();
    set.insert(k("type"), Value::from("http"));
    set.insert(k("behavior"), Value::from("domain"));
    set.insert(k("format"), Value::from("mrs"));
    set.insert(k("url"), Value::from(url));
    set.insert(k("path"), Value::from(format!("./ruleset/{name}.mrs")));
    set.insert(k("interval"), Value::from(86400));
    if let Some(Value::Mapping(sets)) = root.get_mut("rule-providers") {
        sets.insert(k(name), Value::Mapping(set));
    }
}

/// Build the runtime config without user rules (validation of freshly imported profiles).
pub fn build(
    profile_yaml: Option<&str>,
    active_profile: Option<&str>,
    s: &Settings,
    chains: &[Chain],
    tun_on: bool,
) -> Result<Built> {
    build_with_rules(profile_yaml, active_profile, s, chains, &[], tun_on)
}

/// Build the runtime config. `tun_on` is the live TUN state to bake into the file, so a hot reload
/// never flips it.
pub fn build_with_rules(
    profile_yaml: Option<&str>,
    active_profile: Option<&str>,
    s: &Settings,
    chains: &[Chain],
    user_rules: &[UserRule],
    tun_on: bool,
) -> Result<Built> {
    build_all(profile_yaml, active_profile, s, chains, user_rules, tun_on, None)
}

/// [`build_with_rules`] plus the Xray helper: with `xray` set, the servers it takes over are
/// replaced by SOCKS5 nodes that point to it and `Built::xray` holds its config.
pub fn build_all(
    profile_yaml: Option<&str>,
    active_profile: Option<&str>,
    s: &Settings,
    chains: &[Chain],
    user_rules: &[UserRule],
    tun_on: bool,
    xray: Option<&XrayRun>,
) -> Result<Built> {
    let mut root = parse_root(profile_yaml)?;
    let profile_dns = root.get("dns").and_then(Value::as_mapping).cloned();
    for key in OWNED_KEYS {
        root.remove(*key);
    }
    ensure_seq(&mut root, "proxies");
    ensure_seq(&mut root, "proxy-groups");
    ensure_seq(&mut root, "rules");

    let proxy_names = names_of(&root, "proxies");
    let has_providers = root
        .get("proxy-providers")
        .and_then(Value::as_mapping)
        .is_some_and(|m| !m.is_empty());
    if proxy_names.is_empty() && !has_providers {
        root.insert(k("proxy-groups"), Value::Sequence(vec![]));
        root.insert(k("rules"), strs(["MATCH,DIRECT"]));
    } else {
        if seq_len(&root, "proxy-groups") == 0 && !has_providers {
            root.insert(
                k("proxy-groups"),
                Value::Sequence(subscription::default_groups(&proxy_names)),
            );
        }
        if seq_len(&root, "rules") == 0 {
            let target = names_of(&root, "proxy-groups")
                .into_iter()
                .next()
                .unwrap_or_else(|| "DIRECT".into());
            root.insert(k("rules"), strs([format!("MATCH,{target}")]));
        }
    }

    // "always direct" lists from older versions (the rule editor owns this now, see Manager::new)
    let mut pre: Vec<String> = Vec::new();
    pre.extend(
        s.bypass
            .processes
            .iter()
            .filter(|p| safe_rule_part(p))
            .map(|p| format!("PROCESS-NAME,{},DIRECT", p.trim())),
    );
    pre.extend(
        s.bypass
            .domains
            .iter()
            .filter(|d| safe_rule_part(d))
            .map(|d| format!("DOMAIN-SUFFIX,{},DIRECT", d.trim())),
    );
    pre.extend(s.bypass.cidrs.iter().filter(|c| safe_rule_part(c)).map(|c| {
        let kind = if c.contains(':') { "IP-CIDR6" } else { "IP-CIDR" };
        format!("{kind},{},DIRECT,no-resolve", c.trim())
    }));

    let mut info = BuildInfo {
        main_groups: main_groups(&root),
        proxy_count: proxy_names.len(),
        ..Default::default()
    };
    let report = chain::inject(&mut root, chains, active_profile, &info.main_groups);
    info.chain_exits = report.exits;
    info.broken_chains = report.broken;

    // After the chains: their hops after the first carry a `dialer-proxy` and stay with mihomo,
    // while a first hop that Xray runs is simply a SOCKS5 node to them.
    let mut xray_built = None;
    if let Some(run) = xray {
        let plan = xray_conf::plan(&mut root, run);
        info.xray_skipped = plan.skipped.iter().map(|(n, why)| format!("{n}: {why}")).collect();
        if plan.nodes > 0 {
            info.xray_kinds = plan.kinds;
            info.xray_dpi_nodes = plan.dpi_nodes;
            xray_built = Some(XrayBuilt {
                json: plan.json,
                nodes: plan.nodes,
                port: run.port,
                secret: run.secret.clone(),
                tags: plan.tags,
            });
            // Xray's own connections to the servers must not enter the TUN again and come back to it
            if safe_rule_part(&run.exe_name) {
                pre.insert(0, format!("PROCESS-NAME,{},DIRECT", run.exe_name.trim()));
            }
        }
    }

    // User rules: resolve their symbolic targets against what this profile really has (after the
    // chain clones exist). A rule that cannot be resolved is skipped and reported, never half-applied.
    let exits_by_id: HashMap<String, String> = chains
        .iter()
        .map(|c| (c.id.clone(), chain::exit_name(c)))
        .filter(|(_, exit)| info.chain_exits.contains(exit))
        .collect();
    let mut known: HashSet<String> = names_of(&root, "proxies")
        .into_iter()
        .chain(names_of(&root, "proxy-groups"))
        .collect();
    known.insert("GLOBAL".into());
    let rule_sets: HashSet<String> = root
        .get("rule-providers")
        .and_then(Value::as_mapping)
        .map(|m| m.keys().filter_map(|k| k.as_str().map(String::from)).collect())
        .unwrap_or_default();
    for r in user_rules.iter().filter(|r| r.enabled) {
        if r.kind == "RULE-SET" && !rule_sets.contains(&r.value) {
            info.rule_issues.push(RuleIssue {
                id: r.id.clone(),
                reason: format!("rule set “{}” is not in this profile", r.value),
            });
            continue;
        }
        match resolve_target(&r.target, &info.main_groups, &exits_by_id, &known) {
            Ok(target) => pre.push(r.rule_line(&target)),
            Err(reason) => info.rule_issues.push(RuleIssue {
                id: r.id.clone(),
                reason,
            }),
        }
    }
    // Online games in one piece, direct (the smart mode says games go direct; the full VPN mode ignores rules)
    pre.extend(GAME_PROCESSES.iter().map(|p| format!("PROCESS-NAME,{p},DIRECT")));
    // Ads below the user's rules, so a site the user lets through on purpose wins
    if s.adblock {
        add_rule_set(&mut root, "kometfy-ads-all", ADS_LIST);
        pre.push(ADS_RULE.to_string());
    }
    // LAN stays below the user's rules (so "send 192.168.1.5 through the proxy" can win), above the profile's
    pre.extend(LAN_RULES.iter().map(|r| r.to_string()));
    info.injected_rules = pre.len();
    if let Some(Value::Sequence(rules)) = root.get_mut("rules") {
        let mut merged: Vec<Value> = pre.into_iter().map(Value::String).collect();
        merged.append(rules);
        *rules = merged;
    }

    put(&mut root, "mixed-port", s.mixed_port);
    put(&mut root, "allow-lan", s.allow_lan);
    if s.allow_lan {
        put(&mut root, "bind-address", "*");
    }
    put(&mut root, "mode", s.mode.as_str());
    put(&mut root, "log-level", s.log_level.as_str());
    put(&mut root, "ipv6", s.ipv6);
    put(&mut root, "external-controller", format!("127.0.0.1:{}", s.controller_port));
    put(&mut root, "secret", s.secret.as_str());
    put(&mut root, "unified-delay", s.unified_delay);
    put(&mut root, "tcp-concurrent", s.tcp_concurrent);
    put(&mut root, "find-process-mode", s.find_process_mode.as_str());
    put(&mut root, "geo-auto-update", false);
    let mut prof = Mapping::new();
    put(&mut prof, "store-selected", true);
    put(&mut prof, "store-fake-ip", true);
    put(&mut root, "profile", prof);

    put(&mut root, "tun", tun_block(s, tun_on));
    root.insert(k("dns"), Value::Mapping(dns_block(s, profile_dns.as_ref())));
    if !root.contains_key("sniffer") {
        root.insert(k("sniffer"), serde_yaml::from_str(SNIFFER_YAML)?);
    }

    Ok(Built {
        yaml: serde_yaml::to_string(&Value::Mapping(root))?,
        info,
        xray: xray_built,
    })
}

/// Plain proxies of a profile, for pickers (chain builder) that work with the core stopped.
pub fn list_nodes(profile_yaml: &str) -> Vec<NodeInfo> {
    let Ok(root) = parse_root(Some(profile_yaml)) else {
        return vec![];
    };
    let mut seen = HashSet::new();
    root.get("proxies")
        .and_then(Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(Value::as_mapping)
                .filter_map(|m| {
                    let name = str_of(m, "name")?.to_string();
                    seen.insert(name.clone()).then(|| NodeInfo {
                        kind: str_of(m, "type").unwrap_or("?").to_string(),
                        server: str_of(m, "server").unwrap_or("").to_string(),
                        port: m.get("port").and_then(Value::as_u64).unwrap_or(0),
                        name,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dpi_route_sits_above_the_catch_all() {
        let yaml = "proxies: []\nrules:\n  - DOMAIN-SUFFIX,lan,DIRECT\n  - MATCH,DIRECT\n";
        let out = with_dpi(yaml, 10880, &["youtube.com".to_string(), "example.org".to_string()]).unwrap();
        let root: Mapping = serde_yaml::from_str(&out).unwrap();
        let rules: Vec<&str> = root.get("rules").and_then(Value::as_sequence).unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(rules.first(), Some(&"DOMAIN-SUFFIX,lan,DIRECT"));
        assert_eq!(rules.last(), Some(&"MATCH,DIRECT"));
        assert!(rules.contains(&"DOMAIN-SUFFIX,youtube.com,DPI") && rules.contains(&"DOMAIN-SUFFIX,example.org,DPI"));
        assert!(rules.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),DIRECT") && rules.contains(&"RULE-SET,kometfy-youtube,DPI"));
        assert!(root.get("rule-providers").and_then(Value::as_mapping).is_some_and(|m| m.contains_key("kometfy-discord")));
        assert!(out.contains("10880") && out.contains("socks5"));
    }

    #[test]
    fn ads_are_refused_below_the_users_rules() {
        let yaml = "proxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - MATCH,a\n";
        let mut s = Settings { adblock: true, ..Settings::default() };
        let user = vec![user("DOMAIN-SUFFIX", "ads.example", "DIRECT")];
        let b = build_with_rules(Some(yaml), None, &s, &[], &user, false).unwrap();
        let r = b.yaml.lines().filter(|l| l.trim_start().starts_with("- ")).map(|l| l.trim_start()[2..].trim().to_string()).collect::<Vec<_>>();
        let at = |x: &str| r.iter().position(|l| l == x).unwrap_or_else(|| panic!("{x} missing"));
        assert!(at("DOMAIN-SUFFIX,ads.example,DIRECT") < at(ADS_RULE));
        assert!(at(ADS_RULE) < at(LAN_RULES[0]));
        assert!(b.yaml.contains("kometfy-ads-all.mrs"), "the ad list is a rule set the core downloads");
        // the bigger list sits right below it
        let more = with_more_ads(&b.yaml).unwrap();
        let r: Vec<&str> = more.lines().map(str::trim).collect();
        let i = r.iter().position(|l| *l == format!("- {ADS_RULE}")).unwrap();
        assert_eq!(r[i + 1], format!("- RULE-SET,{ADS_MORE},REJECT"));
        assert!(more.contains("./ruleset/kometfy-ads-more.mrs"));
        s.adblock = false;
        let b = build_with_rules(Some(yaml), None, &s, &[], &user, false).unwrap();
        assert!(!b.yaml.contains(ADS_RULE));
    }

    #[test]
    fn games_ask_nulls_dns_and_go_direct_above_the_profiles_rules() {
        let yaml = "proxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - DOMAIN-SUFFIX,brawlstarsgame.com,a\n  - MATCH,a\n";
        let s = Settings { adblock: true, ..Settings::default() };
        let b = build_with_rules(Some(yaml), None, &s, &[], &[], false).unwrap();
        // no gaming DNS from the app: Roblox's pictures get their resolver, Supercell's names and rules are left alone
        let roblox: Mapping = serde_yaml::from_str(&with_games(&b.yaml, &[], &[]).unwrap()).unwrap();
        let policy = roblox.get("dns").and_then(|d| d.get("nameserver-policy")).and_then(Value::as_mapping).unwrap();
        assert_eq!(policy.get(ROBLOX_CDN).and_then(Value::as_sequence).and_then(|s| s[0].as_str()), Some(ROBLOX_DNS));
        assert!(policy.get("+.brawlstarsgame.com").is_none());
        assert!(!serde_yaml::to_string(&roblox).unwrap().contains("kometfy-games"));
        let out = with_games(&b.yaml, &["supercell.net".into(), "newgame.example".into()], &["https://dns.example/dns-query".into()]).unwrap();
        assert!(out.contains("+.newgame.example"));
        let root: Mapping = serde_yaml::from_str(&out).unwrap();
        let policy = root.get("dns").and_then(|d| d.get("nameserver-policy")).and_then(Value::as_mapping).unwrap();
        let servers = policy.get("+.brawlstarsgame.com").and_then(Value::as_sequence).unwrap();
        assert_eq!(servers[0].as_str(), Some("https://dns.example/dns-query"));
        let r: Vec<&str> = root.get("rules").and_then(Value::as_sequence).unwrap().iter().filter_map(Value::as_str).collect();
        let at = |x: &str| r.iter().position(|l| *l == x).unwrap_or_else(|| panic!("{x} missing"));
        // below ad blocking, above the LAN rules and the profile's own route for the game
        assert!(at(ADS_RULE) < at("RULE-SET,kometfy-games,DIRECT"));
        assert!(at("RULE-SET,kometfy-games,DIRECT") < at(LAN_RULES[0]));
        assert!(at(LAN_RULES[0]) < at("DOMAIN-SUFFIX,brawlstarsgame.com,a"));
    }

    #[test]
    fn ai_goes_through_the_proxy_above_the_quic_rule_and_the_catch_all() {
        let yaml = "rules:\n  - MATCH,DIRECT\n";
        assert_eq!(with_ai(yaml, &[], &[]).unwrap(), yaml, "no AI proxy from the app: nothing changes");
        let out = with_dpi(&with_ai(yaml, &[], &["proxy.example:8888".into(), "192.0.2.7:8080".into()]).unwrap(), 10880, &[]).unwrap();
        let r: Vec<&str> = out.lines().map(str::trim).filter(|l| l.starts_with("- ") && l.contains(',')).collect();
        let at = |x: &str| r.iter().position(|l| l.ends_with(x)).unwrap_or_else(|| panic!("{x} missing"));
        assert!(at("community.openai.com,DIRECT") < at("RULE-SET,kometfy-ai,Kometfy AI"));
        assert!(at("(RULE-SET,kometfy-ai)),REJECT") < at("RULE-SET,kometfy-ai,Kometfy AI"));
        assert!(at("RULE-SET,kometfy-ai,Kometfy AI") < at("(DST-PORT,443)),DIRECT"));
        assert_eq!(r.last().copied(), Some("- MATCH,DIRECT"));
        assert!(out.contains("+.chatgpt.com") && out.contains("proxy.example") && out.contains("Kometfy AI 2") && out.contains("8080"));
        // every name is a plain domain
        assert!(AI_SITES.iter().all(|d| crate::zapret::clean_domain(d).as_deref() == Some(*d)));
        // the closed services ride along, the names that stay off the shared proxy do not
        assert!(out.contains("+.notion.so") && out.contains("+.canva.com"));
        assert!(proxy_sites().count() > 100 && proxy_sites().all(|d| crate::zapret::clean_domain(d).as_deref() == Some(d)));
        for off in ["googleapis.com", "gstatic.com", "googleusercontent.com", "www.google.com", "windowsupdate.com", "githubusercontent.com"] {
            assert!(!proxy_sites().any(|d| d == off || d.ends_with(&format!(".{off}"))), "{off} stays off the proxy");
        }
        assert!(!out.contains("+.googleapis.com") && out.contains("+.generativelanguage.googleapis.com"));
    }

    #[test]
    fn macos_tun_binds_outbound_to_the_physical_default_interface() {
        let input = "tun: {enable: true, auto-detect-interface: true}\nproxies:\n  - {name: test, type: socks5, server: 192.0.2.4, port: 1080}\n";
        let output = bind_macos_tun_outbound(input, "en0").unwrap();
        let root = parse_root(Some(&output)).unwrap();
        assert_eq!(root.get("interface-name").and_then(Value::as_str), Some("en0"));
        assert_eq!(root.get("tun").and_then(Value::as_mapping).unwrap().get("auto-detect-interface").and_then(Value::as_bool), Some(false));
        assert!(bind_macos_tun_outbound(input, "utun6").is_err());
        let conflicting = "tun: {enable: true}\nproxies: [{name: test, interface-name: en1}]\n";
        assert!(bind_macos_tun_outbound(conflicting, "en0").is_err());
        let provider = "tun: {enable: true}\nproxy-providers: {test: {type: http, url: 'https://example.invalid/list'}}\n";
        assert!(bind_macos_tun_outbound(provider, "en0").is_err());
        let empty_provider = "tun: {enable: true}\nproxy-providers: {}\n";
        assert!(bind_macos_tun_outbound(empty_provider, "en0").is_ok());
    }

    #[test]
    fn preopened_tun_uses_external_routes_and_intercepts_dns() {
        let plan = crate::tun_macos_interface::TunInterfacePlan::experimental_ipv4();
        let input = "ipv6: true\ndns: {fake-ip-range: 198.18.0.1/18}\ntun:\n  enable: true\n  mtu: 9000\n  inet6-address: ['fd00::1/126']\n  auto-route: true\n  auto-detect-interface: true\n  strict-route: true\n  dns-hijack: ['any:53']\n";
        let result = configure_preopened_tun(input, 42, plan).unwrap();
        let root = parse_root(Some(&result)).unwrap();
        let tun = root.get("tun").unwrap().as_mapping().unwrap();
        assert_eq!(tun.get("file-descriptor").and_then(Value::as_i64), Some(42));
        assert_eq!(tun.get("mtu").and_then(Value::as_i64), Some(i64::from(plan.mtu())));
        assert!(tun.get("inet6-address").and_then(Value::as_sequence).unwrap().is_empty());
        assert_eq!(tun.get("dns-hijack").and_then(Value::as_sequence).unwrap().len(), 2);
        assert_eq!(root.get("dns").and_then(Value::as_mapping).unwrap().get("fake-ip-range").and_then(Value::as_str), Some("198.18.0.1/18"));
        for key in ["auto-route", "auto-redirect", "strict-route"] {
            assert_eq!(tun.get(key).and_then(Value::as_bool), Some(false));
        }
        assert_eq!(tun.get("auto-detect-interface").and_then(Value::as_bool), Some(true));
        assert_eq!(tun.get("dns-mode").and_then(Value::as_str), Some("disabled"));
        assert!(configure_preopened_tun(input, 2, plan).is_err());
        assert!(configure_preopened_tun("tun: {enable: false}", 42, plan).is_err());
        assert!(configure_preopened_tun("{}", 42, plan).is_err());
    }

    #[test]
    fn the_free_mode_hands_fake_addresses_only_to_what_the_core_works_on() {
        let free = "dns: {enable: true, enhanced-mode: fake-ip, fake-ip-range: 198.18.0.1/16, fake-ip-filter: ['*.lan']}\n\
            rule-providers:\n  kometfy-youtube: {type: http, behavior: domain, format: mrs, url: 'https://x', path: ./y.mrs}\n\
            rules:\n- PROCESS-NAME,bf6.exe,DIRECT\n- IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n- AND,((NETWORK,UDP),(DOMAIN-SUFFIX,googlevideo.com)),DPI\n\
            - AND,((NETWORK,UDP),(DST-PORT,443)),DIRECT\n- RULE-SET,kometfy-youtube,DPI\n- DOMAIN-SUFFIX,discord.com,DPI\n- DOMAIN,ads.example,REJECT\n- MATCH,DIRECT\n";
        let out = fake_ip_only_for_core(free).unwrap().expect("a free config splits");
        let root: Mapping = serde_yaml::from_str(&out).unwrap();
        let dns = root.get("dns").and_then(Value::as_mapping).unwrap();
        assert_eq!(dns.get("fake-ip-filter-mode").and_then(Value::as_str), Some("whitelist"));
        let names: Vec<&str> = dns.get("fake-ip-filter").and_then(Value::as_sequence).unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(names, ["+.googlevideo.com", "rule-set:kometfy-youtube", "+.discord.com", "ads.example"]);
        // something told apart by address, or a catch-all through a proxy, needs the whole traffic
        assert!(fake_ip_only_for_core(&free.replace("MATCH,DIRECT", "MATCH,PROXY")).unwrap().is_none());
        assert!(fake_ip_only_for_core(&free.replace("IP-CIDR,10.0.0.0/8,DIRECT", "IP-CIDR,10.0.0.0/8,DPI")).unwrap().is_none());
        assert!(fake_ip_only_for_core(&free.replace("AND,((NETWORK,UDP),(DST-PORT,443)),DIRECT", "AND,((NETWORK,UDP),(DST-PORT,443)),DPI")).unwrap().is_none());
    }

    #[test]
    fn android_tun_is_a_descriptor_without_routes() {
        let profile = "proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1}\nrules:\n  - MATCH,a\n";
        let built = build(Some(profile), None, &settings(), &[], true).unwrap();
        let yaml = configure_android_tun(&built.yaml, 77).unwrap();
        let root = parse_root(Some(&yaml)).unwrap();
        let tun = root.get("tun").unwrap().as_mapping().unwrap();
        assert_eq!(tun.get("file-descriptor").and_then(Value::as_i64), Some(77));
        assert_eq!(tun.get("enable").and_then(Value::as_bool), Some(true));
        assert!(tun.get("device").is_none());
        for key in ["auto-route", "auto-redirect", "auto-detect-interface", "strict-route"] {
            assert_eq!(tun.get(key).and_then(Value::as_bool), Some(false), "{key}");
        }
        assert_eq!(tun.get("dns-hijack").and_then(Value::as_sequence).unwrap().len(), 2);
        assert_eq!(root.get("find-process-mode").and_then(Value::as_str), Some("off"));
        assert!(root.get("dns").and_then(Value::as_mapping).unwrap().contains_key("fake-ip-range"));
        assert!(configure_android_tun(&built.yaml, 2).is_err());
        assert!(configure_android_tun("{}", 77).is_err());
    }

    #[test]
    fn preopened_tun_requires_compatible_fake_ip_host() {
        let plan = crate::tun_macos_interface::TunInterfacePlan::experimental_ipv4();
        for range in ["10.9.0.1/16", "198.18.0.1/33", "198.18.0.1", "garbage/16"] {
            let input = format!("dns: {{fake-ip-range: {range}}}\ntun: {{enable: true}}");
            assert!(configure_preopened_tun(&input, 42, plan).is_err(), "{range}");
        }
        let result = configure_preopened_tun("tun: {enable: true}", 42, plan).unwrap();
        let root = parse_root(Some(&result)).unwrap();
        let dns = root.get("dns").unwrap().as_mapping().unwrap();
        assert_eq!(dns.get("fake-ip-range").and_then(Value::as_str), Some("198.18.0.1/16"));
        for explicit in ["[10.0.0.1/30]", "[198.18.0.1/30]", "[]"] {
            let input = format!("tun: {{enable: true, inet4-address: {explicit}}}");
            assert!(configure_preopened_tun(&input, 42, plan).is_err(), "{explicit}");
        }
    }

    const PROFILE: &str = r#"
proxies:
  - {name: A, type: socks5, server: 1.1.1.1, port: 1}
  - {name: B, type: socks5, server: 2.2.2.2, port: 2}
proxy-groups:
  - {name: PROXY, type: select, proxies: [A, B, DIRECT]}
rules:
  - DOMAIN-SUFFIX,example.com,PROXY
  - MATCH,PROXY
port: 1234
external-controller: 0.0.0.0:9090
tun: {enable: true, device: Evil}
"#;

    fn settings() -> Settings {
        Settings {
            secret: "sek".into(),
            ..Default::default()
        }
    }

    fn parse(b: &Built) -> Mapping {
        serde_yaml::from_str(&b.yaml).unwrap()
    }

    #[test]
    fn owned_keys_overridden() {
        let b = build(Some(PROFILE), None, &settings(), &[], false).unwrap();
        let m = parse(&b);
        assert!(m.get("port").is_none());
        assert_eq!(str_of(&m, "external-controller"), Some("127.0.0.1:19097"));
        assert_eq!(m.get("mixed-port").and_then(Value::as_u64), Some(17897));
        let tun = m.get("tun").and_then(Value::as_mapping).unwrap();
        assert_eq!(str_of(tun, "device"), Some(settings().tun.device.as_str()));
        assert_eq!(tun.get("enable").and_then(Value::as_bool), Some(false));
    }

    #[test]
    fn tun_state_baked_in_and_dns_forced_on() {
        let b = build(Some(PROFILE), None, &settings(), &[], true).unwrap();
        let m = parse(&b);
        let tun = m.get("tun").and_then(Value::as_mapping).unwrap();
        assert_eq!(tun.get("enable").and_then(Value::as_bool), Some(true));
        let dns = m.get("dns").and_then(Value::as_mapping).unwrap();
        assert_eq!(dns.get("enable").and_then(Value::as_bool), Some(true));
        assert_eq!(str_of(dns, "enhanced-mode"), Some("fake-ip"));
    }

    #[test]
    fn bypass_and_lan_rules_come_first() {
        let mut s = settings();
        s.bypass.processes = vec!["steam.exe".into(), "bad,rule".into()];
        s.bypass.domains = vec!["steamcontent.com".into()];
        let b = build(Some(PROFILE), None, &s, &[], false).unwrap();
        let m = parse(&b);
        let rules = m.get("rules").and_then(Value::as_sequence).unwrap();
        assert_eq!(rules[0].as_str(), Some("PROCESS-NAME,steam.exe,DIRECT"));
        assert_eq!(rules[1].as_str(), Some("DOMAIN-SUFFIX,steamcontent.com,DIRECT"));
        assert!(rules.iter().any(|r| r.as_str() == Some("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")));
        assert_eq!(rules.last().and_then(Value::as_str), Some("MATCH,PROXY"));
        assert!(!rules.iter().any(|r| r.as_str().is_some_and(|x| x.contains("bad,rule"))));
    }

    #[test]
    fn chains_are_injected_and_main_group_detected() {
        let c = Chain {
            id: "c".into(),
            name: "Duo".into(),
            hops: vec!["A".into(), "B".into()],
            profile: None,
        };
        let b = build(Some(PROFILE), None, &settings(), &[c], false).unwrap();
        assert_eq!(b.info.main_groups, vec!["PROXY".to_string()]);
        assert_eq!(b.info.chain_exits, vec!["⛓ Duo".to_string()]);
        let m = parse(&b);
        let names = names_of(&m, "proxies");
        assert!(names.contains(&"⛓ Duo".to_string()));
    }

    fn user(kind: &str, value: &str, target: &str) -> UserRule {
        UserRule {
            id: format!("r-{value}"),
            enabled: true,
            kind: kind.into(),
            value: value.into(),
            target: target.into(),
            ..Default::default()
        }
    }

    #[test]
    fn user_rules_sit_between_bypass_and_lan() {
        let mut s = settings();
        s.bypass.processes = vec!["steam.exe".into()];
        let rules = vec![
            user("DOMAIN-SUFFIX", "claude.ai", "@proxy"),
            user("PROCESS-NAME", "game.exe", "DIRECT"),
            user("DOMAIN-SUFFIX", "ads.example", "REJECT"),
        ];
        let b = build_with_rules(Some(PROFILE), None, &s, &[], &rules, false).unwrap();
        let m = parse(&b);
        let r: Vec<&str> = m
            .get("rules")
            .and_then(Value::as_sequence)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(r[0], "PROCESS-NAME,steam.exe,DIRECT");
        assert_eq!(r[1], "DOMAIN-SUFFIX,claude.ai,PROXY"); // @proxy -> the profile's main selector
        assert_eq!(r[2], "PROCESS-NAME,game.exe,DIRECT");
        assert_eq!(r[3], "DOMAIN-SUFFIX,ads.example,REJECT");
        // the games under the user's rules, then the LAN
        assert_eq!(r[4], "PROCESS-NAME,bf6.exe,DIRECT");
        let lan = 4 + GAME_PROCESSES.len();
        assert!(r[lan].starts_with("IP-CIDR,127.0.0.0/8"));
        assert_eq!(b.info.injected_rules, lan + LAN_RULES.len());
        assert_eq!(r[b.info.injected_rules], "DOMAIN-SUFFIX,example.com,PROXY");
        assert!(b.info.rule_issues.is_empty());
    }

    #[test]
    fn unresolvable_and_disabled_user_rules_are_left_out() {
        let mut off = user("DOMAIN", "off.com", "DIRECT");
        off.enabled = false;
        let rules = vec![
            user("DOMAIN", "a.com", "No Such Group"),
            user("DOMAIN", "b.com", "@chain:missing"),
            user("RULE-SET", "nothing", "DIRECT"),
            off,
            user("DOMAIN", "ok.com", "B"),
        ];
        let b = build_with_rules(Some(PROFILE), None, &settings(), &[], &rules, false).unwrap();
        let ids: Vec<&str> = b.info.rule_issues.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["r-a.com", "r-b.com", "r-nothing"]);
        let text = parse(&b)
            .get("rules")
            .and_then(Value::as_sequence)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("DOMAIN,ok.com,B"));
        assert!(!text.contains("a.com") && !text.contains("off.com"));
    }

    #[test]
    fn chain_targets_resolve_to_the_exit_clone() {
        let c = Chain {
            id: "c1".into(),
            name: "Duo".into(),
            hops: vec!["A".into(), "B".into()],
            profile: None,
        };
        let rules = vec![user("DOMAIN-SUFFIX", "claude.ai", "@chain:c1")];
        let b = build_with_rules(Some(PROFILE), None, &settings(), &[c], &rules, false).unwrap();
        let m = parse(&b);
        let first_custom = m.get("rules").and_then(Value::as_sequence).unwrap()[0].as_str().unwrap().to_string();
        assert_eq!(first_custom, "DOMAIN-SUFFIX,claude.ai,⛓ Duo");
        assert!(b.info.rule_issues.is_empty());
    }

    const XRAY_PROFILE: &str = "proxies:
  - {name: V, type: vless, server: v.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, servername: v.example.com}
  - {name: A, type: socks5, server: 2.2.2.2, port: 2}
proxy-groups:
  - {name: PROXY, type: select, proxies: [V, A, DIRECT]}
rules:
  - MATCH,PROXY
";

    fn xray_run() -> XrayRun {
        XrayRun {
            mode: crate::settings::XrayMode::All,
            dpi: None,
            core: None,
            port: 41000,
            secret: "pw".into(),
            log_level: "info".into(),
            exe_name: "xray.exe".into(),
            refused: Default::default(),
        }
    }

    #[test]
    fn xray_takes_servers_and_its_own_traffic_stays_direct() {
        let b = build_all(Some(XRAY_PROFILE), None, &settings(), &[], &[], false, Some(&xray_run())).unwrap();
        let x = b.xray.as_ref().expect("one server goes to Xray");
        assert_eq!(x.nodes, 1);
        assert!(x.json.contains("\"vless\""));
        let m = parse(&b);
        let rules: Vec<&str> = m.get("rules").and_then(Value::as_sequence).unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(rules[0], "PROCESS-NAME,xray.exe,DIRECT", "else TUN would feed Xray's traffic back into itself");
        assert_eq!(b.info.injected_rules, 1 + GAME_PROCESSES.len() + LAN_RULES.len());
        assert_eq!(b.info.xray_kinds["V"], "vless");
        let proxies = m.get("proxies").and_then(Value::as_sequence).unwrap();
        let v = proxies[0].as_mapping().unwrap();
        assert_eq!((str_of(v, "name"), str_of(v, "type")), (Some("V"), Some("socks5")));
        assert_eq!(v.get("port").and_then(Value::as_u64), Some(41000));
        assert_eq!(str_of(proxies[1].as_mapping().unwrap(), "server"), Some("2.2.2.2"));
        // without the helper nothing changes
        let plain = build_all(Some(XRAY_PROFILE), None, &settings(), &[], &[], false, None).unwrap();
        assert!(plain.xray.is_none());
        assert_eq!(plain.info.injected_rules, GAME_PROCESSES.len() + LAN_RULES.len());
    }

    #[test]
    fn a_chain_still_leads_through_a_server_that_xray_runs() {
        let c = Chain {
            id: "c".into(),
            name: "Duo".into(),
            hops: vec!["V".into(), "A".into()],
            profile: None,
        };
        let b = build_all(Some(XRAY_PROFILE), None, &settings(), &[c], &[], false, Some(&xray_run())).unwrap();
        assert_eq!(b.xray.as_ref().map(|x| x.nodes), Some(1));
        let m = parse(&b);
        let exit = m
            .get("proxies")
            .and_then(Value::as_sequence)
            .unwrap()
            .iter()
            .filter_map(Value::as_mapping)
            .find(|p| str_of(p, "name") == Some("⛓ Duo"))
            .unwrap();
        assert_eq!(str_of(exit, "dialer-proxy"), Some("V"), "mihomo reaches A through the Xray-backed V");
        assert_eq!(str_of(exit, "server"), Some("2.2.2.2"));
    }

    #[test]
    fn empty_profile_is_direct_only() {
        let b = build(None, None, &settings(), &[], false).unwrap();
        let m = parse(&b);
        let rules = m.get("rules").and_then(Value::as_sequence).unwrap();
        assert_eq!(rules.last().and_then(Value::as_str), Some("MATCH,DIRECT"));
    }

    #[test]
    fn bare_proxies_get_default_groups() {
        let y = "proxies:\n  - {name: A, type: socks5, server: 1.1.1.1, port: 1}\n";
        let b = build(Some(y), None, &settings(), &[], false).unwrap();
        let m = parse(&b);
        assert_eq!(names_of(&m, "proxy-groups"), vec!["PROXY".to_string()]);
        let rules = m.get("rules").and_then(Value::as_sequence).unwrap();
        assert_eq!(rules.last().and_then(Value::as_str), Some("MATCH,PROXY"));
    }

    #[test]
    fn empty_proxy_providers_still_generates_default_groups() {
        let y = "proxies:\n  - {name: A, type: socks5, server: 1.1.1.1, port: 1}\nproxy-providers: {}\n";
        let b = build(Some(y), None, &settings(), &[], false).unwrap();
        let m = parse(&b);
        assert_eq!(names_of(&m, "proxy-groups"), vec!["PROXY".to_string()]);
    }

    #[test]
    fn nodes_listed() {
        let nodes = list_nodes(PROFILE);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].server, "2.2.2.2");
    }
}
