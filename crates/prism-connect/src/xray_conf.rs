//! Clash proxies -> Xray outbounds, plus the shim that lets mihomo use them.
//!
//! A server that Xray runs is replaced, in the config handed to mihomo, by a SOCKS5 node with the
//! same name that points to the private Xray listener. The user name selects the outbound inside
//! Xray (`user` routing), so one port serves every server. Names, groups, rules and chains in
//! mihomo are untouched. Servers that carry a `dialer-proxy` (chain hops after the first) and
//! everything Xray cannot run stay with mihomo.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value as J};
use serde_yaml::{Mapping, Value};

use crate::{
    dpi::Dpi,
    settings::XrayMode,
    util::{put, str_of},
    xray::{self, FINALMASK_FRAGMENT},
};

/// Name of the freedom outbound that fragments for cores without the `fragment` mask.
const DPI_HOP: &str = "dpi";
const BLOCK: &str = "block";
const INBOUND: &str = "shim";
pub const SHIM_HOST: &str = "127.0.0.1";

/// What the config needs to know about the Xray that will run it.
#[derive(Debug, Clone)]
pub struct XrayRun {
    /// `Auto` or `All` (`Off` never gets this far).
    pub mode: XrayMode,
    /// DPI bypass in force (user's or the subscription's), if any.
    pub dpi: Option<Dpi>,
    /// Version of the installed core. None: unknown, assume a current one.
    pub core: Option<[u32; 3]>,
    /// Private loopback port and password of the SOCKS listener.
    pub port: u16,
    pub secret: String,
    /// mihomo style: debug / info / warning / error / silent.
    pub log_level: String,
    /// File name of the Xray program, e.g. `xray.exe`.
    pub exe_name: String,
    /// Servers the core itself turned down earlier, name -> its reason. They stay with mihomo.
    pub refused: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// The Xray config file.
    pub json: String,
    /// Outbound tag in the config -> server name, to find out which server the core objected to.
    pub tags: BTreeMap<String, String>,
    /// Servers that Xray runs now.
    pub nodes: usize,
    /// Of those, the ones whose TLS handshake is cut up.
    pub dpi_nodes: usize,
    /// Server name -> its protocol in the profile (`vless`, `vmess`, `trojan`, `ss`).
    pub kinds: BTreeMap<String, String>,
    /// Servers Xray was supposed to run but cannot, with the reason.
    pub skipped: Vec<(String, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sec {
    None,
    Tls,
    Reality,
}

/// How a TLS server gets its handshake cut.
enum Cut<'a> {
    No,
    /// `streamSettings.finalmask.tcp` (core 26.3.23 and later)
    Mask(&'a Dpi),
    /// a `freedom` outbound in front of the server (older cores)
    Hop(&'a Dpi),
}

// ---------------------------------------------------------------- reading a Clash mapping

fn text(m: &Mapping, key: &str) -> Option<String> {
    match m.get(key)? {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn flag(m: &Mapping, key: &str) -> Option<bool> {
    match m.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => Some(matches!(s.trim().to_lowercase().as_str(), "true" | "1" | "yes")),
        Value::Number(n) => Some(n.as_u64() == Some(1)),
        _ => None,
    }
}

fn sub<'a>(m: &'a Mapping, key: &str) -> Option<&'a Mapping> {
    m.get(key)?.as_mapping()
}

fn list(m: &Mapping, key: &str) -> Vec<String> {
    let clean = |s: &str| s.trim().to_string();
    match m.get(key) {
        Some(Value::Sequence(s)) => s.iter().filter_map(Value::as_str).map(clean).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(clean).filter(|s| !s.is_empty()).collect(),
        _ => vec![],
    }
}

/// `headers:` of a transport; a value may be a string or a list.
fn headers(o: &Mapping) -> BTreeMap<String, String> {
    let Some(h) = sub(o, "headers") else { return BTreeMap::new() };
    h.iter()
        .filter_map(|(k, v)| {
            let value = match v {
                Value::String(s) => s.clone(),
                Value::Sequence(s) => s.first()?.as_str()?.to_string(),
                _ => return None,
            };
            Some((k.as_str()?.to_string(), value))
        })
        .collect()
}

/// `Host` is its own setting in Xray; the other headers stay a map.
fn split_host(mut h: BTreeMap<String, String>) -> (Option<String>, BTreeMap<String, String>) {
    let key = h.keys().find(|k| k.eq_ignore_ascii_case("host")).cloned();
    (key.and_then(|k| h.remove(&k)), h)
}

/// Xray lets VLESS go out without TLS or encryption only to this PC or a private network
/// (a domain does not qualify, however innocent it looks).
fn is_local_target(address: &str) -> bool {
    use std::net::IpAddr;
    let a = address.trim().trim_matches(['[', ']']);
    if a.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match a.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_private() || a.is_loopback() || a.is_link_local(),
        Ok(IpAddr::V6(a)) => {
            let seg = a.segments()[0];
            a.is_loopback() || seg & 0xfe00 == 0xfc00 || seg & 0xffc0 == 0xfe80
        }
        Err(_) => false,
    }
}

fn security(m: &Mapping, ty: &str) -> Sec {
    if m.contains_key("reality-opts") {
        Sec::Reality
    } else if ty == "trojan" || flag(m, "tls") == Some(true) {
        Sec::Tls
    } else {
        Sec::None
    }
}

// ---------------------------------------------------------------- one server

fn stream(m: &Mapping, sec: Sec, cut: &Cut) -> Result<J, String> {
    let mut s = Map::new();
    let net = text(m, "network").unwrap_or_else(|| "tcp".into()).to_lowercase();
    match net.as_str() {
        "tcp" => {
            s.insert("network".into(), "tcp".into());
        }
        "ws" => {
            let o = sub(m, "ws-opts");
            let path = o.and_then(|o| text(o, "path")).unwrap_or_else(|| "/".into());
            let (host, hdrs) = split_host(o.map(headers).unwrap_or_default());
            let mut set = Map::new();
            let upgrade = o.and_then(|o| flag(o, "v2ray-http-upgrade")) == Some(true);
            let mut path = path;
            let early = o.and_then(|o| o.get("max-early-data")).and_then(Value::as_u64).unwrap_or(0);
            if !upgrade && early > 0 && !path.contains("ed=") {
                path.push(if path.contains('?') { '&' } else { '?' });
                path.push_str(&format!("ed={early}"));
            }
            set.insert("path".into(), path.into());
            if let Some(h) = host {
                set.insert("host".into(), h.into());
            }
            if !hdrs.is_empty() {
                set.insert("headers".into(), json!(hdrs));
            }
            let (name, key) = if upgrade { ("httpupgrade", "httpupgradeSettings") } else { ("ws", "wsSettings") };
            s.insert("network".into(), name.into());
            s.insert(key.into(), J::Object(set));
        }
        "grpc" => {
            let name = sub(m, "grpc-opts").and_then(|o| text(o, "grpc-service-name")).unwrap_or_default();
            s.insert("network".into(), "grpc".into());
            s.insert("grpcSettings".into(), json!({ "serviceName": name }));
        }
        "xhttp" => {
            let o = sub(m, "xhttp-opts");
            let mut x = Map::new();
            x.insert("path".into(), o.and_then(|o| text(o, "path")).unwrap_or_else(|| "/".into()).into());
            for key in ["host", "mode"] {
                if let Some(v) = o.and_then(|o| text(o, key)) {
                    x.insert(key.into(), v.into());
                }
            }
            s.insert("network".into(), "xhttp".into());
            s.insert("xhttpSettings".into(), J::Object(x));
        }
        other => return Err(format!("transport “{other}” is not supported by Xray")),
    }

    let sni = text(m, "servername").or_else(|| text(m, "sni"));
    let utls = text(m, "client-fingerprint");
    match sec {
        Sec::None => {
            s.insert("security".into(), "none".into());
        }
        Sec::Tls => {
            let mut t = Map::new();
            if let Some(n) = sni {
                t.insert("serverName".into(), n.into());
            }
            let alpn = list(m, "alpn");
            if !alpn.is_empty() {
                t.insert("alpn".into(), json!(alpn));
            }
            if let Some(f) = utls {
                t.insert("fingerprint".into(), f.into());
            }
            // Xray dropped "allowInsecure": the certificate is either checked or pinned. A pinned
            // server is trusted by its hash, which is what `fingerprint:` means in a Clash profile.
            match text(m, "fingerprint") {
                Some(pin) => {
                    t.insert("pinnedPeerCertSha256".into(), pin.into());
                }
                None if flag(m, "skip-cert-verify") == Some(true) => {
                    return Err("Xray no longer accepts a server whose certificate is not checked".into());
                }
                None => {}
            }
            s.insert("security".into(), "tls".into());
            s.insert("tlsSettings".into(), J::Object(t));
        }
        Sec::Reality => {
            let r = sub(m, "reality-opts").ok_or("no reality options")?;
            let key = text(r, "public-key").ok_or("Reality server without a public key")?;
            s.insert("security".into(), "reality".into());
            s.insert(
                "realitySettings".into(),
                json!({
                    "serverName": sni.unwrap_or_default(),
                    "fingerprint": utls.unwrap_or_else(|| "chrome".into()),
                    "publicKey": key,
                    "shortId": text(r, "short-id").unwrap_or_default(),
                    "spiderX": text(r, "spider-x").unwrap_or_default(),
                }),
            );
        }
    }

    if sec != Sec::None {
        match cut {
            Cut::No => {}
            Cut::Mask(d) => {
                let mut f = Map::new();
                f.insert("packets".into(), d.packets.clone().into());
                f.insert("length".into(), d.length.clone().into());
                f.insert("delay".into(), d.interval.clone().into());
                if !d.max_split.is_empty() {
                    f.insert("maxSplit".into(), d.max_split.clone().into());
                }
                s.insert("finalmask".into(), json!({ "tcp": [{ "type": "fragment", "settings": f }] }));
            }
            Cut::Hop(_) => {
                s.insert("sockopt".into(), json!({ "dialerProxy": DPI_HOP }));
            }
        }
    }
    Ok(J::Object(s))
}

/// Ciphers the Xray shadowsocks outbound knows (the old stream ciphers are gone from it).
const SS_CIPHERS: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "chacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
];

/// The Xray outbound for one Clash server, or why it cannot be one.
fn outbound(m: &Mapping, ty: &str, sec: Sec, cut: &Cut) -> Result<J, String> {
    if sub(m, "smux").and_then(|s| flag(s, "enabled")) == Some(true) {
        return Err("sing-mux is not supported by Xray".into());
    }
    if m.contains_key("ech-opts") {
        return Err("ECH is not supported here".into());
    }
    let address = text(m, "server").ok_or("no server address")?;
    let port: u16 = text(m, "port").and_then(|p| p.parse().ok()).ok_or("bad port")?;

    let (protocol, settings) = match ty {
        "vless" => {
            let id = text(m, "uuid").ok_or("no uuid")?;
            let encryption = text(m, "encryption").unwrap_or_else(|| "none".into());
            if sec == Sec::None && encryption == "none" && !is_local_target(&address) {
                return Err("Xray runs VLESS without TLS or encryption only for this PC or a private network".into());
            }
            let mut user = json!({ "id": id, "encryption": encryption });
            if let Some(flow) = text(m, "flow") {
                user["flow"] = flow.into();
            }
            ("vless", json!({ "vnext": [{ "address": address, "port": port, "users": [user] }] }))
        }
        "vmess" => {
            if text(m, "alterId").or_else(|| text(m, "alter-id")).and_then(|a| a.parse::<u32>().ok()).unwrap_or(0) > 0 {
                return Err("legacy VMess (alterId) is not supported by Xray".into());
            }
            let id = text(m, "uuid").ok_or("no uuid")?;
            let user = json!({ "id": id, "security": text(m, "cipher").unwrap_or_else(|| "auto".into()) });
            ("vmess", json!({ "vnext": [{ "address": address, "port": port, "users": [user] }] }))
        }
        "trojan" => {
            let password = text(m, "password").ok_or("no password")?;
            ("trojan", json!({ "servers": [{ "address": address, "port": port, "password": password }] }))
        }
        "ss" => {
            if m.contains_key("plugin") {
                return Err("Shadowsocks plugins are not supported by Xray".into());
            }
            if flag(m, "udp-over-tcp") == Some(true) {
                return Err("UDP over TCP is not supported by Xray".into());
            }
            let method = text(m, "cipher").ok_or("no cipher")?;
            if !SS_CIPHERS.contains(&method.as_str()) {
                return Err(format!("cipher “{method}” is not supported by Xray"));
            }
            let password = text(m, "password").unwrap_or_default();
            let server = json!({ "address": address, "port": port, "method": method, "password": password });
            ("shadowsocks", json!({ "servers": [server] }))
        }
        other => return Err(format!("“{other}” is not run by Xray")),
    };
    let mut ob = json!({ "protocol": protocol, "settings": settings });
    if protocol != "shadowsocks" {
        ob["streamSettings"] = stream(m, sec, cut)?;
    }
    Ok(ob)
}

/// The node mihomo gets in place of the real one.
fn shim(name: &str, user: &str, run: &XrayRun, udp: bool) -> Mapping {
    let mut s = Mapping::new();
    put(&mut s, "name", name);
    put(&mut s, "type", "socks5");
    put(&mut s, "server", SHIM_HOST);
    put(&mut s, "port", run.port);
    put(&mut s, "username", user);
    put(&mut s, "password", run.secret.as_str());
    put(&mut s, "udp", udp);
    s
}

fn xray_log_level(mihomo: &str) -> &'static str {
    match mihomo {
        "debug" => "debug",
        "warning" => "warning",
        "error" => "error",
        "silent" => "none",
        _ => "info",
    }
}

/// Hand servers over to Xray. Rewrites `root["proxies"]` in place and returns the Xray config.
/// Which servers go depends on `run.mode`: `All` takes every server Xray can run; `Auto` takes
/// the ones that start a TLS handshake, and only while DPI bypass is on.
pub fn plan(root: &mut Mapping, run: &XrayRun) -> Plan {
    let mut plan = Plan::default();
    let Some(Value::Sequence(proxies)) = root.get_mut("proxies") else { return plan };

    let cut = match &run.dpi {
        None => Cut::No,
        Some(d) if run.core.is_some_and(|v| v < FINALMASK_FRAGMENT) => Cut::Hop(d),
        Some(d) => Cut::Mask(d),
    };
    let mut outbounds: Vec<J> = Vec::new();
    let mut accounts: Vec<J> = Vec::new();
    let mut rules: Vec<J> = Vec::new();

    for (i, p) in proxies.iter_mut().enumerate() {
        let Value::Mapping(m) = p else { continue };
        let Some(name) = str_of(m, "name").map(String::from) else { continue };
        let ty = str_of(m, "type").unwrap_or("").to_lowercase();
        if m.contains_key("dialer-proxy") || !matches!(ty.as_str(), "vless" | "vmess" | "trojan" | "ss") {
            continue;
        }
        let sec = security(m, &ty);
        let wanted = run.mode == XrayMode::All || (run.dpi.is_some() && sec != Sec::None);
        if !wanted {
            continue;
        }
        if let Some(why) = run.refused.get(&name) {
            plan.skipped.push((name, why.clone()));
            continue;
        }
        let ob = match outbound(m, &ty, sec, &cut) {
            Ok(ob) => ob,
            Err(why) => {
                plan.skipped.push((name, why));
                continue;
            }
        };
        let (tag, user) = (format!("o{i}"), format!("u{i}"));
        let mut ob = ob;
        ob["tag"] = tag.clone().into();
        outbounds.push(ob);
        accounts.push(json!({ "user": user, "pass": run.secret }));
        rules.push(json!({ "type": "field", "inboundTag": [INBOUND], "user": [user], "outboundTag": tag }));
        if sec != Sec::None && !matches!(cut, Cut::No) {
            plan.dpi_nodes += 1;
        }
        let udp = flag(m, "udp") != Some(false);
        plan.tags.insert(tag, name.clone());
        plan.kinds.insert(name.clone(), ty);
        *m = shim(&name, &user, run, udp);
        plan.nodes += 1;
    }
    if plan.nodes == 0 {
        return plan;
    }

    if let Cut::Hop(d) = &cut {
        let mut f = Map::new();
        f.insert("packets".into(), d.packets.clone().into());
        f.insert("length".into(), d.length.clone().into());
        f.insert("interval".into(), d.interval.clone().into());
        if !d.max_split.is_empty() {
            f.insert("maxSplit".into(), d.max_split.clone().into());
        }
        outbounds.push(json!({ "tag": DPI_HOP, "protocol": "freedom", "settings": { "fragment": f } }));
    }
    outbounds.push(json!({ "tag": BLOCK, "protocol": "blackhole" }));
    // nothing but the servers above may leave through this listener
    rules.push(json!({ "type": "field", "inboundTag": [INBOUND], "outboundTag": BLOCK }));

    let config = json!({
        "log": { "access": "none", "loglevel": xray_log_level(&run.log_level) },
        "inbounds": [{
            "tag": INBOUND,
            "listen": SHIM_HOST,
            "port": run.port,
            "protocol": "socks",
            "settings": { "auth": "password", "accounts": accounts, "udp": true, "ip": SHIM_HOST },
        }],
        "outbounds": outbounds,
        "routing": { "domainStrategy": "AsIs", "rules": rules },
    });
    plan.json = serde_json::to_string_pretty(&config).unwrap_or_default();
    plan
}

/// Is this core new enough for the `fragment` mask? (Shown in the UI as a hint.)
pub fn core_has_fragment_mask(version: Option<&str>) -> bool {
    version.and_then(xray::version_tuple).is_none_or(|v| v >= FINALMASK_FRAGMENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(mode: XrayMode, dpi: Option<Dpi>) -> XrayRun {
        XrayRun {
            mode,
            dpi,
            core: Some([26, 10, 31]),
            port: 40000,
            secret: "s3cret".into(),
            log_level: "warning".into(),
            exe_name: "xray.exe".into(),
            refused: BTreeMap::new(),
        }
    }

    fn root(y: &str) -> Mapping {
        serde_yaml::from_str(y).unwrap()
    }

    fn cfg(p: &Plan) -> J {
        serde_json::from_str(&p.json).unwrap()
    }

    const PROFILE: &str = r#"
proxies:
  - {name: R, type: vless, server: r.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, flow: xtls-rprx-vision, tls: true, servername: www.microsoft.com, client-fingerprint: chrome, network: tcp, reality-opts: {public-key: PUB, short-id: ab12}, udp: true}
  - {name: W, type: vmess, server: w.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: auto, tls: true, servername: cdn.example.com, network: ws, ws-opts: {path: /ws, headers: {Host: cdn.example.com, X-A: b}, max-early-data: 2048}, alpn: [h2, http/1.1], skip-cert-verify: true, fingerprint: 438a24fc9cd26eba3079e0baaea8784de564f41eb2f861af81134c268ee2d249}
  - {name: T, type: trojan, server: t.example.com, port: 443, password: pw, sni: t.example.com, network: grpc, grpc-opts: {grpc-service-name: svc}}
  - {name: S, type: ss, server: s.example.com, port: 8388, cipher: aes-256-gcm, password: pw}
  - {name: P, type: vless, server: 192.168.50.7, port: 80, uuid: 11111111-2222-3333-4444-555555555555, network: tcp}
  - {name: H2, type: vless, server: h.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, network: h2, h2-opts: {path: /}}
  - {name: Old, type: vmess, server: o.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, alterId: 4, cipher: auto}
  - {name: Obfs, type: ss, server: b.example.com, port: 8388, cipher: aes-128-gcm, password: pw, plugin: obfs}
  - {name: Ins, type: vless, server: i.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, servername: i.example.com, skip-cert-verify: true}
  - {name: Hy, type: hysteria2, server: y.example.com, port: 443, password: pw}
  - {name: Hop2, type: vless, server: r.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, dialer-proxy: R}
  - {name: Plain, type: socks5, server: 1.1.1.1, port: 1080}
"#;

    fn names(root: &Mapping) -> Vec<(String, String)> {
        root.get("proxies")
            .and_then(Value::as_sequence)
            .unwrap()
            .iter()
            .map(|p| {
                let m = p.as_mapping().unwrap();
                (str_of(m, "name").unwrap().to_string(), str_of(m, "type").unwrap().to_string())
            })
            .collect()
    }

    #[test]
    fn auto_without_dpi_touches_nothing() {
        let mut r = root(PROFILE);
        let before = r.clone();
        let p = plan(&mut r, &run(XrayMode::Auto, None));
        assert_eq!(p.nodes, 0);
        assert!(p.json.is_empty());
        assert_eq!(r, before);
    }

    #[test]
    fn all_takes_every_server_xray_can_run() {
        let mut r = root(PROFILE);
        let p = plan(&mut r, &run(XrayMode::All, None));
        // R, W, T, S, P: five; H2, Old, Obfs and Ins are refused, Hy / Hop2 / Plain are not Xray's
        assert_eq!(p.nodes, 5, "{:?}", p.skipped);
        let skipped: Vec<&str> = p.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(skipped, vec!["H2", "Old", "Obfs", "Ins"]);
        let n = names(&r);
        let ty = |name: &str| n.iter().find(|(a, _)| a == name).unwrap().1.clone();
        for shimmed in ["R", "W", "T", "S", "P"] {
            assert_eq!(ty(shimmed), "socks5", "{shimmed}");
        }
        assert_eq!(ty("H2"), "vless");
        assert_eq!(ty("Hy"), "hysteria2");
        assert_eq!(ty("Hop2"), "vless", "a chain hop keeps its dialer-proxy and stays with mihomo");
        assert_eq!(p.kinds["R"], "vless");
        assert_eq!(p.kinds["S"], "ss");
        assert_eq!(p.dpi_nodes, 0);

        let c = cfg(&p);
        assert_eq!(c["inbounds"][0]["port"], 40000);
        assert_eq!(c["inbounds"][0]["settings"]["accounts"].as_array().unwrap().len(), 5);
        assert_eq!(c["log"]["loglevel"], "warning");
        let rules = c["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 6);
        assert_eq!(rules[0]["user"][0], "u0");
        assert_eq!(rules[0]["outboundTag"], "o0");
        assert_eq!(rules[5]["outboundTag"], "block", "unknown users are blocked");
    }

    #[test]
    fn the_shim_node_points_at_the_private_listener() {
        let mut r = root(PROFILE);
        plan(&mut r, &run(XrayMode::All, None));
        let m = r.get("proxies").and_then(Value::as_sequence).unwrap()[0].as_mapping().unwrap().clone();
        assert_eq!(str_of(&m, "server"), Some("127.0.0.1"));
        assert_eq!(m.get("port").and_then(Value::as_u64), Some(40000));
        assert_eq!(str_of(&m, "username"), Some("u0"));
        assert_eq!(str_of(&m, "password"), Some("s3cret"));
        assert_eq!(m.get("uuid"), None, "no secret of the real server stays in the mihomo config");
        assert_eq!(m.get("udp").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn vless_reality_vision() {
        let mut r = root(PROFILE);
        let c = cfg(&plan(&mut r, &run(XrayMode::All, None)));
        let o = &c["outbounds"][0];
        assert_eq!(o["protocol"], "vless");
        assert_eq!(o["tag"], "o0");
        let u = &o["settings"]["vnext"][0];
        assert_eq!((u["address"].as_str(), u["port"].as_u64()), (Some("r.example.com"), Some(443)));
        assert_eq!(u["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(u["users"][0]["encryption"], "none");
        let s = &o["streamSettings"];
        assert_eq!(s["security"], "reality");
        assert_eq!(s["realitySettings"]["publicKey"], "PUB");
        assert_eq!(s["realitySettings"]["shortId"], "ab12");
        assert_eq!(s["realitySettings"]["serverName"], "www.microsoft.com");
        assert_eq!(s["realitySettings"]["fingerprint"], "chrome");
    }

    #[test]
    fn vmess_ws_tls() {
        let mut r = root(PROFILE);
        let c = cfg(&plan(&mut r, &run(XrayMode::All, None)));
        let o = &c["outbounds"][1];
        assert_eq!(o["protocol"], "vmess");
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["security"], "auto");
        let s = &o["streamSettings"];
        assert_eq!(s["network"], "ws");
        assert_eq!(s["wsSettings"]["path"], "/ws?ed=2048");
        assert_eq!(s["wsSettings"]["host"], "cdn.example.com");
        assert_eq!(s["wsSettings"]["headers"]["X-A"], "b");
        assert!(s["wsSettings"]["headers"].get("Host").is_none());
        assert_eq!(s["tlsSettings"]["serverName"], "cdn.example.com");
        assert_eq!(s["tlsSettings"]["alpn"][1], "http/1.1");
        assert_eq!(s["tlsSettings"]["pinnedPeerCertSha256"], "438a24fc9cd26eba3079e0baaea8784de564f41eb2f861af81134c268ee2d249");
        assert!(s["tlsSettings"].get("allowInsecure").is_none(), "Xray rejects the removed option outright");
    }

    #[test]
    fn trojan_grpc_and_ss() {
        let mut r = root(PROFILE);
        let c = cfg(&plan(&mut r, &run(XrayMode::All, None)));
        let t = &c["outbounds"][2];
        assert_eq!(t["protocol"], "trojan");
        assert_eq!(t["settings"]["servers"][0]["password"], "pw");
        assert_eq!(t["streamSettings"]["network"], "grpc");
        assert_eq!(t["streamSettings"]["grpcSettings"]["serviceName"], "svc");
        assert_eq!(t["streamSettings"]["security"], "tls");
        let s = &c["outbounds"][3];
        assert_eq!(s["protocol"], "shadowsocks");
        assert_eq!(s["settings"]["servers"][0]["method"], "aes-256-gcm");
        assert!(s.get("streamSettings").is_none());
        // plain vless without TLS
        assert_eq!(c["outbounds"][4]["streamSettings"]["security"], "none");
    }

    fn dpi() -> Dpi {
        Dpi {
            packets: "tlshello".into(),
            length: "50-100".into(),
            interval: "5".into(),
            max_split: "100-200".into(),
        }
    }

    #[test]
    fn auto_with_dpi_takes_only_tls_servers_and_cuts_their_handshake() {
        let mut r = root(PROFILE);
        let p = plan(&mut r, &run(XrayMode::Auto, Some(dpi())));
        // R (reality), W (tls), T (trojan); S and P have no handshake to cut
        assert_eq!(p.nodes, 3, "{:?}", p.skipped);
        assert_eq!(p.dpi_nodes, 3);
        let n = names(&r);
        assert_eq!(n.iter().find(|(a, _)| a == "S").unwrap().1, "ss");
        assert_eq!(n.iter().find(|(a, _)| a == "P").unwrap().1, "vless");
        let c = cfg(&p);
        let mask = &c["outbounds"][0]["streamSettings"]["finalmask"]["tcp"][0];
        assert_eq!(mask["type"], "fragment");
        assert_eq!(mask["settings"]["packets"], "tlshello");
        assert_eq!(mask["settings"]["length"], "50-100");
        assert_eq!(mask["settings"]["delay"], "5");
        assert_eq!(mask["settings"]["maxSplit"], "100-200");
        assert!(c["outbounds"][0]["streamSettings"].get("sockopt").is_none());
    }

    #[test]
    fn old_core_gets_a_fragmenting_hop_instead() {
        let mut r = root(PROFILE);
        let mut run = run(XrayMode::Auto, Some(dpi()));
        run.core = Some([25, 12, 8]);
        let c = cfg(&plan(&mut r, &run));
        let o = &c["outbounds"][0]["streamSettings"];
        assert_eq!(o["sockopt"]["dialerProxy"], "dpi");
        assert!(o.get("finalmask").is_none());
        let hop = c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "dpi").unwrap();
        assert_eq!(hop["protocol"], "freedom");
        assert_eq!(hop["settings"]["fragment"]["interval"], "5");
        assert_eq!(hop["settings"]["fragment"]["length"], "50-100");
    }

    #[test]
    fn plain_vless_runs_only_for_local_targets() {
        let y = "proxies:
  - {name: Pub, type: vless, server: 198.51.100.9, port: 80, uuid: 11111111-2222-3333-4444-555555555555}
  - {name: Lan, type: vless, server: 192.168.1.5, port: 80, uuid: 11111111-2222-3333-4444-555555555555}
  - {name: Name, type: vless, server: plain.example.com, port: 80, uuid: 11111111-2222-3333-4444-555555555555}
  - {name: Tls, type: vless, server: 198.51.100.9, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true}
";
        let mut r = root(y);
        let p = plan(&mut r, &run(XrayMode::All, None));
        assert_eq!(p.skipped.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), vec!["Pub", "Name"]);
        assert_eq!(p.nodes, 2, "Lan and Tls");
        assert!(is_local_target("localhost") && is_local_target("127.0.0.1") && is_local_target("10.1.2.3"));
        assert!(is_local_target("fd00::1") && is_local_target("[::1]") && is_local_target("169.254.1.1"));
        assert!(!is_local_target("example.com") && !is_local_target("198.51.100.9") && !is_local_target("2606:4700::1"));
    }

    #[test]
    fn a_server_the_core_turned_down_stays_with_mihomo() {
        let mut r = root(PROFILE);
        let mut run = run(XrayMode::All, None);
        run.refused.insert("T".into(), "main: bad outbound".into());
        let p = plan(&mut r, &run);
        assert_eq!(p.nodes, 4);
        assert!(p.skipped.iter().any(|(n, why)| n == "T" && why == "main: bad outbound"));
        assert!(!p.tags.values().any(|n| n == "T"));
        let ty = names(&r).into_iter().find(|(n, _)| n == "T").unwrap().1;
        assert_eq!(ty, "trojan");
        assert_eq!(p.tags.get("o0").map(String::as_str), Some("R"));
    }

    #[test]
    fn nothing_converted_means_no_config() {
        let mut r = root("proxies:\n  - {name: A, type: hysteria2, server: a, port: 1, password: x}\n");
        let p = plan(&mut r, &run(XrayMode::All, None));
        assert_eq!(p.nodes, 0);
        assert!(p.json.is_empty());
    }

    #[test]
    fn mask_support_is_detected_from_the_version() {
        assert!(core_has_fragment_mask(Some("v26.10.31")));
        assert!(core_has_fragment_mask(None));
        assert!(!core_has_fragment_mask(Some("v25.12.8")));
        assert!(!core_has_fragment_mask(Some("v1.8.24")));
    }
}
