//! Share-link (`vless://`, `vmess://`, `ss://` ...) and WireGuard `.conf` parsers.
//! Output is a mihomo proxy mapping, ready to drop into a profile's `proxies:` list.

use std::collections::{HashMap, HashSet};

use base64::{
    alphabet,
    engine::{general_purpose::GeneralPurpose, general_purpose::GeneralPurposeConfig, DecodePaddingMode},
    Engine,
};
use percent_encoding::percent_decode_str;
use serde_json::Value as J;
use serde_yaml::{Mapping, Value};
use url::Url;

use crate::util::{put, strs};

type Q = HashMap<String, String>;

fn engine() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
}

/// Base64 in either alphabet, padded or not, whitespace ignored.
pub fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    engine().decode(cleaned.trim_end_matches('=')).ok()
}

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn query(u: &Url) -> Q {
    u.query_pairs()
        .map(|(a, b)| (a.to_lowercase(), b.into_owned()))
        .collect()
}

fn opt<'a>(q: &'a Q, key: &str) -> Option<&'a str> {
    q.get(key).map(String::as_str).filter(|s| !s.is_empty())
}

fn truthy(q: &Q, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        matches!(
            q.get(*key).map(|s| s.to_lowercase()).as_deref(),
            Some("1") | Some("true") | Some("yes")
        )
    })
}

fn host_port(u: &Url) -> Result<(String, u16), String> {
    let host = u
        .host_str()
        .ok_or("missing host")?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = u.port().ok_or("missing port")?;
    Ok((host, port))
}

fn name_of(u: &Url, host: &str, port: u16) -> String {
    u.fragment()
        .map(|f| dec(f).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"))
}

fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// TLS fields shared by vless / vmess / trojan / hysteria2 / tuic.
fn apply_tls(m: &mut Mapping, q: &Q, sni_key: &str, default_sni: &str, set_flag: bool) {
    if set_flag {
        put(m, "tls", true);
    }
    let sni = opt(q, "sni")
        .or_else(|| opt(q, "peer"))
        .or_else(|| opt(q, "servername"))
        .unwrap_or(default_sni);
    if !sni.is_empty() {
        put(m, sni_key, sni);
    }
    if let Some(a) = opt(q, "alpn") {
        put(m, "alpn", strs(csv(a)));
    }
    if let Some(fp) = opt(q, "fp") {
        put(m, "client-fingerprint", fp);
    }
    // `pcs`: SHA-256 of the server certificate (the share-link form of Xray's pinnedPeerCertSha256)
    if let Some(pin) = opt(q, "pcs") {
        put(m, "fingerprint", pin);
    }
    if truthy(q, &["allowinsecure", "insecure", "allow_insecure"]) {
        put(m, "skip-cert-verify", true);
    }
}

fn apply_transport(m: &mut Mapping, net: &str, q: &Q) -> Result<(), String> {
    let net = net.to_lowercase();
    match net.as_str() {
        "" | "tcp" | "raw" => {
            if opt(q, "headertype") == Some("http") {
                put(m, "network", "http");
                let mut o = Mapping::new();
                put(&mut o, "method", "GET");
                put(&mut o, "path", strs(csv(opt(q, "path").unwrap_or("/"))));
                if let Some(h) = opt(q, "host") {
                    let mut hd = Mapping::new();
                    put(&mut hd, "Host", strs(csv(h)));
                    put(&mut o, "headers", hd);
                }
                put(m, "http-opts", o);
            } else {
                put(m, "network", "tcp");
            }
        }
        "ws" | "websocket" | "httpupgrade" => {
            put(m, "network", "ws");
            let mut o = Mapping::new();
            put(&mut o, "path", opt(q, "path").unwrap_or("/"));
            if let Some(h) = opt(q, "host") {
                let mut hd = Mapping::new();
                put(&mut hd, "Host", h);
                put(&mut o, "headers", hd);
            }
            if net == "httpupgrade" {
                put(&mut o, "v2ray-http-upgrade", true);
            }
            put(m, "ws-opts", o);
        }
        "grpc" => {
            put(m, "network", "grpc");
            let mut o = Mapping::new();
            put(&mut o, "grpc-service-name", opt(q, "servicename").unwrap_or(""));
            put(m, "grpc-opts", o);
        }
        "h2" | "http" => {
            put(m, "network", "h2");
            let mut o = Mapping::new();
            if let Some(h) = opt(q, "host") {
                put(&mut o, "host", strs(csv(h)));
            }
            put(&mut o, "path", opt(q, "path").unwrap_or("/"));
            put(m, "h2-opts", o);
        }
        "xhttp" | "splithttp" => {
            put(m, "network", "xhttp");
            let mut o = Mapping::new();
            put(&mut o, "path", opt(q, "path").unwrap_or("/"));
            if let Some(h) = opt(q, "host") {
                put(&mut o, "host", h);
            }
            if let Some(mode) = opt(q, "mode") {
                put(&mut o, "mode", mode);
            }
            put(m, "xhttp-opts", o);
        }
        other => return Err(format!("unsupported transport '{other}'")),
    }
    Ok(())
}

fn parse_vless(u: &Url) -> Result<Mapping, String> {
    let q = query(u);
    let (host, port) = host_port(u)?;
    let uuid = dec(u.username());
    if uuid.is_empty() {
        return Err("missing uuid".into());
    }
    let mut m = Mapping::new();
    put(&mut m, "name", name_of(u, &host, port));
    put(&mut m, "type", "vless");
    put(&mut m, "server", host.clone());
    put(&mut m, "port", port);
    put(&mut m, "uuid", uuid);
    put(&mut m, "udp", true);
    if let Some(enc) = opt(&q, "encryption") {
        if enc != "none" {
            put(&mut m, "encryption", enc);
        }
    }
    match opt(&q, "flow") {
        Some(flow) => put(&mut m, "flow", flow),
        None => put(&mut m, "packet-encoding", "xudp"),
    }
    let sec = opt(&q, "security").unwrap_or("none").to_lowercase();
    if sec == "tls" || sec == "reality" || sec == "xtls" {
        apply_tls(&mut m, &q, "servername", &host, true);
    }
    if sec == "reality" {
        let mut r = Mapping::new();
        put(&mut r, "public-key", opt(&q, "pbk").unwrap_or(""));
        put(&mut r, "short-id", opt(&q, "sid").unwrap_or(""));
        put(&mut m, "reality-opts", r);
        if !m.contains_key("client-fingerprint") {
            put(&mut m, "client-fingerprint", "chrome");
        }
    }
    apply_transport(&mut m, opt(&q, "type").unwrap_or("tcp"), &q)?;
    Ok(m)
}

fn parse_vmess(body: &str) -> Result<Mapping, String> {
    let body = body.split('#').next().unwrap_or(body).trim();
    let bytes = b64_decode_any(body).ok_or("bad base64")?;
    let j: J = serde_json::from_slice(&bytes).map_err(|e| format!("bad json: {e}"))?;
    let s = |key: &str| -> Option<String> {
        match j.get(key) {
            Some(J::String(v)) if !v.is_empty() => Some(v.clone()),
            Some(J::Number(n)) => Some(n.to_string()),
            Some(J::Bool(b)) => Some(b.to_string()),
            _ => None,
        }
    };
    let host = s("add").ok_or("missing address")?;
    let port: u16 = s("port")
        .ok_or("missing port")?
        .parse()
        .map_err(|_| "bad port".to_string())?;
    let id = s("id").ok_or("missing id")?;
    let net = s("net").unwrap_or_else(|| "tcp".into());

    let mut q: Q = HashMap::new();
    for (src, dst) in [("host", "host"), ("sni", "sni"), ("alpn", "alpn"), ("fp", "fp")] {
        if let Some(v) = s(src) {
            q.insert(dst.into(), v);
        }
    }
    if let Some(p) = s("path") {
        q.insert(if net == "grpc" { "servicename" } else { "path" }.into(), p);
    }
    if s("type").as_deref() == Some("http") {
        q.insert("headertype".into(), "http".into());
    }
    if matches!(s("allowInsecure").as_deref(), Some("1") | Some("true")) {
        q.insert("allowinsecure".into(), "1".into());
    }

    let mut m = Mapping::new();
    put(&mut m, "name", s("ps").unwrap_or_else(|| format!("{host}:{port}")));
    put(&mut m, "type", "vmess");
    put(&mut m, "server", host.clone());
    put(&mut m, "port", port);
    put(&mut m, "uuid", id);
    put(&mut m, "alterId", s("aid").and_then(|a| a.parse::<u32>().ok()).unwrap_or(0));
    put(&mut m, "cipher", s("scy").unwrap_or_else(|| "auto".into()));
    put(&mut m, "udp", true);
    if matches!(s("tls").as_deref(), Some("tls") | Some("1") | Some("true")) {
        let default_sni = s("host").unwrap_or_else(|| host.clone());
        apply_tls(&mut m, &q, "servername", &default_sni, true);
    }
    apply_transport(&mut m, &net, &q)?;
    Ok(m)
}

fn parse_trojan(u: &Url) -> Result<Mapping, String> {
    let q = query(u);
    let (host, port) = host_port(u)?;
    let password = match u.password() {
        Some(p) => format!("{}:{}", dec(u.username()), dec(p)),
        None => dec(u.username()),
    };
    if password.is_empty() {
        return Err("missing password".into());
    }
    let mut m = Mapping::new();
    put(&mut m, "name", name_of(u, &host, port));
    put(&mut m, "type", "trojan");
    put(&mut m, "server", host.clone());
    put(&mut m, "port", port);
    put(&mut m, "password", password);
    put(&mut m, "udp", true);
    apply_tls(&mut m, &q, "sni", &host, false);
    apply_transport(&mut m, opt(&q, "type").unwrap_or("tcp"), &q)?;
    Ok(m)
}

fn split_host_port(s: &str) -> Result<(String, u16), String> {
    let (h, p) = s.rsplit_once(':').ok_or("missing port")?;
    let port = p.trim().parse::<u16>().map_err(|_| "bad port".to_string())?;
    Ok((h.trim().trim_matches(|c| c == '[' || c == ']').to_string(), port))
}

fn parse_ss(rest: &str) -> Result<Mapping, String> {
    let (main, frag) = match rest.split_once('#') {
        Some((a, b)) => (a, Some(dec(b).trim().to_string())),
        None => (rest, None),
    };
    let (main, query_str) = match main.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (main, None),
    };
    let main = main.trim_end_matches('/');

    let (userinfo, hostport) = match main.rsplit_once('@') {
        Some((u, h)) => {
            let d = dec(u);
            let info = if d.contains(':') {
                d
            } else {
                String::from_utf8(b64_decode_any(&d).ok_or("bad base64 userinfo")?)
                    .map_err(|_| "userinfo is not utf-8".to_string())?
            };
            (info, h.to_string())
        }
        None => {
            let all = String::from_utf8(b64_decode_any(main).ok_or("bad base64")?)
                .map_err(|_| "payload is not utf-8".to_string())?;
            let (u, h) = all.rsplit_once('@').ok_or("missing '@'")?;
            (u.to_string(), h.to_string())
        }
    };
    let (method, password) = userinfo.split_once(':').ok_or("missing method:password")?;
    let (host, port) = split_host_port(&hostport)?;

    let mut m = Mapping::new();
    put(&mut m, "name", frag.filter(|s| !s.is_empty()).unwrap_or_else(|| format!("{host}:{port}")));
    put(&mut m, "type", "ss");
    put(&mut m, "server", host);
    put(&mut m, "port", port);
    put(&mut m, "cipher", method);
    put(&mut m, "password", password);
    put(&mut m, "udp", true);

    if let Some(qs) = query_str {
        let pairs: Q = url::form_urlencoded::parse(qs.as_bytes())
            .map(|(a, b)| (a.to_lowercase(), b.into_owned()))
            .collect();
        if let Some(plugin) = pairs.get("plugin") {
            apply_ss_plugin(&mut m, plugin)?;
        }
    }
    Ok(m)
}

fn apply_ss_plugin(m: &mut Mapping, spec: &str) -> Result<(), String> {
    let mut parts = spec.split(';');
    let name = parts.next().unwrap_or("").trim();
    let mut kv: HashMap<String, String> = HashMap::new();
    let mut flags: HashSet<String> = HashSet::new();
    for p in parts {
        match p.split_once('=') {
            Some((a, b)) => {
                kv.insert(a.trim().to_lowercase(), b.trim().to_string());
            }
            None if !p.trim().is_empty() => {
                flags.insert(p.trim().to_lowercase());
            }
            None => {}
        }
    }
    let mut o = Mapping::new();
    match name {
        "obfs-local" | "simple-obfs" | "obfs" => {
            put(m, "plugin", "obfs");
            put(&mut o, "mode", kv.get("obfs").map(String::as_str).unwrap_or("http"));
            if let Some(h) = kv.get("obfs-host") {
                put(&mut o, "host", h.as_str());
            }
        }
        "v2ray-plugin" => {
            put(m, "plugin", "v2ray-plugin");
            put(&mut o, "mode", kv.get("mode").map(String::as_str).unwrap_or("websocket"));
            if flags.contains("tls") {
                put(&mut o, "tls", true);
            }
            if let Some(h) = kv.get("host") {
                put(&mut o, "host", h.as_str());
            }
            if let Some(p) = kv.get("path") {
                put(&mut o, "path", p.as_str());
            }
            if flags.contains("mux") {
                put(&mut o, "mux", true);
            }
        }
        "" => return Ok(()),
        other => return Err(format!("unsupported ss plugin '{other}'")),
    }
    put(m, "plugin-opts", o);
    Ok(())
}

/// `hysteria2://auth@host:443,5000-6000/?x` -> (url without the port list, Some("5000-6000"))
fn split_multiport(raw: &str) -> (String, Option<String>) {
    let Some(sch) = raw.find("://") else {
        return (raw.to_string(), None);
    };
    let rest = &raw[sch + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    let host_start = auth.rfind('@').map(|i| i + 1).unwrap_or(0);
    if let Some(ci) = auth[host_start..].find(',') {
        let ci = host_start + ci;
        let ports = auth[ci + 1..].to_string();
        let rebuilt = format!("{}{}{}", &raw[..sch + 3], &auth[..ci], &rest[end..]);
        return (rebuilt, Some(ports));
    }
    (raw.to_string(), None)
}

fn parse_hy2(u: &Url, mport: Option<String>) -> Result<Mapping, String> {
    let q = query(u);
    let host = u
        .host_str()
        .ok_or("missing host")?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = u.port().unwrap_or(443);
    let auth = match u.password() {
        Some(p) => format!("{}:{}", dec(u.username()), dec(p)),
        None => dec(u.username()),
    };
    if auth.is_empty() {
        return Err("missing password".into());
    }
    let mut m = Mapping::new();
    put(&mut m, "name", name_of(u, &host, port));
    put(&mut m, "type", "hysteria2");
    put(&mut m, "server", host.clone());
    put(&mut m, "port", port);
    put(&mut m, "password", auth);
    if let Some(p) = mport {
        put(&mut m, "ports", p);
    }
    apply_tls(&mut m, &q, "sni", &host, false);
    if let Some(o) = opt(&q, "obfs") {
        put(&mut m, "obfs", o);
        if let Some(p) = opt(&q, "obfs-password") {
            put(&mut m, "obfs-password", p);
        }
    }
    for key in ["up", "down"] {
        if let Some(v) = opt(&q, key) {
            put(&mut m, key, v);
        }
    }
    Ok(m)
}

fn parse_tuic(u: &Url) -> Result<Mapping, String> {
    let q = query(u);
    let (host, port) = host_port(u)?;
    let uuid = dec(u.username());
    let password = u.password().map(dec).unwrap_or_default();
    if uuid.is_empty() {
        return Err("missing uuid".into());
    }
    let mut m = Mapping::new();
    put(&mut m, "name", name_of(u, &host, port));
    put(&mut m, "type", "tuic");
    put(&mut m, "server", host.clone());
    put(&mut m, "port", port);
    put(&mut m, "uuid", uuid);
    put(&mut m, "password", password);
    put(
        &mut m,
        "congestion-controller",
        opt(&q, "congestion_control").unwrap_or("bbr"),
    );
    put(
        &mut m,
        "udp-relay-mode",
        opt(&q, "udp_relay_mode").unwrap_or("native"),
    );
    if truthy(&q, &["disable_sni"]) {
        put(&mut m, "disable-sni", true);
    }
    if truthy(&q, &["reduce_rtt"]) {
        put(&mut m, "reduce-rtt", true);
    }
    apply_tls(&mut m, &q, "sni", &host, false);
    Ok(m)
}

fn parse_anytls(u: &Url) -> Result<Mapping, String> {
    let q = query(u);
    let (host, port) = host_port(u)?;
    let password = dec(u.username());
    if password.is_empty() {
        return Err("missing password".into());
    }
    let mut m = Mapping::new();
    put(&mut m, "name", name_of(u, &host, port));
    put(&mut m, "type", "anytls");
    put(&mut m, "server", host.clone());
    put(&mut m, "port", port);
    put(&mut m, "password", password);
    put(&mut m, "udp", true);
    apply_tls(&mut m, &q, "sni", &host, false);
    Ok(m)
}

fn parse_socks_or_http(u: &Url, kind: &str) -> Result<Mapping, String> {
    let (host, port) = host_port(u)?;
    let mut m = Mapping::new();
    put(&mut m, "name", name_of(u, &host, port));
    put(&mut m, "type", kind);
    put(&mut m, "server", host);
    put(&mut m, "port", port);
    if !u.username().is_empty() {
        put(&mut m, "username", dec(u.username()));
        put(&mut m, "password", u.password().map(dec).unwrap_or_default());
    }
    if kind == "socks5" {
        put(&mut m, "udp", true);
    }
    if u.scheme() == "https" {
        put(&mut m, "tls", true);
    }
    Ok(m)
}

fn strip_scheme<'a>(line: &'a str, scheme: &str) -> Option<&'a str> {
    let n = scheme.len();
    if line.len() >= n && line.is_char_boundary(n) && line[..n].eq_ignore_ascii_case(scheme) {
        Some(&line[n..])
    } else {
        None
    }
}

/// Parse one share link.
pub fn parse_link(line: &str) -> Result<Mapping, String> {
    let line = line.trim();
    if let Some(rest) = strip_scheme(line, "vmess://") {
        return parse_vmess(rest);
    }
    if let Some(rest) = strip_scheme(line, "ss://") {
        return parse_ss(rest);
    }
    let (norm, mport) = split_multiport(line);
    let u = Url::parse(&norm).map_err(|e| format!("bad url: {e}"))?;
    match u.scheme() {
        "vless" => parse_vless(&u),
        "trojan" => parse_trojan(&u),
        "hysteria2" | "hy2" => parse_hy2(&u, mport),
        "tuic" => parse_tuic(&u),
        "anytls" => parse_anytls(&u),
        "socks5" | "socks" | "socks5h" => parse_socks_or_http(&u, "socks5"),
        "http" | "https" => {
            let looks_like_proxy = !u.username().is_empty()
                || (u.port().is_some() && matches!(u.path(), "" | "/") && u.query().is_none());
            if looks_like_proxy {
                parse_socks_or_http(&u, "http")
            } else {
                Err("looks like a web page, not a proxy".into())
            }
        }
        s => Err(format!("unsupported scheme '{s}'")),
    }
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub proxies: Vec<Mapping>,
    pub errors: Vec<String>,
}

/// Parse a block of text: one link per line (or several per line, space separated).
pub fn parse_links(text: &str) -> Parsed {
    let mut out = Parsed::default();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = if line.matches("://").count() > 1 {
            line.split_whitespace().filter(|t| t.contains("://")).collect()
        } else {
            vec![line]
        };
        for t in tokens {
            match parse_link(t) {
                Ok(m) => out.proxies.push(m),
                Err(e) => {
                    let preview: String = t.chars().take(40).collect();
                    out.errors.push(format!("{preview}: {e}"));
                }
            }
        }
    }
    dedupe_names(&mut out.proxies);
    out
}

pub fn dedupe_names(list: &mut [Mapping]) {
    let mut seen: HashSet<String> = HashSet::new();
    for m in list.iter_mut() {
        let base = m
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("node")
            .to_string();
        let mut name = base.clone();
        let mut i = 2;
        while !seen.insert(name.clone()) {
            name = format!("{base} {i}");
            i += 1;
        }
        put(m, "name", name);
    }
}

pub fn looks_like_wireguard(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("[interface]") && t.contains("[peer]") && t.contains("privatekey")
}

/// WireGuard / AmneziaWG `.conf` -> mihomo `wireguard` proxy (first peer only).
pub fn parse_wireguard(text: &str, fallback_name: &str) -> Result<Mapping, String> {
    let mut section = String::new();
    let mut iface: Q = HashMap::new();
    let mut peer: Q = HashMap::new();
    let mut peers = 0;
    let mut name: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(c) = line.strip_prefix('#').or_else(|| line.strip_prefix(';')) {
            let c = c.trim();
            if name.is_none() && !c.is_empty() && c.chars().count() < 60 {
                name = Some(c.to_string());
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_lowercase();
            if section == "peer" {
                peers += 1;
            }
            continue;
        }
        if let Some((a, b)) = line.split_once('=') {
            let key = a.trim().to_lowercase();
            let val = b.trim().to_string();
            match section.as_str() {
                "interface" => {
                    iface.insert(key, val);
                }
                "peer" if peers == 1 => {
                    peer.insert(key, val);
                }
                _ => {}
            }
        }
    }
    let private_key = iface.get("privatekey").ok_or("missing PrivateKey")?;
    let public_key = peer.get("publickey").ok_or("missing PublicKey")?;
    let endpoint = peer.get("endpoint").ok_or("missing Endpoint")?;
    let (host, port) = split_host_port(endpoint)?;

    let mut m = Mapping::new();
    put(&mut m, "name", name.unwrap_or_else(|| fallback_name.to_string()));
    put(&mut m, "type", "wireguard");
    put(&mut m, "server", host);
    put(&mut m, "port", port);
    put(&mut m, "private-key", private_key.as_str());
    put(&mut m, "public-key", public_key.as_str());
    if let Some(p) = peer.get("presharedkey") {
        put(&mut m, "pre-shared-key", p.as_str());
    }
    for addr in csv(iface.get("address").map(String::as_str).unwrap_or("")) {
        let ip = addr.split('/').next().unwrap_or("").to_string();
        if ip.contains(':') {
            if !m.contains_key("ipv6") {
                put(&mut m, "ipv6", ip);
            }
        } else if !m.contains_key("ip") {
            put(&mut m, "ip", ip);
        }
    }
    let allowed = csv(peer.get("allowedips").map(String::as_str).unwrap_or("0.0.0.0/0, ::/0"));
    put(&mut m, "allowed-ips", strs(allowed));
    put(&mut m, "udp", true);
    if let Some(mtu) = iface.get("mtu").and_then(|v| v.parse::<u32>().ok()) {
        put(&mut m, "mtu", mtu);
    }
    if let Some(ka) = peer.get("persistentkeepalive").and_then(|v| v.parse::<u32>().ok()) {
        put(&mut m, "persistent-keepalive", ka);
    }
    let dns: Vec<String> = csv(iface.get("dns").map(String::as_str).unwrap_or(""))
        .into_iter()
        .filter(|d| d.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if !dns.is_empty() {
        put(&mut m, "remote-dns-resolve", true);
        put(&mut m, "dns", strs(dns));
    }
    if let Some(r) = iface.get("reserved").or_else(|| peer.get("reserved")) {
        let nums: Vec<Value> = csv(r)
            .iter()
            .filter_map(|n| n.parse::<u8>().ok())
            .map(|n| Value::from(n as u64))
            .collect();
        if nums.len() == 3 {
            put(&mut m, "reserved", Value::Sequence(nums));
        }
    }
    // AmneziaWG obfuscation parameters
    let mut awg = Mapping::new();
    for (src, dst) in [
        ("jc", "jc"),
        ("jmin", "jmin"),
        ("jmax", "jmax"),
        ("s1", "s1"),
        ("s2", "s2"),
        ("h1", "h1"),
        ("h2", "h2"),
        ("h3", "h3"),
        ("h4", "h4"),
    ] {
        if let Some(v) = iface.get(src).and_then(|v| v.parse::<u64>().ok()) {
            put(&mut awg, dst, v);
        }
    }
    if !awg.is_empty() {
        put(&mut m, "amnezia-wg-option", awg);
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::str_of;

    fn s<'a>(m: &'a Mapping, key: &str) -> &'a str {
        str_of(m, key).unwrap_or("")
    }

    #[test]
    fn vless_reality() {
        let m = parse_link("vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&type=tcp&flow=xtls-rprx-vision#My%20Node").unwrap();
        assert_eq!(s(&m, "name"), "My Node");
        assert_eq!(s(&m, "type"), "vless");
        assert_eq!(s(&m, "flow"), "xtls-rprx-vision");
        assert_eq!(s(&m, "servername"), "www.microsoft.com");
        assert_eq!(s(&m, "client-fingerprint"), "chrome");
        let r = m.get("reality-opts").and_then(Value::as_mapping).unwrap();
        assert_eq!(s(r, "public-key"), "PUBKEY");
        assert_eq!(s(r, "short-id"), "ab12");
    }

    #[test]
    fn vless_ws_tls() {
        let m = parse_link("vless://uuid@cdn.example.com:443?security=tls&type=ws&host=h.example.com&path=%2Fws&sni=h.example.com&alpn=h2,http/1.1&allowInsecure=1#ws").unwrap();
        assert_eq!(s(&m, "network"), "ws");
        let ws = m.get("ws-opts").and_then(Value::as_mapping).unwrap();
        assert_eq!(s(ws, "path"), "/ws");
        assert_eq!(m.get("skip-cert-verify").and_then(Value::as_bool), Some(true));
        assert_eq!(m.get("alpn").and_then(Value::as_sequence).map(|a| a.len()), Some(2));
    }

    #[test]
    fn pinned_certificate_hash_is_kept() {
        let m = parse_link("vless://uuid@h.example.com:443?security=tls&sni=h.example.com&pcs=438a24fc9cd26eba&allowInsecure=1#p").unwrap();
        assert_eq!(s(&m, "fingerprint"), "438a24fc9cd26eba");
        assert_eq!(m.get("skip-cert-verify").and_then(Value::as_bool), Some(true));
        assert!(m.get("client-fingerprint").is_none(), "the pin is not the uTLS fingerprint");
    }

    #[test]
    fn vmess_json() {
        let json = r#"{"v":"2","ps":"vm","add":"1.2.3.4","port":"443","id":"uuid","aid":"0","scy":"auto","net":"ws","type":"none","host":"h.com","path":"/p","tls":"tls","sni":"h.com"}"#;
        let link = format!("vmess://{}", base64_std(json));
        let m = parse_link(&link).unwrap();
        assert_eq!(s(&m, "name"), "vm");
        assert_eq!(s(&m, "network"), "ws");
        assert_eq!(m.get("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(s(&m, "servername"), "h.com");
    }

    fn base64_std(s: &str) -> String {
        use base64::engine::general_purpose::STANDARD;
        STANDARD.encode(s)
    }

    #[test]
    fn trojan_basic() {
        let m = parse_link("trojan://p%40ss@host.com:443?sni=a.com&type=grpc&serviceName=svc#T").unwrap();
        assert_eq!(s(&m, "password"), "p@ss");
        assert_eq!(s(&m, "sni"), "a.com");
        assert_eq!(s(&m, "network"), "grpc");
    }

    #[test]
    fn ss_both_forms() {
        let a = parse_link(&format!("ss://{}@1.2.3.4:8388#a", base64_std("aes-256-gcm:pw"))).unwrap();
        assert_eq!(s(&a, "cipher"), "aes-256-gcm");
        assert_eq!(s(&a, "password"), "pw");
        let b = parse_link(&format!("ss://{}#b", base64_std("chacha20-ietf-poly1305:pw2@host:1234"))).unwrap();
        assert_eq!(s(&b, "server"), "host");
        assert_eq!(s(&b, "name"), "b");
    }

    #[test]
    fn ss_obfs_plugin() {
        let l = format!(
            "ss://{}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.com#p",
            base64_std("aes-128-gcm:x")
        );
        let m = parse_link(&l).unwrap();
        assert_eq!(s(&m, "plugin"), "obfs");
        let o = m.get("plugin-opts").and_then(Value::as_mapping).unwrap();
        assert_eq!(s(o, "host"), "cdn.com");
    }

    #[test]
    fn hysteria2_multiport() {
        let m = parse_link("hysteria2://pw@h.com:443,20000-30000/?sni=h.com&insecure=1&obfs=salamander&obfs-password=op#hy").unwrap();
        assert_eq!(s(&m, "type"), "hysteria2");
        assert_eq!(s(&m, "ports"), "20000-30000");
        assert_eq!(s(&m, "obfs"), "salamander");
        assert_eq!(m.get("skip-cert-verify").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn tuic_basic() {
        let m = parse_link("tuic://uuid:pw@h.com:443?congestion_control=bbr&alpn=h3&sni=h.com#t").unwrap();
        assert_eq!(s(&m, "uuid"), "uuid");
        assert_eq!(s(&m, "password"), "pw");
    }

    #[test]
    fn list_dedupes_names() {
        let p = parse_links("socks5://1.1.1.1:1080#x\nsocks5://2.2.2.2:1080#x\nbogus://nope");
        assert_eq!(p.proxies.len(), 2);
        assert_eq!(p.errors.len(), 1);
        assert_eq!(s(&p.proxies[1], "name"), "x 2");
    }

    #[test]
    fn wireguard_conf_with_awg() {
        let conf = "# Berlin\n[Interface]\nPrivateKey = PRIV\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 1.1.1.1, example.com\nMTU = 1280\nJc = 5\nS1 = 30\nH1 = 123\n\n[Peer]\nPublicKey = PUB\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.5:51820\nPersistentKeepalive = 25\n";
        assert!(looks_like_wireguard(conf));
        let m = parse_wireguard(conf, "wg").unwrap();
        assert_eq!(s(&m, "name"), "Berlin");
        assert_eq!(s(&m, "ip"), "10.0.0.2");
        assert_eq!(s(&m, "ipv6"), "fd00::2");
        assert_eq!(m.get("port").and_then(Value::as_u64), Some(51820));
        let a = m.get("amnezia-wg-option").and_then(Value::as_mapping).unwrap();
        assert_eq!(a.get("jc").and_then(Value::as_u64), Some(5));
        let dns = m.get("dns").and_then(Value::as_sequence).unwrap();
        assert_eq!(dns.len(), 1);
    }
}
