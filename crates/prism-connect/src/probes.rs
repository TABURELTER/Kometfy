//! The checks a remote test runs on this device's own network (docs/BACKEND.md, "Remote tests"): a site's TLS
//! handshake with the step where it breaks, DNS answers against DNS-over-HTTPS, TCP to host:port, a download's
//! speed, and any VPN subscription (fetched without this device's ids, each server tried over TCP and through a
//! core of its own that lives only for the test). Plus the kind of link a desktop is on.
//!
//! What they return names public sites, the addresses those resolve to and the servers of the subscription the
//! test itself gave; never a site the user opened, this device's address, a link of the user's or a key.

use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use futures_util::{stream, StreamExt};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const STEP: Duration = Duration::from_secs(3);

/// One TLS handshake with `host`:443, directly or through a SOCKS5 proxy ("socks5://127.0.0.1:10880"): did a
/// server hello come back, in how many ms, and if not, where it broke: `dns` (the name did not resolve), `tcp` (no
/// connection), `reset` (the connection was cut in the handshake, the usual DPI answer), `timeout` (no answer) or
/// `tls` (an answer that is not a server hello).
pub async fn site(host: &str, via: Option<&str>) -> Value {
    let t = Instant::now();
    let stage = handshake(host, via).await;
    let ms = t.elapsed().as_millis() as u64;
    match stage {
        None => json!({ "ok": true, "ms": ms }),
        Some(s) => json!({ "ok": false, "ms": ms, "stage": s }),
    }
}

async fn handshake(host: &str, via: Option<&str>) -> Option<&'static str> {
    let mut stream = match via.and_then(|v| v.split("://").nth(1)) {
        Some(proxy) => match timeout(STEP, crate::zapret::socks_connect(proxy, host)).await {
            Ok(Ok(s)) => s,
            _ => return Some("tcp"),
        },
        None => {
            let addrs: Vec<SocketAddr> = match timeout(STEP, tokio::net::lookup_host((host, 443))).await {
                Ok(Ok(a)) => a.collect(),
                _ => return Some("dns"),
            };
            if addrs.is_empty() {
                return Some("dns");
            }
            match timeout(STEP, TcpStream::connect(&addrs[..])).await {
                Ok(Ok(s)) => s,
                _ => return Some("tcp"),
            }
        }
    };
    let answer = async {
        stream.write_all(&crate::zapret::client_hello(host)).await?;
        let mut head = [0u8; 6];
        stream.read_exact(&mut head).await?;
        Ok::<_, std::io::Error>(head[0] == 0x16 && head[1] == 3 && head[5] == 2)
    };
    match timeout(Duration::from_secs(4), answer).await {
        Ok(Ok(true)) => None,
        Ok(Ok(false)) => Some("tls"),
        Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::UnexpectedEof) => Some("reset"),
        Ok(Err(_)) => Some("tls"),
        Err(_) => Some("timeout"),
    }
}

/// An address no public site answers on: what a provider's DNS gives instead of a blocked name.
fn bogus(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_unspecified() || v.is_loopback() || v.is_private() || v.is_link_local() || v.octets()[0] == 0,
        IpAddr::V6(v) => v.is_unspecified() || v.is_loopback(),
    }
}

/// Each domain asked of the system's resolver (the provider's DNS) and of Cloudflare's DNS-over-HTTPS, with a
/// verdict: `same`, `differs` (other addresses: often just a CDN), `bogus` (a private or empty address: a stub),
/// `blocked` (the system has no answer, DoH has), `doh_failed`, `both_failed`.
pub async fn dns(http: &reqwest::Client, domains: &[String]) -> Value {
    let one = |d: String| async move {
        let system: Option<Vec<IpAddr>> = match timeout(Duration::from_secs(4), tokio::net::lookup_host((d.as_str(), 0))).await {
            Ok(Ok(a)) => Some(a.map(|s| s.ip()).filter(IpAddr::is_ipv4).collect()),
            _ => None,
        };
        let doh = doh_a(http, &d).await;
        let sys = system.clone().unwrap_or_default();
        let verdict = match (&system, &doh) {
            (None, None) => "both_failed",
            _ if sys.iter().any(bogus) => "bogus",
            (_, None) => "doh_failed",
            (None, Some(_)) => "blocked",
            (Some(s), _) if s.is_empty() => "blocked",
            (Some(s), Some(h)) if s.iter().any(|ip| h.contains(ip)) => "same",
            _ => "differs",
        };
        let list = |v: &[IpAddr]| v.iter().take(4).map(|ip| ip.to_string()).collect::<Vec<_>>();
        json!({ "domain": d, "system": list(&sys), "doh": list(&doh.unwrap_or_default()), "verdict": verdict })
    };
    let out: Vec<Value> = stream::iter(domains.iter().cloned().map(one)).buffered(6).collect().await;
    json!({ "resolver": "cloudflare", "domains": out })
}

/// The IPv4 answers of Cloudflare's DNS-over-HTTPS, asked at its address (so no DNS is needed to reach it).
async fn doh_a(http: &reqwest::Client, name: &str) -> Option<Vec<IpAddr>> {
    let v: Value = http
        .get("https://1.1.1.1/dns-query")
        .query(&[("name", name), ("type", "A")])
        .header("accept", "application/dns-json")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    Some(v["Answer"].as_array().into_iter().flatten().filter(|a| a["type"] == 1).filter_map(|a| a["data"].as_str()?.parse().ok()).collect())
}

/// TCP to each "host:port": connected or not (`timeout`, `refused`, `dns`, `other`), in how many ms.
pub async fn tcp(targets: &[String]) -> Value {
    let one = |t: String| async move {
        let start = Instant::now();
        let r = timeout(STEP, TcpStream::connect(t.as_str())).await;
        let ms = start.elapsed().as_millis() as u64;
        match r {
            Ok(Ok(_)) => json!({ "target": t, "ok": true, "ms": ms }),
            Ok(Err(e)) => {
                let error = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => "refused",
                    _ if e.to_string().contains("lookup") || e.to_string().contains("resolve") => "dns",
                    _ => "other",
                };
                json!({ "target": t, "ok": false, "ms": ms, "error": error })
            }
            Err(_) => json!({ "target": t, "ok": false, "ms": ms, "error": "timeout" }),
        }
    };
    let out: Vec<Value> = stream::iter(targets.iter().cloned().map(one)).buffered(8).collect().await;
    json!({ "targets": out })
}

/// Download `url` (up to `max` bytes, at most 15 s of body), directly or through a proxy ("socks5://…",
/// "http://…"): the time to the first byte and the speed in Mbit/s.
pub async fn download(url: &str, proxy: Option<&str>, max: u64) -> Value {
    let client = match proxy {
        Some(p) => reqwest::Proxy::all(p).ok().and_then(|p| reqwest::Client::builder().proxy(p).timeout(Duration::from_secs(25)).build().ok()),
        None => reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(25)).build().ok(),
    };
    let Some(client) = client else { return json!({ "ok": false, "error": "client" }) };
    let start = Instant::now();
    let mut resp = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => return json!({ "ok": false, "error": format!("status {}", r.status().as_u16()) }),
        Err(e) => return json!({ "ok": false, "error": if e.is_timeout() { "timeout".to_string() } else { "connect".to_string() } }),
    };
    let first = start.elapsed();
    let body = Instant::now();
    let mut bytes = 0u64;
    while bytes < max && body.elapsed() < Duration::from_secs(15) {
        match resp.chunk().await {
            Ok(Some(c)) => bytes += c.len() as u64,
            Ok(None) => break,
            Err(_) => break,
        }
    }
    let secs = body.elapsed().as_secs_f64().max(0.001);
    json!({ "ok": bytes > 0, "mbps": ((bytes as f64 * 8.0 / secs / 1e6) * 10.0).round() / 10.0, "ms_first": first.as_millis() as u64, "bytes": bytes })
}

/// Protocols that run over UDP: a TCP try tells nothing about them.
const UDP_ONLY: &[&str] = &["hysteria", "hysteria2", "tuic", "wireguard"];

/// Any VPN subscription: fetched without this device's ids, its servers (up to `max`) tried over TCP and, when a
/// core is at hand, each through a core of its own (in `work`, gone after the test) for a real delay to `test_url`.
pub async fn subscription(url: &str, max: usize, test_url: &str, core: Option<PathBuf>, work: PathBuf) -> Value {
    let start = Instant::now();
    let fetched = match crate::subscription::fetch(url, None, None).await {
        Ok(f) => f,
        Err(e) => return json!({ "fetched": false, "ms": start.elapsed().as_millis() as u64, "error": short(&e.to_string()) }),
    };
    let ms = start.elapsed().as_millis() as u64;
    let proxies: Vec<serde_yaml::Mapping> = crate::subscription::normalize(&fetched.body)
        .ok()
        .and_then(|n| serde_yaml::from_str::<serde_yaml::Value>(&n.yaml).ok())
        .and_then(|root| root.get("proxies").and_then(|p| p.as_sequence()).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.as_mapping().cloned())
        .take(max)
        .collect();
    let field = |p: &serde_yaml::Mapping, k: &str| p.get(k).map(|v| v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|n| n.to_string())).unwrap_or_default()).unwrap_or_default();
    let tcp_try = |p: serde_yaml::Mapping| async move {
        let kind = field(&p, "type");
        if UDP_ONLY.contains(&kind.as_str()) {
            return Value::Null;
        }
        let target = format!("{}:{}", field(&p, "server"), field(&p, "port"));
        let start = Instant::now();
        let ok = matches!(timeout(STEP, TcpStream::connect(target.as_str())).await, Ok(Ok(_)));
        json!({ "ok": ok, "ms": start.elapsed().as_millis() as u64 })
    };
    let tcp: Vec<Value> = stream::iter(proxies.clone().into_iter().map(tcp_try)).buffered(8).collect().await;
    let names: Vec<String> = proxies.iter().map(|p| field(p, "name")).collect();
    let delays = match &core {
        Some(bin) if !proxies.is_empty() => through_core(bin, &work, &proxies, &names, test_url).await,
        _ => None,
    };
    let servers: Vec<Value> = proxies
        .iter()
        .enumerate()
        .map(|(i, p)| json!({ "name": names[i], "type": field(p, "type"), "tcp": tcp[i], "delay": delays.as_ref().map(|d| d[i]).unwrap_or(0) }))
        .collect();
    json!({ "fetched": true, "ms": ms, "title": fetched.title, "total": servers.len(), "core": delays.is_some(), "servers": servers })
}

fn short(s: &str) -> String {
    s.chars().take(160).collect()
}

/// A core of its own with only these servers and a controller on a free local port: each server's delay to
/// `test_url` (0 = no answer). The core and its folder go when the test ends.
async fn through_core(bin: &Path, work: &Path, proxies: &[serde_yaml::Mapping], names: &[String], test_url: &str) -> Option<Vec<u64>> {
    let port = std::net::TcpListener::bind("127.0.0.1:0").ok()?.local_addr().ok()?.port();
    let secret = uuid::Uuid::new_v4().to_string();
    let mut root = serde_yaml::Mapping::new();
    let put = |r: &mut serde_yaml::Mapping, k: &str, v: serde_yaml::Value| {
        r.insert(k.into(), v);
    };
    put(&mut root, "external-controller", format!("127.0.0.1:{port}").into());
    put(&mut root, "secret", secret.clone().into());
    put(&mut root, "log-level", "silent".into());
    put(&mut root, "ipv6", false.into());
    put(&mut root, "geo-auto-update", false.into());
    put(&mut root, "mode", "global".into());
    put(&mut root, "proxies", serde_yaml::Value::Sequence(proxies.iter().cloned().map(serde_yaml::Value::Mapping).collect()));
    put(&mut root, "rules", serde_yaml::Value::Sequence(vec!["MATCH,DIRECT".into()]));
    std::fs::create_dir_all(work).ok()?;
    let cfg = work.join("config.yaml");
    std::fs::write(&cfg, serde_yaml::to_string(&root).ok()?).ok()?;
    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg("-d").arg(work).arg("-f").arg(&cfg).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(crate::util::CREATE_NO_WINDOW);
    let mut child = cmd.spawn().ok()?;
    let http = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(8)).build().ok()?;
    let base = format!("http://127.0.0.1:{port}");
    let auth = format!("Bearer {secret}");
    let mut up = false;
    for _ in 0..40 {
        if http.get(format!("{base}/version")).header("authorization", &auth).send().await.is_ok_and(|r| r.status().is_success()) {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let out = if up {
        let one = |name: String| {
            let (http, base, auth) = (http.clone(), base.clone(), auth.clone());
            async move {
                let path = format!(
                    "{base}/proxies/{}/delay?url={}&timeout=5000",
                    utf8_percent_encode(&name, NON_ALPHANUMERIC),
                    utf8_percent_encode(test_url, NON_ALPHANUMERIC)
                );
                let v: Option<Value> = match http.get(path).header("authorization", auth).send().await {
                    Ok(r) => r.json().await.ok(),
                    Err(_) => None,
                };
                v.and_then(|v| v["delay"].as_u64()).unwrap_or(0)
            }
        };
        Some(stream::iter(names.iter().cloned().map(one)).buffered(6).collect().await)
    } else {
        None
    };
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(work);
    out
}

/// The kind of link a desktop is on: `wifi`, `ethernet`, `cellular` (a mobile modem), or "" when it cannot tell.
/// Blocking (it asks the system); run it off the async threads.
#[cfg(windows)]
pub fn net_type() -> &'static str {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH};
    let mut size: u32 = 32 * 1024;
    for _ in 0..3 {
        // u64 words: the structures want 8-byte alignment
        let mut buf = vec![0u64; size as usize / 8 + 1];
        let r = unsafe { GetAdaptersAddresses(0, GAA_FLAG_INCLUDE_GATEWAYS, std::ptr::null(), buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH, &mut size) };
        if r == 111 {
            continue; // ERROR_BUFFER_OVERFLOW: `size` now holds what is needed
        }
        if r != 0 {
            return "";
        }
        // an adapter that is up and has a gateway: the one the Internet goes through (a VPN's own adapter is
        // virtual and has no type of these)
        let (mut wifi, mut ethernet, mut cellular) = (false, false, false);
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = unsafe { &*p };
            if a.OperStatus == 1 && !a.FirstGatewayAddress.is_null() {
                match a.IfType {
                    71 => wifi = true,
                    6 => ethernet = true,
                    243 | 244 => cellular = true,
                    _ => {}
                }
            }
            p = a.Next;
        }
        return if ethernet { "ethernet" } else if wifi { "wifi" } else if cellular { "cellular" } else { "" };
    }
    ""
}

#[cfg(target_os = "macos")]
pub fn net_type() -> &'static str {
    let Ok(out) = std::process::Command::new("/usr/sbin/networksetup").arg("-listallhardwareports").output() else { return "" };
    let text = String::from_utf8_lossy(&out.stdout);
    let (mut wifi, mut ethernet, mut cellular) = (false, false, false);
    let mut port = String::new();
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("Hardware Port: ") {
            port = p.to_string();
        } else if let Some(dev) = line.strip_prefix("Device: ") {
            let has_ip = std::process::Command::new("/usr/sbin/ipconfig").args(["getifaddr", dev.trim()]).output().is_ok_and(|o| o.status.success() && !o.stdout.is_empty());
            if has_ip {
                if port.contains("Wi-Fi") || port.contains("AirPort") {
                    wifi = true;
                } else if port.contains("iPhone") || port.contains("Modem") {
                    cellular = true;
                } else if !port.contains("Bluetooth") {
                    ethernet = true;
                }
            }
        }
    }
    if ethernet { "ethernet" } else if wifi { "wifi" } else if cellular { "cellular" } else { "" }
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn net_type() -> &'static str {
    ""
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stub_address_is_bogus_and_a_public_one_is_not() {
        for ip in ["127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.0.1", "172.16.5.5"] {
            assert!(bogus(&ip.parse().unwrap()), "{ip}");
        }
        assert!(!bogus(&"142.250.74.46".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_closed_port_is_refused_and_a_name_that_does_not_exist_fails_at_dns() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let r = tcp(&[format!("127.0.0.1:{free}")]).await;
        assert_eq!(r["targets"][0]["ok"], false);
        let s = site("no-such-host.invalid", None).await;
        assert_eq!((s["ok"].as_bool(), s["stage"].as_str()), (Some(false), Some("dns")));
    }
}
