//! Names looked up over HTTPS when the system's DNS gives nothing. Some public DNS services (AdGuard DNS among them)
//! answer nothing for young domains, and Kometfy's backend and the Telegram gateways behind Cloudflare were then out of
//! reach without a word. Only the names these two connect to are ever asked, at Cloudflare's and Google's resolvers,
//! and only after the system's own lookup came back empty.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;

/// JSON DNS over HTTPS, reached by address so no lookup is needed to reach them.
const SERVERS: [&str; 2] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"];

/// The system's addresses for a name, or the ones DNS over HTTPS gives when the system has none.
pub async fn lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    let system = match tokio::net::lookup_host((host, port)).await {
        Ok(found) => {
            let all: Vec<SocketAddr> = found.collect();
            if !all.is_empty() {
                return Ok(all);
            }
            std::io::Error::new(std::io::ErrorKind::NotFound, format!("{host}: no address"))
        }
        Err(e) => e,
    };
    let ips = cached(host).await;
    if ips.is_empty() {
        return Err(system);
    }
    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

/// Answers kept for ten minutes: the Telegram bridge opens a connection for every chat request.
async fn cached(host: &str) -> Vec<IpAddr> {
    static SEEN: OnceLock<Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>> = OnceLock::new();
    let seen = SEEN.get_or_init(Default::default);
    if let Some((at, ips)) = seen.lock().unwrap().get(host) {
        if at.elapsed() < Duration::from_secs(600) {
            return ips.clone();
        }
    }
    let ips = over_https(host).await;
    if !ips.is_empty() {
        tracing::info!("{host}: the system's DNS gave nothing, found over HTTPS");
        seen.lock().unwrap().insert(host.to_string(), (Instant::now(), ips.clone()));
    }
    ips
}

/// IPv4 addresses for a name from the first resolver that answers.
async fn over_https(host: &str) -> Vec<IpAddr> {
    static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
    let http = HTTP.get_or_init(|| reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(6)).build().unwrap_or_default());
    for server in SERVERS {
        let Ok(resp) = http.get(server).query(&[("name", host), ("type", "A")]).header("accept", "application/dns-json").send().await else {
            continue;
        };
        let Ok(v) = resp.json::<Value>().await else { continue };
        let ips = answers(&v);
        if !ips.is_empty() {
            return ips;
        }
    }
    Vec::new()
}

/// The A records of a JSON DNS answer (CNAMEs and the rest are skipped).
fn answers(v: &Value) -> Vec<IpAddr> {
    v["Answer"].as_array().into_iter().flatten().filter(|a| a["type"].as_u64() == Some(1)).filter_map(|a| a["data"].as_str()?.parse().ok()).collect()
}

/// The same lookup as reqwest's resolver, for a client that talks to the backend.
pub struct Fallback;

impl reqwest::dns::Resolve for Fallback {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // port 0: the client puts the URL's port in
            let addrs = lookup(&host, 0).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_records_are_taken() {
        let v = serde_json::json!({ "Status": 0, "Answer": [
            { "name": "a.example.", "type": 5, "data": "b.example." },
            { "name": "b.example.", "type": 1, "data": "203.0.113.7" },
            { "name": "b.example.", "type": 1, "data": "not an address" },
            { "name": "b.example.", "type": 28, "data": "2001:db8::1" }
        ]});
        assert_eq!(answers(&v), vec!["203.0.113.7".parse::<IpAddr>().unwrap()]);
        assert!(answers(&serde_json::json!({ "Status": 3 })).is_empty());
    }

    /// Needs the internet: a resolver answers by address, its certificate checked.
    #[tokio::test]
    #[ignore]
    async fn resolvers_answer_over_https() {
        assert!(!over_https("example.com").await.is_empty());
    }
}
