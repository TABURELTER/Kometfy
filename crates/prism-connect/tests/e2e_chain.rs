//! End-to-end check against a real mihomo core: a chain must really pass through every hop.
//!
//! Two fixture mihomo processes each expose one local SOCKS5 listener (hop-a :28001, hop-b
//! :28002). They must be separate processes: mihomo rejects "loopback" traffic that re-enters one
//! of its own listeners. The app's core gets a profile with those two nodes plus the chain
//! [hop-a, hop-b]. A request through the app's mixed port must show up in hop-a's log as "connect
//! to hop-b's address" (the tunnel to the next hop) and in hop-b's log as the real destination.
//!
//! cargo test -p prism-connect --test e2e_chain -- --ignored --nocapture

use std::{
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use prism_connect::{chain::Chain, discover, paths::Paths, Manager};
use serde_json::json;

struct Fixture {
    child: Child,
    log: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Fixture {
    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

#[allow(clippy::zombie_processes)] // the child is reaped by Fixture::drop, or the test panics first
fn start_fixture(core: &Path, dir: &Path, name: &str, port: u16, ctl_port: u16) -> Fixture {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("config.yaml"),
        format!(
            "log-level: info
external-controller: 127.0.0.1:{ctl_port}
listeners:
  - {{name: {name}, type: socks, port: {port}, listen: 127.0.0.1, udp: true}}
rules:
  - MATCH,DIRECT
"
        ),
    )
    .unwrap();
    let log = dir.join("out.log");
    let out = fs::File::create(&log).unwrap();
    let child = Command::new(core)
        .arg("-d")
        .arg(dir)
        .arg("-f")
        .arg(dir.join("config.yaml"))
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn fixture core");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Fixture { child, log };
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "fixture core did not open :{port}:\n{}",
        fs::read_to_string(&log).unwrap_or_default()
    );
}

/// Every share-link type we parse must produce a proxy the real core accepts (field names, enums,
/// key formats). Unit tests can only check our own idea of the schema; `mihomo -t` is the judge.
#[test]
#[ignore = "needs a mihomo core on this machine"]
fn parsed_links_are_accepted_by_core() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use prism_connect::{config, mihomo, settings::Settings, subscription};

    let uuid = "11111111-2222-3333-4444-555555555555";
    let key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"; // 32 bytes, base64url
    let vmess = STANDARD.encode(format!(
        r#"{{"v":"2","ps":"vmess-ws","add":"198.51.100.20","port":"443","id":"{uuid}","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/v","tls":"tls","sni":"cdn.example.com"}}"#
    ));
    let ss = STANDARD.encode("aes-256-gcm:secret");
    let wg = format!(
        "# wg\n[Interface]\nPrivateKey = {key}=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = {key}=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.30:51820\nPersistentKeepalive = 25\n"
    );
    let awg = wg.replace("MTU = 1280", "MTU = 1280\nJc = 5\nJmin = 50\nJmax = 100\nS1 = 30\nS2 = 40\nH1 = 11111\nH2 = 22222\nH3 = 33333\nH4 = 44444");
    let inputs: Vec<(&str, String)> = vec![
        ("vless reality", format!("vless://{uuid}@198.51.100.1:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={key}&sid=ab12cd34&type=tcp&flow=xtls-rprx-vision#a")),
        ("vless ws tls", format!("vless://{uuid}@198.51.100.2:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws&alpn=h2,http/1.1#a")),
        ("vless grpc", format!("vless://{uuid}@198.51.100.3:443?encryption=none&security=tls&sni=g.example.com&type=grpc&serviceName=svc#a")),
        ("vless httpupgrade", format!("vless://{uuid}@198.51.100.4:443?encryption=none&security=tls&sni=h.example.com&type=httpupgrade&path=%2Fu&host=h.example.com#a")),
        ("vless xhttp reality", format!("vless://{uuid}@198.51.100.5:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={key}&sid=ab&type=xhttp&path=%2Fx&mode=auto#a")),
        ("vmess ws tls", format!("vmess://{vmess}")),
        ("trojan ws", "trojan://pass@198.51.100.6:443?sni=t.example.com&type=ws&path=%2Ft&host=t.example.com#a".into()),
        ("trojan grpc", "trojan://pass@198.51.100.7:443?sni=t.example.com&type=grpc&serviceName=g#a".into()),
        ("ss sip002", format!("ss://{ss}@198.51.100.8:8388#a")),
        ("ss obfs", format!("ss://{ss}@198.51.100.9:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.com#a")),
        ("ss v2ray-plugin", format!("ss://{ss}@198.51.100.10:8388/?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.com%3Bpath%3D%2Fp#a")),
        ("hysteria2 mport", "hysteria2://pw@198.51.100.11:443,20000-30000/?sni=h.example.com&insecure=1&obfs=salamander&obfs-password=x#a".into()),
        ("hysteria2 plain", "hy2://pw@198.51.100.12:443?sni=h.example.com#a".into()),
        ("tuic", format!("tuic://{uuid}:pw@198.51.100.13:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=t.example.com#a")),
        ("anytls", "anytls://pw@198.51.100.14:443?sni=a.example.com#a".into()),
        ("socks5", "socks5://u:p@198.51.100.15:1080#a".into()),
        ("http", "http://u:p@198.51.100.16:8080#a".into()),
        ("wireguard", wg),
        ("amneziawg", awg),
    ];

    let root = std::env::temp_dir().join(format!("prism-e2e-links-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let paths = Paths::new(root.clone());
    paths.ensure().unwrap();
    let core = discover::candidates(&paths)
        .into_iter()
        .next()
        .expect("no mihomo core found on this machine");
    let settings = Settings {
        secret: "x".into(),
        ..Default::default()
    };

    let mut failures = Vec::new();
    for (label, input) in &inputs {
        let norm = match subscription::normalize(input) {
            Ok(n) => n,
            Err(e) => {
                failures.push(format!("{label}: not parsed: {e}"));
                continue;
            }
        };
        let built = config::build(Some(&norm.yaml), None, &settings, &[], false).unwrap();
        fs::write(paths.runtime_config(), &built.yaml).unwrap();
        if let Err(e) = mihomo::validate(Path::new(&core.path), &paths.runtime_dir(), &paths.runtime_config()) {
            failures.push(format!("{label}: core rejected it: {e}\n{}", norm.yaml));
        }
    }
    let _ = fs::remove_dir_all(&root);
    assert!(failures.is_empty(), "{} of {} link types failed:\n{}", failures.len(), inputs.len(), failures.join("\n---\n"));
}

/// Rules written in the editor (every kind, the one-click templates, chain and group targets)
/// must end up as a config the real core loads. GEOSITE/GEOIP names are checked against the
/// geodata that ships with the core.
#[test]
#[ignore = "needs a mihomo core on this machine"]
fn user_rules_are_accepted_by_core() {
    use prism_connect::{chain::Chain, config, mihomo, rules::UserRule, settings::Settings};

    let root = std::env::temp_dir().join(format!("prism-e2e-rules-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let paths = Paths::new(root.clone());
    paths.ensure().unwrap();
    let core = discover::candidates(&paths)
        .into_iter()
        .next()
        .expect("no mihomo core found on this machine");
    discover::ensure_geodata(Path::new(&core.path), &paths);

    let profile = "proxies:
  - {name: A, type: socks5, server: 127.0.0.1, port: 1}
  - {name: B, type: socks5, server: 127.0.0.2, port: 2}
proxy-groups:
  - {name: PROXY, type: select, proxies: [A, B, DIRECT]}
rules:
  - MATCH,PROXY
";
    let chain = Chain {
        id: "c1".into(),
        name: "Duo".into(),
        hops: vec!["A".into(), "B".into()],
        profile: None,
    };
    let rule = |kind: &str, value: &str, target: &str| {
        UserRule {
            enabled: true,
            kind: kind.into(),
            value: value.into(),
            target: target.into(),
            no_resolve: kind.starts_with("IP-CIDR"),
            ..Default::default()
        }
        .normalize()
        .unwrap()
    };
    let rules = vec![
        rule("DOMAIN-SUFFIX", "claude.ai", "@chain:c1"),
        rule("DOMAIN", "www.example.com", "@proxy"),
        rule("DOMAIN-KEYWORD", "youtube", "A"),
        rule("DOMAIN-WILDCARD", "*.cdn.example.com", "DIRECT"),
        rule("DOMAIN-REGEX", "^ad[0-9]+\\.", "REJECT"),
        rule("PROCESS-NAME", "steam.exe", "DIRECT"),
        rule("PROCESS-PATH", "C:\\Games\\game.exe", "DIRECT"),
        rule("IP-CIDR", "203.0.113.0/24", "@proxy"),
        rule("IP-CIDR", "2001:db8::/32", "DIRECT"),
        rule("GEOIP", "RU", "DIRECT"),
        rule("GEOSITE", "category-ru", "DIRECT"),
        rule("GEOSITE", "category-ads-all", "REJECT"),
        rule("GEOSITE", "netflix", "B"),
        rule("DST-PORT", "22", "DIRECT"),
        rule("DST-PORT", "80/8080-8090", "@proxy"),
        rule("NETWORK", "udp", "DIRECT"),
    ];
    let settings = Settings {
        secret: "x".into(),
        ..Default::default()
    };
    for tun in [false, true] {
        let built = config::build_with_rules(Some(profile), None, &settings, std::slice::from_ref(&chain), &rules, tun).unwrap();
        assert!(built.info.rule_issues.is_empty(), "unexpected issues: {:?}", built.info.rule_issues);
        fs::write(paths.runtime_config(), &built.yaml).unwrap();
        mihomo::validate(Path::new(&core.path), &paths.runtime_dir(), &paths.runtime_config())
            .unwrap_or_else(|e| panic!("core rejected the rules (tun={tun}): {e}\n{}", built.yaml));
    }

    // a rule naming a geosite list that does not exist must be refused by the core (the editor rolls it back)
    let bad = vec![rule("GEOSITE", "no-such-list-xyz", "DIRECT")];
    let built = config::build_with_rules(Some(profile), None, &settings, &[], &bad, false).unwrap();
    fs::write(paths.runtime_config(), &built.yaml).unwrap();
    assert!(
        mihomo::validate(Path::new(&core.path), &paths.runtime_dir(), &paths.runtime_config()).is_err(),
        "core unexpectedly accepted an unknown geosite list"
    );
    let _ = fs::remove_dir_all(&root);
}

/// A real provider subscription, end to end: fetch, normalize, build, validate with the core.
/// The URL comes from the environment so no secret ever lands in the repository:
///   $env:PRISM_E2E_SUB='https://...'; cargo test -p prism-connect --test e2e_chain real_subscription -- --ignored --nocapture
#[tokio::test]
#[ignore = "needs PRISM_E2E_SUB (a subscription URL), a mihomo core and internet access"]
async fn real_subscription_is_accepted_by_core() {
    use prism_connect::{config, mihomo, settings::Settings, subscription};

    let Ok(url) = std::env::var("PRISM_E2E_SUB") else {
        println!("PRISM_E2E_SUB is not set: nothing to check");
        return;
    };
    let device = prism_connect::device::info();
    let fetched = subscription::fetch(&url, None, Some(&device)).await.expect("fetch failed");
    let norm = subscription::normalize(&fetched.body).expect("normalize failed");
    println!(
        "title={:?} format={:?} bytes={} nodes={} usage={:?} interval_h={:?}",
        fetched.title,
        norm.source,
        fetched.body.len(),
        norm.nodes,
        fetched.usage,
        fetched.interval_hours
    );
    println!("provider meta: {:?}", fetched.meta);

    let root: serde_yaml::Mapping = serde_yaml::from_str(&norm.yaml).unwrap();
    let mut kinds: std::collections::BTreeMap<String, usize> = Default::default();
    for p in root.get("proxies").and_then(|v| v.as_sequence()).into_iter().flatten() {
        let k = p.get("type").and_then(|t| t.as_str()).unwrap_or("?").to_string();
        *kinds.entry(k).or_default() += 1;
    }
    let count = |k: &str| root.get(k).and_then(|v| v.as_sequence()).map_or(0, |s| s.len());
    println!(
        "proxy types: {kinds:?}; groups={} rules={} providers: proxy={} rule={}",
        count("proxy-groups"),
        count("rules"),
        root.get("proxy-providers").and_then(|v| v.as_mapping()).map_or(0, |m| m.len()),
        root.get("rule-providers").and_then(|v| v.as_mapping()).map_or(0, |m| m.len()),
    );

    let tmp = std::env::temp_dir().join(format!("prism-e2e-sub-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let paths = Paths::new(tmp.clone());
    paths.ensure().unwrap();
    let core = discover::candidates(&paths).into_iter().next().expect("no mihomo core found");
    discover::ensure_geodata(Path::new(&core.path), &paths);
    let settings = Settings {
        secret: "x".into(),
        ..Default::default()
    };
    for tun in [false, true] {
        let built = config::build(Some(&norm.yaml), None, &settings, &[], tun).unwrap();
        fs::write(paths.runtime_config(), &built.yaml).unwrap();
        mihomo::validate(Path::new(&core.path), &paths.runtime_dir(), &paths.runtime_config())
            .unwrap_or_else(|e| panic!("core rejected the config (tun={tun}): {e}"));
        println!("tun={tun}: core accepts the generated config; main groups {:?}", built.info.main_groups);
    }
    let _ = fs::remove_dir_all(&tmp);
}

/// The TUN + DNS + sniffer sections we generate must be accepted by the real core
/// (`mihomo -t` validates without creating the adapter, so this is safe next to other VPNs).
#[test]
#[ignore = "needs a mihomo core on this machine"]
fn generated_tun_config_is_accepted_by_core() {
    use prism_connect::{config, mihomo, settings::Settings};

    let root = std::env::temp_dir().join(format!("prism-e2e-tun-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let paths = Paths::new(root.clone());
    paths.ensure().unwrap();
    let core = discover::candidates(&paths)
        .into_iter()
        .next()
        .expect("no mihomo core found on this machine");

    let profile = "proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1}
  - {name: b, type: socks5, server: 127.0.0.2, port: 2}
proxy-groups:
  - {name: PROXY, type: select, proxies: [a, b, DIRECT]}
rules:
  - MATCH,PROXY
";
    let mut settings = Settings {
        secret: "x".into(),
        ..Default::default()
    };
    settings.bypass.processes = vec!["steam.exe".into()];
    let chain = prism_connect::chain::Chain {
        id: "c".into(),
        name: "Duo".into(),
        hops: vec!["a".into(), "b".into()],
        profile: None,
    };
    for (tun_on, stack) in [(true, "mixed"), (true, "gvisor"), (true, "system"), (false, "mixed")] {
        settings.tun.stack = stack.into();
        let built = config::build(Some(profile), None, &settings, std::slice::from_ref(&chain), tun_on).unwrap();
        fs::write(paths.runtime_config(), &built.yaml).unwrap();
        mihomo::validate(Path::new(&core.path), &paths.runtime_dir(), &paths.runtime_config())
            .unwrap_or_else(|e| panic!("core rejected tun={tun_on} stack={stack}: {e}\n{}", built.yaml));
    }
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "needs a mihomo core on this machine and internet access"]
async fn chain_goes_through_every_hop() {
    let root = std::env::temp_dir().join(format!("prism-e2e-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let paths = Paths::new(root.join("data"));
    let core = discover::candidates(&paths)
        .into_iter()
        .next()
        .expect("no mihomo core found on this machine");
    println!("using core {} {:?}", core.path, core.version);

    let hop_a = start_fixture(Path::new(&core.path), &root.join("fx-a"), "hop-a", 28001, 28099);
    let hop_b = start_fixture(Path::new(&core.path), &root.join("fx-b"), "hop-b", 28002, 28098);

    let m = Manager::new(root.join("data"), Arc::new(|_, _| {})).unwrap();
    m.update_settings(json!({
        "mixed_port": 27897, "controller_port": 28097, "auto_start_core": false, "log_level": "info"
    }))
    .await
    .unwrap();
    m.install_core(Some(core.path.clone())).await.unwrap();
    m.import_profile(
        "socks5://127.0.0.1:28001#hop-a\nsocks5://127.0.0.1:28002#hop-b",
        Some("fixture".into()),
    )
    .await
    .unwrap();
    m.start_core().await.unwrap();

    let chain = m
        .save_chain(Chain {
            name: "Duo".into(),
            hops: vec!["hop-a".into(), "hop-b".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    m.activate_chain(&chain.id).await.unwrap();

    let proxies = m.ctl("GET", "/proxies", None).await.unwrap();
    assert!(proxies["proxies"]["⛓ Duo"].is_object(), "chain exit missing: {proxies}");
    assert_eq!(proxies["proxies"]["PROXY"]["now"], "⛓ Chains");
    assert_eq!(proxies["proxies"]["⛓ Chains"]["now"], "⛓ Duo");

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://127.0.0.1:27897").unwrap())
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let resp = client.get("http://www.gstatic.com/generate_204").send().await.unwrap();
    if resp.status() != 204 {
        println!("---- app core log ----");
        for l in m.log_history() {
            println!("{} {}", l["level"], l["msg"]);
        }
        println!("---- hop-a log ----\n{}", hop_a.log());
        println!("---- hop-b log ----\n{}", hop_b.log());
        panic!("chain request failed with {}", resp.status());
    }

    let delay_path = format!(
        "/proxies/{}/delay?url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=8000",
        utf8_percent_encode("⛓ Duo", NON_ALPHANUMERIC)
    );
    let delay = m.ctl("GET", &delay_path, None).await.unwrap();
    println!("chain delay: {delay}");
    assert!(delay["delay"].as_u64().unwrap_or(0) > 0, "chain delay test failed: {delay}");

    std::thread::sleep(Duration::from_millis(500));
    let (log_a, log_b) = (hop_a.log(), hop_b.log());
    println!("---- hop-a log ----\n{log_a}\n---- hop-b log ----\n{log_b}");
    assert!(
        log_a.contains("--> 127.0.0.1:28002"),
        "hop-a never saw a request for hop-b's address (chain not used)"
    );
    assert!(
        log_b.contains("gstatic.com:80"),
        "hop-b never saw the final destination"
    );
    assert!(
        !log_a.contains("gstatic.com:80"),
        "hop-a saw the final destination: the traffic skipped hop-b"
    );

    // a plain node still works on its own, without the chain
    m.ctl("PUT", "/proxies/PROXY", Some(json!({ "name": "hop-a" }))).await.unwrap();
    let before = hop_a.log().matches("gstatic.com:80").count();
    let resp = client.get("http://www.gstatic.com/generate_204").send().await.unwrap();
    assert_eq!(resp.status(), 204);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        hop_a.log().matches("gstatic.com:80").count() > before,
        "standalone hop-a should reach the destination directly"
    );

    m.shutdown();
    let _ = fs::remove_dir_all(&root);
}
