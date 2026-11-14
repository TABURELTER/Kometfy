//! End-to-end checks against real cores: the Xray helper must really carry the traffic.
//!
//! Needs `xray.exe` (set `PRISM_XRAY`, or install it from the app first) and, for the traffic
//! tests, a mihomo core on this PC. Everything stays on the loopback interface.
//!
//!   $env:PRISM_XRAY='C:\path\to\xray.exe'; cargo test -p prism-connect --test e2e_xray -- --ignored --nocapture --test-threads=1

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use prism_connect::{
    discover,
    dpi::Dpi,
    paths::Paths,
    rules::UserRule,
    settings::XrayMode,
    subscription,
    xray,
    xray_conf::{self, XrayRun},
    Manager,
};
use serde_json::json;

const UUID: &str = "11111111-2222-3333-4444-555555555555";

fn xray_exe() -> PathBuf {
    if let Some(p) = std::env::var_os("PRISM_XRAY") {
        return PathBuf::from(p);
    }
    let p = PathBuf::from(std::env::var_os("APPDATA").unwrap_or_default())
        .join("dev.prismroute.console/connect/core/xray/xray.exe");
    assert!(p.is_file(), "no Xray core: set PRISM_XRAY to the path of xray.exe");
    p
}

fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("prism-e2e-xray-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_port(port: u16) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("nothing listens on :{port}");
}

/// A VLESS server (the far end of the tunnel). Its access log shows what it was asked to open.
fn vless_server(dir: &Path, port: u16, tls: Option<&Path>) -> (Proc, PathBuf) {
    let log = dir.join(format!("access-{port}.log"));
    let mut inbound = json!({
        "listen": "127.0.0.1", "port": port, "protocol": "vless",
        "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
    });
    if let Some(cert) = tls {
        inbound["streamSettings"] = json!({
            "network": "tcp", "security": "tls",
            "tlsSettings": { "certificates": [{
                "certificateFile": cert.join("srv.crt"), "keyFile": cert.join("srv.key") }] },
        });
    }
    let cfg = json!({
        "log": { "loglevel": "warning", "access": log },
        "inbounds": [inbound],
        // Xray's freedom refuses private addresses unless told otherwise
        "outbounds": [{ "protocol": "freedom", "settings": { "finalRules": [{ "action": "allow" }] } }],
    });
    let file = dir.join(format!("server-{port}.json"));
    fs::write(&file, cfg.to_string()).unwrap();
    let child = Command::new(xray_exe())
        .args(["run", "-c"])
        .arg(&file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the server Xray");
    wait_port(port);
    (Proc(child), log)
}

/// Answers every HTTP request with `pong-from-target`.
fn target(port: u16) {
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let body = "pong-from-target";
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            });
        }
    });
}

/// Forwards to `to` and remembers the size of the first reads of every client connection.
fn relay(from: u16, to: u16) -> Arc<Mutex<Vec<Vec<usize>>>> {
    let seen: Arc<Mutex<Vec<Vec<usize>>>> = Arc::default();
    let l = TcpListener::bind(("127.0.0.1", from)).unwrap();
    let log = seen.clone();
    std::thread::spawn(move || {
        for client in l.incoming().flatten() {
            let Ok(server) = TcpStream::connect(("127.0.0.1", to)) else { continue };
            let idx = {
                let mut g = log.lock().unwrap();
                g.push(Vec::new());
                g.len() - 1
            };
            let (mut c_rd, mut s_wr) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            let log = log.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c_rd.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let mut g = log.lock().unwrap();
                    if g[idx].len() < 12 {
                        g[idx].push(n);
                    }
                    drop(g);
                    if s_wr.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
            let (mut s_rd, mut c_wr) = (server, client);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s_rd.read(&mut buf) {
                    if n == 0 || c_wr.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    seen
}

fn http_client(mixed: u16) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{mixed}")).unwrap())
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
}

async fn fetch(mixed: u16, url: &str) -> String {
    let r = http_client(mixed).get(url).header("Connection", "close").send().await.expect("request failed");
    assert_eq!(r.status(), 200);
    r.text().await.unwrap()
}

fn through_proxy_rule(host: &str) -> UserRule {
    UserRule {
        enabled: true,
        kind: "IP-CIDR".into(),
        value: format!("{host}/32"),
        target: "@proxy".into(),
        no_resolve: true,
        ..Default::default()
    }
    .normalize()
    .unwrap()
}

fn manager(dir: &Path) -> Arc<Manager> {
    Manager::new(dir.join("data"), Arc::new(|_, _| {})).unwrap()
}

/// Every protocol and transport the converter knows must be accepted by the real core; a config
/// that is nonsense must not be (else the check proves nothing).
#[test]
#[ignore = "needs an Xray core (PRISM_XRAY)"]
fn generated_configs_are_accepted_by_xray() {
    let key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
    let ss = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode("aes-256-gcm:secret")
    };
    let links = [
        format!("vless://{UUID}@198.51.100.1:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={key}&sid=ab12cd34&type=tcp&flow=xtls-rprx-vision#reality"),
        format!("vless://{UUID}@198.51.100.2:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws&alpn=h2,http/1.1&allowInsecure=1&pcs=438a24fc9cd26eba3079e0baaea8784de564f41eb2f861af81134c268ee2d249#ws"),
        format!("vless://{UUID}@198.51.100.3:443?encryption=none&security=tls&sni=g.example.com&type=grpc&serviceName=svc#grpc"),
        format!("vless://{UUID}@198.51.100.4:443?encryption=none&security=tls&sni=h.example.com&type=httpupgrade&path=%2Fu&host=h.example.com#httpupgrade"),
        format!("vless://{UUID}@198.51.100.5:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={key}&sid=ab&type=xhttp&path=%2Fx&mode=auto#xhttp"),
        "trojan://pass@198.51.100.6:443?sni=t.example.com&type=ws&path=%2Ft&host=t.example.com#trojan-ws".to_string(),
        "trojan://pass@198.51.100.7:443?sni=t.example.com&type=grpc&serviceName=g#trojan-grpc".to_string(),
        format!("ss://{ss}@198.51.100.8:8388#ss"),
        format!("vless://{UUID}@192.168.50.7:80?encryption=none&type=tcp#plain"),
    ];
    let vmess = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(format!(r#"{{"v":"2","ps":"vmess-ws","add":"198.51.100.20","port":"443","id":"{UUID}","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/v","tls":"tls","sni":"cdn.example.com"}}"#))
    };
    let all = format!("{}\nvmess://{vmess}", links.join("\n"));
    let profile = subscription::normalize(&all).unwrap();
    let want = links.len() + 1;

    let dir = temp("accept");
    let exe = xray_exe();
    let version = xray::version(&exe).expect("not an Xray core");
    println!("core {version}");
    let core_tuple = xray::version_tuple(&version);
    let dpi = Dpi { packets: "tlshello".into(), length: "50-100".into(), interval: "5".into(), max_split: "100-200".into() };
    // (label, mode, dpi, core version to pretend)
    type Case = (&'static str, XrayMode, Option<Dpi>, Option<[u32; 3]>);
    let cases: Vec<Case> = vec![
        ("all, no dpi", XrayMode::All, None, core_tuple),
        ("all + dpi (fragment mask)", XrayMode::All, Some(dpi.clone()), core_tuple),
        ("all + dpi (legacy outbound)", XrayMode::All, Some(dpi.clone()), Some([25, 12, 8])),
        ("auto + dpi", XrayMode::Auto, Some(dpi.clone()), core_tuple),
    ];
    for (label, mode, dpi, core) in cases {
        let mut root: serde_yaml::Mapping = serde_yaml::from_str(&profile.yaml).unwrap();
        let run = XrayRun { mode, dpi, core, port: 41999, secret: "pw".into(), log_level: "warning".into(), exe_name: "xray.exe".into(), refused: Default::default() };
        let plan = xray_conf::plan(&mut root, &run);
        assert!(plan.skipped.is_empty(), "{label}: refused {:?}", plan.skipped);
        if mode == XrayMode::All {
            assert_eq!(plan.nodes, want, "{label}");
        } else {
            assert_eq!(plan.nodes, want - 2, "{label}: every server with a handshake, not the plain VLESS and Shadowsocks");
        }
        let file = dir.join("cfg.json");
        fs::write(&file, &plan.json).unwrap();
        xray::validate(&exe, &file).unwrap_or_else(|e| panic!("{label}: Xray rejected the config: {e}\n{}", plan.json));
        println!("{label}: {} servers accepted ({} cut up)", plan.nodes, plan.dpi_nodes);
    }

    fs::write(dir.join("bad.json"), r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"x","port":1,"users":[{"id":"not-a-uuid"}]}]}}]}"#).unwrap();
    assert!(xray::validate(&exe, &dir.join("bad.json")).is_err(), "validate() must fail on a broken config");
    let _ = fs::remove_dir_all(dir);
}

/// mihomo -> SOCKS5 shim -> Xray -> VLESS -> a second Xray -> the target, with a reload and a
/// switch of the mode in between.
#[tokio::test]
#[ignore = "needs a mihomo core and an Xray core (PRISM_XRAY)"]
async fn traffic_flows_mihomo_to_xray_to_server() {
    let dir = temp("flow");
    let paths = Paths::new(dir.join("data"));
    let core = discover::candidates(&paths).into_iter().next().expect("no mihomo core found on this machine");
    println!("mihomo {:?} / xray {:?}", core.version, xray::version(&xray_exe()));

    target(29101);
    let (_server, access) = vless_server(&dir, 29102, None);

    let m = manager(&dir);
    m.update_settings(json!({ "mixed_port": 29197, "controller_port": 29198, "auto_start_core": false, "xray": { "mode": "all" } }))
        .await
        .unwrap();
    m.install_core(Some(core.path.clone())).await.unwrap();
    m.install_xray(xray_exe().display().to_string()).await.unwrap();
    m.import_profile(&format!("vless://{UUID}@127.0.0.1:29102?encryption=none&security=none&type=tcp#vless-local"), Some("fx".into()))
        .await
        .unwrap();
    m.set_rules(vec![through_proxy_rule("127.0.0.1")]).await.unwrap();
    m.start_core().await.unwrap();

    let st = m.state();
    assert!(st.xray.running, "the helper should be running: {:?}", st.xray);
    assert_eq!(st.xray.nodes, 1);
    assert_eq!(st.xray.kinds.get("vless-local").map(String::as_str), Some("vless"));
    assert_eq!(st.xray.issue, None);
    let px = m.ctl("GET", "/proxies", None).await.unwrap();
    assert_eq!(px["proxies"]["vless-local"]["type"], "Socks5", "mihomo sees the shim, not the real server");

    assert_eq!(fetch(29197, "http://127.0.0.1:29101/a").await, "pong-from-target");
    std::thread::sleep(Duration::from_millis(300));
    let log = fs::read_to_string(&access).unwrap_or_default();
    assert!(log.contains("127.0.0.1:29101"), "the far Xray never saw the request:\n{log}\n{:?}", m.log_history());

    let delay = m
        .ctl("GET", "/proxies/vless-local/delay?url=http%3A%2F%2F127.0.0.1%3A29101%2F&timeout=5000", None)
        .await
        .unwrap();
    assert!(delay["delay"].as_u64().unwrap_or(0) > 0, "latency test through Xray failed: {delay}");

    // Xray off: the same server is dialed by mihomo itself and the helper is gone
    m.update_settings(json!({ "xray": { "mode": "off" } })).await.unwrap();
    let st = m.state();
    assert!(!st.xray.running && st.xray.nodes == 0);
    let before = fs::read_to_string(&access).unwrap_or_default().matches("29101").count();
    assert_eq!(fetch(29197, "http://127.0.0.1:29101/b").await, "pong-from-target");
    std::thread::sleep(Duration::from_millis(300));
    assert!(fs::read_to_string(&access).unwrap_or_default().matches("29101").count() > before);
    let px = m.ctl("GET", "/proxies", None).await.unwrap();
    assert_eq!(px["proxies"]["vless-local"]["type"], "Vless");

    // and back
    m.update_settings(json!({ "xray": { "mode": "all" } })).await.unwrap();
    assert!(m.state().xray.running);
    assert_eq!(fetch(29197, "http://127.0.0.1:29101/c").await, "pong-from-target");

    m.shutdown();
    std::thread::sleep(Duration::from_millis(300));
    assert!(TcpStream::connect(("127.0.0.1", 29197)).is_err(), "the core outlived shutdown");
    let _ = fs::remove_dir_all(dir);
}

/// The TLS handshake of a server run by Xray reaches the wire in pieces; without DPI bypass mihomo
/// sends it in one piece.
#[tokio::test]
#[ignore = "needs a mihomo core and an Xray core (PRISM_XRAY)"]
async fn dpi_bypass_cuts_the_client_hello() {
    let dir = temp("dpi");
    let paths = Paths::new(dir.join("data"));
    let core = discover::candidates(&paths).into_iter().next().expect("no mihomo core found on this machine");
    let exe = xray_exe();

    // a self-signed certificate for the far end
    let certs = dir.join("certs");
    fs::create_dir_all(&certs).unwrap();
    let out = Command::new(&exe).args(["tls", "cert", "-domain=localhost"]).arg(format!("-file={}", certs.join("srv").display())).output().unwrap();
    assert!(out.status.success() && certs.join("srv.crt").is_file(), "xray tls cert failed");
    // Xray no longer skips certificate checks; a self-signed server is trusted by its hash instead
    let hash = Command::new(&exe).args(["tls", "hash", "-cert"]).arg(certs.join("srv.crt")).output().unwrap();
    let pin = String::from_utf8_lossy(&hash.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Leaf SHA256:").map(|h| h.trim().to_string()))
        .expect("xray tls hash printed no pin");

    target(29111);
    let (_server, _access) = vless_server(&dir, 29112, Some(&certs));
    let seen = relay(29113, 29112);

    let m = manager(&dir);
    m.update_settings(json!({
        "mixed_port": 29297, "controller_port": 29298, "auto_start_core": false,
        "xray": { "mode": "auto" },
        "dpi": { "enabled": true, "packets": "tlshello", "length": "40-60", "interval": "10-20" },
    }))
    .await
    .unwrap();
    m.install_core(Some(core.path.clone())).await.unwrap();
    m.install_xray(exe.display().to_string()).await.unwrap();
    m.import_profile(
        &format!("vless://{UUID}@127.0.0.1:29113?encryption=none&security=tls&sni=localhost&allowInsecure=1&pcs={pin}&type=tcp#tls-local"),
        Some("fx".into()),
    )
    .await
    .unwrap();
    m.set_rules(vec![through_proxy_rule("127.0.0.1")]).await.unwrap();
    m.start_core().await.unwrap();

    let st = m.state();
    assert!(st.xray.running, "{:?} / {:?}", st.xray, m.log_history());
    assert_eq!((st.xray.nodes, st.xray.dpi_nodes), (1, 1));
    assert_eq!(st.xray.dpi_source, "manual");

    assert_eq!(fetch(29297, "http://127.0.0.1:29111/x").await, "pong-from-target");
    let cut = seen.lock().unwrap().first().cloned().expect("the relay saw no connection");
    println!("with DPI bypass the first writes were {cut:?} bytes");
    assert!(cut[0] <= 80, "the first piece of the handshake is {} bytes: {cut:?}", cut[0]);
    assert!(cut.len() >= 4, "the handshake was not cut up: {cut:?}");

    // bypass off: in Auto mode nothing needs Xray any more and mihomo speaks TLS itself
    m.update_settings(json!({ "dpi": { "enabled": false } })).await.unwrap();
    assert!(!m.state().xray.running);
    assert_eq!(fetch(29297, "http://127.0.0.1:29111/y").await, "pong-from-target");
    let whole = seen.lock().unwrap().get(1).cloned().expect("no second connection");
    println!("without it: {whole:?}");
    assert!(whole[0] > 100, "the handshake should be one piece now: {whole:?}");

    m.shutdown();
    let _ = fs::remove_dir_all(dir);
}
