//! Telegram bridge: a local MTProto proxy that carries Telegram Desktop's traffic to Telegram's own
//! web gateways (`wss://kwsN.web.telegram.org/apiws`, the transport Telegram Web uses) instead of
//! the plain TCP ports of the data centres. The idea comes from Flowseal/tg-ws-proxy (MIT).
//!
//! Telegram connects to 127.0.0.1 with a `dd` secret. Its stream is obfuscated2: the proxy
//! decrypts it with the secret, encrypts it again for the gateway and sends every MTProto packet
//! as its own WebSocket frame. If no gateway answers, the data centre is reached over plain TCP.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aes::cipher::{KeyIvInit, StreamCipher};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};
use tokio_tungstenite::WebSocketStream;
use tracing::{info, warn};

use crate::error::{Error, Result};

type Ctr = ctr::Ctr128BE<aes::Aes256>;
type Ws = WebSocketStream<TlsStream<TcpStream>>;

const ABRIDGED: [u8; 4] = [0xef; 4];
const TAGS: [[u8; 4]; 3] = [ABRIDGED, [0xee; 4], [0xdd; 4]];
/// The DC2 and DC4 gateways answer here (both in Amsterdam); the others are looked up by name.
const GATEWAY_2_4: &str = "149.154.167.220";
/// Plain TCP addresses of the data centres, the last resort.
const DC_IPS: [(u16, &str); 6] = [
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
    (203, "91.105.192.100"),
];

// The Cloudflare base domains that ship with the app (the project's own, kwsN records as in docs/TELEGRAM_CF.md)
// are tried after the user's own. The app build supplies them (`crate::builtin`); the open core has none.

/// A running bridge. Dropping it closes the port and every connection.
pub struct Bridge {
    pub port: u16,
    pub secret: String,
    /// The Cloudflare base domains this bridge was started with.
    pub cf_domains: Vec<String>,
    task: JoinHandle<()>,
    seen: Arc<Seen>,
}

/// What the bridge saw of its clients, for the "old link" hint.
#[derive(Default)]
struct Seen {
    /// When (unix seconds) a client last came with another secret: Telegram has an old link somewhere.
    stale_at: AtomicU64,
    /// When a client last came with the right secret.
    good_at: AtomicU64,
    /// Connections with the right secret open now.
    live: AtomicUsize,
}

impl Seen {
    fn stale(&self, now: u64) -> bool {
        let (stale, good) = (self.stale_at.load(Relaxed), self.good_at.load(Relaxed));
        stale > 0 && now.saturating_sub(stale) < 90 && self.live.load(Relaxed) == 0 && now.saturating_sub(good) > 90
    }
}

/// Counts one open connection with the right secret while it lives.
struct Live<'a>(&'a AtomicUsize);

impl Drop for Live<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Bridge {
    pub async fn start(port: u16, secret_hex: &str, cf_domains: &[String]) -> Result<Self> {
        let secret = parse_secret(secret_hex)?;
        let cf: Arc<[String]> = cf_domains
            .iter()
            .cloned()
            .chain(crate::builtin::tg_domains())
            .collect::<Vec<_>>()
            .into();
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| Error::msg(format!("port {port} is busy: {e}")))?;
        info!("telegram bridge listens on 127.0.0.1:{port}");
        let seen = Arc::new(Seen::default());
        let shared = seen.clone();
        let task = tokio::spawn(async move {
            // dropping the set (when the task is aborted) aborts every connection too
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    r = listener.accept() => match r {
                        Ok((sock, peer)) => {
                            let seen = shared.clone();
                            let cf = cf.clone();
                            clients.spawn(async move {
                                match serve(sock, &secret, &seen, &cf).await {
                                    Err(Error::Msg(m)) if m == WRONG_SECRET => {
                                        // Telegram retries every few seconds: one line in a minute is enough
                                        let now = unix_now();
                                        if now.saturating_sub(seen.stale_at.swap(now, Relaxed)) > 60 {
                                            warn!("telegram bridge: Telegram uses an old link (another secret); apply the link again");
                                        }
                                    }
                                    Err(e) => warn!("telegram bridge {peer}: {e}"),
                                    Ok(()) => {}
                                }
                            });
                        }
                        Err(e) => {
                            warn!("telegram bridge accept: {e}");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    },
                    Some(_) = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        Ok(Self { port, secret: secret_hex.to_string(), cf_domains: cf_domains.to_vec(), task, seen })
    }

    /// Telegram came with an old link in the last minute and a half, and nothing goes through with the
    /// right one. Telegram also checks the other proxies of its list now and then; while it works through
    /// the bridge, an old entry there does no harm.
    pub fn stale_link(&self) -> bool {
        self.seen.stale(unix_now())
    }

    /// Opens Telegram's "add proxy" dialog with everything filled in.
    pub fn link(&self) -> String {
        link(self.port, &self.secret)
    }
}

const WRONG_SECRET: &str = "wrong secret or protocol";

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn link(port: u16, secret_hex: &str) -> String {
    format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{secret_hex}")
}

/// 16 random bytes as hex: the secret Telegram must present to this bridge.
pub fn new_secret() -> String {
    let mut b = [0u8; 16];
    random(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_secret(hex: &str) -> Result<[u8; 16]> {
    let bad = || Error::msg("the Telegram bridge secret must be 32 hex characters");
    if hex.len() != 32 || !hex.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("the system random source failed");
}

fn ctr(key: &[u8], iv: &[u8]) -> Ctr {
    Ctr::new_from_slices(key, iv).expect("32-byte key and 16-byte iv")
}

fn reversed(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

/// What the client's first 64 bytes say, and the ciphers for its side of the connection.
struct Hello {
    /// Data centre, negative for media. Test data centres are 10000 higher.
    idx: i16,
    tag: [u8; 4],
    /// Decrypts what the client sends, already past the 64 bytes.
    dec: Ctr,
    /// Encrypts what goes back to the client.
    enc: Ctr,
}

fn client_hello(init: &[u8; 64], secret: &[u8]) -> Option<Hello> {
    let key = |pre: &[u8]| Sha256::new().chain_update(pre).chain_update(secret).finalize();
    let mut dec = ctr(&key(&init[8..40]), &init[40..56]);
    let mut plain = *init;
    dec.apply_keystream(&mut plain);
    let tag: [u8; 4] = plain[56..60].try_into().ok()?;
    if !TAGS.contains(&tag) {
        return None;
    }
    let rev = reversed(&init[8..56]);
    Some(Hello {
        idx: i16::from_le_bytes([plain[60], plain[61]]),
        tag,
        dec,
        enc: ctr(&key(&rev[..32]), &rev[32..48]),
    })
}

/// A fresh obfuscated2 start for Telegram's side (no secret there) and its two ciphers:
/// (bytes to send first, encrypts towards Telegram, decrypts what Telegram sends).
fn relay_init(tag: [u8; 4], idx: i16) -> ([u8; 64], Ctr, Ctr) {
    let mut rnd = [0u8; 64];
    loop {
        random(&mut rnd);
        // these starts would look like another protocol to the server
        let starts: [&[u8]; 7] = [b"HEAD", b"POST", b"GET ", b"OPTI", &[0xee; 4], &[0xdd; 4], &[0x16, 3, 1, 2]];
        if rnd[0] != 0xef && !starts.contains(&&rnd[..4]) && rnd[4..8] != [0; 4] {
            break;
        }
    }
    let mut enc = ctr(&rnd[8..40], &rnd[40..56]);
    let mut stream = rnd;
    enc.apply_keystream(&mut stream);
    let mut tail = [0u8; 8];
    tail[..4].copy_from_slice(&tag);
    tail[4..6].copy_from_slice(&idx.to_le_bytes());
    random(&mut tail[6..]);
    for i in 0..8 {
        // stream ^ rnd is the key stream here: the server decrypts these bytes to `tail`
        rnd[56 + i] ^= tail[i] ^ stream[56 + i];
    }
    let rev = reversed(&rnd[8..56]);
    (rnd, enc, ctr(&rev[..32], &rev[32..48]))
}

/// What Telegram Desktop does: a random start with the tag and the DC hidden at its end.
/// Returns (the start, encrypts towards the proxy, decrypts the proxy's answers).
fn telegram_start(secret: &[u8], tag: [u8; 4], idx: i16) -> ([u8; 64], Ctr, Ctr) {
    let key = |pre: &[u8]| Sha256::new().chain_update(pre).chain_update(secret).finalize();
    let mut init = [0u8; 64];
    random(&mut init);
    let mut enc = ctr(&key(&init[8..40]), &init[40..56]);
    let mut stream = init;
    enc.apply_keystream(&mut stream);
    let mut plain = [0u8; 8];
    plain[..4].copy_from_slice(&tag);
    plain[4..6].copy_from_slice(&idx.to_le_bytes());
    for i in 0..8 {
        init[56 + i] ^= plain[i] ^ stream[56 + i];
    }
    let rev = reversed(&init[8..56]);
    (init, enc, ctr(&key(&rev[..32]), &rev[32..48]))
}

/// Ask Telegram's DC2 for `resPQ` through a running bridge, the way Telegram Desktop talks to it
/// (`dd` secret, padded intermediate transport). Returns how long the answer took.
pub async fn self_test(port: u16, secret_hex: &str) -> Result<Duration> {
    let secret = parse_secret(secret_hex)?;
    let started = std::time::Instant::now();
    let run = async {
        let (init, mut tx, mut rx) = telegram_start(&secret, [0xdd; 4], 2);
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await?;
        sock.write_all(&init).await?;
        // an unencrypted message: auth_key_id 0, msg_id, length 20, req_pq_multi, nonce
        let msg_id = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() << 32;
        let mut pkt = 40u32.to_le_bytes().to_vec();
        pkt.extend_from_slice(&[0; 8]);
        pkt.extend_from_slice(&msg_id.to_le_bytes());
        pkt.extend_from_slice(&20u32.to_le_bytes());
        pkt.extend_from_slice(&0xbe7e_8ef1u32.to_le_bytes());
        let mut nonce = [0u8; 16];
        random(&mut nonce);
        pkt.extend_from_slice(&nonce);
        tx.apply_keystream(&mut pkt);
        sock.write_all(&pkt).await?;
        let mut head = [0u8; 28];
        sock.read_exact(&mut head).await?;
        rx.apply_keystream(&mut head);
        if u32::from_le_bytes([head[24], head[25], head[26], head[27]]) != 0x0516_2463 {
            return Err(Error::msg("Telegram answered something unexpected"));
        }
        Ok::<_, Error>(())
    };
    match timeout(Duration::from_secs(15), run).await {
        Ok(Ok(())) => Ok(started.elapsed()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::msg("Telegram did not answer through the bridge in 15 seconds")),
    }
}

/// Cuts the stream into MTProto transport packets: the gateway wants one packet per frame.
struct Splitter {
    abridged: bool,
    cipher: Vec<u8>,
    plain: Vec<u8>,
    /// An unknown length was seen: pass the rest through as it comes.
    off: bool,
}

impl Splitter {
    fn new(tag: [u8; 4]) -> Self {
        Self { abridged: tag == ABRIDGED, cipher: vec![], plain: vec![], off: false }
    }

    fn split(&mut self, cipher: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if self.off {
            return vec![cipher.to_vec()];
        }
        self.cipher.extend_from_slice(cipher);
        self.plain.extend_from_slice(plain);
        let mut out = vec![];
        let mut at = 0;
        while at < self.cipher.len() {
            match self.next_len(at) {
                None => break,
                Some(0) => {
                    out.push(self.cipher[at..].to_vec());
                    at = self.cipher.len();
                    self.off = true;
                }
                Some(n) => {
                    out.push(self.cipher[at..at + n].to_vec());
                    at += n;
                }
            }
        }
        self.cipher.drain(..at);
        self.plain.drain(..at);
        out
    }

    fn flush(&mut self) -> Option<Vec<u8>> {
        self.plain.clear();
        (!self.cipher.is_empty()).then(|| std::mem::take(&mut self.cipher))
    }

    /// Length of the packet that starts at `at`; None: not all of it is here yet; 0: unknown.
    fn next_len(&self, at: usize) -> Option<usize> {
        let p = &self.plain[at..];
        let (head, body) = if self.abridged {
            let first = *p.first()?;
            if first & 0x7f == 0x7f {
                if p.len() < 4 {
                    return None;
                }
                (4, u32::from_le_bytes([p[1], p[2], p[3], 0]) as usize * 4)
            } else {
                (1, (first & 0x7f) as usize * 4)
            }
        } else {
            if p.len() < 4 {
                return None;
            }
            (4, (u32::from_le_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff) as usize)
        };
        if body == 0 {
            return Some(0);
        }
        (p.len() >= head + body).then_some(head + body)
    }
}

async fn serve(mut client: TcpStream, secret: &[u8; 16], seen: &Seen, cf: &[String]) -> Result<()> {
    client.set_nodelay(true)?;
    let mut init = [0u8; 64];
    timeout(Duration::from_secs(10), client.read_exact(&mut init))
        .await
        .map_err(|_| Error::msg("no handshake"))??;
    let hello = client_hello(&init, secret).ok_or_else(|| Error::msg(WRONG_SECRET))?;
    seen.good_at.store(unix_now(), Relaxed);
    seen.live.fetch_add(1, Relaxed);
    let _live = Live(&seen.live);
    let media = hello.idx < 0;
    let raw = hello.idx.unsigned_abs();
    let test = raw >= 10_000;
    let dc = raw % 10_000;
    let out_idx = if media { -(dc as i16) } else { dc as i16 };
    let (relay, tg_enc, tg_dec) = relay_init(hello.tag, out_idx);

    if let Some((ws, via)) = gateway(dc, media, test, cf).await {
        info!("telegram bridge: DC{dc}{} over {via}", if media { " media" } else { "" });
        return relay_ws(client, ws, relay, hello, tg_enc, tg_dec).await;
    }
    let ip = DC_IPS.iter().find(|(d, _)| *d == dc).map(|(_, ip)| *ip).filter(|_| !test);
    let Some(ip) = ip else { return Err(Error::msg(format!("no way to DC{dc}"))) };
    info!("telegram bridge: DC{dc} over plain TCP (no web gateway answered)");
    let mut up = timeout(Duration::from_secs(10), TcpStream::connect((ip, 443)))
        .await
        .map_err(|_| Error::msg("the data centre does not answer"))??;
    up.set_nodelay(true)?;
    up.write_all(&relay).await?;
    let (Hello { mut dec, mut enc, .. }, mut tg_enc, mut tg_dec) = (hello, tg_enc, tg_dec);
    let (crd, cwr) = client.into_split();
    let (urd, uwr) = up.into_split();
    tokio::select! {
        r = pump(crd, uwr, move |b| { dec.apply_keystream(b); tg_enc.apply_keystream(b); }) => r,
        r = pump(urd, cwr, move |b| { tg_dec.apply_keystream(b); enc.apply_keystream(b); }) => r,
    }
}

async fn pump(mut from: impl AsyncRead + Unpin, mut to: impl AsyncWrite + Unpin, mut f: impl FnMut(&mut [u8])) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        f(&mut buf[..n]);
        to.write_all(&buf[..n]).await?;
    }
}

async fn relay_ws(client: TcpStream, ws: Ws, relay: [u8; 64], hello: Hello, mut tg_enc: Ctr, mut tg_dec: Ctr) -> Result<()> {
    let Hello { mut dec, mut enc, tag, .. } = hello;
    let ws_err = |e: tokio_tungstenite::tungstenite::Error| Error::msg(format!("gateway: {e}"));
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::binary(relay.to_vec())).await.map_err(ws_err)?;
    let (mut rd, mut wr) = client.into_split();
    let up = async move {
        let mut split = Splitter::new(tag);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                if let Some(rest) = split.flush() {
                    sink.send(Message::binary(rest)).await.map_err(ws_err)?;
                }
                let _ = sink.close().await;
                return Ok::<_, Error>(());
            }
            let chunk = &mut buf[..n];
            dec.apply_keystream(chunk);
            let plain = chunk.to_vec();
            tg_enc.apply_keystream(chunk);
            for part in split.split(chunk, &plain) {
                sink.feed(Message::binary(part)).await.map_err(ws_err)?;
            }
            sink.flush().await.map_err(ws_err)?;
        }
    };
    let down = async move {
        while let Some(msg) = stream.next().await {
            match msg.map_err(ws_err)? {
                Message::Binary(data) => {
                    let mut data = data.to_vec();
                    tg_dec.apply_keystream(&mut data);
                    enc.apply_keystream(&mut data);
                    wr.write_all(&data).await?;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok(())
    };
    tokio::select! { r = up => r, r = down => r }
}

/// A WebSocket to the data centre's web gateway, or None when none answers.
/// When Telegram's own gateway for a data centre last failed: for ten minutes after that, connections
/// go to Cloudflare first instead of waiting for the blocked gateway every time.
fn blocked() -> &'static Mutex<HashMap<u16, Instant>> {
    static AT: OnceLock<Mutex<HashMap<u16, Instant>>> = OnceLock::new();
    AT.get_or_init(Default::default)
}

const BLOCKED_FOR: Duration = Duration::from_secs(600);

/// When a Cloudflare name last failed. For a short while after that, connections skip it and go on at once: when
/// the network itself is down, every new connection of the Telegram app waited 10 seconds for it, and hundreds of
/// them piled up (about 300 a minute in the log), each holding a socket while nothing could get through.
fn cf_down() -> &'static Mutex<HashMap<String, Instant>> {
    static AT: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    AT.get_or_init(Default::default)
}

const CF_DOWN_FOR: Duration = Duration::from_secs(45);

/// A WebSocket to data centre `dc`: Telegram's own gateway, then `kwsN.<domain>` through each Cloudflare
/// domain (Cloudflare forwards it to the data centre, so it works where Telegram's addresses are blocked).
/// Returns the socket and what carried it, for the log.
async fn gateway(dc: u16, media: bool, test: bool, cf: &[String]) -> Option<(Ws, String)> {
    let n = if dc == 203 { 2 } else { dc };
    let path = if test { "/apiws_test" } else { "/apiws" };
    let recently_blocked = blocked().lock().unwrap().get(&n).is_some_and(|at| at.elapsed() < BLOCKED_FOR);
    // test data centres are not behind the Cloudflare domains
    let cf_hosts: Vec<String> = if test { vec![] } else { cf.iter().map(|base| format!("kws{n}.{base}")).collect() };
    if !recently_blocked || cf_hosts.is_empty() {
        let mut hosts = vec![];
        if media {
            hosts.push(format!("kws{n}-1.web.telegram.org"));
        }
        hosts.push(format!("kws{n}.web.telegram.org"));
        for host in hosts {
            let addr = if matches!(n, 2 | 4) { format!("{GATEWAY_2_4}:443") } else { format!("{host}:443") };
            match timeout(Duration::from_secs(8), open_ws(&addr, &host, path)).await {
                Ok(Ok(ws)) => {
                    blocked().lock().unwrap().remove(&n);
                    return Some((ws, "the web gateway".into()));
                }
                Ok(Err(e)) => warn!("telegram gateway {host}: {e}"),
                Err(_) => warn!("telegram gateway {host}: timed out"),
            }
        }
        blocked().lock().unwrap().insert(n, Instant::now());
    }
    for host in cf_hosts {
        if cf_down().lock().unwrap().get(&host).is_some_and(|at| at.elapsed() < CF_DOWN_FOR) {
            continue;
        }
        match timeout(Duration::from_secs(10), open_ws(&format!("{host}:443"), &host, path)).await {
            Ok(Ok(ws)) => {
                cf_down().lock().unwrap().remove(&host);
                return Some((ws, format!("Cloudflare ({host})")));
            }
            Ok(Err(e)) => warn!("telegram over Cloudflare {host}: {e}"),
            Err(_) => warn!("telegram over Cloudflare {host}: timed out"),
        }
        cf_down().lock().unwrap().insert(host, Instant::now());
    }
    None
}

async fn open_ws(addr: &str, host: &str, path: &str) -> Result<Ws> {
    let (to, port) = addr.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse().ok()?))).ok_or_else(|| Error::msg(format!("bad address {addr}")))?;
    // the Cloudflare names are young: some public DNS services answer nothing for them
    let tcp = TcpStream::connect(&crate::doh::lookup(to, port).await?[..]).await?;
    tcp.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| Error::msg(e.to_string()))?;
    let tls = tls().connect(name, tcp).await?;
    let mut req = format!("wss://{host}{path}").into_client_request().map_err(|e| Error::msg(e.to_string()))?;
    req.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static("binary"));
    let (ws, _) = tokio_tungstenite::client_async(req, tls).await.map_err(|e| Error::msg(e.to_string()))?;
    Ok(ws)
}

/// Ordinary certificate checks against the public roots.
fn tls() -> TlsConnector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    });
    TlsConnector::from(config.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [7; 16];

    #[test]
    fn the_proxy_reads_what_telegram_hid() {
        let (init, mut tx, mut rx) = telegram_start(&SECRET, [0xdd; 4], -4);
        let mut h = client_hello(&init, &SECRET).unwrap();
        assert_eq!((h.idx, h.tag), (-4, [0xdd; 4]));
        // both directions line up after the start
        let mut msg = *b"hello telegram";
        tx.apply_keystream(&mut msg);
        h.dec.apply_keystream(&mut msg);
        assert_eq!(&msg, b"hello telegram");
        let mut back = *b"answer";
        h.enc.apply_keystream(&mut back);
        rx.apply_keystream(&mut back);
        assert_eq!(&back, b"answer");
        assert!(client_hello(&init, &[8; 16]).is_none(), "another secret must not pass");
    }

    #[test]
    fn the_server_reads_the_relay_start() {
        let (init, _, _) = relay_init([0xef; 4], 2);
        // the server side: no secret, the key is the raw bytes
        let mut plain = init;
        ctr(&init[8..40], &init[40..56]).apply_keystream(&mut plain);
        assert_eq!(&plain[56..60], &[0xef; 4]);
        assert_eq!(i16::from_le_bytes([plain[60], plain[61]]), 2);
        assert_ne!(init[0], 0xef);
    }

    #[test]
    fn packets_are_cut_where_they_end() {
        // intermediate: 4-byte length, then the body; arrives in odd pieces
        let mut wire = vec![];
        for body in [vec![1u8; 8], vec![2u8; 12]] {
            wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
            wire.extend_from_slice(&body);
        }
        let mut s = Splitter::new([0xee; 4]);
        let mut parts = s.split(&wire[..5], &wire[..5]);
        parts.extend(s.split(&wire[5..], &wire[5..]));
        assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), vec![12, 16]);
        assert!(s.flush().is_none());

        // abridged: one byte of length/4, or 0x7f and three bytes
        let mut wire = vec![2u8];
        wire.extend_from_slice(&[9; 8]);
        wire.extend_from_slice(&[0x7f, 1, 0, 0]);
        wire.extend_from_slice(&[5; 4]);
        let mut s = Splitter::new([0xef; 4]);
        assert_eq!(s.split(&wire, &wire).iter().map(Vec::len).collect::<Vec<_>>(), vec![9, 8]);
    }

    #[test]
    fn the_old_link_hint_stays_only_while_nothing_works() {
        let seen = Seen::default();
        assert!(!seen.stale(1000));
        seen.stale_at.store(1000, Relaxed);
        assert!(seen.stale(1010));
        assert!(!seen.stale(1100), "the hint goes after a minute and a half");
        {
            seen.live.fetch_add(1, Relaxed);
            let _open = Live(&seen.live);
            assert!(!seen.stale(1010), "Telegram works through the bridge right now");
        }
        assert!(seen.stale(1010));
        seen.good_at.store(1005, Relaxed);
        assert!(!seen.stale(1010), "a client with the right link came a moment ago");
    }

    #[test]
    fn link_and_secret() {
        let s = new_secret();
        assert_eq!(s.len(), 32);
        assert!(parse_secret(&s).is_ok());
        assert!(parse_secret("zz").is_err());
        assert_eq!(link(1443, "ab"), "tg://proxy?server=127.0.0.1&port=1443&secret=ddab");
    }

    /// Through the bridge to the real DC2: `req_pq_multi` must come back as `resPQ`.
    /// Needs the Internet: cargo test -p prism-connect tgbridge -- --ignored
    #[tokio::test]
    #[ignore]
    async fn telegram_answers_through_the_bridge() {
        if let Err(e) = open_ws(&format!("{GATEWAY_2_4}:443"), "kws2.web.telegram.org", "/apiws").await {
            panic!("the DC2 web gateway must answer: {e}");
        }
        let hex: String = SECRET.iter().map(|x| format!("{x:02x}")).collect();
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let _bridge = Bridge::start(port, &hex, &[]).await.unwrap();
        let took = self_test(port, &hex).await.unwrap();
        assert!(took < Duration::from_secs(15));

        let (init, mut tx, mut rx) = telegram_start(&SECRET, [0xef; 4], 2);
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(&init).await.unwrap();
        // an unencrypted message: auth_key_id 0, msg_id, length 20, req_pq_multi, nonce
        let msg_id = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() << 32;
        let mut pkt = vec![10u8];
        pkt.extend_from_slice(&[0; 8]);
        pkt.extend_from_slice(&msg_id.to_le_bytes());
        pkt.extend_from_slice(&20u32.to_le_bytes());
        pkt.extend_from_slice(&0xbe7e_8ef1u32.to_le_bytes());
        pkt.extend_from_slice(&[0x42; 16]);
        tx.apply_keystream(&mut pkt);
        sock.write_all(&pkt).await.unwrap();

        let mut head = [0u8; 25];
        timeout(Duration::from_secs(15), sock.read_exact(&mut head)).await.unwrap().unwrap();
        rx.apply_keystream(&mut head);
        assert_eq!(u32::from_le_bytes(head[21..25].try_into().unwrap()), 0x0516_2463, "resPQ");
    }
}
