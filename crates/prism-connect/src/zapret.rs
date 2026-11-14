//! Zapret: the free bypass for YouTube and Discord, without a VPN.
//!
//! The engine is `winws.exe` from bol-van/zapret with the WinDivert driver, in the build and with the
//! strategies of Flowseal/zapret-discord-youtube (both MIT). Nothing is bundled: the release zip is
//! downloaded from GitHub on request and checked against the SHA-256 GitHub publishes for it.
//! A "strategy" is one `general*.bat` of that release; only the arguments of its `winws.exe` call are
//! used, with the variables of the batch file filled in here. No batch file and no console is run.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::util::write_atomic;

pub const API: &str = "https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest";
/// The release zip is about 1.5 MB; anything far larger is not what we asked for.
const MAX_ZIP: u64 = 32 * 1024 * 1024;
/// Ports of the game filter when it is on; "12" (a port nobody uses) keeps it off, as in the release.
const GAME_ON: &str = "1024-65535";
const GAME_OFF: &str = "12";

/// A YouTube thumbnail of about 20 KB: past the 16 KB where some providers freeze a connection.
const THUMB: &str = "https://i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg";
/// Each check is tried this many times in a row, as ByeByeDPI's tester does: an auto strategy (`-A`) learns
/// from a failed attempt and gets the next one through, the way a real app's retry would.
const TRIES: u32 = 3;
/// A YouTube page that has been up since 2005. It names the video server this viewer is sent to.
const WATCH: &str = "https://www.youtube.com/watch?v=jNQXAC9IVRw";
/// Used when the page names no video server.
const VIDEO_FALLBACK: &str = "redirector.googlevideo.com";

pub struct Release {
    pub tag: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
}

/// The `.zip` asset of the latest release, with its published checksum. A release without one is refused:
/// the program in it runs with administrator rights.
pub fn pick(release: &Value) -> Result<Release> {
    let tag = release.get("tag_name").and_then(Value::as_str).ok_or_else(|| Error::msg("the release has no version"))?;
    let asset = release
        .get("assets")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find(|x| x.get("name").and_then(Value::as_str).is_some_and(|n| n.ends_with(".zip"))))
        .ok_or_else(|| Error::msg("the Zapret release has no zip file"))?;
    let sha256 = asset
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|d| d.strip_prefix("sha256:"))
        .map(str::to_lowercase)
        .ok_or_else(|| Error::msg("the Zapret release has no published SHA-256 checksum; nothing was installed"))?;
    Ok(Release {
        tag: tag.to_string(),
        url: asset.get("browser_download_url").and_then(Value::as_str).unwrap_or_default().to_string(),
        size: asset.get("size").and_then(Value::as_u64).unwrap_or(0),
        sha256,
    })
}

pub async fn latest(proxy: Option<&str>) -> Result<Release> {
    let resp = crate::coredl::client(proxy)?.get(API).header("Accept", "application/vnd.github+json").send().await?;
    if !resp.status().is_success() {
        return Err(Error::msg(format!("GitHub answered {}", resp.status())));
    }
    pick(&resp.json().await?)
}

pub async fn download(rel: &Release, proxy: Option<&str>) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    if rel.size > MAX_ZIP {
        return Err(Error::msg("the Zapret release is larger than expected, refusing to download it"));
    }
    let bytes = crate::coredl::client(proxy)?.get(&rel.url).send().await?.error_for_status()?.bytes().await?;
    if bytes.len() as u64 > MAX_ZIP {
        return Err(Error::msg("the Zapret release is larger than expected, refusing to download it"));
    }
    let got: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if got != rel.sha256 {
        return Err(Error::msg("the downloaded Zapret does not match its published checksum, nothing was installed"));
    }
    Ok(bytes.to_vec())
}

/// Files without which winws does not start.
const NEEDED: [&str; 4] = ["winws.exe", "WinDivert.dll", "WinDivert64.sys", "cygwin1.dll"];

/// Unpack `bin/`, `lists/` and the `general*.bat` strategies into `dir`, file by file over what is there,
/// and remember the version. The user's own list files are kept; strategies the release dropped go.
///
/// Nothing is deleted wholesale: after winws stops, Windows keeps the WinDivert driver loaded and its
/// file locked, so emptying the folder first would leave half of it gone. A locked file that already
/// holds the new bytes is fine; any other file that cannot be written fails the update.
pub fn unpack(zip_bytes: &[u8], dir: &Path, version: &str) -> Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).map_err(|e| Error::msg(format!("bad Zapret archive: {e}")))?;
    // a leftover of the old way of updating
    let _ = std::fs::remove_dir_all(dir.with_extension("new"));
    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| Error::msg(e.to_string()))?;
        let Some(path) = file.enclosed_name() else { continue };
        // the release keeps everything in one top folder: drop it
        let rel: PathBuf = path.components().skip(1).collect();
        let s = rel.to_string_lossy().replace('\\', "/");
        let wanted = s.starts_with("bin/") || s.starts_with("lists/") || (!s.contains('/') && s.starts_with("general") && s.ends_with(".bat"));
        if !wanted || file.is_dir() {
            continue;
        }
        let mut buf = Vec::with_capacity(file.size() as usize);
        std::io::Read::read_to_end(&mut file, &mut buf)?;
        files.push((rel, buf));
    }
    for name in NEEDED {
        if !files.iter().any(|(p, _)| p == &Path::new("bin").join(name)) {
            return Err(Error::msg(format!("the Zapret archive has no {name}")));
        }
    }
    std::fs::create_dir_all(dir)?;
    for (rel, data) in &files {
        let user_list = rel.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with("-user.txt"));
        let out = dir.join(rel);
        if user_list && out.exists() {
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        replace_file(&out, data)?;
    }
    let keep: Vec<String> = files.iter().filter_map(|(p, _)| p.to_str().map(String::from)).collect();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with("general") && name.ends_with(".bat") && !keep.contains(&name) {
            let _ = std::fs::remove_file(e.path());
        }
    }
    std::fs::write(dir.join("version.txt"), version)?;
    Ok(())
}

/// Write a file through a temporary one. A file Windows keeps locked is left alone when it already
/// holds exactly these bytes.
fn replace_file(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("kometfy-new");
    std::fs::write(&tmp, data)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            if std::fs::read(path).is_ok_and(|old| old == data) {
                Ok(())
            } else {
                Err(Error::msg(format!("{} is in use and cannot be updated: {e}", path.display())))
            }
        }
    }
}

/// The installed version, if every file winws needs is there; otherwise the UI offers the download again.
pub fn version(dir: &Path) -> Option<String> {
    let v = std::fs::read_to_string(dir.join("version.txt")).ok()?;
    let v = v.trim();
    let whole = NEEDED.iter().all(|n| dir.join("bin").join(n).exists());
    (!v.is_empty() && whole).then(|| v.to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Strategy {
    /// The batch file's name without `.bat`: "general", "general (ALT2)".
    pub name: String,
    pub args: Vec<String>,
}

/// Only the names of the strategies, in the same order: what the state shows.
pub fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().strip_suffix(".bat").filter(|s| s.starts_with("general")).map(String::from))
        .collect();
    out.sort_by_key(|s| (s != "general", natural(s)));
    out
}

/// Every strategy of the installed release, the plain "general" first, then in the release's order of names.
pub fn strategies(dir: &Path, game: bool) -> Vec<Strategy> {
    let bin = format!("{}\\", dir.join("bin").display());
    let lists = format!("{}\\", dir.join("lists").display());
    let mut out: Vec<Strategy> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let stem = name.strip_suffix(".bat")?.to_string();
            if !stem.starts_with("general") {
                return None;
            }
            let text = std::fs::read(e.path()).ok()?;
            let args = parse_bat(&String::from_utf8_lossy(&text), &bin, &lists, game)?;
            Some(Strategy { name: stem, args })
        })
        .collect();
    out.sort_by_key(|s| (s.name != "general", natural(&s.name)));
    out
}

/// "general (ALT10)" after "general (ALT9)".
fn natural(name: &str) -> (String, u32) {
    let digits: String = name.chars().filter(char::is_ascii_digit).collect();
    let word: String = name.chars().filter(|c| !c.is_ascii_digit()).collect();
    (word, digits.parse().unwrap_or(0))
}

/// The arguments of the `winws.exe` call in a strategy file, with %BIN%, %LISTS% and the game filter filled in.
fn parse_bat(text: &str, bin: &str, lists: &str, game: bool) -> Option<Vec<String>> {
    // a line ending in ^ goes on in the next one
    let joined = text.replace("^\r\n", " ").replace("^\n", " ");
    let line = joined.lines().find(|l| l.contains("winws.exe\""))?;
    let rest = &line[line.find("winws.exe\"")? + "winws.exe\"".len()..];
    let ports = if game { GAME_ON } else { GAME_OFF };
    let filled = rest
        .replace("%BIN%", bin)
        .replace("%LISTS%", lists)
        .replace("%GameFilterTCP%", ports)
        .replace("%GameFilterUDP%", ports)
        .replace("%GameFilter%", ports);
    let args = split_args(&filled);
    (!args.is_empty() && args.iter().all(|a| !a.contains('%'))).then_some(args)
}

/// Split on spaces outside double quotes and drop the quotes: `--hostlist="C:\a b\x.txt"` is one argument.
/// Outside quotes a caret escapes the next character, as cmd reads it: `--dpi-desync-fake-tls=^!` is `=!`.
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '^' if !quoted => cur.extend(chars.next()),
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The user's own sites go into the release's own "user" list (never empty, as the release asks);
/// the two exclusion lists get their placeholders if they are missing.
pub fn write_user_lists(dir: &Path, domains: &[String]) -> Result<()> {
    let lists = dir.join("lists");
    let mut general = String::from("# Kometfy: your own sites. Never leave this file empty.\n");
    if domains.is_empty() {
        general.push_str("domain.example.abc\n");
    }
    for d in domains {
        general.push_str(d);
        general.push('\n');
    }
    write_atomic(&lists.join("list-general-user.txt"), general.as_bytes())?;
    for (name, placeholder) in [("list-exclude-user.txt", "domain.example.abc\n"), ("ipset-exclude-user.txt", "203.0.113.113/32\n")] {
        let p = lists.join(name);
        if !p.exists() {
            write_atomic(&p, placeholder.as_bytes())?;
        }
    }
    Ok(())
}

/// A site name as a user may type it: "https://Example.com/path" becomes "example.com".
pub fn clean_domain(input: &str) -> Option<String> {
    let s = input.trim().to_lowercase();
    let s = s.split("://").last()?.split(['/', '?', '#']).next()?.trim_start_matches("*.").trim_end_matches('.');
    let ok = s.contains('.') && s.len() <= 253 && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    ok.then(|| s.to_string())
}

/// What a probe found, as scores: how many tries got through, out of how many, for YouTube (its site, the
/// app's API, a thumbnail read to the end, its video server), for Discord, and for the user's own sites.
/// A site whose address does not even take a TCP connection is left out: no strategy changes that.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Probe {
    pub youtube: u32,
    pub youtube_of: u32,
    pub discord: u32,
    pub discord_of: u32,
    pub sites: u32,
    pub sites_of: u32,
}

impl Probe {
    /// Everything got through every time: no need to look further.
    pub fn all(&self) -> bool {
        self.youtube_of > 0 && self.youtube == self.youtube_of && self.discord == self.discord_of && self.sites == self.sites_of
    }

    /// Better than `other`: more of YouTube first, then more of Discord and the user's sites together.
    pub fn beats(&self, other: &Probe) -> bool {
        (self.youtube, self.discord + self.sites) > (other.youtube, other.discord + other.sites)
    }

    /// Two probes of the same strategy, added up.
    pub fn plus(self, o: Probe) -> Probe {
        Probe {
            youtube: self.youtube + o.youtube,
            youtube_of: self.youtube_of + o.youtube_of,
            discord: self.discord + o.discord,
            discord_of: self.discord_of + o.discord_of,
            sites: self.sites + o.sites,
            sites_of: self.sites_of + o.sites_of,
        }
    }
}

/// How well do YouTube (its video too), Discord and the user's own `sites` work right now? Directly, past
/// any proxy, or through a local engine.
///
/// Two things fool a simple check. Providers often let the first 16–20 KB through and then freeze the
/// connection, so a YouTube page opens while its video stalls: the checks read a thumbnail to its end and
/// send 64 KB to the video server a YouTube page names (as Flowseal's DPI test does) and to Discord. And
/// real apps (browsers, the YouTube app) send a TLS hello of about 1.8 KB, two TCP segments, which some
/// strategies do not get past while a small hello passes: the handshakes here are made the way Chrome
/// makes them ([`client_hello`]).
/// YouTube, Discord and the sites are scored apart: some providers freeze Cloudflare's addresses (where
/// Discord lives) whatever the strategy, and YouTube should not wait for that.
/// `node` keeps the video server between calls, so a search loads the page only once.
/// `via`: test through a local engine (byedpi's SOCKS5 URL) instead of directly.
pub async fn probe(node: &mut Option<String>, via: Option<&str>, sites: &[String]) -> Probe {
    let builder = match via.map(reqwest::Proxy::all) {
        Some(Ok(proxy)) => reqwest::Client::builder().proxy(proxy),
        Some(Err(_)) => return Probe::default(),
        None => reqwest::Client::builder().no_proxy(),
    };
    let Ok(http) = builder
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(4))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
        .build()
    else {
        return Probe::default();
    };
    if node.is_none() {
        // the page that names the video server; without it YouTube itself does not open
        match video_server(&http).await {
            Some(found) => *node = Some(found),
            None => tracing::info!("probe: the YouTube page did not load"),
        }
    }
    let host = node.clone().unwrap_or_else(|| VIDEO_FALLBACK.to_string());
    let hello = |h: &str| Check::Hello(h.to_string());
    let youtube = [
        hello("www.youtube.com"),
        hello("youtubei.googleapis.com"),
        Check::Whole(THUMB.into()),
        hello(&host),
        Check::Upload(format!("https://{host}/videoplayback")),
    ];
    // a small answer on purpose: Discord's home page is 170 KB, more than a slow line fetches in time
    let discord = [
        hello("discord.com"),
        hello("gateway.discord.gg"),
        hello("cdn.discordapp.com"),
        Check::Upload("https://discord.com/api/v9/gateway".into()),
    ];
    let own: Vec<Check> = sites.iter().take(MAX_SITES).map(|d| hello(d)).collect();
    let ((yt, yt_of), (dc, dc_of), (st, st_of)) =
        tokio::join!(score(&http, via, &youtube), score(&http, via, &discord), score(&http, via, &own));
    Probe { youtube: yt, youtube_of: yt_of, discord: dc, discord_of: dc_of, sites: st, sites_of: st_of }
}

/// The user's own sites checked by a probe, at most.
const MAX_SITES: usize = 12;

/// One thing to check.
enum Check {
    /// A TLS handshake the size real apps make; a server hello back counts.
    Hello(String),
    /// A GET read to the end of its declared length.
    Whole(String),
    /// 64 KB up; any HTTP answer counts.
    Upload(String),
}

/// What one try came to.
enum Try {
    Ok,
    Failed(String),
    /// Not even a TCP connection: the address is blocked, which no strategy changes.
    Unreachable,
}

impl Check {
    async fn once(&self, http: &reqwest::Client, via: Option<&str>) -> Try {
        let done = |r: std::result::Result<(), String>| r.map_or_else(Try::Failed, |()| Try::Ok);
        let err = |e: reqwest::Error| e.to_string();
        match self {
            Check::Hello(host) => hello(host, via).await,
            Check::Whole(url) => done(
                async {
                    let resp = http.get(url).send().await.map_err(err)?;
                    let want = resp.content_length();
                    let got = resp.bytes().await.map_err(err)?.len() as u64;
                    match want {
                        Some(n) if got < n => Err(format!("{got} of {n} bytes, then silence")),
                        _ => Ok(()),
                    }
                }
                .await,
            ),
            Check::Upload(url) => {
                done(http.post(url).body(vec![0u8; 64 * 1024]).timeout(Duration::from_secs(6)).send().await.map(drop).map_err(err))
            }
        }
    }

    fn what(&self) -> &str {
        match self {
            Check::Hello(u) | Check::Whole(u) | Check::Upload(u) => u,
        }
    }
}

/// Every check `TRIES` times in a row (the checks run side by side): how many tries got through, out of how
/// many counted. A check whose address takes no TCP connection is not counted and not tried again.
async fn score(http: &reqwest::Client, via: Option<&str>, checks: &[Check]) -> (u32, u32) {
    let runs = checks.iter().map(|c| async move {
        let (mut ok, mut of) = (0, 0);
        for _ in 0..TRIES {
            match c.once(http, via).await {
                Try::Ok => ok += 1,
                Try::Failed(e) => tracing::debug!("probe: {}: {e}", c.what()),
                Try::Unreachable => {
                    tracing::debug!("probe: {}: no TCP connection", c.what());
                    return (ok, of);
                }
            }
            of += 1;
        }
        (ok, of)
    });
    futures_util::future::join_all(runs).await.into_iter().fold((0, 0), |(a, b), (c, d)| (a + c, b + d))
}

/// A remote test's site check: one TLS handshake with `host` (directly, or through a SOCKS5 proxy given as
/// "socks5://127.0.0.1:10880"), whether a server hello came back and in how many milliseconds.
pub async fn reach(host: &str, via: Option<&str>) -> (bool, u64) {
    let t = std::time::Instant::now();
    let ok = matches!(hello(host, via).await, Try::Ok);
    (ok, t.elapsed().as_millis() as u64)
}

/// One TLS handshake with `host`, directly or through the engine's SOCKS5 port: did a server hello come back?
async fn hello(host: &str, via: Option<&str>) -> Try {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let connect = async {
        match via.and_then(|v| v.split("://").nth(1)) {
            Some(proxy) => socks_connect(proxy, host).await,
            None => tokio::net::TcpStream::connect((host, 443)).await,
        }
    };
    let mut stream = match tokio::time::timeout(Duration::from_secs(3), connect).await {
        Ok(Ok(s)) => s,
        _ => return Try::Unreachable,
    };
    let answer = async {
        stream.write_all(&client_hello(host)).await?;
        // a handshake record whose first message is a server hello
        let mut head = [0u8; 6];
        stream.read_exact(&mut head).await?;
        Ok::<_, std::io::Error>(head[0] == 0x16 && head[1] == 3 && head[5] == 2)
    };
    match tokio::time::timeout(Duration::from_secs(4), answer).await {
        Ok(Ok(true)) => Try::Ok,
        Ok(Ok(false)) => Try::Failed("not a server hello".into()),
        Ok(Err(e)) => Try::Failed(e.to_string()),
        Err(_) => Try::Failed("no answer".into()),
    }
}

/// A SOCKS5 CONNECT to `host`:443 through `proxy` ("127.0.0.1:10880"). byedpi answers only once its own
/// connection is up, so a refusal here means the address itself takes no connection.
pub(crate) async fn socks_connect(proxy: &str, host: &str) -> std::io::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let refused = || std::io::Error::other("refused by the proxy");
    let mut s = tokio::net::TcpStream::connect(proxy).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut two = [0u8; 2];
    s.read_exact(&mut two).await?;
    if two != [5, 0] || host.len() > 255 {
        return Err(refused());
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&443u16.to_be_bytes());
    s.write_all(&req).await?;
    let mut rep = [0u8; 4];
    s.read_exact(&mut rep).await?;
    if rep[1] != 0 {
        return Err(refused());
    }
    let rest = match rep[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => s.read_u8().await? as usize + 2,
        _ => return Err(refused()),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

/// A TLS 1.3 ClientHello for `sni` the way Chrome and the YouTube app make one: a post-quantum key share
/// (X25519MLKEM768) makes it about 1.8 KB, two TCP segments, and the extensions come in a new order each
/// time, so the name may sit in either segment. The key share is well formed (servers check it) but random:
/// the handshake never goes past the server hello.
pub(crate) fn client_hello(sni: &str) -> Vec<u8> {
    // client random, session id, ML-KEM seed, X25519 key, then the ML-KEM coefficients
    let mut rnd = vec![0u8; 128 + 768 * 2];
    let _ = getrandom::getrandom(&mut rnd);
    let ext = |kind: u16, body: &[u8]| -> Vec<u8> {
        let mut e = kind.to_be_bytes().to_vec();
        e.extend_from_slice(&(body.len() as u16).to_be_bytes());
        e.extend_from_slice(body);
        e
    };
    let list16 = |items: &[u16]| -> Vec<u8> {
        let mut v = ((items.len() * 2) as u16).to_be_bytes().to_vec();
        items.iter().for_each(|i| v.extend_from_slice(&i.to_be_bytes()));
        v
    };
    let name = sni.as_bytes();
    let mut server_name = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    server_name.push(0);
    server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
    server_name.extend_from_slice(name);
    // ML-KEM-768 encapsulation key: 3 × 256 coefficients below 3329, 12 bits each, then a 32-byte seed;
    // the X25519 half follows
    let coefs: Vec<u16> = rnd[128..].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]]) % 3329).collect();
    let mut hybrid = Vec::with_capacity(1216);
    for pair in coefs.chunks(2) {
        let (a, b) = (pair[0], pair[1]);
        hybrid.extend_from_slice(&[a as u8, ((a >> 8) | ((b & 0xf) << 4)) as u8, (b >> 4) as u8]);
    }
    hybrid.extend_from_slice(&rnd[64..96]);
    let x25519 = &rnd[96..128];
    hybrid.extend_from_slice(x25519);
    let mut shares = Vec::new();
    for (group, key) in [(0x11ecu16, &hybrid[..]), (0x001d, x25519)] {
        shares.extend_from_slice(&group.to_be_bytes());
        shares.extend_from_slice(&(key.len() as u16).to_be_bytes());
        shares.extend_from_slice(key);
    }
    let mut key_share = (shares.len() as u16).to_be_bytes().to_vec();
    key_share.extend_from_slice(&shares);
    let mut exts = vec![
        ext(0x0000, &server_name),
        ext(0x0017, &[]),
        ext(0xff01, &[0]),
        ext(0x000a, &list16(&[0x11ec, 0x001d, 0x0017, 0x0018])),
        ext(0x000b, &[1, 0]),
        ext(0x0023, &[]),
        ext(0x0010, b"\x00\x0c\x02h2\x08http/1.1"),
        ext(0x0005, &[1, 0, 0, 0, 0]),
        ext(0x000d, &list16(&[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601])),
        ext(0x0012, &[]),
        ext(0x0033, &key_share),
        ext(0x002d, &[1, 1]),
        ext(0x002b, &[4, 3, 4, 3, 3]),
        ext(0x001b, &[2, 0, 2]),
    ];
    // Chrome shuffles its extensions on every connection
    for i in (1..exts.len()).rev() {
        exts.swap(i, rnd[i] as usize % (i + 1));
    }
    let exts = exts.concat();
    let mut body = vec![3, 3];
    body.extend_from_slice(&rnd[..32]);
    body.push(32);
    body.extend_from_slice(&rnd[32..64]);
    body.extend_from_slice(&list16(&[
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ]));
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut handshake = vec![1];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Load the YouTube page until it names a video server. None when the page does not load: then
/// YouTube itself does not work. A page that loads without naming one gives the fallback.
async fn video_server(http: &reqwest::Client) -> Option<String> {
    let mut resp = http.get(WATCH).header("Accept-Language", "en").timeout(Duration::from_secs(10)).send().await.ok()?;
    let mut page = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        let from = page.len().saturating_sub(80);
        page.extend_from_slice(&chunk);
        if let Some(host) = video_node(&page[from..]) {
            return Some(host);
        }
        if page.len() > 3 * 1024 * 1024 {
            break;
        }
    }
    Some(VIDEO_FALLBACK.to_string())
}

/// The first `rrN---sn-xxxx.googlevideo.com` in a page: the server its video would come from.
fn video_node(page: &[u8]) -> Option<String> {
    const MARK: &[u8] = b"---sn-";
    let host_byte = |b: &u8| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.';
    let mut from = 0;
    while let Some(i) = page[from..].windows(MARK.len()).position(|w| w == MARK) {
        let at = from + i;
        let start = page[..at].iter().rposition(|b| !b.is_ascii_alphanumeric()).map_or(0, |p| p + 1);
        let end = page[at..].iter().position(|b| !host_byte(b)).map_or(page.len(), |p| at + p);
        let host = std::str::from_utf8(&page[start..end]).unwrap_or_default();
        if host.starts_with("rr") && host.ends_with(".googlevideo.com") {
            return Some(host.to_string());
        }
        from = at + MARK.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const BAT: &str = "@echo off\r\nset \"BIN=%~dp0bin\\\"\r\nstart \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,%GameFilterTCP% ^\r\n--filter-udp=443 --hostlist=\"%LISTS%list-general.txt\" --dpi-desync=fake --new ^\r\n--filter-tcp=%GameFilterTCP% --dpi-desync-fake-quic=\"%BIN%quic one.bin\"\r\n";

    #[test]
    fn the_video_server_is_read_from_the_page() {
        let page = br#"..."url":"https://rr1---sn-5opm-up5e.googlevideo.com/initplayback?source=youtube&oeis=1"..."#;
        assert_eq!(video_node(page).as_deref(), Some("rr1---sn-5opm-up5e.googlevideo.com"));
        // the url-encoded form and other hosts are skipped; the plain one later is found
        let page = b"https%3A%2F%2Frr3---sn-abc.googlevideo.com x---sn-y.example.com \"https://rr12---sn-4g5e6nz7.googlevideo.com/videoplayback";
        assert_eq!(video_node(page).as_deref(), Some("rr12---sn-4g5e6nz7.googlevideo.com"));
        assert_eq!(video_node(b"no servers here ---sn-"), None);
    }

    #[test]
    fn a_strategy_becomes_plain_arguments() {
        let args = parse_bat(BAT, "C:\\z\\bin\\", "C:\\z\\lists\\", false).unwrap();
        assert_eq!(
            args,
            vec![
                "--wf-tcp=80,443,12",
                "--filter-udp=443",
                "--hostlist=C:\\z\\lists\\list-general.txt",
                "--dpi-desync=fake",
                "--new",
                "--filter-tcp=12",
                "--dpi-desync-fake-quic=C:\\z\\bin\\quic one.bin",
            ]
        );
        let game = parse_bat(BAT, "b\\", "l\\", true).unwrap();
        assert_eq!(game[0], "--wf-tcp=80,443,1024-65535");
        assert!(parse_bat("echo nothing here", "b", "l", false).is_none());
        // an unknown variable left in place means the file is not one we understand
        assert!(parse_bat("start \"\" \"%BIN%winws.exe\" --x=%Other%", "b", "l", false).is_none());
        // cmd's caret escape (Flowseal's FAKE TLS AUTO files), but a caret inside quotes stays
        let fake = parse_bat("start \"\" \"%BIN%winws.exe\" --dpi-desync-fake-tls=^! --x=\"a^b\"", "b", "l", false).unwrap();
        assert_eq!(fake, ["--dpi-desync-fake-tls=!", "--x=a^b"]);
    }

    #[test]
    fn strategies_are_ordered_like_people_count() {
        let mut names = ["general (ALT10)", "general (ALT2)", "general", "general (ALT)"].map(String::from).to_vec();
        names.sort_by_key(|s| (s != "general", natural(s)));
        assert_eq!(names, ["general", "general (ALT)", "general (ALT2)", "general (ALT10)"]);
    }

    #[test]
    fn an_update_keeps_the_users_lists_and_drops_old_strategies() {
        use std::io::Write;
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (name, body) in [
            ("r/bin/winws.exe", "exe"),
            ("r/bin/WinDivert.dll", "dll"),
            ("r/bin/WinDivert64.sys", "sys"),
            ("r/bin/cygwin1.dll", "cyg"),
            ("r/lists/list-general.txt", "discord.com"),
            ("r/lists/list-general-user.txt", "domain.example.abc"),
            ("r/general.bat", "start \"\" \"%BIN%winws.exe\" --wf-tcp=443"),
            ("r/service.bat", "no"),
        ] {
            zip.start_file(name, opts).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        let dir = std::env::temp_dir().join(format!("kometfy-unpack-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("lists")).unwrap();
        std::fs::write(dir.join("lists").join("list-general-user.txt"), "mine.example").unwrap();
        std::fs::write(dir.join("general (OLD).bat"), "old").unwrap();
        unpack(&bytes, &dir, "9.9").unwrap();
        assert_eq!(version(&dir).as_deref(), Some("9.9"));
        assert_eq!(std::fs::read_to_string(dir.join("lists").join("list-general-user.txt")).unwrap(), "mine.example");
        assert!(!dir.join("general (OLD).bat").exists() && dir.join("general.bat").exists() && !dir.join("service.bat").exists());
        // a missing file makes the install count as broken, so the download is offered again
        std::fs::remove_file(dir.join("bin").join("cygwin1.dll")).unwrap();
        assert_eq!(version(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn domains_are_cleaned() {
        assert_eq!(clean_domain(" https://Example.COM/path?q=1 ").as_deref(), Some("example.com"));
        assert_eq!(clean_domain("*.discord.gg").as_deref(), Some("discord.gg"));
        assert_eq!(clean_domain("not a domain"), None);
        assert_eq!(clean_domain("localhost"), None);
        assert_eq!(clean_domain("bad_char.com"), None);
    }

    #[test]
    fn a_release_without_a_checksum_is_refused() {
        let rel = serde_json::json!({"tag_name": "1.0", "assets": [{"name": "z.zip", "browser_download_url": "u", "size": 1}]});
        assert!(pick(&rel).is_err());
        let rel = serde_json::json!({"tag_name": "1.0", "assets": [{"name": "z.rar"}, {"name": "z.zip", "browser_download_url": "u", "size": 1, "digest": "sha256:ABC"}]});
        let r = pick(&rel).unwrap();
        assert_eq!((r.tag.as_str(), r.sha256.as_str()), ("1.0", "abc"));
    }

    /// The real release: download, check, unpack and read its strategies.
    /// Needs the Internet: cargo test -p prism-connect zapret -- --ignored
    #[tokio::test]
    #[ignore]
    async fn the_real_release_unpacks_into_strategies() {
        let rel = latest(None).await.unwrap();
        let zip = download(&rel, None).await.unwrap();
        let dir = std::env::temp_dir().join(format!("kometfy-zapret-test-{}", std::process::id()));
        unpack(&zip, &dir, &rel.tag).unwrap();
        write_user_lists(&dir, &["example.org".into()]).unwrap();
        assert_eq!(version(&dir).as_deref(), Some(rel.tag.as_str()));
        let all = strategies(&dir, false);
        assert!(all.len() >= 5, "{} strategies", all.len());
        assert_eq!(all[0].name, "general");
        assert!(all.iter().all(|s| s.args.iter().any(|a| a.starts_with("--wf-tcp="))));
        let user = std::fs::read_to_string(dir.join("lists").join("list-general-user.txt")).unwrap();
        assert!(user.contains("example.org"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_hello_is_as_big_as_chromes_and_well_formed() {
        for _ in 0..20 {
            let h = client_hello("www.youtube.com");
            // two TCP segments, as the YouTube app's
            assert!(h.len() > 1500 && h.len() < 2000, "{}", h.len());
            assert_eq!(&h[..3], &[0x16, 3, 1]);
            assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
            assert_eq!(h[5], 1);
            // the name is there, wherever the shuffle put it
            assert!(h.windows(15).any(|w| w == b"www.youtube.com"));
            // the ML-KEM key's coefficients are below 3329, or a server refuses it
            let at = h.windows(4).position(|w| w == [0x11, 0xec, 0x04, 0xc0]).expect("the hybrid share");
            let key = &h[at + 4..at + 4 + 1152];
            for t in key.chunks(3) {
                let a = t[0] as u16 | ((t[1] as u16 & 0xf) << 8);
                let b = (t[1] as u16 >> 4) | ((t[2] as u16) << 4);
                assert!(a < 3329 && b < 3329);
            }
        }
    }

    #[test]
    fn probes_add_up_and_compare_youtube_first() {
        let a = Probe { youtube: 15, youtube_of: 15, discord: 3, discord_of: 12, sites: 0, sites_of: 6 };
        let b = Probe { youtube: 14, youtube_of: 15, discord: 12, discord_of: 12, sites: 6, sites_of: 6 };
        assert!(a.beats(&b) && !b.beats(&a));
        assert!(!a.all() && !b.all());
        assert_eq!(a.plus(b).youtube, 29);
        assert!(Probe { youtube: 3, youtube_of: 3, ..Probe::default() }.all());
    }
}
