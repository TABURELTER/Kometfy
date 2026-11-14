//! The diagnostic report a user can attach to a bug report.
//!
//! It is made of facts about the app (versions, settings without secrets, counters) and the tails
//! of the logs after `scrub`, which takes out addresses, server and site names, subscription
//! links, ids and user names. It is written to a file and shown to the user first; nothing is sent
//! anywhere by the app.

use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde::Serialize;

use crate::{error::Result, metrics::Summary, util::write_atomic};

#[derive(Debug, Serialize)]
pub struct Report {
    /// Where the report was saved.
    pub path: String,
    pub text: String,
}

/// Reports that stay on disk; older ones are deleted.
const KEEP_REPORTS: usize = 5;

/// Last part of a file name that is a file, not a host (`config.yaml`, `mihomo.exe`).
const FILE_EXT: &[&str] = &[
    "yaml", "yml", "json", "log", "exe", "dll", "txt", "toml", "db", "dat", "mmdb", "zip", "png", "sig", "rs", "js", "ts", "lock", "tmp", "gz", "md", "ico",
    "pid", "conf", "cfg", "ini", "msi", "dmg", "svg",
];

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | '\\' | '@' | '%' | '+' | '=' | '~' | '?' | '&' | '#')
}

/// Replace what could identify a person, a server or a site with a marker (`<ip>`, `<host>`,
/// `<url>`, `<id>`, `<email>`, `<token>`, `<user>`, `“<name>”`). Everything else stays as it is.
pub fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let mut in_name = false;
    for c in text.chars() {
        if in_name {
            // the app puts server names in curly quotes
            if c == '”' {
                in_name = false;
                out.push_str("<name>”");
            }
            continue;
        }
        if c == '“' {
            flush(&mut word, &mut out);
            in_name = true;
            out.push('“');
        } else if is_word(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    if in_name {
        out.push_str("<name>");
    }
    out
}

fn flush(word: &mut String, out: &mut String) {
    if word.is_empty() {
        return;
    }
    // punctuation at the end belongs to the sentence, not to the value
    let core = word.trim_end_matches(['.', ',', ':', ';']);
    out.push_str(&scrub_value(core));
    out.push_str(&word[core.len()..]);
    word.clear();
}

fn scrub_value(w: &str) -> String {
    if w.contains("://") {
        return "<url>".into();
    }
    // key=value: the key stays, the value is judged on its own
    if let Some((k, v)) = w.split_once('=') {
        if k.len() <= 24 && k.starts_with(|c: char| c.is_alphabetic()) && k.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return format!("{k}={}", scrub_value(v));
        }
    }
    if let Some(p) = user_path(w) {
        return p;
    }
    match marker(w) {
        Some(m) => m.into(),
        None => w.to_string(),
    }
}

/// `C:\Users\Anna\...` keeps its shape but not the name.
fn user_path(w: &str) -> Option<String> {
    let lower = w.to_ascii_lowercase();
    for marker in ["\\users\\", "/users/", "/home/"] {
        if let Some(i) = lower.find(marker) {
            let start = i + marker.len();
            let end = w[start..].find(['\\', '/']).map_or(w.len(), |j| start + j);
            return Some(format!("{}<user>{}", &w[..start], &w[end..]));
        }
    }
    None
}

fn marker(w: &str) -> Option<&'static str> {
    let bare = host_part(w);
    if is_ipv4(bare) || is_ipv6(w) {
        Some("<ip>")
    } else if is_uuid(w) {
        Some("<id>")
    } else if w.split_once('@').is_some_and(|(l, d)| !l.is_empty() && d.contains('.')) {
        Some("<email>")
    } else if is_secret(w) {
        Some("<token>")
    } else if is_host(bare) {
        Some("<host>")
    } else {
        None
    }
}

/// `example.com:443/path` -> `example.com`
fn host_part(w: &str) -> &str {
    let h = w.split('/').next().unwrap_or(w);
    match h.rsplit_once(':') {
        Some((a, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !a.contains(':') => a,
        _ => h,
    }
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok_and(|n| n <= 255))
}

fn is_ipv6(w: &str) -> bool {
    if w.matches(':').count() < 2 || !w.chars().all(|c| c.is_ascii_hexdigit() || c == ':') || !w.chars().any(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    // 12:01:33 is a time of day
    !w.split(':').all(|g| !g.is_empty() && g.len() <= 2 && g.bytes().all(|b| b.is_ascii_digit()))
}

fn is_uuid(w: &str) -> bool {
    w.len() == 36 && w.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

/// A long run of letters and digits: a token, a key, a subscription id.
fn is_secret(w: &str) -> bool {
    w.len() >= 24
        && w.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '=' | '-'))
        && w.chars().any(|c| c.is_ascii_digit())
        && w.chars().any(|c| c.is_ascii_alphabetic())
}

fn is_host(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    let Some(last) = labels.last() else { return false };
    labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty() && l.chars().all(|c| c.is_alphanumeric() || c == '-'))
        && last.len() >= 2
        && last.chars().all(char::is_alphabetic)
        && !FILE_EXT.contains(&last.to_ascii_lowercase().as_str())
}

/// The core's log without the lines that name the sites visited (`a --> b`), the rest scrubbed.
pub fn core_log(lines: &[String]) -> String {
    let kept: Vec<&str> = lines.iter().map(String::as_str).filter(|l| !l.contains(" --> ")).collect();
    let mut out = scrub(&kept.join("\n"));
    let dropped = lines.len() - kept.len();
    if dropped > 0 {
        out.push_str(&format!("\n({dropped} connection lines left out)"));
    }
    out
}

fn stat_line(label: &str, s: &crate::metrics::Stat, digits: usize) -> String {
    format!("  {label}: n={}, avg {:.d$}, P50 {:.d$}, P95 {:.d$}, max {:.d$}\n", s.n, s.avg, s.p50, s.p95, s.max, d = digits)
}

/// The statistics as plain text for the report.
pub fn metrics_text(s: &Summary) -> String {
    let c = |k: &str| s.counts.get(k).copied().unwrap_or(0);
    let r = &s.reliability;
    let mut t = format!("Period: the last {} days (data since {})\n", s.days, s.from.as_deref().unwrap_or("-"));
    t += &format!("Connection attempts: {}, successful: {}\n", r.attempts, r.ok);
    t += &format!("  failed on Kometfy's side: app {}, core {}\n", r.app, r.core);
    t += &format!(
        "  failure rate of Kometfy itself: {}\n",
        r.own_failure_pct.map_or("no data".to_string(), |p| format!("{p:.1}%"))
    );
    t += &format!("  not counted against Kometfy: subscription {}, network {}, stopped by the user {}\n", r.subscription, r.network, r.user);
    t += &format!(
        "Unexpected stops: app crashes {}, killed without exiting {}, mihomo {}, Xray {}\n",
        c("app_crash_count"),
        c("unclean_exit_count"),
        c("core_unexpected_exit.mihomo"),
        c("core_unexpected_exit.xray")
    );
    let kinds = |base: &str| {
        ["app", "core", "subscription", "network", "user"]
            .iter()
            .filter_map(|k| Some(format!("{k} {}", s.counts.get(&format!("{base}.{k}")).copied().filter(|n| *n > 0)?)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    t += &format!("Config reloads: ok {}, failed {} ({})\n", c("config_reload_ok"), s.counts.iter().filter(|(k, _)| k.starts_with("config_reload_failed.")).map(|(_, n)| n).sum::<u64>(), kinds("config_reload_failed"));
    t += &format!("Subscription downloads: ok {}, failed ({})\n", c("subscription_update_ok"), kinds("subscription_update_failed"));
    t += &format!("TUN adapter did not start: {}\n", c("tun_start_failed"));
    t += "\nTimings in milliseconds\n";
    for (k, v) in s.stats.iter().filter(|(k, _)| k.ends_with("_ms")) {
        t += &stat_line(k, v, 0);
    }
    t += "\nResources (working set in MB, processor load in % of the whole machine)\n";
    for (k, v) in s.stats.iter().filter(|(k, _)| !k.ends_with("_ms")) {
        t += &stat_line(k, v, 1);
    }
    if !s.recent.is_empty() {
        t += "\nRecent events\n";
        for e in &s.recent {
            let when = chrono::DateTime::from_timestamp(e.t, 0).map_or_else(|| "?".into(), |d| d.format("%Y-%m-%d %H:%M").to_string());
            t += &format!("  {when} UTC  {} {}\n", e.kind, e.detail);
        }
    }
    t
}

/// Header, notice and the sections in order.
pub fn assemble(sections: &[(&str, String)]) -> String {
    let mut t = format!(
        "Kometfy diagnostic report\nCreated: {} UTC\n\nThis report holds no server addresses, site names, subscription links, device id or credentials: they are\ncut out of the logs and never gathered. Read it before you share it; the app sends it nowhere.\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S")
    );
    for (title, body) in sections {
        t += &format!("\n## {title}\n{}\n", body.trim_end());
    }
    t
}

/// Write the report into `dir` and keep the newest `KEEP_REPORTS` there.
pub fn save(dir: &Path, text: &str) -> Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("Kometfy-diagnostics-{}.txt", Utc::now().format("%Y%m%d-%H%M%S")));
    write_atomic(&path, text.as_bytes())?;
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("Kometfy-diagnostics-") || n.starts_with("PrismRoute-diagnostics-")))
        .collect();
    files.sort();
    while files.len() > KEEP_REPORTS {
        let _ = fs::remove_file(files.remove(0));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_sites_do_not_survive() {
        for (input, gone) in [
            ("dial tcp 203.0.113.7:443: i/o timeout", "203.0.113.7"),
            ("[TCP] 192.168.1.23:51234 reached example.com:443", "example.com"),
            ("fetch https://panel.example.org/sub/abcDEF123?token=SECRET failed", "SECRET"),
            ("proxy at [2001:db8::1]:8443 is down", "2001:db8"),
            ("user anna@example.com asked", "anna@example.com"),
            ("id 3f2b8c1e-9a4d-4f6e-8b7a-1c2d3e4f5a6b used", "3f2b8c1e"),
            ("key=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg== set", "Zm9vYmFy"),
            ("path C:\\Users\\Anna\\AppData\\Roaming\\dev.prismroute.console\\app.log", "Anna"),
            ("xray refused “Berlin 01 secret-provider”: bad outbound", "Berlin"),
        ] {
            let out = scrub(input);
            assert!(!out.contains(gone), "{input} -> {out}");
        }
    }

    #[test]
    fn what_helps_to_debug_stays() {
        for line in [
            "2026-11-09T12:01:33.123Z INFO prism_connect::manager: mihomo started, pid 4242",
            "core mihomo v1.19.33 reads config.yaml and runs mihomo.exe",
            "time=\"12:01:33\" level=warning msg=\"TUN adapter did not start\"",
            "TUN stack mixed, MTU 1500, auto_route true",
        ] {
            assert_eq!(scrub(line), line);
        }
        assert_eq!(scrub("a 10.0.0.1 b"), "a <ip> b");
        assert_eq!(scrub("see https://x.org/a?b=c."), "see <url>.");
        assert_eq!(scrub("C:\\Users\\Anna\\x.log"), "C:\\Users\\<user>\\x.log");
        assert_eq!(scrub("level=info host=example.com"), "level=info host=<host>");
    }

    #[test]
    fn the_core_log_drops_lines_that_name_sites() {
        let lines: Vec<String> = [
            "time=\"1\" level=info msg=\"[TCP] 10.0.0.2:5 --> example.com:443 match Domain using PROXY\"",
            "time=\"2\" level=info msg=\"[DNS] example.com --> [1.2.3.4]\"",
            "time=\"3\" level=error msg=\"listen tcp 127.0.0.1:17897: bind: address already in use\"",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = core_log(&lines);
        assert!(!out.contains("example.com") && !out.contains("1.2.3.4"));
        assert!(out.contains("address already in use") && out.contains("2 connection lines left out"), "{out}");
    }

    #[test]
    fn old_reports_are_deleted() {
        let dir = std::env::temp_dir().join(format!("prism-diag-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for i in 0..8 {
            fs::write(dir.join(format!("Kometfy-diagnostics-2020010{i}-000000.txt")), "old").unwrap();
        }
        fs::write(dir.join("notes.txt"), "mine").unwrap();
        let fresh = save(&dir, "new").unwrap();
        let mut names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names.iter().filter(|n| n.starts_with("Kometfy-diagnostics-")).count(), KEEP_REPORTS);
        assert!(names.contains(&"notes.txt".to_string()) && fresh.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn the_metrics_text_names_what_is_not_counted() {
        let dir = std::env::temp_dir().join(format!("prism-diag-m-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let m = crate::metrics::Metrics::open(crate::metrics::file_in(&dir), true);
        m.count("connect_attempts");
        m.count("connect_ok");
        m.millis("connect_duration_ms", std::time::Duration::from_millis(900));
        let t = metrics_text(&m.summary(30));
        assert!(t.contains("successful: 1") && t.contains("not counted against Kometfy") && t.contains("connect_duration_ms"), "{t}");
        let _ = fs::remove_dir_all(dir);
    }
}
