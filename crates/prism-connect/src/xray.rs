//! The Xray core as a helper process: how it is started, checked and read.
//!
//! mihomo stays the front of the app (rules, groups, chains, TUN, the controller). Servers that
//! only Xray can run well (or that need DPI bypass) are handed to an Xray process that listens on
//! a private loopback port; the config for it is made by `xray_conf`.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use crate::{
    error::{Error, Result},
};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use crate::util::CREATE_NO_WINDOW;

/// The first release whose `finalmask` has the TCP `fragment` mask (older cores fragment through
/// a `freedom` outbound, which newer cores still accept but call deprecated).
pub const FINALMASK_FRAGMENT: [u32; 3] = [26, 3, 23];

/// `Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 windows/amd64)` -> `v26.10.31`
pub fn parse_version(out: &str) -> Option<String> {
    let first = out.lines().next()?;
    let tok = first.strip_prefix("Xray ")?.split_whitespace().next()?;
    let ok = !tok.is_empty() && tok.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    ok.then(|| format!("v{tok}"))
}

pub fn version(bin: &Path) -> Option<String> {
    let mut cmd = Command::new(bin);
    cmd.arg("version").stdin(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    if !out.status.success() { return None; }
    parse_version(&String::from_utf8_lossy(&out.stdout))
}

/// `v26.10.31` / `26.10.31` / `1.8.24` -> numbers, missing parts are 0.
pub fn version_tuple(v: &str) -> Option<[u32; 3]> {
    let mut it = v.trim().trim_start_matches('v').split('.').map(|p| p.parse::<u32>().ok());
    let a = it.next()??;
    let b = it.next().unwrap_or(Some(0))?;
    let c = it.next().unwrap_or(Some(0))?;
    Some([a, b, c])
}

/// `xray run -c <config>`
pub fn command(bin: &Path, config: &Path) -> Command {
    let mut cmd = Command::new(bin);
    cmd.arg("run").arg("-c").arg(config);
    cmd
}

/// `xray run -test -c <config>`: load the config and stop, nothing is started.
pub fn validate(bin: &Path, config: &Path) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(["run", "-test", "-c"])
        .arg(config)
        .stdin(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output()?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Err(Error::msg(summarize_error(&text)))
}

/// `2026/11/06 07:49:36.003586 [Warning] common/errors: text` -> (level, text)
fn split_line(raw: &str) -> (&'static str, &str) {
    let mut rest = raw.trim();
    // timestamp: "2026/11/06 07:49:36.003586 "
    if let Some((date, tail)) = rest.split_once(' ') {
        if date.contains('/') && date.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            if let Some((time, tail)) = tail.split_once(' ') {
                if time.contains(':') {
                    rest = tail;
                }
            }
        }
    }
    for (tag, level) in [("[Debug]", "debug"), ("[Info]", "info"), ("[Warning]", "warning"), ("[Error]", "error")] {
        if let Some(text) = rest.strip_prefix(tag) {
            return (level, text.trim());
        }
    }
    ("info", rest)
}

/// One line of Xray output in the logfmt shape the rest of the app reads (`level=... msg="..."`).
pub fn log_line(raw: &str) -> String {
    let (level, text) = split_line(raw);
    let text = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!("level={level} msg=\"xray: {text}\"")
}

/// The human part of a failed `xray run -test`.
pub fn summarize_error(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let pick = lines
        .iter()
        .rev()
        .find(|l| l.contains("ailed") || l.contains("[Error]"))
        .or_else(|| lines.last())
        .copied()
        .unwrap_or("Xray rejected the config");
    let (_, msg) = split_line(pick);
    let msg = msg.strip_prefix("Failed to start:").unwrap_or(msg).trim();
    // "failed to load config files: [C:\...\xray.json] > " only repeats the path we passed
    let msg = match (msg.find("config files: ["), msg.find("] > ")) {
        (Some(a), Some(b)) if a < b => format!("{}{}", &msg[..a + "config files: ".len()], &msg[b + 4..]),
        _ => msg.to_string(),
    };
    msg.chars().take(400).collect()
}

/// `... failed to build outbound config with tag o8 > ...` -> `o8`: the outbound Xray refused.
pub fn failing_tag(msg: &str) -> Option<String> {
    let rest = msg.split("outbound config with tag ").nth(1)?;
    let tag: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    (!tag.is_empty()).then_some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line() {
        let out = "Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 windows/amd64)\nA unified platform for anti-censorship.\n";
        assert_eq!(parse_version(out).as_deref(), Some("v26.10.31"));
        assert_eq!(parse_version("Xray 1.8.24 (Xray)").as_deref(), Some("v1.8.24"));
        assert_eq!(parse_version("mihomo v1.19.33"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(version_tuple("v26.10.31"), Some([26, 10, 31]));
        assert_eq!(version_tuple("1.8"), Some([1, 8, 0]));
        assert_eq!(version_tuple("alpha-abc"), None);
        assert!(version_tuple("v26.3.22").unwrap() < FINALMASK_FRAGMENT);
        assert!(version_tuple("v26.10.31").unwrap() >= FINALMASK_FRAGMENT);
    }

    #[test]
    fn log_lines_become_logfmt() {
        let l = log_line(r#"2026/11/06 07:49:36.003586 [Warning] common/errors: This feature "fragment" is deprecated"#);
        assert_eq!(l, r#"level=warning msg="xray: common/errors: This feature \"fragment\" is deprecated""#);
        assert_eq!(log_line("plain text"), r#"level=info msg="xray: plain text""#);
        assert_eq!(log_line("[Error] boom").as_str(), r#"level=error msg="xray: boom""#);
    }

    #[test]
    fn failure_is_summarized() {
        let t = "Xray 26.10.31 (Xray)\nA unified platform.\n2026/11/06 07:49:36.003586 [Info] infra/conf/serial: Reading config\nFailed to start: main: failed to load config files: [x.json] > bad outbound\n";
        assert_eq!(summarize_error(t), "main: failed to load config files: bad outbound");
        assert_eq!(summarize_error(""), "Xray rejected the config");
    }

    #[test]
    fn the_refused_outbound_is_named() {
        let t = "Failed to start: main: failed to load config files: [C:\\Users\\a b\\cfg.json] > infra/conf: failed to build outbound config with tag o8 > infra/conf: vless without TLS or other encryption is prohibited";
        let msg = summarize_error(t);
        assert!(!msg.contains("cfg.json"));
        assert_eq!(failing_tag(&msg).as_deref(), Some("o8"));
        assert_eq!(failing_tag("something else failed"), None);
    }
}
