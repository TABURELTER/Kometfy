//! The error journal: every warning and error the app logs, grouped by what it says (numbers stripped, personal
//! data scrubbed as in a diagnostic report), with how often and when. It is kept in `errors.json` beside the log, and
//! it is what Diagnostics shows as the frequent errors, what goes into a report, and where the per-module error
//! counts of the statistics come from (a module's name and a number, never a message).
//!
//! `record` is called from the logging layer for each warning and error, so it never logs itself.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, OnceLock},
};

use serde::{Deserialize, Serialize};

/// Kinds of errors kept; the ones seen least recently go first.
const MAX: usize = 200;
const FILE: &str = "errors.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    /// "error" or "warn".
    pub level: String,
    /// The part of the app that logged it: `manager`, `zapret`, `connect_app`...
    pub module: String,
    /// The latest message of this kind, scrubbed.
    pub text: String,
    pub count: u64,
    /// Unix seconds.
    pub first: i64,
    pub last: i64,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    /// Errors per module since the statistics last took them.
    pending: HashMap<String, u64>,
    dirty: bool,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(Mutex::default)
}

/// A module's name from a log target: `prism_connect::manager` is `manager`.
pub fn module(target: &str) -> String {
    let last = target.rsplit("::").next().unwrap_or(target);
    let m: String = last.chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_').take(24).collect();
    if m.is_empty() { "other".into() } else { m }
}

/// What a message says without what changes each time (numbers: ports, counts, milliseconds), so one failure that
/// repeats is one entry.
pub fn shape(text: &str) -> String {
    let mut out = String::new();
    let mut digits = false;
    for c in text.chars() {
        if c.is_ascii_digit() {
            if !digits {
                out.push('#');
            }
            digits = true;
        } else {
            digits = false;
            out.push(c);
        }
    }
    out.chars().take(160).collect()
}

pub fn record(error: bool, target: &str, text: &str) {
    let text: String = crate::diagnostics::scrub(text).chars().filter(|c| !c.is_control()).take(300).collect();
    let module = module(target);
    let key = format!("{module}|{}|{}", error, shape(&text));
    let now = chrono::Utc::now().timestamp();
    let Ok(mut s) = state().lock() else { return };
    let e = s.entries.entry(key).or_insert_with(|| Entry {
        level: if error { "error" } else { "warn" }.into(),
        module: module.clone(),
        text: String::new(),
        count: 0,
        first: now,
        last: now,
    });
    e.count += 1;
    e.last = now;
    e.text = text;
    if error {
        *s.pending.entry(module).or_default() += 1;
    }
    if s.entries.len() > MAX {
        if let Some(oldest) = s.entries.iter().min_by_key(|(_, e)| e.last).map(|(k, _)| k.clone()) {
            s.entries.remove(&oldest);
        }
    }
    s.dirty = true;
}

/// The errors per module since the last call (for the statistics).
pub fn take_counts() -> HashMap<String, u64> {
    state().lock().map(|mut s| std::mem::take(&mut s.pending)).unwrap_or_default()
}

/// The kinds seen most, the most recent first among equals.
pub fn top(n: usize) -> Vec<Entry> {
    let Ok(s) = state().lock() else { return vec![] };
    let mut v: Vec<Entry> = s.entries.values().cloned().collect();
    v.sort_by(|a, b| (b.level == "error").cmp(&(a.level == "error")).then(b.count.cmp(&a.count)).then(b.last.cmp(&a.last)));
    v.truncate(n);
    v
}

pub fn clear(dir: &Path) {
    if let Ok(mut s) = state().lock() {
        s.entries.clear();
        s.pending.clear();
        s.dirty = false;
    }
    let _ = std::fs::remove_file(dir.join(FILE));
}

/// At the start: what earlier runs saw.
pub fn load(dir: &Path) {
    let Ok(text) = std::fs::read_to_string(dir.join(FILE)) else { return };
    let Ok(list) = serde_json::from_str::<Vec<Entry>>(&text) else { return };
    if let Ok(mut s) = state().lock() {
        for e in list.into_iter().take(MAX) {
            s.entries.insert(format!("{}|{}|{}", e.module, e.level == "error", shape(&e.text)), e);
        }
    }
}

/// Writes `errors.json` when something changed since the last time.
pub fn save(dir: &Path) {
    let list = {
        let Ok(mut s) = state().lock() else { return };
        if !s.dirty {
            return;
        }
        s.dirty = false;
        s.entries.values().cloned().collect::<Vec<_>>()
    };
    if let Ok(text) = serde_json::to_string(&list) {
        let _ = crate::util::write_atomic(&dir.join(FILE), text.as_bytes());
    }
}

/// The journal as text for a diagnostic report.
pub fn report(n: usize) -> String {
    let list = top(n);
    if list.is_empty() {
        return "none".into();
    }
    list.iter()
        .map(|e| {
            let when = chrono::DateTime::from_timestamp(e.last, 0).map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default();
            format!("{} ×{} [{}] last {} — {}", e.level, e.count, e.module, when, e.text)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // the journal is one per process: the tests use their own module names and look only at those
    fn mine(prefix: &str) -> Vec<Entry> {
        top(MAX).into_iter().filter(|e| e.module.starts_with(prefix)).collect()
    }

    #[test]
    fn the_same_failure_with_other_numbers_is_one_entry() {
        record(true, "prism_connect::jt_one", "core did not become ready in 40 s on port 17897");
        record(true, "prism_connect::jt_one", "core did not become ready in 41 s on port 27897");
        record(false, "prism_connect::jt_one", "core did not become ready in 40 s on port 17897");
        let v = mine("jt_one");
        assert_eq!(v.len(), 2, "an error and a warning saying the same are two kinds");
        assert_eq!((v[0].level.as_str(), v[0].count), ("error", 2));
        assert!(v[0].text.contains("27897"), "the latest message is kept");
    }

    #[test]
    fn errors_are_counted_per_module_for_the_statistics_and_warnings_are_not() {
        record(true, "prism_connect::jt_count", "boom");
        record(true, "prism_connect::jt_count", "boom 2");
        record(false, "prism_connect::jt_count", "just a warning");
        let counts = take_counts();
        assert_eq!(counts.get("jt_count"), Some(&2));
        // taken: the next call starts from zero
        assert_eq!(take_counts().get("jt_count"), None);
    }

    #[test]
    fn personal_data_is_scrubbed_before_it_is_kept() {
        record(true, "x::jt_scrub", r"cannot read C:\Users\Anna\AppData\Roaming\dev.prismroute.console\settings.json");
        let v = mine("jt_scrub");
        assert!(!v[0].text.contains("Anna"), "{}", v[0].text);
    }

    #[test]
    fn module_names_are_safe_for_the_statistics() {
        assert_eq!(module("prism_connect::manager"), "manager");
        assert_eq!(module("prismroute_lib::connect_app"), "connect_app");
        assert_eq!(module("Weird-Target!"), "eirdarget");
        assert_eq!(module("::"), "other");
        assert_eq!(shape("took 1534 ms, 2 tries"), "took # ms, # tries");
    }
}
