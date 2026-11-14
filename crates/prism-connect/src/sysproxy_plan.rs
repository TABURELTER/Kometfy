//! Pure planning logic for a future transactional macOS system proxy adapter.
//!
//! This module does not touch network settings. A platform adapter must persist
//! the complete plan before writing anything and keep it until every service is
//! either restored or found already restored.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

type Settings = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum Entry {
    Absent,
    Present(Value),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyPlan {
    before: BTreeMap<String, Entry>,
    applied: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Restore {
    /// Nothing changed, for example after a crash before commit or after recovery.
    AlreadyRestored,
    /// Apply this merged configuration to the service in the same transaction.
    Apply(Settings),
    /// Some managed setting changed externally; do not overwrite any of them.
    Conflict,
}

impl ProxyPlan {
    pub fn new(current: &Settings, server: &str, bypass: &str) -> Result<Self, &'static str> {
        let (host, port) = server.rsplit_once(':').ok_or("invalid proxy address")?;
        let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        let port: u16 = port.parse().map_err(|_| "invalid proxy port")?;
        if host.is_empty() || host.chars().any(char::is_whitespace) || port == 0 {
            return Err("invalid proxy address");
        }
        let mut exceptions = Vec::new();
        let mut local = false;
        for item in bypass.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            if item.eq_ignore_ascii_case("<local>") {
                local = true;
            } else if item.starts_with('<') || item.contains('\0') {
                return Err("unsupported proxy exception");
            } else {
                exceptions.push(item);
            }
        }
        let wanted = BTreeMap::from([
            ("HTTPEnable", json!(1)), ("HTTPProxy", json!(host)), ("HTTPPort", json!(port)),
            ("HTTPSEnable", json!(1)), ("HTTPSProxy", json!(host)), ("HTTPSPort", json!(port)),
            ("SOCKSEnable", json!(0)), ("ProxyAutoConfigEnable", json!(0)),
            ("ProxyAutoDiscoveryEnable", json!(0)), ("ExceptionsList", json!(exceptions)),
            ("ExcludeSimpleHostnames", json!(if local { 1 } else { 0 })),
        ]);
        let before = wanted.keys().map(|k| ((*k).to_string(), current.get(*k).cloned().map(Entry::Present).unwrap_or(Entry::Absent))).collect();
        let applied = wanted.into_iter().map(|(k, v)| (k.to_string(), Entry::Present(v))).collect();
        Ok(Self { before, applied })
    }

    pub fn apply_to(&self, current: &Settings) -> Settings {
        merge(current, &self.applied)
    }

    pub fn restore(&self, current: &Settings) -> Restore {
        if matches(current, &self.before) {
            Restore::AlreadyRestored
        } else if matches(current, &self.applied) {
            Restore::Apply(merge(current, &self.before))
        } else {
            Restore::Conflict
        }
    }
}

fn matches(current: &Settings, expected: &BTreeMap<String, Entry>) -> bool {
    expected.iter().all(|(key, value)| match value {
        Entry::Absent => !current.contains_key(key),
        Entry::Present(value) => current.get(key) == Some(value),
    })
}

fn merge(current: &Settings, values: &BTreeMap<String, Entry>) -> Settings {
    let mut result = current.clone();
    for (key, value) in values {
        match value {
            Entry::Present(v) => { result.insert(key.clone(), v.clone()); }
            Entry::Absent => { result.remove(key); }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_original_and_preserves_unrelated_changes() {
        let original = BTreeMap::from([
            ("HTTPEnable".into(), json!(1)), ("HTTPProxy".into(), json!("old.example")),
            ("HTTPPort".into(), json!(8080)), ("ProxyAutoConfigEnable".into(), json!(1)),
            ("ProxyAutoConfigURLString".into(), json!("https://example.test/proxy.pac")),
        ]);
        let plan = ProxyPlan::new(&original, "127.0.0.1:7890", "localhost;127.*;<local>").unwrap();
        let mut active = plan.apply_to(&original);
        active.insert("Unrelated".into(), json!("changed"));
        let Restore::Apply(restored) = plan.restore(&active) else { panic!("expected restore") };
        let mut expected = original.clone();
        expected.insert("Unrelated".into(), json!("changed"));
        assert_eq!(restored, expected);
        assert_eq!(plan.restore(&restored), Restore::AlreadyRestored);
    }

    #[test]
    fn external_changes_are_never_overwritten() {
        let old = Settings::new();
        let plan = ProxyPlan::new(&old, "127.0.0.1:7890", "").unwrap();
        let mut active = plan.apply_to(&old);
        active.insert("HTTPProxy".into(), json!("another-proxy"));
        assert_eq!(plan.restore(&active), Restore::Conflict);
    }

    #[test]
    fn plan_roundtrip_and_recovery_before_commit() {
        let old = BTreeMap::from([("HTTPProxy".into(), Value::Null)]);
        let plan = ProxyPlan::new(&old, "[::1]:7890", "").unwrap();
        let saved = serde_json::to_vec(&plan).unwrap();
        let restored: ProxyPlan = serde_json::from_slice(&saved).unwrap();
        assert_eq!(plan, restored);
        assert_eq!(restored.restore(&old), Restore::AlreadyRestored);
    }

    #[test]
    fn invalid_addresses_and_exceptions_fail_closed() {
        for address in ["localhost", ":80", "127.0.0.1:0", "127.0.0.1:65536"] {
            assert!(ProxyPlan::new(&Settings::new(), address, "").is_err());
        }
        assert!(ProxyPlan::new(&Settings::new(), "127.0.0.1:7890", "<unknown>").is_err());
    }
}
