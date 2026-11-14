//! User routing rules: a friendly, validated layer over mihomo's rule list.
//!
//! Rules are checked top to bottom, the first match wins. User rules sit in front of the
//! profile's own rules. A rule's `target` is symbolic so it survives a profile switch:
//! `@proxy` (the profile's default selector), `DIRECT`, `REJECT`, `@chain:<id>`, or a group /
//! server name of the profile.

use std::{fs, net::IpAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    paths::Paths,
    profiles::new_id,
    util::write_atomic,
};

pub const MAX_RULES: usize = 500;

/// mihomo rule types the editor can produce.
pub const KINDS: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "GEOSITE",
    "DST-PORT",
    "NETWORK",
    "RULE-SET",
];

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct UserRule {
    pub id: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub kind: String,
    pub value: String,
    pub target: String,
    pub note: String,
    /// IP-based kinds only: match when the destination is already an IP, never resolve a domain first.
    pub no_resolve: bool,
}

fn bad(value: &str, why: &str) -> Error {
    Error::msg(format!("“{value}”: {why}"))
}

fn has_forbidden(s: &str) -> bool {
    s.chars().any(|c| c == ',' || c.is_control())
}

fn parse_cidr(v: &str) -> Option<(IpAddr, u8, bool)> {
    let (ip, prefix) = match v.split_once('/') {
        Some((a, b)) => (a, Some(b.parse::<u8>().ok()?)),
        None => (v, None),
    };
    let addr: IpAddr = ip.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let p = prefix.unwrap_or(max);
    (p <= max).then_some((addr, p, addr.is_ipv6()))
}

fn valid_ports(v: &str) -> bool {
    !v.is_empty()
        && v.split('/').all(|part| {
            let mut it = part.split('-');
            let (a, b, extra) = (it.next(), it.next(), it.next());
            let ok = |s: &str| s.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
            extra.is_none() && a.is_some_and(ok) && b.is_none_or(ok)
        })
}

impl UserRule {
    /// Validate and canonicalize (lowercase domains, `/32` on bare IPs, IPv4/IPv6 kind fix-up...).
    pub fn normalize(mut self) -> Result<Self> {
        self.kind = self.kind.trim().to_uppercase();
        self.value = self.value.trim().to_string();
        self.target = self.target.trim().to_string();
        self.note = self.note.trim().chars().take(120).collect();
        if !KINDS.contains(&self.kind.as_str()) {
            return Err(bad(&self.kind, "unknown rule type"));
        }
        if self.value.is_empty() {
            return Err(Error::msg("a rule needs a value"));
        }
        if self.value.chars().count() > 200 {
            return Err(bad(&self.value[..20], "value is too long"));
        }
        if has_forbidden(&self.value) {
            return Err(bad(&self.value, "commas and control characters are not allowed"));
        }
        if self.target.is_empty() || self.target.chars().count() > 100 || has_forbidden(&self.target) {
            return Err(bad(&self.value, "pick where this traffic should go"));
        }
        if self.id.is_empty() {
            self.id = new_id();
        } else if !self.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::msg("invalid rule id"));
        }

        match self.kind.as_str() {
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-WILDCARD" => {
                let mut v = self.value.to_lowercase();
                if self.kind == "DOMAIN-SUFFIX" {
                    v = v.trim_start_matches("*.").trim_start_matches('.').to_string();
                }
                if v.is_empty() || v.chars().any(|c| c.is_whitespace() || c == '/' || c == ':') {
                    return Err(bad(&self.value, "enter a domain such as example.com"));
                }
                self.value = v;
            }
            "DOMAIN-REGEX" => {}
            "PROCESS-NAME" => {
                if self.value.contains(['/', '\\']) {
                    return Err(bad(&self.value, "use “program path” for full paths"));
                }
            }
            "PROCESS-PATH" => {}
            "IP-CIDR" | "IP-CIDR6" => {
                let (addr, prefix, v6) = parse_cidr(&self.value)
                    .ok_or_else(|| bad(&self.value, "enter an IP address or range such as 10.0.0.0/8"))?;
                self.kind = if v6 { "IP-CIDR6" } else { "IP-CIDR" }.into();
                self.value = format!("{addr}/{prefix}");
            }
            "GEOIP" => {
                let v = self.value.to_uppercase();
                let ok = (v.len() == 2 && v.chars().all(|c| c.is_ascii_alphabetic())) || v == "LAN" || v == "PRIVATE";
                if !ok {
                    return Err(bad(&self.value, "enter a two-letter country code such as RU"));
                }
                self.value = v;
            }
            "GEOSITE" => {
                let v = self.value.to_lowercase();
                if !v.chars().all(|c| c.is_ascii_alphanumeric() || "@!._-".contains(c)) {
                    return Err(bad(&self.value, "enter a site list name such as category-ads-all"));
                }
                self.value = v;
            }
            "DST-PORT" => {
                if !valid_ports(&self.value) {
                    return Err(bad(&self.value, "enter a port (443), a range (1000-2000) or several joined with /"));
                }
            }
            "NETWORK" => {
                let v = self.value.to_lowercase();
                if v != "tcp" && v != "udp" {
                    return Err(bad(&self.value, "use tcp or udp"));
                }
                self.value = v;
            }
            "RULE-SET" => {
                if !self.value.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
                    return Err(bad(&self.value, "enter the name of a rule set from the profile"));
                }
            }
            _ => {}
        }
        if !matches!(self.kind.as_str(), "IP-CIDR" | "IP-CIDR6" | "GEOIP") {
            self.no_resolve = false;
        }
        Ok(self)
    }

    /// The rule as mihomo reads it, once the symbolic target has been resolved.
    pub fn rule_line(&self, target: &str) -> String {
        let mut s = format!("{},{},{}", self.kind, self.value, target);
        if self.no_resolve {
            s.push_str(",no-resolve");
        }
        s
    }
}

pub struct RuleStore {
    path: PathBuf,
    items: Vec<UserRule>,
}

impl RuleStore {
    pub fn load(paths: &Paths) -> Self {
        let items = fs::read_to_string(paths.rules_file())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path: paths.rules_file(),
            items,
        }
    }

    pub fn exists(paths: &Paths) -> bool {
        paths.rules_file().exists()
    }

    pub fn items(&self) -> &[UserRule] {
        &self.items
    }

    /// Replace the whole list (the editor reorders / toggles / edits and sends everything back).
    pub fn replace(&mut self, rules: Vec<UserRule>) -> Result<Vec<UserRule>> {
        if rules.len() > MAX_RULES {
            return Err(Error::msg(format!("at most {MAX_RULES} rules are supported")));
        }
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::with_capacity(rules.len());
        for r in rules {
            let mut r = r.normalize()?;
            while !seen.insert(r.id.clone()) {
                r.id = new_id();
            }
            out.push(r);
        }
        self.items = out.clone();
        self.persist()?;
        Ok(out)
    }

    fn persist(&self) -> Result<()> {
        write_atomic(&self.path, serde_json::to_string_pretty(&self.items)?.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: &str, value: &str) -> UserRule {
        UserRule {
            kind: kind.into(),
            value: value.into(),
            target: "DIRECT".into(),
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn domains_are_canonicalized() {
        let r = rule("domain-suffix", "  *.Claude.AI ").normalize().unwrap();
        assert_eq!((r.kind.as_str(), r.value.as_str()), ("DOMAIN-SUFFIX", "claude.ai"));
        assert!(!r.id.is_empty());
        assert!(rule("DOMAIN", "a b.com").normalize().is_err());
        assert!(rule("DOMAIN", "https://a.com").normalize().is_err());
    }

    #[test]
    fn ip_ranges_fix_family_and_prefix() {
        let a = rule("IP-CIDR", "10.1.2.3").normalize().unwrap();
        assert_eq!(a.value, "10.1.2.3/32");
        let b = rule("IP-CIDR", "fd00::/8").normalize().unwrap();
        assert_eq!((b.kind.as_str(), b.value.as_str()), ("IP-CIDR6", "fd00::/8"));
        assert!(rule("IP-CIDR", "10.0.0.0/33").normalize().is_err());
        assert!(rule("IP-CIDR", "not-an-ip").normalize().is_err());
    }

    #[test]
    fn ports_programs_and_lists() {
        assert!(rule("DST-PORT", "443").normalize().is_ok());
        assert!(rule("DST-PORT", "80/8080-8090").normalize().is_ok());
        assert!(rule("DST-PORT", "0").normalize().is_err());
        assert!(rule("DST-PORT", "70000").normalize().is_err());
        assert!(rule("PROCESS-NAME", "steam.exe").normalize().is_ok());
        assert!(rule("PROCESS-NAME", "C:\\Games\\steam.exe").normalize().is_err());
        assert_eq!(rule("GEOIP", "ru").normalize().unwrap().value, "RU");
        assert_eq!(rule("GEOSITE", "Category-Ads-All").normalize().unwrap().value, "category-ads-all");
        assert!(rule("NETWORK", "icmp").normalize().is_err());
    }

    #[test]
    fn commas_and_empty_targets_are_rejected() {
        assert!(rule("DOMAIN-REGEX", "a,b").normalize().is_err());
        let mut r = rule("DOMAIN", "a.com");
        r.target = String::new();
        assert!(r.normalize().is_err());
        assert!(rule("MATCH", "x").normalize().is_err());
    }

    #[test]
    fn no_resolve_only_for_ip_kinds() {
        let mut a = rule("DOMAIN", "a.com");
        a.no_resolve = true;
        assert!(!a.normalize().unwrap().no_resolve);
        let mut b = rule("IP-CIDR", "10.0.0.0/8");
        b.no_resolve = true;
        let b = b.normalize().unwrap();
        assert_eq!(b.rule_line("DIRECT"), "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
    }

    #[test]
    fn duplicate_ids_get_fresh_ones() {
        let dir = std::env::temp_dir().join(format!("prism-rules-{}", std::process::id()));
        let paths = Paths::new(dir.clone());
        paths.ensure().unwrap();
        let mut store = RuleStore::load(&paths);
        let mut a = rule("DOMAIN", "a.com");
        a.id = "same".into();
        let mut b = rule("DOMAIN", "b.com");
        b.id = "same".into();
        let out = store.replace(vec![a, b]).unwrap();
        assert_ne!(out[0].id, out[1].id);
        assert_eq!(RuleStore::load(&paths).items().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
