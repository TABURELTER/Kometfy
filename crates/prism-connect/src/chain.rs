//! Chain proxies.
//!
//! A chain `[A, B, C]` sends traffic client -> A -> B -> C -> target. mihomo expresses this with
//! `dialer-proxy`: "reach my server through that proxy". The original nodes stay untouched; for
//! every chain we add *clones* of hops 2..n whose `dialer-proxy` points at the previous hop, plus
//! a selectable group, so a node used standalone and inside a chain never interfere.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::{
    error::{Error, Result},
    paths::Paths,
    profiles::new_id,
    util::{k, put, str_of, write_atomic},
};

pub const CHAIN_PREFIX: &str = "⛓ ";
pub const CHAINS_GROUP: &str = "⛓ Chains";
pub const MAX_HOPS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Chain {
    pub id: String,
    pub name: String,
    /// Node names in traffic order: entry first, exit last.
    pub hops: Vec<String>,
    /// Profile the node names belong to. None = applies to any profile.
    pub profile: Option<String>,
}

/// Name of the selectable exit node (a clone of the last hop).
pub fn exit_name(c: &Chain) -> String {
    format!("{CHAIN_PREFIX}{}", c.name)
}

/// Name of the clone for hop `i` (0-based, never the first).
pub fn hop_name(c: &Chain, i: usize) -> String {
    format!("{CHAIN_PREFIX}{} ‹hop {}›", c.name, i + 1)
}

/// True for the internal intermediate clones the UI should hide.
pub fn is_internal_hop(name: &str) -> bool {
    name.starts_with(CHAIN_PREFIX) && name.ends_with('›') && name.contains(" ‹hop ")
}

fn clean_name(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '‹' && *c != '›')
        .collect::<String>()
        .trim()
        .chars()
        .take(40)
        .collect()
}

pub struct ChainStore {
    path: PathBuf,
    items: Vec<Chain>,
}

impl ChainStore {
    pub fn load(paths: &Paths) -> Self {
        let items = fs::read_to_string(paths.chains_file())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path: paths.chains_file(),
            items,
        }
    }

    pub fn items(&self) -> &[Chain] {
        &self.items
    }

    /// Insert or update (by id). Returns the stored, sanitized chain.
    pub fn save(&mut self, mut c: Chain) -> Result<Chain> {
        c.name = clean_name(&c.name);
        c.hops = c
            .hops
            .iter()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .take(MAX_HOPS)
            .collect();
        if c.hops.is_empty() {
            return Err(Error::msg("a chain needs at least one hop"));
        }
        if c.id.is_empty() {
            c.id = new_id();
        } else if !c.id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
            return Err(Error::msg("invalid chain id"));
        }
        if c.name.is_empty() {
            c.name = format!("Chain {}", self.items.len() + 1);
        }
        let base = c.name.clone();
        let mut n = 2;
        while exit_name(&c) == CHAINS_GROUP
            || self.items.iter().any(|o| o.id != c.id && o.name == c.name)
        {
            c.name = format!("{base} {n}");
            n += 1;
        }
        match self.items.iter_mut().find(|o| o.id == c.id) {
            Some(slot) => *slot = c.clone(),
            None => self.items.push(c.clone()),
        }
        self.persist()?;
        Ok(c)
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.items.retain(|c| c.id != id);
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        write_atomic(&self.path, serde_json::to_string_pretty(&self.items)?.as_bytes())
    }
}

#[derive(Debug, Default, Clone)]
pub struct InjectReport {
    pub exits: Vec<String>,
    pub broken: Vec<String>,
}

/// Add chain clones + the `⛓ Chains` group to a runtime config.
pub fn inject(
    root: &mut Mapping,
    chains: &[Chain],
    active_profile: Option<&str>,
    main_groups: &[String],
) -> InjectReport {
    let mut report = InjectReport::default();

    let mut by_name: HashMap<String, Mapping> = HashMap::new();
    if let Some(seq) = root.get("proxies").and_then(Value::as_sequence) {
        for p in seq {
            if let Some(m) = p.as_mapping() {
                if let Some(n) = str_of(m, "name") {
                    by_name.insert(n.to_string(), m.clone());
                }
            }
        }
    }
    let group_names: HashSet<String> = root
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .map(|s| {
            s.iter()
                .filter_map(|g| g.as_mapping().and_then(|m| str_of(m, "name")).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut added: Vec<Value> = Vec::new();
    for c in chains {
        if c.hops.len() < 2 {
            continue;
        }
        if let Some(cp) = c.profile.as_deref() {
            if active_profile != Some(cp) {
                continue;
            }
        }
        let first_ok = by_name.contains_key(&c.hops[0]) || group_names.contains(&c.hops[0]);
        let rest_ok = c.hops[1..].iter().all(|h| by_name.contains_key(h));
        if !(first_ok && rest_ok) {
            report.broken.push(c.name.clone());
            continue;
        }
        let last = c.hops.len() - 1;
        let mut prev = c.hops[0].clone();
        for i in 1..=last {
            let mut clone = by_name[&c.hops[i]].clone();
            let name = if i == last { exit_name(c) } else { hop_name(c, i) };
            put(&mut clone, "name", name.clone());
            put(&mut clone, "dialer-proxy", prev.clone());
            added.push(Value::Mapping(clone));
            prev = name;
        }
        report.exits.push(exit_name(c));
    }
    if report.exits.is_empty() {
        return report;
    }

    match root.get_mut("proxies") {
        Some(Value::Sequence(seq)) => seq.extend(added),
        _ => {
            root.insert(k("proxies"), Value::Sequence(added));
        }
    }

    if !matches!(root.get("proxy-groups"), Some(Value::Sequence(_))) {
        root.insert(k("proxy-groups"), Value::Sequence(vec![]));
    }
    let Some(groups) = root.get_mut("proxy-groups").and_then(Value::as_sequence_mut) else {
        return report;
    };
    let mut g = Mapping::new();
    put(&mut g, "name", CHAINS_GROUP);
    put(&mut g, "type", "select");
    put(
        &mut g,
        "proxies",
        Value::Sequence(report.exits.iter().map(|e| Value::String(e.clone())).collect()),
    );
    groups.push(Value::Mapping(g));

    for gv in groups.iter_mut() {
        let Value::Mapping(gm) = gv else { continue };
        let is_main = str_of(gm, "name").is_some_and(|n| main_groups.iter().any(|m| m == n));
        if !is_main {
            continue;
        }
        if let Some(Value::Sequence(list)) = gm.get_mut("proxies") {
            if !list.iter().any(|v| v.as_str() == Some(CHAINS_GROUP)) {
                list.push(Value::String(CHAINS_GROUP.to_string()));
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Mapping {
        let y = r#"
proxies:
  - {name: A, type: socks5, server: 1.1.1.1, port: 1}
  - {name: B, type: socks5, server: 2.2.2.2, port: 2}
  - {name: C, type: socks5, server: 3.3.3.3, port: 3}
proxy-groups:
  - {name: PROXY, type: select, proxies: [A, B, C, DIRECT]}
"#;
        serde_yaml::from_str::<Mapping>(y).unwrap()
    }

    fn chain(hops: &[&str]) -> Chain {
        Chain {
            id: "c1".into(),
            name: "Euro".into(),
            hops: hops.iter().map(|s| s.to_string()).collect(),
            profile: None,
        }
    }

    #[test]
    fn three_hops_link_through_dialer_proxy() {
        let mut root = sample();
        let r = inject(&mut root, &[chain(&["A", "B", "C"])], None, &["PROXY".into()]);
        assert_eq!(r.exits, vec!["⛓ Euro".to_string()]);
        let proxies = root.get("proxies").and_then(Value::as_sequence).unwrap();
        assert_eq!(proxies.len(), 5);
        let hop2 = proxies[3].as_mapping().unwrap();
        assert_eq!(str_of(hop2, "name"), Some("⛓ Euro ‹hop 2›"));
        assert_eq!(str_of(hop2, "dialer-proxy"), Some("A"));
        assert_eq!(str_of(hop2, "server"), Some("2.2.2.2"));
        let exit = proxies[4].as_mapping().unwrap();
        assert_eq!(str_of(exit, "name"), Some("⛓ Euro"));
        assert_eq!(str_of(exit, "dialer-proxy"), Some("⛓ Euro ‹hop 2›"));
        assert_eq!(str_of(exit, "server"), Some("3.3.3.3"));
        // originals untouched
        assert!(proxies[1].as_mapping().unwrap().get("dialer-proxy").is_none());
        // group + reference from the main selector
        let groups = root.get("proxy-groups").and_then(Value::as_sequence).unwrap();
        assert_eq!(groups.len(), 2);
        let main = groups[0].as_mapping().unwrap();
        let list = main.get("proxies").and_then(Value::as_sequence).unwrap();
        assert!(list.iter().any(|v| v.as_str() == Some(CHAINS_GROUP)));
    }

    #[test]
    fn missing_node_marks_chain_broken() {
        let mut root = sample();
        let r = inject(&mut root, &[chain(&["A", "ZZZ"])], None, &[]);
        assert!(r.exits.is_empty());
        assert_eq!(r.broken, vec!["Euro".to_string()]);
        assert_eq!(root.get("proxies").and_then(Value::as_sequence).unwrap().len(), 3);
    }

    #[test]
    fn other_profile_chain_skipped() {
        let mut root = sample();
        let mut c = chain(&["A", "B"]);
        c.profile = Some("other".into());
        let r = inject(&mut root, &[c], Some("mine"), &[]);
        assert!(r.exits.is_empty() && r.broken.is_empty());
    }

    #[test]
    fn hop_names_are_recognised_as_internal() {
        let c = chain(&["A", "B", "C"]);
        assert!(is_internal_hop(&hop_name(&c, 1)));
        assert!(!is_internal_hop(&exit_name(&c)));
    }
}
