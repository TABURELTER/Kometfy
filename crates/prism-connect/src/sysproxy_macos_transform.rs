//! Pure, type-preserving proxy dictionary transformations. No system changes.
use plist::{Dictionary, Value};

const KEYS: &[&str] = &[
    "HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort",
    "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable", "ExceptionsList",
    "ExcludeSimpleHostnames",
];

fn dictionary(bytes: &[u8]) -> Result<Dictionary, &'static str> {
    if bytes.len() > 1024 * 1024 { return Err("proxy settings exceed size limit"); }
    match Value::from_reader(std::io::Cursor::new(bytes)).map_err(|_| "invalid proxy property list")? {
        Value::Dictionary(d) => Ok(d),
        _ => Err("proxy property list is not a dictionary"),
    }
}

fn encode(value: Dictionary) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    Value::Dictionary(value).to_writer_binary(&mut out).map_err(|_| "cannot encode proxy property list")?;
    if out.len() > 1024 * 1024 { return Err("proxy settings exceed size limit"); }
    Ok(out)
}

fn endpoint(address: &str) -> Result<(&str, u16), &'static str> {
    let (host, port) = address.rsplit_once(':').ok_or("invalid proxy address")?;
    let host = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    let port = port.parse::<u16>().map_err(|_| "invalid proxy port")?;
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c == '\0') || port == 0 {
        return Err("invalid proxy address");
    }
    // A network-settings helper must only ever direct traffic to this machine.
    // PrismRoute currently uses 127.0.0.1; accept literal IPv6 loopback as well.
    if !host.eq_ignore_ascii_case("localhost")
        && !host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return Err("proxy address must be loopback");
    }
    Ok((host, port))
}

/// An enabled proxy with missing or malformed host/port is unknown, not safe.
pub fn points_to_values(enabled: bool, host: Option<&str>, port: Option<u16>, ours: &str) -> Result<bool, &'static str> {
    let (our_host, our_port) = endpoint(ours)?;
    if !enabled { return Ok(false); }
    let host = host.filter(|h| !h.is_empty() && !h.chars().any(char::is_whitespace)).ok_or("enabled proxy has no valid host")?;
    let port = port.filter(|p| *p != 0).ok_or("enabled proxy has no valid port")?;
    let equivalent_host = host.eq_ignore_ascii_case(our_host)
        || host.parse::<std::net::IpAddr>().ok().zip(our_host.parse::<std::net::IpAddr>().ok()).is_some_and(|(a, b)| a == b)
        || (host.eq_ignore_ascii_case("localhost") && our_host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()))
        || (our_host.eq_ignore_ascii_case("localhost") && host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
    Ok(equivalent_host && port == our_port)
}

/// Examine HTTP and HTTPS independently; malformed settings fail closed.
pub fn points_to_proxy(bytes: &[u8], ours: &str) -> Result<bool, &'static str> {
    let d = dictionary(bytes)?;
    let mut found = false;
    for prefix in ["HTTP", "HTTPS"] {
        let enabled = match d.get(&format!("{prefix}Enable")) {
            None => false,
            Some(Value::Integer(v)) if v.as_unsigned() == Some(0) => false,
            Some(Value::Integer(v)) if v.as_unsigned() == Some(1) => true,
            Some(Value::Boolean(v)) => *v,
            _ => return Err("invalid proxy enabled flag"),
        };
        if !enabled { continue; }
        let host = match d.get(&format!("{prefix}Proxy")) {
            Some(Value::String(v)) => Some(v.as_str()), None => None,
            _ => return Err("invalid proxy host"),
        };
        let port = match d.get(&format!("{prefix}Port")) {
            Some(Value::Integer(v)) => v.as_unsigned().and_then(|v| u16::try_from(v).ok()),
            None => None,
            _ => return Err("invalid proxy port"),
        };
        // Continue checking even after one match so malformed settings are not ignored.
        found |= points_to_values(enabled, host, port, ours)?;
    }
    // Validate the address even if both protocol settings are disabled.
    endpoint(ours)?;
    Ok(found)
}

pub fn applied(before: &[u8], address: &str, bypass: &str) -> Result<Vec<u8>, &'static str> {
    let (host, port) = endpoint(address)?;
    let mut exceptions = Vec::new();
    let mut local = false;
    for item in bypass.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        if item.eq_ignore_ascii_case("<local>") { local = true; }
        else if item.starts_with('<') || item.contains('\0') { return Err("invalid proxy exception"); }
        else { exceptions.push(Value::String(item.to_owned())); }
    }
    let mut d = dictionary(before)?;
    for key in ["HTTPEnable", "HTTPSEnable"] { d.insert(key.into(), Value::Integer(1.into())); }
    for key in ["HTTPProxy", "HTTPSProxy"] { d.insert(key.into(), Value::String(host.to_owned())); }
    for key in ["HTTPPort", "HTTPSPort"] { d.insert(key.into(), Value::Integer((port as u64).into())); }
    for key in ["SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"] {
        d.insert(key.into(), Value::Integer(0.into()));
    }
    d.insert("ExceptionsList".into(), Value::Array(exceptions));
    d.insert("ExcludeSimpleHostnames".into(), Value::Integer((local as u64).into()));
    encode(d)
}

/// Check only the fields managed by PrismRoute; unrelated service metadata
/// can legitimately change while a connection is active.
pub fn matches_applied(current: &[u8], address: &str, bypass: &str) -> Result<bool, &'static str> {
    let actual = dictionary(current)?;
    let expected = dictionary(&applied(current, address, bypass)?)?;
    Ok(KEYS.iter().all(|key| actual.get(key) == expected.get(key)))
}

#[derive(Debug, PartialEq)]
pub enum Restoration { AlreadyRestored, Merged { data: Vec<u8>, conflict: bool }, Conflict }

/// Preserve all unrelated settings and refuse to overwrite externally changed managed keys.
pub fn restore(current: &[u8], before: &[u8], applied: &[u8]) -> Result<Restoration, &'static str> {
    let mut current = dictionary(current)?;
    let before = dictionary(before)?;
    let applied = dictionary(applied)?;
    if KEYS.iter().all(|k| current.get(k) == before.get(k)) { return Ok(Restoration::AlreadyRestored); }
    // A host, port, and enable flag are one setting: never combine one app's proxy
    // address with another app's port. Other settings can be restored separately.
    const GROUPS: &[&[&str]] = &[
        &["HTTPEnable", "HTTPProxy", "HTTPPort"],
        &["HTTPSEnable", "HTTPSProxy", "HTTPSPort"],
        &["ProxyAutoDiscoveryEnable"],
        &["ExceptionsList"], &["ExcludeSimpleHostnames"],
    ];
    let mut conflict = false;
    let mut changed = false;
    for group in GROUPS {
        if group.iter().all(|k| current.get(k) == before.get(k)) { continue; }
        if !group.iter().all(|k| current.get(k) == applied.get(k)) { conflict = true; continue; }
        for key in *group {
            match before.get(key) { Some(v) => { current.insert((*key).into(), v.clone()); }, None => { current.remove(key); } }
        }
        changed = true;
    }
    // Re-enabling a previous SOCKS or PAC setting is safe only if its target
    // still matches the snapshot. Another app may edit the target while the
    // protocol is disabled; restoring just the flag would activate its edits.
    for (flag, context) in [
        ("SOCKSEnable", &["SOCKSProxy", "SOCKSPort", "SOCKSUser", "SOCKSPassword"][..]),
        ("ProxyAutoConfigEnable", &["ProxyAutoConfigURLString", "ProxyAutoConfigJavaScript"][..]),
    ] {
        if current.get(flag) == before.get(flag) { continue; }
        if current.get(flag) != applied.get(flag)
            || !context.iter().all(|key| current.get(key) == applied.get(key)) {
            conflict = true;
            continue;
        }
        match before.get(flag) {
            Some(value) => { current.insert(flag.into(), value.clone()); }
            None => { current.remove(flag); }
        }
        changed = true;
    }
    if changed { Ok(Restoration::Merged { data: encode(current)?, conflict }) }
    else { Ok(Restoration::Conflict) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_managed_proxy_changes_without_reacting_to_unrelated_metadata() {
        let mut original = Dictionary::new();
        original.insert("Other".into(), Value::String("before".into()));
        let current = applied(&encode(original).unwrap(), "127.0.0.1:7890", "localhost;<local>").unwrap();
        assert!(matches_applied(&current, "127.0.0.1:7890", "localhost;<local>").unwrap());
        let mut edited = dictionary(&current).unwrap();
        edited.insert("Other".into(), Value::String("after".into()));
        assert!(matches_applied(&encode(edited.clone()).unwrap(), "127.0.0.1:7890", "localhost;<local>").unwrap());
        edited.insert("ExceptionsList".into(), Value::Array(vec![Value::String("*".into())]));
        assert!(!matches_applied(&encode(edited.clone()).unwrap(), "127.0.0.1:7890", "localhost;<local>").unwrap());
        edited = dictionary(&current).unwrap();
        edited.insert("SOCKSEnable".into(), Value::Integer(1.into()));
        assert!(!matches_applied(&encode(edited).unwrap(), "127.0.0.1:7890", "localhost;<local>").unwrap());
        assert!(!matches_applied(&current, "127.0.0.1:7891", "localhost;<local>").unwrap());
    }
    #[test]
    fn does_not_reenable_a_changed_socks_or_pac_target() {
        for (flag, target, original, other) in [
            ("SOCKSEnable", "SOCKSProxy", "old-proxy", "new-proxy"),
            ("ProxyAutoConfigEnable", "ProxyAutoConfigURLString", "https://old/pac", "https://new/pac"),
        ] {
            let mut old = Dictionary::new();
            old.insert(flag.into(), Value::Integer(1.into()));
            old.insert(target.into(), Value::String(original.into()));
            let before = encode(old).unwrap();
            let applied = applied(&before, "127.0.0.1:7890", "").unwrap();
            let mut edited = dictionary(&applied).unwrap();
            edited.insert(target.into(), Value::String(other.into()));
            let Restoration::Merged { data, conflict: true } = restore(&encode(edited).unwrap(), &before, &applied).unwrap() else { panic!("expected conflict for {flag}") };
            let result = dictionary(&data).unwrap();
            assert_eq!(result.get(flag), Some(&Value::Integer(0.into())));
            assert_eq!(result.get(target), Some(&Value::String(other.into())));
            assert_eq!(restore(&data, &before, &applied).unwrap(), Restoration::Conflict);
        }
    }
    #[test]
    fn only_loopback_proxy_endpoints_can_be_applied() {
        let before = encode(Dictionary::new()).unwrap();
        for address in ["127.0.0.1:7890", "[::1]:7890", "localhost:7890"] {
            assert!(applied(&before, address, "").is_ok(), "{address}");
        }
        for address in ["192.168.1.2:7890", "example.com:7890", "0.0.0.0:7890", "127.0.0.1:0", "127.0.0.1:notaport"] {
            assert!(applied(&before, address, "").is_err(), "{address}");
        }
    }
    #[test]
    fn roundtrip_preserves_unmanaged_types_and_detects_conflicts() {
        let mut old = Dictionary::new();
        old.insert("HTTPEnable".into(), Value::Integer(1.into()));
        old.insert("HTTPProxy".into(), Value::String("prior".into()));
        old.insert("SecretMetadata".into(), Value::Data(vec![0, 1, 2]));
        let before = encode(old.clone()).unwrap();
        let changed = applied(&before, "127.0.0.1:7890", "localhost;<local>").unwrap();
        let mut active = dictionary(&changed).unwrap();
        active.insert("Other".into(), Value::Boolean(true));
        let result = restore(&encode(active.clone()).unwrap(), &before, &changed).unwrap();
        let Restoration::Merged { data: result, conflict: false } = result else { panic!("not restored") };
        old.insert("Other".into(), Value::Boolean(true));
        assert_eq!(dictionary(&result).unwrap(), old);
        active.insert("HTTPProxy".into(), Value::String("other".into()));
        let Restoration::Merged { data: partly_restored, conflict: true } = restore(&encode(active).unwrap(), &before, &changed).unwrap() else { panic!("expected partial restore") };
        let partial = dictionary(&partly_restored).unwrap();
        assert_eq!(partial.get("HTTPProxy"), Some(&Value::String("other".into())));
        assert_eq!(partial.get("HTTPSEnable"), old.get("HTTPSEnable"));
        assert_eq!(restore(&before, &before, &changed).unwrap(), Restoration::AlreadyRestored);
    }

    #[test]
    fn detects_either_enabled_proxy_and_rejects_unknown_states() {
        let ours = "127.0.0.1:7890";
        let mut d = Dictionary::new();
        assert_eq!(points_to_proxy(&encode(d.clone()).unwrap(), ours), Ok(false));
        d.insert("HTTPEnable".into(), Value::Integer(1.into()));
        d.insert("HTTPProxy".into(), Value::String("127.0.0.1".into()));
        d.insert("HTTPPort".into(), Value::Integer(7890.into()));
        assert_eq!(points_to_proxy(&encode(d.clone()).unwrap(), ours), Ok(true));
        d.insert("HTTPEnable".into(), Value::Integer(0.into()));
        d.insert("HTTPSEnable".into(), Value::Integer(1.into()));
        d.insert("HTTPSProxy".into(), Value::String("localhost".into()));
        d.insert("HTTPSPort".into(), Value::Integer(7890.into()));
        assert_eq!(points_to_proxy(&encode(d.clone()).unwrap(), ours), Ok(true));
        d.insert("HTTPSPort".into(), Value::Integer(8888.into()));
        assert_eq!(points_to_proxy(&encode(d.clone()).unwrap(), ours), Ok(false));
        d.remove("HTTPSPort");
        assert!(points_to_proxy(&encode(d.clone()).unwrap(), ours).is_err());
        d.insert("HTTPEnable".into(), Value::String("yes".into()));
        assert!(points_to_proxy(&encode(d).unwrap(), ours).is_err());
        assert!(points_to_proxy(&encode(Dictionary::new()).unwrap(), "bad").is_err());
    }
}
