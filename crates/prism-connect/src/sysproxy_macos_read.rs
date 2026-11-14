//! Read-only inspection of the effective macOS HTTP and HTTPS proxy settings.
//!
//! This deliberately provides no mutation API. Persistent settings must only
//! be changed after transactional backup and recovery are implemented.
use std::{ffi::{c_char, c_void, CString}, ptr};

type CfRef = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
    fn CFStringCreateWithCString(alloc: CfRef, string: *const c_char, encoding: u32) -> CfRef;
    fn CFStringGetCString(string: CfRef, buffer: *mut c_char, capacity: isize, encoding: u32) -> u8;
    fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    fn CFGetTypeID(value: CfRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFNumberGetValue(number: CfRef, kind: i32, value: *mut c_void) -> u8;
    fn CFArrayGetCount(array: CfRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CfRef, index: isize) -> CfRef;
    fn CFPropertyListCreateData(alloc: CfRef, plist: CfRef, format: isize, options: usize, error: *mut CfRef) -> CfRef;
    fn CFDataGetLength(data: CfRef) -> isize;
    fn CFDataGetBytePtr(data: CfRef) -> *const u8;
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCDynamicStoreCopyProxies(store: CfRef) -> CfRef;
    fn SCPreferencesCreate(alloc: CfRef, name: CfRef, prefs_id: CfRef) -> CfRef;
    fn SCNetworkSetCopyCurrent(prefs: CfRef) -> CfRef;
    fn SCNetworkSetGetSetID(set: CfRef) -> CfRef;
    fn SCNetworkSetCopyServices(set: CfRef) -> CfRef;
    fn SCNetworkServiceCopyAll(prefs: CfRef) -> CfRef;
    fn SCNetworkServiceGetServiceID(service: CfRef) -> CfRef;
    fn SCNetworkServiceGetName(service: CfRef) -> CfRef;
    fn SCNetworkServiceGetInterface(service: CfRef) -> CfRef;
    fn SCNetworkInterfaceGetBSDName(interface: CfRef) -> CfRef;
    fn SCNetworkServiceCopyProtocol(service: CfRef, protocol_type: CfRef) -> CfRef;
    fn SCNetworkProtocolGetConfiguration(protocol: CfRef) -> CfRef;
    static kSCNetworkProtocolTypeProxies: CfRef;
}

/// Resolve a named service and require that it belongs to the expected hardware interface.
#[cfg(test)]
pub fn service_named(name: &str, interface: &str) -> Result<String, &'static str> {
    unsafe {
        let label = owned_string("PrismRoute test inspection")?;
        let prefs = SCPreferencesCreate(ptr::null(), label.0, ptr::null());
        if prefs.is_null() { return Err("could not open preferences") }
        let prefs = Owned(prefs);
        let set = SCNetworkSetCopyCurrent(prefs.0);
        if set.is_null() { return Err("no current network location") }
        let set = Owned(set);
        let services = SCNetworkSetCopyServices(set.0);
        if services.is_null() { return Err("cannot list services") }
        let services = Owned(services);
        let mut matches = Vec::new();
        for i in 0..CFArrayGetCount(services.0) {
            let s = CFArrayGetValueAtIndex(services.0, i);
            if s.is_null() || string_value(SCNetworkServiceGetName(s)).ok().as_deref() != Some(name) { continue }
            let device = SCNetworkServiceGetInterface(s);
            if device.is_null() || string_value(SCNetworkInterfaceGetBSDName(device)).ok().as_deref() != Some(interface) { return Err("service interface mismatch") }
            matches.push(string_value(SCNetworkServiceGetServiceID(s))?);
        }
        if matches.len() != 1 { return Err("service name is missing or ambiguous") }
        Ok(matches.remove(0))
    }
}

const UTF8: u32 = 0x0800_0100;
const SINT64: i32 = 4;

struct Owned(CfRef);
impl Drop for Owned {
    fn drop(&mut self) { unsafe { CFRelease(self.0) } }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Proxy {
    pub enabled: bool,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Effective {
    pub http: Proxy,
    pub https: Proxy,
    pub auto_config: bool,
    pub auto_discovery: bool,
}

/// An unmodified binary property list or an absent proxy protocol/configuration.
#[derive(Debug, PartialEq, Eq)]
pub struct ServiceSnapshot {
    pub service_id: String,
    pub proxy_protocol_exists: bool,
    pub configuration: Option<Vec<u8>>,
}

unsafe fn owned_string(value: &str) -> Result<Owned, &'static str> {
    let value = CString::new(value).map_err(|_| "invalid text")?;
    let ptr = CFStringCreateWithCString(ptr::null(), value.as_ptr(), UTF8);
    if ptr.is_null() { return Err("could not allocate string") }
    Ok(Owned(ptr))
}

unsafe fn string_value(value: CfRef) -> Result<String, &'static str> {
    if value.is_null() || CFGetTypeID(value) != CFStringGetTypeID() {
        return Err("unexpected string type");
    }
    let mut buffer = vec![0_u8; 4096];
    if CFStringGetCString(value, buffer.as_mut_ptr().cast(), buffer.len() as isize, UTF8) == 0 {
        return Err("invalid or oversized string");
    }
    let end = buffer.iter().position(|b| *b == 0).ok_or("invalid string")?;
    String::from_utf8(buffer[..end].to_vec()).map_err(|_| "invalid string")
}

/// Read the complete per-service proxy dictionaries for the current location.
/// The caller must protect any saved snapshots because they may contain sensitive metadata.
pub fn service_snapshots() -> Result<Vec<ServiceSnapshot>, &'static str> {
    snapshots(false)
}

/// Identifies the current network location, independent of its visible name.
pub fn current_location_id() -> Result<String, &'static str> {
    unsafe {
        let name = owned_string("PrismRoute proxy inspection")?;
        let prefs = SCPreferencesCreate(ptr::null(), name.0, ptr::null());
        if prefs.is_null() { return Err("could not open network preferences") }
        let prefs = Owned(prefs);
        let set = SCNetworkSetCopyCurrent(prefs.0);
        if set.is_null() { return Err("no current network location") }
        let set = Owned(set);
        string_value(SCNetworkSetGetSetID(set.0))
    }
}

/// Read persistent proxy dictionaries for every service, including inactive locations.
pub fn all_service_snapshots() -> Result<Vec<ServiceSnapshot>, &'static str> {
    snapshots(true)
}

fn snapshots(all: bool) -> Result<Vec<ServiceSnapshot>, &'static str> {
    unsafe {
        let name = owned_string("PrismRoute proxy inspection")?;
        let prefs = SCPreferencesCreate(ptr::null(), name.0, ptr::null());
        if prefs.is_null() { return Err("could not open network preferences") }
        let prefs = Owned(prefs);
        let services = if all {
            SCNetworkServiceCopyAll(prefs.0)
        } else {
            let set = SCNetworkSetCopyCurrent(prefs.0);
            if set.is_null() { return Err("no current network location") }
            let set = Owned(set);
            SCNetworkSetCopyServices(set.0)
        };
        if services.is_null() { return Err("could not list network services") }
        let services = Owned(services);
        let count = CFArrayGetCount(services.0);
        if count < 0 || count > 1024 { return Err("invalid network service count") }
        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count {
            let service = CFArrayGetValueAtIndex(services.0, i);
            if service.is_null() { return Err("invalid network service") }
            let service_id = string_value(SCNetworkServiceGetServiceID(service))?;
            let protocol = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies);
            if protocol.is_null() {
                result.push(ServiceSnapshot { service_id, proxy_protocol_exists: false, configuration: None });
                continue;
            }
            let protocol = Owned(protocol);
            let config = SCNetworkProtocolGetConfiguration(protocol.0);
            let configuration = if config.is_null() { None } else {
                // Binary plist preserves CoreFoundation types without JSON conversion.
                let data = CFPropertyListCreateData(ptr::null(), config, 200, 0, ptr::null_mut());
                if data.is_null() { return Err("could not serialize network service proxy settings") }
                let data = Owned(data);
                let len = CFDataGetLength(data.0);
                if !(0..=1024 * 1024).contains(&len) { return Err("invalid proxy settings size") }
                let bytes = CFDataGetBytePtr(data.0);
                if bytes.is_null() && len != 0 { return Err("invalid proxy settings data") }
                Some(if len == 0 { Vec::new() } else { std::slice::from_raw_parts(bytes, len as usize).to_vec() })
            };
            result.push(ServiceSnapshot { service_id, proxy_protocol_exists: true, configuration });
        }
        Ok(result)
    }
}

unsafe fn lookup(dictionary: CfRef, key: &str) -> Result<CfRef, &'static str> {
    let name = CString::new(key).map_err(|_| "invalid key")?;
    let name = CFStringCreateWithCString(ptr::null(), name.as_ptr(), UTF8);
    if name.is_null() { return Err("could not allocate key") }
    let name = Owned(name);
    Ok(CFDictionaryGetValue(dictionary, name.0))
}

unsafe fn number(dictionary: CfRef, key: &str) -> Result<Option<i64>, &'static str> {
    let value = lookup(dictionary, key)?;
    if value.is_null() { return Ok(None) }
    if CFGetTypeID(value) != CFNumberGetTypeID() { return Err("unexpected proxy setting type") }
    let mut result = 0_i64;
    if CFNumberGetValue(value, SINT64, (&mut result as *mut i64).cast()) == 0 {
        return Err("invalid numeric proxy setting");
    }
    Ok(Some(result))
}

unsafe fn string(dictionary: CfRef, key: &str) -> Result<Option<String>, &'static str> {
    let value = lookup(dictionary, key)?;
    if value.is_null() { return Ok(None) }
    Ok(Some(string_value(value)?))
}

unsafe fn proxy(dictionary: CfRef, prefix: &str) -> Result<Proxy, &'static str> {
    let enabled = number(dictionary, &format!("{prefix}Enable"))?.unwrap_or(0) != 0;
    let host = string(dictionary, &format!("{prefix}Proxy"))?;
    let port = number(dictionary, &format!("{prefix}Port"))?
        .map(|n| u16::try_from(n).map_err(|_| "invalid proxy port"))
        .transpose()?;
    Ok(Proxy { enabled, host, port })
}

pub fn effective() -> Result<Effective, &'static str> {
    unsafe {
        let dictionary = SCDynamicStoreCopyProxies(ptr::null());
        if dictionary.is_null() { return Err("could not read system proxy settings") }
        let dictionary = Owned(dictionary);
        Ok(Effective {
            http: proxy(dictionary.0, "HTTP")?,
            https: proxy(dictionary.0, "HTTPS")?,
            auto_config: number(dictionary.0, "ProxyAutoConfigEnable")?.unwrap_or(0) != 0,
            auto_discovery: number(dictionary.0, "ProxyAutoDiscoveryEnable")?.unwrap_or(0) != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_effective_configuration_without_mutating_it() {
        let _ = super::effective().expect("cannot read effective proxy settings");
    }

    #[test]
    fn reads_service_snapshots_without_mutating_them() {
        let location = super::current_location_id().expect("cannot inspect current location");
        assert!(!location.is_empty(), "current location has no identifier");
        let snapshots = super::service_snapshots().expect("cannot inspect proxy services");
        let all = super::all_service_snapshots().expect("cannot inspect all proxy services");
        assert!(!snapshots.is_empty(), "current network location has no services");
        assert!(snapshots.iter().all(|s| !s.service_id.is_empty()));
        assert!(snapshots.iter().filter_map(|s| s.configuration.as_ref()).all(|b| b.starts_with(b"bplist00")));
        assert!(snapshots.iter().all(|s| all.iter().any(|a| a.service_id == s.service_id)), "all-services enumeration misses a current service");
    }
}
