//! macOS utun primitives. The app does not enable TUN until the privileged
//! helper and its routing, DNS and recovery lifecycle are connected.
//!
//! An interface name alone does not prove that it belongs to the core.

/// Route output is untrusted input even though the command itself is fixed.
/// Do not allow the current VPN interface, loopback, or a shell-like name as
/// an outbound interface: that would immediately feed traffic back into TUN.
pub(crate) fn valid_outbound_interface(name: &str) -> bool {
    !name.is_empty() && name.len() < 16
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && !["utun", "tun", "lo", "gif", "stf"].iter().any(|prefix| name.starts_with(prefix))
}

#[cfg(any(target_os = "macos", test))]
fn parse_default_interface(output: &str) -> std::io::Result<String> {
    let mut selected: Option<&str> = None;
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("default") { continue; }
        let Some(_gateway) = parts.next() else { return Err(std::io::Error::other("invalid default route")); };
        let Some(flags) = parts.next() else { return Err(std::io::Error::other("invalid default route")); };
        let Some(name) = parts.next() else { return Err(std::io::Error::other("invalid default route")); };
        // Ignore interface-scoped alternatives; only the active unscoped
        // default describes the system's normal outbound interface.
        if !flags.contains('U') || !flags.contains('G') || flags.contains('I') { continue; }
        if !valid_outbound_interface(name) { return Err(std::io::Error::other("unsafe default outbound interface")); }
        if selected.is_some_and(|previous| previous != name) { return Err(std::io::Error::other("ambiguous default outbound interface")); }
        selected = Some(name);
    }
    selected.map(str::to_owned).ok_or_else(|| std::io::Error::other("cannot determine a usable outbound interface"))
}

/// Gateways of active IPv4 routes must remain reachable outside the TUN. A
/// more-specific host route to one of them would prevent the physical network
/// from delivering traffic, including traffic bound to its interface.
#[cfg(any(target_os = "macos", test))]
fn parse_active_ipv4_gateways(output: &str) -> std::io::Result<Vec<std::net::Ipv4Addr>> {
    use std::net::Ipv4Addr;
    let mut gateways = Vec::new();
    let mut default: Option<(Ipv4Addr, &str)> = None;
    if !output.contains("Destination") || !output.contains("Gateway") {
        return Err(std::io::Error::other("unrecognized IPv4 route table"));
    }
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let Some(destination) = parts.next() else { continue };
        let Some(gateway) = parts.next() else { continue };
        let Some(flags) = parts.next() else { continue };
        if !flags.contains('U') || !flags.contains('G') { continue; }
        let interface = parts.next().ok_or_else(|| std::io::Error::other("invalid gateway route"))?;
        let gateway: Ipv4Addr = gateway.parse().map_err(|_| std::io::Error::other("cannot verify an IPv4 gateway"))?;
        if gateway.is_unspecified() || gateway.is_loopback() || gateway.is_multicast() || gateway.is_broadcast() {
            return Err(std::io::Error::other("invalid IPv4 gateway"));
        }
        if !gateways.contains(&gateway) { gateways.push(gateway); }
        if destination == "default" && !flags.contains('I') {
            if !valid_outbound_interface(interface) { return Err(std::io::Error::other("unsafe default outbound interface")); }
            let candidate = (gateway, interface);
            if default.is_some_and(|previous| previous != candidate) {
                return Err(std::io::Error::other("ambiguous default gateway"));
            }
            default = Some(candidate);
        }
    }
    if default.is_none() { return Err(std::io::Error::other("cannot verify the default IPv4 gateway")); }
    Ok(gateways)
}

#[cfg(target_os = "macos")]
fn ipv4_route_table() -> std::io::Result<String> {
    let mut command = std::process::Command::new("/usr/sbin/netstat");
    command.args(["-rn", "-f", "inet"]).env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").env("LC_ALL", "C");
    let result = crate::macos_installer_runner::run_process(&mut command, std::time::Duration::from_secs(5), 1024 * 1024)
        .map_err(std::io::Error::other)?;
    if !result.success { return Err(std::io::Error::other("cannot inspect the IPv4 route table")); }
    Ok(result.stdout)
}

/// Refuse to capture a DNS server that is itself a currently used gateway.
/// Never include resolver or gateway addresses in an error or log message.
#[cfg(any(target_os = "macos", test))]
fn dns_uses_gateway_in_routes(dns: &[std::net::Ipv4Addr], routes: &str) -> std::io::Result<bool> {
    let gateways = parse_active_ipv4_gateways(routes)?;
    Ok(dns.iter().any(|address| gateways.contains(address)))
}

/// The default gateway can change while the interface name remains the same,
/// for example when DHCP renews or a Mac joins another Wi-Fi network.
#[cfg(any(target_os = "macos", test))]
fn parse_default_gateway(output: &str) -> std::io::Result<std::net::Ipv4Addr> {
    let mut selected = None;
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("default") { continue; }
        let gateway = parts.next().ok_or_else(|| std::io::Error::other("invalid default gateway"))?;
        let flags = parts.next().ok_or_else(|| std::io::Error::other("invalid default gateway"))?;
        let interface = parts.next().ok_or_else(|| std::io::Error::other("invalid default gateway"))?;
        if !flags.contains('U') || !flags.contains('G') || flags.contains('I') { continue; }
        if !valid_outbound_interface(interface) { return Err(std::io::Error::other("unsafe default outbound interface")); }
        let gateway: std::net::Ipv4Addr = gateway.parse().map_err(|_| std::io::Error::other("invalid default gateway"))?;
        if gateway.is_unspecified() || gateway.is_loopback() || gateway.is_multicast() || gateway.is_broadcast() {
            return Err(std::io::Error::other("invalid default gateway"));
        }
        let candidate = (gateway, interface);
        if selected.is_some_and(|previous| previous != candidate) {
            return Err(std::io::Error::other("ambiguous default gateway"));
        }
        selected = Some(candidate);
    }
    selected.map(|(gateway, _)| gateway).ok_or_else(|| std::io::Error::other("cannot verify the default IPv4 gateway"))
}

/// The settings whose change can invalidate a running IPv4-only TUN session.
/// Addresses are only used for equality checks and are never logged.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TunNetworkSnapshot {
    dns: Vec<std::net::Ipv4Addr>,
    default_gateway: std::net::Ipv4Addr,
}

#[cfg(any(target_os = "macos", test))]
fn network_snapshot_from(mut dns: Vec<std::net::Ipv4Addr>, routes: &str) -> std::io::Result<TunNetworkSnapshot> {
    dns.sort_unstable();
    dns.dedup();
    if dns_uses_gateway_in_routes(&dns, routes)? {
        return Err(std::io::Error::other("System DNS is also a network gateway; TUN cannot safely capture it on macOS yet"));
    }
    Ok(TunNetworkSnapshot { dns, default_gateway: parse_default_gateway(routes)? })
}

#[cfg(target_os = "macos")]
pub(crate) fn tun_network_snapshot() -> std::io::Result<TunNetworkSnapshot> {
    require_no_ipv6().map_err(|_| std::io::Error::other("IPv6 is active; IPv4-only TUN cannot be enabled safely"))?;
    let dns = system_ipv4_dns().map_err(|_| std::io::Error::other("System DNS includes an unsupported or unavailable resolver"))?;
    let routes = ipv4_route_table()?;
    network_snapshot_from(dns, &routes)
}

#[cfg(target_os = "macos")]
pub(crate) fn dns_uses_active_gateway(dns: &[std::net::Ipv4Addr]) -> std::io::Result<bool> {
    dns_uses_gateway_in_routes(dns, &ipv4_route_table()?)
}

/// Resolve the system's unscoped IPv4 default route before and during TUN.
/// Reading the routing table is non-mutating; gateway addresses are not logged.
#[cfg(target_os = "macos")]
pub(crate) fn default_outbound_interface() -> std::io::Result<String> {
    let name = parse_default_interface(&ipv4_route_table()?)?;
    let c_name = std::ffi::CString::new(name.as_str()).map_err(std::io::Error::other)?;
    if unsafe { libc::if_nametoindex(c_name.as_ptr()) } == 0 {
        return Err(std::io::Error::other("default outbound interface disappeared"));
    }
    let mut list = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 { return Err(std::io::Error::last_os_error()); }
    struct Interfaces(*mut libc::ifaddrs);
    impl Drop for Interfaces { fn drop(&mut self) { unsafe { libc::freeifaddrs(self.0) } } }
    let _owned = Interfaces(list);
    let mut current = list;
    let mut active = false;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null()
            && unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) } == c_name.as_c_str()
            && unsafe { (*entry.ifa_addr).sa_family as i32 } == libc::AF_INET
            && entry.ifa_flags & (libc::IFF_UP as u32) != 0
            && entry.ifa_flags & (libc::IFF_LOOPBACK as u32) == 0 {
            active = true;
            break;
        }
        current = entry.ifa_next;
    }
    if !active { return Err(std::io::Error::other("default outbound interface is not active")); }
    Ok(name)
}

#[cfg(target_os = "macos")]
pub(crate) struct Utun {
    pub descriptor: std::os::fd::OwnedFd,
    pub name: String,
}

/// Transfer one descriptor over an already authenticated, private Unix socket.
/// The socket must be used for this frame only; authentication is the caller's
/// responsibility. This primitive itself does not make an IPC peer trustworthy.
#[cfg(target_os = "macos")]
pub(crate) fn send_descriptor(socket: std::os::fd::BorrowedFd<'_>, descriptor: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    use std::{mem, os::fd::AsRawFd};
    #[repr(C, align(16))]
    struct Control([u8; 128]);
    let mut control = Control([0; 128]);
    let mut byte = [b'F'];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) } as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        if header.is_null() { return Err(std::io::Error::other("cannot create descriptor message")); }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as _) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), descriptor.as_raw_fd());
        if libc::sendmsg(socket.as_raw_fd(), &msg, 0) != 1 { return Err(std::io::Error::last_os_error()); }
    }
    Ok(())
}

/// The sender keeps its original fd open until this acknowledgement arrives.
/// This function is for the helper process, not the UI thread.
#[cfg(target_os = "macos")]
pub(crate) fn send_descriptor_and_confirm(socket: std::os::fd::BorrowedFd<'_>, descriptor: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    send_descriptor(socket, descriptor)?;
    let mut poll = libc::pollfd { fd: socket.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 5000) } <= 0 || poll.revents & libc::POLLIN == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "descriptor acknowledgement unavailable"));
    }
    let mut ack = [0u8; 1];
    let count = unsafe { libc::recv(socket.as_raw_fd(), ack.as_mut_ptr().cast(), 1, 0) };
    if count != 1 || ack != [b'A'] { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid descriptor acknowledgement")); }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn confirm_descriptor_received(socket: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let ack = [b'A'];
    if unsafe { libc::send(socket.as_raw_fd(), ack.as_ptr().cast(), 1, 0) } != 1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one descriptor. Call only in a single-threaded supervisor before it
/// can spawn children: macOS does not offer atomic MSG_CMSG_CLOEXEC, so setting
/// FD_CLOEXEC after recvmsg would otherwise race another thread's fork/exec.
/// All received descriptors are owned immediately and closed on any error.
#[cfg(target_os = "macos")]
pub(crate) fn receive_descriptor_single_threaded(socket: std::os::fd::BorrowedFd<'_>) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::{mem, os::fd::{AsRawFd, FromRawFd, OwnedFd}};
    #[repr(C, align(16))]
    struct Control([u8; 128]);
    let mut control = Control([0; 128]);
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = control.0.len() as _;
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if count < 0 { return Err(std::io::Error::last_os_error()); }
    let mut owned: Vec<OwnedFd> = Vec::new();
    let mut invalid = count != 1 || byte != [b'F'] || msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        let end = (msg.msg_control as usize).saturating_add(msg.msg_controllen as usize);
        while !header.is_null() {
            let len = (*header).cmsg_len as usize;
            let base = libc::CMSG_LEN(0) as usize;
            let available = end.saturating_sub(header as usize);
            if len < base || available < base { invalid = true; break; }
            if len > available { invalid = true; }
            let bytes = len.min(available) - base;
            if bytes % mem::size_of::<libc::c_int>() != 0 { invalid = true; }
            if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
                invalid = true;
            } else {
                let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for i in 0..bytes / mem::size_of::<libc::c_int>() {
                    let fd = std::ptr::read_unaligned(data.add(i));
                    if fd < 0 { invalid = true; continue; }
                    let owned_fd = OwnedFd::from_raw_fd(fd);
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 { invalid = true; }
                    owned.push(owned_fd);
                }
            }
            if len > available { break; }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    if invalid || owned.len() != 1 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid descriptor message")); }
    Ok(owned.pop().unwrap())
}

/// Reject ordinary files and sockets: only the kernel can answer this utun
/// control-socket query with a valid interface name.
#[cfg(target_os = "macos")]
pub(crate) fn descriptor_utun_name(descriptor: std::os::fd::BorrowedFd<'_>) -> std::io::Result<String> {
    use std::{ffi::CStr, os::fd::AsRawFd};
    let mut bytes = [0u8; libc::IFNAMSIZ];
    let mut length = bytes.len() as libc::socklen_t;
    if unsafe { libc::getsockopt(descriptor.as_raw_fd(), libc::SYSPROTO_CONTROL, libc::UTUN_OPT_IFNAME, bytes.as_mut_ptr().cast(), &mut length) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize > bytes.len() { return Err(std::io::Error::other("invalid utun name length")); }
    CStr::from_bytes_until_nul(&bytes[..length as usize]).ok().and_then(|s| s.to_str().ok())
        .filter(|name| valid_device(name)).map(str::to_owned)
        .ok_or_else(|| std::io::Error::other("invalid utun name"))
}

/// Only a connected local stream can be handed to the supervisor. It must be
/// authenticated as part of the enclosing helper channel, not by its pathname.
#[cfg(target_os = "macos")]
pub(crate) fn validate_handoff_socket(descriptor: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    use std::{mem, os::fd::AsRawFd};
    let fd = descriptor.as_raw_fd();
    let mut kind: libc::c_int = 0;
    let mut kind_len = mem::size_of_val(&kind) as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, (&mut kind as *mut libc::c_int).cast(), &mut kind_len) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if kind != libc::SOCK_STREAM { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "handoff requires a stream socket")); }
    let mut local: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&local) as libc::socklen_t;
    if unsafe { libc::getsockname(fd, (&mut local as *mut libc::sockaddr_storage).cast(), &mut len) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if local.ss_family as i32 != libc::AF_UNIX { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "handoff socket must be local")); }
    let mut remote: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&remote) as libc::socklen_t;
    if unsafe { libc::getpeername(fd, (&mut remote as *mut libc::sockaddr_storage).cast(), &mut len) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if remote.ss_family as i32 != libc::AF_UNIX { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "handoff peer must be local")); }
    Ok(())
}

/// Create a kernel-allocated utun without configuring its address, routes or
/// DNS. Only the narrowly scoped privileged helper should call this function.
/// The descriptor is closed on every failure and is close-on-exec by default.
#[cfg(target_os = "macos")]
pub(crate) fn create_utun() -> std::io::Result<Utun> {
    use std::{mem, os::fd::{AsFd, FromRawFd, OwnedFd}};
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut control: libc::ctl_info = unsafe { mem::zeroed() };
    let name = b"com.apple.net.utun_control\0";
    for (to, from) in control.ctl_name.iter_mut().zip(name) { *to = *from as libc::c_char; }
    if unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut control) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let address = libc::sockaddr_ctl {
        sc_len: mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: control.ctl_id,
        sc_unit: 0, // Ask the kernel for a free unit.
        sc_reserved: [0; 5],
    };
    if unsafe { libc::connect(raw, &address as *const _ as *const libc::sockaddr, mem::size_of_val(&address) as libc::socklen_t) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let name = descriptor_utun_name(descriptor.as_fd())?;
    Ok(Utun { descriptor, name })
}

/// The routing socket is opened before SystemConfiguration is initialized so
/// that setting close-on-exec cannot race a framework thread spawning a child.
#[cfg(target_os = "macos")]
pub(crate) fn open_route_socket() -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Refuse IPv4-only capture when the host has usable IPv6 on an active
/// interface. Link-local addresses are checked separately in DNS settings.
#[cfg(target_os = "macos")]
pub(crate) fn require_no_ipv6() -> std::io::Result<()> {
    use std::net::Ipv6Addr;
    struct Interfaces(*mut libc::ifaddrs);
    impl Drop for Interfaces { fn drop(&mut self) { unsafe { libc::freeifaddrs(self.0) } } }
    let mut list = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 { return Err(std::io::Error::last_os_error()); }
    let _owned = Interfaces(list);
    let mut item = list;
    while !item.is_null() {
        let entry = unsafe { &*item };
        if !entry.ifa_addr.is_null() && unsafe { (*entry.ifa_addr).sa_family as i32 } == libc::AF_INET6
            && entry.ifa_flags & (libc::IFF_UP as u32) != 0 && entry.ifa_flags & (libc::IFF_LOOPBACK as u32) == 0 {
            let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
            if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_unicast_link_local() && !ip.is_multicast() {
                return Err(std::io::Error::other("IPv6 is active; this TUN mode currently supports IPv4 only"));
            }
        }
        item = entry.ifa_next;
    }
    Ok(())
}

/// Read all configured resolver addresses from the OS; the command has no
/// writable inputs and is bounded. Local, IPv6 and unparseable DNS endpoints
/// cannot safely be captured by this IPv4 implementation.
#[cfg(target_os = "macos")]
pub(crate) fn system_ipv4_dns() -> std::io::Result<Vec<std::net::Ipv4Addr>> {
    let mut command = std::process::Command::new("/usr/sbin/scutil");
    command.arg("--dns").env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").env("LC_ALL", "C");
    let result = crate::macos_installer_runner::run_process(&mut command, std::time::Duration::from_secs(5), 1024 * 1024)
        .map_err(std::io::Error::other)?;
    if !result.success { return Err(std::io::Error::other("cannot inspect system DNS")); }
    let mut addresses = Vec::new();
    for line in result.stdout.lines().map(str::trim) {
        if !line.starts_with("nameserver[") { continue; }
        let value = line.split_once(':').ok_or_else(|| std::io::Error::other("invalid system DNS entry"))?.1.trim();
        // Scoped IPv6 addresses contain '%' and must be rejected as well.
        let parsed: std::net::IpAddr = value.split('%').next().unwrap_or("").parse()
            .map_err(|_| std::io::Error::other("invalid system DNS address"))?;
        let std::net::IpAddr::V4(ip) = parsed else { return Err(std::io::Error::other("IPv6 DNS is not supported by IPv4-only TUN")); };
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            return Err(std::io::Error::other("local or invalid system DNS is not supported by IPv4-only TUN"));
        }
        if !addresses.contains(&ip) { addresses.push(ip); }
        if addresses.len() > 32 { return Err(std::io::Error::other("too many system DNS servers")); }
    }
    if addresses.is_empty() { return Err(std::io::Error::other("no system DNS servers could be verified")); }
    Ok(addresses)
}

/// Add a route without replacing an existing entry. A kernel acknowledgement
/// for our PID/sequence is required; the caller must close the owning utun on
/// any error (including an ambiguous acknowledgement). No delete is issued.
#[cfg(target_os = "macos")]
pub(crate) fn add_ipv4_route(socket: std::os::fd::BorrowedFd<'_>, name: &str, dst: [u8; 4], mask: [u8; 4], sequence: i32) -> std::io::Result<()> {
    use std::{ffi::CString, mem, os::fd::AsRawFd};
    #[repr(C)]
    struct Message { header: libc::rt_msghdr, dst: libc::sockaddr_in, gateway: libc::sockaddr_in, mask: libc::sockaddr_in }
    let name = CString::new(name).map_err(|_| std::io::Error::other("invalid interface"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 || index > u16::MAX as u32 { return Err(std::io::Error::other("TUN interface disappeared")); }
    let mut msg: Message = unsafe { mem::zeroed() };
    msg.header.rtm_msglen = mem::size_of::<Message>() as u16;
    msg.header.rtm_version = libc::RTM_VERSION as u8;
    msg.header.rtm_type = libc::RTM_ADD as u8;
    msg.header.rtm_index = index as u16;
    msg.header.rtm_flags = libc::RTF_UP | libc::RTF_GATEWAY | libc::RTF_STATIC;
    if mask == [255, 255, 255, 255] { msg.header.rtm_flags |= libc::RTF_HOST; }
    msg.header.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
    msg.header.rtm_pid = unsafe { libc::getpid() };
    msg.header.rtm_seq = sequence;
    for (address, bytes) in [(&mut msg.dst, dst), (&mut msg.gateway, [198, 18, 0, 1]), (&mut msg.mask, mask)] {
        address.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
        address.sin_family = libc::AF_INET as u8;
        address.sin_addr.s_addr = u32::from_ne_bytes(bytes);
    }
    let count = unsafe { libc::write(socket.as_raw_fd(), (&msg as *const Message).cast(), mem::size_of::<Message>()) };
    if count != mem::size_of::<Message>() as isize { return Err(std::io::Error::last_os_error()); }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let remaining = deadline.checked_duration_since(std::time::Instant::now()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "routing acknowledgement timed out"))?;
        let mut poll = libc::pollfd { fd: socket.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().clamp(1, 3000) as i32) };
        if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted { continue; }
        if ready <= 0 || poll.revents & libc::POLLIN == 0 { return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "routing acknowledgement unavailable")); }
        let mut data = [0_u8; 2048];
        let count = unsafe { libc::read(socket.as_raw_fd(), data.as_mut_ptr().cast(), data.len()) };
        if count < mem::size_of::<libc::rt_msghdr>() as isize { return Err(std::io::Error::other("invalid routing acknowledgement")); }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<libc::rt_msghdr>()) };
        if header.rtm_version as i32 != libc::RTM_VERSION || header.rtm_msglen as usize > count as usize { return Err(std::io::Error::other("invalid routing acknowledgement")); }
        if header.rtm_pid != msg.header.rtm_pid || header.rtm_seq != sequence { continue; }
        if header.rtm_errno != 0 { return Err(std::io::Error::from_raw_os_error(header.rtm_errno)); }
        if header.rtm_type as i32 != libc::RTM_ADD || header.rtm_index as u32 != index { return Err(std::io::Error::other("route was not attached to the TUN interface")); }
        return Ok(());
    }
}

/// `utun` interfaces are kernel allocated; the requested name must include a
/// canonical decimal unit and fit within Darwin's IFNAMSIZ (including NUL).
fn valid_device(name: &str) -> bool {
    if name.len() >= 16 { return false; }
    let Some(unit) = name.strip_prefix("utun") else { return false };
    if unit.is_empty() || !unit.bytes().all(|c| c.is_ascii_digit()) { return false; }
    // Mihomo's Darwin name validation parses this as a signed 16-bit unit.
    unit.parse::<i16>().is_ok_and(|number| number >= 0 && number.to_string() == unit)
}

#[cfg(target_os = "macos")]
pub(crate) fn validate_device(name: &str) -> crate::Result<()> {
    if valid_device(name) { Ok(()) } else {
        Err(crate::Error::msg("macOS TUN device must be a name such as utun1024"))
    }
}

/// Query the kernel rather than addresses: a newly created interface might not
/// yet have an IP address. A matching name alone is not proof of ownership.
#[cfg(target_os = "macos")]
pub(crate) fn interface_exists(name: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(name) else { return false };
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

#[cfg(test)]
mod tests {
    #[test]
    fn tun_network_changes_detect_dns_gateway_and_default_gateway() {
        let routes = "Internet:\nDestination Gateway Flags Netif\ndefault 192.0.2.1 UGScg en0\ndefault 192.0.2.2 UGScIg en5\n";
        let snapshot = |dns: &[&str], routes: &str| super::network_snapshot_from(
            dns.iter().map(|address| address.parse().unwrap()).collect(), routes,
        );
        let baseline = snapshot(&["1.1.1.1", "8.8.8.8"], routes).unwrap();
        // Resolver order and duplicate resolver entries do not change capture.
        assert_eq!(baseline, snapshot(&["8.8.8.8", "1.1.1.1", "1.1.1.1"], routes).unwrap());
        assert_ne!(baseline, snapshot(&["1.1.1.1"], routes).unwrap());
        assert_ne!(baseline, snapshot(&["1.1.1.1", "8.8.8.8"], &routes.replace("192.0.2.1", "192.0.2.3")).unwrap());
        assert!(snapshot(&["192.0.2.1"], routes).is_err());
        // A new gateway on any route can conflict with an unchanged resolver.
        let conflicting = format!("{routes}203.0.113/24 1.1.1.1 UGSc en0\n");
        assert!(snapshot(&["1.1.1.1", "8.8.8.8"], &conflicting).is_err());
        let ambiguous = format!("{routes}default 192.0.2.3 UGScg en0\n");
        assert!(snapshot(&["1.1.1.1"], &ambiguous).is_err());
    }
    use super::valid_device;

    #[test]
    fn dns_gateway_conflicts_are_detected_on_all_active_routes() {
        let routes = "Internet:\nDestination Gateway Flags Netif\ndefault 192.0.2.1 UGScg en0\ndefault 192.0.2.2 UGScIg en5\n203.0.113/24 192.0.2.3 UGSc en0\n192.0.2/24 link#1 UCS en0\n";
        for address in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
            assert!(super::dns_uses_gateway_in_routes(&[address.parse().unwrap()], routes).unwrap());
        }
        assert!(!super::dns_uses_gateway_in_routes(&["192.0.2.4".parse().unwrap()], routes).unwrap());
    }

    #[test]
    fn dns_gateway_verification_fails_closed_without_disclosing_addresses() {
        for routes in [
            "",
            "Destination Gateway Flags Netif\ndefault link#3 UGScg en0\n",
            "Destination Gateway Flags Netif\ndefault 192.0.2.1 UGScg en0\ndefault 192.0.2.2 UGScg en1\n",
            "Destination Gateway Flags Netif\ndefault 192.0.2.1 UGScIg en0\n",
        ] {
            let error = super::dns_uses_gateway_in_routes(&[], routes).unwrap_err().to_string();
            assert!(!error.contains("192.0.2"));
        }
    }

    #[test]
    fn selects_unscoped_default_and_rejects_tunnel_or_ambiguity() {
        let routes = "Internet:\nDestination Gateway Flags Netif\ndefault 192.0.2.1 UGScg en0\ndefault 192.0.2.2 UGScIg en5\n0/1 198.18.0.1 UGSc utun6\n";
        assert_eq!(super::parse_default_interface(routes).unwrap(), "en0");
        assert!(super::parse_default_interface("default 198.18.0.1 UGScg utun6\n").is_err());
        assert!(super::parse_default_interface("default 192.0.2.1 UGScg en0\ndefault 192.0.2.2 UGScg en1\n").is_err());
        assert!(super::parse_default_interface("default 192.0.2.1 UGScg en0;bad\n").is_err());
    }

    #[test]
    fn accepts_canonical_utun_names_only() {
        for name in ["utun0", "utun1", "utun1024", "utun32767"] {
            assert!(valid_device(name), "{name}");
        }
        for name in ["", "utun", "utun01", "utun-1", "utun+1", "utun1 ", "UTUN1", "en0", "utun32768", "utun1\0"] {
            assert!(!valid_device(name), "{name:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn finds_loopback_without_network_changes() {
        assert!(super::interface_exists("lo0"));
        assert!(!super::interface_exists("not-an-interface"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn transfers_one_descriptor_and_closes_it_on_exec() {
        use std::{io::{Read, Write}, os::{fd::{AsFd, AsRawFd}, unix::net::UnixStream}};
        let (tx, rx) = UnixStream::pair().unwrap();
        let (reader, mut writer) = UnixStream::pair().unwrap();
        super::send_descriptor(tx.as_fd(), reader.as_fd()).unwrap();
        let received = super::receive_descriptor_single_threaded(rx.as_fd()).unwrap();
        assert_ne!(unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
        let mut received = UnixStream::from(received);
        writer.write_all(b"handoff").unwrap();
        let mut data = [0u8; 7];
        received.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"handoff");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_plain_data_without_a_descriptor() {
        use std::{io::Write, os::{fd::AsFd, unix::net::UnixStream}};
        let (mut tx, rx) = UnixStream::pair().unwrap();
        tx.write_all(b"F").unwrap();
        assert_eq!(super::receive_descriptor_single_threaded(rx.as_fd()).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_multiple_descriptors_in_one_message() {
        use std::{mem, os::{fd::{AsFd, AsRawFd}, unix::net::UnixStream}};
        #[repr(C, align(16))]
        struct Control([u8; 128]);
        let (tx, rx) = UnixStream::pair().unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let mut control = Control([0; 128]);
        let mut byte = [b'F'];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE((2 * mem::size_of::<libc::c_int>()) as _) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((2 * mem::size_of::<libc::c_int>()) as _) as _;
            let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
            std::ptr::write_unaligned(data, a.as_raw_fd());
            std::ptr::write_unaligned(data.add(1), b.as_raw_fd());
            assert_eq!(libc::sendmsg(tx.as_raw_fd(), &msg, 0), 1);
        }
        assert_eq!(super::receive_descriptor_single_threaded(rx.as_fd()).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_a_non_utun_descriptor() {
        use std::os::{fd::AsFd, unix::net::UnixStream};
        let (socket, _) = UnixStream::pair().unwrap();
        assert!(super::descriptor_utun_name(socket.as_fd()).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn handoff_channel_must_be_a_connected_unix_stream() {
        use std::os::{fd::AsFd, unix::net::{UnixDatagram, UnixStream}};
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(super::validate_handoff_socket(a.as_fd()).is_ok());
        let (datagram, _peer) = UnixDatagram::pair().unwrap();
        assert!(super::validate_handoff_socket(datagram.as_fd()).is_err());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert!(super::validate_handoff_socket(tcp.as_fd()).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sender_waits_until_receiver_has_secured_the_descriptor() {
        use std::{os::{fd::AsFd, unix::net::UnixStream}, thread};
        let (tx, rx) = UnixStream::pair().unwrap();
        let (reader, _writer) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || super::send_descriptor_and_confirm(tx.as_fd(), reader.as_fd()));
        let received = super::receive_descriptor_single_threaded(rx.as_fd()).unwrap();
        super::confirm_descriptor_received(rx.as_fd()).unwrap();
        sender.join().unwrap().unwrap();
        drop(received);
    }
}
