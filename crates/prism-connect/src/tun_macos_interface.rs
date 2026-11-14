//! Experimental configuration for a freshly created utun. This is not wired
//! to the helper or the application: route/DNS ownership and recovery remain
//! unresolved. The interface is kept alive by the owned kernel descriptor.
//!
//! Adding an address can cause the kernel to create connected/local routes;
//! this module makes no explicit route or DNS requests. Do not call it on a
//! user's network until those effects and their cleanup have been verified.

use std::io;

/// A deliberately restricted experiment. Both the utun setup and mihomo YAML
/// must receive this same validated value; it is never parsed from the UI or
/// privileged IPC. IPv6 is excluded until mihomo's host-dependent IPv6 check,
/// routing and recovery can be verified together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TunInterfacePlan {
    mtu: i32,
    ipv4: [u8; 4],
}

impl TunInterfacePlan {
    pub(crate) fn experimental_ipv4() -> Self {
        Self { mtu: 1500, ipv4: [198, 18, 0, 1] }
    }
    pub(crate) fn mtu(self) -> i32 { self.mtu }
    pub(crate) fn ipv4(self) -> std::net::Ipv4Addr { self.ipv4.into() }
}

const IPV4_MASK: [u8; 4] = [255, 255, 255, 252];

#[derive(Debug, PartialEq, Eq)]
enum Operation {
    Mtu(i32),
    Address4 { address: [u8; 4], mask: [u8; 4] },
}

fn plan(spec: TunInterfacePlan) -> Vec<Operation> {
    vec![
        Operation::Mtu(spec.mtu),
        Operation::Address4 { address: spec.ipv4, mask: IPV4_MASK },
    ]
}

fn apply_plan(spec: TunInterfacePlan, mut apply: impl FnMut(&Operation) -> io::Result<()>) -> io::Result<()> {
    for operation in plan(spec) {
        apply(&operation)?;
    }
    Ok(())
}

/// Consume the freshly created utun, configure it while its FD is owned, and
/// return ownership only if every operation succeeds. On error the FD is closed
/// when dropped; callers must never duplicate or hand it off beforehand.
/// Call only before any other thread can fork or spawn a process: Darwin does
/// not atomically set close-on-exec on the short-lived ioctl sockets below.
/// The caller must use the same plan to prepare the mihomo configuration.
///
/// Merely matching a name is insufficient. The name is read from the kernel
/// through the still-open descriptor and compared to the creation result.
#[cfg(target_os = "macos")]
pub(crate) fn configure_created_utun(tun: crate::tun_macos::Utun, spec: TunInterfacePlan) -> io::Result<crate::tun_macos::Utun> {
    use std::os::fd::AsFd;
    let name = crate::tun_macos::descriptor_utun_name(tun.descriptor.as_fd())?;
    if name != tun.name || !crate::tun_macos::interface_exists(&name) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "utun identity changed"));
    }
    apply_plan(spec, |operation| darwin::apply(&name, operation))?;
    Ok(tun)
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;
    use std::{mem, os::fd::{AsRawFd, FromRawFd, OwnedFd}};

    // Darwin's ifaliasreq layout. The kernel validates the ioctl length.
    #[repr(C)]
    struct Alias4 {
        name: [libc::c_char; libc::IFNAMSIZ],
        address: libc::sockaddr_in,
        destination: libc::sockaddr_in,
        mask: libc::sockaddr_in,
    }
    fn copy_name(name: &str, target: &mut [libc::c_char; libc::IFNAMSIZ]) -> io::Result<()> {
        if name.len() >= target.len() || !name.starts_with("utun")
            || !name[4..].bytes().all(|b| b.is_ascii_digit()) || name.len() == 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid utun name"));
        }
        for (dst, byte) in target.iter_mut().zip(name.bytes()) { *dst = byte as libc::c_char; }
        Ok(())
    }

    fn socket(domain: libc::c_int) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn addr4(address: [u8; 4]) -> libc::sockaddr_in {
        let mut result: libc::sockaddr_in = unsafe { mem::zeroed() };
        result.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
        result.sin_family = libc::AF_INET as _;
        result.sin_addr.s_addr = u32::from_ne_bytes(address);
        result
    }
    pub(super) fn apply(name: &str, operation: &Operation) -> io::Result<()> {
        match operation {
            Operation::Mtu(mtu) => {
                let fd = socket(libc::AF_INET)?;
                let mut request: libc::ifreq = unsafe { mem::zeroed() };
                copy_name(name, &mut request.ifr_name)?;
                request.ifr_ifru.ifru_mtu = *mtu;
                if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFMTU, &mut request) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Operation::Address4 { address, mask } => {
                let fd = socket(libc::AF_INET)?;
                let mut request: Alias4 = unsafe { mem::zeroed() };
                copy_name(name, &mut request.name)?;
                request.address = addr4(*address);
                request.destination = addr4(*address); // Darwin point-to-point utun
                request.mask = addr4(*mask);
                if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCAIFADDR, &mut request) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn darwin_ioctl_layouts_and_names() {
            assert_eq!(mem::size_of::<Alias4>(), 64);
            let mut target = [0; libc::IFNAMSIZ];
            assert!(copy_name("utun42", &mut target).is_ok());
            assert!(copy_name("en0", &mut target).is_err());
            assert!(copy_name("utun42;rm", &mut target).is_err());
            let ip = TunInterfacePlan::experimental_ipv4().ipv4().octets();
            assert_eq!(addr4(ip).sin_addr.s_addr.to_ne_bytes(), ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_is_fixed_and_ipv4_only() {
        assert_eq!(plan(TunInterfacePlan::experimental_ipv4()), vec![Operation::Mtu(1500), Operation::Address4 {
            address: [198, 18, 0, 1], mask: [255, 255, 255, 252]
        }]);
    }
    #[test]
    fn stops_at_first_failed_operation() {
        let mut calls = 0;
        let result = apply_plan(TunInterfacePlan::experimental_ipv4(), |_| {
            calls += 1;
            if calls == 2 { Err(io::Error::other("injected failure")) } else { Ok(()) }
        });
        assert!(result.is_err());
        assert_eq!(calls, 2);
    }
}
