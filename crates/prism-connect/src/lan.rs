//! This PC's own addresses: where other devices find the proxy, and which connection sources are
//! the PC itself (so they are not mistaken for another device).

use std::net::{IpAddr, Ipv4Addr};

use if_addrs::get_if_addrs;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LanAddress {
    /// The adapter as Windows names it: "Wi-Fi", "Ethernet".
    pub name: String,
    pub ip: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Lan {
    /// Private IPv4 addresses of the working adapters: what a phone types as the proxy host.
    pub addresses: Vec<LanAddress>,
    /// Every address of this PC. A connection that comes from one of them is the PC's own traffic.
    pub local: Vec<String>,
}

/// 10/8, 172.16/12, 192.168/16, and 100.64/10 (carrier-grade NAT: Tailscale, some providers).
fn private_enough(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_private() || (a == 100 && (64..=127).contains(&b))
}

/// Look at the adapters now. `skip` is the app's own TUN adapter: nobody connects through that.
pub fn scan(skip: &str) -> Lan {
    let mut lan = Lan::default();
    let Ok(list) = get_if_addrs() else { return lan };
    for i in list {
        let ip = i.ip();
        let text = ip.to_string();
        if !lan.local.contains(&text) {
            lan.local.push(text);
        }
        let IpAddr::V4(v4) = ip else { continue };
        if i.is_oper_up() && !i.is_loopback() && !i.name.eq_ignore_ascii_case(skip) && private_enough(v4) {
            lan.addresses.push(LanAddress {
                name: i.name,
                ip: v4.to_string(),
            });
        }
    }
    lan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_ranges_count_as_a_home_network() {
        for ok in ["10.0.0.5", "172.16.3.4", "172.31.255.1", "192.168.1.20", "100.64.0.1", "100.127.9.9"] {
            assert!(private_enough(ok.parse().unwrap()), "{ok}");
        }
        for no in ["8.8.8.8", "172.32.0.1", "100.63.0.1", "100.128.0.1", "127.0.0.1", "169.254.1.1", "198.18.0.1"] {
            assert!(!private_enough(no.parse().unwrap()), "{no}");
        }
    }

    #[test]
    fn this_pc_knows_itself() {
        let lan = scan("PrismTun");
        assert!(lan.local.iter().any(|a| a == "127.0.0.1"), "loopback is missing: {:?}", lan.local);
        assert!(lan.addresses.iter().all(|a| a.ip.parse::<Ipv4Addr>().is_ok_and(private_enough)));
        // the app's own adapter is never offered
        assert!(lan.addresses.iter().all(|a| !a.name.eq_ignore_ascii_case("PrismTun")));
    }
}
