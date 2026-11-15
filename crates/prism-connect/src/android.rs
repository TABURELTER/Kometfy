//! Android: the system's VPN service, as the host app offers it to the manager.
//!
//! Only an Android app component (a `VpnService`) can open a tunnel, and only after the user has
//! given the VPN permission. The host (the Tauri shell with its Kotlin plugin) implements this trait.
//! The manager asks it for the tunnel's file descriptor and starts the core with that descriptor.

use futures_util::future::BoxFuture;

use crate::error::Result;

/// What the host answers with: a future, as the answer comes from the Kotlin side.
pub type Fut<T> = BoxFuture<'static, Result<T>>;

/// What the tunnel looks like. The address and the DNS server sit in the /30 that the core derives
/// from its fake-IP range (198.18.0.1/16 by default): the service's side of the interface is .1.
#[derive(Debug, Clone)]
pub struct VpnParams {
    pub mtu: u32,
    pub address: String,
    pub prefix: u8,
    pub dns: String,
    /// Route only the core's fake-IP range (198.18.0.0/16) into the tunnel: the free mode,
    /// where the core does something only with the names it hands fake addresses to. The service still takes the
    /// whole traffic when the system resolves names past the tunnel (a strict Private DNS).
    pub split: bool,
}

pub trait AndroidVpn: Send + Sync {
    /// Ask for the permission if it is not given yet, open the tunnel and return its descriptor. The
    /// descriptor stays owned by the service: it is valid until `stop`, and the caller must not close it.
    fn establish(&self, params: VpnParams) -> Fut<i32>;
    /// Close the tunnel and take the notification down.
    fn stop(&self) -> Fut<()>;
    /// The link the device is on now (`wifi`, `cellular`, `ethernet`, `other`, "" unknown) and, on a mobile link,
    /// the SIM's operator name ("MTS RUS"); for the statistics and the remote tests the user agreed to.
    fn network(&self) -> Fut<(String, String)> {
        Box::pin(async { Ok((String::new(), String::new())) })
    }
}
