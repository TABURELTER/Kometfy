//! Addresses an app build hands to the core at start: Kometfy's backend, the project's own Cloudflare domains for
//! the Telegram bridge, the free AI proxy and the gaming DNS. The open core has none built in: a build that sets
//! nothing talks to no backend at all (no remote settings, statistics, ads or tests), the bridge uses only the domains
//! the user entered, and "Access to AI" does nothing ("Games" only fixes Roblox's pictures).

use std::sync::OnceLock;

#[derive(Debug, Clone, Default)]
pub struct Builtin {
    /// `https://…` without a trailing slash.
    pub backend: String,
    /// Cloudflare base domains for the Telegram bridge (kwsN records, docs/TELEGRAM_CF.md).
    pub tg_domains: Vec<String>,
    /// HTTP proxies for AI services in the free mode, `host:port`, tried in order.
    pub ai_proxies: Vec<String>,
    /// DNS servers that answer the games' names with their relays, as mihomo takes them (`https://…`, `tls://…`).
    pub games_dns: Vec<String>,
}

static BUILTIN: OnceLock<Builtin> = OnceLock::new();

/// Called once, before the manager starts; later calls change nothing.
pub fn set(b: Builtin) {
    let _ = BUILTIN.set(b);
}

/// What the app build supplied, or nothing.
pub fn get() -> Builtin {
    BUILTIN.get().cloned().unwrap_or_default()
}

pub fn backend() -> String {
    get().backend
}

pub fn tg_domains() -> Vec<String> {
    get().tg_domains
}
