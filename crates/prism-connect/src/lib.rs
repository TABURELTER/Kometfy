//! Kometfy Connect: a mihomo-powered connection manager.
//!
//! Profiles (subscriptions, share links, WireGuard configs), chain proxies, TUN and system-proxy
//! capture, driven through the mihomo external controller.

#[cfg(target_os = "android")]
pub mod android;
pub mod builtin;
pub mod chain;
pub mod channel;
pub mod reset;
pub mod journal;
pub mod watchdog;
pub mod config;
pub mod controller;
pub mod coredl;
pub mod device;
pub mod diagnostics;
pub mod doh;
pub mod discover;
pub mod dpi;
pub mod elevate;
pub mod error;
pub mod happ;
pub mod instance;
pub mod lan;
#[cfg(windows)]
pub mod launch;
#[cfg(not(windows))]
#[path = "launch_other.rs"]
pub mod launch;
pub mod links;
pub mod logfile;
pub mod manager;
pub mod metrics;
pub mod mihomo;
pub mod opener;
pub mod paths;
pub mod probes;
pub mod profiles;
pub mod remote;
pub mod rules;
pub mod settings;
pub mod subscription;
pub mod tgbridge;
#[cfg(any(target_os = "macos", test))]
mod tun_macos;
#[cfg(any(target_os = "macos", test))]
mod tun_macos_interface;
#[cfg(all(feature = "macos-tun-lab", any(target_os = "macos", test)))]
mod tun_macos_lab;
#[cfg(any(test, all(target_os = "macos", feature = "macos-native-bridge")))]
mod tun_macos_handoff;
#[cfg(windows)]
pub mod sysproxy;
#[cfg(test)]
mod sysproxy_plan;
#[cfg(test)]
mod proxy_recovery_model;
#[cfg(target_os = "macos")]
mod sysproxy_macos_read;
#[cfg(target_os = "macos")]
mod sysproxy_macos_prefs;
// Property-list transformations are pure and can be exercised on any host.
#[cfg(any(test, target_os = "macos"))]
mod sysproxy_macos_transform;
#[cfg(target_os = "macos")]
mod sysproxy_macos;
pub mod macos_proxy_guard;
pub mod macos_proxy_client;
#[cfg(any(test, all(target_os = "macos", feature = "macos-native-bridge")))]
#[allow(dead_code)] // Installer integration is deliberately not enabled yet.
mod macos_helper_payload;
#[cfg(any(target_os = "macos", all(test, unix)))]
#[allow(dead_code)] // Internal installer primitive; no system installer uses it yet.
mod macos_installer_fs;
#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)] // Fake-runner tested on all hosts; real launchctl adapter used on macOS.
mod macos_installer_services;
#[cfg(any(target_os = "macos", all(test, unix)))]
#[allow(dead_code)] // Not connected to an installer.
mod macos_installer_runner;
#[cfg(all(target_os = "macos", feature = "macos-native-installer"))]
pub mod macos_installer;
#[cfg(all(target_os = "macos", feature = "macos-native-bridge"))]
pub(crate) mod macos_installer_client;
#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) mod macos_proxy_session;
#[cfg(not(windows))]
#[path = "sysproxy_other.rs"]
pub mod sysproxy;
mod util;
pub mod xray;
pub mod xray_conf;
pub mod zapret;
pub mod byedpi;

pub use error::{Error, Result};
pub use manager::{AppState, Emitter, Manager};
