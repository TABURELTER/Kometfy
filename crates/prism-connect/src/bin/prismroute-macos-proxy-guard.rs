//! Standalone privileged guard; not installed or launched by the app yet.
#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = prism_connect::macos_proxy_guard::run_installed() {
        eprintln!("proxy guard: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS only");
    std::process::exit(1);
}
