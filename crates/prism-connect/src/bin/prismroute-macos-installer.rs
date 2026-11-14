#[cfg(all(target_os = "macos", feature = "macos-native-installer"))]
fn main() {
    match prism_connect::macos_installer::run_installer() {
        Ok(()) => println!("PRISM_INSTALL_OK"),
        Err(error) => { println!("PRISM_INSTALL_ERROR: {error}"); std::process::exit(1); }
    }
}

#[cfg(not(all(target_os = "macos", feature = "macos-native-installer")))]
fn main() { eprintln!("This installer must be built for macOS with an embedded helper payload."); std::process::exit(1); }
