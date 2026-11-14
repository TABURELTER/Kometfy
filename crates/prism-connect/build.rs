use std::{env, path::PathBuf, process::Command};

fn output(program: &str, args: &[&str]) -> String {
    let result = Command::new(program).args(args).output().expect("cannot run macOS toolchain");
    assert!(result.status.success(), "macOS toolchain command failed: {}", String::from_utf8_lossy(&result.stderr));
    String::from_utf8(result.stdout).expect("invalid toolchain output").trim().to_owned()
}

fn main() {
    for (key, name) in [("PRISM_INSTALLER_GUARD", "installer_guard"), ("PRISM_INSTALLER_BRIDGE", "installer_bridge")] {
        println!("cargo:rerun-if-env-changed={key}");
        let target = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join(name);
        if let Some(source) = env::var_os(key) {
            println!("cargo:rerun-if-changed={}", PathBuf::from(&source).display());
            std::fs::copy(source, target).expect("cannot embed installer payload");
        } else {
            std::fs::write(target, []).expect("cannot create empty installer payload");
        }
    }
    println!("cargo:rerun-if-changed=../../app/src-tauri/macos/proxy-bridge/InstallerIdentity.c");
    if env::var_os("CARGO_FEATURE_MACOS_NATIVE_INSTALLER").is_some() && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() { Ok("aarch64") => "arm64", Ok("x86_64") => "x86_64", _ => panic!("unsupported macOS architecture") };
        let target = format!("{arch}-apple-macos13.0");
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
        let source = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../../app/src-tauri/macos/proxy-bridge/InstallerIdentity.c");
        let obj = out.join("installer_identity.o");
        let result = Command::new("xcrun").arg("clang").args(["-target", &target, "-c"]).arg(source).arg("-o").arg(&obj).output().expect("cannot compile installer identity");
        assert!(result.status.success(), "installer identity build failed: {}", String::from_utf8_lossy(&result.stderr));
        let archive = out.join("libprism_installer_identity.a");
        let result = Command::new("xcrun").arg("ar").args(["-rcs"]).arg(&archive).arg(&obj).output().expect("cannot archive installer identity");
        assert!(result.status.success(), "installer identity archive failed: {}", String::from_utf8_lossy(&result.stderr));
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static=prism_installer_identity");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
    println!("cargo:rerun-if-env-changed=PRISM_BRIDGE_CDHASH");
    println!("cargo:rerun-if-env-changed=PRISM_CLIENT_CERT_SHA1");
    println!("cargo:rerun-if-env-changed=PRISM_BRIDGE_SHA256");
    println!("cargo:rerun-if-env-changed=PRISM_GUARD_SHA256");
    println!("cargo:rerun-if-env-changed=PRISM_INSTALLER_SHA256");
    for path in ["Protocol.swift", "BridgeClient.swift", "BridgeTransport.swift", "InstallerAuthorization.c"] {
        println!("cargo:rerun-if-changed=../../app/src-tauri/macos/proxy-bridge/{path}");
    }
    if env::var_os("CARGO_FEATURE_MACOS_NATIVE_BRIDGE").is_none() { return; }
    // The feature may be selected by workspace-wide checks on Windows; the
    // native bridge itself is compiled and referenced only on macOS.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") { return; }
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64", Ok("x86_64") => "x86_64", _ => panic!("unsupported macOS architecture"),
    };
    let target = format!("{arch}-apple-macos13.0");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let archive = out.join("libprism_proxy_bridge.a");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../../app/src-tauri/macos/proxy-bridge");
    let result = Command::new("xcrun").arg("swiftc").args(["-swift-version", "5", "-parse-as-library", "-emit-library", "-static", "-module-name", "PrismProxyBridge", "-target", &target])
        .arg(root.join("Protocol.swift")).arg(root.join("BridgeClient.swift")).arg(root.join("BridgeTransport.swift"))
        .arg("-o").arg(&archive).output().expect("cannot compile Swift bridge");
    assert!(result.status.success(), "Swift bridge build failed: {}", String::from_utf8_lossy(&result.stderr));
    let installer_obj = out.join("installer_authorization.o");
    let result = Command::new("xcrun").arg("clang").args(["-target", &target, "-c"]).arg(root.join("InstallerAuthorization.c"))
        .arg("-o").arg(&installer_obj).output().expect("cannot compile installer authorization");
    assert!(result.status.success(), "installer authorization build failed: {}", String::from_utf8_lossy(&result.stderr));
    let result = Command::new("xcrun").arg("ar").arg("-r").arg(&archive).arg(&installer_obj)
        .output().expect("cannot link installer authorization");
    assert!(result.status.success(), "installer authorization archive failed: {}", String::from_utf8_lossy(&result.stderr));
    let swiftc = PathBuf::from(output("xcrun", &["--find", "swiftc"]));
    let swiftlib = swiftc.parent().and_then(|p| p.parent()).expect("Swift toolchain path").join("lib/swift/macosx");
    let sdk = PathBuf::from(output("xcrun", &["--show-sdk-path"]));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", swiftlib.display());
    println!("cargo:rustc-link-search=native={}", sdk.join("usr/lib/swift").display());
    println!("cargo:rustc-link-lib=static=prism_proxy_bridge");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
