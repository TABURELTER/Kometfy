//! Fake-only laboratory orchestration for the future guard integration.
//!
//! There is intentionally no implementation for the installed guard. Its
//! SystemConfiguration recovery may start threads before TUN is requested;
//! macOS has no atomic close-on-exec flag for the sockets used by utun setup.
//! Installing or registering this module in the application would therefore
//! introduce a fork/exec descriptor leak. In addition, routes, DNS and crash
//! recovery are not implemented. This feature must not enable capture.

use crate::tun_macos_interface::TunInterfacePlan;

/// A laboratory backend owns its interface until transfer is acknowledged.
/// In real integration, a transfer error may still mean the receiver got the
/// fd; its supervisor must then be stopped before considering cleanup done.
trait LabBackend {
    type Interface;
    fn create(&mut self) -> Result<Self::Interface, String>;
    fn configure(&mut self, interface: &mut Self::Interface, plan: TunInterfacePlan) -> Result<(), String>;
    fn transfer(&mut self, interface: &Self::Interface) -> Result<String, String>;
}

struct Prepared {
    yaml: String,
    device: String,
}

fn prepare(backend: &mut impl LabBackend, yaml: &str, fd: i32) -> Result<Prepared, String> {
    // The plan cannot be supplied by IPC or YAML. Validate the core config
    // before creating the interface, then configure it before transferring it.
    let plan = TunInterfacePlan::experimental_ipv4();
    let yaml = crate::config::configure_preopened_tun(yaml, fd, plan).map_err(|e| e.to_string())?;
    let mut interface = backend.create()?;
    backend.configure(&mut interface, plan)?;
    let device = backend.transfer(&interface)?;
    if !crate::macos_proxy_guard::valid_tun_name(&device) {
        return Err("invalid TUN device from laboratory backend".into());
    }
    Ok(Prepared { yaml, device })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_proxy_guard::{self, Backend};
    use std::io::Cursor;

    #[derive(Default)]
    struct Fake {
        events: Vec<&'static str>,
        fail: Option<&'static str>,
        yaml: Option<String>,
    }

    struct FakeInterface {
        configured: bool,
    }

    impl LabBackend for Fake {
        type Interface = FakeInterface;
        fn create(&mut self) -> Result<Self::Interface, String> {
            self.events.push("create");
            if self.fail == Some("create") { return Err("injected create failure".into()); }
            Ok(FakeInterface { configured: false })
        }
        fn configure(&mut self, interface: &mut Self::Interface, plan: TunInterfacePlan) -> Result<(), String> {
            self.events.push("configure");
            assert_eq!(plan, TunInterfacePlan::experimental_ipv4());
            if self.fail == Some("configure") { return Err("injected configure failure".into()); }
            interface.configured = true;
            Ok(())
        }
        fn transfer(&mut self, interface: &Self::Interface) -> Result<String, String> {
            self.events.push("transfer");
            assert!(interface.configured, "descriptor transferred before configuration");
            if self.fail == Some("transfer") { return Err("uncertain transfer".into()); }
            Ok("utun42".into())
        }
    }

    impl Backend for Fake {
        fn recover_previous(&mut self) -> Result<(), String> { self.events.push("recover"); Ok(()) }
        fn enable(&mut self, _: u16, _: &str) -> Result<(), String> { panic!("proxy must not be enabled") }
        fn restore(&mut self, _: u16) -> Result<(), String> { panic!("proxy must not be restored") }
        fn prepare_tun(&mut self) -> Result<String, String> {
            let result = prepare(self, "dns: {fake-ip-range: 198.18.0.1/16}\ntun: {enable: true, mtu: 9000}", 198)?;
            self.yaml = Some(result.yaml);
            Ok(result.device)
        }
    }

    #[test]
    fn guard_request_configures_before_transfer_and_uses_same_plan_for_yaml() {
        let mut fake = Fake::default();
        let mut output = Vec::new();
        macos_proxy_guard::serve(
            &mut Cursor::new(b"{\"command\":\"prepare_tun\"}\n{\"command\":\"shutdown\"}\n"),
            &mut output, &mut fake,
        ).unwrap();
        assert_eq!(fake.events, ["recover", "create", "configure", "transfer"]);
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("\"device\":\"utun42\""));
        let yaml: serde_yaml::Value = serde_yaml::from_str(fake.yaml.as_ref().unwrap()).unwrap();
        let plan = TunInterfacePlan::experimental_ipv4();
        assert_eq!(yaml["tun"]["mtu"].as_i64(), Some(i64::from(plan.mtu())));
        assert_eq!(yaml["tun"]["file-descriptor"].as_i64(), Some(198));
        assert_eq!(yaml["dns"]["fake-ip-range"].as_str(), Some("198.18.0.1/16"));
        assert_eq!(plan.ipv4().to_string(), "198.18.0.1");
        assert!(yaml["tun"]["inet6-address"].as_sequence().unwrap().is_empty());
    }

    #[test]
    fn invalid_yaml_or_setup_failure_never_transfers() {
        let mut invalid = Fake::default();
        assert!(prepare(&mut invalid, "dns: {fake-ip-range: 10.0.0.1/16}\ntun: {enable: true}", 198).is_err());
        assert!(invalid.events.is_empty());
        for (stage, expected) in [
            ("create", vec!["create"]),
            ("configure", vec!["create", "configure"]),
            ("transfer", vec!["create", "configure", "transfer"]),
        ] {
            let mut fake = Fake { fail: Some(stage), ..Fake::default() };
            assert!(prepare(&mut fake, "tun: {enable: true}", 198).is_err());
            assert_eq!(fake.events, expected);
        }
    }

    #[test]
    fn failed_handoff_is_one_shot_and_reported_as_uncertain() {
        let mut fake = Fake { fail: Some("transfer"), ..Fake::default() };
        let mut output = Vec::new();
        macos_proxy_guard::serve(
            &mut Cursor::new(b"{\"command\":\"prepare_tun\"}\n{\"command\":\"prepare_tun\"}\n"),
            &mut output, &mut fake,
        ).unwrap();
        assert_eq!(fake.events, ["recover", "create", "configure", "transfer"]);
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("tun_uncertain"));
        assert!(output.contains("busy"));
        assert!(fake.yaml.is_none());
    }
}
