//! Fixed launchd service lifecycle. This is not an installer and has no real
//! process runner. The caller must keep the guard lock and file transaction
//! alive until service verification or rollback finishes. Power loss, SIGKILL,
//! lingering runner children, and privileged administrators need separate recovery.
use crate::macos_installer_fs::GuardLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Service { Recovery, Bridge }
impl Service {
    fn label(self) -> &'static str {
        match self { Self::Recovery => "dev.prismroute.proxy-recovery", Self::Bridge => "dev.prismroute.proxy-bridge" }
    }
    fn plist(self) -> &'static str {
        match self { Self::Recovery => "/Library/LaunchDaemons/dev.prismroute.proxy-recovery.plist",
            Self::Bridge => "/Library/LaunchDaemons/dev.prismroute.proxy-bridge.plist" }
    }
    fn program(self) -> &'static str {
        match self { Self::Recovery => "/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard",
            Self::Bridge => "/Library/PrivilegedHelperTools/dev.prismroute.proxy-bridge" }
    }
}

/// The future runner must map these fixed variants to /bin/launchctl without a
/// shell, with a bounded output and deadline; it must not leave a child running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command { Domain, Disabled, Print(Service), Bootstrap(Service), Bootout(Service) }
impl Command {
    /// Exact argv for /bin/launchctl. No string in this table comes from a UI,
    /// file, or peer process. A real runner must avoid invoking a shell.
    pub(crate) fn args(self) -> &'static [&'static str] {
        match self {
            Self::Domain => &["print", "system"],
            Self::Disabled => &["print-disabled", "system"],
            Self::Print(Service::Recovery) => &["print", "system/dev.prismroute.proxy-recovery"],
            Self::Print(Service::Bridge) => &["print", "system/dev.prismroute.proxy-bridge"],
            Self::Bootstrap(Service::Recovery) => &["bootstrap", "system", "/Library/LaunchDaemons/dev.prismroute.proxy-recovery.plist"],
            Self::Bootstrap(Service::Bridge) => &["bootstrap", "system", "/Library/LaunchDaemons/dev.prismroute.proxy-bridge.plist"],
            Self::Bootout(Service::Recovery) => &["bootout", "system/dev.prismroute.proxy-recovery"],
            Self::Bootout(Service::Bridge) => &["bootout", "system/dev.prismroute.proxy-bridge"],
        }
    }
}
pub(crate) struct Output { pub(crate) success: bool, pub(crate) stdout: String }
pub(crate) trait Runner { fn run(&mut self, command: Command) -> Result<Output, &'static str>; }

fn output(runner: &mut impl Runner, command: Command) -> Result<Output, &'static str> {
    let result = runner.run(command)?;
    if result.stdout.len() > 4 * 1024 * 1024 { return Err("launchd output too large"); }
    Ok(result)
}
fn absent(runner: &mut impl Runner, service: Service) -> Result<bool, &'static str> {
    let response = output(runner, Command::Domain)?;
    if !response.success { return Err("cannot inspect system launchd domain"); }
    let lines: Vec<_> = response.stdout.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    if lines.first() != Some(&"system = {") || lines.last() != Some(&"}") {
        return Err("unrecognized system launchd domain");
    }
    // A conservative substring check may refuse a harmless similarly named
    // service; it must never infer absence from an ambiguous listing.
    Ok(!response.stdout.contains(service.label()))
}
fn enabled(runner: &mut impl Runner, service: Service) -> Result<bool, &'static str> {
    let response = output(runner, Command::Disabled)?;
    if !response.success { return Err("cannot inspect disabled launchd services"); }
    let lines: Vec<_> = response.stdout.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    if lines.first() != Some(&"disabled services = {") || lines.last() != Some(&"}") {
        return Err("unrecognized disabled services output");
    }
    let prefix = format!("\"{}\" => ", service.label());
    let values: Vec<_> = lines.iter().filter_map(|line| line.strip_prefix(&prefix)).collect();
    if values.len() > 1 { return Err("ambiguous disabled service override"); }
    if values.is_empty() && response.stdout.contains(service.label()) { return Err("unrecognized disabled service override"); }
    match values.first().copied() { None | Some("enabled") => Ok(true), Some("disabled") => Ok(false), _ => Err("unknown disabled service override") }
}
fn matches_service(service: Service, text: &str) -> bool {
    if text.len() > 1024 * 1024 { return false; }
    let lines: Vec<_> = text.lines().map(str::trim).collect();
    let unique = |expected: &str| lines.iter().filter(|line| **line == expected).count() == 1;
    if !unique(&format!("system/{} = {{", service.label())) || !unique(&format!("path = {}", service.plist()))
        || !unique("type = LaunchDaemon") || !unique(&format!("program = {}", service.program()))
        || !unique("arguments = {") { return false; }
    let Some(index) = lines.iter().position(|line| *line == "arguments = {") else { return false };
    match service {
        Service::Recovery => unique("run interval = 15 seconds")
            && lines.get(index + 1..index + 4) == Some(&[service.program(), "--recover-only", "}"][..]),
        Service::Bridge => {
            if lines.get(index + 1..index + 3) != Some(&[service.program(), "}"][..]) { return false; }
            if unique("mach services = {") {
                let Some(start) = lines.iter().position(|line| *line == "mach services = {") else { return false };
                let Some(relative_end) = lines[start + 1..].iter().position(|line| *line == "}") else { return false };
                let section = &lines[start + 1..start + 1 + relative_end];
                return section.iter().filter(|line| {
                    let line = line.trim_start_matches('"');
                    line.strip_prefix(service.label()).is_some_and(|rest| {
                        let rest = rest.trim_start_matches('"').trim_start();
                        rest.starts_with("=>") || rest.starts_with('=')
                    })
                }).count() == 1;
            }
            // macOS 27 calls this section "endpoints" and nests each Mach
            // service as a dictionary. Require the exact managed endpoint and
            // a structurally complete section, not merely a label substring.
            if !unique("endpoints = {") { return false; }
            let start = lines.iter().position(|line| *line == "endpoints = {").unwrap();
            let target = format!("\"{}\" = {{", service.label());
            let (mut depth, mut matches, mut managed, mut selected, mut closed) = (1usize, 0usize, false, false, false);
            for line in &lines[start + 1..] {
                if line.ends_with("= {") {
                    if depth == 1 { selected = *line == target; if selected { matches += 1; } }
                    depth += 1;
                } else if *line == "}" {
                    if depth == 0 { return false; }
                    depth -= 1;
                    if depth == 1 { selected = false; }
                    if depth == 0 { closed = true; break; }
                } else if depth == 2 && selected && *line == "managed = 1" { managed = true; }
            }
            closed && matches == 1 && managed
        }
    }
}
fn verify(runner: &mut impl Runner, service: Service) -> Result<(), &'static str> {
    let response = output(runner, Command::Print(service))?;
    if !response.success || !matches_service(service, &response.stdout) { return Err("loaded service does not match expected configuration"); }
    Ok(())
}
fn remove_if_owned(runner: &mut impl Runner, service: Service) -> Result<(), &'static str> {
    if absent(runner, service)? { return Ok(()); }
    // Never stop a same-label service with different paths or arguments.
    verify(runner, service)?;
    // Even a failed bootout can have removed the service; confirm its state.
    // A timeout or lost pipe may leave a descendant still changing launchd.
    // Never declare the files removable after such an uncertain command.
    output(runner, Command::Bootout(service))?;
    if !absent(runner, service)? { return Err("service removal could not be confirmed"); }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct RegisterError { pub(crate) reason: &'static str, pub(crate) safe_to_remove_files: bool }
#[derive(Debug, Default)]
pub(crate) struct Attempted { recovery: bool, bridge: bool }
impl Attempted {
    fn rollback(&self, runner: &mut impl Runner) -> Result<(), &'static str> {
        // Keep the recovery service if the bridge removal is uncertain.
        if self.bridge { remove_if_owned(runner, Service::Bridge)?; }
        if self.recovery { remove_if_owned(runner, Service::Recovery)?; }
        Ok(())
    }
}

fn register_inner(runner: &mut impl Runner) -> Result<Attempted, RegisterError> {
    let mut attempted = Attempted::default();
    let mut uncertain_command = false;
    let result = (|| {
        for service in [Service::Recovery, Service::Bridge] {
            if !absent(runner, service)? || !enabled(runner, service)? { return Err("service already exists or is disabled"); }
        }
        for service in [Service::Recovery, Service::Bridge] {
            // Mark before bootstrap: even an error or timeout may have changed launchd.
            match service { Service::Recovery => attempted.recovery = true, Service::Bridge => attempted.bridge = true }
            let response = match output(runner, Command::Bootstrap(service)) {
                Ok(value) => value,
                Err(error) => { uncertain_command = true; return Err(error); }
            };
            if !response.success { return Err("service bootstrap failed"); }
            verify(runner, service)?;
            if !enabled(runner, service)? { return Err("service became disabled"); }
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(attempted),
        Err(reason) => {
            // A pre-existing service might already reference the staged paths;
            // only an independently confirmed empty domain permits file cleanup.
            let safe_to_remove_files = !uncertain_command && attempted.rollback(runner).is_ok()
                && matches!(absent(runner, Service::Bridge), Ok(true))
                && matches!(absent(runner, Service::Recovery), Ok(true));
            Err(RegisterError { reason, safe_to_remove_files })
        }
    }
}

/// No concrete runner exists yet. Registration is available only while the
/// caller holds the same lock as the guard; files must remain present until
/// rollback returns success and all runner children have exited.
pub(crate) struct Controller<'a, R> { runner: R, _lock: &'a GuardLock }
impl<'a, R: Runner> Controller<'a, R> {
    pub(crate) fn new(runner: R, lock: &'a GuardLock) -> Self { Self { runner, _lock: lock } }
    pub(crate) fn preflight(&mut self) -> Result<(), &'static str> {
        for service in [Service::Recovery, Service::Bridge] {
            if !absent(&mut self.runner, service)? || !enabled(&mut self.runner, service)? {
                return Err("service already exists or is disabled");
            }
        }
        Ok(())
    }
    pub(crate) fn files_safe_to_remove(&mut self) -> bool {
        matches!(absent(&mut self.runner, Service::Bridge), Ok(true))
            && matches!(absent(&mut self.runner, Service::Recovery), Ok(true))
    }
    pub(crate) fn verify_existing(&mut self) -> Result<(), &'static str> {
        for service in [Service::Recovery, Service::Bridge] {
            if !enabled(&mut self.runner, service)? { return Err("installed service is disabled"); }
            verify(&mut self.runner, service)?;
        }
        Ok(())
    }
    /// Stop only the two verified services, in dependency order. An uncertain
    /// failure leaves the backup in place and must not lead to file replacement.
    pub(crate) fn stop_existing(&mut self) -> Result<(), &'static str> {
        self.verify_existing()?;
        remove_if_owned(&mut self.runner, Service::Bridge)?;
        remove_if_owned(&mut self.runner, Service::Recovery)?;
        if !self.files_safe_to_remove() { return Err("cannot confirm services stopped"); }
        Ok(())
    }
    /// Restore originally registered services after their files are restored.
    pub(crate) fn start_existing(&mut self) -> Result<(), &'static str> {
        for service in [Service::Recovery, Service::Bridge] {
            if !enabled(&mut self.runner, service)? { return Err("service is disabled"); }
            if absent(&mut self.runner, service)? {
                if !output(&mut self.runner, Command::Bootstrap(service))?.success { return Err("service restart failed"); }
            }
            verify(&mut self.runner, service)?;
        }
        Ok(())
    }
    pub(crate) fn register(&mut self) -> Result<Attempted, RegisterError> { register_inner(&mut self.runner) }
    pub(crate) fn rollback(&mut self, attempted: &Attempted) -> Result<(), &'static str> { attempted.rollback(&mut self.runner) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        recovery: bool,
        bridge: bool,
        disabled: bool,
        bootstrap_failure: Option<Service>,
        bootout_failure: Option<Service>,
        remove_on_failed_bootout: bool,
        bad_service: Option<Service>,
        bad_domain: bool,
        calls: Vec<Command>,
    }
    impl Fake {
        fn present(&self, service: Service) -> bool { match service { Service::Recovery => self.recovery, Service::Bridge => self.bridge } }
        fn set_present(&mut self, service: Service, value: bool) { match service { Service::Recovery => self.recovery = value, Service::Bridge => self.bridge = value } }
        fn status(service: Service) -> String {
            let extra = match service {
                Service::Recovery => " --recover-only\n }\n run interval = 15 seconds\n".to_owned(),
                Service::Bridge => format!(" }}\n mach services = {{\n \"{}\" => active\n }}\n", service.label()),
            };
            format!("system/{} = {{\n path = {}\n type = LaunchDaemon\n program = {}\n arguments = {{\n {}\n{} }}\n", service.label(), service.plist(), service.program(), service.program(), extra)
        }
    }
    impl Runner for Fake {
        fn run(&mut self, command: Command) -> Result<Output, &'static str> {
            self.calls.push(command);
            let mut result = Output { success: true, stdout: String::new() };
            match command {
                Command::Domain => {
                    result.stdout = if self.bad_domain { "unknown domain".into() } else { format!("system = {{\n{}{}\n}}\n", if self.recovery { Service::Recovery.label() } else { "" }, if self.bridge { Service::Bridge.label() } else { "" }) };
                }
                Command::Disabled => result.stdout = if self.disabled { format!("disabled services = {{\n\"{}\" => disabled\n}}", Service::Bridge.label()) } else { "disabled services = {\n}".into() },
                Command::Print(service) => {
                    result.success = self.present(service);
                    result.stdout = if self.bad_service == Some(service) { Self::status(service).replace(service.program(), "/tmp/foreign") } else { Self::status(service) };
                }
                Command::Bootstrap(service) => {
                    self.set_present(service, true);
                    result.success = self.bootstrap_failure != Some(service);
                }
                Command::Bootout(service) => {
                    result.success = self.bootout_failure != Some(service);
                    if result.success || self.remove_on_failed_bootout { self.set_present(service, false); }
                }
            }
            Ok(result)
        }
    }

    #[test]
    fn registers_and_rolls_back_in_reverse_order() {
        let mut fake = Fake::default();
        let started = register_inner(&mut fake).unwrap();
        assert!(fake.recovery && fake.bridge);
        started.rollback(&mut fake).unwrap();
        assert!(!fake.recovery && !fake.bridge);
        let removals: Vec<_> = fake.calls.iter().filter(|c| matches!(c, Command::Bootout(_))).copied().collect();
        assert_eq!(removals, [Command::Bootout(Service::Bridge), Command::Bootout(Service::Recovery)]);
    }
    #[test]
    fn bootstrap_error_after_registration_still_reverses_both() {
        let mut fake = Fake { bootstrap_failure: Some(Service::Bridge), ..Fake::default() };
        let error = register_inner(&mut fake).unwrap_err();
        assert_eq!(error.reason, "service bootstrap failed");
        assert!(error.safe_to_remove_files);
        assert!(!fake.recovery && !fake.bridge);
    }
    #[test]
    fn uncertain_bridge_keeps_recovery_and_installed_files() {
        let mut fake = Fake { bootstrap_failure: Some(Service::Bridge), bad_service: Some(Service::Bridge), ..Fake::default() };
        let error = register_inner(&mut fake).unwrap_err();
        assert!(!error.safe_to_remove_files);
        assert!(fake.recovery && fake.bridge);
        assert!(!fake.calls.contains(&Command::Bootout(Service::Bridge)));
        assert!(!fake.calls.contains(&Command::Bootout(Service::Recovery)));
    }
    #[test]
    fn bootout_failure_is_only_safe_when_absence_is_confirmed() {
        for (removed, expected) in [(true, true), (false, false)] {
            let mut fake = Fake { bootstrap_failure: Some(Service::Bridge), bootout_failure: Some(Service::Bridge), remove_on_failed_bootout: removed, ..Fake::default() };
            let error = register_inner(&mut fake).unwrap_err();
            assert_eq!(error.safe_to_remove_files, expected);
            assert_eq!(fake.recovery, !expected);
        }
    }
    #[test]
    fn preexisting_disabled_and_unrecognizable_services_fail_closed() {
        let mut existing = Fake { recovery: true, ..Fake::default() };
        let error = register_inner(&mut existing).unwrap_err();
        assert!(!error.safe_to_remove_files);
        assert!(!existing.calls.iter().any(|c| matches!(c, Command::Bootstrap(_) | Command::Bootout(_))));
        let mut disabled = Fake { disabled: true, ..Fake::default() };
        assert!(register_inner(&mut disabled).is_err());
        assert!(!disabled.calls.iter().any(|c| matches!(c, Command::Bootstrap(_))));
        let mut unknown = Fake { bad_domain: true, ..Fake::default() };
        assert!(!register_inner(&mut unknown).unwrap_err().safe_to_remove_files);
    }
    #[test]
    fn service_identity_is_checked_for_fixed_paths_arguments_and_schedule() {
        for service in [Service::Bridge, Service::Recovery] {
            let text = Fake::status(service);
            assert!(matches_service(service, &text));
            assert!(!matches_service(service, &text.replace(service.plist(), "/tmp/other.plist")));
            assert!(!matches_service(service, &text.replace(service.program(), "/tmp/other")));
        }
        assert!(!matches_service(Service::Recovery, &Fake::status(Service::Recovery).replace("15 seconds", "30 seconds")));
        assert!(!matches_service(Service::Bridge, &Fake::status(Service::Bridge).replace("mach services = {", "other = {")));
    }
    #[test]
    fn recognizes_macos_27_managed_endpoint_without_trusting_other_labels() {
        let original = Fake::status(Service::Bridge);
        let old = format!(" mach services = {{\n \"{}\" => active\n }}", Service::Bridge.label());
        let new = format!(" endpoints = {{\n \"{}\" = {{\n port = 0x123\n active = 1\n managed = 1\n }}\n }}", Service::Bridge.label());
        let status = original.replace(&old, &new);
        assert!(matches_service(Service::Bridge, &status));
        assert!(!matches_service(Service::Bridge, &status.replace("managed = 1", "managed = 0")));
        assert!(!matches_service(Service::Bridge, &status.replace(Service::Bridge.label(), "dev.example.other")));
        assert!(!matches_service(Service::Bridge, &status.replace("active = 1\n managed = 1\n }\n }", "active = 1\n managed = 1")));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn installed_service_format_when_explicitly_requested() {
        if std::env::var_os("PRISM_VERIFY_INSTALLED_SERVICE").is_none() { return; }
        for service in [Service::Recovery, Service::Bridge] {
            let output = std::process::Command::new("/bin/launchctl").args(["print", &format!("system/{}", service.label())]).output().unwrap();
            assert!(output.status.success());
            assert!(matches_service(service, std::str::from_utf8(&output.stdout).unwrap()), "unexpected launchd format for {:?}", service);
        }
    }
}
