//! Client for the narrow proxy guard channel. Obtaining an authenticated,
//! privileged channel is separate and is not implemented by the preview.
use std::io::{BufRead, Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Idle, Active(u16), TunPrepared, TunActive, Uncertain, Stopped }

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Response { status: String, #[serde(default)] device: Option<String> }

pub struct Client<R, W> { input: R, output: W, state: State, healthy: bool, tun_attempted: bool }

impl<R: BufRead, W: Write> Client<R, W> {
    pub fn new(input: R, output: W) -> Self { Self { input, output, state: State::Idle, healthy: true, tun_attempted: false } }
    pub fn state(&self) -> State { self.state }

    fn exchange(&mut self, command: serde_json::Value) -> Result<Response, String> {
        if !self.healthy { return Err("guard channel is no longer synchronized".into()); }
        let result = (|| {
            serde_json::to_writer(&mut self.output, &command).map_err(|e| e.to_string())?;
            self.output.write_all(b"\n").and_then(|_| self.output.flush()).map_err(|e| e.to_string())?;
            let mut line = Vec::new();
            let len = (&mut self.input).take(4097).read_until(b'\n', &mut line).map_err(|e| e.to_string())?;
            if len == 0 || len > 4096 || !line.ends_with(b"\n") { return Err("invalid guard response framing".into()); }
            let response: Response = serde_json::from_slice(&line).map_err(|_| "invalid guard response".to_string())?;
            if !matches!(response.status.as_str(), "idle" | "active" | "restored" | "stopped" | "recovery_required" | "enable_failed" | "invalid_request" | "busy" | "tun_ready" | "tun_uncertain" | "tun_active" | "tun_ipv6_unsupported" | "tun_dns_unsupported" | "tun_dns_gateway" | "tun_route_failed") {
                return Err("unknown guard response".into());
            }
            if response.status == "tun_ready" {
                if !response.device.as_deref().is_some_and(crate::macos_proxy_guard::valid_tun_name) { return Err("invalid TUN device".into()); }
            } else if response.device.is_some() { return Err("unexpected TUN device".into()); }
            Ok(response)
        })();
        if result.is_err() { self.healthy = false; }
        result
    }

    pub fn enable(&mut self, port: u16, bypass: &str) -> Result<(), String> {
        if self.state != State::Idle || port == 0 || !crate::macos_proxy_guard::validate_bypass(bypass) {
            return Err("proxy guard is not ready or bypass list is invalid".into());
        }
        // A broken channel can occur after the guard has already changed the
        // system; never treat a missing acknowledgement as a clean failure.
        self.state = State::Uncertain;
        match self.exchange(serde_json::json!({"command":"enable", "port":port, "bypass":bypass}))?.status.as_str() {
            "active" => { self.state = State::Active(port); Ok(()) }
            "enable_failed" => { self.state = State::Idle; Err("proxy activation failed and was restored".into()) }
            "recovery_required" => Err("proxy activation needs recovery".into()),
            _ => { self.healthy = false; Err("unexpected guard response; channel is no longer synchronized".into()) }
        }
    }

    /// Start the supervisor concurrently: the guard waits for its descriptor
    /// acknowledgement before replying. A failed handoff must stop that
    /// supervisor and close this one-shot session before retrying.
    pub fn prepare_tun(&mut self) -> Result<String, String> {
        if self.state != State::Idle || self.tun_attempted { return Err("TUN handoff is not ready".into()); }
        self.tun_attempted = true;
        self.state = State::Uncertain;
        let response = self.exchange(serde_json::json!({"command":"prepare_tun"}))?;
        match response.status.as_str() {
            "tun_ready" => { self.state = State::TunPrepared; Ok(response.device.unwrap()) }
            "tun_uncertain" => Err("TUN handoff needs cleanup".into()),
            _ => { self.healthy = false; Err("unexpected guard response; channel is no longer synchronized".into()) }
        }
    }

    /// A failure may mean some routes were added. Always stop the TUN core
    /// before closing this session when activation returns an error.
    pub fn activate_tun(&mut self) -> Result<(), String> {
        if self.state != State::TunPrepared { return Err("TUN interface is not ready".into()); }
        self.state = State::Uncertain;
        match self.exchange(serde_json::json!({"command":"activate_tun"}))?.status.as_str() {
            "tun_active" => { self.state = State::TunActive; Ok(()) }
            "tun_ipv6_unsupported" => Err("IPv6 is active; IPv4-only TUN cannot be enabled safely".into()),
            "tun_dns_unsupported" => Err("System DNS includes an unsupported or unavailable resolver".into()),
            "tun_dns_gateway" => Err("System DNS is also a network gateway; TUN cannot safely capture it on macOS yet".into()),
            "tun_route_failed" => Err("Could not add TUN routes; another VPN or route may be active".into()),
            _ => { self.healthy = false; Err("unexpected TUN response; channel is no longer synchronized".into()) }
        }
    }

    pub fn check_tun_session(&mut self) -> Result<(), String> {
        if self.state != State::TunActive { return Err("TUN session is not active".into()); }
        match self.exchange(serde_json::json!({"command":"status"})) {
            Ok(response) if response.status == "idle" => Ok(()),
            _ => { self.state = State::Uncertain; Err("TUN helper connection was lost".into()) }
        }
    }

    pub fn restore(&mut self) -> Result<(), String> {
        if self.state == State::Stopped { return Err("proxy guard is stopped".into()); }
        if self.tun_attempted { return Err("stop the TUN supervisor and close its session first".into()); }
        self.state = State::Uncertain;
        match self.exchange(serde_json::json!({"command":"restore"}))?.status.as_str() {
            "restored" | "idle" => { self.state = State::Idle; Ok(()) }
            "recovery_required" => Err("proxy recovery remains unresolved".into()),
            _ => { self.healthy = false; Err("unexpected guard response; channel is no longer synchronized".into()) }
        }
    }

    pub fn shutdown(&mut self) -> Result<(), String> {
        if self.state == State::Stopped { return Ok(()); }
        self.state = State::Uncertain;
        match self.exchange(serde_json::json!({"command":"shutdown"}))?.status.as_str() {
            "stopped" => { self.state = State::Stopped; Ok(()) }
            "recovery_required" => Err("proxy guard did not shut down safely".into()),
            _ => { self.healthy = false; Err("unexpected guard response; channel is no longer synchronized".into()) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reports_dns_gateway_conflict_as_a_specific_error() {
        let input = Cursor::new(b"{\"status\":\"tun_ready\",\"device\":\"utun42\"}\n{\"status\":\"tun_dns_gateway\"}\n".to_vec());
        let mut client = Client::new(input, Vec::new());
        client.prepare_tun().unwrap();
        let error = client.activate_tun().unwrap_err();
        assert!(error.contains("network gateway"));
    }

    #[test]
    fn activation_and_shutdown_follow_confirmed_guard_responses() {
        let input = Cursor::new(b"{\"status\":\"active\"}\n{\"status\":\"stopped\"}\n".to_vec());
        let mut client = Client::new(input, Vec::new());
        client.enable(7890, "localhost;<local>").unwrap();
        assert_eq!(client.state(), State::Active(7890));
        client.shutdown().unwrap();
        assert_eq!(client.state(), State::Stopped);
        let requests = String::from_utf8(client.output).unwrap();
        assert_eq!(requests, "{\"bypass\":\"localhost;<local>\",\"command\":\"enable\",\"port\":7890}\n{\"command\":\"shutdown\"}\n");
    }

    #[test]
    fn lost_acknowledgement_never_claims_the_proxy_is_restored() {
        let mut client = Client::new(Cursor::new(Vec::<u8>::new()), Vec::new());
        assert!(client.enable(7890, "").is_err());
        assert_eq!(client.state(), State::Uncertain);
        assert!(client.enable(7891, "").is_err());
        let before = client.output.len();
        assert!(client.restore().is_err());
        assert_eq!(client.output.len(), before, "a broken channel must not be reused");
    }

    #[test]
    fn recovery_failure_is_retryable_but_not_reported_as_success() {
        let input = Cursor::new(b"{\"status\":\"active\"}\n{\"status\":\"recovery_required\"}\n{\"status\":\"restored\"}\n".to_vec());
        let mut client = Client::new(input, Vec::new());
        client.enable(7890, "").unwrap();
        assert!(client.restore().is_err());
        assert_eq!(client.state(), State::Uncertain);
        client.restore().unwrap();
        assert_eq!(client.state(), State::Idle);
    }

    #[test]
    fn rejects_invalid_or_oversized_responses() {
        for data in ["{\"status\":\"active\",\"other\":true}\n".to_string(), format!("{}\n", "x".repeat(4097))] {
            let mut client = Client::new(Cursor::new(data), Vec::new());
            assert!(client.enable(7890, "").is_err());
            assert_eq!(client.state(), State::Uncertain);
        }
    }

    #[test]
    fn tun_handoff_requires_valid_device_and_is_one_shot() {
        let input = Cursor::new(b"{\"status\":\"tun_ready\",\"device\":\"utun42\"}\n{\"status\":\"stopped\"}\n".to_vec());
        let mut client = Client::new(input, Vec::new());
        assert_eq!(client.prepare_tun().unwrap(), "utun42");
        assert_eq!(client.state(), State::TunPrepared);
        assert!(client.prepare_tun().is_err());
        assert!(client.enable(7890, "").is_err());
        assert!(client.restore().is_err());
        client.shutdown().unwrap();
        assert_eq!(client.state(), State::Stopped);
        for response in ["{\"status\":\"tun_ready\",\"device\":\"en0\"}\n", "{\"status\":\"tun_ready\"}\n", "{\"status\":\"tun_uncertain\"}\n"] {
            let mut client = Client::new(Cursor::new(response), Vec::new());
            assert!(client.prepare_tun().is_err());
            assert_eq!(client.state(), State::Uncertain);
            assert!(client.restore().is_err());
            assert!(client.prepare_tun().is_err());
        }
    }

    #[test]
    fn valid_but_unexpected_status_must_not_be_reused_as_a_recovery_channel() {
        let input = Cursor::new(b"{\"status\":\"idle\"}\n{\"status\":\"idle\"}\n".to_vec());
        let mut client = Client::new(input, Vec::new());
        assert!(client.enable(7890, "").is_err());
        assert_eq!(client.state(), State::Uncertain);
        let before = client.output.len();
        assert!(client.restore().is_err());
        assert_eq!(client.output.len(), before);
    }

    #[cfg(unix)]
    #[test]
    fn talks_to_guard_over_a_real_bidirectional_channel() {
        use std::{io::BufReader, os::unix::net::UnixStream, thread};
        struct Fake(Vec<String>);
        impl crate::macos_proxy_guard::Backend for Fake {
            fn recover_previous(&mut self) -> Result<(), String> { self.0.push("startup".into()); Ok(()) }
            fn enable(&mut self, port: u16, bypass: &str) -> Result<(), String> { self.0.push(format!("enable:{port}:{bypass}")); Ok(()) }
            fn restore(&mut self, port: u16) -> Result<(), String> { self.0.push(format!("restore:{port}")); Ok(()) }
        }
        let (user, guard) = UnixStream::pair().unwrap();
        let task = thread::spawn(move || {
            let mut backend = Fake(Vec::new());
            let mut input = BufReader::new(guard.try_clone().unwrap());
            let mut output = guard;
            crate::macos_proxy_guard::serve(&mut input, &mut output, &mut backend).unwrap();
            backend.0
        });
        let mut client = Client::new(BufReader::new(user.try_clone().unwrap()), user);
        client.enable(7890, "localhost;10.0.0.0/8;<local>").unwrap();
        client.shutdown().unwrap();
        assert_eq!(task.join().unwrap(), ["startup", "enable:7890:localhost;10.0.0.0/8;<local>", "restore:7890"]);
    }
}
