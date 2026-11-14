import Foundation
import Security

/// Registered by the installer with the system rule `is-admin` (see macos_installer.rs).
private let sessionRight = "dev.prismroute.proxy-bridge.session"

/// Does the handle hold `name`, or can it get it? Without `interactive` no dialog is shown.
private func obtain(_ authorization: AuthorizationRef, _ name: String, interactive: Bool) -> Bool {
    name.withCString { right -> Bool in
        var item = AuthorizationItem(name: right, valueLength: 0, value: nil, flags: 0)
        return withUnsafeMutablePointer(to: &item) { ptr in
            var rights = AuthorizationRights(count: 1, items: ptr)
            // Check an existing grant first, without user interaction.
            if AuthorizationCopyRights(authorization, &rights, nil, [], nil) == errAuthorizationSuccess {
                return true
            }
            let flags: AuthorizationFlags = interactive ? [.interactionAllowed, .extendRights] : [.extendRights]
            return AuthorizationCopyRights(authorization, &rights, nil, flags, nil) == errAuthorizationSuccess
        }
    }
}

/// Keep the OS authorization handle for this app process, not the password.
/// Switching between proxy and TUN opens a new authenticated helper session;
/// retaining this handle avoids asking for credentials again while the OS
/// considers the previously granted right valid. macOS may still require a
/// fresh approval after expiration or a policy change.
private final class AuthorizationSession {
    static let shared = AuthorizationSession()
    private let lock = NSLock()
    private var authorization: AuthorizationRef?

    func externalForm() -> Data? {
        lock.lock(); defer { lock.unlock() }
        if authorization == nil {
            var created: AuthorizationRef?
            guard AuthorizationCreate(nil, nil, [], &created) == errAuthorizationSuccess,
                  let created else { return nil }
            authorization = created
        }
        guard let authorization else { return nil }
        // An administrator already approved this installation: the session right needs no second password.
        // Without it (another user, or an install from before the right existed) the system asks as before.
        guard obtain(authorization, sessionRight, interactive: false)
            || obtain(authorization, kAuthorizationRightExecute, interactive: true) else { return nil }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(authorization, &form) == errAuthorizationSuccess else { return nil }
        defer { _ = withUnsafeMutableBytes(of: &form) { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        return withUnsafeBytes(of: &form) { Data($0) }
    }

    deinit {
        if let authorization { AuthorizationFree(authorization, []) }
    }
}

// This client is not yet wired into PrismRoute. The expected CDHash must come
// from a verified, build-bound trust policy, never from the XPC peer or UI.
final class PrismBridgeClient {
    private let connection: NSXPCConnection
    private let expected: String
    private var authenticated = false
    private var opened = false
    private var healthy = true

    private final class Once {
        let lock = NSLock()
        let semaphore = DispatchSemaphore(value: 0)
        var result: String?
        func finish(_ value: String) {
            lock.lock(); defer { lock.unlock() }
            guard result == nil else { return }
            result = value; semaphore.signal()
        }
        func wait() -> String? {
            guard semaphore.wait(timeout: .now() + 10) == .success else { return nil }
            lock.lock(); defer { lock.unlock() }; return result
        }
    }

    init?(service: String, expectedCDHash: String) {
        #if PRISM_BRIDGE_TEST
        let validService = service.hasPrefix("dev.prismroute.bridgetest.")
        let options: NSXPCConnection.Options = []
        #else
        let validService = service == "dev.prismroute.proxy-bridge"
        let options: NSXPCConnection.Options = .privileged
        #endif
        guard validService, expectedCDHash.utf8.count == 40,
              expectedCDHash.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else { return nil }
        expected = expectedCDHash
        connection = NSXPCConnection(machServiceName: service, options: options)
        connection.remoteObjectInterface = NSXPCInterface(with: PrismProxyBridge.self)
        connection.setCodeSigningRequirement("cdhash H\"\(expectedCDHash)\"")
        connection.resume()
    }
    deinit { connection.invalidate() }

    private func call(_ operation: (PrismProxyBridge, @escaping (String) -> Void) -> Void) -> String? {
        guard healthy else { return nil }
        let once = Once()
        guard let remote = connection.remoteObjectProxyWithErrorHandler({ _ in once.finish("connection_error") }) as? PrismProxyBridge else { return nil }
        operation(remote) { value in once.finish(value) }
        let result = once.wait()
        if result == nil || result == "connection_error" { healthy = false; connection.invalidate() }
        return result
    }

    /// A side-effect-free message is the only request before XPC verifies the
    /// daemon requirement. No authorization form or handle is sent before its
    /// response is accepted; a wrong requirement or timeout closes the channel.
    func authenticatePeer() -> Bool {
        guard !authenticated, call({ $0.hello(reply: $1) }) == "ready" else { connection.invalidate(); return false }
        authenticated = true
        return true
    }

    /// Authenticate the daemon first, then use the in-memory OS authorization.
    /// The application never receives or stores the user's password.
    func open(tunChannel: FileHandle?) -> Bool {
        guard authenticated, !opened else { return false }
        guard var token = AuthorizationSession.shared.externalForm() else { return false }
        defer { token.resetBytes(in: 0..<token.count) }
        return openWithToken(token, tunChannel: tunChannel)
    }

    private func openWithToken(_ token: Data, tunChannel: FileHandle?) -> Bool {
        guard authenticated, !opened, call({ $0.openSession(token, tunChannel: tunChannel, reply: $1) }) == "ready" else { connection.invalidate(); healthy = false; return false }
        opened = true; return true
    }
    #if PRISM_BRIDGE_TEST
    func openForTesting(_ token: Data, tunChannel: FileHandle?) -> Bool {
        openWithToken(token, tunChannel: tunChannel)
    }
    #endif

    func enable(port: UInt16, bypass: String) -> String? {
        guard opened, port != 0, bypass.utf8.count <= 2048 else { return nil }
        return call { $0.enable(port, bypass: bypass, reply: $1) }
    }
    func prepareTun() -> String? { guard opened else { return nil }; return call { $0.prepareTun(reply: $1) } }
    func activateTun() -> String? { guard opened else { return nil }; return call { $0.activateTun(reply: $1) } }
    func status() -> String? { guard opened else { return nil }; return call { $0.status(reply: $1) } }
    func restore() -> String? { guard opened else { return nil }; return call { $0.restore(reply: $1) } }
    func shutdown() -> String? {
        guard opened else { return nil }
        let result = call { $0.shutdown(reply: $1) }
        if result == "{\"status\":\"stopped\"}" { opened = false }
        return result
    }
}
