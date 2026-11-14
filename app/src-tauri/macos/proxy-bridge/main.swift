// Privileged XPC bridge. Not installed, registered or used by the preview yet.
// Build together with Protocol.swift and fdpass.c on macOS 13+.
import Foundation
import Security
import Darwin

@_silgen_name("prism_bridge_send_fd")
private func sendDescriptor(_ channel: Int32, _ descriptor: Int32) -> Int32

private let guardPath = "/Library/PrivilegedHelperTools/dev.prismroute.proxy-guard"
private let bridgePath = "/Library/PrivilegedHelperTools/dev.prismroute.proxy-bridge"
private let policyPath = "/private/var/db/dev.prismroute/client-cdhash"
private let serviceName = "dev.prismroute.proxy-bridge"

// Both the policy and every parent are protected from unprivileged mutation.
// Do not accept a requirement, path or executable from the client.
private func trusted(_ path: String, directory: Bool, privateFile: Bool = false) -> Bool {
    var st = stat()
    guard lstat(path, &st) == 0, st.st_uid == 0,
          (st.st_mode & S_IFMT) == (directory ? S_IFDIR : S_IFREG),
          (st.st_mode & (privateFile ? 0o077 : 0o022)) == 0 else { return false }
    return directory || st.st_nlink == 1
}

private func clientRequirement() -> String? {
    for path in ["/", "/Library", "/Library/PrivilegedHelperTools", "/private", "/private/var", "/private/var/db"] {
        guard trusted(path, directory: true) else { return nil }
    }
    guard trusted("/private/var/db/dev.prismroute", directory: true, privateFile: true),
          trusted(bridgePath, directory: false), trusted(guardPath, directory: false),
          Bundle.main.executableURL?.resolvingSymlinksInPath().path == bridgePath else { return nil }
    let fd = open(policyPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var st = stat()
    // A build's code hash (40 hex digits), or "cert:" and the SHA-1 of the certificate the app is signed
    // with: then every build signed with it is trusted, and an update asks for no password.
    guard fstat(fd, &st) == 0, st.st_uid == 0, (st.st_mode & S_IFMT) == S_IFREG,
          (st.st_mode & 0o077) == 0, st.st_nlink == 1, st.st_size == 40 || st.st_size == 45 else { return nil }
    var bytes = [UInt8](repeating: 0, count: Int(st.st_size))
    guard read(fd, &bytes, bytes.count) == bytes.count else { return nil }
    let certificate = bytes.count == 45
    if certificate && !bytes.starts(with: Array("cert:".utf8)) { return nil }
    let hex = certificate ? Array(bytes[5...]) : bytes
    guard hex.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
          let hash = String(bytes: hex, encoding: .ascii) else { return nil }
    // The installer checks the same requirement (macos_installer.rs, certificate_requirement).
    return certificate ? "identifier \"dev.prismroute.console\" and certificate leaf = H\"\(hash)\"" : "cdhash H\"\(hash)\""
}

// This checks rights previously obtained via the system UI. The daemon never
// asks for or sees the user's password. A failed or expired form fails closed.
private func isAuthorized(_ token: Data) -> Bool {
    guard token.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
    var form = AuthorizationExternalForm()
    _ = withUnsafeMutableBytes(of: &form) { token.copyBytes(to: $0) }
    defer { _ = withUnsafeMutableBytes(of: &form) { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    var authorization: AuthorizationRef?
    guard AuthorizationCreateFromExternalForm(&form, &authorization) == errAuthorizationSuccess,
          let authorization else { return false }
    defer { AuthorizationFree(authorization, []) }
    // The session right (rule `is-admin`, registered by the installer) or the administrator right.
    return ["dev.prismroute.proxy-bridge.session", kAuthorizationRightExecute].contains { name in
        name.withCString { right in
            var item = AuthorizationItem(name: right, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { ptr in
                var rights = AuthorizationRights(count: 1, items: ptr)
                return AuthorizationCopyRights(authorization, &rights, nil, [], nil) == errAuthorizationSuccess
            }
        }
    }
}

private final class GuardChannel {
    private let process: Process
    private let socket: Int32
    private var open = true
    init?(tunChannel: FileHandle?) {
        var pair = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { return nil }
        var noSigPipe: Int32 = 1
        guard setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            close(pair[0]); close(pair[1]); return nil
        }
        var timeout = timeval(tv_sec: 8, tv_usec: 0)
        guard setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            close(pair[0]); close(pair[1]); return nil
        }
        let child = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: guardPath)
        process.arguments = tunChannel == nil ? [] : ["--tun-channel"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardInput = child; process.standardOutput = child
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { close(pair[0]); child.closeFile(); return nil }
        child.closeFile()
        self.process = process; self.socket = pair[0]
        if let tunChannel, sendDescriptor(socket, tunChannel.fileDescriptor) != 0 { closeChannel(); return nil }
        // Guard startup restores any old journal before answering status.
        guard request(["command": "status"]) == "{\"status\":\"idle\"}" else { closeChannel(); return nil }
    }
    deinit { closeChannel() }
    func closeChannel() {
        if open { open = false; _ = shutdown(socket, SHUT_RDWR); close(socket) }
    }
    func request(_ command: [String: Any]) -> String? {
        guard open, JSONSerialization.isValidJSONObject(command),
              var data = try? JSONSerialization.data(withJSONObject: command), data.count <= 4095 else { return nil }
        data.append(0x0a)
        let written = data.withUnsafeBytes { buf -> Bool in
            guard let base = buf.baseAddress else { return false }
            var offset = 0
            while offset < buf.count {
                let count = Darwin.write(socket, base.advanced(by: offset), buf.count - offset)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { return false }
                offset += count
            }
            return true
        }
        guard written else { closeChannel(); return nil }
        let deadline = DispatchTime.now().uptimeNanoseconds + 8_000_000_000
        var response = [UInt8]()
        while response.count < 4096 {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { closeChannel(); return nil }
            var event = pollfd(fd: socket, events: Int16(POLLIN), revents: 0)
            let ready = poll(&event, 1, Int32((deadline - now + 999_999) / 1_000_000))
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0 else { closeChannel(); return nil }
            var byte: UInt8 = 0
            guard read(socket, &byte, 1) == 1 else { closeChannel(); return nil }
            if byte == 10 { return String(bytes: response, encoding: .utf8) }
            response.append(byte)
        }
        closeChannel(); return nil
    }
}

private final class Session: NSObject, PrismProxyBridge {
    private let queue = DispatchQueue(label: "dev.prismroute.proxy-bridge.session")
    private var greeted = false
    private var channel: GuardChannel?
    func hello(reply: @escaping (String) -> Void) { queue.async { self.greeted = true; reply("ready") } }
    func openSession(_ authorization: Data, tunChannel: FileHandle?, reply: @escaping (String) -> Void) {
        queue.async {
            guard self.greeted, self.channel == nil, isAuthorized(authorization) else { reply("unauthorized"); return }
            guard let channel = GuardChannel(tunChannel: tunChannel) else { reply("guard_unavailable"); return }
            self.channel = channel; reply("ready")
        }
    }
    private func send(_ command: [String: Any], reply: @escaping (String) -> Void) {
        queue.async { guard let channel = self.channel else { reply("not_open"); return }; reply(channel.request(command) ?? "recovery_required") }
    }
    func enable(_ port: UInt16, bypass: String, reply: @escaping (String) -> Void) {
        guard port != 0, bypass.utf8.count <= 2048 else { reply("invalid_request"); return }
        send(["command": "enable", "port": port, "bypass": bypass], reply: reply)
    }
    func restore(reply: @escaping (String) -> Void) { send(["command": "restore"], reply: reply) }
    func prepareTun(reply: @escaping (String) -> Void) { send(["command": "prepare_tun"], reply: reply) }
    func activateTun(reply: @escaping (String) -> Void) { send(["command": "activate_tun"], reply: reply) }
    func status(reply: @escaping (String) -> Void) { send(["command": "status"], reply: reply) }
    func shutdown(reply: @escaping (String) -> Void) { send(["command": "shutdown"], reply: reply) }
    func invalidate() { queue.async { self.channel?.closeChannel(); self.channel = nil } }
}

private final class Delegate: NSObject, NSXPCListenerDelegate {
    let requirement: String
    init(_ requirement: String) { self.requirement = requirement }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let session = Session()
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: PrismProxyBridge.self)
        connection.exportedObject = session
        connection.invalidationHandler = { session.invalidate() }
        connection.interruptionHandler = { session.invalidate() }
        connection.resume()
        return true
    }
}

#if PRISM_BRIDGE_AUTH_TEST
// No network access, no privilege prompt, and no privileged operation.
guard !isAuthorized(Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)),
      !isAuthorized(Data(repeating: 0, count: 1)) else { exit(1) }
print("invalid authorization forms rejected")
#else
guard geteuid() == 0, let requirement = clientRequirement() else { exit(1) }
private let delegate = Delegate(requirement)
let listener = NSXPCListener(machServiceName: serviceName)
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
#endif
