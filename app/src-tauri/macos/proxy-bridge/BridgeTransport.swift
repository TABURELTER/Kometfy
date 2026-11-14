import Foundation
import Darwin

// This code is designed to be statically linked into the app executable: the
// daemon then authenticates the GUI's live XPC identity, not a launchable
// sidecar which another local process could abuse as a confused deputy.
private final class Transport {
    let fd: Int32
    let client: PrismBridgeClient
    init(_ fd: Int32, _ client: PrismBridgeClient) { self.fd = fd; self.client = client }

    private func respond(_ value: String) -> Bool {
        guard value.utf8.count < 4096, !value.contains("\n"),
              let data = value.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["status"] is String else { return false }
        var bytes = Array(data); bytes.append(10)
        return bytes.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return false }
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, base.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { return false }
                offset += count
            }
            return true
        }
    }

    func run() {
        var clean = false
        defer { if !clean { _ = client.shutdown() }; close(fd) }
        var frame = [UInt8]()
        while frame.count <= 4096 {
            var byte: UInt8 = 0
            let count = read(fd, &byte, 1)
            if count < 0 && errno == EINTR { continue }
            guard count == 1 else { return }
            if byte != 10 { frame.append(byte); continue }
            guard let request = try? JSONSerialization.jsonObject(with: Data(frame)) as? [String: Any],
                  let command = request["command"] as? String else { return }
            frame.removeAll(keepingCapacity: true)
            let keys = Set(request.keys)
            let response: String?
            switch command {
            case "enable":
                guard keys == Set(["command", "port", "bypass"]),
                      let port = request["port"] as? UInt16, port != 0,
                      let bypass = request["bypass"] as? String, bypass.utf8.count <= 2048 else { return }
                response = client.enable(port: port, bypass: bypass)
            case "restore":
                guard keys == Set(["command"]) else { return }
                response = client.restore()
            case "prepare_tun":
                guard keys == Set(["command"]) else { return }
                response = client.prepareTun()
            case "activate_tun":
                guard keys == Set(["command"]) else { return }
                response = client.activateTun()
            case "status":
                guard keys == Set(["command"]) else { return }
                response = client.status()
            case "shutdown":
                guard keys == Set(["command"]) else { return }
                response = client.shutdown()
            default: return
            }
            guard let response, respond(response) else { return }
            if command == "shutdown", response == "{\"status\":\"stopped\"}" { clean = true; return }
        }
    }
}

private func startTransport(service: String, hash: String, tunFD: Int32, testToken: Data?) -> Int32 {
    guard let client = PrismBridgeClient(service: service, expectedCDHash: hash), client.authenticatePeer() else { return -1 }
    let tunChannel: FileHandle? = tunFD < 0 ? nil : FileHandle(fileDescriptor: tunFD, closeOnDealloc: false)
    #if PRISM_BRIDGE_TEST
    let opened = testToken.map { client.openForTesting($0, tunChannel: tunChannel) } ?? client.open(tunChannel: tunChannel)
    #else
    let opened = client.open(tunChannel: tunChannel)
    #endif
    guard opened else { return -1 }
    var pair = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { _ = client.shutdown(); return -1 }
    for fd in pair {
        let flags = fcntl(fd, F_GETFD)
        if flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0 {
            close(pair[0]); close(pair[1]); _ = client.shutdown(); return -1
        }
    }
    // Either endpoint can outlive its peer if a bridge or the app exits while
    // an exchange is in progress. Return EPIPE instead of delivering SIGPIPE
    // to the application from either side of the transport.
    for fd in pair {
        var noSigPipe: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            close(pair[0]); close(pair[1]); _ = client.shutdown(); return -1
        }
    }
    let transport = Transport(pair[1], client)
    DispatchQueue.global(qos: .userInitiated).async { transport.run() }
    return pair[0]
}

/// Called only from the app's trusted launcher. The hash is a build-bound pin,
/// never a frontend parameter. Returns an owned Unix socket or -1 on failure.
@_cdecl("prism_proxy_bridge_open")
public func prismProxyBridgeOpen(_ hash: UnsafePointer<CChar>?, _ tunFD: Int32) -> Int32 {
    guard let hash else { return -1 }
    return startTransport(service: "dev.prismroute.proxy-bridge", hash: String(cString: hash), tunFD: tunFD, testToken: nil)
}

/// Probe peer identity without requesting or sending authorization. A failed
/// handshake lets the installer update an older bridge or client policy.
@_cdecl("prism_proxy_bridge_probe")
public func prismProxyBridgeProbe(_ hash: UnsafePointer<CChar>?) -> Int32 {
    guard let hash,
          let client = PrismBridgeClient(service: "dev.prismroute.proxy-bridge", expectedCDHash: String(cString: hash)),
          client.authenticatePeer() else { return -1 }
    return 0
}

#if PRISM_BRIDGE_TEST
func openTestTransport(service: String, hash: String, tunFD: Int32) -> Int32 {
    startTransport(service: service, hash: hash, tunFD: tunFD, testToken: Data("test-token".utf8))
}
#endif
