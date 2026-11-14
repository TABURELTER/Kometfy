import Foundation

// Only this narrow interface is exposed over XPC. Never send a password.
@objc protocol PrismProxyBridge {
    func hello(reply: @escaping (String) -> Void)
    func openSession(_ authorization: Data, tunChannel: FileHandle?, reply: @escaping (String) -> Void)
    func enable(_ port: UInt16, bypass: String, reply: @escaping (String) -> Void)
    func restore(reply: @escaping (String) -> Void)
    func prepareTun(reply: @escaping (String) -> Void)
    func activateTun(reply: @escaping (String) -> Void)
    func status(reply: @escaping (String) -> Void)
    func shutdown(reply: @escaping (String) -> Void)
}
