import Cpcap
import Foundation

/// An error originating from libpcap.
public struct PcapError: Error, CustomStringConvertible, Sendable {
    /// A human-readable message, usually libpcap's own error text.
    public let message: String

    /// The libpcap status code, when one is available.
    public let code: Int32?

    public init(message: String, code: Int32? = nil) {
        self.message = message
        self.code = code
    }

    public var description: String {
        if let code {
            return "PcapError(\(code)): \(message)"
        }
        return "PcapError: \(message)"
    }
}

extension PcapError {
    /// Builds an error from a libpcap status code via `pcap_statustostr`.
    static func status(_ code: Int32) -> PcapError {
        let text = pcap_statustostr(code).map { String(cString: $0) } ?? "unknown libpcap error"
        return PcapError(message: text, code: code)
    }
}

/// Runs `body` with a zero-initialized libpcap error buffer and returns both the
/// closure's result and the buffer's contents as a `String`.
///
/// Many libpcap entry points report failure detail by writing into a
/// caller-provided `char errbuf[PCAP_ERRBUF_SIZE]`; this centralizes that
/// allocation so call sites stay readable.
func withPcapErrorBuffer<T>(_ body: (UnsafeMutablePointer<CChar>) -> T) -> (result: T, message: String) {
    let size = Int(PCAP_ERRBUF_SIZE)
    let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: size)
    defer { buffer.deallocate() }
    buffer.initialize(repeating: 0, count: size)
    let result = body(buffer)
    return (result, String(cString: buffer))
}
