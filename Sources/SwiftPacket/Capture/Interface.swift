import Cpcap
import Foundation

/// A network interface discovered via libpcap, suitable for opening a
/// ``LiveCapture``.
public struct Interface: Sendable, Hashable {
    /// The interface name to pass to ``LiveCapture`` (for example `"en0"`).
    public let name: String
    /// A human-friendly description, when libpcap provides one.
    public let descriptionText: String?
    /// Whether this is a loopback interface.
    public let isLoopback: Bool
    /// Whether the interface is administratively up.
    public let isUp: Bool
    /// Whether the interface is running (link present).
    public let isRunning: Bool
}

/// Enumerates capture-capable network interfaces.
public enum Devices {
    /// Lists the available capture interfaces.
    /// - Throws: ``PcapError`` if enumeration fails.
    public static func all() throws -> [Interface] {
        var list: UnsafeMutablePointer<pcap_if_t>?
        let (status, message) = withPcapErrorBuffer { errbuf in
            pcap_findalldevs(&list, errbuf)
        }
        guard status == 0 else {
            throw PcapError(message: message.isEmpty ? "pcap_findalldevs failed" : message, code: status)
        }
        defer {
            if let list { pcap_freealldevs(list) }
        }

        var interfaces: [Interface] = []
        var cursor = list
        while let device = cursor?.pointee {
            let flags = device.flags
            interfaces.append(
                Interface(
                    name: device.name.map { String(cString: $0) } ?? "",
                    descriptionText: device.description.map { String(cString: $0) },
                    isLoopback: (flags & UInt32(PCAP_IF_LOOPBACK)) != 0,
                    isUp: (flags & UInt32(PCAP_IF_UP)) != 0,
                    isRunning: (flags & UInt32(PCAP_IF_RUNNING)) != 0
                )
            )
            cursor = device.next
        }
        return interfaces
    }
}
