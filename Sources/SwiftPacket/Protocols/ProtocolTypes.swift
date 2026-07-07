import Foundation

/// An EtherType value from an Ethernet frame's type field.
public struct EtherType: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let ipv4 = EtherType(rawValue: 0x0800)
    public static let arp = EtherType(rawValue: 0x0806)
    public static let ipv6 = EtherType(rawValue: 0x86DD)
    public static let vlan = EtherType(rawValue: 0x8100)
}

/// An IP protocol number (the IPv4 `protocol` / IPv6 `next header` field).
public struct IPProtocol: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let icmp = IPProtocol(rawValue: 1)
    public static let tcp = IPProtocol(rawValue: 6)
    public static let udp = IPProtocol(rawValue: 17)
    public static let icmpv6 = IPProtocol(rawValue: 58)
}

/// Layer type identities for the protocols decoded in Phase 3. Ids continue the
/// numbering begun by the built-in ``LayerType/payload`` (0) and
/// ``LayerType/decodeFailure`` (1).
extension LayerType {
    public static let ethernet = LayerType(id: 2, name: "Ethernet", category: .link)
    public static let loopback = LayerType(id: 3, name: "Loopback", category: .link)
    public static let ipv4 = LayerType(id: 4, name: "IPv4", category: .network)
    public static let ipv6 = LayerType(id: 5, name: "IPv6", category: .network)
    public static let arp = LayerType(id: 6, name: "ARP", category: .network)
    public static let tcp = LayerType(id: 7, name: "TCP", category: .transport)
    public static let udp = LayerType(id: 8, name: "UDP", category: .transport)
    public static let icmpv4 = LayerType(id: 9, name: "ICMPv4", category: .transport)
    public static let icmpv6 = LayerType(id: 10, name: "ICMPv6", category: .transport)
    public static let dns = LayerType(id: 11, name: "DNS", category: .application)
    public static let rawIP = LayerType(id: 12, name: "RawIP", category: .network)
}
