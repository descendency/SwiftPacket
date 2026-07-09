import Foundation

/// An EtherType value from an Ethernet frame's type field.
public struct EtherType: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let ipv4 = EtherType(rawValue: 0x0800)
    public static let arp = EtherType(rawValue: 0x0806)
    public static let ipv6 = EtherType(rawValue: 0x86DD)
    public static let vlan = EtherType(rawValue: 0x8100)
    /// 802.1ad service tag (Q-in-Q outer VLAN).
    public static let qinq = EtherType(rawValue: 0x88A8)
    public static let mplsUnicast = EtherType(rawValue: 0x8847)
    public static let mplsMulticast = EtherType(rawValue: 0x8848)
    public static let pppoeDiscovery = EtherType(rawValue: 0x8863)
    public static let pppoeSession = EtherType(rawValue: 0x8864)
    public static let lldp = EtherType(rawValue: 0x88CC)
    public static let eapol = EtherType(rawValue: 0x888E)
    /// Transparent Ethernet bridging — an Ethernet frame inside GRE/VXLAN.
    public static let transparentEthernetBridging = EtherType(rawValue: 0x6558)
    public static let erspan = EtherType(rawValue: 0x88BE)
}

/// The layer that decodes a payload with the given EtherType — shared by every
/// header that carries one (Ethernet, VLAN tags, SLL, GRE, ERSPAN, …).
func etherNextLayerType(for etherType: EtherType) -> LayerType {
    switch etherType {
    case .ipv4: return .ipv4
    case .ipv6: return .ipv6
    case .arp: return .arp
    case .vlan, .qinq: return .vlan
    case .mplsUnicast, .mplsMulticast: return .mpls
    case .pppoeDiscovery, .pppoeSession: return .pppoe
    case .lldp: return .lldp
    case .eapol: return .eapol
    case .transparentEthernetBridging: return .ethernet
    case .erspan: return .erspan
    default: return .payload
    }
}

/// An IP protocol number (the IPv4 `protocol` / IPv6 `next header` field).
public struct IPProtocol: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let hopByHop = IPProtocol(rawValue: 0)
    public static let icmp = IPProtocol(rawValue: 1)
    public static let igmp = IPProtocol(rawValue: 2)
    public static let ipv4 = IPProtocol(rawValue: 4)
    public static let tcp = IPProtocol(rawValue: 6)
    public static let udp = IPProtocol(rawValue: 17)
    public static let ipv6 = IPProtocol(rawValue: 41)
    public static let routing = IPProtocol(rawValue: 43)
    public static let fragment = IPProtocol(rawValue: 44)
    public static let gre = IPProtocol(rawValue: 47)
    public static let esp = IPProtocol(rawValue: 50)
    public static let ah = IPProtocol(rawValue: 51)
    public static let icmpv6 = IPProtocol(rawValue: 58)
    public static let noNextHeader = IPProtocol(rawValue: 59)
    public static let destinationOptions = IPProtocol(rawValue: 60)
    public static let ospf = IPProtocol(rawValue: 89)
    public static let etherIP = IPProtocol(rawValue: 97)
    public static let vrrp = IPProtocol(rawValue: 112)
    public static let l2tp = IPProtocol(rawValue: 115)
    public static let sctp = IPProtocol(rawValue: 132)
    public static let udpLite = IPProtocol(rawValue: 136)
}

extension IPProtocol: CustomStringConvertible {
    /// The conventional IANA keyword for well-known protocol numbers, or `nil`
    /// for numbers this library does not name.
    public var name: String? {
        switch self {
        case .hopByHop: return "HOPOPT"
        case .icmp: return "ICMP"
        case .igmp: return "IGMP"
        case .ipv4: return "IPv4"
        case .tcp: return "TCP"
        case .udp: return "UDP"
        case .ipv6: return "IPv6"
        case .routing: return "IPv6-Route"
        case .fragment: return "IPv6-Frag"
        case .gre: return "GRE"
        case .esp: return "ESP"
        case .ah: return "AH"
        case .icmpv6: return "ICMPv6"
        case .noNextHeader: return "IPv6-NoNxt"
        case .destinationOptions: return "IPv6-Opts"
        case .ospf: return "OSPF"
        case .vrrp: return "VRRP"
        case .etherIP: return "ETHERIP"
        case .l2tp: return "L2TP"
        case .sctp: return "SCTP"
        case .udpLite: return "UDPLite"
        default: return nil
        }
    }

    /// The IANA keyword if known, otherwise the bare number (e.g. `"proto-253"`).
    public var description: String { name ?? "proto-\(rawValue)" }
}

extension IPv6 {
    /// The L4 protocol number, under the same name IPv4 uses — so callers can
    /// read the protocol of either IP version uniformly.
    public var proto: IPProtocol { nextHeader }
}

extension Packet {
    /// The L4 protocol number from the packet's IP header (IPv4 `protocol` or
    /// IPv6 `next header`), if the packet has an IP layer.
    ///
    /// This is the raw protocol identity — present even when the library has no
    /// decoder for the protocol, so consumers never have to bucket unrecognized
    /// transports as "other".
    public var ipProtocol: IPProtocol? {
        if let v4 = layer(IPv4.self) { return v4.proto }
        if let v6 = layer(IPv6.self) { return v6.nextHeader }
        return nil
    }
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
    // id 13 is LayerType.tls (declared alongside the TLS layer).

    // Link layers.
    public static let vlan = LayerType(id: 14, name: "802.1Q", category: .link)
    public static let mpls = LayerType(id: 15, name: "MPLS", category: .link)
    public static let llc = LayerType(id: 16, name: "LLC", category: .link)
    public static let stp = LayerType(id: 17, name: "STP", category: .link)
    public static let lldp = LayerType(id: 18, name: "LLDP", category: .link)
    public static let eapol = LayerType(id: 19, name: "EAPOL", category: .link)
    public static let linuxSLL = LayerType(id: 20, name: "LinuxSLL", category: .link)
    public static let pflog = LayerType(id: 21, name: "PFLog", category: .link)

    // Tunnels and encapsulations.
    public static let gre = LayerType(id: 22, name: "GRE", category: .network)
    public static let vxlan = LayerType(id: 23, name: "VXLAN", category: .network)
    public static let etherIP = LayerType(id: 24, name: "EtherIP", category: .network)
    public static let erspan = LayerType(id: 25, name: "ERSPAN", category: .network)
    public static let pppoe = LayerType(id: 26, name: "PPPoE", category: .link)
    public static let ppp = LayerType(id: 27, name: "PPP", category: .link)

    // IP-carried protocols.
    public static let igmp = LayerType(id: 28, name: "IGMP", category: .transport)
    public static let esp = LayerType(id: 29, name: "ESP", category: .transport)
    public static let ah = LayerType(id: 30, name: "AH", category: .transport)
    public static let sctp = LayerType(id: 31, name: "SCTP", category: .transport)
    public static let udpLite = LayerType(id: 32, name: "UDPLite", category: .transport)
    public static let vrrp = LayerType(id: 33, name: "VRRP", category: .transport)

    // UDP applications.
    public static let dhcpv4 = LayerType(id: 34, name: "DHCPv4", category: .application)
    public static let dhcpv6 = LayerType(id: 35, name: "DHCPv6", category: .application)
    public static let ntp = LayerType(id: 36, name: "NTP", category: .application)

    /// The IPv6 fragment extension header (next-header 44).
    public static let ipv6Fragment = LayerType(id: 37, name: "IPv6Fragment", category: .network)

    // Phase 13 breadth.
    public static let cdp = LayerType(id: 38, name: "CDP", category: .link)
    public static let eap = LayerType(id: 39, name: "EAP", category: .link)
    public static let ospf = LayerType(id: 40, name: "OSPF", category: .network)
    public static let radiotap = LayerType(id: 41, name: "Radiotap", category: .link)
    public static let dot11 = LayerType(id: 42, name: "802.11", category: .link)
}
