import Foundation

/// One end of a network conversation — a MAC address, an IP address, or a
/// transport port — as a hashable value suitable for keying flow tables.
///
/// Mirrors GoPacket's `Endpoint`: the raw bytes plus a kind tag, so endpoints
/// of different layers never collide and each renders in its natural form.
public struct Endpoint: Hashable, Sendable, CustomStringConvertible {
    /// The layer an endpoint belongs to.
    public enum Kind: Sendable, Hashable {
        case mac
        case ipv4
        case ipv6
        case port
    }

    public let kind: Kind
    /// The raw address/port bytes, big-endian (network order) for ports.
    public let bytes: [UInt8]

    public init(kind: Kind, bytes: [UInt8]) {
        self.kind = kind
        self.bytes = bytes
    }

    public init(_ mac: MACAddress) {
        self.init(kind: .mac, bytes: mac.bytes)
    }

    public init(_ address: IPv4Address) {
        self.init(kind: .ipv4, bytes: address.octets)
    }

    public init(_ address: IPv6Address) {
        self.init(kind: .ipv6, bytes: address.bytes)
    }

    /// A transport-port endpoint.
    public init(port: UInt16) {
        self.init(kind: .port, bytes: [UInt8(port >> 8), UInt8(port & 0xFF)])
    }

    /// The port value, for a `.port` endpoint.
    public var port: UInt16? {
        guard kind == .port, bytes.count == 2 else { return nil }
        return UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    }

    /// Byte-lexicographic ordering (shorter addresses first), used to
    /// canonicalize flows into a direction-insensitive form.
    static func precedes(_ lhs: Endpoint, _ rhs: Endpoint) -> Bool {
        if lhs.bytes.count != rhs.bytes.count { return lhs.bytes.count < rhs.bytes.count }
        for (left, right) in zip(lhs.bytes, rhs.bytes) where left != right { return left < right }
        return false
    }

    public var description: String {
        switch kind {
        case .mac:
            return MACAddress(bytes)?.description ?? bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
        case .ipv4:
            return IPv4Address(Data(bytes))?.description ?? "?"
        case .ipv6:
            return IPv6Address(Data(bytes))?.description ?? "?"
        case .port:
            return port.map(String.init) ?? "?"
        }
    }
}

/// A directional pair of endpoints — the source and destination of one layer
/// of a packet (MAC↔MAC, IP↔IP, or port↔port).
///
/// `Flow` is directional: `a → b` and `b → a` are distinct and hash
/// differently, which is what you want for per-direction accounting. To key
/// both halves of a bidirectional conversation to one bucket, use
/// ``canonical`` (or ``ConnectionKey`` across layers), which orders the
/// endpoints so a flow and its reverse compare equal.
public struct Flow: Hashable, Sendable, CustomStringConvertible {
    public let source: Endpoint
    public let destination: Endpoint

    public init(source: Endpoint, destination: Endpoint) {
        self.source = source
        self.destination = destination
    }

    /// The same conversation with source and destination swapped.
    public var reversed: Flow {
        Flow(source: destination, destination: source)
    }

    /// A direction-insensitive form: the endpoints sorted into a stable order,
    /// so `a → b` and `b → a` produce equal canonical flows (and equal
    /// hashes). Use this as a dictionary key to fold both directions together.
    public var canonical: Flow {
        Flow.ordered(source, destination) ? self : reversed
    }

    /// Whether two endpoints are already in canonical (ascending) order.
    private static func ordered(_ lhs: Endpoint, _ rhs: Endpoint) -> Bool {
        if lhs.bytes.count != rhs.bytes.count {
            return lhs.bytes.count < rhs.bytes.count
        }
        for (left, right) in zip(lhs.bytes, rhs.bytes) where left != right {
            return left < right
        }
        return true
    }

    public var description: String {
        "\(source) → \(destination)"
    }
}

/// A bidirectional connection key spanning the network and transport layers —
/// the canonical 5-tuple. Equal for both directions of the same connection.
///
/// Build one with ``Packet/connectionKey``; use it to correlate the two halves
/// of a TCP/UDP conversation in a flow table.
public struct ConnectionKey: Hashable, Sendable, CustomStringConvertible {
    public let network: Flow
    public let transport: Flow?

    public init(network: Flow, transport: Flow?) {
        // Canonicalize the network and transport flows *together* so both
        // directions map equal AND each address stays paired with its own
        // port. (Canonicalizing them independently could pair a source address
        // with the peer's port when the two flows sort in opposite orders.)
        let flip: Bool
        if Endpoint.precedes(network.destination, network.source) {
            flip = true
        } else if network.source == network.destination,
            let transport, Endpoint.precedes(transport.destination, transport.source)
        {
            flip = true
        } else {
            flip = false
        }
        self.network = flip ? network.reversed : network
        self.transport = flip ? transport?.reversed : transport
    }

    public var description: String {
        if let transport {
            return "\(network) / \(transport)"
        }
        return network.description
    }
}

extension Packet {
    /// The link-layer flow (source → destination MAC), if the packet has an
    /// Ethernet layer.
    public var linkFlow: Flow? {
        guard let ethernet = layer(Ethernet.self) else { return nil }
        return Flow(source: Endpoint(ethernet.source), destination: Endpoint(ethernet.destination))
    }

    /// The network-layer flow (source → destination IP), for IPv4 or IPv6.
    public var networkFlow: Flow? {
        if let ip = layer(IPv4.self) {
            return Flow(source: Endpoint(ip.sourceAddress), destination: Endpoint(ip.destinationAddress))
        }
        if let ip = layer(IPv6.self) {
            return Flow(source: Endpoint(ip.sourceAddress), destination: Endpoint(ip.destinationAddress))
        }
        return nil
    }

    /// The transport-layer flow (source → destination port), for TCP, UDP,
    /// SCTP, or UDP-Lite.
    public var transportFlow: Flow? {
        if let tcp = layer(TCP.self) {
            return Flow(source: Endpoint(port: tcp.sourcePort), destination: Endpoint(port: tcp.destinationPort))
        }
        if let udp = layer(UDP.self) {
            return Flow(source: Endpoint(port: udp.sourcePort), destination: Endpoint(port: udp.destinationPort))
        }
        if let sctp = layer(SCTP.self) {
            return Flow(source: Endpoint(port: sctp.sourcePort), destination: Endpoint(port: sctp.destinationPort))
        }
        if let udpLite = layer(UDPLite.self) {
            return Flow(source: Endpoint(port: udpLite.sourcePort), destination: Endpoint(port: udpLite.destinationPort))
        }
        return nil
    }

    /// A bidirectional connection key (canonical network + transport flow),
    /// or `nil` if the packet has no network layer. Both directions of a
    /// conversation produce equal keys.
    public var connectionKey: ConnectionKey? {
        guard let networkFlow else { return nil }
        return ConnectionKey(network: networkFlow, transport: transportFlow)
    }
}
