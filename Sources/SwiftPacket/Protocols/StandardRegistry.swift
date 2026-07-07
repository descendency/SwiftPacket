import Foundation

/// Dispatches `DLT_RAW` captures (a bare IP packet with no link header) to the
/// IPv4 or IPv6 decoder based on the version nibble. Adds no layer of its own;
/// it returns the underlying IP decoder's result directly.
public struct RawIPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        let version = (data.first ?? 0) >> 4
        switch version {
        case 4: return try IPv4Decoder().decode(data)
        case 6: return try IPv6Decoder().decode(data)
        default:
            throw DecodingError.invalidValue(field: "IP version", value: UInt64(version))
        }
    }
}

extension DecoderRegistry {
    /// A registry wired for the protocols SwiftPacket decodes, with link-type
    /// mappings for Ethernet, loopback, and raw-IP captures.
    public static let standard: DecoderRegistry = {
        var registry = DecoderRegistry()

        registry.register(.ethernet, decoder: EthernetDecoder())
        registry.register(.loopback, decoder: LoopbackDecoder())
        registry.register(.rawIP, decoder: RawIPDecoder())
        registry.register(.ipv4, decoder: IPv4Decoder())
        registry.register(.ipv6, decoder: IPv6Decoder())
        registry.register(.arp, decoder: ARPDecoder())
        registry.register(.tcp, decoder: TCPDecoder())
        registry.register(.udp, decoder: UDPDecoder())
        registry.register(.icmpv4, decoder: ICMPv4Decoder())
        registry.register(.icmpv6, decoder: ICMPv6Decoder())
        registry.register(.dns, decoder: DNSDecoder())

        registry.mapLink(.ethernet, to: .ethernet)
        registry.mapLink(.null, to: .loopback)
        registry.mapLink(.loop, to: .loopback)
        registry.mapLink(.raw, to: .rawIP)

        return registry
    }()
}
