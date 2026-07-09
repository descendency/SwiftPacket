import Foundation

/// An IPv4 packet header (RFC 791).
public struct IPv4: Layer {
    public static let layerType = LayerType.ipv4

    public let version: UInt8
    /// Header length in bytes (IHL × 4).
    public let headerLength: Int
    public let dscp: UInt8
    public let ecn: UInt8
    /// Total datagram length in bytes, from the header.
    public let totalLength: Int
    public let identification: UInt16
    public let dontFragment: Bool
    public let moreFragments: Bool
    /// Fragment offset in 8-byte units.
    public let fragmentOffset: UInt16
    public let ttl: UInt8
    public let proto: IPProtocol
    public let headerChecksum: UInt16
    public let sourceAddress: IPv4Address
    public let destinationAddress: IPv4Address
    public let options: Data
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes an IPv4 header, validating version and IHL and clamping the payload
/// to the header's declared total length (so trailing link padding is not
/// mistaken for transport data).
public struct IPv4Decoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        let (layer, next) = try IPv4.decodeValue(data)
        return DecodeResult(layer: layer, next: next)
    }
}

extension IPv4 {
    /// Concrete, non-boxing decode for the ``StackDecoder`` fast path.
    static func decodeValue(_ data: Data) throws -> (IPv4, NextDecode) {
        var reader = ByteReader(data)

        let versionIHL = try reader.readUInt8()
        let version = versionIHL >> 4
        let ihl = Int(versionIHL & 0x0F)
        guard version == 4 else {
            throw DecodingError.invalidValue(field: "IP version", value: UInt64(version))
        }
        guard ihl >= 5 else {
            throw DecodingError.malformed("IPv4 IHL < 5")
        }
        let headerLength = ihl * 4

        let tos = try reader.readUInt8()
        let totalLength = Int(try reader.readUInt16())
        let identification = try reader.readUInt16()
        let flagsAndFragment = try reader.readUInt16()
        let ttl = try reader.readUInt8()
        let proto = IPProtocol(rawValue: try reader.readUInt8())
        let checksum = try reader.readUInt16()
        let source = try reader.readIPv4Address()
        let destination = try reader.readIPv4Address()

        let optionsLength = headerLength - 20
        guard optionsLength >= 0 else {
            throw DecodingError.malformed("IPv4 header length underflow")
        }
        let options = optionsLength > 0 ? try reader.readBytes(optionsLength) : Data()

        let base = data.startIndex
        let available = data.count
        let end = (totalLength >= headerLength && totalLength <= available) ? totalLength : available
        let payload = data[(base + headerLength)..<(base + end)]
        let fragmentOffset = flagsAndFragment & 0x1FFF

        let layer = IPv4(
            version: version,
            headerLength: headerLength,
            dscp: tos >> 2,
            ecn: tos & 0x03,
            totalLength: totalLength,
            identification: identification,
            dontFragment: (flagsAndFragment & 0x4000) != 0,
            moreFragments: (flagsAndFragment & 0x2000) != 0,
            fragmentOffset: fragmentOffset,
            ttl: ttl,
            proto: proto,
            headerChecksum: checksum,
            sourceAddress: source,
            destinationAddress: destination,
            options: options,
            payload: payload,
            header: data.prefix(headerLength)
        )

        if payload.isEmpty {
            return (layer, .done)
        }
        // Non-initial fragments carry no clean transport header.
        let next = fragmentOffset > 0 ? LayerType.payload : IPv4Decoder.nextLayerType(for: proto)
        return (layer, .next(next, payload))
    }
}

func ipNextLayerType(for proto: IPProtocol) -> LayerType {
    switch proto {
    case .tcp: return .tcp
    case .udp: return .udp
    case .icmp: return .icmpv4
    case .icmpv6: return .icmpv6
    case .igmp: return .igmp
    case .fragment: return .ipv6Fragment
    case .gre: return .gre
    case .esp: return .esp
    case .ah: return .ah
    case .etherIP: return .etherIP
    case .sctp: return .sctp
    case .udpLite: return .udpLite
    case .vrrp: return .vrrp
    case .ospf: return .ospf
    default: return .payload
    }
}

extension IPv4Decoder {
    static func nextLayerType(for proto: IPProtocol) -> LayerType {
        ipNextLayerType(for: proto)
    }
}
