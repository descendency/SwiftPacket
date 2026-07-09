import Foundation

/// A UDP datagram header (RFC 768).
public struct UDP: Layer {
    public static let layerType = LayerType.udp

    public let sourcePort: UInt16
    public let destinationPort: UInt16
    /// Datagram length in bytes, including the 8-byte header.
    public let length: Int
    public let checksum: UInt16
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes a UDP header. Payloads are routed to application decoders by
/// well-known port — DNS (53), DHCPv4 (67/68), DHCPv6 (546/547), NTP (123),
/// and VXLAN (4789); everything else becomes opaque ``Payload``.
public struct UDPDecoder: LayerDecoder {
    public init() {}

    static let dnsPort: UInt16 = 53

    static func nextLayerType(source: UInt16, destination: UInt16) -> LayerType {
        switch (source, destination) {
        case (dnsPort, _), (_, dnsPort): return .dns
        case (67, _), (_, 67), (68, _), (_, 68): return .dhcpv4
        case (546, _), (_, 546), (547, _), (_, 547): return .dhcpv6
        case (123, _), (_, 123): return .ntp
        case (_, 4789): return .vxlan
        default: return .payload
        }
    }

    public func decode(_ data: Data) throws -> DecodeResult {
        let (layer, next) = try UDP.decodeValue(data)
        return DecodeResult(layer: layer, next: next)
    }
}

extension UDP {
    /// Concrete, non-boxing decode for the ``StackDecoder`` fast path.
    static func decodeValue(_ data: Data) throws -> (UDP, NextDecode) {
        var reader = ByteReader(data)
        let sourcePort = try reader.readUInt16()
        let destinationPort = try reader.readUInt16()
        let length = Int(try reader.readUInt16())
        let checksum = try reader.readUInt16()

        let base = data.startIndex
        let available = data.count
        let end = (length >= 8 && length <= available) ? base + length : data.endIndex
        let payload = data[(base + 8)..<end]

        let layer = UDP(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            length: length,
            checksum: checksum,
            payload: payload,
            header: data.prefix(8)
        )

        if payload.isEmpty {
            return (layer, .done)
        }
        let next = UDPDecoder.nextLayerType(source: sourcePort, destination: destinationPort)
        return (layer, .next(next, payload))
    }
}
