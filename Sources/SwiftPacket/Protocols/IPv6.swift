import Foundation

/// An IPv6 packet header (RFC 8200), fixed 40-byte form.
public struct IPv6: Layer {
    public static let layerType = LayerType.ipv6

    public let version: UInt8
    public let trafficClass: UInt8
    public let flowLabel: UInt32
    public let payloadLength: Int
    public let nextHeader: IPProtocol
    public let hopLimit: UInt8
    public let sourceAddress: IPv6Address
    public let destinationAddress: IPv6Address
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the fixed IPv6 header.
///
/// Extension headers (hop-by-hop, routing, fragment, …) are not chained in this
/// phase: if ``IPv6/nextHeader`` is not a recognized transport protocol, the
/// remainder is delivered as an opaque ``Payload``.
public struct IPv6Decoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)

        let word = try reader.readUInt32()
        let version = UInt8(word >> 28)
        guard version == 6 else {
            throw DecodingError.invalidValue(field: "IP version", value: UInt64(version))
        }
        let trafficClass = UInt8((word >> 20) & 0xFF)
        let flowLabel = word & 0x000F_FFFF

        let payloadLength = Int(try reader.readUInt16())
        let nextHeader = IPProtocol(rawValue: try reader.readUInt8())
        let hopLimit = try reader.readUInt8()
        let source = try reader.readIPv6Address()
        let destination = try reader.readIPv6Address()

        let base = data.startIndex
        let available = data.count
        let declaredEnd = 40 + payloadLength
        let end = (payloadLength > 0 && declaredEnd <= available) ? declaredEnd : available
        let payload = data[(base + 40)..<(base + end)]

        let layer = IPv6(
            version: version,
            trafficClass: trafficClass,
            flowLabel: flowLabel,
            payloadLength: payloadLength,
            nextHeader: nextHeader,
            hopLimit: hopLimit,
            sourceAddress: source,
            destinationAddress: destination,
            payload: payload,
            header: data.prefix(40)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        return DecodeResult(layer: layer, next: .next(ipNextLayerType(for: nextHeader), payload))
    }
}
