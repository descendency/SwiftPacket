import Foundation

/// An IEEE 802.3 / Ethernet II frame header.
public struct Ethernet: Layer {
    public static let layerType = LayerType.ethernet

    public let destination: MACAddress
    public let source: MACAddress
    public let etherType: EtherType
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes an Ethernet II frame header (14 bytes).
///
/// A type field below 1536 (0x0600) is an IEEE 802.3 length, not an EtherType;
/// such frames carry an LLC payload we do not decode further, so the remainder
/// becomes an opaque ``Payload``.
public struct EthernetDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let destination = try reader.readMACAddress()
        let source = try reader.readMACAddress()
        let etherType = EtherType(rawValue: try reader.readUInt16())
        let payload = reader.readRemaining()

        let layer = Ethernet(
            destination: destination,
            source: source,
            etherType: etherType,
            payload: payload,
            header: data.prefix(14)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        let next: LayerType = etherType.rawValue < 1536 ? .payload : Self.nextLayerType(for: etherType)
        return DecodeResult(layer: layer, next: .next(next, payload))
    }

    static func nextLayerType(for etherType: EtherType) -> LayerType {
        switch etherType {
        case .ipv4: return .ipv4
        case .ipv6: return .ipv6
        case .arp: return .arp
        default: return .payload
        }
    }
}
