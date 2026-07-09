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
/// such frames carry an 802.2 LLC header and chain to the ``LLC`` decoder.
public struct EthernetDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        let (layer, next) = try Ethernet.decodeValue(data)
        return DecodeResult(layer: layer, next: next)
    }

    static func nextLayerType(for etherType: EtherType) -> LayerType {
        etherNextLayerType(for: etherType)
    }
}

extension Ethernet {
    /// Decodes an Ethernet frame into a concrete value plus what to decode
    /// next, without boxing — the ``StackDecoder`` fast path. ``EthernetDecoder``
    /// wraps this for the general (boxed) decode chain.
    static func decodeValue(_ data: Data) throws -> (Ethernet, NextDecode) {
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
            return (layer, .done)
        }
        let next: LayerType =
            etherType.rawValue < 1536 ? .llc : EthernetDecoder.nextLayerType(for: etherType)
        return (layer, .next(next, payload))
    }
}
