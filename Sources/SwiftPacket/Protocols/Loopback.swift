import Foundation

/// A BSD loopback / null encapsulation header: a 4-byte address family.
public struct Loopback: Layer {
    public static let layerType = LayerType.loopback

    /// The address family value (e.g. `AF_INET` = 2).
    public let family: UInt32
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the 4-byte BSD loopback header.
///
/// `DLT_NULL` stores the family in host byte order and `DLT_LOOP` in network
/// order; rather than depend on which we're given, this reads both
/// interpretations and prefers whichever is a recognized address family.
public struct LoopbackDecoder: LayerDecoder {
    public init() {}

    // Address families that mean "IPv6" across the BSDs, macOS, and Linux.
    private static let ipv6Families: Set<UInt32> = [30, 28, 24, 10, 23]

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let networkOrder = try reader.readUInt32()
        let hostOrder = networkOrder.byteSwapped

        let family: UInt32
        if Self.isRecognized(hostOrder) {
            family = hostOrder
        } else if Self.isRecognized(networkOrder) {
            family = networkOrder
        } else {
            family = hostOrder  // best effort; likely maps to Payload below
        }

        let payload = reader.readRemaining()
        let layer = Loopback(family: family, payload: payload, header: data.prefix(4))

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        return DecodeResult(layer: layer, next: .next(Self.nextLayerType(for: family), payload))
    }

    private static func isRecognized(_ family: UInt32) -> Bool {
        family == 2 || ipv6Families.contains(family)
    }

    static func nextLayerType(for family: UInt32) -> LayerType {
        if family == 2 { return .ipv4 }
        if ipv6Families.contains(family) { return .ipv6 }
        return .payload
    }
}
