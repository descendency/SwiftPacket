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

/// Decodes a UDP header. Payloads on port 53 are routed to the DNS decoder;
/// everything else becomes opaque ``Payload``.
public struct UDPDecoder: LayerDecoder {
    public init() {}

    static let dnsPort: UInt16 = 53

    public func decode(_ data: Data) throws -> DecodeResult {
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
            return DecodeResult(layer: layer, next: .done)
        }
        let isDNS = sourcePort == Self.dnsPort || destinationPort == Self.dnsPort
        return DecodeResult(layer: layer, next: .next(isDNS ? .dns : .payload, payload))
    }
}
