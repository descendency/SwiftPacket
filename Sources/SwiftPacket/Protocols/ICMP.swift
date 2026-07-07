import Foundation

/// An ICMPv4 message header (RFC 792).
public struct ICMPv4: Layer {
    public static let layerType = LayerType.icmpv4

    public let type: UInt8
    public let code: UInt8
    public let checksum: UInt16
    /// The 4-byte "rest of header" whose meaning depends on ``type``.
    public let restOfHeader: UInt32
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }

    public var isEchoRequest: Bool { type == 8 }
    public var isEchoReply: Bool { type == 0 }
}

/// Decodes the fixed 8-byte ICMPv4 header.
public struct ICMPv4Decoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let type = try reader.readUInt8()
        let code = try reader.readUInt8()
        let checksum = try reader.readUInt16()
        let restOfHeader = try reader.readUInt32()
        let payload = reader.readRemaining()

        let layer = ICMPv4(
            type: type,
            code: code,
            checksum: checksum,
            restOfHeader: restOfHeader,
            payload: payload,
            header: data.prefix(8)
        )
        return DecodeResult(layer: layer, next: payload.isEmpty ? .done : .next(.payload, payload))
    }
}

/// An ICMPv6 message header (RFC 4443).
public struct ICMPv6: Layer {
    public static let layerType = LayerType.icmpv6

    public let type: UInt8
    public let code: UInt8
    public let checksum: UInt16
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the fixed 4-byte ICMPv6 header.
public struct ICMPv6Decoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let type = try reader.readUInt8()
        let code = try reader.readUInt8()
        let checksum = try reader.readUInt16()
        let payload = reader.readRemaining()

        let layer = ICMPv6(
            type: type,
            code: code,
            checksum: checksum,
            payload: payload,
            header: data.prefix(4)
        )
        return DecodeResult(layer: layer, next: payload.isEmpty ? .done : .next(.payload, payload))
    }
}
