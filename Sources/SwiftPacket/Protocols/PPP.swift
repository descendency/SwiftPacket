import Foundation

/// A PPPoE header (RFC 2516). Session-stage packets chain to ``PPP``;
/// discovery-stage packets (PADI/PADO/…) carry opaque tag payloads.
public struct PPPoE: Layer {
    public static let layerType = LayerType.pppoe

    public let version: UInt8
    public let type: UInt8
    /// 0 for session data; PADI/PADO/PADR/PADS/PADT codes during discovery.
    public let code: UInt8
    public let sessionID: UInt16
    public let length: Int
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }

    public var isSessionData: Bool { code == 0 }
}

/// Decodes the 6-byte PPPoE header.
public struct PPPoEDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let versionType = try reader.readUInt8()
        let code = try reader.readUInt8()
        let sessionID = try reader.readUInt16()
        let length = Int(try reader.readUInt16())

        let base = data.startIndex
        let end = min(base + 6 + length, data.endIndex)
        let payload = data[(base + 6)..<max(base + 6, end)]

        let layer = PPPoE(
            version: versionType >> 4,
            type: versionType & 0x0F,
            code: code,
            sessionID: sessionID,
            length: length,
            payload: payload,
            header: data.prefix(6)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        return DecodeResult(
            layer: layer, next: .next(layer.isSessionData ? .ppp : .payload, payload))
    }
}

/// A PPP frame (RFC 1661), as carried in PPPoE sessions or over serial links.
public struct PPP: Layer {
    public static let layerType = LayerType.ppp

    /// The PPP protocol number (`0x0021` IPv4, `0x0057` IPv6, `0xC021` LCP, …).
    public let protocolNumber: UInt16
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes a PPP header: the optional `FF 03` address/control prefix (HDLC
/// framing), then a 1- or 2-byte protocol number (protocol field compression
/// leaves the low bit set in a 1-byte number).
public struct PPPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)

        if try reader.peekUInt8() == 0xFF {
            try reader.skip(2)  // HDLC address/control
        }
        let first = try reader.readUInt8()
        // An odd first byte is a compressed 1-byte protocol number.
        let protocolNumber: UInt16
        if first & 0x01 != 0 {
            protocolNumber = UInt16(first)
        } else {
            protocolNumber = UInt16(first) << 8 | UInt16(try reader.readUInt8())
        }

        let headerLength = reader.bytesRead
        let payload = reader.readRemaining()
        let layer = PPP(
            protocolNumber: protocolNumber,
            payload: payload,
            header: data.prefix(headerLength)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        let next: LayerType
        switch protocolNumber {
        case 0x0021: next = .ipv4
        case 0x0057: next = .ipv6
        case 0x0281: next = .mpls
        default: next = .payload
        }
        return DecodeResult(layer: layer, next: .next(next, payload))
    }
}
