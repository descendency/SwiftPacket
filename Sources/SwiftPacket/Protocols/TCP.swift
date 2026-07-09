import Foundation

/// A TCP segment header (RFC 9293).
public struct TCP: Layer {
    public static let layerType = LayerType.tcp

    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let sequenceNumber: UInt32
    public let acknowledgmentNumber: UInt32
    /// Header length in bytes (data offset × 4).
    public let headerLength: Int
    public let window: UInt16
    public let checksum: UInt16
    public let urgentPointer: UInt16
    public let options: Data
    public let payload: Data

    // Flags.
    public let ns: Bool
    public let cwr: Bool
    public let ece: Bool
    public let urg: Bool
    public let ack: Bool
    public let psh: Bool
    public let rst: Bool
    public let syn: Bool
    public let fin: Bool

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes a TCP header. The payload is delivered as opaque ``Payload``; the
/// library does not infer an application protocol from TCP ports (DNS-over-TCP,
/// for instance, has its own framing). The one exception is TLS, whose records
/// are self-describing: a payload that begins with a well-formed record header
/// (see ``TLSDecoder/looksLikeTLSRecord(_:)``) decodes as ``TLS`` regardless
/// of port.
public struct TCPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        let (layer, next) = try TCP.decodeValue(data)
        return DecodeResult(layer: layer, next: next)
    }
}

extension TCP {
    /// Concrete, non-boxing decode for the ``StackDecoder`` fast path.
    static func decodeValue(_ data: Data) throws -> (TCP, NextDecode) {
        var reader = ByteReader(data)
        let sourcePort = try reader.readUInt16()
        let destinationPort = try reader.readUInt16()
        let sequence = try reader.readUInt32()
        let acknowledgment = try reader.readUInt32()
        let offsetAndFlags = try reader.readUInt16()
        let window = try reader.readUInt16()
        let checksum = try reader.readUInt16()
        let urgentPointer = try reader.readUInt16()

        let dataOffset = Int((offsetAndFlags >> 12) & 0x0F)
        guard dataOffset >= 5 else {
            throw DecodingError.malformed("TCP data offset < 5")
        }
        let headerLength = dataOffset * 4
        let optionsLength = headerLength - 20
        guard optionsLength >= 0 else {
            throw DecodingError.malformed("TCP header length underflow")
        }
        let options = optionsLength > 0 ? try reader.readBytes(optionsLength) : Data()
        let payload = reader.readRemaining()

        let layer = TCP(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            sequenceNumber: sequence,
            acknowledgmentNumber: acknowledgment,
            headerLength: headerLength,
            window: window,
            checksum: checksum,
            urgentPointer: urgentPointer,
            options: options,
            payload: payload,
            ns: offsetAndFlags & 0x0100 != 0,
            cwr: offsetAndFlags & 0x0080 != 0,
            ece: offsetAndFlags & 0x0040 != 0,
            urg: offsetAndFlags & 0x0020 != 0,
            ack: offsetAndFlags & 0x0010 != 0,
            psh: offsetAndFlags & 0x0008 != 0,
            rst: offsetAndFlags & 0x0004 != 0,
            syn: offsetAndFlags & 0x0002 != 0,
            fin: offsetAndFlags & 0x0001 != 0,
            header: data.prefix(headerLength)
        )

        if payload.isEmpty {
            return (layer, .done)
        }
        let next: LayerType = TLSDecoder.looksLikeTLSRecord(payload) ? .tls : .payload
        return (layer, .next(next, payload))
    }
}
