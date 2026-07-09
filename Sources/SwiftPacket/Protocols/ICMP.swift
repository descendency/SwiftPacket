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

    public var isDestinationUnreachable: Bool { type == 3 }
    public var isRedirect: Bool { type == 5 }
    public var isTimeExceeded: Bool { type == 11 }
    public var isParameterProblem: Bool { type == 12 }

    /// Whether this is an error message that quotes the packet that caused it
    /// (destination unreachable, source quench, redirect, time exceeded, or
    /// parameter problem — RFC 792).
    public var isError: Bool {
        type == 3 || type == 4 || type == 5 || type == 11 || type == 12
    }

    /// The echo identifier, for echo request/reply messages.
    public var identifier: UInt16? {
        guard isEchoRequest || isEchoReply else { return nil }
        return UInt16(restOfHeader >> 16)
    }

    /// The echo sequence number, for echo request/reply messages.
    public var sequenceNumber: UInt16? {
        guard isEchoRequest || isEchoReply else { return nil }
        return UInt16(restOfHeader & 0xFFFF)
    }

    /// The next-hop MTU, for "fragmentation needed" (type 3, code 4) messages.
    public var nextHopMTU: UInt16? {
        guard type == 3, code == 4 else { return nil }
        return UInt16(restOfHeader & 0xFFFF)
    }

    /// A conventional name for the message type, e.g. `"EchoRequest"` or
    /// `"DestinationUnreachable"`; unrecognized types render as `"type-N"`.
    public var typeName: String { icmpv4TypeName(type) }

    // MARK: - Quoted packet

    /// The bytes of the original packet quoted by an error message (the
    /// embedded IPv4 header plus at least eight bytes of its payload), or `nil`
    /// for non-error messages.
    public var quotedData: Data? { isError ? payload : nil }

    /// Decodes the packet quoted by an error message.
    ///
    /// Quotes are usually truncated (RFC 792 requires only the IP header plus
    /// eight bytes), so the result may end in a ``DecodeFailure`` for
    /// protocols whose full header did not fit — the IP layer, and for
    /// TCP/UDP the ports via ``quotedFlow``, remain accessible regardless.
    public func quotedPacket(using registry: DecoderRegistry) -> Packet? {
        guard let quoted = quotedData, !quoted.isEmpty else { return nil }
        return Packet.decode(quoted, startingAt: .ipv4, using: registry)
    }

    /// The 5-tuple of the quoted packet, parsed leniently so it works even
    /// with the RFC-minimum quote, where a full TCP decode would fail on
    /// truncation. Ports are `nil` for protocols that carry none in their
    /// first four bytes (everything but TCP/UDP/SCTP/UDP-Lite).
    public var quotedFlow: ICMPv4QuotedFlow? {
        guard let quoted = quotedData else { return nil }
        return ICMPv4QuotedFlow(quoted)
    }
}

/// The 5-tuple of the original IPv4 packet quoted inside an ICMPv4 error
/// message — the flow the error is *about*, used to correlate unreachables
/// and time-exceededs back to the connection that triggered them.
public struct ICMPv4QuotedFlow: Sendable, Hashable {
    public let source: IPv4Address
    public let destination: IPv4Address
    public let proto: IPProtocol
    public let sourcePort: UInt16?
    public let destinationPort: UInt16?

    init?(_ quoted: Data) {
        var reader = ByteReader(quoted)
        guard
            let versionIHL = try? reader.readUInt8(),
            versionIHL >> 4 == 4
        else { return nil }
        let headerLength = Int(versionIHL & 0x0F) * 4
        guard headerLength >= 20 else { return nil }

        guard
            (try? reader.skip(8)) != nil,
            let protoRaw = try? reader.readUInt8(),
            (try? reader.skip(2)) != nil,  // header checksum
            let source = try? reader.readIPv4Address(),
            let destination = try? reader.readIPv4Address()
        else { return nil }

        self.source = source
        self.destination = destination
        self.proto = IPProtocol(rawValue: protoRaw)

        // Ports live in the first four bytes past the IP header for the
        // port-bearing transports.
        var ports: (UInt16, UInt16)?
        if [.tcp, .udp, .sctp, .udpLite].contains(proto),
            (try? reader.skip(headerLength - 20)) != nil,
            let src = try? reader.readUInt16(),
            let dst = try? reader.readUInt16()
        {
            ports = (src, dst)
        }
        self.sourcePort = ports?.0
        self.destinationPort = ports?.1
    }
}

private func icmpv4TypeName(_ type: UInt8) -> String {
    switch type {
    case 0: return "EchoReply"
    case 3: return "DestinationUnreachable"
    case 4: return "SourceQuench"
    case 5: return "Redirect"
    case 8: return "EchoRequest"
    case 9: return "RouterAdvertisement"
    case 10: return "RouterSolicitation"
    case 11: return "TimeExceeded"
    case 12: return "ParameterProblem"
    case 13: return "Timestamp"
    case 14: return "TimestampReply"
    case 17: return "AddressMaskRequest"
    case 18: return "AddressMaskReply"
    default: return "type-\(type)"
    }
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

    public var isEchoRequest: Bool { type == 128 }
    public var isEchoReply: Bool { type == 129 }

    /// Whether this is an error message that quotes the packet that caused it.
    /// In ICMPv6 the type space is split down the middle: types below 128 are
    /// errors, 128 and above are informational (RFC 4443 §2.1).
    public var isError: Bool { type < 128 }

    /// The echo identifier, for echo request/reply messages. Unlike ICMPv4,
    /// ICMPv6 carries it in the message body (the first four bytes of
    /// ``payload``), not the header.
    public var identifier: UInt16? {
        guard isEchoRequest || isEchoReply else { return nil }
        var reader = ByteReader(payload)
        return try? reader.readUInt16()
    }

    /// The echo sequence number, for echo request/reply messages.
    public var sequenceNumber: UInt16? {
        guard isEchoRequest || isEchoReply else { return nil }
        var reader = ByteReader(payload)
        guard (try? reader.skip(2)) != nil else { return nil }
        return try? reader.readUInt16()
    }

    /// The MTU reported by a "packet too big" (type 2) message.
    public var mtu: UInt32? {
        guard type == 2 else { return nil }
        var reader = ByteReader(payload)
        return try? reader.readUInt32()
    }

    /// A conventional name for the message type, e.g. `"EchoRequest"` or
    /// `"NeighborSolicitation"`; unrecognized types render as `"type-N"`.
    public var typeName: String { icmpv6TypeName(type) }

    // MARK: - Quoted packet

    /// The bytes of the original packet quoted by an error message. Error
    /// message bodies start with a four-byte type-specific field (unused
    /// bits, the MTU, or a pointer), followed by as much of the invoking
    /// packet as fit (RFC 4443).
    public var quotedData: Data? {
        guard isError, payload.count > 4 else { return nil }
        return payload.dropFirst(4)
    }

    /// Decodes the packet quoted by an error message. As with ICMPv4, quotes
    /// may be truncated; earlier layers survive a truncated tail.
    public func quotedPacket(using registry: DecoderRegistry) -> Packet? {
        guard let quoted = quotedData else { return nil }
        return Packet.decode(quoted, startingAt: .ipv6, using: registry)
    }

    /// The 5-tuple of the quoted packet, parsed leniently (see
    /// ``ICMPv4/quotedFlow``). Ports are read only when the quoted packet's
    /// next header is directly a port-bearing transport — a quote whose ports
    /// hide behind IPv6 extension headers yields `nil` ports.
    public var quotedFlow: ICMPv6QuotedFlow? {
        guard let quoted = quotedData else { return nil }
        return ICMPv6QuotedFlow(quoted)
    }
}

/// The 5-tuple of the original IPv6 packet quoted inside an ICMPv6 error
/// message. See ``ICMPv4QuotedFlow``.
public struct ICMPv6QuotedFlow: Sendable, Hashable {
    public let source: IPv6Address
    public let destination: IPv6Address
    public let proto: IPProtocol
    public let sourcePort: UInt16?
    public let destinationPort: UInt16?

    init?(_ quoted: Data) {
        var reader = ByteReader(quoted)
        guard
            let first = try? reader.peekUInt8(),
            first >> 4 == 6,
            (try? reader.skip(6)) != nil,
            let nextHeader = try? reader.readUInt8(),
            (try? reader.skip(1)) != nil,  // hop limit
            let source = try? reader.readIPv6Address(),
            let destination = try? reader.readIPv6Address()
        else { return nil }

        self.source = source
        self.destination = destination
        self.proto = IPProtocol(rawValue: nextHeader)

        var ports: (UInt16, UInt16)?
        if [.tcp, .udp, .sctp, .udpLite].contains(proto),
            let src = try? reader.readUInt16(),
            let dst = try? reader.readUInt16()
        {
            ports = (src, dst)
        }
        self.sourcePort = ports?.0
        self.destinationPort = ports?.1
    }
}

private func icmpv6TypeName(_ type: UInt8) -> String {
    switch type {
    case 1: return "DestinationUnreachable"
    case 2: return "PacketTooBig"
    case 3: return "TimeExceeded"
    case 4: return "ParameterProblem"
    case 128: return "EchoRequest"
    case 129: return "EchoReply"
    case 130: return "MulticastListenerQuery"
    case 131: return "MulticastListenerReport"
    case 132: return "MulticastListenerDone"
    case 133: return "RouterSolicitation"
    case 134: return "RouterAdvertisement"
    case 135: return "NeighborSolicitation"
    case 136: return "NeighborAdvertisement"
    case 137: return "Redirect"
    default: return "type-\(type)"
    }
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
