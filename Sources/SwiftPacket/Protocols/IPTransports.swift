import Foundation

// MARK: - IGMP

/// An IGMP message (RFC 2236 / RFC 3376). The v1/v2 fixed fields are decoded
/// for every message; v3 membership reports additionally expose their group
/// records.
public struct IGMP: Layer {
    public static let layerType = LayerType.igmp

    /// 0x11 query, 0x12 v1 report, 0x16 v2 report, 0x17 leave, 0x22 v3 report.
    public let type: UInt8
    /// Max response time in 1/10 s (v2 semantics; reserved in v1).
    public let maxResponseTime: UInt8
    public let checksum: UInt16
    /// The group address for v1/v2 messages (zero for general queries).
    public let groupAddress: IPv4Address?
    /// Group records of a v3 membership report: (recordType, multicast group).
    public let groupRecords: [IGMPGroupRecord]

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    public var typeName: String {
        switch type {
        case 0x11: return "MembershipQuery"
        case 0x12: return "V1MembershipReport"
        case 0x16: return "V2MembershipReport"
        case 0x17: return "LeaveGroup"
        case 0x22: return "V3MembershipReport"
        default: return "type-\(type)"
        }
    }
}

/// One group record of an IGMPv3 membership report.
public struct IGMPGroupRecord: Sendable, Hashable {
    /// 1 = include, 2 = exclude, 3/4 = change-to, 5/6 = allow/block sources.
    public let recordType: UInt8
    public let multicastAddress: IPv4Address
    public let sourceAddresses: [IPv4Address]
}

/// Decodes IGMP v1/v2 messages and v3 membership reports.
public struct IGMPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let type = try reader.readUInt8()
        let maxResponseTime = try reader.readUInt8()
        let checksum = try reader.readUInt16()

        var groupAddress: IPv4Address?
        var groupRecords: [IGMPGroupRecord] = []

        if type == 0x22 {
            try reader.skip(2)  // reserved
            let recordCount = Int(try reader.readUInt16())
            for _ in 0..<recordCount {
                let recordType = try reader.readUInt8()
                let auxLength = Int(try reader.readUInt8())
                let sourceCount = Int(try reader.readUInt16())
                let multicast = try reader.readIPv4Address()
                var sources: [IPv4Address] = []
                for _ in 0..<sourceCount {
                    sources.append(try reader.readIPv4Address())
                }
                try reader.skip(auxLength * 4)
                groupRecords.append(
                    IGMPGroupRecord(
                        recordType: recordType,
                        multicastAddress: multicast,
                        sourceAddresses: sources
                    ))
            }
        } else {
            groupAddress = try reader.readIPv4Address()
        }

        let layer = IGMP(
            type: type,
            maxResponseTime: maxResponseTime,
            checksum: checksum,
            groupAddress: groupAddress,
            groupRecords: groupRecords,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }
}

// MARK: - IPsec

/// An IPsec ESP header (RFC 4303). Everything past SPI and sequence number is
/// encrypted, so this layer is terminal.
public struct ESP: Layer {
    public static let layerType = LayerType.esp

    /// The security parameters index identifying the SA.
    public let spi: UInt32
    public let sequenceNumber: UInt32
    /// The encrypted remainder (payload, padding, ICV).
    public let encrypted: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { encrypted }
}

/// Decodes the 8-byte cleartext prefix of an ESP packet.
public struct ESPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let spi = try reader.readUInt32()
        let sequenceNumber = try reader.readUInt32()
        let encrypted = reader.readRemaining()

        let layer = ESP(
            spi: spi,
            sequenceNumber: sequenceNumber,
            encrypted: encrypted,
            header: data.prefix(8)
        )
        return DecodeResult(layer: layer, next: .done)
    }
}

/// An IPsec Authentication Header (RFC 4302). Unlike ESP, AH does not encrypt,
/// so decoding continues into the protected payload.
public struct AH: Layer {
    public static let layerType = LayerType.ah

    /// The protocol of the protected payload.
    public let nextHeader: IPProtocol
    public let spi: UInt32
    public let sequenceNumber: UInt32
    /// The integrity check value.
    public let icv: Data
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes an AH header and chains to the protected protocol.
public struct AHDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let nextHeader = IPProtocol(rawValue: try reader.readUInt8())
        // Payload length: AH length in 4-byte words, minus 2.
        let payloadLength = Int(try reader.readUInt8())
        try reader.skip(2)  // reserved
        let spi = try reader.readUInt32()
        let sequenceNumber = try reader.readUInt32()

        let headerLength = (payloadLength + 2) * 4
        let icvLength = headerLength - 12
        guard icvLength >= 0 else {
            throw DecodingError.malformed("AH header length underflow")
        }
        let icv = try reader.readBytes(icvLength)

        let payload = reader.readRemaining()
        let layer = AH(
            nextHeader: nextHeader,
            spi: spi,
            sequenceNumber: sequenceNumber,
            icv: icv,
            payload: payload,
            header: data.prefix(headerLength)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        return DecodeResult(layer: layer, next: .next(ipNextLayerType(for: nextHeader), payload))
    }
}

// MARK: - SCTP

/// One SCTP chunk, with its raw value bytes.
public struct SCTPChunk: Sendable, Hashable {
    /// 0 = DATA, 1 = INIT, 2 = INIT-ACK, 3 = SACK, 4 = HEARTBEAT, …
    public let type: UInt8
    public let flags: UInt8
    /// The declared chunk length (unpadded), including the 4-byte chunk header.
    public let length: Int
    /// The chunk value (contents after the 4-byte chunk header).
    public let value: Data

    public var typeName: String {
        switch type {
        case 0: return "DATA"
        case 1: return "INIT"
        case 2: return "INIT-ACK"
        case 3: return "SACK"
        case 4: return "HEARTBEAT"
        case 5: return "HEARTBEAT-ACK"
        case 6: return "ABORT"
        case 7: return "SHUTDOWN"
        case 8: return "SHUTDOWN-ACK"
        case 9: return "ERROR"
        case 10: return "COOKIE-ECHO"
        case 11: return "COOKIE-ACK"
        case 14: return "SHUTDOWN-COMPLETE"
        default: return "type-\(type)"
        }
    }
}

/// An SCTP common header plus its chunk list (RFC 9260).
public struct SCTP: Layer {
    public static let layerType = LayerType.sctp

    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let verificationTag: UInt32
    public let checksum: UInt32
    public let chunks: [SCTPChunk]

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }
}

/// Decodes the SCTP common header and walks the chunk list. A truncated final
/// chunk is kept with the bytes that are present.
public struct SCTPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let sourcePort = try reader.readUInt16()
        let destinationPort = try reader.readUInt16()
        let verificationTag = try reader.readUInt32()
        let checksum = try reader.readUInt32()

        var chunks: [SCTPChunk] = []
        while reader.remaining >= 4 {
            let type = try reader.readUInt8()
            let flags = try reader.readUInt8()
            let length = Int(try reader.readUInt16())
            guard length >= 4 else {
                throw DecodingError.malformed("SCTP chunk length < 4")
            }
            let valueLength = min(length - 4, reader.remaining)
            let value = try reader.readBytes(valueLength)
            chunks.append(SCTPChunk(type: type, flags: flags, length: length, value: value))
            // Chunks are padded to 4-byte boundaries.
            let padding = (4 - length % 4) % 4
            try reader.skip(min(padding, reader.remaining))
        }

        let layer = SCTP(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            verificationTag: verificationTag,
            checksum: checksum,
            chunks: chunks,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }
}

// MARK: - UDP-Lite

/// A UDP-Lite header (RFC 3828): UDP with a checksum-coverage field where
/// UDP's length field sits.
public struct UDPLite: Layer {
    public static let layerType = LayerType.udpLite

    public let sourcePort: UInt16
    public let destinationPort: UInt16
    /// How many leading bytes the checksum covers (0 = the whole datagram).
    public let checksumCoverage: Int
    public let checksum: UInt16
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the 8-byte UDP-Lite header.
public struct UDPLiteDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let sourcePort = try reader.readUInt16()
        let destinationPort = try reader.readUInt16()
        let checksumCoverage = Int(try reader.readUInt16())
        let checksum = try reader.readUInt16()

        let payload = reader.readRemaining()
        let layer = UDPLite(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            checksumCoverage: checksumCoverage,
            checksum: checksum,
            payload: payload,
            header: data.prefix(8)
        )
        return DecodeResult(
            layer: layer, next: payload.isEmpty ? .done : .next(.payload, payload))
    }
}

// MARK: - VRRP

/// A VRRPv2 advertisement (RFC 3768); v3 (RFC 5798) shares the layout with a
/// centiseconds interval and no authentication fields.
public struct VRRP: Layer {
    public static let layerType = LayerType.vrrp

    public let version: UInt8
    /// 1 = advertisement (the only defined type).
    public let type: UInt8
    /// Virtual router identifier.
    public let virtualRouterID: UInt8
    public let priority: UInt8
    /// The advertisement interval, in seconds (v2) or centiseconds (v3).
    public let advertisementInterval: UInt16
    public let checksum: UInt16
    /// The virtual router's IPv4 addresses.
    public let addresses: [IPv4Address]

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }
}

/// Decodes VRRP v2/v3 advertisements (over IPv4).
public struct VRRPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let versionType = try reader.readUInt8()
        let version = versionType >> 4
        let virtualRouterID = try reader.readUInt8()
        let priority = try reader.readUInt8()
        let addressCount = Int(try reader.readUInt8())

        let advertisementInterval: UInt16
        if version >= 3 {
            // v3: 4 bits reserved, 12 bits max-advertisement-interval.
            advertisementInterval = try reader.readUInt16() & 0x0FFF
        } else {
            // v2: auth type byte, then a 1-byte interval.
            try reader.skip(1)
            advertisementInterval = UInt16(try reader.readUInt8())
        }
        let checksum = try reader.readUInt16()

        var addresses: [IPv4Address] = []
        for _ in 0..<min(addressCount, 64) {
            addresses.append(try reader.readIPv4Address())
        }

        let layer = VRRP(
            version: version,
            type: versionType & 0x0F,
            virtualRouterID: virtualRouterID,
            priority: priority,
            advertisementInterval: advertisementInterval,
            checksum: checksum,
            addresses: addresses,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }
}
