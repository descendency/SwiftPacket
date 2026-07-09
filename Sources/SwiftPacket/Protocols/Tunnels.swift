import Foundation

/// A GRE header (RFC 2784, with the RFC 2890 key/sequence extensions and
/// legacy RFC 1701 routing flag).
public struct GRE: Layer {
    public static let layerType = LayerType.gre

    public let checksumPresent: Bool
    public let keyPresent: Bool
    public let sequencePresent: Bool
    public let version: UInt8
    /// The EtherType of the encapsulated protocol.
    public let protocolType: EtherType
    public let checksum: UInt16?
    public let key: UInt32?
    public let sequenceNumber: UInt32?
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes a GRE header and chains to the encapsulated protocol — IPv4/IPv6
/// tunnels, transparent Ethernet bridging, or ERSPAN.
public struct GREDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let flags = try reader.readUInt16()
        let protocolType = EtherType(rawValue: try reader.readUInt16())

        let checksumPresent = flags & 0x8000 != 0
        let routingPresent = flags & 0x4000 != 0  // legacy RFC 1701
        let keyPresent = flags & 0x2000 != 0
        let sequencePresent = flags & 0x1000 != 0

        var checksum: UInt16?
        if checksumPresent || routingPresent {
            checksum = try reader.readUInt16()
            try reader.skip(2)  // reserved offset field
        }
        let key = keyPresent ? try reader.readUInt32() : nil
        let sequenceNumber = sequencePresent ? try reader.readUInt32() : nil

        let headerLength = reader.bytesRead
        let payload = reader.readRemaining()
        let layer = GRE(
            checksumPresent: checksumPresent,
            keyPresent: keyPresent,
            sequencePresent: sequencePresent,
            version: UInt8(flags & 0x0007),
            protocolType: protocolType,
            checksum: checksum,
            key: key,
            sequenceNumber: sequenceNumber,
            payload: payload,
            header: data.prefix(headerLength)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        return DecodeResult(
            layer: layer, next: .next(etherNextLayerType(for: protocolType), payload))
    }
}

/// A VXLAN header (RFC 7348), carrying an inner Ethernet frame.
public struct VXLAN: Layer {
    public static let layerType = LayerType.vxlan

    /// Whether the VNI field is valid (the I flag).
    public let vniValid: Bool
    /// The 24-bit VXLAN network identifier.
    public let vni: UInt32
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the 8-byte VXLAN header and chains to the inner Ethernet frame.
public struct VXLANDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let flags = try reader.readUInt8()
        try reader.skip(3)  // reserved
        let vni = try reader.readUInt24()
        try reader.skip(1)  // reserved

        let payload = reader.readRemaining()
        let layer = VXLAN(
            vniValid: flags & 0x08 != 0,
            vni: vni,
            payload: payload,
            header: data.prefix(8)
        )
        return DecodeResult(
            layer: layer, next: payload.isEmpty ? .done : .next(.ethernet, payload))
    }
}

/// An EtherIP header (RFC 3378): Ethernet frames tunneled directly in IP
/// (protocol 97).
public struct EtherIP: Layer {
    public static let layerType = LayerType.etherIP

    public let version: UInt8
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the 2-byte EtherIP header and chains to the inner Ethernet frame.
public struct EtherIPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let versionByte = try reader.readUInt8()
        try reader.skip(1)  // reserved

        let payload = reader.readRemaining()
        let layer = EtherIP(
            version: versionByte >> 4,
            payload: payload,
            header: data.prefix(2)
        )
        return DecodeResult(
            layer: layer, next: payload.isEmpty ? .done : .next(.ethernet, payload))
    }
}

/// An ERSPAN Type II header (carried in GRE with protocol `0x88BE`) — Cisco's
/// remote SPAN mirroring encapsulation.
public struct ERSPAN: Layer {
    public static let layerType = LayerType.erspan

    public let version: UInt8
    /// The VLAN of the mirrored frame.
    public let vlan: UInt16
    /// Class of service.
    public let cos: UInt8
    /// The mirroring session id.
    public let sessionID: UInt16
    /// The port/index field.
    public let index: UInt32
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the 8-byte ERSPAN Type II header and chains to the mirrored
/// Ethernet frame.
public struct ERSPANDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let first = try reader.readUInt16()
        let second = try reader.readUInt16()
        let index = try reader.readUInt32()

        let payload = reader.readRemaining()
        let layer = ERSPAN(
            version: UInt8(first >> 12),
            vlan: first & 0x0FFF,
            cos: UInt8(second >> 13),
            sessionID: second & 0x03FF,
            index: index & 0x000F_FFFF,
            payload: payload,
            header: data.prefix(8)
        )
        return DecodeResult(
            layer: layer, next: payload.isEmpty ? .done : .next(.ethernet, payload))
    }
}
