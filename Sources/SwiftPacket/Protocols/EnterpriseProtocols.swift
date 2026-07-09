import Foundation

// MARK: - CDP (Cisco Discovery Protocol)

/// One CDP TLV (type/length-prefixed value).
public struct CDPTLV: Sendable, Hashable {
    public let type: UInt16
    public let value: Data

    /// The value as UTF-8 text (device id, port id, version, platform, …).
    public var text: String { String(decoding: value, as: UTF8.self) }
}

/// A Cisco Discovery Protocol advertisement (carried in LLC/SNAP, OUI
/// `00:00:0c`, protocol `0x2000`).
public struct CDP: Layer {
    public static let layerType = LayerType.cdp

    public let version: UInt8
    /// Time-to-live in seconds.
    public let ttl: UInt8
    public let checksum: UInt16
    public let tlvs: [CDPTLV]

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    /// The first TLV of the given type.
    public func tlv(_ type: UInt16) -> Data? { tlvs.first { $0.type == type }?.value }

    /// The advertised device identifier (TLV 1).
    public var deviceID: String? { tlv(1).map { String(decoding: $0, as: UTF8.self) } }
    /// The sending port identifier (TLV 3).
    public var portID: String? { tlv(3).map { String(decoding: $0, as: UTF8.self) } }
    /// The software version string (TLV 5).
    public var softwareVersion: String? { tlv(5).map { String(decoding: $0, as: UTF8.self) } }
    /// The platform string (TLV 6).
    public var platform: String? { tlv(6).map { String(decoding: $0, as: UTF8.self) } }
}

/// Decodes a CDP advertisement: a 4-byte header then type(2)/length(2) TLVs.
public struct CDPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let version = try reader.readUInt8()
        let ttl = try reader.readUInt8()
        let checksum = try reader.readUInt16()

        var tlvs: [CDPTLV] = []
        while reader.remaining >= 4 {
            guard let type = try? reader.readUInt16(), let length = try? reader.readUInt16(),
                length >= 4
            else { break }
            // The TLV length counts its own 4-byte header.
            guard let value = try? reader.readBytes(Int(length) - 4) else { break }
            tlvs.append(CDPTLV(type: type, value: value))
        }
        guard !tlvs.isEmpty else { throw DecodingError.malformed("CDP with no TLVs") }

        let layer = CDP(version: version, ttl: ttl, checksum: checksum, tlvs: tlvs, bytes: data)
        return DecodeResult(layer: layer, next: .done)
    }
}

// MARK: - EAP (Extensible Authentication Protocol)

/// An EAP message (RFC 3748), carried inside an EAPOL EAP-Packet.
public struct EAP: Layer {
    public static let layerType = LayerType.eap

    /// 1 request, 2 response, 3 success, 4 failure.
    public let code: UInt8
    public let identifier: UInt8
    public let length: UInt16
    /// The method type, for request/response messages (1 Identity, 4 MD5,
    /// 13 TLS, 25 PEAP, …); `nil` for success/failure.
    public let methodType: UInt8?
    public let typeData: Data

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    public var codeName: String {
        switch code {
        case 1: return "Request"
        case 2: return "Response"
        case 3: return "Success"
        case 4: return "Failure"
        default: return "code-\(code)"
        }
    }

    /// The identity string, for an Identity request/response (method type 1).
    public var identity: String? {
        guard methodType == 1 else { return nil }
        return String(decoding: typeData, as: UTF8.self)
    }
}

/// Decodes an EAP message: code(1), id(1), length(2), and — for request and
/// response codes — a method type byte plus its data.
public struct EAPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let code = try reader.readUInt8()
        let identifier = try reader.readUInt8()
        let length = try reader.readUInt16()

        var methodType: UInt8?
        var typeData = Data()
        if code == 1 || code == 2 {  // request / response carry a method
            methodType = try? reader.readUInt8()
            typeData = reader.readRemaining()
        }
        let layer = EAP(
            code: code, identifier: identifier, length: length, methodType: methodType,
            typeData: typeData, bytes: data)
        return DecodeResult(layer: layer, next: .done)
    }
}

// MARK: - OSPFv2

/// An OSPFv2 packet (RFC 2328): the common 24-byte header plus, for Hello
/// packets, the decoded Hello body.
public struct OSPF: Layer {
    public static let layerType = LayerType.ospf

    public let version: UInt8
    /// 1 Hello, 2 Database Description, 3 Link State Request, 4 Link State
    /// Update, 5 Link State Acknowledgment.
    public let messageType: UInt8
    public let packetLength: UInt16
    public let routerID: IPv4Address
    public let areaID: IPv4Address
    public let checksum: UInt16
    public let authType: UInt16
    /// The decoded Hello body, when ``messageType`` is 1.
    public let hello: OSPFHello?

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    public var messageTypeName: String {
        switch messageType {
        case 1: return "Hello"
        case 2: return "DatabaseDescription"
        case 3: return "LinkStateRequest"
        case 4: return "LinkStateUpdate"
        case 5: return "LinkStateAcknowledgment"
        default: return "type-\(messageType)"
        }
    }
}

/// The body of an OSPFv2 Hello packet.
public struct OSPFHello: Sendable {
    public let networkMask: IPv4Address
    public let helloInterval: UInt16
    public let routerPriority: UInt8
    public let routerDeadInterval: UInt32
    public let designatedRouter: IPv4Address
    public let backupDesignatedRouter: IPv4Address
    /// The neighbors this router has heard from.
    public let neighbors: [IPv4Address]
}

/// Decodes an OSPFv2 packet's common header, and the Hello body for type 1.
public struct OSPFDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let version = try reader.readUInt8()
        guard version == 2 else {
            // OSPFv3 (version 3) has a different header; not decoded here.
            throw DecodingError.invalidValue(field: "OSPF version", value: UInt64(version))
        }
        let messageType = try reader.readUInt8()
        let packetLength = try reader.readUInt16()
        let routerID = try reader.readIPv4Address()
        let areaID = try reader.readIPv4Address()
        let checksum = try reader.readUInt16()
        let authType = try reader.readUInt16()
        try reader.skip(8)  // authentication data

        var hello: OSPFHello?
        if messageType == 1 {
            hello = Self.parseHello(&reader)
        }

        let layer = OSPF(
            version: version, messageType: messageType, packetLength: packetLength,
            routerID: routerID, areaID: areaID, checksum: checksum, authType: authType,
            hello: hello, bytes: data)
        return DecodeResult(layer: layer, next: .done)
    }

    private static func parseHello(_ reader: inout ByteReader) -> OSPFHello? {
        guard let mask = try? reader.readIPv4Address(),
            let interval = try? reader.readUInt16(),
            (try? reader.skip(1)) != nil,  // options
            let priority = try? reader.readUInt8(),
            let dead = try? reader.readUInt32(),
            let designated = try? reader.readIPv4Address(),
            let backup = try? reader.readIPv4Address()
        else { return nil }

        var neighbors: [IPv4Address] = []
        while reader.remaining >= 4 {
            guard let neighbor = try? reader.readIPv4Address() else { break }
            neighbors.append(neighbor)
        }
        return OSPFHello(
            networkMask: mask, helloInterval: interval, routerPriority: priority,
            routerDeadInterval: dead, designatedRouter: designated,
            backupDesignatedRouter: backup, neighbors: neighbors)
    }
}
