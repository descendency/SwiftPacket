import Foundation

/// An IEEE 802.2 LLC header, with its SNAP extension when present.
public struct LLC: Layer {
    public static let layerType = LayerType.llc

    public let dsap: UInt8
    public let ssap: UInt8
    /// The control field: one byte for U-format frames (low two bits `11`),
    /// two bytes for I/S-format.
    public let control: UInt16
    /// The SNAP OUI, when DSAP/SSAP are `0xAA` (SNAP).
    public let oui: UInt32?
    /// The SNAP protocol id (an EtherType when ``oui`` is zero).
    public let snapType: EtherType?
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes an 802.2 LLC header. STP BPDUs (DSAP `0x42`) chain to the ``STP``
/// decoder; SNAP frames with a zero OUI chain by their EtherType; everything
/// else is opaque payload.
public struct LLCDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let dsap = try reader.readUInt8()
        let ssap = try reader.readUInt8()
        let firstControl = try reader.readUInt8()

        // U-format frames (low two control bits set) have a 1-byte control
        // field; I/S-format have 2 bytes.
        var control = UInt16(firstControl)
        var headerLength = 3
        if firstControl & 0x03 != 0x03 {
            control = control << 8 | UInt16(try reader.readUInt8())
            headerLength = 4
        }

        var oui: UInt32?
        var snapType: EtherType?
        if dsap == 0xAA, ssap == 0xAA {
            oui = try reader.readUInt24()
            snapType = EtherType(rawValue: try reader.readUInt16())
            headerLength += 5
        }

        let payload = reader.readRemaining()
        let layer = LLC(
            dsap: dsap,
            ssap: ssap,
            control: control,
            oui: oui,
            snapType: snapType,
            payload: payload,
            header: data.prefix(headerLength)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        let next: LayerType
        if dsap == 0x42, ssap == 0x42 {
            next = .stp
        } else if oui == 0, let snapType {
            next = etherNextLayerType(for: snapType)
        } else if oui == 0x00_000C, snapType?.rawValue == 0x2000 {
            next = .cdp  // Cisco SNAP OUI + CDP protocol id
        } else {
            next = .payload
        }
        return DecodeResult(layer: layer, next: .next(next, payload))
    }
}

/// A spanning-tree BPDU (IEEE 802.1D configuration format).
public struct STP: Layer {
    public static let layerType = LayerType.stp

    public let protocolID: UInt16
    public let version: UInt8
    /// 0 = configuration, 0x80 = topology change notification, 2 = RSTP.
    public let bpduType: UInt8
    public let flags: UInt8
    /// Root bridge identifier (priority + MAC), raw 8 bytes.
    public let rootID: Data
    public let rootPathCost: UInt32
    /// Sender bridge identifier, raw 8 bytes.
    public let bridgeID: Data
    public let portID: UInt16
    /// Timer values in 1/256ths of a second, as encoded.
    public let messageAge: UInt16
    public let maxAge: UInt16
    public let helloTime: UInt16
    public let forwardDelay: UInt16

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    /// The MAC address portion of ``rootID``.
    public var rootMAC: MACAddress? { MACAddress(rootID.suffix(6)) }
    /// The MAC address portion of ``bridgeID``.
    public var bridgeMAC: MACAddress? { MACAddress(bridgeID.suffix(6)) }
}

/// Decodes an 802.1D spanning-tree BPDU. Topology-change BPDUs stop after the
/// type field; configuration/RSTP BPDUs carry the full set of fields.
public struct STPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let protocolID = try reader.readUInt16()
        let version = try reader.readUInt8()
        let bpduType = try reader.readUInt8()

        var rootID = Data()
        var rootPathCost: UInt32 = 0
        var bridgeID = Data()
        var portID: UInt16 = 0
        var messageAge: UInt16 = 0
        var maxAge: UInt16 = 0
        var helloTime: UInt16 = 0
        var forwardDelay: UInt16 = 0

        // A topology-change-notification BPDU is just the 4-byte prelude.
        if bpduType != 0x80 {
            let flags = try reader.readUInt8()
            rootID = try reader.readBytes(8)
            rootPathCost = try reader.readUInt32()
            bridgeID = try reader.readBytes(8)
            portID = try reader.readUInt16()
            messageAge = try reader.readUInt16()
            maxAge = try reader.readUInt16()
            helloTime = try reader.readUInt16()
            forwardDelay = try reader.readUInt16()

            let layer = STP(
                protocolID: protocolID, version: version, bpduType: bpduType,
                flags: flags, rootID: rootID, rootPathCost: rootPathCost,
                bridgeID: bridgeID, portID: portID, messageAge: messageAge,
                maxAge: maxAge, helloTime: helloTime, forwardDelay: forwardDelay,
                bytes: data
            )
            return DecodeResult(layer: layer, next: .done)
        }

        let layer = STP(
            protocolID: protocolID, version: version, bpduType: bpduType,
            flags: 0, rootID: rootID, rootPathCost: rootPathCost,
            bridgeID: bridgeID, portID: portID, messageAge: messageAge,
            maxAge: maxAge, helloTime: helloTime, forwardDelay: forwardDelay,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }
}

/// One LLDP TLV, raw.
public struct LLDPTLV: Sendable, Hashable {
    public let type: UInt8
    public let value: Data
}

/// An LLDP frame (IEEE 802.1AB): the raw TLV list plus the common fields
/// decoded.
public struct LLDP: Layer {
    public static let layerType = LayerType.lldp

    /// All TLVs in order, ending before (not including) the end-of-LLDPDU TLV.
    public let tlvs: [LLDPTLV]

    /// Chassis identifier (TLV 1), rendered per its subtype — MAC addresses as
    /// `aa:bb:…`, everything else as UTF-8 text.
    public let chassisID: String?
    /// Port identifier (TLV 2), rendered like ``chassisID``.
    public let portID: String?
    /// Time-to-live seconds (TLV 3).
    public let ttl: UInt16?
    public let portDescription: String?
    public let systemName: String?
    public let systemDescription: String?

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }
}

/// Decodes LLDP TLVs (2-byte header: 7-bit type, 9-bit length).
public struct LLDPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        var tlvs: [LLDPTLV] = []
        var chassisID: String?
        var portID: String?
        var ttl: UInt16?
        var portDescription: String?
        var systemName: String?
        var systemDescription: String?

        while reader.remaining >= 2 {
            let header = try reader.readUInt16()
            let type = UInt8(header >> 9)
            let length = Int(header & 0x01FF)
            if type == 0 { break }  // end of LLDPDU
            let value = try reader.readBytes(length)
            tlvs.append(LLDPTLV(type: type, value: value))

            switch type {
            case 1: chassisID = Self.identifier(value)
            case 2: portID = Self.identifier(value)
            case 3:
                var field = ByteReader(value)
                ttl = try? field.readUInt16()
            case 4: portDescription = String(decoding: value, as: UTF8.self)
            case 5: systemName = String(decoding: value, as: UTF8.self)
            case 6: systemDescription = String(decoding: value, as: UTF8.self)
            default: break
            }
        }
        guard !tlvs.isEmpty else {
            throw DecodingError.malformed("LLDP frame with no TLVs")
        }

        let layer = LLDP(
            tlvs: tlvs,
            chassisID: chassisID,
            portID: portID,
            ttl: ttl,
            portDescription: portDescription,
            systemName: systemName,
            systemDescription: systemDescription,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }

    /// Chassis/port id TLVs: subtype byte, then a value whose rendering
    /// depends on it. Subtype 4 (chassis) / 3 (port) are MAC addresses; the
    /// rest are effectively text.
    private static func identifier(_ value: Data) -> String? {
        guard let subtype = value.first else { return nil }
        let body = value.dropFirst()
        if (subtype == 4 || subtype == 3), let mac = MACAddress(body) {
            return mac.description
        }
        return String(decoding: body, as: UTF8.self)
    }
}

/// An EAPOL (802.1X) packet header.
public struct EAPOL: Layer {
    public static let layerType = LayerType.eapol

    public let version: UInt8
    /// 0 = EAP-Packet, 1 = Start, 2 = Logoff, 3 = Key, 4 = Encapsulated-ASF-Alert.
    public let packetType: UInt8
    public let length: Int
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }

    public var typeName: String {
        switch packetType {
        case 0: return "EAP-Packet"
        case 1: return "Start"
        case 2: return "Logoff"
        case 3: return "Key"
        case 4: return "Encapsulated-ASF-Alert"
        default: return "type-\(packetType)"
        }
    }
}

/// Decodes the 4-byte EAPOL header; the body (EAP or key descriptor) is
/// delivered as opaque payload.
public struct EAPOLDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let version = try reader.readUInt8()
        let packetType = try reader.readUInt8()
        let length = Int(try reader.readUInt16())
        let body = reader.readRemaining().prefix(length)

        let layer = EAPOL(
            version: version,
            packetType: packetType,
            length: length,
            payload: body,
            header: data.prefix(4)
        )
        // An EAP-Packet (type 0) carries an EAP message; other EAPOL types
        // (Start/Logoff/Key) carry opaque bodies.
        let next: LayerType = packetType == 0 ? .eap : .payload
        return DecodeResult(
            layer: layer, next: body.isEmpty ? .done : .next(next, body))
    }
}
