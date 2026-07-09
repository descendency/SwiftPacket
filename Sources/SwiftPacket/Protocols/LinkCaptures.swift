import Foundation

/// A Linux "cooked" capture header (`DLT_LINUX_SLL`, 16 bytes) — what
/// `tcpdump -i any` writes on Linux. Reading such files on macOS is exactly
/// why SwiftPacket decodes it.
public struct LinuxSLL: Layer {
    public static let layerType = LayerType.linuxSLL

    /// 0 = to us, 1 = broadcast, 2 = multicast, 3 = to another host, 4 = sent by us.
    public let packetType: UInt16
    /// The ARPHRD_* hardware type (1 = Ethernet).
    public let hardwareType: UInt16
    /// The link-layer address, trimmed to its declared length.
    public let address: Data
    /// The EtherType of the payload (for Ethernet-like hardware types).
    public let protocolType: EtherType
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes the 16-byte Linux SLL header.
public struct LinuxSLLDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let packetType = try reader.readUInt16()
        let hardwareType = try reader.readUInt16()
        let addressLength = Int(try reader.readUInt16())
        let addressField = try reader.readBytes(8)
        let protocolType = EtherType(rawValue: try reader.readUInt16())

        let payload = reader.readRemaining()
        let layer = LinuxSLL(
            packetType: packetType,
            hardwareType: hardwareType,
            address: addressField.prefix(min(addressLength, 8)),
            protocolType: protocolType,
            payload: payload,
            header: data.prefix(16)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        return DecodeResult(
            layer: layer, next: .next(etherNextLayerType(for: protocolType), payload))
    }
}

/// A BSD/macOS `pflog` header (`DLT_PFLOG`) — what capturing on `pflog0`
/// yields when pf logging is enabled.
public struct PFLog: Layer {
    public static let layerType = LayerType.pflog

    /// The address family of the logged packet (2 = INET, everything in
    /// ``LoopbackDecoder``'s IPv6 set = INET6).
    public let addressFamily: UInt8
    /// The pf action (0 = pass, 1 = drop/block, …).
    public let action: UInt8
    /// The reason code for the action.
    public let reason: UInt8
    /// The interface the rule matched on.
    public let interfaceName: String
    /// The rule number that matched.
    public let ruleNumber: UInt32
    /// 0 = inbound, 1 = outbound (pf's PF_IN/PF_OUT).
    public let direction: UInt8
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }

    public var actionName: String {
        switch action {
        case 0: return "pass"
        case 1: return "block"
        case 8: return "rdr"
        default: return "action-\(action)"
        }
    }
}

/// Decodes a pflog header. The first byte declares the header's own length
/// (the struct has grown over the years), so decoding tolerates any vintage;
/// the payload is routed by address family.
public struct PFLogDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let length = Int(try reader.readUInt8())
        let family = try reader.readUInt8()
        let action = try reader.readUInt8()
        let reason = try reader.readUInt8()
        let nameBytes = try reader.readBytes(16)
        try reader.skip(16)  // ruleset name
        let ruleNumber = try reader.readUInt32()

        // Everything past the rule number varies by pf vintage; trust the
        // declared length for where the payload begins. The direction byte
        // sits third from the end of the fixed header on modern layouts.
        guard length >= reader.bytesRead, length <= data.count else {
            throw DecodingError.malformed("pflog header length \(length)")
        }
        let base = data.startIndex
        let direction: UInt8 = length >= 4 ? data[base + length - 4] : 0
        let payload = data[(base + length)..<data.endIndex]

        let interfaceName = String(
            decoding: nameBytes.prefix(while: { $0 != 0 }), as: UTF8.self)

        let layer = PFLog(
            addressFamily: family,
            action: action,
            reason: reason,
            interfaceName: interfaceName,
            ruleNumber: ruleNumber,
            direction: direction,
            payload: payload,
            header: data.prefix(length)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        let next = LoopbackDecoder.nextLayerType(for: UInt32(family))
        return DecodeResult(layer: layer, next: .next(next, payload))
    }
}
