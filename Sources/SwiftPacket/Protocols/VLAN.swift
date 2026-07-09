import Foundation

/// An IEEE 802.1Q VLAN tag (or an 802.1ad service tag — Q-in-Q outer tags
/// simply chain to another ``Dot1Q`` layer).
public struct Dot1Q: Layer {
    public static let layerType = LayerType.vlan

    /// Priority code point (0–7).
    public let priority: UInt8
    /// Drop-eligible indicator.
    public let dropEligible: Bool
    /// VLAN identifier (0–4095).
    public let vlanID: UInt16
    /// The EtherType of the tagged payload.
    public let etherType: EtherType
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes a 4-byte 802.1Q tag and chains to the tagged payload's decoder.
public struct Dot1QDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let tci = try reader.readUInt16()
        let etherType = EtherType(rawValue: try reader.readUInt16())
        let payload = reader.readRemaining()

        let layer = Dot1Q(
            priority: UInt8(tci >> 13),
            dropEligible: tci & 0x1000 != 0,
            vlanID: tci & 0x0FFF,
            etherType: etherType,
            payload: payload,
            header: data.prefix(4)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        let next: LayerType = etherType.rawValue < 1536 ? .llc : etherNextLayerType(for: etherType)
        return DecodeResult(layer: layer, next: .next(next, payload))
    }
}

/// One entry of an MPLS label stack.
public struct MPLSLabel: Sendable, Hashable {
    /// The 20-bit label value.
    public let label: UInt32
    /// Traffic class (the former EXP bits).
    public let trafficClass: UInt8
    /// Whether this is the bottom of the label stack.
    public let bottomOfStack: Bool
    public let ttl: UInt8
}

/// An MPLS label stack (RFC 3032).
public struct MPLS: Layer {
    public static let layerType = LayerType.mpls

    /// The label stack, outermost first. Always ends with the bottom-of-stack
    /// entry.
    public let labels: [MPLSLabel]
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes an MPLS label stack. MPLS carries no protocol field, so the payload
/// is identified by its leading version nibble (4 → IPv4, 6 → IPv6), the same
/// heuristic GoPacket and Wireshark use; anything else is an opaque payload
/// (e.g. an Ethernet pseudowire).
public struct MPLSDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        var labels: [MPLSLabel] = []
        while true {
            let entry = try reader.readUInt32()
            labels.append(
                MPLSLabel(
                    label: entry >> 12,
                    trafficClass: UInt8((entry >> 9) & 0x07),
                    bottomOfStack: entry & 0x100 != 0,
                    ttl: UInt8(entry & 0xFF)
                ))
            if entry & 0x100 != 0 { break }
            // A stack deeper than any sane network uses is malformed input.
            guard labels.count < 32 else {
                throw DecodingError.malformed("MPLS label stack too deep")
            }
        }
        let payload = reader.readRemaining()
        let layer = MPLS(
            labels: labels,
            payload: payload,
            header: data.prefix(labels.count * 4)
        )

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        let next: LayerType
        switch (payload.first ?? 0) >> 4 {
        case 4: next = .ipv4
        case 6: next = .ipv6
        default: next = .payload
        }
        return DecodeResult(layer: layer, next: .next(next, payload))
    }
}
