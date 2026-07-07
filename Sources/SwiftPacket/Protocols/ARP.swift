import Foundation

/// An ARP message (RFC 826). Terminal — carries no payload layer.
public struct ARP: Layer {
    public static let layerType = LayerType.arp

    public enum Operation: UInt16, Sendable {
        case request = 1
        case reply = 2
    }

    public let hardwareType: UInt16
    public let protocolType: UInt16
    public let hardwareSize: Int
    public let protocolSize: Int
    public let operation: UInt16

    public let senderHardwareAddress: Data
    public let senderProtocolAddress: Data
    public let targetHardwareAddress: Data
    public let targetProtocolAddress: Data

    fileprivate let contents: Data
    public var layerContents: Data { contents }
    public var layerPayload: Data { Data() }

    /// The operation as an enum, when recognized.
    public var op: Operation? { Operation(rawValue: operation) }

    /// The sender's MAC, when the hardware address is 6 bytes.
    public var senderMAC: MACAddress? { MACAddress(senderHardwareAddress) }
    /// The target's MAC, when the hardware address is 6 bytes.
    public var targetMAC: MACAddress? { MACAddress(targetHardwareAddress) }
    /// The sender's IPv4 address, when the protocol address is 4 bytes.
    public var senderIPv4: IPv4Address? { IPv4Address(senderProtocolAddress) }
    /// The target's IPv4 address, when the protocol address is 4 bytes.
    public var targetIPv4: IPv4Address? { IPv4Address(targetProtocolAddress) }
}

/// Decodes an ARP message using the hardware and protocol address sizes it
/// declares, so it works for non-Ethernet/IPv4 combinations too.
public struct ARPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let hardwareType = try reader.readUInt16()
        let protocolType = try reader.readUInt16()
        let hardwareSize = Int(try reader.readUInt8())
        let protocolSize = Int(try reader.readUInt8())
        let operation = try reader.readUInt16()
        let senderHardware = try reader.readBytes(hardwareSize)
        let senderProtocol = try reader.readBytes(protocolSize)
        let targetHardware = try reader.readBytes(hardwareSize)
        let targetProtocol = try reader.readBytes(protocolSize)

        let consumed = 8 + 2 * hardwareSize + 2 * protocolSize
        let layer = ARP(
            hardwareType: hardwareType,
            protocolType: protocolType,
            hardwareSize: hardwareSize,
            protocolSize: protocolSize,
            operation: operation,
            senderHardwareAddress: senderHardware,
            senderProtocolAddress: senderProtocol,
            targetHardwareAddress: targetHardware,
            targetProtocolAddress: targetProtocol,
            contents: data.prefix(consumed)
        )
        return DecodeResult(layer: layer, next: .done)
    }
}
