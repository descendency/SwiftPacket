import Foundation

/// One DHCP option (a raw tag/value pair).
public struct DHCPOption: Sendable, Hashable {
    public let code: UInt8
    public let value: Data
}

/// A DHCPv4 / BOOTP message (RFC 2131), UDP ports 67/68.
public struct DHCPv4: Layer {
    public static let layerType = LayerType.dhcpv4

    /// 1 = request (BOOTREQUEST), 2 = reply (BOOTREPLY).
    public let op: UInt8
    public let hardwareType: UInt8
    public let hops: UInt8
    public let transactionID: UInt32
    public let seconds: UInt16
    public let broadcast: Bool
    /// The client's current address (`ciaddr`).
    public let clientAddress: IPv4Address
    /// The address being offered/assigned (`yiaddr`).
    public let yourAddress: IPv4Address
    /// The next server (`siaddr`).
    public let serverAddress: IPv4Address
    /// The relay agent (`giaddr`).
    public let gatewayAddress: IPv4Address
    /// The client hardware address, trimmed to its declared length.
    public let clientHardwareAddress: Data
    /// All options in order (padding and end markers excluded).
    public let options: [DHCPOption]

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    /// The first option with the given code.
    public func option(_ code: UInt8) -> Data? {
        options.first { $0.code == code }?.value
    }

    /// The DHCP message type (option 53): 1 DISCOVER … 8 INFORM.
    public var messageType: UInt8? { option(53)?.first }

    public var messageTypeName: String {
        switch messageType {
        case 1: return "DISCOVER"
        case 2: return "OFFER"
        case 3: return "REQUEST"
        case 4: return "DECLINE"
        case 5: return "ACK"
        case 6: return "NAK"
        case 7: return "RELEASE"
        case 8: return "INFORM"
        default: return "BOOTP"
        }
    }

    /// The client MAC, when the hardware address is Ethernet-sized.
    public var clientMAC: MACAddress? { MACAddress(clientHardwareAddress) }
    /// The requested IP address (option 50).
    public var requestedAddress: IPv4Address? { option(50).flatMap(IPv4Address.init) }
    /// The server identifier (option 54).
    public var serverIdentifier: IPv4Address? { option(54).flatMap(IPv4Address.init) }
    /// The client hostname (option 12).
    public var hostname: String? {
        option(12).map { String(decoding: $0, as: UTF8.self) }
    }
    /// The lease time in seconds (option 51).
    public var leaseTime: UInt32? {
        guard let value = option(51), value.count == 4 else { return nil }
        var reader = ByteReader(value)
        return try? reader.readUInt32()
    }
}

/// Decodes a DHCPv4/BOOTP message.
public struct DHCPv4Decoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let op = try reader.readUInt8()
        let hardwareType = try reader.readUInt8()
        let hardwareLength = Int(try reader.readUInt8())
        let hops = try reader.readUInt8()
        let transactionID = try reader.readUInt32()
        let seconds = try reader.readUInt16()
        let flags = try reader.readUInt16()
        let clientAddress = try reader.readIPv4Address()
        let yourAddress = try reader.readIPv4Address()
        let serverAddress = try reader.readIPv4Address()
        let gatewayAddress = try reader.readIPv4Address()
        let chaddr = try reader.readBytes(16)
        try reader.skip(64 + 128)  // sname, file (legacy BOOTP fields)

        // Options begin after the magic cookie 99.130.83.99.
        var options: [DHCPOption] = []
        if reader.remaining >= 4, try reader.readUInt32() == 0x6382_5363 {
            while let code = try? reader.readUInt8() {
                if code == 0 { continue }  // pad
                if code == 255 { break }  // end
                guard let length = try? reader.readUInt8(),
                    let value = try? reader.readBytes(Int(length))
                else { break }
                options.append(DHCPOption(code: code, value: value))
            }
        }

        let layer = DHCPv4(
            op: op,
            hardwareType: hardwareType,
            hops: hops,
            transactionID: transactionID,
            seconds: seconds,
            broadcast: flags & 0x8000 != 0,
            clientAddress: clientAddress,
            yourAddress: yourAddress,
            serverAddress: serverAddress,
            gatewayAddress: gatewayAddress,
            clientHardwareAddress: chaddr.prefix(min(hardwareLength, 16)),
            options: options,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }
}

/// One DHCPv6 option (a raw code/value pair; codes are 16-bit).
public struct DHCPv6Option: Sendable, Hashable {
    public let code: UInt16
    public let value: Data
}

/// A DHCPv6 message (RFC 8415), UDP ports 546/547.
public struct DHCPv6: Layer {
    public static let layerType = LayerType.dhcpv6

    /// 1 SOLICIT, 2 ADVERTISE, 3 REQUEST, 5 RENEW, 7 REPLY, 12/13 relay …
    public let messageType: UInt8
    /// The 24-bit transaction id (zero for relay messages, which carry
    /// addresses instead).
    public let transactionID: UInt32
    public let options: [DHCPv6Option]

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    /// The first option with the given code.
    public func option(_ code: UInt16) -> Data? {
        options.first { $0.code == code }?.value
    }

    public var messageTypeName: String {
        switch messageType {
        case 1: return "SOLICIT"
        case 2: return "ADVERTISE"
        case 3: return "REQUEST"
        case 4: return "CONFIRM"
        case 5: return "RENEW"
        case 6: return "REBIND"
        case 7: return "REPLY"
        case 8: return "RELEASE"
        case 9: return "DECLINE"
        case 10: return "RECONFIGURE"
        case 11: return "INFORMATION-REQUEST"
        case 12: return "RELAY-FORW"
        case 13: return "RELAY-REPL"
        default: return "type-\(messageType)"
        }
    }
}

/// Decodes a DHCPv6 message (client/server form; relay messages decode their
/// type but no options).
public struct DHCPv6Decoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let messageType = try reader.readUInt8()
        var transactionID: UInt32 = 0
        var options: [DHCPv6Option] = []

        // Relay messages (12/13) have a different fixed header; leave their
        // nested payload undecoded.
        if messageType != 12, messageType != 13 {
            transactionID = try reader.readUInt24()
            while reader.remaining >= 4 {
                let code = try reader.readUInt16()
                let length = Int(try reader.readUInt16())
                guard let value = try? reader.readBytes(length) else { break }
                options.append(DHCPv6Option(code: code, value: value))
            }
        }

        let layer = DHCPv6(
            messageType: messageType,
            transactionID: transactionID,
            options: options,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }
}

/// An NTP packet header (RFC 5905), UDP port 123.
public struct NTP: Layer {
    public static let layerType = LayerType.ntp

    /// Leap indicator (0–3).
    public let leapIndicator: UInt8
    public let version: UInt8
    /// 3 = client, 4 = server, 5 = broadcast, …
    public let mode: UInt8
    public let stratum: UInt8
    /// log2 seconds.
    public let poll: Int8
    /// log2 seconds.
    public let precision: Int8
    public let rootDelay: UInt32
    public let rootDispersion: UInt32
    public let referenceID: UInt32
    /// NTP 64-bit timestamps (seconds since 1900 in the high 32 bits).
    public let referenceTimestamp: UInt64
    public let originTimestamp: UInt64
    public let receiveTimestamp: UInt64
    public let transmitTimestamp: UInt64

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    public var modeName: String {
        switch mode {
        case 1: return "symmetric-active"
        case 2: return "symmetric-passive"
        case 3: return "client"
        case 4: return "server"
        case 5: return "broadcast"
        case 6: return "control"
        default: return "mode-\(mode)"
        }
    }

    /// Converts an NTP 64-bit timestamp to a `Date` (era 0).
    public static func date(fromTimestamp timestamp: UInt64) -> Date? {
        guard timestamp != 0 else { return nil }
        let seconds = Double(timestamp >> 32)
        let fraction = Double(timestamp & 0xFFFF_FFFF) / 4_294_967_296.0
        // NTP epoch (1900-01-01) is 2,208,988,800 s before the Unix epoch.
        return Date(timeIntervalSince1970: seconds + fraction - 2_208_988_800)
    }

    /// ``transmitTimestamp`` as a `Date`, when set.
    public var transmitDate: Date? { Self.date(fromTimestamp: transmitTimestamp) }
}

/// Decodes the fixed 48-byte NTP header.
public struct NTPDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let first = try reader.readUInt8()
        let stratum = try reader.readUInt8()
        let poll = Int8(bitPattern: try reader.readUInt8())
        let precision = Int8(bitPattern: try reader.readUInt8())
        let rootDelay = try reader.readUInt32()
        let rootDispersion = try reader.readUInt32()
        let referenceID = try reader.readUInt32()
        let referenceTimestamp = try reader.readUInt64()
        let originTimestamp = try reader.readUInt64()
        let receiveTimestamp = try reader.readUInt64()
        let transmitTimestamp = try reader.readUInt64()

        let layer = NTP(
            leapIndicator: first >> 6,
            version: (first >> 3) & 0x07,
            mode: first & 0x07,
            stratum: stratum,
            poll: poll,
            precision: precision,
            rootDelay: rootDelay,
            rootDispersion: rootDispersion,
            referenceID: referenceID,
            referenceTimestamp: referenceTimestamp,
            originTimestamp: originTimestamp,
            receiveTimestamp: receiveTimestamp,
            transmitTimestamp: transmitTimestamp,
            bytes: data
        )
        return DecodeResult(layer: layer, next: .done)
    }
}
