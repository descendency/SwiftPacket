import Foundation

/// A 48-bit IEEE 802 MAC address.
public struct MACAddress: Hashable, Sendable, CustomStringConvertible {
    /// The six address bytes, most-significant first.
    public let bytes: [UInt8]

    /// Creates an address from exactly six bytes, or `nil` otherwise.
    public init?(_ bytes: [UInt8]) {
        guard bytes.count == 6 else { return nil }
        self.bytes = bytes
    }

    /// Creates an address from exactly six bytes of `data`, or `nil` otherwise.
    public init?(_ data: Data) {
        self.init(Array(data))
    }

    /// The broadcast address `ff:ff:ff:ff:ff:ff`.
    public static let broadcast = MACAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])!

    public var description: String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}

/// A 32-bit IPv4 address.
public struct IPv4Address: Hashable, Sendable, CustomStringConvertible {
    /// The address as a host-order integer, first octet in the most-significant byte.
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Creates an address from exactly four bytes of `data`, or `nil` otherwise.
    public init?(_ data: Data) {
        guard data.count == 4 else { return nil }
        var value: UInt32 = 0
        for byte in data { value = value << 8 | UInt32(byte) }
        self.rawValue = value
    }

    /// The four octets, most-significant first.
    public var octets: [UInt8] {
        [
            UInt8((rawValue >> 24) & 0xFF),
            UInt8((rawValue >> 16) & 0xFF),
            UInt8((rawValue >> 8) & 0xFF),
            UInt8(rawValue & 0xFF),
        ]
    }

    public var description: String {
        octets.map(String.init).joined(separator: ".")
    }
}

/// A 128-bit IPv6 address.
public struct IPv6Address: Hashable, Sendable, CustomStringConvertible {
    /// The sixteen address bytes, most-significant first.
    public let bytes: [UInt8]

    /// Creates an address from exactly sixteen bytes of `data`, or `nil` otherwise.
    public init?(_ data: Data) {
        guard data.count == 16 else { return nil }
        self.bytes = Array(data)
    }

    /// The address formatted per RFC 5952, compressing the longest run of zero
    /// groups to `::`.
    public var description: String {
        var groups = [UInt16]()
        groups.reserveCapacity(8)
        for index in stride(from: 0, to: 16, by: 2) {
            groups.append(UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]))
        }

        // Locate the longest run of consecutive zero groups (length >= 2).
        var bestStart = -1
        var bestLength = 0
        var runStart = -1
        var runLength = 0
        for (index, group) in groups.enumerated() {
            if group == 0 {
                if runStart < 0 { runStart = index }
                runLength += 1
                if runLength > bestLength {
                    bestLength = runLength
                    bestStart = runStart
                }
            } else {
                runStart = -1
                runLength = 0
            }
        }
        if bestLength < 2 { bestStart = -1 }

        func hex(_ range: Range<Int>) -> String {
            range.map { String(groups[$0], radix: 16) }.joined(separator: ":")
        }

        guard bestStart >= 0 else { return hex(0..<8) }
        let head = hex(0..<bestStart)
        let tail = hex((bestStart + bestLength)..<8)
        return "\(head)::\(tail)"
    }
}

extension ByteReader {
    /// Reads a six-byte MAC address.
    mutating func readMACAddress() throws -> MACAddress {
        guard let mac = MACAddress(try readBytes(6)) else {
            throw DecodingError.malformed("MAC address")
        }
        return mac
    }

    /// Reads a four-byte IPv4 address.
    mutating func readIPv4Address() throws -> IPv4Address {
        IPv4Address(rawValue: try readUInt32())
    }

    /// Reads a sixteen-byte IPv6 address.
    mutating func readIPv6Address() throws -> IPv6Address {
        guard let ip = IPv6Address(try readBytes(16)) else {
            throw DecodingError.malformed("IPv6 address")
        }
        return ip
    }
}
