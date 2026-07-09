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

    /// The four address bytes, most-significant first — the same as ``octets``,
    /// named to match ``IPv6Address/bytes``.
    public var bytes: [UInt8] { octets }

    /// Parses a dotted-decimal string such as `"192.0.2.1"`, or `nil` if it is
    /// not four decimal octets.
    public init?(string: String) {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard part.count >= 1, part.count <= 3, part.allSatisfy(\.isNumber),
                let octet = UInt16(part), octet <= 255
            else { return nil }
            value = value << 8 | UInt32(octet)
        }
        self.rawValue = value
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

    /// Parses a textual IPv6 address such as `"2001:db8::1"` — including `::`
    /// zero-compression and an embedded IPv4 tail (`"::ffff:192.0.2.1"`) — or
    /// `nil` if it is not a valid address. Pure Swift; no `inet_pton` needed.
    public init?(string: String) {
        // At most one "::" may appear.
        let halves = string.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }

        func groups(_ text: String) -> [UInt16]? {
            if text.isEmpty { return [] }
            var result: [UInt16] = []
            for token in text.split(separator: ":", omittingEmptySubsequences: false) {
                if token.contains(".") {
                    // An embedded IPv4 address occupies two 16-bit groups.
                    guard let v4 = IPv4Address(string: String(token)) else { return nil }
                    let octets = v4.octets
                    result.append(UInt16(octets[0]) << 8 | UInt16(octets[1]))
                    result.append(UInt16(octets[2]) << 8 | UInt16(octets[3]))
                } else {
                    guard token.count >= 1, token.count <= 4,
                        let value = UInt16(token, radix: 16)
                    else { return nil }
                    result.append(value)
                }
            }
            return result
        }

        let allGroups: [UInt16]
        if halves.count == 2 {
            guard let head = groups(halves[0]), let tail = groups(halves[1]) else { return nil }
            let missing = 8 - head.count - tail.count
            guard missing >= 1 else { return nil }  // "::" stands for ≥1 zero group
            allGroups = head + Array(repeating: 0, count: missing) + tail
        } else {
            guard let all = groups(halves[0]) else { return nil }
            allGroups = all
        }
        guard allGroups.count == 8 else { return nil }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(16)
        for group in allGroups {
            bytes.append(UInt8(group >> 8))
            bytes.append(UInt8(group & 0xFF))
        }
        self.bytes = bytes
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
