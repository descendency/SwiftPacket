import Foundation

/// A forward-only, bounds-checked cursor over packet bytes.
///
/// Every read validates that enough bytes remain and **throws**
/// ``DecodingError/insufficientBytes(needed:available:)`` on underflow — it
/// never traps. Multi-byte integers are assembled by explicit shifting rather
/// than reinterpreting memory, so there are no alignment hazards and endianness
/// is unambiguous. Network byte order (big-endian) is the default; little-endian
/// variants are provided for the few link/host-order cases (e.g. `DLT_NULL`).
///
/// `ByteReader` is a value type: branching decoders can copy it freely to
/// explore alternatives without disturbing the original cursor.
public struct ByteReader: Sendable {
    /// The bytes this reader draws from. May itself be a slice of a larger
    /// buffer; all indexing is done relative to `data.startIndex`.
    public let data: Data

    private let start: Int
    private var cursor: Int

    public init(_ data: Data) {
        self.data = data
        self.start = data.startIndex
        self.cursor = data.startIndex
    }

    /// Total bytes available to this reader.
    public var count: Int { data.count }

    /// Bytes consumed so far.
    public var bytesRead: Int { cursor - start }

    /// Bytes not yet consumed.
    public var remaining: Int { data.endIndex - cursor }

    /// Whether the cursor has reached the end of the data.
    public var isAtEnd: Bool { cursor >= data.endIndex }

    private func require(_ n: Int) throws {
        guard n >= 0 else { throw DecodingError.invalidLength(n) }
        guard remaining >= n else {
            throw DecodingError.insufficientBytes(needed: n, available: remaining)
        }
    }

    // MARK: - Unsigned integers (big-endian / network order)

    public mutating func readUInt8() throws -> UInt8 {
        try require(1)
        defer { cursor += 1 }
        return data[cursor]
    }

    public mutating func readUInt16() throws -> UInt16 {
        try require(2)
        let value = UInt16(data[cursor]) << 8 | UInt16(data[cursor + 1])
        cursor += 2
        return value
    }

    public mutating func readUInt24() throws -> UInt32 {
        try require(3)
        var value: UInt32 = 0
        for index in 0..<3 {
            value = value << 8 | UInt32(data[cursor + index])
        }
        cursor += 3
        return value
    }

    public mutating func readUInt32() throws -> UInt32 {
        try require(4)
        var value: UInt32 = 0
        for index in 0..<4 {
            value = value << 8 | UInt32(data[cursor + index])
        }
        cursor += 4
        return value
    }

    public mutating func readUInt64() throws -> UInt64 {
        try require(8)
        var value: UInt64 = 0
        for index in 0..<8 {
            value = value << 8 | UInt64(data[cursor + index])
        }
        cursor += 8
        return value
    }

    // MARK: - Little-endian variants

    public mutating func readUInt16LE() throws -> UInt16 {
        try require(2)
        let value = UInt16(data[cursor]) | UInt16(data[cursor + 1]) << 8
        cursor += 2
        return value
    }

    public mutating func readUInt32LE() throws -> UInt32 {
        try require(4)
        var value: UInt32 = 0
        for index in 0..<4 {
            value |= UInt32(data[cursor + index]) << (8 * index)
        }
        cursor += 4
        return value
    }

    // MARK: - Raw bytes

    /// Returns the next `n` bytes as a slice sharing the underlying storage.
    public mutating func readBytes(_ n: Int) throws -> Data {
        try require(n)
        let slice = data[cursor..<(cursor + n)]
        cursor += n
        return slice
    }

    /// Returns all remaining bytes and advances the cursor to the end.
    public mutating func readRemaining() -> Data {
        let slice = data[cursor..<data.endIndex]
        cursor = data.endIndex
        return slice
    }

    /// Advances the cursor by `n` bytes without returning them.
    public mutating func skip(_ n: Int) throws {
        try require(n)
        cursor += n
    }

    // MARK: - Non-consuming peeks

    /// Reads the next byte without advancing the cursor.
    public func peekUInt8() throws -> UInt8 {
        try require(1)
        return data[cursor]
    }
}
