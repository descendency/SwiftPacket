import Foundation

/// Accumulates bytes in network byte order — the serialization counterpart to
/// ``ByteReader``. Integers are written by explicit shifting, so byte order is
/// unambiguous and there are no alignment concerns.
public struct ByteWriter {
    public private(set) var data: Data

    public init() {
        self.data = Data()
    }

    public mutating func writeUInt8(_ value: UInt8) {
        data.append(value)
    }

    public mutating func writeUInt16(_ value: UInt16) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xFF))
    }

    public mutating func writeUInt32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    public mutating func writeBytes(_ bytes: Data) {
        data.append(bytes)
    }
}
