import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 2 — ByteReader")
struct ByteReaderTests {

    @Test("reads big-endian integers in sequence")
    func bigEndianSequence() throws {
        var reader = ByteReader(Data([0x12, 0x34, 0x56, 0x78, 0x9A]))
        #expect(try reader.readUInt8() == 0x12)
        #expect(try reader.readUInt16() == 0x3456)
        #expect(try reader.readUInt16() == 0x789A)
        #expect(reader.isAtEnd)
        #expect(reader.bytesRead == 5)
        #expect(reader.remaining == 0)
    }

    @Test("reads 24/32/64-bit big-endian values")
    func widerBigEndian() throws {
        var reader = ByteReader(Data([0x01, 0x02, 0x03, 0xAA, 0xBB, 0xCC, 0xDD]))
        #expect(try reader.readUInt24() == 0x01_02_03)
        #expect(try reader.readUInt32() == 0xAABB_CCDD)

        var wide = ByteReader(Data([0, 0, 0, 0, 0, 0, 0x01, 0x00]))
        #expect(try wide.readUInt64() == 256)
    }

    @Test("reads little-endian variants")
    func littleEndian() throws {
        var reader = ByteReader(Data([0x34, 0x12, 0x78, 0x56, 0x34, 0x12]))
        #expect(try reader.readUInt16LE() == 0x1234)
        #expect(try reader.readUInt32LE() == 0x1234_5678)
    }

    @Test("reading past the end throws with accurate counts, never traps")
    func underflowThrows() throws {
        var reader = ByteReader(Data([0x01, 0x02]))
        _ = try reader.readUInt8()
        #expect(throws: DecodingError.insufficientBytes(needed: 4, available: 1)) {
            _ = try reader.readUInt32()
        }
        // The failed read must not have advanced the cursor.
        #expect(reader.remaining == 1)
        #expect(try reader.readUInt8() == 0x02)
    }

    @Test("empty data reads throw immediately")
    func emptyData() {
        var reader = ByteReader(Data())
        #expect(reader.isAtEnd)
        #expect(throws: DecodingError.self) { _ = try reader.readUInt8() }
    }

    @Test("readBytes returns a correct slice and advances")
    func readBytesSlice() throws {
        var reader = ByteReader(Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00]))
        let head = try reader.readBytes(4)
        #expect(Array(head) == [0xDE, 0xAD, 0xBE, 0xEF])
        #expect(Array(reader.readRemaining()) == [0x00])
    }

    @Test("works correctly over a Data slice with a non-zero start index")
    func nonZeroStartIndex() throws {
        // A classic bug source: Data slices do not start at index 0.
        let full = Data((0..<20).map { UInt8($0) })
        let slice = full[5..<15]
        #expect(slice.startIndex == 5)

        var reader = ByteReader(slice)
        #expect(reader.count == 10)
        #expect(try reader.readUInt8() == 5)
        #expect(try reader.readUInt8() == 6)
        let rest = try reader.readBytes(3)
        #expect(Array(rest) == [7, 8, 9])
        #expect(reader.remaining == 5)
    }

    @Test("skip and peek behave correctly")
    func skipAndPeek() throws {
        var reader = ByteReader(Data([0x01, 0x02, 0x03]))
        #expect(try reader.peekUInt8() == 0x01)
        #expect(reader.bytesRead == 0)  // peek does not advance
        try reader.skip(2)
        #expect(try reader.readUInt8() == 0x03)
        #expect(throws: DecodingError.self) { try reader.skip(1) }
    }
}
