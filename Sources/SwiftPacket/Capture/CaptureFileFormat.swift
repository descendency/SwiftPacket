import Foundation

/// A capture-file container format.
public enum CaptureFileFormat: Sendable, Hashable {
    /// Classic libpcap `.pcap` (a global header followed by packet records).
    case pcap
    /// PcapNG `.pcapng` (a block stream; what Wireshark writes by default).
    case pcapng
}

/// An error reading a capture file.
public enum CaptureFileError: Error, Sendable, Equatable {
    /// The bytes are neither classic pcap nor pcapng.
    case unrecognizedFormat
    /// The file ends before a required header is complete.
    case truncatedHeader
    /// The file is structurally invalid.
    case malformed(String)
}

/// A little/big-endian cursor over a byte buffer, returning `nil` on underflow
/// rather than trapping. Used to parse capture-file headers, whose byte order
/// is discovered from a magic number.
struct EndianReader {
    let data: Data
    private let base: Int
    private(set) var offset: Int
    var bigEndian: Bool

    init(_ data: Data, bigEndian: Bool) {
        self.data = data
        self.base = data.startIndex
        self.offset = 0
        self.bigEndian = bigEndian
    }

    var remaining: Int { data.count - offset }
    var isAtEnd: Bool { offset >= data.count }

    mutating func seek(to newOffset: Int) { offset = newOffset }

    mutating func u16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        let i = base + offset
        defer { offset += 2 }
        return bigEndian
            ? UInt16(data[i]) << 8 | UInt16(data[i + 1])
            : UInt16(data[i + 1]) << 8 | UInt16(data[i])
    }

    mutating func u32() -> UInt32? {
        guard remaining >= 4 else { return nil }
        let i = base + offset
        defer { offset += 4 }
        let bytes = (0..<4).map { UInt32(data[i + $0]) }
        return bigEndian
            ? bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]
            : bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0]
    }

    mutating func bytes(_ count: Int) -> Data? {
        guard count >= 0, remaining >= count else { return nil }
        let start = base + offset
        defer { offset += count }
        return data[start..<(start + count)]
    }

    @discardableResult
    mutating func skip(_ count: Int) -> Bool {
        guard count >= 0, remaining >= count else { return false }
        offset += count
        return true
    }
}

/// Pure-Swift reading of capture files, with no libpcap dependency.
///
/// Both classic pcap (either byte order, microsecond or nanosecond
/// timestamps) and pcapng (Section Header / Interface Description / Enhanced
/// & Simple Packet blocks) are supported, with per-interface link types and
/// timestamp resolutions. A truncated tail is tolerated: whole packets read so
/// far are returned rather than throwing.
public enum CaptureFile {
    /// Detects the container format from the leading bytes, or `nil` if the
    /// bytes match neither format.
    public static func detectFormat(_ data: Data) -> CaptureFileFormat? {
        guard data.count >= 4 else { return nil }
        let b = data.startIndex
        let word = UInt32(data[b]) << 24 | UInt32(data[b + 1]) << 16 | UInt32(data[b + 2]) << 8
            | UInt32(data[b + 3])
        // The pcapng SHB block type 0x0A0D0D0A reads identically either way.
        if word == 0x0A0D_0D0A { return .pcapng }
        switch word {
        case 0xA1B2_C3D4, 0xD4C3_B2A1, 0xA1B2_3C4D, 0x4D3C_B2A1: return .pcap
        default: return nil
        }
    }

    /// Reads every packet from the file at `url`.
    public static func read(contentsOf url: URL) throws -> [CapturedPacket] {
        try read(Data(contentsOf: url))
    }

    /// Reads every packet from an in-memory capture.
    public static func read(_ data: Data) throws -> [CapturedPacket] {
        try parse(data).packets
    }

    /// The parsed contents of a capture: its format, the link type to report
    /// for the source as a whole, and the packets.
    struct Parsed {
        let format: CaptureFileFormat
        let linkType: LinkType
        let packets: [CapturedPacket]
    }

    static func parse(_ data: Data) throws -> Parsed {
        switch detectFormat(data) {
        case .pcap: return try parseClassic(data)
        case .pcapng: return try parsePcapNG(data)
        case nil: throw CaptureFileError.unrecognizedFormat
        }
    }

    // MARK: - Classic pcap

    private static func parseClassic(_ data: Data) throws -> Parsed {
        let b = data.startIndex
        let magic = UInt32(data[b]) << 24 | UInt32(data[b + 1]) << 16 | UInt32(data[b + 2]) << 8
            | UInt32(data[b + 3])
        // Big-endian if the magic reads "forwards".
        let bigEndian = (magic == 0xA1B2_C3D4 || magic == 0xA1B2_3C4D)
        let nanosecond = (magic == 0xA1B2_3C4D || magic == 0x4D3C_B2A1)

        var reader = EndianReader(data, bigEndian: bigEndian)
        guard reader.skip(4),  // magic (already read)
            reader.u16() != nil,  // version major
            reader.u16() != nil,  // version minor
            reader.u32() != nil,  // thiszone
            reader.u32() != nil,  // sigfigs
            reader.u32() != nil,  // snaplen
            let network = reader.u32()
        else { throw CaptureFileError.truncatedHeader }

        let linkType = LinkType(rawValue: Int32(truncatingIfNeeded: network))
        let fraction = nanosecond ? 1_000_000_000.0 : 1_000_000.0

        var packets: [CapturedPacket] = []
        while reader.remaining >= 16 {
            guard let seconds = reader.u32(), let subseconds = reader.u32(),
                let capturedLength = reader.u32(), let originalLength = reader.u32()
            else { break }
            guard let payload = reader.bytes(Int(capturedLength)) else { break }  // truncated tail

            let timestamp = Double(seconds) + Double(subseconds) / fraction
            packets.append(
                CapturedPacket(
                    data: Data(payload),
                    info: CaptureInfo(
                        timestamp: Date(timeIntervalSince1970: timestamp),
                        captureLength: Int(capturedLength),
                        originalLength: Int(originalLength)),
                    linkType: linkType))
        }
        return Parsed(format: .pcap, linkType: linkType, packets: packets)
    }

    // MARK: - pcapng

    private struct Interface {
        let linkType: LinkType
        /// Seconds per timestamp tick (default 1e-6).
        let tickSeconds: Double
    }

    private static func parsePcapNG(_ data: Data) throws -> Parsed {
        // The byte-order magic in the first Section Header Block fixes endianness.
        guard data.count >= 12 else { throw CaptureFileError.truncatedHeader }
        let b = data.startIndex
        let bomBig = UInt32(data[b + 8]) << 24 | UInt32(data[b + 9]) << 16
            | UInt32(data[b + 10]) << 8 | UInt32(data[b + 11])
        let bigEndian: Bool
        if bomBig == 0x1A2B_3C4D {
            bigEndian = true
        } else if bomBig == 0x4D3C_2B1A {
            bigEndian = false
        } else {
            throw CaptureFileError.malformed("bad pcapng byte-order magic")
        }

        var reader = EndianReader(data, bigEndian: bigEndian)
        var interfaces: [Interface] = []
        var packets: [CapturedPacket] = []

        while reader.remaining >= 12 {
            let blockStart = reader.offset
            guard let blockType = reader.u32(), let blockTotalLength = reader.u32() else { break }
            // The length includes the 12 bytes of framing; guard against a
            // zero/short/misaligned length that would loop or overrun.
            guard blockTotalLength >= 12, blockTotalLength % 4 == 0,
                blockStart + Int(blockTotalLength) <= data.count
            else { break }
            let bodyLength = Int(blockTotalLength) - 12

            switch blockType {
            case 0x0000_0001:  // Interface Description Block
                interfaces.append(parseInterface(&reader, bodyLength: bodyLength))
            case 0x0000_0006:  // Enhanced Packet Block
                if let packet = parseEnhancedPacket(
                    &reader, bodyLength: bodyLength, interfaces: interfaces)
                {
                    packets.append(packet)
                }
            case 0x0000_0003:  // Simple Packet Block
                if let packet = parseSimplePacket(
                    &reader, bodyLength: bodyLength, interfaces: interfaces)
                {
                    packets.append(packet)
                }
            case 0x0A0D_0D0A:  // a new Section Header Block: interfaces reset
                interfaces.removeAll()
            default:
                break  // ISB and others are skipped
            }

            // Advance to the next block regardless of how much the body parse
            // consumed.
            reader.seek(to: blockStart + Int(blockTotalLength))
        }

        let linkType = interfaces.first?.linkType ?? LinkType(rawValue: 1)
        return Parsed(format: .pcapng, linkType: linkType, packets: packets)
    }

    private static func parseInterface(_ reader: inout EndianReader, bodyLength: Int) -> Interface {
        let bodyStart = reader.offset
        let linkTypeValue = reader.u16() ?? 1
        _ = reader.u16()  // reserved
        _ = reader.u32()  // snaplen

        // Options: default timestamp resolution is 1e-6 unless if_tsresol says.
        var tickSeconds = 1e-6
        let optionsConsumed = reader.offset - bodyStart
        for option in parseOptions(&reader, available: bodyLength - optionsConsumed) {
            if option.code == 9, let first = option.value.first {  // if_tsresol
                if first & 0x80 != 0 {
                    tickSeconds = pow(2.0, -Double(first & 0x7F))
                } else {
                    tickSeconds = pow(10.0, -Double(first))
                }
            }
        }
        return Interface(
            linkType: LinkType(rawValue: Int32(truncatingIfNeeded: linkTypeValue)),
            tickSeconds: tickSeconds)
    }

    private static func parseEnhancedPacket(
        _ reader: inout EndianReader, bodyLength: Int, interfaces: [Interface]
    ) -> CapturedPacket? {
        guard let interfaceID = reader.u32(), let tsHigh = reader.u32(), let tsLow = reader.u32(),
            let capturedLength = reader.u32(), let originalLength = reader.u32(),
            let payload = reader.bytes(Int(capturedLength))
        else { return nil }

        let interface = interfaces.indices.contains(Int(interfaceID))
            ? interfaces[Int(interfaceID)] : interfaces.first
        let ticks = UInt64(tsHigh) << 32 | UInt64(tsLow)
        let seconds = Double(ticks) * (interface?.tickSeconds ?? 1e-6)

        return CapturedPacket(
            data: Data(payload),
            info: CaptureInfo(
                timestamp: Date(timeIntervalSince1970: seconds),
                captureLength: Int(capturedLength),
                originalLength: Int(originalLength)),
            linkType: interface?.linkType ?? LinkType(rawValue: 1))
    }

    private static func parseSimplePacket(
        _ reader: inout EndianReader, bodyLength: Int, interfaces: [Interface]
    ) -> CapturedPacket? {
        guard let originalLength = reader.u32() else { return nil }
        // A Simple Packet Block has no captured-length field; the data fills
        // the block body (minus this 4-byte field, ignoring trailing padding).
        let available = bodyLength - 4
        let captured = Swift.min(Int(originalLength), Swift.max(0, available))
        guard let payload = reader.bytes(captured) else { return nil }
        return CapturedPacket(
            data: Data(payload),
            info: CaptureInfo(
                timestamp: Date(timeIntervalSince1970: 0),
                captureLength: captured, originalLength: Int(originalLength)),
            linkType: interfaces.first?.linkType ?? LinkType(rawValue: 1))
    }

    private struct BlockOption {
        let code: UInt16
        let value: Data
    }

    /// Parses an options list (code/length/value, 4-byte-padded, terminated by
    /// code 0) from the current position, consuming at most `available` bytes.
    private static func parseOptions(_ reader: inout EndianReader, available: Int)
        -> [BlockOption]
    {
        guard available >= 4 else { return [] }
        var options: [BlockOption] = []
        let end = reader.offset + available
        while reader.offset + 4 <= end {
            guard let code = reader.u16(), let length = reader.u16() else { break }
            if code == 0 { break }  // opt_endofopt
            guard let value = reader.bytes(Int(length)) else { break }
            options.append(BlockOption(code: code, value: Data(value)))
            let padding = (4 - Int(length) % 4) % 4
            if !reader.skip(padding) { break }
        }
        return options
    }
}

/// A ``CaptureEngine`` that vends a pre-parsed array of packets — the backing
/// for pure-Swift file reading.
final class BufferedPacketEngine: CaptureEngine, @unchecked Sendable {
    let linkType: LinkType
    private let packets: [CapturedPacket]
    private let lock = NSLock()
    private var index = 0

    init(packets: [CapturedPacket], linkType: LinkType) {
        self.packets = packets
        self.linkType = linkType
    }

    func next() async throws -> CapturedPacket? {
        nextSynchronously()
    }

    /// The locking is kept in a synchronous method: holding an `NSLock` across
    /// a potential suspension is disallowed, and there is none here.
    private func nextSynchronously() -> CapturedPacket? {
        lock.lock()
        defer { lock.unlock() }
        guard index < packets.count else { return nil }
        defer { index += 1 }
        return packets[index]
    }
}
