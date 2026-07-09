import Foundation

/// Timestamp precision for a written capture file.
public enum TimestampPrecision: Sendable {
    case microsecond
    case nanosecond

    var ticksPerSecond: Double {
        switch self {
        case .microsecond: return 1_000_000
        case .nanosecond: return 1_000_000_000
        }
    }
}

/// Writes a capture file — classic pcap or pcapng — with no libpcap
/// dependency.
///
/// This is the pure-Swift counterpart to ``PcapFileWriter``. Records are
/// written little-endian and incrementally, so a writer streams to disk
/// without buffering the whole capture. For pcapng a single interface (the
/// ``linkType`` given at creation) is described; every packet is written as an
/// Enhanced Packet Block against it.
///
/// ```swift
/// let writer = try CaptureFileWriter(url: url, linkType: .ethernet, format: .pcapng)
/// for packet in packets { try writer.write(packet) }
/// writer.close()
/// ```
public final class CaptureFileWriter: @unchecked Sendable {
    private let handle: FileHandle
    private let format: CaptureFileFormat
    private let precision: TimestampPrecision
    private let lock = NSLock()
    private var closed = false

    /// The link type stamped into the file header.
    public let linkType: LinkType

    /// Creates a capture file at `url`, writing its header immediately.
    /// - Throws: if the file cannot be created.
    public init(
        url: URL,
        linkType: LinkType,
        format: CaptureFileFormat = .pcap,
        snapshotLength: UInt32 = 262_144,
        timestampPrecision: TimestampPrecision = .microsecond
    ) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        self.handle = try FileHandle(forWritingTo: url)
        self.linkType = linkType
        self.format = format
        self.precision = timestampPrecision

        switch format {
        case .pcap:
            handle.write(Self.classicHeader(linkType: linkType, snapshotLength: snapshotLength, precision: precision))
        case .pcapng:
            handle.write(Self.sectionHeaderBlock())
            handle.write(Self.interfaceDescriptionBlock(linkType: linkType, snapshotLength: snapshotLength, precision: precision))
        }
    }

    /// Appends one packet. No-op after ``close()``.
    public func write(_ packet: CapturedPacket) {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        switch format {
        case .pcap: handle.write(classicRecord(packet))
        case .pcapng: handle.write(enhancedPacketBlock(packet))
        }
    }

    /// Finalizes the file. Idempotent.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        try? handle.close()
    }

    deinit {
        if !closed { try? handle.close() }
    }

    // MARK: - Little-endian byte helpers

    private static func u16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8(value >> 8)]
    }
    private static func u32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF),
        ]
    }

    // MARK: - Classic pcap

    private static func classicHeader(
        linkType: LinkType, snapshotLength: UInt32, precision: TimestampPrecision
    ) -> Data {
        var bytes: [UInt8] = []
        // Little-endian magic; the nanosecond variant swaps the constant.
        let magic: UInt32 = precision == .nanosecond ? 0xA1B2_3C4D : 0xA1B2_C3D4
        bytes += u32(magic)
        bytes += u16(2) + u16(4)  // version 2.4
        bytes += u32(0)  // thiszone
        bytes += u32(0)  // sigfigs
        bytes += u32(snapshotLength)
        bytes += u32(UInt32(bitPattern: linkType.rawValue))
        return Data(bytes)
    }

    private func classicRecord(_ packet: CapturedPacket) -> Data {
        let (seconds, subseconds) = ticks(for: packet.info.timestamp)
        var bytes: [UInt8] = []
        bytes += Self.u32(seconds)
        bytes += Self.u32(subseconds)
        bytes += Self.u32(UInt32(packet.data.count))
        bytes += Self.u32(UInt32(packet.info.originalLength))
        return Data(bytes) + packet.data
    }

    // MARK: - pcapng

    private static func sectionHeaderBlock() -> Data {
        var body: [UInt8] = []
        body += u32(0x1A2B_3C4D)  // byte-order magic
        body += u16(1) + u16(0)  // version 1.0
        body += u32(0xFFFF_FFFF) + u32(0xFFFF_FFFF)  // section length: -1 (unknown)
        return block(type: 0x0A0D_0D0A, body: body)
    }

    private static func interfaceDescriptionBlock(
        linkType: LinkType, snapshotLength: UInt32, precision: TimestampPrecision
    ) -> Data {
        var body: [UInt8] = []
        body += u16(UInt16(truncatingIfNeeded: linkType.rawValue))
        body += u16(0)  // reserved
        body += u32(snapshotLength)
        // if_tsresol option (code 9): 6 = 1e-6, 9 = 1e-9.
        let resolution: UInt8 = precision == .nanosecond ? 9 : 6
        body += u16(9) + u16(1) + [resolution, 0, 0, 0]  // value padded to 4
        body += u16(0) + u16(0)  // opt_endofopt
        return block(type: 0x0000_0001, body: body)
    }

    private func enhancedPacketBlock(_ packet: CapturedPacket) -> Data {
        let (seconds, subseconds) = ticks(for: packet.info.timestamp)
        let totalTicks = UInt64(seconds) * UInt64(precision.ticksPerSecond) + UInt64(subseconds)

        var body: [UInt8] = []
        body += Self.u32(0)  // interface ID 0
        body += Self.u32(UInt32(totalTicks >> 32))  // timestamp high
        body += Self.u32(UInt32(totalTicks & 0xFFFF_FFFF))  // timestamp low
        body += Self.u32(UInt32(packet.data.count))  // captured length
        body += Self.u32(UInt32(packet.info.originalLength))  // original length
        body += [UInt8](packet.data)
        // Packet data is padded to a 4-byte boundary.
        let padding = (4 - packet.data.count % 4) % 4
        body += [UInt8](repeating: 0, count: padding)
        return Self.block(type: 0x0000_0006, body: body)
    }

    /// Wraps a block body in its type / total-length framing (length repeated
    /// at both ends), padding the body to a 4-byte boundary.
    private static func block(type: UInt32, body: [UInt8]) -> Data {
        var padded = body
        padded += [UInt8](repeating: 0, count: (4 - body.count % 4) % 4)
        let total = UInt32(12 + padded.count)
        return Data(u32(type) + u32(total) + padded + u32(total))
    }

    // MARK: - Timestamp split

    /// Splits a `Date` into whole seconds and sub-second ticks at the writer's
    /// precision.
    private func ticks(for date: Date) -> (seconds: UInt32, subseconds: UInt32) {
        let interval = date.timeIntervalSince1970
        let whole = interval.rounded(.down)
        let fraction = (interval - whole) * precision.ticksPerSecond
        return (UInt32(truncatingIfNeeded: Int64(whole)), UInt32(fraction.rounded()))
    }
}
