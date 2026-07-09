import Foundation
import Testing

@testable import SwiftPacket

@Suite("Pure-Swift capture file I/O (pcap & pcapng)")
struct CaptureFileTests {

    static let frames: [[UInt8]] = [
        Array(repeating: 0xAA, count: 42),
        (0..<60).map { UInt8($0) },
        [0xDE, 0xAD, 0xBE, 0xEF],
        [],  // a zero-length record must round-trip too
    ]
    static let base = Date(timeIntervalSince1970: 1_700_000_000.123456)

    static func samplePackets() -> [CapturedPacket] {
        frames.enumerated().map { index, frame in
            CapturedPacket(
                data: Data(frame),
                info: CaptureInfo(
                    timestamp: base.addingTimeInterval(Double(index)),
                    captureLength: frame.count, originalLength: frame.count),
                linkType: .ethernet)
        }
    }

    static func temporaryURL(_ ext: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("swiftpacket-\(UUID().uuidString).\(ext)")
    }

    /// Writes the sample packets and reads them back with the pure-Swift path.
    func roundTrip(format: CaptureFileFormat, precision: TimestampPrecision) throws {
        let url = Self.temporaryURL(format == .pcap ? "pcap" : "pcapng")
        defer { try? FileManager.default.removeItem(at: url) }

        let writer = try CaptureFileWriter(
            url: url, linkType: .ethernet, format: format, timestampPrecision: precision)
        for packet in Self.samplePackets() { writer.write(packet) }
        writer.close()

        let reader = try CaptureFileReader(contentsOf: url)
        #expect(reader.format == format)
        #expect(reader.linkType == .ethernet)
        #expect(reader.parsedPackets.count == Self.frames.count)

        for (original, roundTripped) in zip(Self.frames, reader.parsedPackets) {
            #expect(Array(roundTripped.data) == original)
            #expect(roundTripped.info.captureLength == original.count)
            #expect(roundTripped.info.originalLength == original.count)
            #expect(roundTripped.linkType == .ethernet)
        }
        // Timestamp survives at the chosen precision.
        let tolerance = precision == .nanosecond ? 1e-6 : 1e-3
        let first = try #require(reader.parsedPackets.first)
        #expect(abs(first.info.timestamp.timeIntervalSince1970 - Self.base.timeIntervalSince1970) < tolerance)
    }

    @Test("classic pcap round-trips (microsecond)")
    func classicMicro() throws { try roundTrip(format: .pcap, precision: .microsecond) }

    @Test("classic pcap round-trips (nanosecond)")
    func classicNano() throws { try roundTrip(format: .pcap, precision: .nanosecond) }

    @Test("pcapng round-trips (microsecond)")
    func pcapngMicro() throws { try roundTrip(format: .pcapng, precision: .microsecond) }

    @Test("pcapng round-trips (nanosecond)")
    func pcapngNano() throws { try roundTrip(format: .pcapng, precision: .nanosecond) }

    // MARK: - Cross-compatibility with libpcap

    @Test("our pcap writer produces files the libpcap reader accepts")
    func writerReadableByLibpcap() async throws {
        let url = Self.temporaryURL("pcap")
        defer { try? FileManager.default.removeItem(at: url) }

        let writer = try CaptureFileWriter(url: url, linkType: .ethernet, format: .pcap)
        for packet in Self.samplePackets() { writer.write(packet) }
        writer.close()

        let reader = try PcapFileReader(url: url)  // libpcap-backed
        var readBack: [CapturedPacket] = []
        for try await packet in reader.packets() { readBack.append(packet) }
        #expect(readBack.count == Self.frames.count)
        for (original, roundTripped) in zip(Self.frames, readBack) {
            #expect(Array(roundTripped.data) == original)
        }
    }

    @Test("our pcap reader accepts files the libpcap writer produced")
    func readerAcceptsLibpcap() throws {
        let url = Self.temporaryURL("pcap")
        defer { try? FileManager.default.removeItem(at: url) }

        let writer = try PcapFileWriter(path: url.path, linkType: .ethernet)  // libpcap-backed
        for packet in Self.samplePackets() { writer.write(packet) }
        writer.close()

        let packets = try CaptureFile.read(contentsOf: url)  // pure-Swift
        #expect(packets.count == Self.frames.count)
        for (original, roundTripped) in zip(Self.frames, packets) {
            #expect(Array(roundTripped.data) == original)
            #expect(roundTripped.linkType == .ethernet)
        }
    }

    @Test("a decoded packet survives a pcapng round-trip end-to-end")
    func decodeAfterRoundTrip() throws {
        let dnsFrame = Data(
            ProtocolTests.ethernetHeader + ProtocolTests.ipv4Header + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery)
        let url = Self.temporaryURL("pcapng")
        defer { try? FileManager.default.removeItem(at: url) }

        let writer = try CaptureFileWriter(url: url, linkType: .ethernet, format: .pcapng)
        writer.write(
            CapturedPacket(
                data: dnsFrame,
                info: CaptureInfo(timestamp: Self.base, captureLength: dnsFrame.count, originalLength: dnsFrame.count),
                linkType: .ethernet))
        writer.close()

        let packets = try CaptureFile.read(contentsOf: url)
        let decoded = try #require(packets.first).decoded(using: .standard)
        #expect(decoded.summary == "Ethernet | IPv4 | UDP | DNS")
        #expect(decoded.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    // MARK: - Format detection & robustness

    @Test("format detection recognizes both magics in both byte orders")
    func detection() {
        #expect(CaptureFile.detectFormat(Data([0xA1, 0xB2, 0xC3, 0xD4])) == .pcap)  // BE micro
        #expect(CaptureFile.detectFormat(Data([0xD4, 0xC3, 0xB2, 0xA1])) == .pcap)  // LE micro
        #expect(CaptureFile.detectFormat(Data([0xA1, 0xB2, 0x3C, 0x4D])) == .pcap)  // BE nano
        #expect(CaptureFile.detectFormat(Data([0x4D, 0x3C, 0xB2, 0xA1])) == .pcap)  // LE nano
        #expect(CaptureFile.detectFormat(Data([0x0A, 0x0D, 0x0D, 0x0A])) == .pcapng)
        #expect(CaptureFile.detectFormat(Data([0x00, 0x01, 0x02, 0x03])) == nil)
        #expect(CaptureFile.detectFormat(Data([0x01])) == nil)
    }

    @Test("unrecognized bytes throw, not trap")
    func unrecognized() {
        #expect(throws: CaptureFileError.self) {
            _ = try CaptureFile.read(Data([0x00, 0x01, 0x02, 0x03, 0x04]))
        }
    }

    @Test("a truncated tail yields the whole packets read so far")
    func truncatedTail() throws {
        let url = Self.temporaryURL("pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let writer = try CaptureFileWriter(url: url, linkType: .ethernet, format: .pcap)
        for packet in Self.samplePackets() { writer.write(packet) }
        writer.close()

        // Lop off the last 10 bytes: the final record is now incomplete.
        var bytes = try Data(contentsOf: url)
        bytes.removeLast(10)
        let packets = try CaptureFile.read(bytes)
        // The earlier complete records survive; the truncated one is dropped.
        #expect(packets.count == Self.frames.count - 1)
        #expect(Array(packets[0].data) == Self.frames[0])
    }

    @Test("random bytes never trap the parsers")
    func fuzz() {
        var generator = SystemRandomNumberGenerator()
        for magic in [[0xA1, 0xB2, 0xC3, 0xD4], [0x0A, 0x0D, 0x0D, 0x0A]] as [[UInt8]] {
            for _ in 0..<300 {
                let count = Int.random(in: 4...200, using: &generator)
                var bytes = [UInt8](repeating: 0, count: count)
                for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max, using: &generator) }
                bytes.replaceSubrange(0..<4, with: magic)
                if magic[0] == 0x0A {
                    // Give pcapng a plausible byte-order magic sometimes.
                    if count >= 12 { bytes.replaceSubrange(8..<12, with: [0x4D, 0x3C, 0x2B, 0x1A]) }
                }
                _ = try? CaptureFile.read(Data(bytes))
            }
        }
    }
}
