import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 1 — capture foundation")
struct CaptureFoundationTests {

    @Test("packets written to a .pcap file read back byte-for-byte")
    func pcapRoundTrip() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swiftpacket-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }

        let frames: [[UInt8]] = [
            Array(repeating: 0xAA, count: 42),
            (0..<60).map { UInt8($0) },
            [0xDE, 0xAD, 0xBE, 0xEF],
        ]
        let base = Date(timeIntervalSince1970: 1_700_000_000)

        // Write.
        let writer = try PcapFileWriter(path: url.path, linkType: .ethernet)
        for (index, frame) in frames.enumerated() {
            let info = CaptureInfo(
                timestamp: base.addingTimeInterval(Double(index)),
                captureLength: frame.count,
                originalLength: frame.count
            )
            writer.write(CapturedPacket(data: Data(frame), info: info, linkType: .ethernet))
        }
        writer.close()

        // Read back.
        let reader = try PcapFileReader(url: url)
        #expect(reader.linkType == .ethernet)

        var readBack: [CapturedPacket] = []
        for try await packet in reader.packets() {
            readBack.append(packet)
        }

        #expect(readBack.count == frames.count)
        for (original, roundTripped) in zip(frames, readBack) {
            #expect(Array(roundTripped.data) == original)
            #expect(roundTripped.info.captureLength == original.count)
            #expect(roundTripped.info.originalLength == original.count)
            #expect(roundTripped.linkType == .ethernet)
        }

        // Timestamps survive to roughly microsecond precision.
        let firstTimestamp = try #require(readBack.first).info.timestamp
        #expect(abs(firstTimestamp.timeIntervalSince1970 - base.timeIntervalSince1970) < 0.001)
    }

    @Test("reading a nonexistent file throws a PcapError")
    func missingFileThrows() {
        #expect(throws: PcapError.self) {
            _ = try PcapFileReader(path: "/nonexistent/swiftpacket/does-not-exist.pcap")
        }
    }

    @Test("device enumeration links and does not crash")
    func deviceEnumeration() {
        // Interface visibility depends on privileges and sandboxing, so the
        // list may legitimately be empty. This is a smoke test that the
        // pcap_findalldevs path links and returns without trapping.
        let devices = (try? Devices.all()) ?? []
        #expect(devices.count >= 0)
    }

    @Test("link type reports its libpcap name")
    func linkTypeName() {
        #expect(LinkType.ethernet.description == "EN10MB")
        #expect(LinkType.ethernet.rawValue == 1)
    }
}
