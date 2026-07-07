import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 5 — BPF filtering")
struct BPFFilterTests {

    // The Phase 3 golden packet: Ethernet / IPv4 / UDP(dst 53) / DNS.
    static func goldenPacket() -> CapturedPacket {
        let bytes = Data(
            ProtocolTests.ethernetHeader
                + ProtocolTests.ipv4Header
                + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery
        )
        let info = CaptureInfo(
            timestamp: .init(timeIntervalSince1970: 0),
            captureLength: bytes.count,
            originalLength: bytes.count
        )
        return CapturedPacket(data: bytes, info: info, linkType: .ethernet)
    }

    @Test("matching filters accept the packet")
    func matchingFilters() throws {
        let packet = Self.goldenPacket()
        #expect(try BPFProgram("udp port 53", linkType: .ethernet).matches(packet))
        #expect(try BPFProgram("udp", linkType: .ethernet).matches(packet))
        #expect(try BPFProgram("ip", linkType: .ethernet).matches(packet))
        #expect(try BPFProgram("dst port 53", linkType: .ethernet).matches(packet))
    }

    @Test("non-matching filters reject the packet")
    func nonMatchingFilters() throws {
        let packet = Self.goldenPacket()
        #expect(try !BPFProgram("tcp", linkType: .ethernet).matches(packet))
        #expect(try !BPFProgram("port 80", linkType: .ethernet).matches(packet))
        #expect(try !BPFProgram("icmp", linkType: .ethernet).matches(packet))
    }

    @Test("matching works on raw bytes too")
    func matchesRawBytes() throws {
        let bytes = Self.goldenPacket().data
        #expect(try BPFProgram("udp port 53", linkType: .ethernet).matches(bytes))
    }

    @Test("an invalid filter expression throws a PcapError")
    func invalidExpression() {
        #expect(throws: PcapError.self) {
            _ = try BPFProgram("this is not valid bpf ))(", linkType: .ethernet)
        }
    }
}
