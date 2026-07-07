import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 4 — serialization")
struct SerializationTests {

    private static func goldenPacket() -> Data {
        Data(
            ProtocolTests.ethernetHeader
                + ProtocolTests.ipv4Header
                + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery
        )
    }

    private static func capture(_ bytes: Data) -> CapturedPacket {
        let info = CaptureInfo(
            timestamp: .init(timeIntervalSince1970: 0),
            captureLength: bytes.count,
            originalLength: bytes.count
        )
        return CapturedPacket(data: bytes, info: info, linkType: .ethernet)
    }

    // MARK: - Round trip (the phase gate)

    @Test("decode then re-serialize reproduces the original bytes exactly")
    func roundTrip() throws {
        let original = Self.goldenPacket()
        let packet = Self.capture(original).decoded(using: .standard)

        // The golden packet carries zero checksums, so leave them as-is; length
        // fix-up must still reproduce the exact same length fields.
        let out = try packet.serializedData(
            options: SerializeOptions(fixLengths: true, computeChecksums: false)
        )
        #expect(out == original)
    }

    // MARK: - Checksums

    @Test("internet checksum matches the canonical RFC 1071 / IPv4 example")
    func canonicalChecksum() {
        // Wikipedia's IPv4 header example, checksum field zeroed; expected 0xB1E6.
        let header = Data([
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xAC, 0x10, 0x0A, 0x63,
            0xAC, 0x10, 0x0A, 0x0C,
        ])
        #expect(internetChecksum(header) == 0xB1E6)

        // The same header with the checksum in place must verify to zero.
        var verified = header
        verified[10] = 0xB1
        verified[11] = 0xE6
        #expect(internetChecksum(verified) == 0)
    }

    @Test("serializing with checksums produces valid IPv4 and UDP checksums")
    func computedChecksumsVerify() throws {
        let packet = Self.capture(Self.goldenPacket()).decoded(using: .standard)
        let out = try packet.serializedData(
            options: SerializeOptions(fixLengths: true, computeChecksums: true)
        )

        // A valid IPv4 header (bytes 14..<34) checksums to zero.
        #expect(internetChecksum(out.subdata(in: 14..<34)) == 0)

        // Verify the UDP checksum over the pseudo-header + UDP segment.
        let udpSegment = out.subdata(in: 34..<out.count)
        var verify = Data()
        verify.append(out.subdata(in: 26..<30))  // IPv4 source
        verify.append(out.subdata(in: 30..<34))  // IPv4 destination
        verify.append(0x00)
        verify.append(17)  // protocol UDP
        verify.append(UInt8((udpSegment.count >> 8) & 0xFF))
        verify.append(UInt8(udpSegment.count & 0xFF))
        verify.append(udpSegment)
        #expect(internetChecksum(verify) == 0)
    }

    @Test("length fix-up recomputes IPv4 total length and UDP length")
    func lengthFixup() throws {
        let packet = Self.capture(Self.goldenPacket()).decoded(using: .standard)
        let out = try packet.serializedData(
            options: SerializeOptions(fixLengths: true, computeChecksums: false)
        )
        // IPv4 total length at bytes 16..17 = 20 + 8 + 29 = 57.
        #expect(UInt16(out[16]) << 8 | UInt16(out[17]) == 57)
        // UDP length at bytes 38..39 = 8 + 29 = 37.
        #expect(UInt16(out[38]) << 8 | UInt16(out[39]) == 37)
    }

    @Test("a transport checksum without a network layer throws")
    func checksumWithoutNetworkLayer() {
        // A UDP layer alone cannot build a pseudo-header.
        let udpBytes = Data(ProtocolTests.udpHeader + [0x00, 0x01])
        let result = try? UDPDecoder().decode(udpBytes)
        let udp = result?.layer as? UDP
        #expect(udp != nil)

        var buffer = SerializeBuffer()
        #expect(throws: SerializationError.missingNetworkLayerForChecksum) {
            try udp?.serialize(
                into: &buffer,
                context: SerializationContext(),
                options: SerializeOptions(computeChecksums: true)
            )
        }
    }
}
