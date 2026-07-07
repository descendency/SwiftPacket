import Foundation
import Testing

@testable import SwiftPacket

/// Hardening tests: the decoder's core promise is that it never traps, no matter
/// how malformed the input. These tests exercise that by throwing large volumes
/// of random, truncated, and mutated bytes at the decode path. Because a trap
/// aborts the whole test process, *reaching the assertions at all* is most of
/// the guarantee; the assertions add invariant checks on top.
@Suite("Phase 6 — fuzzing & hardening")
struct FuzzTests {

    /// A small, fast, deterministic PRNG (SplitMix64) so fuzz runs are
    /// reproducible: a failure can be re-run with the same seed.
    struct SplitMix64: RandomNumberGenerator {
        private var state: UInt64
        init(seed: UInt64) { self.state = seed }
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    private static let linkTypes: [LinkType] = [.ethernet, .raw, .null, .loop, LinkType(rawValue: 9999)]

    private static func capture(_ bytes: Data, link: LinkType) -> CapturedPacket {
        let info = CaptureInfo(
            timestamp: .init(timeIntervalSince1970: 0),
            captureLength: bytes.count,
            originalLength: bytes.count
        )
        return CapturedPacket(data: bytes, info: info, linkType: link)
    }

    // Decoding must always terminate with a well-formed packet, and any decoded
    // packet must be re-serializable without trapping.
    private static func check(_ bytes: Data, link: LinkType) {
        let packet = capture(bytes, link: link).decoded(using: .standard)
        #expect(packet.layers.count <= 32)
        _ = packet.summary
        _ = packet.networkLayer
        _ = packet.transportLayer
        // Every layer type is serializable; re-serialization must not trap.
        _ = try? packet.serializedData(options: SerializeOptions(fixLengths: false, computeChecksums: false))
    }

    @Test("random bytes never trap the decoder")
    func randomBytes() {
        var rng = SplitMix64(seed: 0xDEAD_BEEF)
        for _ in 0..<5000 {
            let length = Int(rng.next() % 256)
            var bytes = Data(count: length)
            for index in 0..<length {
                bytes[index] = UInt8(rng.next() & 0xFF)
            }
            let link = Self.linkTypes[Int(rng.next() % UInt64(Self.linkTypes.count))]
            Self.check(bytes, link: link)
        }
    }

    @Test("every truncation of a real packet decodes safely")
    func truncation() {
        let full = Data(
            ProtocolTests.ethernetHeader
                + ProtocolTests.ipv4Header
                + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery
        )
        for length in 0...full.count {
            Self.check(full.prefix(length), link: .ethernet)
        }
    }

    @Test("single-byte mutations of a real packet decode safely")
    func mutation() {
        let base = Array(
            Data(
                ProtocolTests.ethernetHeader
                    + ProtocolTests.ipv4Header
                    + ProtocolTests.udpHeader
                    + ProtocolTests.dnsQuery
            )
        )
        for index in base.indices {
            for delta: UInt8 in [0x01, 0x7F, 0x80, 0xFF] {
                var mutated = base
                mutated[index] = base[index] &+ delta
                Self.check(Data(mutated), link: .ethernet)
            }
        }
    }

    @Test("a self-referential DNS compression pointer terminates")
    func dnsCompressionLoop() throws {
        // Header (qd=1) then a name that is a pointer to offset 12 — itself.
        var bytes = Data([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        bytes.append(contentsOf: [0xC0, 0x0C])  // pointer -> offset 12 (this pointer)

        // Decoding must return (with a failure), not hang.
        let packet = Self.capture(bytes, link: .ethernet)
        let result = packet.decoded(using: DecoderRegistry.standard)
        _ = result.summary  // reaching here means it terminated

        // And decoding the DNS message directly surfaces a thrown error.
        #expect(throws: DecodingError.self) {
            _ = try DNSDecoder().decode(bytes)
        }
    }

    @Test("random DNS-shaped messages never trap")
    func randomDNS() {
        var rng = SplitMix64(seed: 0x1234_5678)
        for _ in 0..<2000 {
            let length = Int(rng.next() % 128)
            var bytes = Data(count: length)
            for index in 0..<length {
                bytes[index] = UInt8(rng.next() & 0xFF)
            }
            _ = try? DNSDecoder().decode(bytes)
        }
    }
}
