import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 5 — lazy decoding")
struct LazyDecodeTests {

    // A reference counter used to observe whether a decoder actually ran.
    final class CallCounter: @unchecked Sendable {
        var count = 0
    }

    // Wraps the real DNS decoder, recording each invocation.
    struct SpyDNSDecoder: LayerDecoder {
        let counter: CallCounter
        func decode(_ data: Data) throws -> DecodeResult {
            counter.count += 1
            return try DNSDecoder().decode(data)
        }
    }

    static func goldenCapture() -> CapturedPacket {
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

    private static func spyRegistry(_ counter: CallCounter) -> DecoderRegistry {
        var registry = DecoderRegistry()
        registry.register(.ethernet, decoder: EthernetDecoder())
        registry.register(.ipv4, decoder: IPv4Decoder())
        registry.register(.udp, decoder: UDPDecoder())
        registry.register(.dns, decoder: SpyDNSDecoder(counter: counter))
        registry.mapLink(.ethernet, to: .ethernet)
        return registry
    }

    @Test("lazy iteration produces the same layers as eager decoding")
    func lazyMatchesEager() {
        let captured = Self.goldenCapture()
        let eager = captured.decoded(using: .standard).layers.map { $0.layerType.name }
        let lazy = captured.lazyLayers(using: .standard).map { $0.layerType.name }

        #expect(lazy == eager)
        #expect(lazy == ["Ethernet", "IPv4", "UDP", "DNS"])
    }

    @Test("firstLayer stops before decoding deeper layers")
    func firstLayerStopsEarly() {
        let counter = CallCounter()
        let registry = Self.spyRegistry(counter)
        let captured = Self.goldenCapture()

        // Lazily finding UDP must not decode the DNS layer beneath it.
        let udp = captured.firstLayer(UDP.self, using: registry)
        #expect(udp?.destinationPort == 53)
        #expect(counter.count == 0)

        // A full eager decode reaches — and runs — the DNS decoder exactly once.
        _ = captured.decoded(using: registry)
        #expect(counter.count == 1)
    }

    @Test("firstLayer returns nil when the layer is absent")
    func firstLayerMissing() {
        let captured = Self.goldenCapture()
        // There is no TCP layer in this UDP packet.
        #expect(captured.firstLayer(TCP.self, using: .standard) == nil)
    }
}
