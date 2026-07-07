import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 2 — decode model")
struct DecodeModelTests {

    // MARK: - Test fixtures

    // A tiny TLV-style protocol used only to exercise the decode machinery.
    // Wire format per record: [length: UInt8][length bytes of value]. Any bytes
    // beyond one record chain into another record of the same type.
    static let fakeType = LayerType(id: 1000, name: "Fake", category: .metadata)
    static let danglingType = LayerType(id: 1001, name: "Dangling", category: .metadata)

    struct FakeLayer: Layer {
        static let layerType = DecodeModelTests.fakeType
        let value: Data
        let rest: Data
        var layerContents: Data { value }
        var layerPayload: Data { rest }
    }

    struct FakeDecoder: LayerDecoder {
        func decode(_ data: Data) throws -> DecodeResult {
            var reader = ByteReader(data)
            let length = Int(try reader.readUInt8())
            let value = try reader.readBytes(length)  // throws if truncated
            let rest = reader.readRemaining()
            let layer = FakeLayer(value: value, rest: rest)
            // Chain to another record if bytes remain; otherwise done.
            return DecodeResult(
                layer: layer,
                next: rest.isEmpty ? .done : .next(DecodeModelTests.fakeType, rest)
            )
        }
    }

    // A decoder that always points at an unregistered next type.
    struct DanglingDecoder: LayerDecoder {
        func decode(_ data: Data) throws -> DecodeResult {
            var reader = ByteReader(data)
            _ = try reader.readUInt8()
            let rest = reader.readRemaining()
            return DecodeResult(
                layer: FakeLayer(value: Data(), rest: rest),
                next: .next(DecodeModelTests.danglingType, rest)  // unregistered
            )
        }
    }

    // A pathological decoder that never consumes bytes and loops forever.
    struct LoopingDecoder: LayerDecoder {
        func decode(_ data: Data) throws -> DecodeResult {
            DecodeResult(layer: Payload(data), next: .next(DecodeModelTests.fakeType, data))
        }
    }

    private static func registry(_ decoder: any LayerDecoder) -> DecoderRegistry {
        var registry = DecoderRegistry()
        registry.register(fakeType, decoder: decoder)
        registry.mapLink(.ethernet, to: fakeType)
        return registry
    }

    // MARK: - Tests

    @Test("decoder chain produces one layer per record")
    func chainsMultipleRecords() {
        // Two records: len 2 [0xAA,0xBB], then len 1 [0xCC].
        let bytes = Data([0x02, 0xAA, 0xBB, 0x01, 0xCC])
        let packet = Packet.decode(bytes, startingAt: Self.fakeType, using: Self.registry(FakeDecoder()))

        #expect(packet.layers.count == 2)
        #expect(packet.summary == "Fake | Fake")
        let first = packet.layer(FakeLayer.self)
        #expect(Array(first?.value ?? Data()) == [0xAA, 0xBB])
        #expect(packet.decodeFailure == nil)
    }

    @Test("truncated input yields a trailing DecodeFailure, not a crash")
    func truncationBecomesFailure() {
        // Claims length 5 but only 2 value bytes follow.
        let bytes = Data([0x05, 0xAA, 0xBB])
        let packet = Packet.decode(bytes, startingAt: Self.fakeType, using: Self.registry(FakeDecoder()))

        let failure = packet.decodeFailure
        #expect(failure != nil)
        #expect(failure?.reason.contains("insufficient") == true)
        #expect(packet.layers.last is DecodeFailure)
    }

    @Test("an unregistered next type collects the remainder as Payload")
    func unknownNextBecomesPayload() {
        let bytes = Data([0x00, 0x11, 0x22, 0x33])
        var registry = DecoderRegistry()
        registry.register(Self.fakeType, decoder: DanglingDecoder())
        let packet = Packet.decode(bytes, startingAt: Self.fakeType, using: registry)

        #expect(packet.payload != nil)
        #expect(Array(packet.payload?.bytes ?? Data()) == [0x11, 0x22, 0x33])
    }

    @Test("the layer limit stops a non-consuming decoder from looping forever")
    func layerLimitGuardsInfiniteLoop() {
        let bytes = Data([0x00, 0x01, 0x02])
        let packet = Packet.decode(
            bytes,
            startingAt: Self.fakeType,
            using: Self.registry(LoopingDecoder()),
            layerLimit: 8
        )
        // It terminated (rather than hanging) and bounded the layer count.
        #expect(packet.layers.count <= 9)
        #expect(packet.layers.last is Payload)
    }

    @Test("CapturedPacket.decoded uses the link-type mapping")
    func capturedPacketBridge() {
        let info = CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: 3, originalLength: 3)
        let captured = CapturedPacket(data: Data([0x02, 0xAA, 0xBB]), info: info, linkType: .ethernet)

        let packet = captured.decoded(using: Self.registry(FakeDecoder()))
        #expect(packet.contains(Self.fakeType))
        #expect(packet.layer(FakeLayer.self) != nil)
    }

    @Test("an unmapped link type falls back to a single Payload")
    func unmappedLinkTypeFallsBack() {
        let info = CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: 2, originalLength: 2)
        let captured = CapturedPacket(data: Data([0x01, 0x02]), info: info, linkType: .raw)
        let packet = captured.decoded(using: DecoderRegistry.empty)

        #expect(packet.layers.count == 1)
        #expect(packet.payload != nil)
    }
}
