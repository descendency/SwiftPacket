import Foundation
import Testing

@testable import SwiftPacket

@Suite("TLS stream assembly — cross-segment handshake recovery")
struct TLSStreamTests {

    /// Splits `bytes` into TCP packets of `chunk` bytes each, on the forward
    /// direction, starting at sequence `start`.
    static func segments(_ bytes: [UInt8], chunk: Int, start: UInt32) -> [Packet] {
        var packets: [Packet] = []
        var sequence = start
        var offset = 0
        while offset < bytes.count {
            let slice = Array(bytes[offset..<min(offset + chunk, bytes.count)])
            packets.append(TCPReassemblyTests.packet(seq: sequence, flags: 0x10, payload: slice))
            sequence &+= UInt32(slice.count)
            offset += chunk
        }
        return packets
    }

    @Test("a ServerHello + Certificate flight split across many segments yields the cert")
    func serverFlightAcrossSegments() async {
        // The full TLS server flight from the TLS test fixtures.
        let flight =
            TLSTests.record(type: 22, TLSTests.handshake(type: 2, TLSTests.serverHelloBody()))
            + TLSTests.record(type: 22, TLSTests.handshake(type: 11, TLSTests.certificateBody()))

        // Chop it into deliberately small 40-byte segments so the handshake
        // spans many packets and several records.
        let packets = Self.segments(flight, chunk: 40, start: 1001)
        #expect(packets.count > 3)  // genuinely fragmented

        let assembler = TLSStreamAssembler()
        var events: [TLSHandshakeEvent] = []
        for packet in packets {
            events += await assembler.process(packet)
        }
        events += await assembler.close()

        let serverHello = events.first { $0.discovery == .serverHello }
        #expect(serverHello?.tls.serverHello?.cipherSuite == 0xC02F)
        #expect(serverHello?.tls.serverHello?.ja3s == "896415616b22361262d7a961b6325cfd")

        let certEvent = events.first { $0.discovery == .certificates }
        let certificate = certEvent?.tls.certificates.first
        #expect(certificate?.subject.commonName == "test.swiftpacket.example")
        #expect(certificate?.publicKeyBits == 2048)
    }

    @Test("a ClientHello split across two segments is recovered with its SNI")
    func clientHelloAcrossSegments() async {
        let hello = TLSTests.record(type: 22, TLSTests.handshake(type: 1, TLSTests.clientHelloBody()))
        let packets = Self.segments(hello, chunk: 30, start: 500)

        let assembler = TLSStreamAssembler()
        var events: [TLSHandshakeEvent] = []
        for packet in packets {
            events += await assembler.process(packet)
        }

        let clientHello = events.first { $0.discovery == .clientHello }
        #expect(clientHello?.tls.clientHello?.serverName == "example.com")
        #expect(clientHello?.tls.clientHello?.ja3 == "71951104ba98b6430c7a17fb1cb2cb77")
        #expect(clientHello?.connection != nil)
    }

    @Test("a single-segment handshake still works")
    func singleSegment() async {
        let hello = TLSTests.record(type: 22, TLSTests.handshake(type: 1, TLSTests.clientHelloBody()))
        let packet = TCPReassemblyTests.packet(seq: 1, flags: 0x10, payload: hello)

        let assembler = TLSStreamAssembler()
        let events = await assembler.process(packet)
        #expect(events.contains { $0.discovery == .clientHello })
    }

    @Test("non-TLS traffic produces no events and is dropped cheaply")
    func nonTLS() async {
        let http = Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
        let packets = Self.segments(http, chunk: 8, start: 1)

        let assembler = TLSStreamAssembler()
        var events: [TLSHandshakeEvent] = []
        for packet in packets {
            events += await assembler.process(packet)
        }
        #expect(events.isEmpty)
    }

    @Test("random packets never trap the assembler")
    func robustness() async {
        let assembler = TLSStreamAssembler()
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<300 {
            let seq = UInt32.random(in: .min ... .max, using: &generator)
            let length = Int.random(in: 0...40, using: &generator)
            var payload = [UInt8](repeating: 0, count: length)
            for index in payload.indices { payload[index] = UInt8.random(in: .min ... .max, using: &generator) }
            _ = await assembler.process(TCPReassemblyTests.packet(seq: seq, flags: 0x10, payload: payload))
        }
        _ = await assembler.close()
    }
}
