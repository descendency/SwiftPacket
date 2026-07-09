import Foundation
import Testing

@testable import SwiftPacket

// TCP flag bits (file scope so the instance test methods see them unqualified).
private let fin: UInt16 = 0x01
private let syn: UInt16 = 0x02
private let rst: UInt16 = 0x04
private let ack: UInt16 = 0x10

@Suite("TCP stream reassembly")
struct TCPReassemblyTests {

    /// Builds an IPv4/TCP packet (client → server: 10.0.0.1:1234 → 10.0.0.2:80,
    /// or reversed) with the given sequence number, flags, and payload.
    static func packet(
        seq: UInt32, flags: UInt16, payload: [UInt8] = [], reverse: Bool = false
    ) -> Packet {
        let (srcIP, dstIP): ([UInt8], [UInt8]) =
            reverse ? ([10, 0, 0, 2], [10, 0, 0, 1]) : ([10, 0, 0, 1], [10, 0, 0, 2])
        let (srcPort, dstPort): (UInt16, UInt16) = reverse ? (80, 1234) : (1234, 80)

        let total = 20 + 20 + payload.count
        var ip: [UInt8] = [0x45, 0x00, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0x40, 0x00, 0x40, 0x06, 0, 0]
        ip += srcIP + dstIP

        let offsetFlags = UInt16(5) << 12 | flags
        var tcp: [UInt8] = [
            UInt8(srcPort >> 8), UInt8(srcPort & 0xFF), UInt8(dstPort >> 8), UInt8(dstPort & 0xFF),
            UInt8(seq >> 24), UInt8((seq >> 16) & 0xFF), UInt8((seq >> 8) & 0xFF), UInt8(seq & 0xFF),
            0, 0, 0, 0,
            UInt8(offsetFlags >> 8), UInt8(offsetFlags & 0xFF), 0xFF, 0xFF, 0, 0, 0, 0,
        ]
        tcp += payload
        return Packet.decode(Data(ip + tcp), startingAt: .ipv4, using: .standard)
    }

    static func text(_ deliveries: [TCPSegmentDelivery]) -> String {
        deliveries.map { String(decoding: $0.data, as: UTF8.self) }.joined()
    }

    @Test("in-order segments deliver their bytes in sequence")
    func inOrder() async {
        let reassembler = TCPReassembler()
        var out: [TCPSegmentDelivery] = []
        out += await reassembler.process(Self.packet(seq: 1000, flags: syn))
        out += await reassembler.process(Self.packet(seq: 1001, flags: ack, payload: Array("hello ".utf8)))
        out += await reassembler.process(Self.packet(seq: 1007, flags: ack, payload: Array("world".utf8)))
        #expect(Self.text(out) == "hello world")
        #expect(out.allSatisfy { !$0.hasGap })
    }

    @Test("out-of-order segments are buffered and reordered")
    func outOfOrder() async {
        let reassembler = TCPReassembler()
        _ = await reassembler.process(Self.packet(seq: 1000, flags: syn))
        // Deliver the second segment first: it must be held back.
        let held = await reassembler.process(Self.packet(seq: 1007, flags: ack, payload: Array("world".utf8)))
        #expect(held.isEmpty)
        // Now the first segment arrives; both come out in order.
        let now = await reassembler.process(Self.packet(seq: 1001, flags: ack, payload: Array("hello ".utf8)))
        #expect(Self.text(now) == "hello world")
    }

    @Test("a pure retransmit is discarded")
    func retransmit() async {
        let reassembler = TCPReassembler()
        _ = await reassembler.process(Self.packet(seq: 1000, flags: syn))
        _ = await reassembler.process(Self.packet(seq: 1001, flags: ack, payload: Array("abc".utf8)))
        // Exact retransmit of the same bytes.
        let again = await reassembler.process(Self.packet(seq: 1001, flags: ack, payload: Array("abc".utf8)))
        #expect(again.isEmpty)
    }

    @Test("an overlapping retransmit contributes only its fresh tail")
    func overlap() async {
        let reassembler = TCPReassembler()
        _ = await reassembler.process(Self.packet(seq: 1000, flags: syn))
        _ = await reassembler.process(Self.packet(seq: 1001, flags: ack, payload: Array("abcde".utf8)))
        // Overlaps the last two bytes and adds "fg".
        let out = await reassembler.process(Self.packet(seq: 1004, flags: ack, payload: Array("defg".utf8)))
        #expect(Self.text(out) == "fg")
    }

    @Test("mid-stream capture (no SYN) adopts the first segment's sequence")
    func midStream() async {
        let reassembler = TCPReassembler()
        let out = await reassembler.process(Self.packet(seq: 5000, flags: ack, payload: Array("data".utf8)))
        #expect(Self.text(out) == "data")
    }

    @Test("FIN closes the stream after its data drains")
    func finTeardown() async {
        let reassembler = TCPReassembler()
        _ = await reassembler.process(Self.packet(seq: 1000, flags: syn))
        _ = await reassembler.process(Self.packet(seq: 1001, flags: ack, payload: Array("bye".utf8)))
        let closing = await reassembler.process(Self.packet(seq: 1004, flags: fin | ack))
        #expect(closing.contains { $0.isEnd })
        let count = await reassembler.streamCount
        #expect(count == 0)  // fully closed streams are dropped
    }

    @Test("RST tears the stream down immediately")
    func rstTeardown() async {
        let reassembler = TCPReassembler()
        _ = await reassembler.process(Self.packet(seq: 1000, flags: syn))
        let reset = await reassembler.process(Self.packet(seq: 1001, flags: rst))
        #expect(reset.contains { $0.isEnd })
    }

    @Test("forced flush skips an unrecoverable gap and reports its length")
    func gapSkip() async {
        let reassembler = TCPReassembler()
        _ = await reassembler.process(Self.packet(seq: 1000, flags: syn))
        _ = await reassembler.process(Self.packet(seq: 1001, flags: ack, payload: Array("head".utf8)))
        // A segment 10 bytes past the hole (seq 1005..1015 missing 1005..1010).
        _ = await reassembler.process(Self.packet(seq: 1015, flags: ack, payload: Array("tail".utf8)))

        let flushed = await reassembler.flush(force: true)
        #expect(Self.text(flushed) == "tail")
        #expect(flushed.first?.gapLength == 10)  // 1015 - 1005
        #expect(flushed.first?.hasGap == true)
    }

    @Test("both directions are tracked as independent streams")
    func bidirectional() async {
        let reassembler = TCPReassembler()
        let request = await reassembler.process(
            Self.packet(seq: 100, flags: ack, payload: Array("GET /".utf8)))
        let response = await reassembler.process(
            Self.packet(seq: 200, flags: ack, payload: Array("200 OK".utf8), reverse: true))
        #expect(Self.text(request) == "GET /")
        #expect(Self.text(response) == "200 OK")
        // The two directions share one canonical connection key.
        #expect(request.first?.stream.connection == response.first?.stream.connection)
        #expect(request.first?.stream != response.first?.stream)
        let count = await reassembler.streamCount
        #expect(count == 2)
    }

    @Test("sequence-number wraparound is handled")
    func wraparound() async {
        let reassembler = TCPReassembler()
        // Start just below the 32-bit boundary.
        let start: UInt32 = 0xFFFF_FFFE
        _ = await reassembler.process(Self.packet(seq: start, flags: syn))
        var out: [TCPSegmentDelivery] = []
        // Data begins at start+1 (0xFFFFFFFF); "AB" spans the wrap to 0x0.
        out += await reassembler.process(Self.packet(seq: start &+ 1, flags: ack, payload: Array("AB".utf8)))
        out += await reassembler.process(Self.packet(seq: start &+ 3, flags: ack, payload: Array("CD".utf8)))
        #expect(Self.text(out) == "ABCD")
    }

    @Test("close() drains remaining buffered data past gaps")
    func closeDrains() async {
        let reassembler = TCPReassembler()
        _ = await reassembler.process(Self.packet(seq: 1000, flags: syn))
        // Only an out-of-order segment sitting behind a gap.
        _ = await reassembler.process(Self.packet(seq: 1010, flags: ack, payload: Array("late".utf8)))
        let drained = await reassembler.close()
        #expect(Self.text(drained) == "late")
        let count = await reassembler.streamCount
        #expect(count == 0)
    }

    @Test("random packets never trap the reassembler")
    func robustness() async {
        let reassembler = TCPReassembler()
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<500 {
            let seq = UInt32.random(in: .min ... .max, using: &generator)
            let flags = UInt16.random(in: 0...0x1F, using: &generator)
            let length = Int.random(in: 0...20, using: &generator)
            var payload = [UInt8](repeating: 0, count: length)
            for index in payload.indices { payload[index] = UInt8.random(in: .min ... .max, using: &generator) }
            _ = await reassembler.process(Self.packet(seq: seq, flags: flags, payload: payload))
        }
        _ = await reassembler.close()
    }
}
