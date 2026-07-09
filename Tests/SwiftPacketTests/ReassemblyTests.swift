import Foundation
import Testing

@testable import SwiftPacket

// MARK: - IP fragment builders

enum FragmentBuilder {
    /// The 37-byte UDP/DNS datagram used as fragmented payload: the UDP header
    /// (length 37) followed by the `example.com` A query.
    static let innerUDP = ProtocolTests.udpHeader + ProtocolTests.dnsQuery

    /// An IPv4 fragment: 20-byte header, proto UDP, given fragment offset (in
    /// bytes, a multiple of 8) and more-fragments flag.
    static func ipv4Fragment(offset: Int, more: Bool, payload: [UInt8], id: UInt16 = 0x1234)
        -> Data
    {
        let total = 20 + payload.count
        let fragWord = UInt16(offset / 8) | (more ? 0x2000 : 0)
        let header: [UInt8] = [
            0x45, 0x00, UInt8(total >> 8), UInt8(total & 0xFF),
            UInt8(id >> 8), UInt8(id & 0xFF), UInt8(fragWord >> 8), UInt8(fragWord & 0xFF),
            0x40, 0x11, 0x00, 0x00,
            0xC0, 0x00, 0x02, 0x01, 0xC0, 0x00, 0x02, 0x02,
        ]
        return Data(header + payload)
    }

    /// An IPv6 fragment: 40-byte base header (next-header 44) + 8-byte fragment
    /// header (inner proto UDP) + payload.
    static func ipv6Fragment(offset: Int, more: Bool, payload: [UInt8], id: UInt32 = 0xABCD)
        -> Data
    {
        let payloadLength = 8 + payload.count
        let offsetAndFlags = UInt16(offset / 8) << 3 | (more ? 1 : 0)
        var bytes: [UInt8] = [
            0x60, 0x00, 0x00, 0x00,
            UInt8(payloadLength >> 8), UInt8(payloadLength & 0xFF), 44, 0x40,
        ]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]  // src
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]  // dst
        bytes += [
            17, 0, UInt8(offsetAndFlags >> 8), UInt8(offsetAndFlags & 0xFF),
            UInt8(id >> 24), UInt8((id >> 16) & 0xFF), UInt8((id >> 8) & 0xFF), UInt8(id & 0xFF),
        ]
        return Data(bytes + payload)
    }
}

@Suite("IP defragmentation")
struct IPDefragmentationTests {

    @Test("a two-fragment IPv4 datagram reassembles and re-decodes")
    func ipv4TwoFragments() async {
        let inner = FragmentBuilder.innerUDP  // 37 bytes
        let first = FragmentBuilder.ipv4Fragment(offset: 0, more: true, payload: Array(inner[0..<16]))
        let second = FragmentBuilder.ipv4Fragment(offset: 16, more: false, payload: Array(inner[16...]))

        let defrag = IPDefragmenter()
        let r1 = await defrag.process(Packet.decode(first, startingAt: .ipv4, using: .standard))
        // First fragment alone is incomplete.
        if case .incomplete = r1 {} else { Issue.record("expected incomplete, got \(r1)") }

        let r2 = await defrag.process(Packet.decode(second, startingAt: .ipv4, using: .standard))
        guard case .reassembled(let packet) = r2 else {
            Issue.record("expected reassembled, got \(r2)")
            return
        }
        #expect(packet.summary == "IPv4 | UDP | DNS")
        #expect(packet.layer(UDP.self)?.destinationPort == 53)
        #expect(packet.layer(DNS.self)?.questions.first?.name == "example.com")
        #expect(packet.layer(IPv4.self)?.moreFragments == false)
        let pending = await defrag.pendingCount
        #expect(pending == 0)
    }

    @Test("fragments arriving out of order still reassemble")
    func ipv4OutOfOrder() async {
        let inner = FragmentBuilder.innerUDP
        let first = FragmentBuilder.ipv4Fragment(offset: 0, more: true, payload: Array(inner[0..<16]))
        let second = FragmentBuilder.ipv4Fragment(offset: 16, more: false, payload: Array(inner[16...]))

        let defrag = IPDefragmenter()
        // Last fragment first.
        _ = await defrag.process(Packet.decode(second, startingAt: .ipv4, using: .standard))
        let result = await defrag.process(Packet.decode(first, startingAt: .ipv4, using: .standard))
        #expect(result.packet?.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    @Test("a non-fragmented packet passes straight through")
    func passThrough() async {
        let whole = Data(
            ProtocolTests.ipv4Header + ProtocolTests.udpHeader + ProtocolTests.dnsQuery)
        let defrag = IPDefragmenter()
        let result = await defrag.process(Packet.decode(whole, startingAt: .ipv4, using: .standard))
        guard case .passThrough = result else {
            Issue.record("expected passThrough, got \(result)")
            return
        }
    }

    @Test("overlapping fragments resolve first-fragment-wins")
    func overlap() async {
        let inner = FragmentBuilder.innerUDP
        let first = FragmentBuilder.ipv4Fragment(offset: 0, more: true, payload: Array(inner[0..<24]))
        // Overlapping second fragment: starts at offset 16 but with corrupt
        // bytes in the 16..<24 overlap; the first fragment's bytes must win.
        var tail = Array(inner[16...])
        tail[0] = 0xFF  // corruption inside the overlap region
        tail[1] = 0xFF
        let second = FragmentBuilder.ipv4Fragment(offset: 16, more: false, payload: tail)

        let defrag = IPDefragmenter()
        _ = await defrag.process(Packet.decode(first, startingAt: .ipv4, using: .standard))
        let result = await defrag.process(Packet.decode(second, startingAt: .ipv4, using: .standard))
        // The DNS name is intact because the first fragment's overlap bytes won.
        #expect(result.packet?.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    @Test("a two-fragment IPv6 datagram reassembles and re-decodes")
    func ipv6TwoFragments() async {
        let inner = FragmentBuilder.innerUDP
        let first = FragmentBuilder.ipv6Fragment(offset: 0, more: true, payload: Array(inner[0..<16]))
        let second = FragmentBuilder.ipv6Fragment(offset: 16, more: false, payload: Array(inner[16...]))

        let defrag = IPDefragmenter()
        // Confirm the fragment header decodes as its own layer.
        let firstPacket = Packet.decode(first, startingAt: .ipv6, using: .standard)
        #expect(firstPacket.layer(IPv6Fragment.self)?.moreFragments == true)
        #expect(firstPacket.layer(IPv6Fragment.self)?.nextHeader == .udp)

        _ = await defrag.process(firstPacket)
        let result = await defrag.process(Packet.decode(second, startingAt: .ipv6, using: .standard))
        guard case .reassembled(let packet) = result else {
            Issue.record("expected reassembled, got \(result)")
            return
        }
        #expect(packet.summary == "IPv6 | UDP | DNS")
        #expect(packet.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    @Test("garbage fragments never trap the defragmenter")
    func robustness() async {
        let defrag = IPDefragmenter()
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<300 {
            let count = Int.random(in: 20...60, using: &generator)
            var bytes = [UInt8](repeating: 0, count: count)
            for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max, using: &generator) }
            bytes[0] = 0x45  // look like IPv4
            bytes[6] = 0x20  // MF set → treated as a fragment
            _ = await defrag.process(Packet.decode(Data(bytes), startingAt: .ipv4, using: .standard))
        }
    }
}
