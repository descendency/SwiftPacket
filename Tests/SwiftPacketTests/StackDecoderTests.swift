import Foundation
import Testing

@testable import SwiftPacket

@Suite("StackDecoder — fast-path parity with Packet.decode")
struct StackDecoderTests {

    static func ethernet(type: UInt16) -> [UInt8] {
        [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
         UInt8(type >> 8), UInt8(type & 0xFF)]
    }

    /// An Ethernet/IPv4/TCP packet with a short payload.
    static func tcpPacket() -> Data {
        let payload: [UInt8] = Array("GET / HTTP/1.1\r\n".utf8)
        let total = 20 + 20 + payload.count
        var ip: [UInt8] = [0x45, 0x00, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0x40, 0x00, 0x40, 0x06, 0, 0]
        ip += [10, 0, 0, 1, 10, 0, 0, 2]
        var tcp: [UInt8] = [
            0x04, 0xD2, 0x00, 0x50, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x50, 0x18, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ]
        tcp += payload
        return Data(ethernet(type: 0x0800) + ip + tcp)
    }

    @Test("Ethernet/IPv4/TCP decodes into typed slots matching Packet.decode")
    func tcpStack() {
        let data = Self.tcpPacket()
        let reference = Packet.decode(data, startingAt: .ethernet, using: .standard)

        var stack = DecodedStack()
        StackDecoder().decode(data, startingAt: .ethernet, into: &stack)

        #expect(stack.summary == reference.summary)
        #expect(stack.summary == "Ethernet | IPv4 | TCP | Payload")
        #expect(stack.ethernet?.source == reference.layer(Ethernet.self)?.source)
        #expect(stack.ipv4?.sourceAddress == reference.layer(IPv4.self)?.sourceAddress)
        #expect(stack.ipv4?.destinationAddress.description == "10.0.0.2")
        #expect(stack.tcp?.destinationPort == 80)
        #expect(stack.tcp?.sourcePort == 1234)
        #expect(stack.tcp?.syn == false && stack.tcp?.ack == true)
        #expect(stack.ipProtocol == .tcp)
        #expect(Array(stack.payload?.bytes ?? Data()) == Array("GET / HTTP/1.1\r\n".utf8))
        #expect(stack.overflow.isEmpty)  // pure fast path, no boxing
    }

    @Test("Ethernet/IPv4/UDP/DNS routes DNS through the boxed fallback")
    func udpDNS() {
        let data = Data(
            ProtocolTests.ethernetHeader + ProtocolTests.ipv4Header + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery)
        var stack = DecodedStack()
        StackDecoder().decode(data, startingAt: .ethernet, into: &stack)

        #expect(stack.summary == "Ethernet | IPv4 | UDP | DNS")
        #expect(stack.udp?.destinationPort == 53)
        // DNS has no fast slot, so it lands in overflow.
        let dns = stack.overflow.first as? DNS
        #expect(dns?.questions.first?.name == "example.com")
    }

    @Test("IPv6/TCP decodes without an Ethernet layer")
    func ipv6() {
        var bytes: [UInt8] = [0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
        bytes += [0x1F, 0x40, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xFF, 0xFF, 0, 0, 0, 0]

        var stack = DecodedStack()
        StackDecoder().decode(Data(bytes), startingAt: .ipv6, into: &stack)
        #expect(stack.summary == "IPv6 | TCP")
        #expect(stack.ipv6?.sourceAddress.description == "2001:db8::1")
        #expect(stack.tcp?.sourcePort == 8000)
        #expect(stack.tcp?.syn == true)
    }

    @Test("ARP and ICMP land in their typed slots via the fallback")
    func fallbackSlots() {
        let arp: [UInt8] = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xC0, 0x00, 0x02, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x02,
        ]
        var stack = DecodedStack()
        StackDecoder().decode(
            Data(Self.ethernet(type: 0x0806) + arp), startingAt: .ethernet, into: &stack)
        #expect(stack.summary == "Ethernet | ARP")
        #expect(stack.arp?.senderIPv4?.description == "192.0.2.1")
        #expect(stack.overflow.isEmpty)  // ARP has a typed slot
    }

    @Test("reset() lets one stack be reused across packets")
    func reuse() {
        let decoder = StackDecoder()
        var stack = DecodedStack()

        StackDecoder().decode(Self.tcpPacket(), startingAt: .ethernet, into: &stack)
        #expect(stack.tcp != nil)

        // Decode a UDP/DNS packet into the same stack; TCP slot must clear.
        let dns = Data(
            ProtocolTests.ethernetHeader + ProtocolTests.ipv4Header + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery)
        decoder.decode(dns, startingAt: .ethernet, into: &stack)
        #expect(stack.tcp == nil)
        #expect(stack.udp != nil)
        #expect(stack.overflow.count == 1)  // just DNS
    }

    @Test("a truncated packet records a decode failure, never traps")
    func truncated() {
        var stack = DecodedStack()
        StackDecoder().decode(Data([0xAA, 0xAA, 0xAA]), startingAt: .ethernet, into: &stack)
        #expect(stack.decodeFailure != nil)
        #expect(stack.contains(.decodeFailure))
    }

    @Test("decoding via CapturedPacket picks the link type")
    func viaCaptured() {
        let captured = CapturedPacket(
            data: Self.tcpPacket(),
            info: CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: 0, originalLength: 0),
            linkType: .ethernet)
        var stack = DecodedStack()
        StackDecoder().decode(captured, into: &stack)
        #expect(stack.tcp?.destinationPort == 80)
    }

    @Test("a bare-IP (.raw) packet lands in the typed IP slot, not overflow")
    func rawIPTypedSlot() {
        // A defragmented datagram arrives as link type .raw → .rawIP, which the
        // fallback path decodes straight to IPv4. It must reach stack.ipv4.
        let bytes = Data(ProtocolTests.ipv4Header + ProtocolTests.udpHeader + ProtocolTests.dnsQuery)
        let captured = CapturedPacket(
            data: bytes,
            info: CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: bytes.count, originalLength: bytes.count),
            linkType: .raw)

        var stack = DecodedStack()
        StackDecoder().decode(captured, into: &stack)

        #expect(stack.ipv4 != nil)  // the reported bug: was nil (dropped into overflow)
        #expect(stack.ipv4?.sourceAddress.description == "192.0.2.1")
        #expect(stack.udp?.destinationPort == 53)
        #expect(stack.networkFlow?.source.description == "192.0.2.1")
        #expect(stack.overflow.count == 1)  // just DNS now; IPv4 is no longer boxed
        // Summary records IPv4, not RawIP — matching Packet.decode.
        #expect(stack.summary == "IPv4 | UDP | DNS")
        let reference = captured.decoded(using: .standard)
        #expect(stack.layerTypes == reference.layers.map(\.layerType))
    }

    @Test("an IPv6 bare-IP packet also lands in the typed slot")
    func rawIPv6TypedSlot() {
        var bytes: [UInt8] = [0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
        bytes += [0x00, 0x35, 0xC0, 0x00, 0x00, 0x08, 0x00, 0x00]  // UDP

        var stack = DecodedStack()
        StackDecoder().decode(Data(bytes), startingAt: .rawIP, into: &stack)
        #expect(stack.ipv6 != nil)
        #expect(stack.ipv6?.sourceAddress.description == "2001:db8::1")
        #expect(stack.ipProtocol == .udp)
    }

    @Test("DecodedStack exposes flows, connection key, and checksum validity")
    func ergonomics() throws {
        // Serialize a real Ethernet/IPv4/UDP/DNS packet so the checksums are correct.
        let base = Packet.decode(
            Data(ProtocolTests.ethernetHeader + ProtocolTests.ipv4Header + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery), startingAt: .ethernet, using: .standard)
        let bytes = try base.serializedData()

        var stack = DecodedStack()
        StackDecoder().decode(bytes, startingAt: .ethernet, into: &stack)

        #expect(stack.networkFlow?.source.description == "192.0.2.1")
        #expect(stack.transportFlow?.destination.port == 53)
        #expect(stack.connectionKey != nil)
        // The connection key matches the boxed Packet path.
        let reference = Packet.decode(bytes, startingAt: .ethernet, using: .standard)
        #expect(stack.connectionKey == reference.connectionKey)
        #expect(stack.isTransportChecksumValid == true)
        #expect(stack.isNetworkChecksumValid == true)
    }

    @Test("fast path and Packet.decode agree on many random packets")
    func fuzzParity() {
        let decoder = StackDecoder()
        var stack = DecodedStack()
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<1000 {
            let count = Int.random(in: 0...80, using: &generator)
            var bytes = [UInt8](repeating: 0, count: count)
            for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max, using: &generator) }
            let data = Data(bytes)

            let reference = Packet.decode(data, startingAt: .ethernet, using: .standard)
            decoder.decode(data, startingAt: .ethernet, into: &stack)
            // The recorded layer sequence must match the reference exactly.
            #expect(stack.layerTypes == reference.layers.map(\.layerType))
        }
    }
}
