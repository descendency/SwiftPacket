import Foundation
import Testing

@testable import SwiftPacket

@Suite("ICMP enrichment — echo fields, named types, quoted packets")
struct ICMPQuoteTests {

    // A quoted IPv4+UDP flow: 192.0.2.1:49152 -> 192.0.2.2:53. The RFC-minimum
    // quote — the 20-byte IP header plus exactly eight payload bytes.
    static let quotedIPv4UDP: [UInt8] = [
        0x45, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xC0, 0x00, 0x02, 0x01,
        0xC0, 0x00, 0x02, 0x02,
        0xC0, 0x00, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00,  // UDP header
    ]

    // Same shape but proto TCP: only the first 8 bytes of the TCP header fit.
    static let quotedIPv4TCP: [UInt8] = [
        0x45, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xC0, 0x00, 0x02, 0x01,
        0xC0, 0x00, 0x02, 0x02,
        0x1F, 0x90, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01,  // ports + seq
    ]

    @Test("ICMPv4 echo request exposes identifier and sequence")
    func echoFields() throws {
        let bytes: [UInt8] = [0x08, 0x00, 0x00, 0x00, 0xBE, 0xEF, 0x00, 0x07, 0x70, 0x69]
        let result = try ICMPv4Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv4)
        #expect(icmp.identifier == 0xBEEF)
        #expect(icmp.sequenceNumber == 7)
        #expect(icmp.typeName == "EchoRequest")
        #expect(!icmp.isError)
        #expect(icmp.quotedData == nil)
        #expect(icmp.quotedFlow == nil)
    }

    @Test("ICMPv4 destination unreachable quotes the offending packet")
    func v4Unreachable() throws {
        // Type 3 (unreachable), code 3 (port unreachable).
        let bytes: [UInt8] = [3, 3, 0, 0, 0, 0, 0, 0] + Self.quotedIPv4UDP
        let result = try ICMPv4Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv4)

        #expect(icmp.isError && icmp.isDestinationUnreachable)
        #expect(icmp.typeName == "DestinationUnreachable")

        // The full decode path sees the quoted IP and UDP layers.
        let quoted = try #require(icmp.quotedPacket(using: .standard))
        #expect(quoted.layer(IPv4.self)?.destinationAddress.description == "192.0.2.2")
        #expect(quoted.layer(UDP.self)?.destinationPort == 53)

        // The lenient flow accessor agrees.
        let flow = try #require(icmp.quotedFlow)
        #expect(flow.source.description == "192.0.2.1")
        #expect(flow.destination.description == "192.0.2.2")
        #expect(flow.proto == .udp)
        #expect(flow.sourcePort == 49152)
        #expect(flow.destinationPort == 53)
    }

    @Test("a truncated TCP quote still yields ports via quotedFlow")
    func v4TruncatedTCPQuote() throws {
        // Time exceeded (traceroute's bread and butter).
        let bytes: [UInt8] = [11, 0, 0, 0, 0, 0, 0, 0] + Self.quotedIPv4TCP
        let result = try ICMPv4Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv4)
        #expect(icmp.isTimeExceeded)

        // The eight quoted bytes are not a whole TCP header, so the full
        // decode ends in a failure layer — but the IP layer is intact...
        let quoted = try #require(icmp.quotedPacket(using: .standard))
        #expect(quoted.layer(IPv4.self)?.proto == .tcp)
        #expect(quoted.layer(TCP.self) == nil)
        #expect(quoted.decodeFailure != nil)

        // ...and the lenient flow accessor still recovers the ports.
        let flow = try #require(icmp.quotedFlow)
        #expect(flow.proto == .tcp)
        #expect(flow.sourcePort == 8080)
        #expect(flow.destinationPort == 443)
    }

    @Test("fragmentation-needed exposes the next-hop MTU")
    func v4NextHopMTU() throws {
        let bytes: [UInt8] = [3, 4, 0, 0, 0, 0, 0x05, 0xDC] + Self.quotedIPv4UDP
        let result = try ICMPv4Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv4)
        #expect(icmp.nextHopMTU == 1500)
    }

    @Test("ICMPv6 echo carries identifier and sequence in the body")
    func v6Echo() throws {
        let bytes: [UInt8] = [128, 0, 0, 0, 0xCA, 0xFE, 0x00, 0x2A, 0x70, 0x69]
        let result = try ICMPv6Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv6)
        #expect(icmp.isEchoRequest)
        #expect(icmp.identifier == 0xCAFE)
        #expect(icmp.sequenceNumber == 42)
        #expect(icmp.typeName == "EchoRequest")
        #expect(!icmp.isError)
    }

    @Test("ICMPv6 packet-too-big quotes the offending IPv6 packet with its MTU")
    func v6PacketTooBig() throws {
        var quoted: [UInt8] = [0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40]
        quoted += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        quoted += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
        quoted += [0x00, 0x35, 0xC0, 0x00, 0x00, 0x08, 0x00, 0x00]  // UDP 53 -> 49152

        // Type 2, then a 4-byte MTU of 1280.
        let bytes: [UInt8] = [2, 0, 0, 0, 0x00, 0x00, 0x05, 0x00] + quoted
        let result = try ICMPv6Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv6)

        #expect(icmp.isError)
        #expect(icmp.mtu == 1280)
        #expect(icmp.typeName == "PacketTooBig")

        let packet = try #require(icmp.quotedPacket(using: .standard))
        #expect(packet.layer(IPv6.self)?.sourceAddress.description == "2001:db8::1")
        #expect(packet.layer(UDP.self)?.sourcePort == 53)

        let flow = try #require(icmp.quotedFlow)
        #expect(flow.proto == .udp)
        #expect(flow.source.description == "2001:db8::1")
        #expect(flow.destination.description == "2001:db8::2")
        #expect(flow.sourcePort == 53)
        #expect(flow.destinationPort == 49152)
    }

    @Test("garbage quotes never trap, just yield nil flows")
    func garbageQuotes() throws {
        // An error message whose "quote" is junk.
        let bytes: [UInt8] = [3, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        let result = try ICMPv4Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv4)
        #expect(icmp.quotedFlow == nil)

        // ICMPv6 error with an empty body.
        let v6 = try ICMPv6Decoder().decode(Data([1, 0, 0, 0]))
        let icmp6 = try #require(v6.layer as? ICMPv6)
        #expect(icmp6.quotedData == nil)
        #expect(icmp6.quotedFlow == nil)
    }
}
