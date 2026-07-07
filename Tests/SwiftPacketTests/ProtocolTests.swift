import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 3 — protocol decoders")
struct ProtocolTests {

    // MARK: - Byte fixtures

    // Ethernet II header: dst aa*6, src bb*6, type IPv4.
    static let ethernetHeader: [UInt8] = [
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0x08, 0x00,
    ]

    // IPv4: 20-byte header, total length 57, proto UDP, 192.0.2.1 -> 192.0.2.2.
    static let ipv4Header: [UInt8] = [
        0x45, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xC0, 0x00, 0x02, 0x01,
        0xC0, 0x00, 0x02, 0x02,
    ]

    // UDP: src 49152, dst 53, length 37.
    static let udpHeader: [UInt8] = [
        0xC0, 0x00, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00,
    ]

    // DNS query for example.com, type A, RD set.
    static let dnsQuery: [UInt8] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x03, 0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x01, 0x00, 0x01,
    ]

    // DNS response: answer name is a compression pointer (0xC00C) back to the
    // question name at offset 12; A record 93.184.216.34.
    static let dnsResponse: [UInt8] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x03, 0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x04, 0x5D, 0xB8, 0xD8, 0x22,
    ]

    // MARK: - Address value types

    @Test("MAC and IP address formatting")
    func addressFormatting() {
        #expect(MACAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])?.description == "01:23:45:67:89:ab")
        #expect(IPv4Address(rawValue: 0xC000_0201).description == "192.0.2.1")

        let v6 = IPv6Address(Data([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        #expect(v6?.description == "2001:db8::1")
        #expect(IPv6Address(Data(repeating: 0, count: 16))?.description == "::")
    }

    // MARK: - Individual decoders

    @Test("Ethernet header decodes and selects the next layer")
    func ethernet() throws {
        let result = try EthernetDecoder().decode(Data(Self.ethernetHeader + [0x01, 0x02]))
        let layer = try #require(result.layer as? Ethernet)
        #expect(layer.destination == MACAddress([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]))
        #expect(layer.source == MACAddress([0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]))
        #expect(layer.etherType == .ipv4)
        if case let .next(type, _) = result.next {
            #expect(type == .ipv4)
        } else {
            Issue.record("expected a next layer")
        }
    }

    @Test("IPv4 header fields and payload clamping")
    func ipv4() throws {
        let result = try IPv4Decoder().decode(Data(Self.ipv4Header + Self.udpHeader))
        let ip = try #require(result.layer as? IPv4)
        #expect(ip.version == 4)
        #expect(ip.headerLength == 20)
        #expect(ip.proto == .udp)
        #expect(ip.sourceAddress.description == "192.0.2.1")
        #expect(ip.destinationAddress.description == "192.0.2.2")
        #expect(ip.ttl == 64)
    }

    @Test("IPv6 header decodes and chains to UDP")
    func ipv6() throws {
        var bytes: [UInt8] = [0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]  // src
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]  // dst
        bytes += [0x00, 0x35, 0xC0, 0x00, 0x00, 0x08, 0x00, 0x00]  // UDP header

        let result = try IPv6Decoder().decode(Data(bytes))
        let ip = try #require(result.layer as? IPv6)
        #expect(ip.version == 6)
        #expect(ip.nextHeader == .udp)
        #expect(ip.hopLimit == 64)
        #expect(ip.sourceAddress.description == "2001:db8::1")
    }

    @Test("ARP request decodes with typed sender/target accessors")
    func arp() throws {
        let bytes: [UInt8] = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0xC0, 0x00, 0x02, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x02, 0x02,
        ]
        let result = try ARPDecoder().decode(Data(bytes))
        let arp = try #require(result.layer as? ARP)
        #expect(arp.op == .request)
        #expect(arp.senderMAC?.description == "11:22:33:44:55:66")
        #expect(arp.senderIPv4?.description == "192.0.2.1")
        #expect(arp.targetIPv4?.description == "192.0.2.2")
    }

    @Test("TCP flags, header length, and options")
    func tcp() throws {
        let bytes: [UInt8] = [
            0x00, 0x50, 0x1F, 0x90,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02,
            0x60, 0x12, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00,
            0x02, 0x04, 0x05, 0xB4,  // MSS option
            0x41, 0x42,  // payload "AB"
        ]
        let result = try TCPDecoder().decode(Data(bytes))
        let tcp = try #require(result.layer as? TCP)
        #expect(tcp.sourcePort == 80)
        #expect(tcp.destinationPort == 8080)
        #expect(tcp.headerLength == 24)
        #expect(tcp.syn && tcp.ack)
        #expect(!tcp.fin && !tcp.rst)
        #expect(tcp.options.count == 4)
        #expect(Array(tcp.payload) == [0x41, 0x42])
    }

    @Test("ICMPv4 echo request")
    func icmpv4() throws {
        let bytes: [UInt8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x70, 0x69]
        let result = try ICMPv4Decoder().decode(Data(bytes))
        let icmp = try #require(result.layer as? ICMPv4)
        #expect(icmp.type == 8)
        #expect(icmp.isEchoRequest)
    }

    // MARK: - Full stack and compression

    @Test("full Ethernet / IPv4 / UDP / DNS stack decodes end to end")
    func fullStack() {
        let bytes = Data(Self.ethernetHeader + Self.ipv4Header + Self.udpHeader + Self.dnsQuery)
        let info = CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: bytes.count, originalLength: bytes.count)
        let captured = CapturedPacket(data: bytes, info: info, linkType: .ethernet)

        let packet = captured.decoded(using: .standard)
        #expect(packet.summary == "Ethernet | IPv4 | UDP | DNS")

        #expect(packet.layer(IPv4.self)?.sourceAddress.description == "192.0.2.1")
        #expect(packet.layer(UDP.self)?.destinationPort == 53)

        let dns = packet.layer(DNS.self)
        #expect(dns?.questions.first?.name == "example.com")
        #expect(dns?.questions.first?.type == 1)
        #expect(dns?.recursionDesired == true)

        // Semantic accessors resolve by category.
        #expect(packet.networkLayer is IPv4)
        #expect(packet.transportLayer is UDP)
    }

    @Test("DNS response follows a compression pointer to resolve the answer name")
    func dnsCompression() throws {
        let result = try DNSDecoder().decode(Data(Self.dnsResponse))
        let dns = try #require(result.layer as? DNS)
        #expect(dns.isResponse)
        #expect(dns.answers.count == 1)
        #expect(dns.answers.first?.name == "example.com")
        #expect(dns.answers.first?.ipv4?.description == "93.184.216.34")
    }

    // MARK: - Robustness (ties back to Phase 2 guarantees)

    @Test("a truncated frame yields a DecodeFailure rather than crashing")
    func truncatedFrame() {
        let info = CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: 3, originalLength: 3)
        let captured = CapturedPacket(data: Data([0xAA, 0xAA, 0xAA]), info: info, linkType: .ethernet)
        let packet = captured.decoded(using: .standard)
        #expect(packet.decodeFailure != nil)
    }

    @Test("a bogus IP version in a raw-IP capture fails gracefully")
    func bogusRawIP() {
        let info = CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: 4, originalLength: 4)
        let captured = CapturedPacket(data: Data([0x00, 0x00, 0x00, 0x00]), info: info, linkType: .raw)
        let packet = captured.decoded(using: .standard)
        #expect(packet.decodeFailure != nil)
    }
}
