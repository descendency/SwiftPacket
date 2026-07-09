import Foundation
import Testing

@testable import SwiftPacket

@Suite("Checksum validation")
struct ChecksumValidationTests {

    /// Builds an Ethernet/IPv4/UDP/DNS packet with correct checksums via the
    /// serializer, so validation has something real to check.
    static func validPacket() throws -> Packet {
        let dns = Packet.decode(
            Data(ProtocolTests.ethernetHeader + ProtocolTests.ipv4Header + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery), startingAt: .ethernet, using: .standard)
        let bytes = try dns.serializedData()  // recomputes IPv4 + UDP checksums
        return Packet.decode(bytes, startingAt: .ethernet, using: .standard)
    }

    @Test("correct IPv4 and UDP checksums validate")
    func valid() throws {
        let packet = try Self.validPacket()
        #expect(packet.isNetworkChecksumValid == true)
        #expect(packet.isTransportChecksumValid == true)
    }

    @Test("a corrupted IPv4 header fails validation")
    func corruptIPv4() throws {
        var bytes = [UInt8](try Self.validPacket().data)
        bytes[14 + 8] ^= 0xFF  // flip the IPv4 TTL byte (offset 8 in the IP header)
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)
        #expect(packet.isNetworkChecksumValid == false)
    }

    @Test("a corrupted UDP payload fails transport validation")
    func corruptTransport() throws {
        var bytes = [UInt8](try Self.validPacket().data)
        bytes[bytes.count - 1] ^= 0xFF  // flip a payload byte
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)
        #expect(packet.isTransportChecksumValid == false)
    }

    @Test("a zero UDP checksum is treated as valid over IPv4")
    func zeroUDPChecksum() {
        // ProtocolTests fixtures have a zero UDP checksum.
        let packet = Packet.decode(
            Data(ProtocolTests.ipv4Header + ProtocolTests.udpHeader + ProtocolTests.dnsQuery),
            startingAt: .ipv4, using: .standard)
        #expect(packet.isTransportChecksumValid == true)
    }

    @Test("TCP checksum validates against a real segment")
    func tcpChecksum() throws {
        // Build IPv4/TCP, serialize (computes the TCP checksum), then verify.
        let payload: [UInt8] = Array("hello".utf8)
        var ip = ProtocolTests.ipv4Header
        ip[9] = 6  // TCP
        var tcp: [UInt8] = [
            0x04, 0xD2, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0,
        ]
        tcp += payload
        let decoded = Packet.decode(Data(ip + tcp), startingAt: .ipv4, using: .standard)
        let bytes = try decoded.serializedData()
        let packet = Packet.decode(bytes, startingAt: .ipv4, using: .standard)
        #expect(packet.isTransportChecksumValid == true)
    }
}

@Suite("Typed address round-trips")
struct AddressStringTests {

    @Test("IPv4 addresses parse and round-trip through description")
    func ipv4() {
        #expect(IPv4Address(string: "192.0.2.1")?.description == "192.0.2.1")
        #expect(IPv4Address(string: "255.255.255.255")?.rawValue == 0xFFFF_FFFF)
        #expect(IPv4Address(string: "0.0.0.0")?.rawValue == 0)
        #expect(IPv4Address(string: "192.0.2.1")?.bytes == [192, 0, 2, 1])

        #expect(IPv4Address(string: "256.0.0.1") == nil)
        #expect(IPv4Address(string: "1.2.3") == nil)
        #expect(IPv4Address(string: "a.b.c.d") == nil)
    }

    @Test("IPv6 addresses parse, including :: compression and embedded IPv4")
    func ipv6() {
        #expect(IPv6Address(string: "2001:db8::1")?.description == "2001:db8::1")
        #expect(IPv6Address(string: "::1")?.description == "::1")
        #expect(IPv6Address(string: "::")?.description == "::")
        #expect(IPv6Address(string: "fe80::1")?.bytes.first == 0xFE)
        #expect(
            IPv6Address(string: "2001:0db8:0000:0000:0000:0000:0000:0001")?.description
                == "2001:db8::1")
        // Embedded IPv4 tail.
        let mapped = IPv6Address(string: "::ffff:192.0.2.128")
        #expect(mapped?.bytes.suffix(4) == [192, 0, 2, 128])
        #expect(mapped?.bytes[10] == 0xFF && mapped?.bytes[11] == 0xFF)

        #expect(IPv6Address(string: "2001:db8:::1") == nil)  // double "::"
        #expect(IPv6Address(string: "gggg::1") == nil)
        #expect(IPv6Address(string: "1:2:3:4:5:6:7:8:9") == nil)  // too many groups
    }

    @Test("string parse round-trips through bytes for every fixture")
    func roundTrip() {
        for text in ["::", "::1", "2001:db8::1", "fe80::abcd:1234", "ff02::1"] {
            let address = IPv6Address(string: text)
            #expect(address != nil)
            // Re-parsing the description yields the same bytes.
            #expect(IPv6Address(string: address!.description)?.bytes == address?.bytes)
        }
    }
}

@Suite("Fingerprints — JA4, JA4S, HASSH, Community ID")
struct FingerprintTests {

    @Test("JA4 matches an independent computation of the client fixture")
    func ja4() {
        let hello = TLSDecoder.parseClientHello(Data(TLSTests.clientHelloBody()))
        let ja4 = try? #require(hello?.ja4)
        #expect(ja4 == "t13d0306h2_40b44b994229_fb71836bce29")
    }

    @Test("JA4S matches an independent computation of the server fixture")
    func ja4s() {
        let hello = TLSDecoder.parseServerHello(Data(TLSTests.serverHelloBody()))
        #expect(hello?.ja4s == "t1201h2_c02f_0b08e3dcc50f")
    }

    @Test("HASSH matches the MD5 of the client KEXINIT algorithm lists")
    func hassh() {
        let kexInit = SSHKEXInitTests.sampleKEXInit()
        #expect(kexInit.hassh == "ac29ecc577efbcf842470d0d7a1c9800")
    }

    @Test("Community ID matches the published reference vector, both directions")
    func communityID() {
        func tcpPacket(src: String, sport: UInt16, dst: String, dport: UInt16) -> Packet {
            var ip = ProtocolTests.ipv4Header
            ip[9] = 6  // TCP
            ip.replaceSubrange(12..<16, with: IPv4Address(string: src)!.octets)
            ip.replaceSubrange(16..<20, with: IPv4Address(string: dst)!.octets)
            let tcp: [UInt8] = [
                UInt8(sport >> 8), UInt8(sport & 0xFF), UInt8(dport >> 8), UInt8(dport & 0xFF),
                0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0xFF, 0xFF, 0, 0, 0, 0,
            ]
            return Packet.decode(Data(ip + tcp), startingAt: .ipv4, using: .standard)
        }

        let forward = tcpPacket(src: "128.232.110.120", sport: 34855, dst: "66.35.250.204", dport: 80)
        let reverse = tcpPacket(src: "66.35.250.204", sport: 80, dst: "128.232.110.120", dport: 34855)
        #expect(forward.communityID() == "1:LQU9qZlK+B5F3KDmev6m5PMibrg=")
        #expect(forward.communityID() == reverse.communityID())
    }
}

@Suite("Stateless HTTP + SSH framers")
struct AppFramerTests {

    @Test("an HTTP request frames its method, target, and Content-Length body")
    func httpRequest() {
        let raw = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"
        guard case let .message(message) = HTTPFramer.parse(Data(raw.utf8)) else {
            Issue.record("expected a parsed message")
            return
        }
        #expect(message.isRequest)
        if case let .request(method, target, version) = message.kind {
            #expect(method == "POST")
            #expect(target == "/submit")
            #expect(version == "HTTP/1.1")
        }
        #expect(message.host == "example.com")
        #expect(message.bodyFraming == .length(5))
        #expect(message.headerLength == raw.utf8.count - 5)  // body is the trailing "hello"
    }

    @Test("an HTTP response frames status and chunked body")
    func httpResponse() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        guard case let .message(message) = HTTPFramer.parse(Data(raw.utf8)) else {
            Issue.record("expected a parsed message")
            return
        }
        if case let .response(_, status, reason) = message.kind {
            #expect(status == 200)
            #expect(reason == "OK")
        }
        #expect(message.bodyFraming == .chunked)
    }

    @Test("incomplete and non-HTTP buffers are distinguished")
    func httpEdgeCases() {
        // No blank line yet.
        if case .incomplete = HTTPFramer.parse(Data("GET / HTTP/1.1\r\nHost: x".utf8)) {
        } else {
            Issue.record("expected incomplete")
        }
        // Not HTTP.
        if case .notHTTP = HTTPFramer.parse(Data("\u{16}\u{03}\u{01}garbage\r\n\r\n".utf8)) {
        } else {
            Issue.record("expected notHTTP")
        }
    }

    @Test("an SSH banner parses its protocol and software versions")
    func sshBanner() {
        let banner = SSHIdentification.parse(Data("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n".utf8))
        #expect(banner?.protocolVersion == "2.0")
        #expect(banner?.softwareVersion == "OpenSSH_9.6p1")
        #expect(banner?.comments == "Ubuntu-3")
        #expect(SSHIdentification.parse(Data("HTTP/1.1 200 OK\r\n".utf8)) == nil)
    }

    @Test("an SSH KEXINIT parses all ten algorithm name-lists")
    func sshKexInit() {
        let kexInit = SSHKEXInitTests.sampleKEXInit()
        #expect(kexInit.kexAlgorithms == ["curve25519-sha256", "ecdh-sha2-nistp256"])
        #expect(kexInit.encryptionAlgorithmsClientToServer.first == "chacha20-poly1305@openssh.com")
        #expect(kexInit.compressionAlgorithmsServerToClient == ["none", "zlib@openssh.com"])
    }
}

/// Shared SSH KEXINIT fixture builder.
enum SSHKEXInitTests {
    static func sampleKEXInit() -> SSHKEXInit {
        let lists = [
            "curve25519-sha256,ecdh-sha2-nistp256",  // kex
            "rsa-sha2-512,ssh-ed25519",  // host key
            "chacha20-poly1305@openssh.com,aes128-ctr",  // enc c2s
            "chacha20-poly1305@openssh.com,aes128-ctr",  // enc s2c
            "umac-64-etm@openssh.com,hmac-sha2-256",  // mac c2s
            "umac-64-etm@openssh.com,hmac-sha2-256",  // mac s2c
            "none,zlib@openssh.com",  // comp c2s
            "none,zlib@openssh.com",  // comp s2c
            "",  // lang c2s
            "",  // lang s2c
        ]
        var payload: [UInt8] = [20]  // SSH_MSG_KEXINIT
        payload += [UInt8](repeating: 0xAB, count: 16)  // cookie
        for list in lists {
            let bytes = Array(list.utf8)
            payload += [UInt8(bytes.count >> 24), UInt8((bytes.count >> 16) & 0xFF),
                        UInt8((bytes.count >> 8) & 0xFF), UInt8(bytes.count & 0xFF)]
            payload += bytes
        }
        payload += [0]  // first_kex_packet_follows
        payload += [0, 0, 0, 0]  // reserved

        // Wrap in the SSH binary packet framing.
        let paddingLength = 4
        let packetLength = payload.count + paddingLength + 1
        var packet: [UInt8] = [
            UInt8(packetLength >> 24), UInt8((packetLength >> 16) & 0xFF),
            UInt8((packetLength >> 8) & 0xFF), UInt8(packetLength & 0xFF), UInt8(paddingLength),
        ]
        packet += payload + [UInt8](repeating: 0, count: paddingLength)
        return SSHKEXInit.parse(Data(packet))!
    }
}

@Suite("IPDefragmenter CapturedPacket round-trip")
struct DefragCapturedTests {

    @Test("reassembly yields a CapturedPacket that re-decodes through the pipeline")
    func capturedRoundTrip() async {
        let inner = ProtocolTests.udpHeader + ProtocolTests.dnsQuery  // 37 bytes
        let first = FragmentBuilder.ipv4Fragment(offset: 0, more: true, payload: Array(inner[0..<16]))
        let second = FragmentBuilder.ipv4Fragment(offset: 16, more: false, payload: Array(inner[16...]))

        func captured(_ data: Data) -> CapturedPacket {
            CapturedPacket(
                data: data,
                info: CaptureInfo(timestamp: .init(timeIntervalSince1970: 1000), captureLength: data.count, originalLength: data.count),
                linkType: .raw)
        }

        let defrag = IPDefragmenter()
        let r1 = await defrag.process(captured(first))
        #expect(r1.captured == nil)  // incomplete

        let r2 = await defrag.process(captured(second))
        let reassembled = try? #require(r2.captured)
        #expect(reassembled?.linkType == .raw)
        #expect(reassembled?.info.timestamp == Date(timeIntervalSince1970: 1000))
        // The reassembled CapturedPacket decodes end-to-end.
        let packet = reassembled?.decoded(using: .standard)
        #expect(packet?.summary == "IPv4 | UDP | DNS")
        #expect(packet?.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    @Test("a non-fragment passes through unchanged")
    func passThrough() async {
        let whole = Data(ProtocolTests.ipv4Header + ProtocolTests.udpHeader + ProtocolTests.dnsQuery)
        let captured = CapturedPacket(
            data: whole,
            info: CaptureInfo(timestamp: .init(timeIntervalSince1970: 0), captureLength: whole.count, originalLength: whole.count),
            linkType: .raw)
        let result = await IPDefragmenter().process(captured)
        #expect(result.captured?.data == whole)
    }
}
