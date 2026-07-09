import Foundation
import Testing

@testable import SwiftPacket

@Suite("TLS — records, hellos, certificates, JA3")
struct TLSTests {

    // MARK: - Fixture builders

    /// Wraps `fragment` in a TLS record header.
    static func record(type: UInt8, _ fragment: [UInt8]) -> [UInt8] {
        [type, 0x03, 0x03, UInt8(fragment.count >> 8), UInt8(fragment.count & 0xFF)] + fragment
    }

    /// Wraps a handshake body in its message header.
    static func handshake(type: UInt8, _ body: [UInt8]) -> [UInt8] {
        [type, UInt8(body.count >> 16), UInt8((body.count >> 8) & 0xFF), UInt8(body.count & 0xFF)]
            + body
    }

    static func u16(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 0xFF)] }

    static func ext(_ type: UInt16, _ content: [UInt8]) -> [UInt8] {
        u16(type) + u16(UInt16(content.count)) + content
    }

    /// A ClientHello for `example.com` offering h2/http1.1, with GREASE mixed
    /// into the ciphers and groups. JA3 string:
    /// `771,4865-4866-49199,0-10-11-16-43-13,29-23,0`
    static func clientHelloBody() -> [UInt8] {
        var body: [UInt8] = []
        body += u16(0x0303)  // legacy version
        body += Array(0..<32)  // random
        body += [0]  // session id: empty

        let ciphers: [UInt16] = [0x1301, 0x1302, 0xC02F, 0x0A0A]  // last is GREASE
        body += u16(UInt16(ciphers.count * 2)) + ciphers.flatMap(u16)
        body += [1, 0]  // compression: null

        var extensions: [UInt8] = []
        let name = Array("example.com".utf8)
        extensions += ext(0, u16(UInt16(name.count + 3)) + [0] + u16(UInt16(name.count)) + name)
        extensions += ext(10, u16(6) + u16(0x001D) + u16(0x0017) + u16(0x1A1A))  // groups + GREASE
        extensions += ext(11, [1, 0])  // point formats: uncompressed
        let alpn: [UInt8] = [2] + Array("h2".utf8) + [8] + Array("http/1.1".utf8)
        extensions += ext(16, u16(UInt16(alpn.count)) + alpn)
        extensions += ext(43, [4] + u16(0x0304) + u16(0x0303))  // supported versions
        extensions += ext(13, u16(4) + u16(0x0403) + u16(0x0804))  // signature algorithms
        body += u16(UInt16(extensions.count)) + extensions
        return body
    }

    /// A TLS 1.2 ServerHello selecting ECDHE-RSA-AES128-GCM-SHA256 and h2.
    /// JA3S string: `771,49199,16`
    static func serverHelloBody() -> [UInt8] {
        var body: [UInt8] = []
        body += u16(0x0303)
        body += Array(repeating: 0xAB, count: 32)
        body += [0]
        body += u16(0xC02F)
        body += [0]
        let alpn: [UInt8] = [2] + Array("h2".utf8)
        body += u16(UInt16(ext(16, u16(UInt16(alpn.count)) + alpn).count))
            + ext(16, u16(UInt16(alpn.count)) + alpn)
        return body
    }

    /// A Certificate handshake message carrying the RSA test certificate.
    static func certificateBody() -> [UInt8] {
        let der = Array(X509Tests.rsaCertificate)
        let entry = [UInt8(der.count >> 16), UInt8((der.count >> 8) & 0xFF), UInt8(der.count & 0xFF)] + der
        let total = [UInt8(entry.count >> 16), UInt8((entry.count >> 8) & 0xFF), UInt8(entry.count & 0xFF)]
        return total + entry
    }

    // MARK: - ClientHello

    @Test("ClientHello parses SNI, ALPN, ciphers, and computes JA3")
    func clientHello() throws {
        let data = Data(Self.record(type: 22, Self.handshake(type: 1, Self.clientHelloBody())))
        let tls = try TLSDecoder.parse(data)

        #expect(tls.records.count == 1)
        #expect(tls.records.first?.isHandshake == true)
        #expect(!tls.isTruncated)

        let hello = try #require(tls.clientHello)
        #expect(hello.serverName == "example.com")
        #expect(tls.serverName == "example.com")
        #expect(hello.alpnProtocols == ["h2", "http/1.1"])
        #expect(hello.cipherSuites == [0x1301, 0x1302, 0xC02F, 0x0A0A])
        #expect(hello.supportedGroups == [0x001D, 0x0017, 0x1A1A])
        #expect(hello.supportedVersions == [0x0304, 0x0303])
        #expect(hello.signatureAlgorithms == [0x0403, 0x0804])

        // GREASE (0x0A0A cipher, 0x1A1A group) is excluded from JA3.
        #expect(hello.ja3String == "771,4865-4866-49199,0-10-11-16-43-13,29-23,0")
        #expect(hello.ja3 == "71951104ba98b6430c7a17fb1cb2cb77")
    }

    // MARK: - Server flight

    @Test("ServerHello and Certificate in one flight: JA3S and parsed X.509")
    func serverFlight() throws {
        let flight =
            Self.record(type: 22, Self.handshake(type: 2, Self.serverHelloBody()))
            + Self.record(type: 22, Self.handshake(type: 11, Self.certificateBody()))
        let tls = try TLSDecoder.parse(Data(flight))

        #expect(tls.records.count == 2)
        let hello = try #require(tls.serverHello)
        #expect(hello.cipherSuite == 0xC02F)
        #expect(hello.alpnProtocol == "h2")
        #expect(hello.negotiatedVersion == 0x0303)
        #expect(hello.ja3sString == "771,49199,16")
        #expect(hello.ja3s == "896415616b22361262d7a961b6325cfd")

        // The certificate chain is exposed raw and parsed.
        #expect(tls.certificateDERs.count == 1)
        let cert = try #require(tls.certificates.first)
        #expect(cert.subject.commonName == "test.swiftpacket.example")
        #expect(cert.publicKeyBits == 2048)
    }

    @Test("a handshake message spanning two records is reassembled")
    func spanningRecords() throws {
        let message = Self.handshake(type: 11, Self.certificateBody())
        let half = message.count / 2
        let bytes = Self.record(type: 22, Array(message[..<half]))
            + Self.record(type: 22, Array(message[half...]))
        let tls = try TLSDecoder.parse(Data(bytes))

        #expect(tls.records.count == 2)
        #expect(tls.certificates.first?.subject.commonName == "test.swiftpacket.example")
    }

    @Test("truncation is reported, parsed prefix retained")
    func truncation() throws {
        let full = Self.record(type: 22, Self.handshake(type: 2, Self.serverHelloBody()))
            + Self.record(type: 22, Self.handshake(type: 11, Self.certificateBody()))
        // Cut mid-way through the certificate record.
        let cut = full.count - 200
        let tls = try TLSDecoder.parse(Data(full[..<cut]))

        #expect(tls.isTruncated)
        #expect(tls.serverHello != nil)  // the complete message survived
        #expect(tls.certificates.isEmpty)  // the truncated one did not
    }

    // MARK: - Wiring

    @Test("a TCP payload that looks like TLS decodes as a TLS layer")
    func endToEnd() {
        let hello = Self.record(type: 22, Self.handshake(type: 1, Self.clientHelloBody()))

        var tcp: [UInt8] = []
        tcp += [0xC0, 0x00, 0x01, 0xBB]  // 49152 -> 443
        tcp += [0, 0, 0, 1, 0, 0, 0, 0]
        tcp += [0x50, 0x18, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]
        tcp += hello

        let total = 20 + tcp.count
        var ip: [UInt8] = [0x45, 0x00] + Self.u16(UInt16(total))
        ip += [0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00]
        ip += [0xC0, 0x00, 0x02, 0x01, 0xC0, 0x00, 0x02, 0x02]

        let packet = Packet.decode(
            Data(ProtocolTests.ethernetHeader + ip + tcp), startingAt: .ethernet, using: .standard)
        #expect(packet.summary == "Ethernet | IPv4 | TCP | TLS")
        #expect(packet.layer(TLS.self)?.serverName == "example.com")
    }

    @Test("non-TLS TCP payloads stay opaque")
    func nonTLSPayload() throws {
        let result = try TCPDecoder().decode(
            Data([
                0x00, 0x50, 0x1F, 0x90, 0, 0, 0, 1, 0, 0, 0, 2,
                0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0,
            ] + Array("GET / HTTP/1.1\r\n".utf8)))
        if case let .next(type, _) = result.next {
            #expect(type == .payload)
        } else {
            Issue.record("expected a next layer")
        }
    }

    @Test("application-data records parse without handshake content")
    func applicationData() throws {
        let bytes = Self.record(type: 23, [0xDE, 0xAD, 0xBE, 0xEF])
        let tls = try TLSDecoder.parse(Data(bytes))
        #expect(tls.records.first?.isApplicationData == true)
        #expect(tls.clientHello == nil && tls.serverHello == nil)
        #expect(tls.certificates.isEmpty)
    }

    @Test("GREASE detection matches RFC 8701's sixteen values")
    func grease() {
        let greaseValues = stride(from: 0x0A0A, through: 0xFAFA, by: 0x1010).map { UInt16($0) }
        for value in greaseValues { #expect(isGREASE(value)) }
        for value: UInt16 in [0x1301, 0x0A1A, 0x1A0A, 0x000A, 0x0A00] {
            #expect(!isGREASE(value))
        }
    }

    @Test("a genuine openssl s_client ClientHello parses with a verified JA3")
    func realClientHello() throws {
        // Captured from `openssl s_client -servername real.swiftpacket.example
        // -alpn h2,http/1.1` (LibreSSL). The JA3 below was computed by an
        // independent implementation.
        let bytes = Data(base64Encoded: """
            FgMBAU0BAAFJAwPQYG19S4H7/opXDqYiiWJr97UhorrHmnNRSs8IM8rZ4yCYD+R/c2loPEjEswihbCk1ncV9N8HcFqfdPlIy\
            Gp/wTwBiEwMTAhMBzKnMqMyqwDDALMAowCTAFMAKAJ8AawA5/4UAxACIAIEAnQA9ADUAwACEwC/AK8AnwCPAE8AJAJ4AZwAz\
            AL4ARQCcADwALwC6AEHAEcAHAAUABMASwAgAFgAKAP8BAACeACsACQgDBAMDAwIDAQAzACYAJAAdACDbNrht22VgcqVWyhQA\
            HHSm7U2wIA8EnpJFCpd6PyZYDgAAAB0AGwAAGHJlYWwuc3dpZnRwYWNrZXQuZXhhbXBsZQALAAIBAAAKAAoACAAdABcAGAAZ\
            ACMAAAANABgAFggGBgEGAwgFBQEFAwgEBAEEAwIBAgMAEAAOAAwCaDIIaHR0cC8xLjE=
            """)!

        let tls = try TLSDecoder.parse(bytes)
        let hello = try #require(tls.clientHello)
        #expect(hello.serverName == "real.swiftpacket.example")
        #expect(hello.alpnProtocols == ["h2", "http/1.1"])
        #expect(hello.supportedVersions == [0x0304, 0x0303, 0x0302, 0x0301])
        #expect(hello.ja3 == "0dcde0fb73b656fd510af1874f13fb8b")
    }

    @Test("random bytes never trap the TLS decoder")
    func fuzz() {
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<500 {
            let count = Int.random(in: 0...300, using: &generator)
            var bytes = [UInt8](repeating: 0, count: count)
            for index in bytes.indices {
                bytes[index] = UInt8.random(in: .min ... .max, using: &generator)
            }
            _ = try? TLSDecoder.parse(Data(bytes))
        }
    }
}
