import Foundation
import Testing

@testable import SwiftPacket

@Suite("X.509 certificate parsing")
struct X509Tests {

    // A self-signed RSA-2048 certificate generated with OpenSSL:
    //   subject/issuer CN=test.swiftpacket.example, O=SwiftPacket Test, …
    //   SAN: DNS:test.swiftpacket.example, DNS:*.alt.swiftpacket.example, IP:192.0.2.7
    //   basicConstraints: critical, CA:TRUE
    //   validity: 2026-07-08 10:18:51Z … 2027-07-08 10:18:51Z
    //   serial: FA237774616B2A38
    static let rsaCertificate = Data(base64Encoded: """
        MIID+jCCAuKgAwIBAgIJAPojd3Rhayo4MA0GCSqGSIb3DQEBCwUAMIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv\
        cm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEZMBcGA1UECgwQU3dpZnRQYWNrZXQgVGVzdDEUMBIGA1UECwwLRW5naW5l\
        ZXJpbmcxITAfBgNVBAMMGHRlc3Quc3dpZnRwYWNrZXQuZXhhbXBsZTAeFw0yNjA3MDgxMDE4NTFaFw0yNzA3MDgxMDE4NTFa\
        MIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEZMBcGA1UECgwQ\
        U3dpZnRQYWNrZXQgVGVzdDEUMBIGA1UECwwLRW5naW5lZXJpbmcxITAfBgNVBAMMGHRlc3Quc3dpZnRwYWNrZXQuZXhhbXBs\
        ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKtReFfu5DQPz1irXdCEvcNtTbSXi2cC6MO4itxEM1lXoN+zZdCG\
        tHEW+Dlczv0iGVL78mWdeuNpdGOxMQvTgKxrE8CTVBwxE9jVmJoVAgqHeJb1aMuJzA8VFQdEhW17OyIVFXDjtbmLMLBams2M\
        +/GRbPVv124jI0mpWFmp8Z0m61UgtiPlLSTPQ88RaWdFpCzs5dw8YVfIjjSWhzxQepB6l0RybP661lmmLX68fJfdbTeVHPex\
        FZJ7YeM8j5UIVHElUIJbujyce0rFjVBl5UdgB2/gYjMsHIMT+rD/S8zCu5grGtOmv+czYcPDoPbJTmlVTtQWaSUpHtFflW15\
        GCkCAwEAAaNZMFcwRAYDVR0RBD0wO4IYdGVzdC5zd2lmdHBhY2tldC5leGFtcGxlghkqLmFsdC5zd2lmdHBhY2tldC5leGFt\
        cGxlhwTAAAIHMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKhyNqca6YxANwjC1Hg8de3IVFvPkcNVnst/\
        /EcQTvoga9X4h7UT273jJ5yNNQSahB8fnJ53Dl97OY+VI2YDXudsbaeGmoT5S9Q+BJZ4x1KXQt+gP/ha1fbL0zYZuZlLbbfm\
        jvNP+RAuKzuXC8cOSqM1TEO6ShPsnylb2r5bnFIiOa92IYP1Sh+7EUXXNNXqkFXWbC1iGR1PU8ZGbpfgpY0Tt8UWDL+cKiga\
        0oYE/7oQeyx3hx80kDwVrQ67zrwycj2gWVXaS6tOWTPH9wFRvN7E2c03lFsK8swuESM5ZQud4OeNONsav9te6TBSpJIm1M17\
        XNQUoiuZ/zcT0cTrDaU=
        """)!

    // An ECDSA P-256 certificate with a *named* curve (v1, no extensions).
    static let ecCertificate = Data(base64Encoded: """
        MIIBaTCCAQ4CCQC/+nmVUauxXDAKBggqhkjOPQQDAjA8MRkwFwYDVQQKDBBTd2lmdFBhY2tldCBUZXN0MR8wHQYDVQQDDBZl\
        Yy5zd2lmdHBhY2tldC5leGFtcGxlMB4XDTI2MDcwODEwMTkyMloXDTI3MDcwODEwMTkyMlowPDEZMBcGA1UECgwQU3dpZnRQ\
        YWNrZXQgVGVzdDEfMB0GA1UEAwwWZWMuc3dpZnRwYWNrZXQuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBpl\
        F3ODE10SV1tsIK9t2DSgmejdGHZjlNH/pnt9yY/ix3VpPp0bRVp7E/m3tEOTpKNQPIdUgx4MiHwgISiIWmAwCgYIKoZIzj0E\
        AwIDSQAwRgIhAKj+HKsxEuYivQ+u8YJ05y+PF9xqleB/5XrX0E8NsOk7AiEArwZfW2beNnNd3jVFQeTBBTve9put2feA2L+n\
        Uoez92E=
        """)!

    // The same key type but with *explicit* curve parameters, so the curve
    // (and thus the key size) is not nameable. SHA-1 fingerprint verified
    // against `openssl x509 -fingerprint -sha1`.
    static let ecExplicitCertificate = Data(base64Encoded: """
        MIICXDCCAgICCQD6vR//n1pHhjAKBggqhkjOPQQDAjA8MRkwFwYDVQQKDBBTd2lmdFBhY2tldCBUZXN0MR8wHQYDVQQDDBZl\
        Yy5zd2lmdHBhY2tldC5leGFtcGxlMB4XDTI2MDcwODEwMTkwN1oXDTI3MDcwODEwMTkwN1owPDEZMBcGA1UECgwQU3dpZnRQ\
        YWNrZXQgVGVzdDEfMB0GA1UEAwwWZWMuc3dpZnRwYWNrZXQuZXhhbXBsZTCCAUswggEDBgcqhkjOPQIBMIH3AgEBMCwGByqG\
        SM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP//////////\
        /////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kARBBGsX0fLhLEJH\
        +Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////AAAAAP//////\
        ////vOb6racXnoTzucrC/GMlUQIBAQNCAASkaRs0iVddprwZhq9xQIyFkmr/fdNonK0XEMOKK9VxITl5OLrNddJGFPS2iXVh\
        GQRdLBZwehT4lXVgonnfaT0kMAoGCCqGSM49BAMCA0gAMEUCIF7DazwNENe3/xCLdbinvJPl+8H80Sa7cwCA/VAQ+XQJAiEA\
        vmUyVXCQfAZXtBK3uBHiJ5gzhNs+UKrg8EXIR6nCnZQ=
        """)!

    @Test("a real RSA certificate parses: names, validity, serial, key")
    func rsaCertificate() throws {
        let cert = try X509Certificate(der: Self.rsaCertificate)

        #expect(cert.version == 3)
        #expect(cert.serialNumberHex == "fa237774616b2a38")

        #expect(cert.subject.commonName == "test.swiftpacket.example")
        #expect(cert.subject.organization == "SwiftPacket Test")
        #expect(cert.subject.organizationalUnit == "Engineering")
        #expect(cert.subject.country == "US")
        #expect(cert.subject.stateOrProvince == "California")
        #expect(cert.subject.locality == "San Francisco")
        #expect(cert.isSelfIssued)
        #expect(cert.subject.description.hasPrefix("C=US, ST=California"))

        #expect(cert.signatureAlgorithm == "sha256WithRSAEncryption")
        #expect(cert.publicKeyAlgorithm == "rsaEncryption")
        #expect(cert.publicKeyBits == 2048)

        // Validity: 2026-07-08 10:18:51Z ... 2027-07-08 10:18:51Z.
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let notBefore = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: cert.notBefore)
        #expect(notBefore.year == 2026 && notBefore.month == 7 && notBefore.day == 8)
        #expect(notBefore.hour == 10 && notBefore.minute == 18 && notBefore.second == 51)
        #expect(cert.isValid(at: cert.notBefore.addingTimeInterval(86400)))
        #expect(!cert.isValid(at: cert.notAfter.addingTimeInterval(1)))
    }

    @Test("subject alternative names and basic constraints decode")
    func extensions() throws {
        let cert = try X509Certificate(der: Self.rsaCertificate)

        #expect(cert.subjectAlternativeNames == [
            .dns("test.swiftpacket.example"),
            .dns("*.alt.swiftpacket.example"),
            .ipv4(IPv4Address(rawValue: 0xC000_0207)),
        ])
        #expect(cert.subjectAlternativeNames.map(\.value).contains("192.0.2.7"))
        #expect(cert.isCA == true)
    }

    @Test("fingerprints match OpenSSL's")
    func fingerprints() throws {
        let rsa = try X509Certificate(der: Self.rsaCertificate)
        #expect(rsa.sha256Fingerprint
            == "565f110bb6343560d009074984bd5daa936d9c744e25e25469255c2980fdfd22")

        let ec = try X509Certificate(der: Self.ecExplicitCertificate)
        #expect(ec.sha1Fingerprint == "484fcd186f2b436da1e6ff6774e3b9f42882675d")
    }

    @Test("a v1 ECDSA certificate with a named curve parses")
    func ecCertificate() throws {
        let cert = try X509Certificate(der: Self.ecCertificate)

        #expect(cert.version == 1)
        #expect(cert.subject.commonName == "ec.swiftpacket.example")
        #expect(cert.signatureAlgorithm == "ecdsa-with-SHA256")
        #expect(cert.publicKeyAlgorithm == "ecPublicKey")
        #expect(cert.publicKeyBits == 256)
        #expect(cert.subjectAlternativeNames.isEmpty)
        #expect(cert.isCA == nil)  // no basicConstraints extension at all
    }

    @Test("explicit (unnamed) curve parameters degrade to a nil key size")
    func ecExplicitParameters() throws {
        let cert = try X509Certificate(der: Self.ecExplicitCertificate)
        #expect(cert.publicKeyAlgorithm == "ecPublicKey")
        #expect(cert.publicKeyBits == nil)
        #expect(cert.subject.commonName == "ec.swiftpacket.example")
    }

    @Test("garbage and truncations throw, never trap")
    func robustness() {
        #expect(throws: (any Error).self) {
            _ = try X509Certificate(der: Data([0x30, 0x03, 0x02, 0x01]))
        }
        #expect(throws: (any Error).self) {
            _ = try X509Certificate(der: Data())
        }
        // Every truncation of a real certificate must fail cleanly or parse.
        for length in stride(from: 0, to: Self.rsaCertificate.count, by: 37) {
            _ = try? X509Certificate(der: Self.rsaCertificate.prefix(length))
        }
        // Single-byte corruptions must never trap.
        var corrupt = Self.rsaCertificate
        for index in stride(from: 0, to: corrupt.count, by: 11) {
            let original = corrupt[corrupt.startIndex + index]
            corrupt[corrupt.startIndex + index] = original ^ 0xFF
            _ = try? X509Certificate(der: corrupt)
            corrupt[corrupt.startIndex + index] = original
        }
    }
}
