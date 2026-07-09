import Foundation

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// One attribute of an X.509 distinguished name, e.g. `CN = example.com`.
public struct X509NameAttribute: Sendable, Hashable {
    /// The attribute type as a dotted-decimal OID, e.g. `"2.5.4.3"`.
    public let oid: String
    public let value: String

    /// The conventional short name for ``oid`` (`"CN"`, `"O"`, …), if known.
    public var shortName: String? {
        switch oid {
        case "2.5.4.3": return "CN"
        case "2.5.4.5": return "serialNumber"
        case "2.5.4.6": return "C"
        case "2.5.4.7": return "L"
        case "2.5.4.8": return "ST"
        case "2.5.4.10": return "O"
        case "2.5.4.11": return "OU"
        case "2.5.4.97": return "organizationIdentifier"
        case "1.2.840.113549.1.9.1": return "emailAddress"
        case "0.9.2342.19200300.100.1.25": return "DC"
        default: return nil
        }
    }
}

/// An X.509 distinguished name (an issuer or subject).
public struct X509DistinguishedName: Sendable, Hashable, CustomStringConvertible {
    /// The name's attributes, in the order they were encoded.
    public let attributes: [X509NameAttribute]

    /// The first attribute with the given OID.
    public func first(_ oid: String) -> String? {
        attributes.first { $0.oid == oid }?.value
    }

    public var commonName: String? { first("2.5.4.3") }
    public var organization: String? { first("2.5.4.10") }
    public var organizationalUnit: String? { first("2.5.4.11") }
    public var country: String? { first("2.5.4.6") }
    public var locality: String? { first("2.5.4.7") }
    public var stateOrProvince: String? { first("2.5.4.8") }

    /// The name in the familiar one-line form, e.g.
    /// `"CN=example.com, O=Example Corp, C=US"`.
    public var description: String {
        attributes
            .map { "\($0.shortName ?? $0.oid)=\($0.value)" }
            .joined(separator: ", ")
    }
}

/// A subject-alternative-name entry.
public enum X509AlternativeName: Sendable, Hashable {
    case dns(String)
    case ipv4(IPv4Address)
    case ipv6(IPv6Address)
    case email(String)
    case uri(String)

    /// The name as a plain string, without its kind.
    public var value: String {
        switch self {
        case .dns(let name): return name
        case .ipv4(let address): return address.description
        case .ipv6(let address): return address.description
        case .email(let address): return address
        case .uri(let uri): return uri
        }
    }
}

/// A parsed X.509 v3 certificate (RFC 5280) — the fields that matter for
/// network forensics: identity, validity, key, and fingerprints.
///
/// Parse one directly from DER bytes (as carried in a TLS `Certificate`
/// message, possibly reassembled from a TCP stream by the caller):
///
/// ```swift
/// let certificate = try X509Certificate(der: derBytes)
/// certificate.subject.commonName   // "example.com"
/// certificate.sha256Fingerprint    // "3f2a…"
/// ```
public struct X509Certificate: Sendable {
    /// The complete DER encoding the certificate was parsed from.
    public let der: Data

    /// The X.509 version: 1, 2, or 3.
    public let version: Int
    /// The certificate serial number, as its raw big-endian bytes.
    public let serialNumber: Data
    public let issuer: X509DistinguishedName
    public let subject: X509DistinguishedName
    public let notBefore: Date
    public let notAfter: Date

    /// The signature algorithm as a dotted-decimal OID.
    public let signatureAlgorithmOID: String
    /// The subject public key algorithm as a dotted-decimal OID.
    public let publicKeyAlgorithmOID: String
    /// The size of the subject public key in bits (the RSA modulus size or
    /// the EC curve size), where it could be determined.
    public let publicKeyBits: Int?

    /// The subject alternative names, in encoded order.
    public let subjectAlternativeNames: [X509AlternativeName]
    /// The CA flag from a basic-constraints extension, or `nil` if the
    /// certificate has none.
    public let isCA: Bool?
    /// Whether the certificate is self-issued (issuer equals subject).
    public var isSelfIssued: Bool { issuer == subject }

    /// The serial number as lowercase hex.
    public var serialNumberHex: String { Self.hex(serialNumber) }

    /// A human name for the signature algorithm, falling back to the OID.
    public var signatureAlgorithm: String {
        Self.algorithmName(signatureAlgorithmOID) ?? signatureAlgorithmOID
    }

    /// A human name for the public key algorithm, falling back to the OID.
    public var publicKeyAlgorithm: String {
        Self.algorithmName(publicKeyAlgorithmOID) ?? publicKeyAlgorithmOID
    }

    /// The SHA-256 digest of the DER encoding, as lowercase hex.
    public var sha256Fingerprint: String {
        Self.hex(Data(SHA256.hash(data: der)))
    }

    /// The SHA-1 digest of the DER encoding, as lowercase hex. Provided for
    /// interoperability with tools that key on SHA-1 fingerprints.
    public var sha1Fingerprint: String {
        Self.hex(Data(Insecure.SHA1.hash(data: der)))
    }

    /// Whether `date` falls within the certificate's validity window.
    public func isValid(at date: Date = Date()) -> Bool {
        date >= notBefore && date <= notAfter
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func algorithmName(_ oid: String) -> String? {
        switch oid {
        case "1.2.840.113549.1.1.1": return "rsaEncryption"
        case "1.2.840.113549.1.1.5": return "sha1WithRSAEncryption"
        case "1.2.840.113549.1.1.10": return "rsassa-pss"
        case "1.2.840.113549.1.1.11": return "sha256WithRSAEncryption"
        case "1.2.840.113549.1.1.12": return "sha384WithRSAEncryption"
        case "1.2.840.113549.1.1.13": return "sha512WithRSAEncryption"
        case "1.2.840.10045.2.1": return "ecPublicKey"
        case "1.2.840.10045.4.3.2": return "ecdsa-with-SHA256"
        case "1.2.840.10045.4.3.3": return "ecdsa-with-SHA384"
        case "1.2.840.10045.4.3.4": return "ecdsa-with-SHA512"
        case "1.3.101.112": return "Ed25519"
        case "1.3.101.113": return "Ed448"
        default: return nil
        }
    }
}

// MARK: - Parsing

extension X509Certificate {
    /// Parses a certificate from its DER encoding.
    ///
    /// Throws ``DecodingError`` when the bytes are not a well-formed
    /// certificate; unknown extensions are skipped, not rejected.
    public init(der: Data) throws {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
        let certificate = try ASN1Element.parse(der)
        guard certificate.isUniversal(ASN1Element.tagSequence) else {
            throw DecodingError.malformed("certificate is not a SEQUENCE")
        }
        let parts = try certificate.children()
        guard parts.count >= 3 else {
            throw DecodingError.malformed("certificate has \(parts.count) parts, expected 3")
        }
        let tbs = parts[0]
        guard tbs.isUniversal(ASN1Element.tagSequence) else {
            throw DecodingError.malformed("tbsCertificate is not a SEQUENCE")
        }

        var fields = try tbs.children().makeIterator()
        var field = fields.next()

        // version [0] EXPLICIT INTEGER DEFAULT v1
        var version = 1
        if let candidate = field, candidate.isContextSpecific(0) {
            if let integer = try candidate.children().first, let value = integer.integerValue {
                version = Int(value) + 1
            }
            field = fields.next()
        }
        self.version = version

        // serialNumber INTEGER
        guard let serial = field, serial.isUniversal(ASN1Element.tagInteger) else {
            throw DecodingError.malformed("certificate serial number missing")
        }
        self.serialNumber = serial.content.drop(while: { $0 == 0 }).isEmpty
            ? Data([0]) : Data(serial.content.drop(while: { $0 == 0 }))

        // signature AlgorithmIdentifier
        guard let signatureAlgorithm = fields.next(),
            let signatureOID = try signatureAlgorithm.children().first?.oidValue
        else {
            throw DecodingError.malformed("certificate signature algorithm missing")
        }
        self.signatureAlgorithmOID = signatureOID

        // issuer Name
        guard let issuer = fields.next() else {
            throw DecodingError.malformed("certificate issuer missing")
        }
        self.issuer = try Self.parseName(issuer)

        // validity SEQUENCE { notBefore, notAfter }
        guard let validity = fields.next() else {
            throw DecodingError.malformed("certificate validity missing")
        }
        let bounds = try validity.children()
        guard bounds.count == 2, let notBefore = bounds[0].timeValue,
            let notAfter = bounds[1].timeValue
        else {
            throw DecodingError.malformed("certificate validity is not two times")
        }
        self.notBefore = notBefore
        self.notAfter = notAfter

        // subject Name
        guard let subject = fields.next() else {
            throw DecodingError.malformed("certificate subject missing")
        }
        self.subject = try Self.parseName(subject)

        // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey }
        guard let spki = fields.next() else {
            throw DecodingError.malformed("certificate public key missing")
        }
        let spkiParts = try spki.children()
        guard spkiParts.count >= 2,
            let keyAlgorithmParts = try? spkiParts[0].children(),
            let keyOID = keyAlgorithmParts.first?.oidValue
        else {
            throw DecodingError.malformed("certificate public key algorithm missing")
        }
        self.publicKeyAlgorithmOID = keyOID
        self.publicKeyBits = Self.keyBits(
            algorithm: keyOID,
            parameters: keyAlgorithmParts.count > 1 ? keyAlgorithmParts[1] : nil,
            key: spkiParts[1]
        )

        // Optional trailing fields: unique IDs [1]/[2], extensions [3].
        var alternativeNames: [X509AlternativeName] = []
        var isCA: Bool?
        while let trailing = fields.next() {
            guard trailing.isContextSpecific(3),
                let extensions = try? trailing.children().first, // SEQUENCE OF Extension
                let list = try? extensions.children()
            else { continue }
            for ext in list {
                guard let extParts = try? ext.children(),
                    let oid = extParts.first?.oidValue,
                    // extnValue OCTET STRING is last; `critical` may sit between.
                    let value = extParts.last,
                    value.isUniversal(ASN1Element.tagOctetString)
                else { continue }
                switch oid {
                case "2.5.29.17":  // subjectAltName
                    alternativeNames = Self.parseAlternativeNames(value.content)
                case "2.5.29.19":  // basicConstraints
                    let inner = try? ASN1Element.parse(value.content).children()
                    isCA = inner?.first?.booleanValue ?? false
                default:
                    continue
                }
            }
        }
        self.subjectAlternativeNames = alternativeNames
        self.isCA = isCA

        self.der = certificate.raw
    }

    /// Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value ANY }
    private static func parseName(_ element: ASN1Element) throws -> X509DistinguishedName {
        guard element.isUniversal(ASN1Element.tagSequence) else {
            throw DecodingError.malformed("X.509 name is not a SEQUENCE")
        }
        var attributes: [X509NameAttribute] = []
        for rdn in try element.children() {
            guard rdn.isUniversal(ASN1Element.tagSet) else { continue }
            for pair in try rdn.children() {
                guard let parts = try? pair.children(), parts.count >= 2,
                    let oid = parts[0].oidValue,
                    let value = parts[1].stringValue
                else { continue }
                attributes.append(X509NameAttribute(oid: oid, value: value))
            }
        }
        return X509DistinguishedName(attributes: attributes)
    }

    /// GeneralNames ::= SEQUENCE OF GeneralName, with context-specific tags
    /// for each kind.
    private static func parseAlternativeNames(_ content: Data) -> [X509AlternativeName] {
        guard let names = try? ASN1Element.parse(content).children() else { return [] }
        var result: [X509AlternativeName] = []
        for name in names {
            guard name.elementClass == .contextSpecific else { continue }
            switch name.tagNumber {
            case 1:
                result.append(.email(String(decoding: name.content, as: UTF8.self)))
            case 2:
                result.append(.dns(String(decoding: name.content, as: UTF8.self)))
            case 6:
                result.append(.uri(String(decoding: name.content, as: UTF8.self)))
            case 7:
                if let address = IPv4Address(name.content) {
                    result.append(.ipv4(address))
                } else if let address = IPv6Address(name.content) {
                    result.append(.ipv6(address))
                }
            default:
                continue
            }
        }
        return result
    }

    private static func keyBits(
        algorithm: String, parameters: ASN1Element?, key: ASN1Element
    ) -> Int? {
        switch algorithm {
        case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
            guard let keyBytes = key.bitStringValue,
                let rsa = try? ASN1Element.parse(keyBytes),
                let children = try? rsa.children(),
                let modulus = children.first,
                modulus.isUniversal(ASN1Element.tagInteger)
            else { return nil }
            return modulus.content.drop(while: { $0 == 0 }).count * 8
        case "1.2.840.10045.2.1":
            // The named curve rides in the algorithm parameters.
            switch parameters?.oidValue {
            case "1.2.840.10045.3.1.7": return 256  // P-256
            case "1.3.132.0.34": return 384  // P-384
            case "1.3.132.0.35": return 521  // P-521
            default: return nil
            }
        case "1.3.101.112": return 256  // Ed25519
        case "1.3.101.113": return 448  // Ed448
        default:
            return nil
        }
    }
}
