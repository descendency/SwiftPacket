import Foundation

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

extension LayerType {
    public static let tls = LayerType(id: 13, name: "TLS", category: .application)
}

/// One TLS record (RFC 8446 §5.1): the five-byte header plus its fragment.
public struct TLSRecord: Sendable {
    /// 20 = change_cipher_spec, 21 = alert, 22 = handshake, 23 = application_data.
    public let contentType: UInt8
    /// The version from the record header (`0x0303` for everything modern —
    /// TLS 1.3 masquerades as 1.2 on the wire).
    public let legacyVersion: UInt16
    /// The declared fragment length, which may exceed ``fragment`` when the
    /// record was cut off by the capture's snap length or TCP segmentation.
    public let declaredLength: Int
    /// The fragment bytes actually present.
    public let fragment: Data

    public var isHandshake: Bool { contentType == 22 }
    public var isApplicationData: Bool { contentType == 23 }
    public var isAlert: Bool { contentType == 21 }
    public var isChangeCipherSpec: Bool { contentType == 20 }
}

/// A parsed TLS ClientHello, with the fields a network monitor wants: SNI,
/// ALPN, and the JA3 ingredients.
public struct TLSClientHello: Sendable {
    public let legacyVersion: UInt16
    public let random: Data
    public let sessionID: Data
    public let cipherSuites: [UInt16]
    public let compressionMethods: [UInt8]
    /// Extension type codes, in offered order (GREASE included).
    public let extensionTypes: [UInt16]
    /// The server name from an SNI extension.
    public let serverName: String?
    /// Offered ALPN protocols, e.g. `["h2", "http/1.1"]`.
    public let alpnProtocols: [String]
    /// Supported groups (curves) from extension 10.
    public let supportedGroups: [UInt16]
    /// EC point formats from extension 11.
    public let ecPointFormats: [UInt8]
    /// Offered protocol versions from extension 43 (TLS 1.3).
    public let supportedVersions: [UInt16]
    /// Offered signature schemes from extension 13.
    public let signatureAlgorithms: [UInt16]

    /// The JA3 fingerprint input string
    /// (`version,ciphers,extensions,groups,pointFormats`, GREASE excluded).
    public var ja3String: String {
        let ciphers = dashJoined(cipherSuites.filter { !isGREASE($0) })
        let extensions = dashJoined(extensionTypes.filter { !isGREASE($0) })
        let groups = dashJoined(supportedGroups.filter { !isGREASE($0) })
        let formats = ecPointFormats.map { String($0) }.joined(separator: "-")
        return "\(legacyVersion),\(ciphers),\(extensions),\(groups),\(formats)"
    }

    /// The JA3 fingerprint: the MD5 of ``ja3String``, as lowercase hex.
    public var ja3: String { md5Hex(ja3String) }
}

/// A parsed TLS ServerHello.
public struct TLSServerHello: Sendable {
    public let legacyVersion: UInt16
    public let random: Data
    public let sessionID: Data
    public let cipherSuite: UInt16
    public let compressionMethod: UInt8
    /// Extension type codes, in sent order.
    public let extensionTypes: [UInt16]
    /// The ALPN protocol the server selected.
    public let alpnProtocol: String?
    /// The negotiated version from extension 43, when present (TLS 1.3).
    public let supportedVersion: UInt16?

    /// The version actually negotiated: the supported_versions extension when
    /// present, the legacy field otherwise.
    public var negotiatedVersion: UInt16 { supportedVersion ?? legacyVersion }

    /// The JA3S fingerprint input string (`version,cipher,extensions`).
    public var ja3sString: String {
        "\(legacyVersion),\(cipherSuite),\(dashJoined(extensionTypes))"
    }

    /// The JA3S fingerprint: the MD5 of ``ja3sString``, as lowercase hex.
    public var ja3s: String { md5Hex(ja3sString) }
}

/// TLS records and whatever plaintext handshake content they carry (RFC 8446).
///
/// One decoded layer covers *all* records present in the byte range it was
/// given. Handshake messages that span records within that range are
/// reassembled; a handshake flight that spans multiple **TCP segments** (a
/// certificate chain usually does) cannot be completed from a single packet —
/// for that, reassemble the stream and call ``TLSDecoder/parse(_:)`` on the
/// joined bytes. ``isTruncated`` reports when content ran past the available
/// bytes.
public struct TLS: Layer {
    public static let layerType = LayerType.tls

    public let records: [TLSRecord]
    public let clientHello: TLSClientHello?
    public let serverHello: TLSServerHello?
    /// The raw DER blobs from a Certificate message, in wire order (leaf first).
    public let certificateDERs: [Data]
    /// The certificates that parsed successfully, in wire order.
    public let certificates: [X509Certificate]
    /// Whether a record or handshake message extended past the available bytes.
    public let isTruncated: Bool

    fileprivate let bytes: Data
    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }

    /// The server name (SNI) from the ClientHello, if this is one.
    public var serverName: String? { clientHello?.serverName }
}

/// Decodes TLS records from a TCP payload — or, via ``parse(_:)``, from a
/// reassembled TCP stream.
public struct TLSDecoder: LayerDecoder {
    public init() {}

    /// Whether `data` plausibly starts a TLS record: a known content type,
    /// an SSL3/TLS version, and a nonzero length. Used to route TCP payloads.
    public static func looksLikeTLSRecord(_ data: Data) -> Bool {
        guard data.count >= 5 else { return false }
        let base = data.startIndex
        let contentType = data[base]
        let major = data[base + 1]
        let minor = data[base + 2]
        let length = Int(data[base + 3]) << 8 | Int(data[base + 4])
        return (20...23).contains(contentType) && major == 3 && minor <= 4 && length > 0
    }

    /// Parses TLS content from `data`, which must start at a record boundary.
    public static func parse(_ data: Data) throws -> TLS {
        let result = try TLSDecoder().decode(data)
        // The decoder always returns a TLS layer.
        return result.layer as! TLS
    }

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        var records: [TLSRecord] = []
        var handshakeData = Data()
        var truncated = false

        // Records: type(1) version(2) length(2) fragment.
        while reader.remaining >= 5 {
            let contentType = try reader.readUInt8()
            let version = try reader.readUInt16()
            let declaredLength = Int(try reader.readUInt16())
            guard (20...23).contains(contentType), version >> 8 == 3 else {
                if records.isEmpty {
                    throw DecodingError.malformed("not a TLS record")
                }
                truncated = true  // mid-stream garbage; keep what we have
                break
            }

            let fragment: Data
            if declaredLength <= reader.remaining {
                fragment = try reader.readBytes(declaredLength)
            } else {
                fragment = reader.readRemaining()
                truncated = true
            }
            records.append(
                TLSRecord(
                    contentType: contentType,
                    legacyVersion: version,
                    declaredLength: declaredLength,
                    fragment: fragment
                ))
            // Handshake messages may span records; coalesce their fragments.
            if contentType == 22 {
                handshakeData.append(fragment)
            }
        }
        if records.isEmpty {
            throw DecodingError.insufficientBytes(needed: 5, available: reader.remaining)
        }
        if !reader.isAtEnd { truncated = true }

        // Handshake messages: type(1) length(3) body.
        var clientHello: TLSClientHello?
        var serverHello: TLSServerHello?
        var certificateDERs: [Data] = []
        var handshake = ByteReader(handshakeData)
        while handshake.remaining >= 4 {
            let messageType = try handshake.readUInt8()
            let length = Int(try handshake.readUInt24())
            guard length <= handshake.remaining else {
                truncated = true
                break
            }
            let body = try handshake.readBytes(length)
            switch messageType {
            case 1: clientHello = clientHello ?? Self.parseClientHello(body)
            case 2: serverHello = serverHello ?? Self.parseServerHello(body)
            case 11: certificateDERs = Self.parseCertificateMessage(body)
            default: break
            }
        }
        if handshake.remaining > 0 && handshake.remaining < 4 { truncated = true }

        let consumed = data.count - reader.remaining
        let layer = TLS(
            records: records,
            clientHello: clientHello,
            serverHello: serverHello,
            certificateDERs: certificateDERs,
            certificates: certificateDERs.compactMap { try? X509Certificate(der: $0) },
            isTruncated: truncated,
            bytes: data.prefix(consumed)
        )
        return DecodeResult(layer: layer, next: .done)
    }

    // MARK: - Handshake bodies

    /// Both hello messages share a prefix: version(2) random(32)
    /// session_id<0..32>. Returns nil on underflow (tolerated, not fatal).
    private static func parseHelloPrefix(
        _ reader: inout ByteReader
    ) -> (version: UInt16, random: Data, sessionID: Data)? {
        guard
            let version = try? reader.readUInt16(),
            let random = try? reader.readBytes(32),
            let sessionIDLength = try? reader.readUInt8(),
            sessionIDLength <= 32,
            let sessionID = try? reader.readBytes(Int(sessionIDLength))
        else { return nil }
        return (version, random, sessionID)
    }

    static func parseClientHello(_ body: Data) -> TLSClientHello? {
        var reader = ByteReader(body)
        guard let prefix = parseHelloPrefix(&reader) else { return nil }

        guard
            let cipherSuitesLength = try? reader.readUInt16(),
            cipherSuitesLength % 2 == 0,
            let cipherSuiteBytes = try? reader.readBytes(Int(cipherSuitesLength)),
            let compressionCount = try? reader.readUInt8(),
            let compressionMethods = try? reader.readBytes(Int(compressionCount))
        else { return nil }

        var cipherSuites: [UInt16] = []
        var suites = ByteReader(cipherSuiteBytes)
        while let suite = try? suites.readUInt16() { cipherSuites.append(suite) }

        // Extensions are optional in ancient hellos.
        var extensionTypes: [UInt16] = []
        var serverName: String?
        var alpnProtocols: [String] = []
        var supportedGroups: [UInt16] = []
        var ecPointFormats: [UInt8] = []
        var supportedVersions: [UInt16] = []
        var signatureAlgorithms: [UInt16] = []

        for (type, content) in parseExtensions(&reader) {
            extensionTypes.append(type)
            var ext = ByteReader(content)
            switch type {
            case 0:  // server_name: list length, then type(1)=host, length(2), name
                guard
                    (try? ext.skip(2)) != nil,
                    let nameType = try? ext.readUInt8(), nameType == 0,
                    let nameLength = try? ext.readUInt16(),
                    let name = try? ext.readBytes(Int(nameLength))
                else { break }
                serverName = String(decoding: name, as: UTF8.self)
            case 10:  // supported_groups
                supportedGroups = readUInt16List(&ext)
            case 11:  // ec_point_formats: length(1), bytes
                if let count = try? ext.readUInt8(),
                    let bytes = try? ext.readBytes(Int(count))
                {
                    ecPointFormats = Array(bytes)
                }
            case 13:  // signature_algorithms
                signatureAlgorithms = readUInt16List(&ext)
            case 16:  // ALPN: list length(2), then length(1)-prefixed names
                guard (try? ext.skip(2)) != nil else { break }
                while let length = try? ext.readUInt8(),
                    let name = try? ext.readBytes(Int(length))
                {
                    alpnProtocols.append(String(decoding: name, as: UTF8.self))
                }
            case 43:  // supported_versions (client form): length(1), UInt16s
                guard (try? ext.skip(1)) != nil else { break }
                while let version = try? ext.readUInt16() {
                    supportedVersions.append(version)
                }
            default:
                break
            }
        }

        return TLSClientHello(
            legacyVersion: prefix.version,
            random: prefix.random,
            sessionID: prefix.sessionID,
            cipherSuites: cipherSuites,
            compressionMethods: Array(compressionMethods),
            extensionTypes: extensionTypes,
            serverName: serverName,
            alpnProtocols: alpnProtocols,
            supportedGroups: supportedGroups,
            ecPointFormats: ecPointFormats,
            supportedVersions: supportedVersions,
            signatureAlgorithms: signatureAlgorithms
        )
    }

    static func parseServerHello(_ body: Data) -> TLSServerHello? {
        var reader = ByteReader(body)
        guard let prefix = parseHelloPrefix(&reader),
            let cipherSuite = try? reader.readUInt16(),
            let compressionMethod = try? reader.readUInt8()
        else { return nil }

        var extensionTypes: [UInt16] = []
        var alpnProtocol: String?
        var supportedVersion: UInt16?

        for (type, content) in parseExtensions(&reader) {
            extensionTypes.append(type)
            var ext = ByteReader(content)
            switch type {
            case 16:
                if (try? ext.skip(2)) != nil,
                    let length = try? ext.readUInt8(),
                    let name = try? ext.readBytes(Int(length))
                {
                    alpnProtocol = String(decoding: name, as: UTF8.self)
                }
            case 43:  // supported_versions (server form): a single UInt16
                supportedVersion = try? ext.readUInt16()
            default:
                break
            }
        }

        return TLSServerHello(
            legacyVersion: prefix.version,
            random: prefix.random,
            sessionID: prefix.sessionID,
            cipherSuite: cipherSuite,
            compressionMethod: compressionMethod,
            extensionTypes: extensionTypes,
            alpnProtocol: alpnProtocol,
            supportedVersion: supportedVersion
        )
    }

    /// Certificate (TLS ≤ 1.2, RFC 5246 §7.4.2): total length(3), then
    /// length(3)-prefixed DER blobs. (TLS 1.3 encrypts its certificates, so
    /// they are not visible to passive capture at all.)
    static func parseCertificateMessage(_ body: Data) -> [Data] {
        var reader = ByteReader(body)
        guard let totalLength = try? reader.readUInt24(),
            Int(totalLength) <= reader.remaining
        else { return [] }
        var certificates: [Data] = []
        while reader.remaining >= 3 {
            guard let length = try? reader.readUInt24(),
                let der = try? reader.readBytes(Int(length))
            else { break }
            certificates.append(der)
        }
        return certificates
    }

    /// Reads a full extensions block: total length(2), then type(2) length(2)
    /// value entries. Returns an empty list when absent or malformed.
    private static func parseExtensions(_ reader: inout ByteReader) -> [(UInt16, Data)] {
        guard let totalLength = try? reader.readUInt16(),
            let block = try? reader.readBytes(Int(totalLength))
        else { return [] }
        var extensions: [(UInt16, Data)] = []
        var cursor = ByteReader(block)
        while let type = try? cursor.readUInt16(),
            let length = try? cursor.readUInt16(),
            let content = try? cursor.readBytes(Int(length))
        {
            extensions.append((type, content))
        }
        return extensions
    }

    private static func readUInt16List(_ reader: inout ByteReader) -> [UInt16] {
        guard let listLength = try? reader.readUInt16(),
            let bytes = try? reader.readBytes(Int(listLength))
        else { return [] }
        var values: [UInt16] = []
        var cursor = ByteReader(bytes)
        while let value = try? cursor.readUInt16() { values.append(value) }
        return values
    }
}

/// Whether a TLS code point is a GREASE value (RFC 8701): both bytes equal
/// and ending in nibble `0xA` (0x0A0A, 0x1A1A, … 0xFAFA). Excluded from JA3
/// so randomized GREASE doesn't churn the hash.
func isGREASE(_ value: UInt16) -> Bool {
    value >> 8 == value & 0xFF && value & 0x0F == 0x0A
}

func dashJoined(_ values: [UInt16]) -> String {
    values.map { String($0) }.joined(separator: "-")
}

func md5Hex(_ string: String) -> String {
    Insecure.MD5.hash(data: Data(string.utf8))
        .map { String(format: "%02x", $0) }
        .joined()
}
