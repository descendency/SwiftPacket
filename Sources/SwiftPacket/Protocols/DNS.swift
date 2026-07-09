import Foundation

/// A DNS question entry.
public struct DNSQuestion: Sendable, Hashable {
    public let name: String
    public let type: UInt16
    public let recordClass: UInt16

    /// The mnemonic for ``type`` (`"A"`, `"AAAA"`, `"MX"`, …); unrecognized
    /// types render in the RFC 3597 style, e.g. `"TYPE4711"`.
    public var typeName: String { dnsRecordTypeName(type) }
}

/// The decoded RDATA of an `MX` record (type 15).
public struct DNSMXRecord: Sendable, Hashable {
    public let preference: UInt16
    public let exchange: String
}

/// The decoded RDATA of an `SRV` record (type 33, RFC 2782).
public struct DNSSRVRecord: Sendable, Hashable {
    public let priority: UInt16
    public let weight: UInt16
    public let port: UInt16
    public let target: String
}

/// The decoded RDATA of an `SOA` record (type 6).
public struct DNSSOARecord: Sendable, Hashable {
    public let primaryNameServer: String
    public let responsibleMailbox: String
    public let serial: UInt32
    public let refresh: UInt32
    public let retry: UInt32
    public let expire: UInt32
    public let minimumTTL: UInt32
}

/// A DNS resource record, with common record data decoded where possible.
///
/// ``rdata`` always holds the raw bytes, so record types this library does not
/// decode structurally remain fully accessible.
public struct DNSResourceRecord: Sendable, Hashable {
    public let name: String
    public let type: UInt16
    public let recordClass: UInt16
    public let ttl: UInt32
    /// The raw record data (RDATA).
    public let rdata: Data

    /// The address for an `A` record (type 1).
    public let ipv4: IPv4Address?
    /// The address for an `AAAA` record (type 28).
    public let ipv6: IPv6Address?
    /// The target name for `CNAME`/`NS`/`PTR` records (types 5/2/12).
    public let targetName: String?
    /// The character strings of a `TXT` record (type 16).
    public let txtStrings: [String]?
    /// The decoded `MX` record data (type 15).
    public let mx: DNSMXRecord?
    /// The decoded `SRV` record data (type 33).
    public let srv: DNSSRVRecord?
    /// The decoded `SOA` record data (type 6).
    public let soa: DNSSOARecord?

    /// The mnemonic for ``type`` (`"A"`, `"AAAA"`, `"MX"`, …); unrecognized
    /// types render in the RFC 3597 style, e.g. `"TYPE4711"`.
    public var typeName: String { dnsRecordTypeName(type) }

    /// A display form of the record data: the decoded value for known types,
    /// or the RDATA length for unknown ones.
    public var rdataDescription: String {
        if let ipv4 { return ipv4.description }
        if let ipv6 { return ipv6.description }
        if let targetName { return targetName }
        if let txtStrings { return txtStrings.joined(separator: " ") }
        if let mx { return "\(mx.preference) \(mx.exchange)" }
        if let srv { return "\(srv.priority) \(srv.weight) \(srv.port) \(srv.target)" }
        if let soa { return "\(soa.primaryNameServer) \(soa.responsibleMailbox) \(soa.serial)" }
        return "\(rdata.count) bytes"
    }
}

/// The mnemonic for a DNS record type number, per the IANA registry;
/// unrecognized types render in the RFC 3597 style, e.g. `"TYPE4711"`.
func dnsRecordTypeName(_ type: UInt16) -> String {
    switch type {
    case 1: return "A"
    case 2: return "NS"
    case 5: return "CNAME"
    case 6: return "SOA"
    case 12: return "PTR"
    case 15: return "MX"
    case 16: return "TXT"
    case 28: return "AAAA"
    case 33: return "SRV"
    case 35: return "NAPTR"
    case 41: return "OPT"
    case 43: return "DS"
    case 46: return "RRSIG"
    case 47: return "NSEC"
    case 48: return "DNSKEY"
    case 50: return "NSEC3"
    case 64: return "SVCB"
    case 65: return "HTTPS"
    case 99: return "SPF"
    case 252: return "AXFR"
    case 255: return "ANY"
    case 257: return "CAA"
    default: return "TYPE\(type)"
    }
}

/// A DNS message (RFC 1035). Terminal — carries no payload layer.
public struct DNS: Layer {
    public static let layerType = LayerType.dns

    public let id: UInt16
    public let isResponse: Bool
    public let opcode: UInt8
    public let authoritativeAnswer: Bool
    public let truncated: Bool
    public let recursionDesired: Bool
    public let recursionAvailable: Bool
    public let responseCode: UInt8

    public let questions: [DNSQuestion]
    public let answers: [DNSResourceRecord]
    public let authorities: [DNSResourceRecord]
    public let additionals: [DNSResourceRecord]

    fileprivate let message: Data
    public var layerContents: Data { message }
    public var layerPayload: Data { Data() }

    /// The mnemonic for ``responseCode`` (`"NOERROR"`, `"NXDOMAIN"`, …);
    /// unrecognized codes render as `"RCODE-N"`.
    public var responseCodeName: String {
        switch responseCode {
        case 0: return "NOERROR"
        case 1: return "FORMERR"
        case 2: return "SERVFAIL"
        case 3: return "NXDOMAIN"
        case 4: return "NOTIMP"
        case 5: return "REFUSED"
        default: return "RCODE-\(responseCode)"
        }
    }
}

/// Decodes a DNS message, including compressed names.
public struct DNSDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        let base = data.startIndex
        var reader = ByteReader(data)

        let id = try reader.readUInt16()
        let flags = try reader.readUInt16()
        let questionCount = Int(try reader.readUInt16())
        let answerCount = Int(try reader.readUInt16())
        let authorityCount = Int(try reader.readUInt16())
        let additionalCount = Int(try reader.readUInt16())

        var offset = base + 12  // 12-byte header consumed

        var questions: [DNSQuestion] = []
        for _ in 0..<questionCount {
            let (name, afterName) = try Self.parseName(data, at: offset)
            offset = afterName
            let type = try Self.readUInt16(data, offset)
            let recordClass = try Self.readUInt16(data, offset + 2)
            offset += 4
            questions.append(DNSQuestion(name: name, type: type, recordClass: recordClass))
        }

        func parseRecords(_ count: Int) throws -> [DNSResourceRecord] {
            var records: [DNSResourceRecord] = []
            for _ in 0..<count {
                let (name, afterName) = try Self.parseName(data, at: offset)
                offset = afterName
                let type = try Self.readUInt16(data, offset)
                let recordClass = try Self.readUInt16(data, offset + 2)
                let ttl = try Self.readUInt32(data, offset + 4)
                let rdlength = Int(try Self.readUInt16(data, offset + 8))
                offset += 10

                let rdataStart = offset
                let rdataEnd = rdataStart + rdlength
                guard rdataEnd <= data.endIndex else {
                    throw DecodingError.insufficientBytes(
                        needed: rdlength,
                        available: data.endIndex - rdataStart
                    )
                }
                let rdata = data[rdataStart..<rdataEnd]
                offset = rdataEnd

                records.append(
                    DNSResourceRecord(
                        name: name,
                        type: type,
                        recordClass: recordClass,
                        ttl: ttl,
                        rdata: rdata,
                        ipv4: type == 1 ? IPv4Address(rdata) : nil,
                        ipv6: type == 28 ? IPv6Address(rdata) : nil,
                        targetName: (type == 5 || type == 2 || type == 12)
                            ? (try? Self.parseName(data, at: rdataStart).name) : nil,
                        txtStrings: type == 16 ? Self.parseTXT(rdata) : nil,
                        // Names inside RDATA may point back into the whole
                        // message via compression, so these parse against
                        // `data`, not the rdata slice.
                        mx: type == 15 ? Self.parseMX(data, rdataStart: rdataStart) : nil,
                        srv: type == 33 ? Self.parseSRV(data, rdataStart: rdataStart) : nil,
                        soa: type == 6 ? Self.parseSOA(data, rdataStart: rdataStart) : nil
                    )
                )
            }
            return records
        }

        let answers = try parseRecords(answerCount)
        let authorities = try parseRecords(authorityCount)
        let additionals = try parseRecords(additionalCount)

        let layer = DNS(
            id: id,
            isResponse: flags & 0x8000 != 0,
            opcode: UInt8((flags >> 11) & 0x0F),
            authoritativeAnswer: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursionDesired: flags & 0x0100 != 0,
            recursionAvailable: flags & 0x0080 != 0,
            responseCode: UInt8(flags & 0x000F),
            questions: questions,
            answers: answers,
            authorities: authorities,
            additionals: additionals,
            message: data
        )
        return DecodeResult(layer: layer, next: .done)
    }

    // MARK: - RDATA decoding

    /// Parses TXT record data: a sequence of length-prefixed character strings.
    static func parseTXT(_ rdata: Data) -> [String] {
        var strings: [String] = []
        var reader = ByteReader(rdata)
        while let length = try? reader.readUInt8() {
            guard let bytes = try? reader.readBytes(Int(length)) else { break }
            strings.append(String(decoding: bytes, as: UTF8.self))
        }
        return strings
    }

    static func parseMX(_ data: Data, rdataStart: Int) -> DNSMXRecord? {
        guard
            let preference = try? readUInt16(data, rdataStart),
            let exchange = try? parseName(data, at: rdataStart + 2).name
        else { return nil }
        return DNSMXRecord(preference: preference, exchange: exchange)
    }

    static func parseSRV(_ data: Data, rdataStart: Int) -> DNSSRVRecord? {
        guard
            let priority = try? readUInt16(data, rdataStart),
            let weight = try? readUInt16(data, rdataStart + 2),
            let port = try? readUInt16(data, rdataStart + 4),
            let target = try? parseName(data, at: rdataStart + 6).name
        else { return nil }
        return DNSSRVRecord(priority: priority, weight: weight, port: port, target: target)
    }

    static func parseSOA(_ data: Data, rdataStart: Int) -> DNSSOARecord? {
        guard
            let (mname, afterMName) = try? parseName(data, at: rdataStart),
            let (rname, afterRName) = try? parseName(data, at: afterMName),
            let serial = try? readUInt32(data, afterRName),
            let refresh = try? readUInt32(data, afterRName + 4),
            let retry = try? readUInt32(data, afterRName + 8),
            let expire = try? readUInt32(data, afterRName + 12),
            let minimum = try? readUInt32(data, afterRName + 16)
        else { return nil }
        return DNSSOARecord(
            primaryNameServer: mname,
            responsibleMailbox: rname,
            serial: serial,
            refresh: refresh,
            retry: retry,
            expire: expire,
            minimumTTL: minimum
        )
    }

    // MARK: - Name parsing with compression

    /// Parses a (possibly compressed) DNS name starting at absolute index
    /// `position`. Returns the name and the index at which reading should
    /// continue in the enclosing record (past the terminating zero, or past the
    /// first compression pointer).
    static func parseName(
        _ data: Data,
        at position: Int,
        maxJumps: Int = 128
    ) throws -> (name: String, next: Int) {
        let base = data.startIndex
        var labels: [String] = []
        var offset = position
        var continuation: Int?
        var jumps = 0

        while true {
            guard offset >= base, offset < data.endIndex else {
                throw DecodingError.malformed("DNS name ran past end of message")
            }
            let length = Int(data[offset])
            let kind = length & 0xC0

            if length == 0 {
                offset += 1
                if continuation == nil { continuation = offset }
                break
            } else if kind == 0xC0 {
                guard offset + 1 < data.endIndex else {
                    throw DecodingError.malformed("truncated DNS compression pointer")
                }
                let pointer = ((length & 0x3F) << 8) | Int(data[offset + 1])
                if continuation == nil { continuation = offset + 2 }
                jumps += 1
                guard jumps <= maxJumps else {
                    throw DecodingError.malformed("DNS name compression loop")
                }
                offset = base + pointer
            } else if kind == 0 {
                let start = offset + 1
                let labelEnd = start + length
                guard labelEnd <= data.endIndex else {
                    throw DecodingError.malformed("DNS label runs past end of message")
                }
                labels.append(String(decoding: data[start..<labelEnd], as: UTF8.self))
                offset = labelEnd
            } else {
                throw DecodingError.malformed("unsupported DNS label type")
            }
        }

        return (labels.joined(separator: "."), continuation ?? offset)
    }

    static func readUInt16(_ data: Data, _ offset: Int) throws -> UInt16 {
        guard offset >= data.startIndex, offset + 2 <= data.endIndex else {
            throw DecodingError.insufficientBytes(needed: 2, available: max(0, data.endIndex - offset))
        }
        return UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    static func readUInt32(_ data: Data, _ offset: Int) throws -> UInt32 {
        guard offset >= data.startIndex, offset + 4 <= data.endIndex else {
            throw DecodingError.insufficientBytes(needed: 4, available: max(0, data.endIndex - offset))
        }
        var value: UInt32 = 0
        for index in 0..<4 { value = value << 8 | UInt32(data[offset + index]) }
        return value
    }
}
