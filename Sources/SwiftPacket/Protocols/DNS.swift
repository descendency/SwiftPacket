import Foundation

/// A DNS question entry.
public struct DNSQuestion: Sendable, Hashable {
    public let name: String
    public let type: UInt16
    public let recordClass: UInt16
}

/// A DNS resource record, with common record data decoded where possible.
public struct DNSResourceRecord: Sendable {
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
                            ? (try? Self.parseName(data, at: rdataStart).name) : nil
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
