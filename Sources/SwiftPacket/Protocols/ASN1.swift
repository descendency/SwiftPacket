import Foundation

/// A parsed ASN.1 DER element: the decoded identifier, the content bytes, and
/// the raw TLV encoding it came from.
///
/// This is a deliberately small DER reader — just enough structure to walk
/// X.509 certificates. Like every decoder in this library it is fully
/// bounds-checked: malformed input throws ``DecodingError``, never traps.
/// Indefinite lengths (BER, forbidden in DER) are rejected.
struct ASN1Element: Sendable {
    enum Class: UInt8, Sendable {
        case universal = 0
        case application = 1
        case contextSpecific = 2
        case privateClass = 3
    }

    let elementClass: Class
    let isConstructed: Bool
    let tagNumber: UInt64
    /// The content octets (the V of the TLV).
    let content: Data
    /// The complete element as encoded, identifier and length octets included.
    let raw: Data

    // Universal tag numbers used by X.509.
    static let tagBoolean: UInt64 = 1
    static let tagInteger: UInt64 = 2
    static let tagBitString: UInt64 = 3
    static let tagOctetString: UInt64 = 4
    static let tagNull: UInt64 = 5
    static let tagObjectIdentifier: UInt64 = 6
    static let tagUTF8String: UInt64 = 12
    static let tagSequence: UInt64 = 16
    static let tagSet: UInt64 = 17
    static let tagPrintableString: UInt64 = 19
    static let tagTeletexString: UInt64 = 20
    static let tagIA5String: UInt64 = 22
    static let tagUTCTime: UInt64 = 23
    static let tagGeneralizedTime: UInt64 = 24
    static let tagBMPString: UInt64 = 30

    /// Whether this is a universal-class element with the given tag.
    func isUniversal(_ tag: UInt64) -> Bool {
        elementClass == .universal && tagNumber == tag
    }

    /// Whether this is a context-specific element with the given tag ([n]).
    func isContextSpecific(_ tag: UInt64) -> Bool {
        elementClass == .contextSpecific && tagNumber == tag
    }
}

// MARK: - Parsing

extension ASN1Element {
    /// Parses the single element at the start of `data`. Trailing bytes after
    /// the element are ignored (callers use ``ASN1Reader`` to walk siblings).
    static func parse(_ data: Data) throws -> ASN1Element {
        var reader = ASN1Reader(data)
        return try reader.readElement()
    }

    /// Parses the content of a constructed element as a list of child elements,
    /// requiring the children to fill the content exactly.
    func children() throws -> [ASN1Element] {
        var reader = ASN1Reader(content)
        var elements: [ASN1Element] = []
        while !reader.isAtEnd {
            elements.append(try reader.readElement())
        }
        return elements
    }
}

/// A sequential reader of DER elements over a byte buffer.
struct ASN1Reader {
    private var reader: ByteReader

    init(_ data: Data) {
        self.reader = ByteReader(data)
    }

    var isAtEnd: Bool { reader.isAtEnd }

    mutating func readElement() throws -> ASN1Element {
        let start = reader.data.startIndex + reader.bytesRead

        let identifier = try reader.readUInt8()
        let elementClass = ASN1Element.Class(rawValue: identifier >> 6)!
        let isConstructed = identifier & 0x20 != 0

        // Low tag numbers live in the identifier octet; 0x1F marks the
        // base-128 high-tag-number form.
        var tagNumber = UInt64(identifier & 0x1F)
        if tagNumber == 0x1F {
            tagNumber = 0
            for _ in 0..<9 {
                let byte = try reader.readUInt8()
                tagNumber = tagNumber << 7 | UInt64(byte & 0x7F)
                if byte & 0x80 == 0 { break }
            }
        }

        // Length octets: short form, or long form with a byte count.
        let first = try reader.readUInt8()
        var length = Int(first)
        if first == 0x80 {
            throw DecodingError.malformed("ASN.1 indefinite length is not DER")
        }
        if first & 0x80 != 0 {
            let count = Int(first & 0x7F)
            guard count <= 8 else {
                throw DecodingError.malformed("ASN.1 length of \(count) octets")
            }
            var value: UInt64 = 0
            for _ in 0..<count {
                value = value << 8 | UInt64(try reader.readUInt8())
            }
            guard value <= UInt64(Int.max) else {
                throw DecodingError.invalidLength(Int.max)
            }
            length = Int(value)
        }

        let content = try reader.readBytes(length)
        let end = reader.data.startIndex + reader.bytesRead
        return ASN1Element(
            elementClass: elementClass,
            isConstructed: isConstructed,
            tagNumber: tagNumber,
            content: content,
            raw: reader.data[start..<end]
        )
    }
}

// MARK: - Value decoding

extension ASN1Element {
    /// The value of an INTEGER small enough for `UInt64`, ignoring sign.
    var integerValue: UInt64? {
        guard isUniversal(Self.tagInteger) else { return nil }
        var bytes = content.drop(while: { $0 == 0 })
        if bytes.isEmpty { return 0 }
        guard bytes.count <= 8 else { return nil }
        var value: UInt64 = 0
        while let byte = bytes.popFirst() {
            value = value << 8 | UInt64(byte)
        }
        return value
    }

    /// An OBJECT IDENTIFIER as its dotted-decimal string, e.g. `"2.5.4.3"`.
    var oidValue: String? {
        guard isUniversal(Self.tagObjectIdentifier), !content.isEmpty else { return nil }
        var components: [UInt64] = []
        var accumulator: UInt64 = 0
        for (index, byte) in content.enumerated() {
            // Guard against overflow from absurdly long components.
            guard accumulator < (UInt64.max >> 7) else { return nil }
            accumulator = accumulator << 7 | UInt64(byte & 0x7F)
            if byte & 0x80 == 0 {
                if components.isEmpty {
                    // The first two components are packed into one value.
                    components.append(min(accumulator / 40, 2))
                    components.append(accumulator - min(accumulator / 40, 2) * 40)
                } else {
                    components.append(accumulator)
                }
                accumulator = 0
            } else if index == content.count - 1 {
                return nil  // trailing continuation bit
            }
        }
        return components.map(String.init).joined(separator: ".")
    }

    /// The value of any of the ASN.1 string types X.509 names use.
    var stringValue: String? {
        guard elementClass == .universal else { return nil }
        switch tagNumber {
        case Self.tagUTF8String, Self.tagIA5String, Self.tagPrintableString:
            return String(decoding: content, as: UTF8.self)
        case Self.tagTeletexString:
            // Approximated as Latin-1, which covers practically all real use.
            return String(content.map { Character(UnicodeScalar($0)) })
        case Self.tagBMPString:
            guard content.count % 2 == 0 else { return nil }
            var scalars = String.UnicodeScalarView()
            for index in stride(from: content.startIndex, to: content.endIndex, by: 2) {
                let unit = UInt32(content[index]) << 8 | UInt32(content[index + 1])
                guard let scalar = UnicodeScalar(unit) else { return nil }
                scalars.append(scalar)
            }
            return String(scalars)
        default:
            return nil
        }
    }

    /// The content of a BIT STRING with its leading unused-bits octet removed.
    var bitStringValue: Data? {
        guard isUniversal(Self.tagBitString), !content.isEmpty else { return nil }
        return content.dropFirst()
    }

    /// The value of a BOOLEAN.
    var booleanValue: Bool? {
        guard isUniversal(Self.tagBoolean), content.count == 1 else { return nil }
        return content.first != 0
    }

    /// A UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSS[.f…]Z`)
    /// as a `Date`. X.509 mandates the `Z` (UTC) forms; offsets are rejected.
    var timeValue: Date? {
        guard elementClass == .universal else { return nil }
        let text = String(decoding: content, as: UTF8.self)
        guard text.hasSuffix("Z") else { return nil }
        let digits = text.dropLast().prefix(while: \.isNumber)

        var year: Int
        var rest: Substring
        switch tagNumber {
        case Self.tagUTCTime:
            guard digits.count == 12 || digits.count == 10 else { return nil }
            let yy = Int(digits.prefix(2))!
            year = yy < 50 ? 2000 + yy : 1900 + yy  // RFC 5280 §4.1.2.5.1
            rest = digits.dropFirst(2)
        case Self.tagGeneralizedTime:
            guard digits.count >= 10 else { return nil }
            year = Int(digits.prefix(4))!
            rest = digits.dropFirst(4)
        default:
            return nil
        }

        func take2() -> Int? {
            guard rest.count >= 2, let value = Int(rest.prefix(2)) else { return nil }
            rest = rest.dropFirst(2)
            return value
        }
        guard let month = take2(), let day = take2(), let hour = take2(), let minute = take2()
        else { return nil }
        let second = take2() ?? 0

        var components = DateComponents()
        components.timeZone = TimeZone(identifier: "UTC")
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        guard calendar.date(from: components) != nil, (1...12).contains(month),
            (1...31).contains(day), (0...23).contains(hour), (0...59).contains(minute),
            (0...61).contains(second)
        else { return nil }
        return calendar.date(from: components)
    }
}
