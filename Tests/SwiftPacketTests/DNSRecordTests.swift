import Foundation
import Testing

@testable import SwiftPacket

@Suite("DNS structured records — TXT, MX, SRV, SOA, type names")
struct DNSRecordTests {

    /// Builds a DNS response with a question for `example.com` and the given
    /// answer records appended verbatim.
    static func response(answerCount: UInt16, records: [UInt8]) -> Data {
        var bytes: [UInt8] = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01,
            UInt8(answerCount >> 8), UInt8(answerCount & 0xFF),
            0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,  // "example"
            0x03, 0x63, 0x6F, 0x6D, 0x00,  // "com"
            0x00, 0x01, 0x00, 0x01,
        ]
        bytes += records
        return Data(bytes)
    }

    /// A record header pointing its name back at the question (0xC00C), with
    /// the given type and RDATA.
    static func record(type: UInt16, rdata: [UInt8]) -> [UInt8] {
        [0xC0, 0x0C, UInt8(type >> 8), UInt8(type & 0xFF), 0x00, 0x01,
         0x00, 0x00, 0x01, 0x2C,
         UInt8(rdata.count >> 8), UInt8(rdata.count & 0xFF)] + rdata
    }

    @Test("TXT records decode into their character strings")
    func txt() throws {
        let rdata: [UInt8] = [0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,  // "hello"
                              0x05, 0x77, 0x6F, 0x72, 0x6C, 0x64]  // "world"
        let message = Self.response(answerCount: 1, records: Self.record(type: 16, rdata: rdata))
        let dns = try #require(try DNSDecoder().decode(message).layer as? DNS)

        let answer = try #require(dns.answers.first)
        #expect(answer.typeName == "TXT")
        #expect(answer.txtStrings == ["hello", "world"])
        #expect(answer.rdataDescription == "hello world")
    }

    @Test("MX records decode preference and exchange, following compression")
    func mx() throws {
        // Preference 10, exchange "mail.example.com" — "example.com" via
        // pointer to the question name at offset 12.
        let rdata: [UInt8] = [0x00, 0x0A, 0x04, 0x6D, 0x61, 0x69, 0x6C, 0xC0, 0x0C]
        let message = Self.response(answerCount: 1, records: Self.record(type: 15, rdata: rdata))
        let dns = try #require(try DNSDecoder().decode(message).layer as? DNS)

        let answer = try #require(dns.answers.first)
        #expect(answer.typeName == "MX")
        #expect(answer.mx == DNSMXRecord(preference: 10, exchange: "mail.example.com"))
    }

    @Test("SRV records decode priority, weight, port, and target")
    func srv() throws {
        // 0 5 5060 sip.example.com
        let rdata: [UInt8] = [0x00, 0x00, 0x00, 0x05, 0x13, 0xC4,
                              0x03, 0x73, 0x69, 0x70, 0xC0, 0x0C]
        let message = Self.response(answerCount: 1, records: Self.record(type: 33, rdata: rdata))
        let dns = try #require(try DNSDecoder().decode(message).layer as? DNS)

        let answer = try #require(dns.answers.first)
        #expect(answer.typeName == "SRV")
        #expect(answer.srv == DNSSRVRecord(priority: 0, weight: 5, port: 5060, target: "sip.example.com"))
    }

    @Test("SOA records decode both names and all five timers")
    func soa() throws {
        var rdata: [UInt8] = [0x02, 0x6E, 0x73, 0xC0, 0x0C]  // ns.example.com
        rdata += [0x05, 0x61, 0x64, 0x6D, 0x69, 0x6E, 0xC0, 0x0C]  // admin.example.com
        rdata += [0x78, 0x49, 0x28, 0xD4]  // serial 2018060500
        rdata += [0x00, 0x00, 0x1C, 0x20]  // refresh 7200
        rdata += [0x00, 0x00, 0x0E, 0x10]  // retry 3600
        rdata += [0x00, 0x24, 0xEA, 0x00]  // expire 2419200
        rdata += [0x00, 0x00, 0x00, 0x3C]  // minimum 60
        let message = Self.response(answerCount: 1, records: Self.record(type: 6, rdata: rdata))
        let dns = try #require(try DNSDecoder().decode(message).layer as? DNS)

        let answer = try #require(dns.answers.first)
        #expect(answer.typeName == "SOA")
        let soa = try #require(answer.soa)
        #expect(soa.primaryNameServer == "ns.example.com")
        #expect(soa.responsibleMailbox == "admin.example.com")
        #expect(soa.serial == 2_018_060_500)
        #expect(soa.refresh == 7200)
        #expect(soa.retry == 3600)
        #expect(soa.expire == 2_419_200)
        #expect(soa.minimumTTL == 60)
    }

    @Test("unknown record types keep raw rdata and an RFC 3597 name")
    func unknownType() throws {
        let message = Self.response(
            answerCount: 1, records: Self.record(type: 4711, rdata: [0xDE, 0xAD]))
        let dns = try #require(try DNSDecoder().decode(message).layer as? DNS)

        let answer = try #require(dns.answers.first)
        #expect(answer.typeName == "TYPE4711")
        #expect(Array(answer.rdata) == [0xDE, 0xAD])
        #expect(answer.txtStrings == nil && answer.mx == nil && answer.srv == nil && answer.soa == nil)
        #expect(answer.rdataDescription == "2 bytes")
    }

    @Test("response code names match the classic mnemonics")
    func rcodes() throws {
        let message = Self.response(answerCount: 0, records: [])
        let dns = try #require(try DNSDecoder().decode(message).layer as? DNS)
        #expect(dns.responseCodeName == "NOERROR")
        #expect(dns.questions.first?.typeName == "A")
    }

    @Test("malformed structured rdata degrades to nil, never traps")
    func malformedRdata() throws {
        // An MX record whose rdata is a single byte — too short for anything.
        let message = Self.response(answerCount: 1, records: Self.record(type: 15, rdata: [0x00]))
        let dns = try #require(try DNSDecoder().decode(message).layer as? DNS)
        let answer = try #require(dns.answers.first)
        #expect(answer.mx == nil)
        #expect(Array(answer.rdata) == [0x00])
    }
}
