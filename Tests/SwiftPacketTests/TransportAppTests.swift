import Foundation
import Testing

@testable import SwiftPacket

@Suite("IP transports & UDP applications — IGMP, IPsec, SCTP, VRRP, DHCP, NTP")
struct TransportAppTests {

    /// An IPv4 header carrying `proto` with `payload` bytes after it.
    static func ipv4(proto: UInt8, payloadLength: Int) -> [UInt8] {
        var header = ProtocolTests.ipv4Header
        let total = 20 + payloadLength
        header[2] = UInt8(total >> 8)
        header[3] = UInt8(total & 0xFF)
        header[9] = proto
        return header
    }

    static func decode(proto: UInt8, _ payload: [UInt8]) -> Packet {
        Packet.decode(
            Data(Self.ipv4(proto: proto, payloadLength: payload.count) + payload),
            startingAt: .ipv4, using: .standard)
    }

    // MARK: - IGMP

    @Test("an IGMPv2 membership report decodes type and group")
    func igmpV2() {
        let igmp: [UInt8] = [0x16, 0x64, 0x00, 0x00, 224, 0, 0, 251]
        let packet = Self.decode(proto: 2, igmp)

        #expect(packet.summary == "IPv4 | IGMP")
        let layer = packet.layer(IGMP.self)
        #expect(layer?.typeName == "V2MembershipReport")
        #expect(layer?.groupAddress?.description == "224.0.0.251")
    }

    @Test("an IGMPv3 report decodes its group records")
    func igmpV3() {
        var igmp: [UInt8] = [0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]  // 2 records
        igmp += [2, 0, 0x00, 0x01, 239, 1, 2, 3, 10, 0, 0, 1]  // exclude, 1 source
        igmp += [1, 0, 0x00, 0x00, 239, 4, 5, 6]  // include, no sources
        let packet = Self.decode(proto: 2, igmp)

        let layer = packet.layer(IGMP.self)
        #expect(layer?.typeName == "V3MembershipReport")
        #expect(layer?.groupRecords.count == 2)
        #expect(layer?.groupRecords.first?.multicastAddress.description == "239.1.2.3")
        #expect(layer?.groupRecords.first?.sourceAddresses.first?.description == "10.0.0.1")
        #expect(layer?.groupRecords.last?.recordType == 1)
    }

    // MARK: - IPsec

    @Test("ESP exposes SPI and sequence, keeping the rest opaque")
    func esp() {
        let esp: [UInt8] = [0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDE, 0xAD]
        let packet = Self.decode(proto: 50, esp)

        #expect(packet.summary == "IPv4 | ESP")
        let layer = packet.layer(ESP.self)
        #expect(layer?.spi == 0x1000)
        #expect(layer?.sequenceNumber == 5)
        #expect(layer?.encrypted.count == 2)
    }

    @Test("AH authenticates in cleartext, so decoding continues through it")
    func ah() {
        // AH: next=UDP, payload length 4 (=> 24-byte header, 12-byte ICV).
        var ah: [UInt8] = [17, 4, 0x00, 0x00]
        ah += [0x00, 0x00, 0x20, 0x00]  // SPI
        ah += [0x00, 0x00, 0x00, 0x09]  // sequence
        ah += Array(repeating: 0xAB, count: 12)  // ICV
        let payload = ah + ProtocolTests.udpHeader + ProtocolTests.dnsQuery
        let packet = Self.decode(proto: 51, payload)

        #expect(packet.summary == "IPv4 | AH | UDP | DNS")
        let layer = packet.layer(AH.self)
        #expect(layer?.spi == 0x2000)
        #expect(layer?.sequenceNumber == 9)
        #expect(layer?.nextHeader == .udp)
        #expect(layer?.icv.count == 12)
        #expect(packet.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    // MARK: - SCTP

    @Test("SCTP decodes its common header and chunk list")
    func sctp() {
        var sctp: [UInt8] = [0x1F, 0x90, 0x00, 0x50]  // 8080 -> 80
        sctp += [0xDE, 0xAD, 0xBE, 0xEF]  // verification tag
        sctp += [0x00, 0x00, 0x00, 0x00]  // checksum
        sctp += [0, 3, 0x00, 0x14] + Array(repeating: 0x11, count: 16)  // DATA, len 20
        sctp += [4, 0, 0x00, 0x05, 0x22, 0x00, 0x00, 0x00]  // HEARTBEAT len 5 + 3 pad
        let packet = Self.decode(proto: 132, sctp)

        #expect(packet.summary == "IPv4 | SCTP")
        let layer = packet.layer(SCTP.self)
        #expect(layer?.sourcePort == 8080)
        #expect(layer?.destinationPort == 80)
        #expect(layer?.verificationTag == 0xDEAD_BEEF)
        #expect(layer?.chunks.count == 2)
        #expect(layer?.chunks.first?.typeName == "DATA")
        #expect(layer?.chunks.first?.value.count == 16)
        #expect(layer?.chunks.last?.typeName == "HEARTBEAT")
        #expect(layer?.chunks.last?.value.count == 1)
    }

    // MARK: - UDP-Lite

    @Test("UDP-Lite decodes its checksum coverage")
    func udpLite() {
        let udpLite: [UInt8] = [0xC0, 0x00, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00, 0x01, 0x02]
        let packet = Self.decode(proto: 136, udpLite)

        #expect(packet.summary == "IPv4 | UDPLite | Payload")
        let layer = packet.layer(UDPLite.self)
        #expect(layer?.checksumCoverage == 8)
        #expect(layer?.payload.count == 2)
    }

    // MARK: - VRRP

    @Test("VRRPv2 and v3 advertisements both decode")
    func vrrp() {
        let v2: [UInt8] = [0x21, 1, 100, 1, 0, 1, 0x00, 0x00, 192, 0, 2, 1]
        let packet2 = Self.decode(proto: 112, v2)
        #expect(packet2.summary == "IPv4 | VRRP")
        let layer2 = packet2.layer(VRRP.self)
        #expect(layer2?.version == 2)
        #expect(layer2?.virtualRouterID == 1)
        #expect(layer2?.priority == 100)
        #expect(layer2?.advertisementInterval == 1)
        #expect(layer2?.addresses.first?.description == "192.0.2.1")

        let v3: [UInt8] = [0x31, 7, 200, 1, 0x00, 0x64, 0x00, 0x00, 192, 0, 2, 9]
        let layer3 = Self.decode(proto: 112, v3).layer(VRRP.self)
        #expect(layer3?.version == 3)
        #expect(layer3?.advertisementInterval == 100)
        #expect(layer3?.addresses.first?.description == "192.0.2.9")
    }

    // MARK: - DHCPv4

    static func dhcpMessage() -> [UInt8] {
        var dhcp: [UInt8] = [1, 1, 6, 0]  // BOOTREQUEST, ethernet, hlen 6, hops 0
        dhcp += [0xDE, 0xAD, 0xBE, 0xEF]  // xid
        dhcp += [0x00, 0x00, 0x80, 0x00]  // secs, broadcast flag
        dhcp += [0, 0, 0, 0]  // ciaddr
        dhcp += [192, 0, 2, 50]  // yiaddr
        dhcp += [0, 0, 0, 0, 0, 0, 0, 0]  // siaddr, giaddr
        dhcp += [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] + Array(repeating: 0, count: 10)  // chaddr
        dhcp += Array(repeating: 0, count: 64 + 128)  // sname, file
        dhcp += [0x63, 0x82, 0x53, 0x63]  // magic cookie
        dhcp += [53, 1, 3]  // message type: REQUEST
        dhcp += [12, 4] + Array("mac1".utf8)  // hostname
        dhcp += [50, 4, 192, 0, 2, 50]  // requested address
        dhcp += [51, 4, 0x00, 0x01, 0x51, 0x80]  // lease time 86400
        dhcp += [0, 0]  // padding
        dhcp += [255]  // end
        return dhcp
    }

    @Test("a DHCPv4 REQUEST over UDP 68→67 decodes fields and options")
    func dhcpv4() {
        let dhcp = Self.dhcpMessage()
        let length = 8 + dhcp.count
        let udp: [UInt8] = [0x00, 0x44, 0x00, 0x43,  // 68 -> 67
                            UInt8(length >> 8), UInt8(length & 0xFF), 0x00, 0x00]
        let packet = Packet.decode(
            Data(Self.ipv4(proto: 17, payloadLength: length) + udp + dhcp),
            startingAt: .ipv4, using: .standard)

        #expect(packet.summary == "IPv4 | UDP | DHCPv4")
        let layer = packet.layer(DHCPv4.self)
        #expect(layer?.messageTypeName == "REQUEST")
        #expect(layer?.transactionID == 0xDEAD_BEEF)
        #expect(layer?.broadcast == true)
        #expect(layer?.yourAddress.description == "192.0.2.50")
        #expect(layer?.clientMAC?.description == "aa:bb:cc:dd:ee:ff")
        #expect(layer?.hostname == "mac1")
        #expect(layer?.requestedAddress?.description == "192.0.2.50")
        #expect(layer?.leaseTime == 86400)
    }

    // MARK: - DHCPv6

    @Test("a DHCPv6 SOLICIT over UDP 546→547 decodes options")
    func dhcpv6() {
        var message: [UInt8] = [1, 0xAB, 0xCD, 0xEF]  // SOLICIT + transaction id
        message += [0x00, 0x01, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44]  // client id option
        message += [0x00, 0x08, 0x00, 0x02, 0x00, 0x00]  // elapsed time option

        let length = 8 + message.count
        let udp: [UInt8] = [0x02, 0x22, 0x02, 0x23,  // 546 -> 547
                            UInt8(length >> 8), UInt8(length & 0xFF), 0x00, 0x00]
        let packet = Packet.decode(
            Data(Self.ipv4(proto: 17, payloadLength: length) + udp + message),
            startingAt: .ipv4, using: .standard)

        #expect(packet.summary == "IPv4 | UDP | DHCPv6")
        let layer = packet.layer(DHCPv6.self)
        #expect(layer?.messageTypeName == "SOLICIT")
        #expect(layer?.transactionID == 0xABCDEF)
        #expect(layer?.options.count == 2)
        #expect(layer?.option(1) == Data([0x11, 0x22, 0x33, 0x44]))
    }

    // MARK: - NTP

    @Test("an NTP client request over UDP 123 decodes")
    func ntp() {
        var message: [UInt8] = [0x23, 0, 6, 0xEC]  // LI 0, v4, client; poll 6; prec -20
        message += Array(repeating: 0, count: 12)  // delay, dispersion, ref id
        message += Array(repeating: 0, count: 24)  // reference/origin/receive timestamps
        message += [0xEB, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]  // transmit

        let length = 8 + message.count
        let udp: [UInt8] = [0xC0, 0x00, 0x00, 0x7B,  // 49152 -> 123
                            UInt8(length >> 8), UInt8(length & 0xFF), 0x00, 0x00]
        let packet = Packet.decode(
            Data(Self.ipv4(proto: 17, payloadLength: length) + udp + message),
            startingAt: .ipv4, using: .standard)

        #expect(packet.summary == "IPv4 | UDP | NTP")
        let layer = packet.layer(NTP.self)
        #expect(layer?.version == 4)
        #expect(layer?.modeName == "client")
        #expect(layer?.poll == 6)
        #expect(layer?.precision == -20)
        #expect(layer?.transmitDate != nil)
        // The fraction half-bit: .5 seconds.
        let interval = layer!.transmitTimestamp & 0xFFFF_FFFF
        #expect(interval == 0x8000_0000)
    }

    // MARK: - Robustness

    @Test("truncated transport headers throw cleanly, never trap")
    func robustness() {
        let protos: [UInt8] = [2, 50, 51, 132, 136, 112]
        for proto in protos {
            for length in 0...6 {
                let payload = [UInt8](repeating: 0xFF, count: length)
                let packet = Self.decode(proto: proto, payload)
                _ = packet.summary
            }
        }
        // Fuzz the standalone app decoders directly.
        var generator = SystemRandomNumberGenerator()
        let decoders: [any LayerDecoder] = [
            DHCPv4Decoder(), DHCPv6Decoder(), NTPDecoder(), IGMPDecoder(), SCTPDecoder(),
        ]
        for decoder in decoders {
            for _ in 0..<200 {
                let count = Int.random(in: 0...300, using: &generator)
                var bytes = [UInt8](repeating: 0, count: count)
                for index in bytes.indices {
                    bytes[index] = UInt8.random(in: .min ... .max, using: &generator)
                }
                _ = try? decoder.decode(Data(bytes))
            }
        }
    }
}
