import Foundation
import Testing

@testable import SwiftPacket

@Suite("IP protocol accessor")
struct IPProtocolTests {

    @Test("well-known protocol numbers have IANA names")
    func names() {
        #expect(IPProtocol.tcp.name == "TCP")
        #expect(IPProtocol.udp.name == "UDP")
        #expect(IPProtocol.icmp.name == "ICMP")
        #expect(IPProtocol.icmpv6.name == "ICMPv6")
        #expect(IPProtocol.gre.name == "GRE")
        #expect(IPProtocol.esp.name == "ESP")
        #expect(IPProtocol.sctp.name == "SCTP")
        #expect(IPProtocol.ospf.description == "OSPF")

        // Unknown numbers keep their raw identity rather than becoming "other".
        let unknown = IPProtocol(rawValue: 253)
        #expect(unknown.name == nil)
        #expect(unknown.description == "proto-253")
        #expect(unknown.rawValue == 253)
    }

    @Test("Packet.ipProtocol reads the IPv4 protocol field uniformly")
    func packetAccessorV4() {
        // Ethernet + IPv4 carrying OSPF (proto 89) — no decoder registered,
        // but the protocol number must still be visible.
        var bytes = ProtocolTests.ethernetHeader
        var ip = ProtocolTests.ipv4Header
        ip[9] = 89  // protocol = OSPF
        bytes += ip + [0x01, 0x02, 0x03, 0x04]

        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)
        #expect(packet.ipProtocol == .ospf)
        #expect(packet.ipProtocol?.description == "OSPF")
    }

    @Test("Packet.ipProtocol reads the IPv6 next-header field uniformly")
    func packetAccessorV6() {
        var bytes: [UInt8] = [0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x84, 0x40]  // next header SCTP
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
        bytes += [0xDE, 0xAD, 0xBE, 0xEF]

        let packet = Packet.decode(Data(bytes), startingAt: .ipv6, using: .standard)
        #expect(packet.ipProtocol == .sctp)
        // The uniform `proto` alias matches IPv4's field name.
        #expect(packet.layer(IPv6.self)?.proto == .sctp)
    }

    @Test("Packet.ipProtocol is nil without an IP layer")
    func packetAccessorNoIP() {
        let arp: [UInt8] = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0xC0, 0x00, 0x02, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x02, 0x02,
        ]
        let packet = Packet.decode(Data(arp), startingAt: .arp, using: .standard)
        #expect(packet.ipProtocol == nil)
    }
}
