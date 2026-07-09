import Foundation
import Testing

@testable import SwiftPacket

@Suite("Phase 13 — NDP/MLD, CDP, EAP, OSPF")
struct DiscoveryProtocolTests {

    /// Wraps an ICMPv6 body (message type + code + body) as a bare ICMPv6
    /// message and decodes it.
    static func icmpv6(type: UInt8, body: [UInt8]) throws -> ICMPv6 {
        let bytes = [type, 0, 0, 0] + body  // type, code, checksum(2), body
        let result = try ICMPv6Decoder().decode(Data(bytes))
        return result.layer as! ICMPv6
    }

    @Test("Router Advertisement decodes flags, timers, prefix, and MTU")
    func routerAdvertisement() throws {
        var body: [UInt8] = [64, 0x80, 0x07, 0x08]  // hop limit 64, managed flag, lifetime 1800
        body += [0x00, 0x00, 0xEA, 0x60]  // reachable time
        body += [0x00, 0x00, 0x03, 0xE8]  // retrans timer
        // Prefix-information option (type 3, length 4×8=32): /64, on-link+auto.
        body += [3, 4, 64, 0xC0, 0x00, 0x27, 0x8D, 0x00, 0x00, 0x09, 0x3A, 0x80, 0, 0, 0, 0]
        body += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        // MTU option (type 5, length 1×8=8): reserved(2) + mtu(4).
        body += [5, 1, 0, 0, 0x00, 0x00, 0x05, 0xDC]

        let icmp = try Self.icmpv6(type: 134, body: body)
        let ra = try #require(icmp.routerAdvertisement)
        #expect(ra.hopLimit == 64)
        #expect(ra.managedAddressConfig)
        #expect(ra.routerLifetime == 1800)
        #expect(ra.mtu == 1500)
        let prefix = try #require(ra.prefixes.first)
        #expect(prefix.prefixLength == 64)
        #expect(prefix.onLink && prefix.autonomous)
        #expect(prefix.prefix.description == "2001:db8::")
    }

    @Test("Neighbor Advertisement decodes flags, target, and link address")
    func neighborAdvertisement() throws {
        var body: [UInt8] = [0x60, 0x00, 0x00, 0x00]  // solicited + override flags
        body += [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]  // target
        body += [2, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]  // target link-layer addr option

        let icmp = try Self.icmpv6(type: 136, body: body)
        let na = try #require(icmp.neighborAdvertisement)
        #expect(na.isAdvertisement)
        #expect(na.solicited && na.override && !na.router)
        #expect(na.targetAddress.description == "fe80::1")
        #expect(na.linkLayerAddress?.description == "aa:bb:cc:dd:ee:ff")
    }

    @Test("MLDv2 report decodes its multicast-address records")
    func mldv2Report() throws {
        var body: [UInt8] = [0x00, 0x00, 0x00, 0x01]  // reserved, 1 record
        body += [4, 0, 0x00, 0x01]  // record type 4 (change-to-exclude), 1 source
        body += [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]  // multicast ff02::1
        body += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09]  // source

        let icmp = try Self.icmpv6(type: 143, body: body)
        let records = try #require(icmp.mldv2Records)
        #expect(records.count == 1)
        #expect(records[0].recordType == 4)
        #expect(records[0].multicastAddress.description == "ff02::1")
        #expect(records[0].sourceAddresses.first?.description == "2001:db8::9")
    }

    @Test("MLDv1 query and report decode the group address")
    func mldv1() throws {
        var body: [UInt8] = [0x27, 0x10, 0x00, 0x00]  // max resp delay 10000ms, reserved
        body += [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]  // ff02::1
        let query = try Self.icmpv6(type: 130, body: body)
        #expect(query.mldQuery?.multicastAddress.description == "ff02::1")
        #expect(query.mldQuery?.isVersion2 == false)

        let report = try Self.icmpv6(type: 131, body: body)
        #expect(report.mldv1MulticastAddress?.description == "ff02::1")
    }

    @Test("CDP decodes device ID, port, and platform TLVs")
    func cdp() throws {
        var body: [UInt8] = [0x02, 0xB4, 0x00, 0x00]  // version 2, ttl 180, checksum
        func tlv(_ type: UInt16, _ text: String) -> [UInt8] {
            let value = Array(text.utf8)
            let length = 4 + value.count
            return [UInt8(type >> 8), UInt8(type & 0xFF), UInt8(length >> 8), UInt8(length & 0xFF)] + value
        }
        body += tlv(1, "Switch1")  // Device ID
        body += tlv(3, "GigabitEthernet0/1")  // Port ID
        body += tlv(6, "cisco WS-C2960")  // Platform

        let result = try CDPDecoder().decode(Data(body))
        let cdp = try #require(result.layer as? CDP)
        #expect(cdp.version == 2)
        #expect(cdp.ttl == 180)
        #expect(cdp.deviceID == "Switch1")
        #expect(cdp.portID == "GigabitEthernet0/1")
        #expect(cdp.platform == "cisco WS-C2960")
    }

    @Test("CDP auto-routes from an LLC/SNAP frame with the Cisco OUI")
    func cdpRouting() throws {
        // 802.3 length-framed Ethernet → LLC/SNAP (OUI 00:00:0c, proto 0x2000).
        let snap: [UInt8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]
        let cdpBody: [UInt8] = [0x02, 0xB4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0B]
            + Array("Switch1".utf8)
        let frame = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
            + [UInt8(0), UInt8(snap.count + cdpBody.count)] + snap + cdpBody
        let packet = Packet.decode(Data(frame), startingAt: .ethernet, using: .standard)
        #expect(packet.summary == "Ethernet | LLC | CDP")
        #expect(packet.layer(CDP.self)?.deviceID == "Switch1")
    }

    @Test("EAP decodes an Identity response and routes from EAPOL")
    func eap() throws {
        // EAPOL (version 2, type 0 EAP-Packet) wrapping an EAP Response/Identity.
        let eap: [UInt8] = [2, 0, 0, 9, 1] + Array("bob".utf8)  // code 2, id 0, len 9, type 1
        let eapol: [UInt8] = [0x02, 0x00, 0x00, UInt8(eap.count)] + eap
        let frame = Array(ProtocolTests.ethernetHeader.dropLast(2)) + [0x88, 0x8E] + eapol
        let packet = Packet.decode(Data(frame), startingAt: .ethernet, using: .standard)
        #expect(packet.summary == "Ethernet | EAPOL | EAP")
        let eapLayer = packet.layer(EAP.self)
        #expect(eapLayer?.codeName == "Response")
        #expect(eapLayer?.methodType == 1)
        #expect(eapLayer?.identity == "bob")
    }

    @Test("OSPFv2 Hello decodes neighbors and DR/BDR, routing from IP proto 89")
    func ospfHello() throws {
        var ospf: [UInt8] = [2, 1, 0, 44]  // version 2, Hello, length 44
        ospf += [1, 1, 1, 1]  // router ID 1.1.1.1
        ospf += [0, 0, 0, 0]  // area ID
        ospf += [0, 0, 0, 0]  // checksum, auth type
        ospf += [0, 0, 0, 0, 0, 0, 0, 0]  // auth data
        ospf += [255, 255, 255, 0]  // network mask /24
        ospf += [0x00, 0x0A, 0x00, 1]  // hello interval 10, options, priority 1
        ospf += [0, 0, 0, 40]  // dead interval 40
        ospf += [10, 0, 0, 1]  // DR
        ospf += [10, 0, 0, 2]  // BDR
        ospf += [2, 2, 2, 2]  // one neighbor

        var ip = ProtocolTests.ipv4Header
        ip[9] = 89  // OSPF
        let total = 20 + ospf.count
        ip[2] = UInt8(total >> 8)
        ip[3] = UInt8(total & 0xFF)

        let packet = Packet.decode(Data(ip + ospf), startingAt: .ipv4, using: .standard)
        #expect(packet.summary == "IPv4 | OSPF")
        let hello = try #require(packet.layer(OSPF.self)?.hello)
        #expect(packet.layer(OSPF.self)?.messageTypeName == "Hello")
        #expect(packet.layer(OSPF.self)?.routerID.description == "1.1.1.1")
        #expect(hello.helloInterval == 10)
        #expect(hello.routerDeadInterval == 40)
        #expect(hello.designatedRouter.description == "10.0.0.1")
        #expect(hello.neighbors.map(\.description) == ["2.2.2.2"])
    }
}

@Suite("Phase 13 — wireless (Radiotap + 802.11)")
struct WirelessTests {

    @Test("a radiotap header routes to an 802.11 data frame carrying LLC/IP")
    func radiotapToData() {
        // Radiotap: version 0, pad, length 8, present = Channel(bit3) only.
        // Wait — keep it minimal: present bitmap with no fields, length 8.
        let radiotap: [UInt8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]

        // 802.11 QoS data frame (type 2, subtype 8), from-DS.
        var dot11: [UInt8] = [0x88, 0x02, 0x00, 0x00]  // frame control + duration
        dot11 += [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]  // addr1 (dest)
        dot11 += [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]  // addr2 (BSSID)
        dot11 += [0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]  // addr3 (source)
        dot11 += [0x00, 0x00]  // sequence control
        dot11 += [0x00, 0x00]  // QoS control
        // LLC/SNAP → IPv4 → the standard UDP/DNS stack.
        let snap: [UInt8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]
        let ipStack = ProtocolTests.ipv4Header + ProtocolTests.udpHeader + ProtocolTests.dnsQuery

        let packet = Packet.decode(
            Data(radiotap + dot11 + snap + ipStack), startingAt: .radiotap, using: .standard)
        #expect(packet.summary == "Radiotap | 802.11 | LLC | IPv4 | UDP | DNS")

        let wifi = packet.layer(Dot11.self)
        #expect(wifi?.isData == true)
        #expect(wifi?.typeName == "Data")
        #expect(wifi?.address1?.description == "aa:aa:aa:aa:aa:aa")
        #expect(wifi?.bssid?.description == "cc:cc:cc:cc:cc:cc")
        #expect(packet.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    @Test("radiotap decodes channel frequency and antenna signal when present")
    func radiotapFields() throws {
        // present = Flags(1) | Rate(2) | Channel(3) | Antenna signal(5) = 0x2E.
        var bytes: [UInt8] = [0x00, 0x00, 0x0D, 0x00, 0x2E, 0x00, 0x00, 0x00]
        bytes += [0x10]  // Flags (1 byte)
        bytes += [0x02]  // Rate (1 byte)
        bytes += [0x6C, 0x09, 0x00, 0x00]  // Channel: freq 2412 MHz (0x096C), flags
        bytes += [0xD5]  // Antenna signal: -43 dBm
        bytes += [0x00, 0x00]  // a scrap of payload so it chains

        let result = try RadiotapDecoder().decode(Data(bytes))
        let radiotap = try #require(result.layer as? Radiotap)
        #expect(radiotap.headerLength == 13)
        #expect(radiotap.channelFrequency == 2412)
        #expect(radiotap.antennaSignal == -43)
    }

    @Test("802.11 management frames carry three addresses but no LLC payload")
    func managementFrame() throws {
        // Beacon (type 0, subtype 8).
        var dot11: [UInt8] = [0x80, 0x00, 0x00, 0x00]
        dot11 += [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]  // addr1 broadcast
        dot11 += [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]  // addr2
        dot11 += [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]  // addr3 (BSSID)
        dot11 += [0x00, 0x00]  // sequence control
        dot11 += [0xDE, 0xAD]  // beacon body (opaque)

        let result = try Dot11Decoder().decode(Data(dot11))
        let frame = try #require(result.layer as? Dot11)
        #expect(frame.isManagement)
        #expect(frame.address1?.description == "ff:ff:ff:ff:ff:ff")
        #expect(frame.bssid?.description == "bb:bb:bb:bb:bb:bb")
    }

    @Test("wireless decoders never trap on random bytes")
    func robustness() {
        var generator = SystemRandomNumberGenerator()
        for start in [LayerType.radiotap, .dot11] {
            for _ in 0..<300 {
                let count = Int.random(in: 0...60, using: &generator)
                var bytes = [UInt8](repeating: 0, count: count)
                for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max, using: &generator) }
                _ = Packet.decode(Data(bytes), startingAt: start, using: .standard).summary
            }
        }
    }
}

@Suite("Phase 13 — serialization breadth")
struct SerializationBreadthTests {

    /// Round-trips a packet through serialize → decode and checks the summary.
    func roundTrip(_ data: Data, startingAt start: LayerType, expect summary: String) throws {
        let packet = Packet.decode(data, startingAt: start, using: .standard)
        #expect(packet.summary == summary)
        let serialized = try packet.serializedData(options: SerializeOptions(fixLengths: false, computeChecksums: false))
        let reDecoded = Packet.decode(serialized, startingAt: start, using: .standard)
        #expect(reDecoded.summary == summary)
    }

    @Test("VLAN-tagged frame serializes and round-trips")
    func vlan() throws {
        let ipStack = ProtocolTests.ipv4Header + ProtocolTests.udpHeader + ProtocolTests.dnsQuery
        let frame = Array(ProtocolTests.ethernetHeader.dropLast(2)) + [0x81, 0x00]
            + [0x60, 0x0A, 0x08, 0x00] + ipStack
        let packet = Packet.decode(Data(frame), startingAt: .ethernet, using: .standard)
        let serialized = try packet.serializedData(
            options: SerializeOptions(fixLengths: false, computeChecksums: false))
        let reDecoded = Packet.decode(serialized, startingAt: .ethernet, using: .standard)
        #expect(reDecoded.summary == "Ethernet | 802.1Q | IPv4 | UDP | DNS")
        #expect(reDecoded.layer(Dot1Q.self)?.vlanID == 10)
        #expect(reDecoded.layer(Dot1Q.self)?.priority == 3)
    }

    @Test("VXLAN header serializes and preserves the VNI")
    func vxlan() throws {
        // Decode a VXLAN header (VNI 12345), then serialize it back and confirm
        // the VNI survives.
        let original = try VXLANDecoder().decode(Data([0x08, 0, 0, 0, 0x00, 0x30, 0x39, 0, 0x01, 0x02]))
        let vxlan = try #require(original.layer as? VXLAN)
        #expect(vxlan.vni == 12345)

        var stack = SerializeBuffer()
        stack.prepend(Data([0x01, 0x02]))
        try vxlan.serialize(into: &stack, context: SerializationContext(), options: SerializeOptions())
        let reDecoded = try VXLANDecoder().decode(stack.bytes)
        #expect((reDecoded.layer as? VXLAN)?.vni == 12345)
        #expect((reDecoded.layer as? VXLAN)?.vniValid == true)
    }

    @Test("DHCP and NTP layers serialize by preserving their bytes")
    func headerPreserving() throws {
        // A minimal NTP packet.
        let ntpBytes = [UInt8](repeating: 0, count: 48)
        var ntp = Data(ntpBytes)
        ntp[0] = 0x23
        let packet = Packet.decode(
            Data(ProtocolTests.ipv4Header.prefix(0)) + ntp, startingAt: .ntp, using: .standard)
        let serialized = try packet.serializedData()
        #expect(serialized.count == 48)
    }
}
