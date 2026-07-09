import Foundation
import Testing

@testable import SwiftPacket

@Suite("Link layers & tunnels — VLAN, MPLS, LLC/STP, LLDP, EAPOL, GRE, VXLAN, SLL, PFLog")
struct LinkLayerTests {

    /// An Ethernet header with the given EtherType (or 802.3 length).
    static func ethernet(type: UInt16) -> [UInt8] {
        [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
         UInt8(type >> 8), UInt8(type & 0xFF)]
    }

    /// The familiar IPv4/UDP/DNS stack from `ProtocolTests` (57 bytes).
    static let ipStack = ProtocolTests.ipv4Header + ProtocolTests.udpHeader + ProtocolTests.dnsQuery

    // MARK: - 802.1Q

    @Test("a VLAN-tagged frame decodes tag fields and chains inward")
    func vlan() {
        let bytes = Self.ethernet(type: 0x8100)
            + [0x60, 0x0A, 0x08, 0x00]  // prio 3, vid 10, inner IPv4
            + Self.ipStack
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | 802.1Q | IPv4 | UDP | DNS")
        let tag = packet.layer(Dot1Q.self)
        #expect(tag?.vlanID == 10)
        #expect(tag?.priority == 3)
        #expect(tag?.dropEligible == false)
        #expect(packet.layer(DNS.self)?.questions.first?.name == "example.com")
    }

    @Test("Q-in-Q double tagging chains through two VLAN layers")
    func qinq() {
        let bytes = Self.ethernet(type: 0x88A8)
            + [0x00, 0x64, 0x81, 0x00]  // outer vid 100
            + [0x00, 0x0A, 0x08, 0x00]  // inner vid 10
            + Self.ipStack
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | 802.1Q | 802.1Q | IPv4 | UDP | DNS")
        let tags = packet.layers.compactMap { $0 as? Dot1Q }
        #expect(tags.map(\.vlanID) == [100, 10])
    }

    // MARK: - MPLS

    @Test("an MPLS stack decodes labels and finds the IP payload by nibble")
    func mpls() {
        // Two labels: 100 (not bottom), 200 (bottom of stack).
        let entry1: [UInt8] = [0x00, 0x06, 0x40, 0x40]
        let entry2: [UInt8] = [0x00, 0x0C, 0x81, 0x3F]
        let bytes = Self.ethernet(type: 0x8847) + entry1 + entry2 + Self.ipStack
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | MPLS | IPv4 | UDP | DNS")
        let mpls = packet.layer(MPLS.self)
        #expect(mpls?.labels.map(\.label) == [100, 200])
        #expect(mpls?.labels.last?.bottomOfStack == true)
        #expect(mpls?.labels.first?.bottomOfStack == false)
        #expect(mpls?.labels.last?.ttl == 0x3F)
    }

    // MARK: - LLC / STP

    @Test("an 802.3 frame chains through LLC to a spanning-tree BPDU")
    func llcSTP() {
        var bpdu: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00]  // proto, version, type config, flags
        bpdu += [0x80, 0x00, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]  // root id
        bpdu += [0x00, 0x00, 0x00, 0x04]  // root path cost
        bpdu += [0x80, 0x00, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02]  // bridge id
        bpdu += [0x80, 0x01]  // port id
        bpdu += [0x01, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0F, 0x00]  // timers

        let llc: [UInt8] = [0x42, 0x42, 0x03]
        let bytes = Self.ethernet(type: UInt16(llc.count + bpdu.count)) + llc + bpdu
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | LLC | STP")
        let stp = packet.layer(STP.self)
        #expect(stp?.bpduType == 0)
        #expect(stp?.rootPathCost == 4)
        #expect(stp?.rootMAC?.description == "aa:bb:cc:00:00:01")
        #expect(stp?.bridgeMAC?.description == "aa:bb:cc:00:00:02")
        #expect(stp?.portID == 0x8001)
        #expect(stp?.maxAge == 0x1400)
    }

    @Test("LLC SNAP with a zero OUI routes by EtherType")
    func llcSNAP() {
        let snap: [UInt8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]
        let bytes = Self.ethernet(type: UInt16(snap.count + Self.ipStack.count))
            + snap + Self.ipStack
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | LLC | IPv4 | UDP | DNS")
        #expect(packet.layer(LLC.self)?.snapType == .ipv4)
    }

    // MARK: - LLDP

    @Test("LLDP TLVs decode chassis, port, TTL, and system name")
    func lldp() {
        var tlvs: [UInt8] = []
        tlvs += [0x02, 0x07, 4, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]  // chassis: MAC
        tlvs += [0x04, 0x06, 5] + Array("Gi0/1".utf8)  // port: interface name
        tlvs += [0x06, 0x02, 0x00, 0x78]  // ttl 120
        tlvs += [0x0A, 0x07] + Array("switch1".utf8)  // system name
        tlvs += [0x00, 0x00]  // end of LLDPDU

        let bytes = Self.ethernet(type: 0x88CC) + tlvs
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | LLDP")
        let lldp = packet.layer(LLDP.self)
        #expect(lldp?.chassisID == "aa:bb:cc:dd:ee:ff")
        #expect(lldp?.portID == "Gi0/1")
        #expect(lldp?.ttl == 120)
        #expect(lldp?.systemName == "switch1")
        #expect(lldp?.tlvs.count == 4)
    }

    // MARK: - EAPOL

    @Test("an EAPOL start packet decodes")
    func eapol() {
        let bytes = Self.ethernet(type: 0x888E) + [0x02, 0x01, 0x00, 0x00]
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | EAPOL")
        #expect(packet.layer(EAPOL.self)?.typeName == "Start")
        #expect(packet.layer(EAPOL.self)?.version == 2)
    }

    // MARK: - GRE

    @Test("a keyed GRE tunnel chains to the inner IPv4 packet")
    func gre() {
        var outer = ProtocolTests.ipv4Header
        outer[2] = 0x00
        outer[3] = UInt8(20 + 8 + Self.ipStack.count)  // total length
        outer[9] = 47  // GRE

        let greHeader: [UInt8] = [0x20, 0x00, 0x08, 0x00, 0xCA, 0xFE, 0xBA, 0xBE]
        let packet = Packet.decode(
            Data(outer + greHeader + Self.ipStack), startingAt: .ipv4, using: .standard)

        #expect(packet.summary == "IPv4 | GRE | IPv4 | UDP | DNS")
        let gre = packet.layer(GRE.self)
        #expect(gre?.keyPresent == true)
        #expect(gre?.key == 0xCAFE_BABE)
        #expect(gre?.checksumPresent == false)
        #expect(gre?.protocolType == .ipv4)
    }

    @Test("GRE carrying ERSPAN II exposes the mirrored Ethernet frame")
    func erspan() {
        let inner = Self.ethernet(type: 0x0800) + Self.ipStack
        let erspanHeader: [UInt8] = [0x10, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05]
        let greHeader: [UInt8] = [0x10, 0x00, 0x88, 0xBE, 0x00, 0x00, 0x00, 0x01]  // seq present

        var outer = ProtocolTests.ipv4Header
        outer[2] = 0x00
        outer[3] = UInt8(20 + greHeader.count + erspanHeader.count + inner.count)
        outer[9] = 47

        let packet = Packet.decode(
            Data(outer + greHeader + erspanHeader + inner), startingAt: .ipv4, using: .standard)

        #expect(packet.summary == "IPv4 | GRE | ERSPAN | Ethernet | IPv4 | UDP | DNS")
        let erspan = packet.layer(ERSPAN.self)
        #expect(erspan?.version == 1)
        #expect(erspan?.vlan == 10)
        #expect(erspan?.sessionID == 1)
        #expect(erspan?.index == 5)
    }

    // MARK: - VXLAN

    @Test("VXLAN over UDP 4789 exposes the inner Ethernet frame")
    func vxlan() {
        let inner = Self.ethernet(type: 0x0800) + Self.ipStack
        let vxlanHeader: [UInt8] = [0x08, 0, 0, 0, 0x00, 0x30, 0x39, 0]  // VNI 12345

        var udp: [UInt8] = [0xC0, 0x00, 0x12, 0xB5]  // 49152 -> 4789
        let udpLength = 8 + vxlanHeader.count + inner.count
        udp += [UInt8(udpLength >> 8), UInt8(udpLength & 0xFF), 0x00, 0x00]

        var outer = ProtocolTests.ipv4Header
        let total = 20 + udpLength
        outer[2] = UInt8(total >> 8)
        outer[3] = UInt8(total & 0xFF)

        let packet = Packet.decode(
            Data(outer + udp + vxlanHeader + inner), startingAt: .ipv4, using: .standard)

        #expect(packet.summary == "IPv4 | UDP | VXLAN | Ethernet | IPv4 | UDP | DNS")
        #expect(packet.layer(VXLAN.self)?.vni == 12345)
        #expect(packet.layer(VXLAN.self)?.vniValid == true)
    }

    // MARK: - EtherIP

    @Test("EtherIP (IP protocol 97) exposes the inner Ethernet frame")
    func etherIP() {
        let inner = Self.ethernet(type: 0x0800) + Self.ipStack
        var outer = ProtocolTests.ipv4Header
        outer[2] = 0x00
        outer[3] = UInt8(min(20 + 2 + inner.count, 255))
        outer[9] = 97

        let packet = Packet.decode(
            Data(outer + [0x30, 0x00] + inner), startingAt: .ipv4, using: .standard)
        #expect(packet.summary == "IPv4 | EtherIP | Ethernet | IPv4 | UDP | DNS")
        #expect(packet.layer(EtherIP.self)?.version == 3)
    }

    // MARK: - PPPoE / PPP

    @Test("a PPPoE session frame chains through PPP to IPv4")
    func pppoe() {
        let ppp: [UInt8] = [0x00, 0x21] + Self.ipStack
        let pppoeHeader: [UInt8] = [
            0x11, 0x00, 0x00, 0x01,
            UInt8(ppp.count >> 8), UInt8(ppp.count & 0xFF),
        ]
        let bytes = Self.ethernet(type: 0x8864) + pppoeHeader + ppp
        let packet = Packet.decode(Data(bytes), startingAt: .ethernet, using: .standard)

        #expect(packet.summary == "Ethernet | PPPoE | PPP | IPv4 | UDP | DNS")
        #expect(packet.layer(PPPoE.self)?.sessionID == 1)
        #expect(packet.layer(PPPoE.self)?.isSessionData == true)
        #expect(packet.layer(PPP.self)?.protocolNumber == 0x0021)
    }

    // MARK: - Linux SLL

    @Test("a Linux cooked capture decodes and chains by protocol")
    func linuxSLL() {
        var sll: [UInt8] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x06]  // to-us, ethernet, addrlen 6
        sll += [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00]  // address (8-byte field)
        sll += [0x08, 0x00]  // protocol IPv4
        let packet = Packet.decode(
            Data(sll + Self.ipStack), startingAt: .linuxSLL, using: .standard)

        #expect(packet.summary == "LinuxSLL | IPv4 | UDP | DNS")
        let layer = packet.layer(LinuxSLL.self)
        #expect(layer?.hardwareType == 1)
        #expect(layer?.address == Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        #expect(layer?.protocolType == .ipv4)
    }

    // MARK: - PFLog

    @Test("a pflog header decodes action and interface, then the IP packet")
    func pflog() {
        var header = [UInt8](repeating: 0, count: 64)
        header[0] = 64  // declared header length
        header[1] = 2  // AF_INET
        header[2] = 1  // block
        header[3] = 0
        let name = Array("en0".utf8)
        header.replaceSubrange(4..<(4 + name.count), with: name)
        header[39] = 7  // rule number (low byte of the UInt32 at offset 36)
        header[60] = 1  // direction: out

        let packet = Packet.decode(
            Data(header + Self.ipStack), startingAt: .pflog, using: .standard)

        #expect(packet.summary == "PFLog | IPv4 | UDP | DNS")
        let pflog = packet.layer(PFLog.self)
        #expect(pflog?.actionName == "block")
        #expect(pflog?.interfaceName == "en0")
        #expect(pflog?.ruleNumber == 7)
        #expect(pflog?.direction == 1)
    }

    // MARK: - Robustness

    @Test("truncated link headers throw cleanly, never trap")
    func robustness() {
        let starts: [LayerType] = [.vlan, .mpls, .llc, .stp, .lldp, .eapol,
                                   .gre, .vxlan, .etherIP, .erspan, .pppoe, .ppp,
                                   .linuxSLL, .pflog]
        for start in starts {
            for length in 0...8 {
                let data = Data(repeating: 0xFF, count: length)
                let packet = Packet.decode(data, startingAt: start, using: .standard)
                _ = packet.summary  // must not trap
            }
        }
    }
}
