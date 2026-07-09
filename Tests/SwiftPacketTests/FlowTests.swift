import Foundation
import Testing

@testable import SwiftPacket

@Suite("Flow, Endpoint, and connection keys")
struct FlowTests {

    /// The full Ethernet/IPv4/UDP/DNS stack from `ProtocolTests`.
    static func samplePacket() -> Packet {
        let bytes = Data(
            ProtocolTests.ethernetHeader + ProtocolTests.ipv4Header + ProtocolTests.udpHeader
                + ProtocolTests.dnsQuery)
        return Packet.decode(bytes, startingAt: .ethernet, using: .standard)
    }

    @Test("endpoints render in their natural form and round-trip ports")
    func endpoints() {
        #expect(Endpoint(IPv4Address(rawValue: 0xC000_0201)).description == "192.0.2.1")
        #expect(Endpoint(MACAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])!).description
            == "aa:bb:cc:dd:ee:ff")
        let port = Endpoint(port: 443)
        #expect(port.port == 443)
        #expect(port.description == "443")
        #expect(port.kind == .port)
    }

    @Test("packet flows come from the right layers")
    func packetFlows() {
        let packet = Self.samplePacket()

        let link = packet.linkFlow
        #expect(link?.source.description == "bb:bb:bb:bb:bb:bb")
        #expect(link?.destination.description == "aa:aa:aa:aa:aa:aa")

        let network = packet.networkFlow
        #expect(network?.source.description == "192.0.2.1")
        #expect(network?.destination.description == "192.0.2.2")

        let transport = packet.transportFlow
        #expect(transport?.source.port == 49152)
        #expect(transport?.destination.port == 53)
    }

    @Test("a flow and its reverse are distinct but share a canonical form")
    func canonicalization() {
        let forward = Flow(
            source: Endpoint(IPv4Address(rawValue: 0x0A00_0001)),
            destination: Endpoint(IPv4Address(rawValue: 0x0A00_0002)))
        let backward = forward.reversed

        #expect(forward != backward)
        #expect(forward.hashValue != backward.hashValue || forward == backward)  // directional
        // Both directions canonicalize to the same value — the flow-table key.
        #expect(forward.canonical == backward.canonical)

        var table: [Flow: Int] = [:]
        table[forward.canonical, default: 0] += 1
        table[backward.canonical, default: 0] += 1
        #expect(table.count == 1)
        #expect(table.values.first == 2)
    }

    @Test("connection keys fold both directions of a conversation together")
    func connectionKeys() {
        let clientToServer = Self.samplePacket()

        // Synthesize the reverse packet: swap IPs and ports.
        var reverseBytes = ProtocolTests.ethernetHeader
        var ip = ProtocolTests.ipv4Header
        ip.replaceSubrange(12..<16, with: [0xC0, 0x00, 0x02, 0x02])  // src 192.0.2.2
        ip.replaceSubrange(16..<20, with: [0xC0, 0x00, 0x02, 0x01])  // dst 192.0.2.1
        var udp = ProtocolTests.udpHeader
        udp.replaceSubrange(0..<2, with: [0x00, 0x35])  // src port 53
        udp.replaceSubrange(2..<4, with: [0xC0, 0x00])  // dst port 49152
        reverseBytes += ip + udp + ProtocolTests.dnsQuery
        let serverToClient = Packet.decode(Data(reverseBytes), startingAt: .ethernet, using: .standard)

        let key1 = clientToServer.connectionKey
        let key2 = serverToClient.connectionKey
        #expect(key1 != nil)
        #expect(key1 == key2)  // same connection, both directions
    }

    @Test("a packet with no IP layer has no network flow or connection key")
    func noNetworkLayer() {
        let arp: [UInt8] = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xC0, 0x00, 0x02, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x02,
        ]
        let packet = Packet.decode(Data(arp), startingAt: .arp, using: .standard)
        #expect(packet.networkFlow == nil)
        #expect(packet.transportFlow == nil)
        #expect(packet.connectionKey == nil)
    }
}

@Suite("Hex dump")
struct HexDumpTests {

    @Test("empty data dumps to an empty string")
    func empty() {
        #expect(Data().hexDump() == "")
    }

    @Test("a short buffer renders offset, hex columns, and ASCII gutter")
    func shortBuffer() {
        let data = Data("Hello, SwiftPacket!".utf8)
        let dump = data.hexDump()
        let lines = dump.split(separator: "\n")
        #expect(lines.count == 2)  // 19 bytes → two rows
        #expect(lines[0].hasPrefix("0000  "))
        #expect(lines[1].hasPrefix("0010  "))
        // The printable text appears in the gutter (16 bytes per row).
        #expect(dump.contains("Hello, SwiftPack"))
        #expect(lines[1].hasSuffix("et!"))
        // Non-printable bytes render as dots.
        #expect(Data([0x00, 0x1F, 0x7F, 0x41]).hexDump().hasSuffix("...A"))
    }

    @Test("packet hexDump carries a layer legend over the full bytes")
    func packetDump() {
        let packet = FlowTests.samplePacket()
        let dump = packet.hexDump()
        #expect(dump.contains("Ethernet | IPv4 | UDP | DNS  (71 bytes)"))
        #expect(dump.contains("[0x0000..<0x000e] Ethernet"))
        #expect(dump.contains("[0x000e..<0x0022] IPv4"))
        // The dump body covers every byte of the packet.
        let bodyLines = dump.split(separator: "\n").filter { $0.hasPrefix("00") && $0.contains("  ") }
        #expect(bodyLines.count >= 5)  // 71 bytes → 5 hex rows
    }
}
