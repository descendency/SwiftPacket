import Foundation
import SwiftPacket

// Decodes and prints a summary of each packet in a .pcap file.
//
//   dump-pcap [-x] <file.pcap> [bpf filter]
//
// -x prints a per-layer legend and hex dump of each packet.
// Example: dump-pcap -x capture.pcap "udp port 53"

var positional = Array(CommandLine.arguments.dropFirst())
let hexMode = positional.first == "-x"
if hexMode { positional.removeFirst() }

guard positional.count >= 1 else {
    FileHandle.standardError.write(Data("usage: dump-pcap [-x] <file.pcap> [bpf filter]\n".utf8))
    exit(2)
}

let path = positional[0]
let filter = positional.count >= 2 ? positional[1] : nil

func describe(_ packet: Packet, index: Int) -> String {
    var parts = ["#\(index)", packet.summary]

    if let ip = packet.layer(IPv4.self) {
        parts.append("\(ip.sourceAddress) → \(ip.destinationAddress)")
    } else if let ip = packet.layer(IPv6.self) {
        parts.append("\(ip.sourceAddress) → \(ip.destinationAddress)")
    }

    if let tcp = packet.layer(TCP.self) {
        parts.append("tcp \(tcp.sourcePort)→\(tcp.destinationPort)")
    } else if let udp = packet.layer(UDP.self) {
        parts.append("udp \(udp.sourcePort)→\(udp.destinationPort)")
    }

    if let dns = packet.layer(DNS.self), let question = dns.questions.first {
        parts.append("dns \(dns.isResponse ? "response" : "query") \(question.name)")
    }

    return parts.joined(separator: "  ")
}

do {
    let reader = try PcapFileReader(path: path)
    if let filter {
        try reader.setFilter(filter)
        print("Filter: \(filter)")
    }

    var count = 0
    for try await captured in reader.packets() {
        count += 1
        let packet = captured.decoded(using: .standard)
        print(describe(packet, index: count))
        if hexMode {
            print(packet.hexDump())
            print("")
        }
    }
    print("\n\(count) packet(s).")
} catch {
    FileHandle.standardError.write(Data("Error: \(error)\n".utf8))
    exit(1)
}
