import Foundation
import SwiftPacket

// Decodes and prints a summary of each packet in a .pcap file.
//
//   dump-pcap <file.pcap> [bpf filter]
//
// Example: dump-pcap capture.pcap "udp port 53"

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    FileHandle.standardError.write(Data("usage: dump-pcap <file.pcap> [bpf filter]\n".utf8))
    exit(2)
}

let path = arguments[1]
let filter = arguments.count >= 3 ? arguments[2] : nil

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
        print(describe(captured.decoded(using: .standard), index: count))
    }
    print("\n\(count) packet(s).")
} catch {
    FileHandle.standardError.write(Data("Error: \(error)\n".utf8))
    exit(1)
}
