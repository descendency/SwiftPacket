import Foundation
import SwiftPacket
import SwiftPacketOUI

// Captures live from an interface and prints a one-line summary per packet,
// annotating Ethernet source/destination with their OUI vendor.
//
//   live-dump <interface> [bpf filter]
//
// Live capture needs privileges: root/ChmodBPF on macOS, root or
// CAP_NET_RAW on Linux.

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    let message = """
        usage: live-dump <interface> [bpf filter]
               (try `list-interfaces` to see available interfaces)

        """
    FileHandle.standardError.write(Data(message.utf8))
    exit(2)
}

let interfaceName = arguments[1]
let filter = arguments.count >= 3 ? arguments[2] : nil

func annotate(_ mac: MACAddress) -> String {
    if let vendor = mac.vendor {
        return "\(mac) (\(vendor))"
    }
    return mac.description
}

func describe(_ packet: Packet, index: Int) -> String {
    var parts = ["#\(index)", packet.summary]

    if let ethernet = packet.layer(Ethernet.self) {
        parts.append("\(annotate(ethernet.source)) → \(annotate(ethernet.destination))")
    }
    if let ip = packet.layer(IPv4.self) {
        parts.append("\(ip.sourceAddress) → \(ip.destinationAddress)")
    } else if let ip = packet.layer(IPv6.self) {
        parts.append("\(ip.sourceAddress) → \(ip.destinationAddress)")
    }
    if let proto = packet.ipProtocol {
        parts.append(proto.description)
    }
    return parts.joined(separator: "  ")
}

do {
    let capture = try LiveCapture(interface: interfaceName)
    if let filter {
        try capture.setFilter(filter)
        print("Filter: \(filter)")
    }
    print("Capturing on \(interfaceName) (link \(capture.linkType)). Ctrl-C to stop.")

    var count = 0
    for try await captured in capture.packets() {
        count += 1
        let packet = captured.decoded(using: .standard)
        print(describe(packet, index: count))
    }
} catch {
    FileHandle.standardError.write(Data("Error: \(error)\n".utf8))
    exit(1)
}
