import Foundation
import SwiftPacket

// Lists the network interfaces libpcap can capture from. Needs no privileges.
print("SwiftPacket \(SwiftPacket.version) — \(SwiftPacket.libpcapVersion)")
print()

do {
    let interfaces = try Devices.all()
    if interfaces.isEmpty {
        print("No interfaces found (elevated privileges may be required).")
    }
    for interface in interfaces {
        var flags: [String] = []
        if interface.isUp { flags.append("up") }
        if interface.isRunning { flags.append("running") }
        if interface.isLoopback { flags.append("loopback") }
        let status = flags.isEmpty ? "" : " [\(flags.joined(separator: ", "))]"
        let description = interface.descriptionText.map { " — \($0)" } ?? ""
        print("\(interface.name)\(status)\(description)")
    }
} catch {
    FileHandle.standardError.write(Data("Error: \(error)\n".utf8))
    exit(1)
}
