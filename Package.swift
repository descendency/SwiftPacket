// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SwiftPacket",
    platforms: [
        // macOS 13 (Ventura) is the floor: gives us modern Swift Concurrency
        // and Swift Testing without back-deployment gymnastics.
        .macOS(.v13)
    ],
    products: [
        .library(name: "SwiftPacket", targets: ["SwiftPacket"]),
        .executable(name: "list-interfaces", targets: ["list-interfaces"]),
        .executable(name: "dump-pcap", targets: ["dump-pcap"]),
    ],
    targets: [
        // Thin C bridge to the system libpcap. No Swift here — just a module
        // map that exposes <pcap.h> and links -lpcap.
        .systemLibrary(
            name: "Cpcap",
            path: "Sources/Cpcap"
        ),
        // The library itself.
        .target(
            name: "SwiftPacket",
            dependencies: ["Cpcap"]
        ),
        // Example command-line tools that exercise the public API.
        .executableTarget(
            name: "list-interfaces",
            dependencies: ["SwiftPacket"]
        ),
        .executableTarget(
            name: "dump-pcap",
            dependencies: ["SwiftPacket"]
        ),
        // Tests use Swift Testing (@Test / #expect), the idiomatic Swift 6 framework.
        .testTarget(
            name: "SwiftPacketTests",
            dependencies: ["SwiftPacket"]
        )
    ],
    // Compile the whole package in Swift 6 language mode: complete concurrency
    // checking is on by default, so data races are compile-time errors.
    swiftLanguageModes: [.v6]
)
