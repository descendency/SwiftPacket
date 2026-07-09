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
        // OUI vendor lookup ships as a separate library so the ~exact MAC
        // registry table isn't forced on packet-decoding users who don't
        // want it.
        .library(name: "SwiftPacketOUI", targets: ["SwiftPacketOUI"]),
        .executable(name: "list-interfaces", targets: ["list-interfaces"]),
        .executable(name: "dump-pcap", targets: ["dump-pcap"]),
        .executable(name: "live-dump", targets: ["live-dump"]),
        .executable(name: "packet-bench", targets: ["packet-bench"]),
    ],
    dependencies: [
        // On Apple platforms the hashing in the TLS/X.509 path uses CryptoKit;
        // on Linux, swift-crypto provides the same API under `import Crypto`.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        // Thin C bridge to the system libpcap. No Swift here — just a module
        // map that exposes <pcap.h> and links -lpcap. macOS ships libpcap in
        // the SDK; on Linux install the development package (see providers).
        .systemLibrary(
            name: "Cpcap",
            path: "Sources/Cpcap",
            providers: [
                .apt(["libpcap-dev"]),
                .yum(["libpcap-devel"]),
                .brew(["libpcap"]),
            ]
        ),
        // Native Linux AF_PACKET capture helpers. The C compiles to an empty
        // translation unit off Linux (everything is `#ifdef __linux__`), so
        // the target is harmless on macOS and the dependency stays
        // unconditional.
        .target(
            name: "CLinuxPacket",
            path: "Sources/CLinuxPacket"
        ),
        // The library itself.
        .target(
            name: "SwiftPacket",
            dependencies: [
                "Cpcap",
                "CLinuxPacket",
                .product(
                    name: "Crypto", package: "swift-crypto",
                    condition: .when(platforms: [.linux])),
            ]
        ),
        // MAC OUI → vendor lookup, backed by a generated binary table shipped
        // as a resource.
        .target(
            name: "SwiftPacketOUI",
            dependencies: ["SwiftPacket"],
            exclude: ["Resources/generate-oui.py"],
            resources: [.copy("Resources/oui.bin")]
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
        .executableTarget(
            name: "live-dump",
            dependencies: ["SwiftPacket", "SwiftPacketOUI"]
        ),
        .executableTarget(
            name: "packet-bench",
            dependencies: ["SwiftPacket"]
        ),
        // Tests use Swift Testing (@Test / #expect), the idiomatic Swift 6 framework.
        .testTarget(
            name: "SwiftPacketTests",
            dependencies: ["SwiftPacket", "SwiftPacketOUI"]
        )
    ],
    // Compile the whole package in Swift 6 language mode: complete concurrency
    // checking is on by default, so data races are compile-time errors.
    swiftLanguageModes: [.v6]
)
