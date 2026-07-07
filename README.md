# SwiftPacket

A packet capture, decoding, and serialization library for macOS, written in
idiomatic Swift 6. Spiritually a Swift analogue of Google's
[GoPacket](https://github.com/google/gopacket).

> **Version 0.1.0** — a complete, tested capture → decode → serialize → filter
> pipeline. Requires macOS 13+ and the system libpcap (present by default on
> macOS).

## Installation

Add SwiftPacket to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/yourname/SwiftPacket.git", from: "0.1.0")
]
```

and list `"SwiftPacket"` among your target's dependencies.

## Examples

Two runnable command-line tools ship with the package:

```sh
# List capture interfaces (no privileges needed).
swift run list-interfaces

# Decode every packet in a file, optionally filtered.
swift run dump-pcap capture.pcap "udp port 53"
```

## Filtering

```swift
// Kernel-side: only matching packets are read.
let reader = try PcapFileReader(path: "capture.pcap")
try reader.setFilter("tcp port 443")

// Userspace: test any packet against a compiled program (no privileges needed).
let dnsFilter = try BPFProgram("udp port 53")
for try await captured in reader.packets() where dnsFilter.matches(captured) {
    // …
}
```

## Lazy decoding

```swift
// Decodes only as far as the transport layer — never touches the payload.
if let udp = captured.firstLayer(UDP.self, using: .standard) {
    print(udp.sourcePort, "->", udp.destinationPort)
}
```

## Usage

```swift
import SwiftPacket

let reader = try PcapFileReader(path: "capture.pcap")
for try await captured in reader.packets() {
    let packet = captured.decoded(using: .standard)
    print(packet.summary)  // e.g. "Ethernet | IPv4 | UDP | DNS"

    if let ip = packet.layer(IPv4.self) {
        print(ip.sourceAddress, "->", ip.destinationAddress, ip.proto)
    }
    if let dns = packet.layer(DNS.self), let q = dns.questions.first {
        print("DNS query:", q.name)
    }
}
```

## Requirements

- macOS 13 or later
- Swift 6 toolchain (Xcode 16 or a matching open-source toolchain)
- libpcap (ships with macOS)

## Build & test

```sh
swift build
swift test
```

Live capture (later phases) will require access to the BPF devices
(`/dev/bpf*`), which normally means elevated privileges or a ChmodBPF-style
permission setup — the same approach Wireshark uses. Reading `.pcap` files
needs no special permissions.

## Roadmap

- [x] **Phase 0** — Project bootstrap: SwiftPM package, libpcap C bridge, CI, license, passing test.
- [x] **Phase 1** — Capture & file I/O foundation (`PacketSource`, libpcap backend, pcap read/write, async sequence).
- [x] **Phase 2** — Core decoding model (`Layer` protocol, `Packet`, bounds-checked reader, `LayerType` registry).
- [x] **Phase 3** — Protocol decoders (Ethernet, IPv4/IPv6, ARP, TCP/UDP/ICMP, DNS).
- [x] **Phase 4** — Serialization (`SerializeBuffer`, checksums, length fixup).
- [x] **Phase 5** — Filtering (BPF) & performance.
- [x] **Phase 6** — Hardening (fuzzing), DocC docs, examples, tagged release.

## Documentation

API docs are provided as a DocC catalog. Build them with the
[Swift-DocC plugin](https://github.com/swiftlang/swift-docc-plugin):

```sh
swift package generate-documentation --target SwiftPacket
```

or in Xcode via **Product → Build Documentation**.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
