# Getting Started

Read a capture, decode it, filter it, and write it back out.

## Add the dependency

In your `Package.swift`:

```swift
.package(url: "https://github.com/yourname/SwiftPacket.git", from: "0.1.0")
```

Then add `"SwiftPacket"` to your target's dependencies.

## Read and decode a file

`.pcap` files need no special privileges.

```swift
import SwiftPacket

let reader = try PcapFileReader(path: "capture.pcap")
for try await captured in reader.packets() {
    let packet = captured.decoded(using: .standard)
    print(packet.summary)  // "Ethernet | IPv4 | UDP | DNS"
}
```

Reach into typed layers by type:

```swift
if let ip = packet.layer(IPv4.self) {
    print(ip.sourceAddress, "→", ip.destinationAddress, ip.proto)
}
```

## Decode lazily

When you only need one layer, decode just far enough to find it — deeper layers
are never touched:

```swift
if let tcp = captured.firstLayer(TCP.self, using: .standard) {
    print(tcp.sourcePort, "→", tcp.destinationPort, "syn:", tcp.syn)
}
```

## Filter

Filter in the kernel so non-matching packets never reach your process:

```swift
try reader.setFilter("tcp port 443")
```

Or evaluate a compiled filter against packets you already hold, no privileges
required:

```swift
let dns = try BPFProgram("udp port 53")
let matches = dns.matches(captured)
```

## Capture live

Live capture needs access to the BPF devices (`/dev/bpf*`) — typically elevated
privileges or a ChmodBPF-style grant, the same setup Wireshark uses.

```swift
let live = try LiveCapture(interface: "en0")
try live.setFilter("port 80")
for try await captured in live.packets() {
    print(captured.decoded(using: .standard).summary)
}
```

Cancelling the enclosing `Task` cleanly stops the capture.

## Build and serialize

Decoded layers can be written back to bytes with lengths and checksums fixed up
automatically:

```swift
let bytes = try packet.serializedData(
    options: SerializeOptions(fixLengths: true, computeChecksums: true)
)
```
