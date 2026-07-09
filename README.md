# SwiftPacket

A packet capture, decoding, and serialization library for macOS and Linux,
written in idiomatic Swift 6. Spiritually a Swift analogue of Google's
[GoPacket](https://github.com/google/gopacket).

> **Version 0.2.0 (unreleased)** — a complete, tested capture → decode →
> serialize → filter pipeline, now with TLS/X.509, ICMP quoted-packet, and
> structured DNS decoding, on macOS 13+ and Linux (Swift 6 toolchain +
> libpcap).

## Installation

Add SwiftPacket to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/yourname/SwiftPacket.git", from: "0.1.0")
]
```

and list `"SwiftPacket"` among your target's dependencies.

## Examples

Three runnable command-line tools ship with the package:

```sh
# List capture interfaces (no privileges needed).
swift run list-interfaces

# Decode every packet in a file, optionally filtered.
swift run dump-pcap capture.pcap "udp port 53"

# Capture live, annotating MAC addresses with their OUI vendor (needs privileges).
sudo swift run live-dump en0 "tcp port 443"
```

## Vendor lookup

The optional `SwiftPacketOUI` library resolves a MAC address to its registered
vendor using the IEEE OUI registry (bundled as a generated table):

```swift
import SwiftPacket
import SwiftPacketOUI

MACAddress([0x00, 0x1B, 0x63, 0, 0, 1])?.vendor  // "Apple, Inc."
```

## Flows, statistics, and injection

```swift
let capture = try LiveCapture(interface: "en0")
for try await captured in capture.packets() {
    let packet = captured.decoded(using: .standard)
    // A canonical 5-tuple that keys both directions of a connection alike:
    if let key = packet.connectionKey { flowTable[key, default: 0] += 1 }
}
let stats = try capture.statistics()   // received / dropped counters
print(stats.dropRate)

// Craft and inject a frame:
try capture.send(packet.serializedData())
```

## Reassembly

Fragmented datagrams and TCP streams reassemble through actors you feed every
packet. The `TLSStreamAssembler` completes the story for TLS — it recovers a
certificate chain even when the handshake is split across many TCP segments:

```swift
let tls = TLSStreamAssembler()
for try await captured in reader.packets() {
    let packet = captured.decoded(using: .standard)
    for event in await tls.process(packet) where event.discovery == .certificates {
        for cert in event.tls.certificates {
            print(cert.subject.commonName ?? "?", cert.sha256Fingerprint)
        }
    }
}

// Lower-level building blocks are available too:
let defrag = IPDefragmenter()          // IPv4/IPv6 defragmentation
let streams = TCPReassembler()         // ordered per-direction byte streams
```

## Native AF_PACKET capture (Linux)

For high-rate or multi-core capture, `AFPacketCapture` (Linux only) reads from
a memory-mapped `TPACKET_V3` ring and supports kernel `PACKET_FANOUT` load
balancing — several instances on the same interface share its traffic across
cores, which libpcap's portable API cannot express. Filters still use tcpdump
syntax. `LiveCapture` (libpcap) remains the cross-platform default. See
[Docs/AFPacket.md](Docs/AFPacket.md).

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

## Fast path

For throughput-bound loops, `StackDecoder` decodes the common stack into a
reusable `DecodedStack` with no per-packet allocation — roughly twice as fast
as `Packet.decode` on Ethernet/IPv4/TCP:

```swift
let decoder = StackDecoder()
var stack = DecodedStack()          // reused across packets
for try await captured in reader.packets() {
    decoder.decode(captured, into: &stack)
    if let tcp = stack.tcp { tally(tcp.destinationPort) }
}
```

Measure it yourself: `swift run -c release packet-bench`.

## TLS & certificates

TCP payloads that begin with a well-formed TLS record header decode as a
`TLS` layer automatically — SNI, ALPN, JA3/JA3S, and (for TLS ≤ 1.2)
certificate chains:

```swift
if let tls = packet.layer(TLS.self) {
    tls.serverName                       // "example.com" (SNI)
    tls.clientHello?.ja3                 // "0dcde0fb73b656fd…"
    if let cert = tls.certificates.first {
        print(cert.subject.commonName ?? "?", cert.notAfter, cert.sha256Fingerprint)
    }
}

// A handshake flight that spans TCP segments (certificate chains usually do)
// can be parsed from the reassembled stream, or certificates parsed directly:
let tls = try TLSDecoder.parse(reassembledStreamBytes)
let cert = try X509Certificate(der: derBytes)
```

## ICMP error correlation

ICMP error messages expose the packet that triggered them:

```swift
if let icmp = packet.layer(ICMPv4.self), icmp.isError {
    icmp.quotedFlow      // 5-tuple of the original packet, even from truncated quotes
    icmp.quotedPacket(using: .standard)  // full decode of the quoted bytes
}
```

## Reading & writing capture files (no libpcap)

`CaptureFileReader` and `CaptureFileWriter` handle classic pcap **and** pcapng
in pure Swift, so file-only tools need no system library:

```swift
// Reads pcap or pcapng, autodetected; each packet carries its own link type.
let reader = try CaptureFileReader(contentsOf: url)
for try await captured in reader.packets() {
    print(captured.decoded(using: .standard).summary)
}

// Write pcapng (or .pcap) with microsecond or nanosecond timestamps.
let writer = try CaptureFileWriter(url: out, linkType: .ethernet, format: .pcapng)
for packet in packets { writer.write(packet) }
writer.close()
```

The libpcap-backed `PcapFileReader`/`PcapFileWriter` remain available.

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

### macOS

- macOS 13 or later
- Swift 6 toolchain (Xcode 16 or a matching open-source toolchain)
- libpcap (ships with macOS)

### Linux

- A Swift 6 toolchain ([swift.org](https://www.swift.org/install/) or the
  `swift:6` container images)
- libpcap development headers: `apt-get install libpcap-dev` (Debian/Ubuntu)
  or `yum install libpcap-devel` (RHEL/Fedora)
- Hashing in the TLS/X.509 path uses [swift-crypto](https://github.com/apple/swift-crypto)
  on Linux (CryptoKit on Apple platforms); SwiftPM handles this automatically.

## Build & test

```sh
swift build
swift test
```

CI builds and tests every push on both macOS and Linux
(`.github/workflows/ci.yml`).

Reading `.pcap` files needs no special permissions on either platform. Live
capture does:

- **macOS** — access to the BPF devices (`/dev/bpf*`): elevated privileges or
  a ChmodBPF-style permission grant, the same approach Wireshark uses.
- **Linux** — root, or grant the binary raw-socket capabilities:
  `sudo setcap cap_net_raw,cap_net_admin+eip <binary>`.

A design note for a native Linux `AF_PACKET` capture backend (kernel fanout,
TPACKET_V3 rings) lives in [Docs/AFPacket.md](Docs/AFPacket.md); today live
capture uses libpcap on both platforms.

## Roadmap

- [x] **Phase 0** — Project bootstrap: SwiftPM package, libpcap C bridge, CI, license, passing test.
- [x] **Phase 1** — Capture & file I/O foundation (`PacketSource`, libpcap backend, pcap read/write, async sequence).
- [x] **Phase 2** — Core decoding model (`Layer` protocol, `Packet`, bounds-checked reader, `LayerType` registry).
- [x] **Phase 3** — Protocol decoders (Ethernet, IPv4/IPv6, ARP, TCP/UDP/ICMP, DNS).
- [x] **Phase 4** — Serialization (`SerializeBuffer`, checksums, length fixup).
- [x] **Phase 5** — Filtering (BPF) & performance.
- [x] **Phase 6** — Hardening (fuzzing), DocC docs, examples, tagged release.
- [x] **Phase 7** — Monitor-grade decoding: uniform IP protocol access, ICMP quoted packets, structured DNS rdata (TXT/MX/SRV/SOA), TLS (SNI/ALPN/JA3) and X.509 certificate parsing.
- [x] **Phase 8** — GoPacket layer parity (practical set): 802.1Q/Q-in-Q, MPLS, LLC/SNAP, STP, LLDP, EAPOL, Linux SLL, pflog, GRE, VXLAN, EtherIP, ERSPAN II, PPPoE/PPP, IGMP, ESP/AH, SCTP, UDP-Lite, VRRP, DHCPv4/v6, NTP.
- [x] **Phase 9** — Monitor-critical capture plumbing: capture statistics, packet injection, `Flow`/`Endpoint`/`ConnectionKey`, `hexDump()`, RFMON & buffer-size tuning.
- [x] **Phase 10** — Reassembly: IPv4/IPv6 defragmentation (`IPDefragmenter`), TCP stream reassembly (`TCPReassembler`), and a `TLSStreamAssembler` that recovers certificates from handshakes spanning segments.
- [x] **Phase 11** — Pure-Swift capture-file I/O: `CaptureFileReader`/`CaptureFileWriter` read and write classic pcap (both byte orders, µs/ns) and pcapng, with no libpcap dependency.
- [x] **Phase 12** — Allocation-free `StackDecoder` fast path (~2× faster on the Ethernet/IPv4/TCP stack) + `packet-bench`.
- [x] **Phase 13** — Layer breadth: NDP/MLD (ICMPv6 accessors), CDP, EAP, OSPFv2, the Radiotap + 802.11 wireless stack, and serialization for VLAN/GRE/VXLAN/DHCP/NTP.
- [x] **Phase 14** — Native Linux AF_PACKET capture (`TPACKET_V3` ring + `PACKET_FANOUT`), OUI vendor lookup, `live-dump` example.

Full GoPacket parity is reached; remaining protocols (SIP, RADIUS, GTP, sFlow, BFD, …) are added on demand. Gap analysis: [Docs/GoPacketParity.md](Docs/GoPacketParity.md).

## Documentation

API docs are provided as a DocC catalog. Build them with the
[Swift-DocC plugin](https://github.com/swiftlang/swift-docc-plugin):

```sh
swift package generate-documentation --target SwiftPacket
```

or in Xcode via **Product → Build Documentation**.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
