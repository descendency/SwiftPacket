# ``SwiftPacket``

Capture, decode, build, and filter network packets on macOS — a Swift 6 library
modeled on Google's gopacket, built over the system libpcap.

## Overview

SwiftPacket turns raw bytes on the wire into typed, inspectable layers and back
again. It is built around a few small ideas:

- **Capture** live from an interface or from a `.pcap` file, delivered as a
  backpressured `AsyncSequence` — nothing is read until you ask for it.
- **Decode** bytes into a chain of protocol layers (Ethernet → IPv4 → TCP → …)
  through a bounds-checked reader that *throws* on malformed input rather than
  trapping. A hostile packet yields a partial ``Packet`` with a
  ``DecodeFailure`` layer, never a crash.
- **Serialize** typed layers back to bytes, with automatic length fix-up and
  checksum computation.
- **Filter** with BPF expressions, either in the kernel (``LiveCapture/setFilter(_:)``)
  or in userspace (``BPFProgram``).

```swift
let reader = try PcapFileReader(path: "capture.pcap")
try reader.setFilter("udp port 53")

for try await captured in reader.packets() {
    let packet = captured.decoded(using: .standard)
    if let dns = packet.layer(DNS.self), let question = dns.questions.first {
        print(packet.summary, "—", question.name)
    }
}
```

## Topics

### Essentials

- <doc:GettingStarted>
- ``SwiftPacket/SwiftPacket``

### Capturing packets

- ``LiveCapture``
- ``PcapFileReader``
- ``PcapFileWriter``
- ``CaptureConfig``
- ``Devices``
- ``Interface``
- ``CapturedPacket``
- ``CaptureInfo``
- ``LinkType``
- ``PcapError``

### Decoding

- ``Packet``
- ``Layer``
- ``LayerType``
- ``LayerCategory``
- ``DecoderRegistry``
- ``LayerDecoder``
- ``ByteReader``
- ``DecodingError``
- ``Payload``
- ``DecodeFailure``

### Protocol layers

- ``Ethernet``
- ``Loopback``
- ``IPv4``
- ``IPv6``
- ``ARP``
- ``TCP``
- ``UDP``
- ``ICMPv4``
- ``ICMPv6``
- ``DNS``
- ``MACAddress``
- ``IPv4Address``
- ``IPv6Address``

### Serializing

- ``SerializableLayer``
- ``SerializeBuffer``
- ``SerializeOptions``
- ``ByteWriter``
- ``internetChecksum(_:)``

### Filtering

- ``BPFProgram``
