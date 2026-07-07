# Changelog

All notable changes to SwiftPacket are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-07-03

The first tagged release: a complete capture → decode → serialize → filter
pipeline for macOS, written in Swift 6 with complete concurrency checking.

### Added

- **Capture & file I/O.** Live capture (`LiveCapture`) and `.pcap` reading
  (`PcapFileReader`) and writing (`PcapFileWriter`) over libpcap, delivered as a
  backpressured `AsyncSequence`. Interface enumeration via `Devices`.
- **Decoding model.** A bounds-checked, throwing `ByteReader`; a `Layer` /
  `LayerType` / `Packet` model; and a value-type `DecoderRegistry` that drives a
  decode chain. Decoding never traps — malformed input yields a `DecodeFailure`
  layer, unknown protocols an opaque `Payload`.
- **Protocol decoders.** Ethernet, BSD loopback, IPv4, IPv6, ARP, TCP, UDP,
  ICMPv4/v6, and DNS (including compressed-name resolution), wired together in
  `DecoderRegistry.standard`.
- **Serialization.** A prepend-model `SerializeBuffer` with `SerializableLayer`
  conformances, automatic length fix-up, and Internet-checksum computation for
  the IPv4 header and the TCP/UDP pseudo-header.
- **Filtering.** BPF filters compiled and applied in-kernel via
  `LiveCapture.setFilter(_:)` / `PcapFileReader.setFilter(_:)`, or evaluated in
  userspace via `BPFProgram` (no privileges required).
- **Lazy decoding.** `CapturedPacket.lazyLayers(using:)` and
  `firstLayer(_:using:)` decode only as far as needed.
- **Tooling.** `list-interfaces` and `dump-pcap` example executables, a DocC
  catalog, and a fuzz/hardening test suite.

[0.1.0]: https://github.com/yourname/SwiftPacket/releases/tag/0.1.0
