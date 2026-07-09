# Changelog

All notable changes to SwiftPacket are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] — Unreleased

Deepens the decode pipeline for network-monitoring consumers: uniform L4
protocol identity, ICMP error correlation, structured DNS answers, and a
TLS/X.509 path. Now builds and tests on Linux as well as macOS.

### Added

- **Layer breadth (Phase 13).** Structured **Neighbor Discovery** (Router/
  Neighbor Solicitation & Advertisement, Redirect, with link-layer-address,
  prefix-information, and MTU options) and **MLDv1/v2** (queries and
  multicast-address records) as `ICMPv6` accessors; **CDP** (Cisco Discovery
  Protocol TLVs, auto-routed from LLC/SNAP with the Cisco OUI); **EAP**
  (message bodies, auto-routed from EAPOL); **OSPFv2** (common header + Hello).
  A wireless stack — **Radiotap** (channel frequency, antenna signal) chaining
  to **802.11** (`Dot11`: frame control, type/subtype, addresses, DS flags;
  data frames route to LLC) — wired to `DLT_IEEE802_11` and
  `DLT_IEEE802_11_RADIO`. `SerializableLayer` conformances added for VLAN
  (`Dot1Q`), GRE, VXLAN, DHCPv4/v6, and NTP, so more of the decoded protocols
  round-trip. (SIP/RADIUS/GTP/sFlow/BFD and OSPFv3 remain on-demand additions.)
- **Allocation-free fast path (Phase 12).** `StackDecoder` decodes the common
  stack (Ethernet, loopback, IPv4/IPv6, ARP, TCP, UDP, ICMPv4/v6) into concrete
  value slots on a reusable `DecodedStack`, with no `any Layer` boxing and no
  per-packet array allocation — about **2× faster** than `Packet.decode` on
  Ethernet/IPv4/TCP (~2.2M vs ~1.1M packets/sec on Apple Silicon). Layers
  outside the fast set fall back to the registry and collect in
  `DecodedStack.overflow`, so results always match `Packet.decode` (verified by
  a fuzz-parity test). The hot decoders now share one implementation between
  the boxed and unboxed paths via a `decodeValue` returning `(Self, NextDecode)`.
  A dependency-free `packet-bench` executable reports the numbers.
- **Pure-Swift capture files (Phase 11).** `CaptureFileReader` and
  `CaptureFileWriter` read and write both classic pcap (either byte order,
  microsecond or nanosecond timestamps) and pcapng (SHB/IDB/EPB/SPB blocks,
  per-interface link types and `if_tsresol` resolutions) with no libpcap
  dependency — the reader conforms to `PacketSource` like the rest of the
  library and tolerates a truncated tail. `CaptureFile.read(_:)` /
  `detectFormat(_:)` are lower-level entry points. The libpcap-backed
  `PcapFileReader`/`PcapFileWriter` remain. Verified round-trip against
  libpcap both ways, and the output is read by `tcpdump`.
- **Reassembly (Phase 10).** `IPDefragmenter` reassembles fragmented IPv4 and
  IPv6 datagrams (keyed by src/dst/id/proto, overlap first-fragment-wins, with
  byte/fragment/time caps) and re-decodes the result; IPv6 fragment extension
  headers now decode as an `IPv6Fragment` layer. `TCPReassembler` turns TCP
  segments into ordered, per-direction (`TCPStreamKey`) byte streams —
  handling out-of-order delivery, retransmits and overlaps, 32-bit sequence
  wraparound, mid-stream capture, gap reporting, and FIN/RST teardown — and
  returns `[TCPSegmentDelivery]`. `TLSStreamAssembler` layers TLS parsing on
  top, emitting `TLSHandshakeEvent`s so a ClientHello/ServerHello/certificate
  chain is recovered even when it spans many segments. All three are actors.
- **Linux support.** The package builds and passes its full test suite on
  Linux (Swift 6 + `libpcap-dev`) with no API changes: CryptoKit is replaced
  by swift-crypto via conditional import (Linux only — macOS binaries still
  link the system CryptoKit), Dispatch is imported explicitly, and pcap
  `timeval` fields use the portable `time_t`/`suseconds_t` typedefs. The
  `Cpcap` system library now carries apt/yum/brew provider hints, and CI
  exercises macOS and `swift:6.0`/`6.1` Linux containers.
- **Capture plumbing (Phase 9).** `LiveCapture.statistics()` (received/dropped
  counters via `pcap_stats`) and `send(_:)` (frame injection via
  `pcap_inject`); `CaptureConfig` gains `monitorMode` (RFMON) and `bufferSize`.
  A `Flow`/`Endpoint` model with `Packet.linkFlow` / `networkFlow` /
  `transportFlow` and a canonical `ConnectionKey` that folds both directions
  of a conversation into one key. `Packet.hexDump()` / `Data.hexDump()` with a
  per-layer legend, surfaced as `dump-pcap -x`.
- **Native AF_PACKET capture (Linux).** `AFPacketCapture` reads from a
  memory-mapped `TPACKET_V3` RX ring (with a plain-socket fallback), with
  promiscuous mode, nanosecond timestamps, injection, `PACKET_STATISTICS`,
  and — the reason to use it over libpcap — kernel `PACKET_FANOUT` so several
  captures on one interface share its traffic across cores. Filters keep
  tcpdump syntax (compiled by libpcap, attached via `SO_ATTACH_FILTER`). The
  kernel struct handling, including the ring's block/frame walk, lives in a
  new `CLinuxPacket` C shim; the internal `CaptureEngine` seam lets
  `PacketSequence` drive either backend.
- **OUI vendor lookup.** A separate opt-in `SwiftPacketOUI` library adds
  `MACAddress.vendor` and `OUIDatabase`, resolving MAC prefixes to registered
  vendors from the IEEE registry with correct longest-prefix (MA-L/MA-M/MA-S)
  semantics. The table is a generated, memory-mapped binary resource.
- **`live-dump` example** — live capture printing per-packet summaries with
  OUI-annotated MAC addresses.
- A full GoPacket parity gap analysis and roadmap (Phases 9–14) lives in
  `Docs/GoPacketParity.md`; this release completes Phase 14.

- **Uniform IP protocol access.** `Packet.ipProtocol` reads the L4 protocol
  number from either IP version; `IPv6.proto` aliases `nextHeader` to match
  IPv4's field name. `IPProtocol` gains the common IANA constants
  (IGMP/GRE/ESP/AH/OSPF/SCTP/…) and renders names via
  `CustomStringConvertible` — unknown numbers keep their raw identity instead
  of collapsing into "other".
- **ICMP enrichment.** Echo `identifier`/`sequenceNumber` on both families,
  `typeName`, `isError`, `nextHopMTU` (v4 frag-needed) and `mtu` (v6
  packet-too-big). Error messages expose the embedded quoted packet:
  `quotedData`, `quotedPacket(using:)` for a full decode, and `quotedFlow` —
  a lenient 5-tuple parse that recovers addresses, protocol, and ports even
  from RFC-minimum truncated quotes (where a full TCP decode cannot).
- **Structured DNS answers.** `DNSResourceRecord` decodes TXT strings, MX,
  SRV, and SOA rdata (`DNSMXRecord`/`DNSSRVRecord`/`DNSSOARecord`), is now
  `Hashable`, and offers `typeName` ("A", "AAAA", RFC 3597 `TYPEn` fallback)
  plus `rdataDescription`. `DNS.responseCodeName` names rcodes ("NOERROR",
  "NXDOMAIN", …).
- **TLS decoding.** A `TLS` layer parsing records and plaintext handshake
  content: `TLSClientHello` (SNI, ALPN, cipher suites, groups, point formats,
  supported versions, signature algorithms, and JA3 with GREASE handling),
  `TLSServerHello` (cipher, ALPN, negotiated version, JA3S), and TLS ≤ 1.2
  `Certificate` chains. TCP payloads that begin with a well-formed record
  header route to TLS automatically; `TLSDecoder.parse(_:)` works standalone
  on reassembled streams and reports truncation via `TLS.isTruncated`.
- **X.509 certificate parsing.** `X509Certificate(der:)` over a new internal
  DER reader: version, serial, subject/issuer distinguished names, validity,
  signature/public-key algorithms, key size, subject alternative names,
  basic constraints, and SHA-256/SHA-1 fingerprints.
- **GoPacket layer parity (the practical set).** Twenty-three new decoders,
  all wired into `DecoderRegistry.standard`:
  - *Link:* 802.1Q VLAN (`Dot1Q`, including Q-in-Q), MPLS label stacks,
    802.2 LLC with SNAP, STP BPDUs, LLDP TLVs, EAPOL. Ethernet now chains
    802.3 length-framed payloads to LLC instead of stopping.
  - *Capture link types:* Linux SLL (`tcpdump -i any` files) and BSD/macOS
    `pflog`, with `LinkType.linuxSLL`/`.pflog` mappings.
  - *Tunnels:* GRE (checksum/key/sequence flags), VXLAN, EtherIP, ERSPAN
    Type II, PPPoE and PPP — each chains to its inner Ethernet/IP layers, so
    e.g. `IPv4 | GRE | ERSPAN | Ethernet | IPv4 | UDP | DNS` decodes fully.
  - *IP transports:* IGMP (v1–v3 with group records), IPsec ESP and AH (AH
    chains through to the protected payload), SCTP (common header + chunks),
    UDP-Lite, VRRP v2/v3.
  - *UDP applications:* DHCPv4 (options, message type, requested address,
    lease), DHCPv6 (options), NTP (stratum, mode, timestamps as `Date`).
    UDP now routes ports 67/68, 546/547, 123, and 4789 (VXLAN) in addition
    to 53.

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
