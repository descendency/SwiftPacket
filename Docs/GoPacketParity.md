# GoPacket feature parity: gap analysis & plan of action

Audited against [google/gopacket](https://github.com/google/gopacket) (July
2026). GoPacket is the core package plus fifteen sub-packages; this compares
each against SwiftPacket 0.2.0-unreleased and lays out a phased plan.
Priorities are chosen for SwiftPacket's driving consumer — a Zeek-style
network monitor — where that differs from generic parity.

## Where SwiftPacket already leads

Worth stating first, because parity is not the ceiling:

- **TLS + X.509**: ClientHello/ServerHello field extraction, SNI/ALPN,
  JA3/JA3S, certificate-chain parsing to structured `X509Certificate`.
  GoPacket's `layers.TLS` stops at record/handshake framing.
- **Memory safety as a tested invariant**: bounds-checked reads that throw,
  never trap, with fuzz suites. GoPacket recovers from panics instead.
- **Structured concurrency**: backpressured `AsyncSequence` capture with
  cancellation; GoPacket predates Go generics *and* channels-as-API polish here.
- **DNS rdata & ICMP ergonomics**: decoded TXT/MX/SRV/SOA, quoted-flow
  recovery from truncated ICMP errors.

## Feature matrix

| GoPacket component | What it is | SwiftPacket status |
|---|---|---|
| core: Packet/Layer/lazy decode | decode model | ✅ have (`Packet`, `LayerIterator`) |
| core: `DecodeFailure`-style recovery | partial packets survive | ✅ have |
| core: `flows.go` — `Endpoint`/`Flow` | hashable 5-tuple keys | ✅ have (`Endpoint`/`Flow`/`ConnectionKey`) |
| core: `parser.go` — `DecodingLayerParser` | allocation-free repeated decode | ✅ have (`StackDecoder`) |
| core: `Packet.Dump()` | hex + per-layer dump | ✅ have (`Packet.hexDump()`) |
| core: `writer.go` — serialization | build packets | 🟡 partial: 10 layers vs ~40 |
| `layers/` (~68 files) | protocol decoders | 🟡 ~45 layers + NDP/MLD accessors; only Group B remains (SIP/RADIUS/GTP/sFlow/BFD/Modbus) |
| `pcap/`: live capture, offline, BPF | libpcap binding | ✅ have |
| `pcap/`: **capture statistics** (`pcap_stats`) | received/dropped counts | ✅ have (`LiveCapture.statistics()`) |
| `pcap/`: **packet injection** (`pcap_inject`) | send raw frames | ✅ have (`LiveCapture.send(_:)`) |
| `pcap/`: monitor mode, timestamp sources, buffer size | capture tuning | 🟡 rfmon + buffer size (`CaptureConfig`); ts-source deferred |
| `pcapgo/`: pure-Go classic pcap I/O | file I/O without libpcap | ✅ have (`CaptureFileReader`/`Writer`) |
| `pcapgo/`: **pcapng read/write** | the modern capture format | ✅ have (`CaptureFileReader`/`Writer`) |
| `tcpassembly/` + `reassembly/` | **TCP stream reassembly** | ✅ have (`TCPReassembler`) |
| `ip4defrag/` | IPv4 defragmentation | ✅ have (`IPDefragmenter`, + IPv6) |
| `afpacket/` | native Linux AF_PACKET + fanout | ✅ have (`AFPacketCapture`, TPACKET_V3 + fanout) |
| `bsdbpf/` | direct `/dev/bpf` on BSD/macOS | ❌ missing — **non-goal** (libpcap suffices) |
| `pfring/` | PF_RING binding | ❌ missing — **non-goal** (commercial niche) |
| `routing/` | Linux route-table lookup | ❌ missing — defer until a consumer needs it |
| `macs/` | MAC OUI → vendor database | ❌ missing |
| `bytediff/`, `dumpcommand/`, `examples/` | tooling | 🟡 two example tools |

## Plan of action

Phases continue the README roadmap numbering. Ordered by value-to-effort for
a network monitor; each phase is independently shippable.

### Phase 9 — Monitor-critical capture plumbing ✅ done

1. **Capture statistics** — ✅ `LiveCapture.statistics() -> CaptureStatistics`
   (`pcap_stats`), and `AFPacketCapture.statistics()` (`PACKET_STATISTICS`),
   with a `dropRate` convenience.
2. **Packet injection** — ✅ `LiveCapture.send(_:)` (`pcap_inject`) and
   `AFPacketCapture.send(_:)`. Pair with `Packet.serializedData(_:)` to craft
   and emit frames.
3. **Flow/Endpoint model** — ✅ `Endpoint` (mac/ipv4/ipv6/port), `Flow`
   (directional, with `reversed`/`canonical`), `Packet.linkFlow` /
   `networkFlow` / `transportFlow`, and `ConnectionKey` — a canonical 5-tuple
   that folds both directions of a conversation to one bucket.
4. **`Packet.hexDump()`** — ✅ per-layer legend + classic hex/ASCII dump;
   `Data.hexDump()`; `dump-pcap -x`.
5. **Capture tuning** — ✅ `CaptureConfig.monitorMode` (`pcap_set_rfmon`) and
   `bufferSize` (`pcap_set_buffer_size`), plus AF_PACKET ring sizing. The
   timestamp-source selector (`pcap_set_tstamp_type`) is deferred.

### Phase 10 — Reassembly & defragmentation ✅ done

1. **IP defragmentation** — ✅ `IPDefragmenter` (actor), keyed by
   (src, dst, id, proto), overlap first-fragment-wins, per-datagram byte/
   fragment caps, time + count eviction. Returns `passThrough` / `incomplete`
   / `reassembled(Packet)` (reassembled datagrams are re-decoded).
2. **IPv6 fragment support** — ✅ `IPv6Fragment` layer + decoder (next-header
   44), reassembled by the same engine.
3. **TCP stream reassembly** — ✅ `TCPReassembler` (actor): per-direction
   (`TCPStreamKey`) sequence tracking, out-of-order buffering,
   overlap/retransmit trimming, 32-bit wraparound, gap ("skip") reporting on
   `flush(force:)`, SYN adoption / mid-stream start, FIN/RST teardown, idle
   eviction. Returns `[TCPSegmentDelivery]` (a pull model rather than a
   delegate, keeping ordering explicit under Swift concurrency).
4. **TLS session helper** — ✅ `TLSStreamAssembler`: drives a `TCPReassembler`
   and re-parses each direction's stream, emitting `TLSHandshakeEvent`s for
   ClientHello / ServerHello / certificate chains — so a handshake spanning
   segments yields certificates with no consumer plumbing. Completes the
   ssl.log story end-to-end.

### Phase 11 — File formats without libpcap ✅ done

1. **Pure-Swift classic pcap reader/writer** — ✅ `CaptureFileReader` /
   `CaptureFileWriter` handle both byte orders and both magic numbers (µs and
   ns precision) and tolerate a truncated tail. libpcap-free, so file-only
   consumers need no system library; the libpcap-backed `PcapFileReader` /
   `PcapFileWriter` remain for those who want them. Cross-checked both ways
   against libpcap in the test suite, and the output is read by `tcpdump`.
2. **pcapng reader/writer** — ✅ SHB / IDB / EPB / SPB blocks, per-interface
   link types and `if_tsresol` timestamp resolutions, both byte orders. The
   writer emits one interface + Enhanced Packet Blocks; `tcpdump -r` reads the
   result. (Multi-interface *writing* and ISB stats are a future nicety.)

### Phase 12 — Decode performance parity ✅ done

1. **`StackDecoder`** — ✅ the `DecodingLayerParser` analogue. Decodes the hot
   layers (Ethernet, loopback, IPv4/IPv6, ARP, TCP, UDP, ICMPv4/v6) into
   concrete value slots on a reusable `DecodedStack` — no `any Layer` boxing,
   no per-packet array allocation. Layers outside that set fall back to the
   registry and collect (boxed) in `DecodedStack.overflow`, so correctness
   never depends on a layer being "fast". The hot decoders each expose a
   `decodeValue` returning `(Self, NextDecode)`; their `LayerDecoder.decode`
   wraps it, so the boxed and unboxed paths share one implementation.
2. **Benchmark** — ✅ a dependency-free `packet-bench` executable (`swift run
   -c release packet-bench`). On an Apple Silicon laptop it decodes an
   Ethernet/IPv4/TCP frame at **~2.2M packets/sec** via `StackDecoder` vs
   ~1.1M/sec via `Packet.decode` — a **~1.97×** speedup, both above the 1M/sec
   goal. (A `swift-benchmark` dependency was avoided in favor of a
   zero-dependency harness with warmup and an anti-elision sink.)

### Phase 13 — Layer breadth ✅ Groups A & C done; B/D deferred

- **Group A (LAN/enterprise)** — ✅ done. Structured **NDP** (Router/Neighbor
  Solicitation & Advertisement, Redirect, with options: link-layer addresses,
  prefix information, MTU) and **MLDv1/v2** (queries and multicast-address
  records) as `ICMPv6` accessors; **CDP** (TLVs, auto-routed from LLC/SNAP with
  the Cisco OUI); **EAP** (message bodies, auto-routed from EAPOL EAP-Packet);
  **OSPFv2** (common header + Hello body). IGMPv3 query/record fields already
  landed in Phase 8's `IGMP`. (OSPFv3 is left for later — different header.)
- **Group C (wireless)** — ✅ done. **Radiotap** (presence bitmap, channel
  frequency, antenna signal) chaining to **802.11 / `Dot11`** (frame
  control/type/subtype, addresses, DS flags; data frames route to LLC). Wired
  to `DLT_IEEE802_11` and `DLT_IEEE802_11_RADIO`. Full management-frame body
  parsing and Prism headers are out of scope for now.
- **Serialization breadth** — ✅ `SerializableLayer` for `Dot1Q` (VLAN), GRE,
  VXLAN, DHCPv4/v6, NTP (ICMPv4/v6 already conformed); round-trip tested.
- **Group B (on demand)** — ⬜ deferred: SIP, RADIUS, GTPv1-U, sFlow, BFD,
  Modbus/TCP, RUDP, ERSPAN Type I/III. Each is a self-contained decoder to add
  when a consumer needs it.
- **Group D (explicit non-goals unless requested)** — FDDI, CTP, ASF/RMCP
  (IPMI), USB, LCM.

### Phase 14 — Capture backends & ecosystem ✅ done (Phase 2 ring deferred)

1. **AF_PACKET native backend** — ✅ `AFPacketCapture` (Linux): raw socket,
   promiscuous mode, ns timestamps, `PACKET_FANOUT`, packet injection,
   `PACKET_STATISTICS`, and tcpdump filters via `SO_ATTACH_FILTER`, delivered
   through a `TPACKET_V3` mmap ring (with a plain-socket fallback). Kernel
   structs isolated in the `CLinuxPacket` C shim. See [AFPacket.md](AFPacket.md).
2. **OUI vendor lookup** — ✅ `SwiftPacketOUI` (opt-in library):
   `MACAddress.vendor` / `OUIDatabase`, backed by a generated ~2 MB binary
   table from the IEEE registry (via Wireshark's `manuf`), memory-mapped and
   binary-searched with IEEE longest-prefix semantics (MA-S/MA-M/MA-L).
   Regenerate with `Sources/SwiftPacketOUI/Resources/generate-oui.py`.
3. **Examples** — ✅ `live-dump` (live capture with per-MAC vendor
   annotation).

### Status

Phases 8–14 are **done**. Every capability, performance, and format gap versus
GoPacket is closed — cross-segment TLS (10), pcapng/libpcap-free files (11),
an allocation-free fast path (12), the LAN/enterprise and wireless layers (13),
and native AF_PACKET (14).

What remains is optional and demand-driven: Phase 13 **Group B** decoders
(SIP, RADIUS, GTP, sFlow, BFD, Modbus, RUDP), OSPFv3, and the deliberate
non-goals (`pfring`, `bsdbpf`, `routing`, FDDI/CTP/IPMI/USB). None blocks a
network monitor; each is a self-contained addition when a consumer needs it.
