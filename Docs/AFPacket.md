# Native `AF_PACKET` capture on Linux

Status: **implemented** (`AFPacketCapture`, Linux only). Packets arrive through
a memory-mapped `TPACKET_V3` RX ring (kernel writes frames into shared memory,
no syscall per packet), with promiscuous mode, nanosecond timestamps,
`PACKET_FANOUT`, packet injection, `PACKET_STATISTICS`, and tcpdump-syntax
filters via `SO_ATTACH_FILTER`. If the ring can't be set up the engine falls
back to a plain `recvmsg` socket (`AFPacketCapture.usesRing` reports which is
active). libpcap remains the cross-platform default and the only backend
`LiveCapture` uses; `AFPacketCapture` is opt-in for callers who need fanout or
the ring's throughput.

> **Verification caveat:** the Linux capture path is compiled by CI and its
> Swift half is cross-parsed against a Linux target triple, but it has not been
> *run* on Linux hardware from this workspace. The kernel-facing struct
> handling — including the TPACKET_V3 block/frame walk with acquire/release
> barriers — lives in the `CLinuxPacket` C shim precisely so the system
> compiler checks it against real headers. Exercise it on a real interface (or
> a veth pair) before relying on it.

## Why (and why not yet)

libpcap on Linux already uses a memory-mapped `TPACKET_V3` ring internally, so
raw single-socket throughput would not meaningfully improve. A native backend
earns its keep only for the things libpcap's portable API cannot express:

| Capability | libpcap | native AF_PACKET |
|---|---|---|
| `PACKET_FANOUT` — kernel load-balancing one interface's traffic across N sockets/cores | ✗ | ✓ |
| Ring tuning (block size/count/timeout) per workload | limited | full |
| `PACKET_AUXDATA` / `tp_vlan_tci` — VLAN tag recovery when the NIC strips it | partial | ✓ |
| eBPF socket filters (`SO_ATTACH_BPF`), not just classic BPF | ✗ | ✓ |
| Runtime dependency on libpcap | required | none (for live capture) |

**Recommendation:** implement when a consumer (SwiftBeat) needs multi-core
fanout or NIC-stripped VLAN visibility. Until then the libpcap path is
performance-equivalent for a single capture thread.

## Architecture

### 1. Generalize the engine seam (the only shared-code change)

`PacketSequence` is currently hard-wired to `PcapEngine`
(`Sources/SwiftPacket/Capture/PacketSource.swift`). Introduce an internal
protocol both engines implement:

```swift
protocol CaptureEngine: Sendable {
    var linkType: LinkType { get }
    func next() async throws -> CapturedPacket?
    func setFilter(_ expression: String, optimize: Bool) throws
}
```

`PacketSequence` holds `any CaptureEngine` instead of `PcapEngine`. Source
compatible; no public API changes. This can land ahead of any Linux work.

### 2. `CLinuxPacket` shim target

A tiny system-library/header target compiled only into Linux builds, exposing
what Glibc's Swift overlay doesn't surface cleanly:

- `<linux/if_packet.h>`: `sockaddr_ll`, `tpacket_req3`, `tpacket_block_desc`,
  `tpacket3_hdr`, `PACKET_RX_RING`, `PACKET_FANOUT`, `PACKET_ADD_MEMBERSHIP`,
  `PACKET_MR_PROMISC`, `TP_STATUS_*`
- `<linux/filter.h>`: `sock_fprog` / `sock_filter` for `SO_ATTACH_FILTER`
- `<net/if.h>`: `if_nametoindex`
- Small static-inline helpers for the byte-order and pointer arithmetic the
  ring walk needs (Swift is clumsy at `#define`-based offsets).

Package.swift: add the target unconditionally, but guard every Swift use with
`#if os(Linux)` (SwiftPM cannot conditionally *declare* targets; empty modules
cost nothing on Darwin).

All of items 1–5 and both phases are **done**. What actually shipped, versus
this original design:

- The shim is a C target with `include/` headers (not `static-inline`);
  the block/frame walk and cmsg handling live in `clinuxpacket.c` so the
  system compiler type-checks them. Item 3's `SO_TIMESTAMPNS` fallback to the
  wall clock is implemented; `PACKET_AUXDATA` VLAN reinsertion is **not** (a
  reasonable future addition).
- Cancellation is a stop flag checked between poll timeouts, not
  `shutdown(2)` — AF_PACKET sockets don't support `shutdown`, so the poll
  interval (`CaptureConfig.timeoutMilliseconds`) bounds cancellation latency.
- The ring is the **default**; the plain socket is the fallback.

### 3. `AFPacketCapture: PacketSource` — two phases

**Phase 1 — plain socket (fallback). ✅ implemented.**

```
socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
bind(sockaddr_ll{ sll_ifindex: if_nametoindex(name) })
setsockopt(PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC)   // if promiscuous
setsockopt(SOL_SOCKET, SO_TIMESTAMPNS, 1)
recvmsg(...)  // cmsg: SCM_TIMESTAMPNS → CaptureInfo.timestamp
              // cmsg: PACKET_AUXDATA → tp_vlan_tci for stripped VLANs
```

Concurrency mirrors `PcapEngine` exactly: the socket is read on one private
serial `DispatchQueue`, one `recvmsg` per `next()`, cancellation via
`shutdown(fd, SHUT_RD)` (the AF_PACKET analogue of `pcap_breakloop`). The
`CapturedPacket.linkType` is `.ethernet` for ordinary NICs (`sll_hatype`
maps ARPHRD → LinkType, same table `LinuxSLL` uses).

**Phase 2 — `TPACKET_V3` ring + fanout (performance). ✅ implemented.**

- `setsockopt(PACKET_VERSION, TPACKET_V3)` then `PACKET_RX_RING` with a
  `tpacket_req3` (defaults: `block_size` = `CaptureConfig.ringBlockSize`
  = 1 MB, `block_nr` = `ringBlockCount` = 32, retire timeout =
  `timeoutMilliseconds`), `mmap` the ring, walk blocks: `poll(2)` → iterate
  `tpacket3_hdr` frames → hand the block back (`TP_STATUS_KERNEL`).
- Block status is read/written with acquire/release atomics
  (`__atomic_load_n`/`__atomic_store_n`), per the kernel's ring contract.
- Frames are *copied* into `CapturedPacket.data` before the block is released.
  The subtlety: a block is handed back to the kernel **lazily on the following
  `ring_next` call**, not the moment its last frame is returned, so the
  pointer handed to Swift stays valid across exactly one consumer step (Swift
  copies it before the next call). This avoids a use-after-free the naive
  "release when the block empties" approach would introduce.
- `PACKET_FANOUT` (`PACKET_FANOUT_HASH`) lets N `AFPacketCapture` instances
  share one interface with kernel flow-affinity; exposed as the
  `fanoutGroup:` initializer parameter.

### 4. Filtering without giving up tcpdump syntax

Compile the expression with the already-linked libpcap on a dead handle, then
attach the resulting classic-BPF program natively:

```swift
pcap_open_dead(DLT_EN10MB, snaplen) → pcap_compile(expression)
bpf_program.bf_insns  ≅  sock_filter[]        // identical layout
setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, sock_fprog{...})
```

Filter semantics stay byte-identical with the libpcap backend, and
`BPFProgram` (userspace matching) keeps working unchanged. `SO_ATTACH_BPF`
(eBPF) can come later behind the same `setFilter` API.

### 5. Selection API

```swift
// Explicit:
let capture = try AFPacketCapture(interface: "eth0", config: config)  // Linux-only symbol
// Or transparent: LiveCapture gains a backend option.
public struct CaptureConfig { …; public var backend: Backend = .automatic }
```

`.automatic` = libpcap everywhere today; flips to native when phase 2 is
proven. Keeping `LiveCapture` as the single entry point is the least
surprising for consumers.

## Privileges

Same as libpcap on Linux: root, or grant the binary
`sudo setcap cap_net_raw,cap_net_admin+eip <binary>`. No ChmodBPF equivalent
needed (there are no `/dev/bpf*` devices on Linux).

## Testing reality

- Unit-testable without privileges: sockaddr/ARPHRD mapping, BPF struct
  bridging, ring-header walking against canned memory.
- Functional tests need `CAP_NET_RAW` and an interface: a `veth` pair with
  scripted traffic is the standard fixture (`ip link add veth0 type veth peer
  name veth1`). GitHub Actions containers *can* do this with
  `--privileged`/`NET_ADMIN`; wire it as a separate optional CI job.
- CI on every push should at minimum compile the Linux-only sources
  (the existing `swift:6` container job does, once the target exists).

## Effort estimate

| Piece | Size |
|---|---|
| `CaptureEngine` seam | small, zero-risk, can land now |
| `CLinuxPacket` shim | small |
| Phase 1 socket backend | medium (the concurrency pattern already exists to copy) |
| Filter bridging | small |
| Phase 2 ring + fanout | large — the bulk of the work and the only part that pays |
| veth CI fixture | medium |
