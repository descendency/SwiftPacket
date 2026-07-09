import Foundation

/// Counters describing a live capture's throughput and loss.
///
/// The exact semantics of `dropped` vs `interfaceDropped` follow the capture
/// backend (libpcap's `pcap_stats`, or the kernel's `PACKET_STATISTICS`), but
/// the intent is uniform: `received` is how many packets the capture saw, and
/// the drop counts are packets lost because the consumer or the interface
/// could not keep up. A monitor should surface these — silent loss is the
/// thing you most need to know about.
public struct CaptureStatistics: Sendable, Hashable {
    /// Packets received by the capture (libpcap: `ps_recv`).
    public let received: UInt64

    /// Packets dropped because the capture buffer was full (libpcap: `ps_drop`;
    /// AF_PACKET: `tp_drops`).
    public let dropped: UInt64

    /// Packets dropped by the network interface before capture (libpcap:
    /// `ps_ifdrop`). Not reported by every backend; zero when unavailable.
    public let interfaceDropped: UInt64

    public init(received: UInt64, dropped: UInt64, interfaceDropped: UInt64) {
        self.received = received
        self.dropped = dropped
        self.interfaceDropped = interfaceDropped
    }

    /// The fraction of packets lost to buffer drops, in `0...1`; `0` when no
    /// packets have been received.
    public var dropRate: Double {
        let total = received + dropped
        return total == 0 ? 0 : Double(dropped) / Double(total)
    }
}
