import Foundation

/// Options controlling a live capture session, applied between `pcap_create`
/// and `pcap_activate`.
public struct CaptureConfig: Sendable {
    /// Maximum number of bytes to capture per packet (snapshot length).
    /// The default captures whole packets on typical links.
    public var snapshotLength: Int32

    /// Whether to place the interface into promiscuous mode.
    public var promiscuous: Bool

    /// Deliver packets as soon as they arrive instead of waiting for the
    /// kernel buffer to fill. Recommended on macOS/BSD, where the default
    /// buffering can otherwise delay delivery noticeably.
    public var immediate: Bool

    /// Packet-buffer timeout in milliseconds. Bounds how long a read waits
    /// before returning empty-handed, keeping cancellation responsive.
    public var timeoutMilliseconds: Int32

    /// Kernel capture-buffer size in bytes, or `nil` for libpcap's default.
    /// A larger buffer tolerates longer consumer stalls before dropping
    /// (`pcap_set_buffer_size`).
    public var bufferSize: Int32?

    /// Whether to place the interface into 802.11 monitor (RFMON) mode, which
    /// captures raw radio frames rather than Ethernet-framed traffic
    /// (`pcap_set_rfmon`). Only meaningful on Wi-Fi interfaces that support it.
    public var monitorMode: Bool

    /// The per-block memory of the Linux `AF_PACKET` `TPACKET_V3` ring, in
    /// bytes (page-aligned). Ignored by the libpcap backend.
    public var ringBlockSize: Int32

    /// The number of blocks in the `TPACKET_V3` ring. Total ring memory is
    /// ``ringBlockSize`` × this. Ignored by the libpcap backend.
    public var ringBlockCount: Int32

    public init(
        snapshotLength: Int32 = 262_144,
        promiscuous: Bool = true,
        immediate: Bool = true,
        timeoutMilliseconds: Int32 = 1000,
        bufferSize: Int32? = nil,
        monitorMode: Bool = false,
        ringBlockSize: Int32 = 1 << 20,
        ringBlockCount: Int32 = 32
    ) {
        self.snapshotLength = snapshotLength
        self.promiscuous = promiscuous
        self.immediate = immediate
        self.timeoutMilliseconds = timeoutMilliseconds
        self.bufferSize = bufferSize
        self.monitorMode = monitorMode
        self.ringBlockSize = ringBlockSize
        self.ringBlockCount = ringBlockCount
    }

    /// A sensible default: full-packet snapshot, promiscuous, immediate mode.
    public static let `default` = CaptureConfig()
}
