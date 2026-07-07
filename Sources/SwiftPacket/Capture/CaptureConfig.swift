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

    public init(
        snapshotLength: Int32 = 262_144,
        promiscuous: Bool = true,
        immediate: Bool = true,
        timeoutMilliseconds: Int32 = 1000
    ) {
        self.snapshotLength = snapshotLength
        self.promiscuous = promiscuous
        self.immediate = immediate
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    /// A sensible default: full-packet snapshot, promiscuous, immediate mode.
    public static let `default` = CaptureConfig()
}
