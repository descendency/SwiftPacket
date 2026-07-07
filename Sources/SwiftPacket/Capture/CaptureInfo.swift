import Cpcap
import Foundation

/// Metadata describing a single captured packet, mirroring libpcap's
/// `struct pcap_pkthdr`.
public struct CaptureInfo: Hashable, Sendable {
    /// The time the packet was captured.
    public let timestamp: Date

    /// The number of bytes actually captured and present in the packet data.
    /// This is less than ``originalLength`` when a snapshot length truncated
    /// the packet.
    public let captureLength: Int

    /// The length of the packet as it appeared on the wire, before any
    /// snapshot-length truncation.
    public let originalLength: Int

    public init(timestamp: Date, captureLength: Int, originalLength: Int) {
        self.timestamp = timestamp
        self.captureLength = captureLength
        self.originalLength = originalLength
    }
}

extension CaptureInfo {
    /// Builds capture metadata from a libpcap packet header.
    init(_ header: pcap_pkthdr) {
        let seconds = Double(header.ts.tv_sec)
        let microseconds = Double(header.ts.tv_usec) / 1_000_000
        self.init(
            timestamp: Date(timeIntervalSince1970: seconds + microseconds),
            captureLength: Int(header.caplen),
            originalLength: Int(header.len)
        )
    }
}
