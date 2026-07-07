import Foundation

/// A raw captured packet: the on-wire bytes together with capture metadata and
/// the link-layer type needed to begin decoding in Phase 2.
///
/// The bytes are always a fresh, owned copy taken out of libpcap's reused
/// receive buffer, so a `CapturedPacket` is safe to store, send across
/// isolation domains, and outlive the capture loop.
public struct CapturedPacket: Sendable, Equatable {
    /// The captured packet bytes.
    public let data: Data

    /// Capture metadata (timestamp and lengths).
    public let info: CaptureInfo

    /// The link-layer type of ``data``.
    public let linkType: LinkType

    public init(data: Data, info: CaptureInfo, linkType: LinkType) {
        self.data = data
        self.info = info
        self.linkType = linkType
    }
}
