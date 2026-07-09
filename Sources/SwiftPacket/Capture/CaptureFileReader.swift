import Foundation

/// Reads a capture file — classic pcap or pcapng — with no libpcap dependency.
///
/// This is the pure-Swift counterpart to ``PcapFileReader`` (which wraps
/// libpcap). Prefer it when you only read files: it needs no system library,
/// reads pcapng (which Wireshark writes by default), and reports each packet's
/// own link type — useful for pcapng captures that mix interfaces.
///
/// ```swift
/// let reader = try CaptureFileReader(contentsOf: url)
/// for try await captured in reader.packets() {
///     let packet = captured.decoded(using: .standard)
///     print(packet.summary)
/// }
/// ```
///
/// The whole file is parsed up front, so packets are available immediately and
/// iteration never blocks. A truncated tail yields the packets read so far
/// rather than an error.
public final class CaptureFileReader: PacketSource, Sendable {
    private let engine: BufferedPacketEngine

    /// The container format detected for this file.
    public let format: CaptureFileFormat

    /// The link type reported for the source as a whole — the first
    /// interface's for pcapng. Individual packets carry their own
    /// ``CapturedPacket/linkType``.
    public var linkType: LinkType { engine.linkType }

    /// The packets read from the file, also available as the eager array
    /// (``packets()`` returns the same packets as an async sequence).
    public let parsedPackets: [CapturedPacket]

    /// Opens and parses the capture file at `url`.
    /// - Throws: ``CaptureFileError`` if the format is unrecognized or the
    ///   header is truncated.
    public convenience init(contentsOf url: URL) throws {
        try self.init(data: Data(contentsOf: url))
    }

    /// Parses an in-memory capture.
    public init(data: Data) throws {
        let parsed = try CaptureFile.parse(data)
        self.format = parsed.format
        self.parsedPackets = parsed.packets
        self.engine = BufferedPacketEngine(packets: parsed.packets, linkType: parsed.linkType)
    }

    public func packets() -> PacketSequence {
        PacketSequence(engine: engine)
    }
}
