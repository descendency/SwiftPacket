import Foundation

/// A source of captured packets — a live interface, a `.pcap` file, or any
/// other origin. Sources are single-pass: iterate the sequence from
/// ``packets()`` exactly once.
public protocol PacketSource: Sendable {
    /// The link-layer type shared by every packet from this source.
    var linkType: LinkType { get }

    /// A single-pass async sequence of captured packets.
    ///
    /// Iteration ends when the source is exhausted (end of file) or the
    /// surrounding task is cancelled. libpcap errors terminate iteration by
    /// throwing.
    func packets() -> PacketSequence
}

/// The engine seam between ``PacketSequence`` and a concrete capture
/// mechanism. `PcapEngine` (libpcap) implements it everywhere;
/// `AFPacketEngine` implements it on Linux.
protocol CaptureEngine: Sendable {
    /// The link-layer type shared by every packet this engine produces.
    var linkType: LinkType { get }

    /// Reads the next packet, suspending until one is available; `nil` on
    /// end-of-source or cancellation.
    func next() async throws -> CapturedPacket?
}

/// A single-pass, back-pressured async sequence of ``CapturedPacket`` values.
///
/// Each call to the iterator's `next()` pulls exactly one packet from the
/// underlying capture engine, so no packets are read ahead of demand.
public struct PacketSequence: AsyncSequence, Sendable {
    public typealias Element = CapturedPacket

    private let engine: any CaptureEngine

    init(engine: any CaptureEngine) {
        self.engine = engine
    }

    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(engine: engine)
    }

    public struct AsyncIterator: AsyncIteratorProtocol {
        private let engine: any CaptureEngine

        init(engine: any CaptureEngine) {
            self.engine = engine
        }

        public mutating func next() async throws -> CapturedPacket? {
            try await engine.next()
        }
    }
}
