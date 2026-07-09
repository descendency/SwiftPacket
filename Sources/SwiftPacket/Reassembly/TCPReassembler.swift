import Foundation

/// Identifies one direction of a TCP conversation — the half-stream carrying
/// bytes from a specific source endpoint to a specific destination.
public struct TCPStreamKey: Hashable, Sendable, CustomStringConvertible {
    /// The directional network flow (source → destination IP).
    public let network: Flow
    /// The directional transport flow (source → destination port).
    public let transport: Flow

    public init(network: Flow, transport: Flow) {
        self.network = network
        self.transport = transport
    }

    /// The bidirectional connection this half-stream belongs to; equal for
    /// both directions.
    public var connection: ConnectionKey {
        ConnectionKey(network: network, transport: transport)
    }

    /// The key for the opposite direction.
    public var reversed: TCPStreamKey {
        TCPStreamKey(network: network.reversed, transport: transport.reversed)
    }

    public var description: String { "\(network) \(transport)" }
}

/// A run of in-order stream bytes produced by ``TCPReassembler``.
public struct TCPSegmentDelivery: Sendable {
    /// The half-stream (direction) these bytes belong to.
    public let stream: TCPStreamKey
    /// The reassembled, in-order bytes. Empty when ``isEnd`` marks a bare
    /// teardown or ``gapLength`` reports a skipped hole with no trailing data.
    public let data: Data
    /// The absolute TCP sequence number of the first byte of ``data``.
    public let sequenceNumber: UInt32
    /// Bytes of unrecoverable gap that immediately precede ``data`` (data that
    /// was never captured and has been skipped). Zero in the normal case.
    public let gapLength: Int
    /// Whether the stream closed here (FIN or RST seen and drained).
    public let isEnd: Bool

    /// Whether a gap preceded these bytes.
    public var hasGap: Bool { gapLength > 0 }
}

/// Reassembles TCP segments into ordered, per-direction byte streams.
///
/// Feed every packet through ``process(_:)``; the reassembler tracks each
/// half-connection's sequence space, delivers bytes in order, buffers
/// out-of-order segments, discards retransmits and already-seen overlaps, and
/// reports teardown on FIN/RST. Call ``flush(force:)`` periodically to skip
/// past unrecoverable gaps (data that was dropped by the capture) and to evict
/// idle streams, and ``close()`` at end-of-capture to drain everything.
///
/// Capture starting mid-connection is handled: a stream with no observed SYN
/// simply adopts the first segment's sequence number as its origin.
///
/// An `actor`; deliveries are returned to the caller rather than pushed to a
/// delegate, which keeps ordering explicit and sidesteps re-entrancy.
public actor TCPReassembler {
    public struct Configuration: Sendable {
        /// Most out-of-order bytes to buffer per half-stream before forcing a
        /// gap flush.
        public var maximumBufferedBytes: Int
        /// How long a half-stream may be idle before eviction.
        public var streamTimeout: TimeInterval
        /// Most half-streams to track at once.
        public var maximumStreams: Int

        public init(
            maximumBufferedBytes: Int = 4 << 20,
            streamTimeout: TimeInterval = 60,
            maximumStreams: Int = 65_536
        ) {
            self.maximumBufferedBytes = maximumBufferedBytes
            self.streamTimeout = streamTimeout
            self.maximumStreams = maximumStreams
        }
    }

    /// One out-of-order segment awaiting its turn.
    private struct Segment {
        let sequence: UInt32
        let data: Data
    }

    private struct HalfStream {
        /// Next in-order absolute sequence number expected; `nil` until the
        /// first segment (or SYN) fixes the origin.
        var nextSequence: UInt32?
        var buffered: [Segment] = []
        var bufferedBytes = 0
        /// Absolute sequence position of a seen FIN, if any.
        var finSequence: UInt32?
        var closed = false
        var lastActivity: Date
    }

    private let configuration: Configuration
    private var streams: [TCPStreamKey: HalfStream] = [:]

    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    /// The number of half-streams currently tracked.
    public var streamCount: Int { streams.count }

    // MARK: - Sequence arithmetic (32-bit modular, RFC 1982)

    private static func lt(_ a: UInt32, _ b: UInt32) -> Bool {
        Int32(bitPattern: a &- b) < 0
    }
    private static func le(_ a: UInt32, _ b: UInt32) -> Bool {
        Int32(bitPattern: a &- b) <= 0
    }

    // MARK: - Ingest

    /// Processes one packet; returns any in-order bytes it made deliverable.
    ///
    /// A packet with no TCP layer, or a TCP layer with no network/port flow,
    /// yields no deliveries.
    public func process(_ packet: Packet, now: Date = Date()) -> [TCPSegmentDelivery] {
        guard let tcp = packet.layer(TCP.self),
            let network = packet.networkFlow,
            let transport = packet.transportFlow
        else { return [] }

        let key = TCPStreamKey(network: network, transport: transport)
        var stream = streams[key] ?? HalfStream(lastActivity: now)
        stream.lastActivity = now

        let deliveries = ingest(into: &stream, key: key, tcp: tcp)

        if stream.closed && stream.buffered.isEmpty {
            streams[key] = nil
        } else {
            streams[key] = stream
            enforceStreamCap()
        }
        return deliveries
    }

    private func ingest(into stream: inout HalfStream, key: TCPStreamKey, tcp: TCP)
        -> [TCPSegmentDelivery]
    {
        var out: [TCPSegmentDelivery] = []

        if tcp.rst {
            if !stream.closed {
                stream.closed = true
                out.append(
                    TCPSegmentDelivery(
                        stream: key, data: Data(), sequenceNumber: tcp.sequenceNumber,
                        gapLength: 0, isEnd: true))
            }
            return out
        }

        // The SYN occupies one sequence number; data begins at seq+1.
        var dataSequence = tcp.sequenceNumber
        if tcp.syn {
            if stream.nextSequence == nil { stream.nextSequence = tcp.sequenceNumber &+ 1 }
            dataSequence = tcp.sequenceNumber &+ 1
        }
        if stream.nextSequence == nil {
            // Mid-stream capture: adopt this segment as the origin.
            stream.nextSequence = dataSequence
        }

        let payload = tcp.payload
        if tcp.fin {
            stream.finSequence = dataSequence &+ UInt32(payload.count)
        }

        if !payload.isEmpty {
            insert(Segment(sequence: dataSequence, data: payload), into: &stream)
            out.append(contentsOf: drain(&stream, key: key))
        }

        // A FIN whose sequence has been reached closes the stream.
        if let fin = stream.finSequence, let next = stream.nextSequence,
            next == fin, !stream.closed
        {
            stream.closed = true
            out.append(
                TCPSegmentDelivery(
                    stream: key, data: Data(), sequenceNumber: next, gapLength: 0, isEnd: true))
        }
        return out
    }

    /// Buffers an out-of-order (or in-order) segment, dropping data already
    /// delivered and enforcing the per-stream byte cap.
    private func insert(_ segment: Segment, into stream: inout HalfStream) {
        stream.buffered.append(segment)
        stream.bufferedBytes += segment.data.count
    }

    /// Delivers every buffered byte that is now contiguous from
    /// `nextSequence`, trimming overlaps and dropping pure retransmits.
    private func drain(_ stream: inout HalfStream, key: TCPStreamKey) -> [TCPSegmentDelivery] {
        var out: [TCPSegmentDelivery] = []
        guard var next = stream.nextSequence else { return out }

        while true {
            // Find the buffered segment that carries `next` (its range spans
            // the next expected byte).
            guard
                let index = stream.buffered.firstIndex(where: { segment in
                    let end = segment.sequence &+ UInt32(segment.data.count)
                    return Self.le(segment.sequence, next) && Self.lt(next, end)
                })
            else { break }

            let segment = stream.buffered.remove(at: index)
            stream.bufferedBytes -= segment.data.count

            let alreadySeen = Int(next &- segment.sequence)  // overlap to trim
            let fresh = segment.data.dropFirst(alreadySeen)
            if !fresh.isEmpty {
                out.append(
                    TCPSegmentDelivery(
                        stream: key, data: Data(fresh), sequenceNumber: next,
                        gapLength: 0, isEnd: false))
                next = next &+ UInt32(fresh.count)
            }
        }

        stream.nextSequence = next
        // Discard any fully-old buffered segments (retransmits behind `next`).
        stream.buffered.removeAll { segment in
            let end = segment.sequence &+ UInt32(segment.data.count)
            if Self.le(end, next) {
                stream.bufferedBytes -= segment.data.count
                return true
            }
            return false
        }
        return out
    }

    // MARK: - Flush & close

    /// Skips past unrecoverable gaps and evicts idle streams.
    ///
    /// - Parameter force: when `true`, every stream with buffered data waiting
    ///   behind a gap is advanced to its next available bytes (reporting the
    ///   skipped ``TCPSegmentDelivery/gapLength``), even if not yet idle. Use
    ///   this when a stream has stalled and you would rather have the bytes
    ///   after the hole than wait for data that was dropped by the capture.
    public func flush(force: Bool = false, now: Date = Date()) -> [TCPSegmentDelivery] {
        var out: [TCPSegmentDelivery] = []
        let deadline = now.addingTimeInterval(-configuration.streamTimeout)

        for (key, var stream) in streams {
            let idle = stream.lastActivity < deadline
            let overCap = stream.bufferedBytes > configuration.maximumBufferedBytes
            if force || idle || overCap {
                out.append(contentsOf: skipGap(&stream, key: key))
            }
            if stream.closed && stream.buffered.isEmpty || (idle && stream.buffered.isEmpty) {
                streams[key] = nil
            } else {
                streams[key] = stream
            }
        }
        return out
    }

    /// Drains and removes every stream (end of capture).
    public func close(now: Date = Date()) -> [TCPSegmentDelivery] {
        var out: [TCPSegmentDelivery] = []
        for (key, var stream) in streams {
            out.append(contentsOf: skipGap(&stream, key: key, drainAll: true))
        }
        streams.removeAll()
        return out
    }

    /// Advances past the gap at `nextSequence` to the earliest buffered
    /// segment, delivering it (and everything now contiguous). With
    /// `drainAll`, repeats until the buffer is empty.
    private func skipGap(_ stream: inout HalfStream, key: TCPStreamKey, drainAll: Bool = false)
        -> [TCPSegmentDelivery]
    {
        var out: [TCPSegmentDelivery] = []
        guard stream.nextSequence != nil else { return out }

        repeat {
            guard
                let earliest = stream.buffered.min(by: {
                    Self.lt($0.sequence, $1.sequence)
                })
            else { break }
            let next = stream.nextSequence!

            // If the earliest segment is already contiguous, a plain drain
            // handles it; otherwise report and skip the hole.
            if Self.lt(next, earliest.sequence) {
                let gap = Int(earliest.sequence &- next)
                stream.nextSequence = earliest.sequence
                let delivered = drain(&stream, key: key)
                if let first = delivered.first {
                    out.append(
                        TCPSegmentDelivery(
                            stream: key, data: first.data, sequenceNumber: first.sequenceNumber,
                            gapLength: gap, isEnd: first.isEnd))
                    out.append(contentsOf: delivered.dropFirst())
                } else {
                    out.append(
                        TCPSegmentDelivery(
                            stream: key, data: Data(), sequenceNumber: earliest.sequence,
                            gapLength: gap, isEnd: false))
                }
            } else {
                out.append(contentsOf: drain(&stream, key: key))
            }
        } while drainAll && !stream.buffered.isEmpty

        return out
    }

    private func enforceStreamCap() {
        guard streams.count > configuration.maximumStreams else { return }
        if let oldest = streams.min(by: { $0.value.lastActivity < $1.value.lastActivity })?.key {
            streams[oldest] = nil
        }
    }
}
