import Foundation

/// A TLS handshake fact recovered from a reassembled stream.
public struct TLSHandshakeEvent: Sendable {
    /// What this event newly revealed.
    public enum Discovery: Sendable {
        case clientHello
        case serverHello
        case certificates
    }

    /// The half-stream (direction) the handshake bytes came from.
    public let stream: TCPStreamKey
    /// What triggered this event.
    public let discovery: Discovery
    /// The TLS content parsed from the stream so far. Read
    /// ``TLS/clientHello`` / ``TLS/serverHello`` / ``TLS/certificates``
    /// according to ``discovery``.
    public let tls: TLS

    /// The bidirectional connection the handshake belongs to.
    public var connection: ConnectionKey { stream.connection }
}

/// Recovers TLS handshakes — SNI, ALPN, JA3/JA3S, and certificate chains —
/// from live packets, reassembling the TCP streams first so a handshake that
/// spans several segments (a certificate chain almost always does) is parsed
/// as one piece.
///
/// This is the turnkey answer to the caveat on ``TLSDecoder``: feed every
/// packet through ``process(_:)`` and read the emitted ``TLSHandshakeEvent``s,
/// rather than reassembling streams and calling ``TLSDecoder/parse(_:)``
/// yourself. Internally it drives a ``TCPReassembler`` and re-parses each
/// direction's accumulated bytes as they grow, emitting an event the first
/// time a ClientHello, ServerHello, or certificate chain becomes complete.
///
/// Streams that don't begin with a TLS record are dropped after the first few
/// bytes, so non-TLS traffic costs almost nothing.
public actor TLSStreamAssembler {
    public struct Configuration: Sendable {
        /// Most handshake bytes to accumulate per stream before giving up
        /// (TLS handshakes fit comfortably; this only bounds abuse).
        public var maximumHandshakeBytes: Int

        public init(maximumHandshakeBytes: Int = 65_536) {
            self.maximumHandshakeBytes = maximumHandshakeBytes
        }
    }

    private struct StreamState {
        var buffer = Data()
        /// `nil` until enough bytes exist to judge; `false` drops the stream.
        var isTLS: Bool?
        var clientHelloReported = false
        var serverHelloReported = false
        var certificatesReported = false
    }

    private let configuration: Configuration
    private let reassembler: TCPReassembler
    private var states: [TCPStreamKey: StreamState] = [:]

    public init(
        configuration: Configuration = Configuration(),
        reassemblerConfiguration: TCPReassembler.Configuration = .init()
    ) {
        self.configuration = configuration
        self.reassembler = TCPReassembler(configuration: reassemblerConfiguration)
    }

    /// Processes one packet, returning any TLS handshake facts it completed.
    public func process(_ packet: Packet, now: Date = Date()) async -> [TLSHandshakeEvent] {
        let deliveries = await reassembler.process(packet, now: now)
        return consume(deliveries)
    }

    /// Flushes reassembly (skipping unrecoverable gaps) and returns any TLS
    /// facts that become parseable as a result.
    public func flush(force: Bool = false, now: Date = Date()) async -> [TLSHandshakeEvent] {
        consume(await reassembler.flush(force: force, now: now))
    }

    /// Drains all streams at end-of-capture.
    public func close(now: Date = Date()) async -> [TLSHandshakeEvent] {
        let events = consume(await reassembler.close(now: now))
        states.removeAll()
        return events
    }

    private func consume(_ deliveries: [TCPSegmentDelivery]) -> [TLSHandshakeEvent] {
        var events: [TLSHandshakeEvent] = []
        for delivery in deliveries {
            events.append(contentsOf: handle(delivery))
        }
        return events
    }

    private func handle(_ delivery: TCPSegmentDelivery) -> [TLSHandshakeEvent] {
        // A gap corrupts the byte stream; a handshake straddling it can't be
        // trusted, so stop tracking this stream.
        if delivery.hasGap {
            states[delivery.stream]?.isTLS = false
        }

        var state = states[delivery.stream] ?? StreamState()
        if state.isTLS == false {
            states[delivery.stream] = state
            return []
        }

        if !delivery.data.isEmpty {
            state.buffer.append(delivery.data)
        }

        // Decide whether this even looks like TLS once we have a record header.
        if state.isTLS == nil, state.buffer.count >= 5 {
            state.isTLS = TLSDecoder.looksLikeTLSRecord(state.buffer)
            if state.isTLS == false {
                state.buffer = Data()  // free it; not our traffic
                states[delivery.stream] = state
                return []
            }
        }

        guard state.isTLS == true else {
            states[delivery.stream] = state
            return []
        }

        // Bound accumulation.
        if state.buffer.count > configuration.maximumHandshakeBytes {
            state.isTLS = false
            state.buffer = Data()
            states[delivery.stream] = state
            return []
        }

        var events: [TLSHandshakeEvent] = []
        if let tls = try? TLSDecoder.parse(state.buffer) {
            if !state.clientHelloReported, tls.clientHello != nil {
                state.clientHelloReported = true
                events.append(
                    TLSHandshakeEvent(stream: delivery.stream, discovery: .clientHello, tls: tls))
            }
            if !state.serverHelloReported, tls.serverHello != nil {
                state.serverHelloReported = true
                events.append(
                    TLSHandshakeEvent(stream: delivery.stream, discovery: .serverHello, tls: tls))
            }
            if !state.certificatesReported, !tls.certificates.isEmpty {
                state.certificatesReported = true
                events.append(
                    TLSHandshakeEvent(stream: delivery.stream, discovery: .certificates, tls: tls))
            }

            // Once we have the client hello, or the server's certificates,
            // there's nothing more to learn from this direction — free it.
            if state.clientHelloReported || state.certificatesReported {
                state.buffer = Data()
                state.isTLS = false
            }
        }

        states[delivery.stream] = state
        return events
    }
}
