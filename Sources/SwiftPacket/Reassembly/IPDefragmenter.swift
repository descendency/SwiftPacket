import Foundation

/// The outcome of feeding a packet to ``IPDefragmenter``.
public enum DefragmentationResult: Sendable {
    /// The packet was not a fragment (or set Don't-Fragment); use it as-is.
    case passThrough(Packet)
    /// The packet was a fragment and has been buffered; the datagram is not
    /// yet complete, so there is nothing to process.
    case incomplete
    /// A fragmented datagram is now complete; here is the reassembled,
    /// re-decoded packet.
    case reassembled(Packet)

    /// The packet ready to process — the original for ``passThrough`` or the
    /// reassembled one for ``reassembled``; `nil` while ``incomplete``.
    public var packet: Packet? {
        switch self {
        case .passThrough(let packet), .reassembled(let packet): return packet
        case .incomplete: return nil
        }
    }
}

/// Reassembles fragmented IPv4 and IPv6 datagrams (RFC 791 / RFC 8200).
///
/// Feed every packet through ``process(_:using:)``; non-fragments pass
/// straight through, fragments are buffered by their datagram key
/// (source, destination, identification, protocol), and once a datagram is
/// whole the reassembled bytes are re-decoded and returned. Overlapping data
/// is resolved first-fragment-wins (the conservative choice against overlap
/// evasion), and incomplete datagrams are evicted after a timeout or when the
/// buffer caps are hit, so a flood of first-fragments cannot exhaust memory.
///
/// An `actor`, so it is safe to share across the concurrent tasks draining a
/// capture.
public actor IPDefragmenter {
    /// Bounds on buffering, guarding against resource exhaustion.
    public struct Configuration: Sendable {
        /// Largest reassembled datagram to allow (default 64 KiB, the IPv4
        /// maximum; raise for IPv6 jumbo-ish datagrams).
        public var maximumDatagramBytes: Int
        /// Most fragments to hold for one datagram before dropping it.
        public var maximumFragmentsPerDatagram: Int
        /// How long an incomplete datagram may sit before eviction.
        public var reassemblyTimeout: TimeInterval
        /// Most in-flight datagrams to track at once.
        public var maximumDatagrams: Int

        public init(
            maximumDatagramBytes: Int = 65_535,
            maximumFragmentsPerDatagram: Int = 1024,
            reassemblyTimeout: TimeInterval = 30,
            maximumDatagrams: Int = 4096
        ) {
            self.maximumDatagramBytes = maximumDatagramBytes
            self.maximumFragmentsPerDatagram = maximumFragmentsPerDatagram
            self.reassemblyTimeout = reassemblyTimeout
            self.maximumDatagrams = maximumDatagrams
        }
    }

    private struct Key: Hashable {
        let source: [UInt8]
        let destination: [UInt8]
        let identification: UInt32
        let proto: UInt8
        let isIPv6: Bool
    }

    /// A run of reassembled bytes at a fixed offset within the datagram.
    private struct Piece {
        let offset: Int
        let data: Data
    }

    private struct Datagram {
        var pieces: [Piece] = []
        /// The total datagram length once the last fragment (more=false) is
        /// seen; `nil` until then.
        var totalLength: Int?
        var receivedBytes = 0
        var lastActivity: Date
        /// Template for rebuilding the reassembled datagram's header.
        var headerTemplate: Data
        /// For IPv6, the real transport protocol from the fragment header.
        var finalProtocol: UInt8
    }

    private let configuration: Configuration
    private var datagrams: [Key: Datagram] = [:]

    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    /// The number of incomplete datagrams currently buffered.
    public var pendingCount: Int { datagrams.count }

    /// Processes one packet, reassembling IP fragments.
    ///
    /// - Parameter registry: used to re-decode a completed datagram; defaults
    ///   to ``DecoderRegistry/standard``.
    public func process(_ packet: Packet, using registry: DecoderRegistry = .standard)
        -> DefragmentationResult
    {
        let now = Date()
        evictStale(now: now)

        if let ipv4 = packet.layer(IPv4.self), ipv4.moreFragments || ipv4.fragmentOffset > 0 {
            return handleIPv4(ipv4, now: now, registry: registry)
        }
        if let ipv6 = packet.layer(IPv6.self), let fragment = packet.layer(IPv6Fragment.self) {
            return handleIPv6(ipv6, fragment, now: now, registry: registry)
        }
        return .passThrough(packet)
    }

    // MARK: - IPv4

    private func handleIPv4(_ ipv4: IPv4, now: Date, registry: DecoderRegistry)
        -> DefragmentationResult
    {
        let key = Key(
            source: ipv4.sourceAddress.octets,
            destination: ipv4.destinationAddress.octets,
            identification: UInt32(ipv4.identification),
            proto: ipv4.proto.rawValue,
            isIPv6: false)

        return insert(
            key: key,
            offsetBytes: Int(ipv4.fragmentOffset) * 8,
            payload: ipv4.payload,
            isLast: !ipv4.moreFragments,
            now: now,
            headerTemplate: ipv4.layerContents,
            finalProtocol: ipv4.proto.rawValue,
            registry: registry,
            rebuild: rebuildIPv4)
    }

    /// Rebuilds a complete IPv4 datagram from the first fragment's header plus
    /// the reassembled payload: patches total length, clears the fragment
    /// fields, and recomputes the header checksum.
    private func rebuildIPv4(header: Data, payload: Data, finalProtocol: UInt8) -> Data {
        var bytes = [UInt8](header)
        let total = bytes.count + payload.count
        bytes[2] = UInt8(total >> 8)
        bytes[3] = UInt8(total & 0xFF)
        bytes[6] = 0  // clear flags (incl. MF) and the high fragment-offset bits
        bytes[7] = 0  // clear the low fragment-offset bits
        bytes[10] = 0  // zero the checksum before recomputing
        bytes[11] = 0
        let checksum = internetChecksum(Data(bytes))
        bytes[10] = UInt8(checksum >> 8)
        bytes[11] = UInt8(checksum & 0xFF)
        return Data(bytes) + payload
    }

    // MARK: - IPv6

    private func handleIPv6(
        _ ipv6: IPv6, _ fragment: IPv6Fragment, now: Date, registry: DecoderRegistry
    ) -> DefragmentationResult {
        let key = Key(
            source: ipv6.sourceAddress.bytes,
            destination: ipv6.destinationAddress.bytes,
            identification: fragment.identification,
            proto: fragment.nextHeader.rawValue,
            isIPv6: true)

        return insert(
            key: key,
            offsetBytes: Int(fragment.fragmentOffset) * 8,
            payload: fragment.payload,
            isLast: !fragment.moreFragments,
            now: now,
            headerTemplate: ipv6.layerContents,
            finalProtocol: fragment.nextHeader.rawValue,
            registry: registry,
            rebuild: rebuildIPv6)
    }

    /// Rebuilds a complete IPv6 datagram: the 40-byte base header with the
    /// fragment extension removed, next-header set to the real transport, and
    /// payload length patched.
    private func rebuildIPv6(header: Data, payload: Data, finalProtocol: UInt8) -> Data {
        var bytes = [UInt8](header.prefix(40))
        bytes[4] = UInt8(payload.count >> 8)
        bytes[5] = UInt8(payload.count & 0xFF)
        bytes[6] = finalProtocol  // next header: skip the fragment extension
        return Data(bytes) + payload
    }

    // MARK: - Shared insertion / reassembly

    private func insert(
        key: Key,
        offsetBytes: Int,
        payload: Data,
        isLast: Bool,
        now: Date,
        headerTemplate: Data,
        finalProtocol: UInt8,
        registry: DecoderRegistry,
        rebuild: (Data, Data, UInt8) -> Data
    ) -> DefragmentationResult {
        // Reject obviously malformed or oversized fragments outright.
        guard offsetBytes >= 0, offsetBytes + payload.count <= configuration.maximumDatagramBytes
        else { return .incomplete }

        var datagram =
            datagrams[key]
            ?? Datagram(
                lastActivity: now, headerTemplate: headerTemplate, finalProtocol: finalProtocol)
        datagram.lastActivity = now
        // The first fragment (offset 0) carries the header we rebuild from.
        if offsetBytes == 0 {
            datagram.headerTemplate = headerTemplate
            datagram.finalProtocol = finalProtocol
        }
        if isLast {
            datagram.totalLength = offsetBytes + payload.count
        }

        datagram.pieces.append(Piece(offset: offsetBytes, data: payload))
        datagram.receivedBytes += payload.count

        // Enforce caps: drop a datagram that is trying to exhaust us.
        if datagram.pieces.count > configuration.maximumFragmentsPerDatagram
            || datagram.receivedBytes > configuration.maximumDatagramBytes
        {
            datagrams[key] = nil
            return .incomplete
        }

        // Attempt reassembly if we know the total length.
        if let total = datagram.totalLength,
            let assembled = reassemble(datagram.pieces, total: total)
        {
            datagrams[key] = nil
            let bytes = rebuild(datagram.headerTemplate, assembled, datagram.finalProtocol)
            let startLayer: LayerType = key.isIPv6 ? .ipv6 : .ipv4
            return .reassembled(Packet.decode(bytes, startingAt: startLayer, using: registry))
        }

        datagrams[key] = datagram
        if datagrams.count > configuration.maximumDatagrams {
            evictOldest()
        }
        return .incomplete
    }

    /// Returns the fully reassembled payload if `pieces` cover `0..<total`
    /// with no gaps, resolving overlaps first-fragment-wins.
    private func reassemble(_ pieces: [Piece], total: Int) -> Data? {
        guard total >= 0, total <= configuration.maximumDatagramBytes else { return nil }
        var filled = [Bool](repeating: false, count: total)
        var buffer = [UInt8](repeating: 0, count: total)

        // Earlier fragments win overlaps: process in arrival order and only
        // write bytes not already filled.
        for piece in pieces {
            for (index, byte) in piece.data.enumerated() {
                let position = piece.offset + index
                guard position < total else { break }
                if !filled[position] {
                    filled[position] = true
                    buffer[position] = byte
                }
            }
        }
        return filled.allSatisfy { $0 } ? Data(buffer) : nil
    }

    // MARK: - Eviction

    private func evictStale(now: Date) {
        let deadline = now.addingTimeInterval(-configuration.reassemblyTimeout)
        datagrams = datagrams.filter { $0.value.lastActivity >= deadline }
    }

    private func evictOldest() {
        if let oldest = datagrams.min(by: { $0.value.lastActivity < $1.value.lastActivity })?.key {
            datagrams[oldest] = nil
        }
    }
}
