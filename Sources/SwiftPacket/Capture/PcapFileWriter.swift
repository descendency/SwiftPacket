import Cpcap
import Foundation

/// Writes packets to a `.pcap` capture file.
///
/// Backed by a "dead" libpcap handle (`pcap_open_dead`) plus a dumper
/// (`pcap_dump_open`). All writes are serialized by a lock, so a writer may be
/// shared across concurrency domains; it is `@unchecked Sendable` for that
/// reason. Call ``close()`` (or let the writer deinitialize) to flush and
/// finalize the file.
public final class PcapFileWriter: @unchecked Sendable {
    private let handle: OpaquePointer
    private let dumper: OpaquePointer
    private let lock = NSLock()
    private var closed = false

    /// The link-layer type stamped into the file header.
    public let linkType: LinkType

    /// Creates a `.pcap` file at `path` for packets of the given link type.
    /// - Throws: ``PcapError`` if the file cannot be created.
    public init(path: String, linkType: LinkType, snapshotLength: Int32 = 262_144) throws {
        guard let handle = pcap_open_dead(linkType.rawValue, snapshotLength) else {
            throw PcapError(message: "pcap_open_dead failed")
        }
        guard let dumper = path.withCString({ pcap_dump_open(handle, $0) }) else {
            let text = pcap_geterr(handle).map { String(cString: $0) } ?? "pcap_dump_open failed"
            pcap_close(handle)
            throw PcapError(message: text)
        }
        self.handle = handle
        self.dumper = dumper
        self.linkType = linkType
    }

    deinit {
        close()
    }

    /// Appends one packet to the file.
    ///
    /// The packet's ``CaptureInfo`` supplies the record's timestamp and lengths.
    /// No-op after ``close()``.
    public func write(_ packet: CapturedPacket) {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }

        var header = pcap_pkthdr()
        let seconds = packet.info.timestamp.timeIntervalSince1970
        let whole = seconds.rounded(.down)
        // time_t / suseconds_t: the fields' concrete types differ between
        // Darwin (Int32 microseconds) and glibc (Int); the typedefs are
        // portable.
        header.ts.tv_sec = time_t(whole)
        header.ts.tv_usec = suseconds_t((seconds - whole) * 1_000_000)
        header.caplen = bpf_u_int32(packet.info.captureLength)
        header.len = bpf_u_int32(packet.info.originalLength)

        // pcap_dump's first argument is the dumper reinterpreted as a byte
        // pointer (its historical "user" parameter).
        let dumperUser = UnsafeMutableRawPointer(dumper).assumingMemoryBound(to: UInt8.self)
        packet.data.withUnsafeBytes { raw in
            pcap_dump(dumperUser, &header, raw.bindMemory(to: UInt8.self).baseAddress)
        }
    }

    /// Flushes buffered records to disk without closing the file.
    public func flush() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        pcap_dump_flush(dumper)
    }

    /// Flushes and finalizes the file. Idempotent.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        pcap_dump_flush(dumper)
        pcap_dump_close(dumper)
        pcap_close(handle)
    }
}
