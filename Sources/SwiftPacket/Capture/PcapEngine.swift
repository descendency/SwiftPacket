import Cpcap
import Dispatch  // explicit for Linux, where Foundation does not re-export it
import Foundation

/// Owns a libpcap handle (`pcap_t*`) and turns its blocking, one-at-a-time read
/// API into an `async` pull-based sequence.
///
/// ## Concurrency design
///
/// `pcap_t*` is a stateful, non-`Sendable`, non-thread-safe C handle, so this
/// type is `@unchecked Sendable` and upholds the invariant manually:
///
/// - The handle is only ever *read* on a single private serial `DispatchQueue`.
///   Each `next()` hops onto that queue for exactly one `pcap_next_ex` call,
///   which is why the blocking read never stalls a cooperative-pool thread.
/// - `pcap_breakloop` is the one call libpcap documents as safe to make from
///   another thread; it is used (under a lock, and only while the handle is
///   open) to interrupt an in-flight blocking read on cancellation.
/// - Closing happens once, either after the read loop ends or in `deinit`.
///   Because each queued read block retains `self`, `deinit` cannot run while a
///   read is in flight, so closing never races a read.
///
/// The result is true backpressure: nothing is read until the consumer asks for
/// the next packet, so there is no unbounded in-memory buffer. When a live
/// consumer falls behind, packets queue in the *kernel's* capture buffer — the
/// correct place for loss to occur and be accounted for — rather than silently
/// piling up in Swift.
final class PcapEngine: CaptureEngine, @unchecked Sendable {
    private let handle: OpaquePointer
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var closed = false
    private var stopRequested = false

    /// The link-layer type reported by the handle.
    let linkType: LinkType

    init(handle: OpaquePointer) {
        self.handle = handle
        self.linkType = LinkType(rawValue: pcap_datalink(handle))
        self.queue = DispatchQueue(label: "com.swiftpacket.capture")
    }

    deinit {
        lock.lock()
        let alreadyClosed = closed
        closed = true
        lock.unlock()
        if !alreadyClosed {
            pcap_close(handle)
        }
    }

    /// Wraps this engine in a single-pass async sequence.
    func makeSequence() -> PacketSequence {
        PacketSequence(engine: self)
    }

    /// Compiles `expression` and installs it on the handle so that subsequent
    /// reads only yield matching packets. Runs on the private queue, serialized
    /// with reads.
    func setFilter(_ expression: String, optimize: Bool = true) throws {
        try queue.sync {
            var program = bpf_program()
            let compiled = expression.withCString { cString in
                pcap_compile(handle, &program, cString, optimize ? 1 : 0, 0xFFFF_FFFF)
            }
            guard compiled == 0 else {
                let text = pcap_geterr(handle).map { String(cString: $0) } ?? "filter compile error"
                throw PcapError(message: "failed to compile filter \"\(expression)\": \(text)", code: compiled)
            }
            defer { pcap_freecode(&program) }

            let applied = pcap_setfilter(handle, &program)
            guard applied == 0 else {
                let text = pcap_geterr(handle).map { String(cString: $0) } ?? "setfilter error"
                throw PcapError(message: "failed to install filter: \(text)", code: applied)
            }
        }
    }

    /// Reads (and resets) the handle's capture counters via `pcap_stats`.
    /// Only valid on live captures — libpcap returns an error for savefiles.
    func statistics() throws -> CaptureStatistics {
        try queue.sync {
            var stat = pcap_stat()
            guard pcap_stats(handle, &stat) == 0 else {
                let text = pcap_geterr(handle).map { String(cString: $0) } ?? "pcap_stats error"
                throw PcapError(message: text)
            }
            return CaptureStatistics(
                received: UInt64(stat.ps_recv),
                dropped: UInt64(stat.ps_drop),
                interfaceDropped: UInt64(stat.ps_ifdrop)
            )
        }
    }

    /// Injects a raw frame via `pcap_inject`. Serialized with reads.
    /// - Returns: the number of bytes written.
    func inject(_ data: Data) throws -> Int {
        try queue.sync {
            let written = data.withUnsafeBytes { raw in
                pcap_inject(handle, raw.baseAddress, raw.count)
            }
            guard written >= 0 else {
                let text = pcap_geterr(handle).map { String(cString: $0) } ?? "pcap_inject error"
                throw PcapError(message: text, code: written)
            }
            return Int(written)
        }
    }

    /// Reads the next packet, suspending until one is available, the source is
    /// exhausted (returns `nil`), or the task is cancelled (returns `nil`).
    func next() async throws -> CapturedPacket? {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    do {
                        continuation.resume(returning: try readOne())
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            requestStop()
        }
    }

    /// Runs on `queue`. Loops past live-capture timeouts until it produces a
    /// packet, reaches the end of the source, or is asked to stop.
    private func readOne() throws -> CapturedPacket? {
        while true {
            if isStopRequested { return nil }

            var headerPtr: UnsafeMutablePointer<pcap_pkthdr>?
            var dataPtr: UnsafePointer<UInt8>?
            let status = pcap_next_ex(handle, &headerPtr, &dataPtr)

            switch status {
            case 1:  // a packet was read
                guard let headerPtr, let dataPtr else { continue }
                let header = headerPtr.pointee
                // Copy out of libpcap's reused buffer immediately.
                let bytes = Data(bytes: dataPtr, count: Int(header.caplen))
                return CapturedPacket(
                    data: bytes,
                    info: CaptureInfo(header),
                    linkType: linkType
                )
            case 0:  // live-capture timeout: no packet yet, keep waiting
                continue
            case -2:  // PCAP_ERROR_BREAK: end of a savefile, or pcap_breakloop
                return nil
            default:  // -1 PCAP_ERROR and anything else
                let text = pcap_geterr(handle).map { String(cString: $0) } ?? "capture error"
                throw PcapError(message: text, code: status)
            }
        }
    }

    private var isStopRequested: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopRequested
    }

    /// Signals the read loop to stop and interrupts any in-flight blocking read.
    private func requestStop() {
        lock.lock()
        defer { lock.unlock() }
        stopRequested = true
        if !closed {
            pcap_breakloop(handle)
        }
    }
}
