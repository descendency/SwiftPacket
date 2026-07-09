import Cpcap
import Foundation

/// Captures packets live from a network interface.
///
/// Live capture requires access to the BPF devices (`/dev/bpf*`), which
/// normally means running with elevated privileges or a ChmodBPF-style
/// permission grant — the same setup Wireshark uses.
public final class LiveCapture: PacketSource, Sendable {
    private let engine: PcapEngine

    public var linkType: LinkType { engine.linkType }

    /// Opens a live capture on the named interface (for example `"en0"`).
    /// - Throws: ``PcapError`` if the interface cannot be opened or activated.
    public init(interface: String, config: CaptureConfig = .default) throws {
        let handle = try Self.open(interface: interface, config: config)
        self.engine = PcapEngine(handle: handle)
    }

    public func packets() -> PacketSequence {
        engine.makeSequence()
    }

    /// Installs a BPF filter (for example `"tcp port 443"`) in the kernel, so
    /// only matching packets are delivered. Set it before iterating ``packets()``.
    /// - Throws: ``PcapError`` if the expression fails to compile or install.
    public func setFilter(_ expression: String) throws {
        try engine.setFilter(expression)
    }

    /// The capture's received / dropped counters (`pcap_stats`).
    /// - Throws: ``PcapError`` (drop statistics are unavailable on some
    ///   platforms and always on savefiles).
    public func statistics() throws -> CaptureStatistics {
        try engine.statistics()
    }

    /// Injects a raw frame onto the interface (`pcap_inject`).
    ///
    /// Build the bytes yourself or serialize a packet with
    /// ``Packet/serializedData(options:)`` / ``serializeLayers(_:options:)``.
    /// - Returns: the number of bytes sent.
    /// - Throws: ``PcapError`` on failure (injection may be unsupported on some
    ///   interfaces).
    @discardableResult
    public func send(_ data: Data) throws -> Int {
        try engine.inject(data)
    }

    private static func open(interface: String, config: CaptureConfig) throws -> OpaquePointer {
        let (created, message) = withPcapErrorBuffer { errbuf in
            interface.withCString { pcap_create($0, errbuf) }
        }
        guard let handle = created else {
            throw PcapError(message: message.isEmpty ? "pcap_create failed" : message)
        }

        pcap_set_snaplen(handle, config.snapshotLength)
        pcap_set_promisc(handle, config.promiscuous ? 1 : 0)
        pcap_set_timeout(handle, config.timeoutMilliseconds)
        if config.immediate {
            pcap_set_immediate_mode(handle, 1)
        }
        if let bufferSize = config.bufferSize {
            pcap_set_buffer_size(handle, bufferSize)
        }
        if config.monitorMode {
            // Best effort: fails on interfaces that can't do RFMON, in which
            // case activation below surfaces the error.
            pcap_set_rfmon(handle, 1)
        }

        let status = pcap_activate(handle)
        if status < 0 {
            let text = pcap_geterr(handle).map { String(cString: $0) } ?? "pcap_activate failed"
            pcap_close(handle)
            throw PcapError(message: text, code: status)
        }
        // status > 0 is a warning (e.g. promiscuous mode unavailable); proceed.
        return handle
    }
}
