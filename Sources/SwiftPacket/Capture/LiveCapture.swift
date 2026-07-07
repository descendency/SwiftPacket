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
