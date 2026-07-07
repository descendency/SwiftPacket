import Cpcap
import Foundation

/// Reads packets from a `.pcap` capture file.
///
/// Unlike ``LiveCapture``, reading a savefile needs no special privileges.
public final class PcapFileReader: PacketSource, Sendable {
    private let engine: PcapEngine

    public var linkType: LinkType { engine.linkType }

    /// Opens the `.pcap` file at `path`.
    /// - Throws: ``PcapError`` if the file cannot be opened or parsed.
    public init(path: String) throws {
        let (opened, message) = withPcapErrorBuffer { errbuf in
            path.withCString { pcap_open_offline($0, errbuf) }
        }
        guard let handle = opened else {
            throw PcapError(message: message.isEmpty ? "pcap_open_offline failed" : message)
        }
        self.engine = PcapEngine(handle: handle)
    }

    /// Opens the `.pcap` file at `url` (must be a file URL).
    public convenience init(url: URL) throws {
        try self.init(path: url.path)
    }

    public func packets() -> PacketSequence {
        engine.makeSequence()
    }

    /// Installs a BPF filter so only matching packets are read from the file.
    /// Set it before iterating ``packets()``.
    /// - Throws: ``PcapError`` if the expression fails to compile or install.
    public func setFilter(_ expression: String) throws {
        try engine.setFilter(expression)
    }
}
