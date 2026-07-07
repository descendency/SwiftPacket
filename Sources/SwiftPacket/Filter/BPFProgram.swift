import Cpcap
import Foundation

/// A compiled BPF filter program that can be evaluated against packets in
/// userspace — no live device or elevated privileges required.
///
/// The expression is compiled against a throwaway "dead" handle
/// (`pcap_open_dead`) for a given link type, after which the compiled program is
/// self-contained. Matching uses `pcap_offline_filter`, which runs the BPF
/// bytecode over a packet without touching the kernel. This is the building
/// block for filtering already-captured packets (from a file, memory, or a
/// live stream) after the fact.
///
/// For filtering *at the source* (in the kernel, before packets reach your
/// process), use ``LiveCapture/setFilter(_:)`` or ``PcapFileReader/setFilter(_:)``
/// instead, which is more efficient for live capture.
///
/// The compiled program is immutable after initialization and
/// `pcap_offline_filter` only reads it, so evaluating one program from multiple
/// threads concurrently is safe.
public final class BPFProgram: @unchecked Sendable {
    private var program = bpf_program()

    /// The link type the filter was compiled for.
    public let linkType: LinkType

    /// The original filter expression.
    public let expression: String

    /// Compiles `expression` for `linkType`.
    /// - Throws: ``PcapError`` if the expression cannot be compiled.
    public init(
        _ expression: String,
        linkType: LinkType = .ethernet,
        snapshotLength: Int32 = 262_144,
        optimize: Bool = true
    ) throws {
        self.linkType = linkType
        self.expression = expression

        guard let dead = pcap_open_dead(linkType.rawValue, snapshotLength) else {
            throw PcapError(message: "pcap_open_dead failed for link type \(linkType.rawValue)")
        }
        defer { pcap_close(dead) }

        let status = expression.withCString { cString in
            pcap_compile(dead, &program, cString, optimize ? 1 : 0, 0xFFFF_FFFF)
        }
        guard status == 0 else {
            let text = pcap_geterr(dead).map { String(cString: $0) } ?? "filter compile error"
            throw PcapError(message: "failed to compile filter \"\(expression)\": \(text)", code: status)
        }
    }

    deinit {
        pcap_freecode(&program)
    }

    /// Returns whether `packet` matches the filter.
    public func matches(_ packet: CapturedPacket) -> Bool {
        matches(packet.data, originalLength: packet.info.originalLength)
    }

    /// Returns whether `data` (a packet of `originalLength` bytes on the wire)
    /// matches the filter.
    public func matches(_ data: Data, originalLength: Int? = nil) -> Bool {
        var header = pcap_pkthdr()
        header.caplen = UInt32(data.count)
        header.len = UInt32(originalLength ?? data.count)

        // Borrow a local (shallow) copy so evaluation never needs exclusive
        // access to `self.program`; the compiled instructions are shared and are
        // only freed once, in deinit.
        let compiled = program

        return withUnsafePointer(to: compiled) { (programPtr: UnsafePointer<bpf_program>) -> Bool in
            withUnsafePointer(to: header) { (headerPtr: UnsafePointer<pcap_pkthdr>) -> Bool in
                data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
                    let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    return pcap_offline_filter(programPtr, headerPtr, base) != 0
                }
            }
        }
    }
}
