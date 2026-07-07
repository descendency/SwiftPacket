import Cpcap

/// Library-wide metadata and namespace.
public enum SwiftPacket {

    /// The semantic version of this Swift package.
    public static let version = "0.1.0"

    /// The version string reported by the underlying libpcap, e.g.
    /// `"libpcap version 1.10.4"`.
    ///
    /// Returns `"unknown"` if libpcap reports no version (it never should on
    /// macOS, but we handle the null pointer rather than force-unwrapping —
    /// a habit this library keeps everywhere it touches C).
    public static var libpcapVersion: String {
        guard let cString = pcap_lib_version() else { return "unknown" }
        return String(cString: cString)
    }
}
