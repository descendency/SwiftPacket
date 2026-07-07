import Cpcap

/// A link-layer (data-link) type, corresponding to libpcap's `DLT_*` "linktype"
/// values. It determines which link-layer decoder a packet begins with — the
/// hand-off point to Phase 2's decoding model.
///
/// Modeled as a `RawRepresentable` wrapper rather than a closed `enum` because
/// libpcap can report data-link types we don't have named constants for; an
/// unknown value round-trips cleanly instead of failing to construct.
public struct LinkType: RawRepresentable, Hashable, Sendable {
    public let rawValue: Int32

    public init(rawValue: Int32) {
        self.rawValue = rawValue
    }
}

extension LinkType {
    /// BSD loopback encapsulation (`DLT_NULL`).
    public static let null = LinkType(rawValue: Int32(DLT_NULL))
    /// IEEE 802.3 Ethernet (`DLT_EN10MB`).
    public static let ethernet = LinkType(rawValue: Int32(DLT_EN10MB))
    /// Raw IP with no link layer (`DLT_RAW`).
    public static let raw = LinkType(rawValue: Int32(DLT_RAW))
    /// OpenBSD loopback encapsulation (`DLT_LOOP`).
    public static let loop = LinkType(rawValue: Int32(DLT_LOOP))
    /// IEEE 802.11 wireless (`DLT_IEEE802_11`).
    public static let ieee80211 = LinkType(rawValue: Int32(DLT_IEEE802_11))
}

extension LinkType: CustomStringConvertible {
    /// The short libpcap name for this link type (e.g. `"EN10MB"`), or a
    /// `DLT(n)` placeholder when libpcap has no name for the value.
    public var description: String {
        guard let namePtr = pcap_datalink_val_to_name(rawValue) else {
            return "DLT(\(rawValue))"
        }
        return String(cString: namePtr)
    }
}
