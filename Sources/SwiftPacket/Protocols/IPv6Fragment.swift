import Foundation

/// An IPv6 fragment extension header (RFC 8200 §4.5, next-header 44).
///
/// A fragment header marks a packet as one piece of a larger datagram. Only
/// the first fragment (``fragmentOffset`` 0) begins a clean transport header,
/// so — like a non-initial IPv4 fragment — the payload here is delivered as
/// opaque bytes; reassemble with ``IPDefragmenter`` to recover the transport.
public struct IPv6Fragment: Layer {
    public static let layerType = LayerType.ipv6Fragment

    /// The protocol of the fragmented payload (the datagram's real transport).
    public let nextHeader: IPProtocol
    /// Fragment offset in 8-byte units.
    public let fragmentOffset: UInt16
    /// Whether more fragments follow this one.
    public let moreFragments: Bool
    /// The datagram identification shared by every fragment.
    public let identification: UInt32
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }

    /// Whether this is the first fragment of its datagram.
    public var isFirstFragment: Bool { fragmentOffset == 0 }
}

/// Decodes the fixed 8-byte IPv6 fragment header.
public struct IPv6FragmentDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let nextHeader = IPProtocol(rawValue: try reader.readUInt8())
        try reader.skip(1)  // reserved
        let offsetAndFlags = try reader.readUInt16()
        let identification = try reader.readUInt32()

        let payload = reader.readRemaining()
        let layer = IPv6Fragment(
            nextHeader: nextHeader,
            fragmentOffset: offsetAndFlags >> 3,
            moreFragments: offsetAndFlags & 0x0001 != 0,
            identification: identification,
            payload: payload,
            header: data.prefix(8)
        )

        // The first fragment's payload starts a real transport header, but it
        // is incomplete until reassembly, so it is not chained here.
        return DecodeResult(
            layer: layer, next: payload.isEmpty ? .done : .next(.payload, payload))
    }
}
