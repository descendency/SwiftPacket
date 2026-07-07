import Foundation

/// The broad role a layer plays in a packet, used for semantic accessors like
/// ``Packet/networkLayer`` and ``Packet/transportLayer``.
public enum LayerCategory: Sendable, Hashable {
    case link
    case network
    case transport
    case application
    case metadata
    case payload
    case failure
}

/// Identifies a kind of layer (Ethernet, IPv4, TCP, …).
///
/// Identity is the ``id`` alone; ``name`` and ``category`` are metadata. Modeled
/// as a struct rather than an enum so that new protocols — including ones
/// defined outside this package — can mint their own layer types without
/// modifying a central enum.
public struct LayerType: Sendable, Hashable, CustomStringConvertible {
    public let id: Int
    public let name: String
    public let category: LayerCategory

    public init(id: Int, name: String, category: LayerCategory) {
        self.id = id
        self.name = name
        self.category = category
    }

    public static func == (lhs: LayerType, rhs: LayerType) -> Bool {
        lhs.id == rhs.id
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    public var description: String { name }
}

extension LayerType {
    /// Opaque, undecoded bytes — the terminal catch-all layer.
    public static let payload = LayerType(id: 0, name: "Payload", category: .payload)

    /// Bytes that could not be decoded because a decoder threw.
    public static let decodeFailure = LayerType(id: 1, name: "DecodeFailure", category: .failure)

    // Protocol layer types (Ethernet, IPv4, TCP, …) are added in Phase 3,
    // continuing the id numbering from 2 onward.
}
