import Foundation

/// A decoded packet: the original bytes plus the ordered layers extracted from
/// them.
///
/// Decoding never throws — a decoder error becomes a trailing ``DecodeFailure``
/// layer and unrecognized bytes become a trailing ``Payload`` — so a `Packet`
/// always represents as much of the input as could be understood.
public struct Packet: Sendable {
    /// The full original bytes the packet was decoded from.
    public let data: Data

    /// The decoded layers, outermost first (link → network → transport → …).
    public let layers: [any Layer]

    public init(data: Data, layers: [any Layer]) {
        self.data = data
        self.layers = layers
    }

    // MARK: - Accessors

    /// The first layer of the given concrete type, if present.
    public func layer<L: Layer>(_ type: L.Type) -> L? {
        for layer in layers {
            if let match = layer as? L { return match }
        }
        return nil
    }

    /// Whether a layer of the given type is present.
    public func contains(_ type: LayerType) -> Bool {
        layers.contains { $0.layerType == type }
    }

    /// The first layer belonging to the given category.
    public func firstLayer(in category: LayerCategory) -> (any Layer)? {
        layers.first { $0.layerType.category == category }
    }

    /// The link-layer layer (Ethernet, loopback, …), if any.
    public var linkLayer: (any Layer)? { firstLayer(in: .link) }
    /// The network-layer layer (IPv4, IPv6, ARP, …), if any.
    public var networkLayer: (any Layer)? { firstLayer(in: .network) }
    /// The transport-layer layer (TCP, UDP, ICMP, …), if any.
    public var transportLayer: (any Layer)? { firstLayer(in: .transport) }
    /// The application-layer layer (DNS, …), if any.
    public var applicationLayer: (any Layer)? { firstLayer(in: .application) }

    /// The trailing opaque payload, if the packet ended in undecoded bytes.
    public var payload: Payload? { layer(Payload.self) }

    /// The decode failure, if decoding stopped on an error.
    public var decodeFailure: DecodeFailure? { layer(DecodeFailure.self) }

    /// A compact one-line summary, e.g. `"Ethernet | IPv4 | TCP | Payload"`.
    public var summary: String {
        layers.map { $0.layerType.name }.joined(separator: " | ")
    }
}

extension Packet {
    /// Decodes `data`, beginning by treating it as `first` and following the
    /// chain of decoders in `registry`.
    ///
    /// - Parameter layerLimit: An upper bound on decoded layers, guarding
    ///   against a misbehaving decoder that never consumes bytes. On reaching
    ///   the limit, remaining bytes become a ``Payload``.
    public static func decode(
        _ data: Data,
        startingAt first: LayerType,
        using registry: DecoderRegistry,
        layerLimit: Int = 32
    ) -> Packet {
        var layers: [any Layer] = []
        var iterator = LayerIterator(data: data, first: first, registry: registry, limit: layerLimit)
        while let layer = iterator.next() {
            layers.append(layer)
        }
        return Packet(data: data, layers: layers)
    }
}

extension CapturedPacket {
    /// Decodes this captured packet into layered form using `registry`.
    ///
    /// The starting layer type is chosen from the packet's ``CapturedPacket/linkType``.
    /// If the registry has no mapping for that link type, the whole packet is
    /// returned as a single opaque ``Payload``.
    public func decoded(using registry: DecoderRegistry) -> Packet {
        if let first = registry.initialLayerType(for: linkType) {
            return Packet.decode(data, startingAt: first, using: registry)
        }
        return Packet(data: data, layers: data.isEmpty ? [] : [Payload(data)])
    }
}
