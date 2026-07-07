import Foundation

/// Walks a packet's decode chain one layer at a time.
///
/// This is the lazy primitive underneath decoding: each `next()` decodes exactly
/// one more layer. A consumer that stops early — for example `first(where:)`
/// looking for the transport layer — never pays to decode the layers beyond it.
/// The eager ``Packet/decode(_:startingAt:using:layerLimit:)`` is simply this
/// iterator run to exhaustion.
public struct LayerIterator: IteratorProtocol {
    private let registry: DecoderRegistry
    private let limit: Int
    private var currentType: LayerType?
    private var currentData: Data
    private var produced: Int = 0
    private var finished: Bool = false

    init(data: Data, first: LayerType, registry: DecoderRegistry, limit: Int) {
        self.registry = registry
        self.limit = limit
        self.currentType = first
        self.currentData = data
    }

    public mutating func next() -> (any Layer)? {
        if finished { return nil }
        guard let type = currentType else {
            finished = true
            return nil
        }

        // Layer budget exhausted: hand back the remainder as opaque bytes.
        if produced >= limit {
            finished = true
            return currentData.isEmpty ? nil : Payload(currentData)
        }

        // No decoder for this layer type: the rest is an opaque payload.
        guard let decoder = registry.decoder(for: type) else {
            finished = true
            return currentData.isEmpty ? nil : Payload(currentData)
        }

        do {
            let result = try decoder.decode(currentData)
            produced += 1
            switch result.next {
            case .done:
                finished = true
            case let .next(nextType, rest):
                if rest.isEmpty {
                    finished = true
                } else {
                    currentType = nextType
                    currentData = rest
                }
            }
            return result.layer
        } catch {
            finished = true
            return DecodeFailure(unconsumed: currentData, reason: String(describing: error))
        }
    }
}

/// A lazily-decoded sequence of a packet's layers.
public struct LayerSequence: Sequence {
    let data: Data
    let first: LayerType
    let registry: DecoderRegistry
    let limit: Int

    public func makeIterator() -> LayerIterator {
        LayerIterator(data: data, first: first, registry: registry, limit: limit)
    }
}

extension CapturedPacket {
    /// A lazily-decoded view of this packet's layers.
    ///
    /// Decoding advances only as the sequence is iterated, so a consumer that
    /// stops early does not decode deeper layers. If the registry has no mapping
    /// for this packet's link type, the sequence yields a single opaque
    /// ``Payload``.
    public func lazyLayers(using registry: DecoderRegistry, layerLimit: Int = 32) -> LayerSequence {
        let first = registry.initialLayerType(for: linkType) ?? .payload
        return LayerSequence(data: data, first: first, registry: registry, limit: layerLimit)
    }

    /// Lazily finds the first layer of type `L`, decoding only as far as needed.
    public func firstLayer<L: Layer>(
        _ type: L.Type,
        using registry: DecoderRegistry,
        layerLimit: Int = 32
    ) -> L? {
        for layer in lazyLayers(using: registry, layerLimit: layerLimit) {
            if let match = layer as? L { return match }
        }
        return nil
    }
}
