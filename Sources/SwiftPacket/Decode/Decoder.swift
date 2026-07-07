import Foundation

/// What to decode after a layer: either nothing more, or another layer type
/// applied to the remaining bytes.
public enum NextDecode: Sendable {
    /// This layer is terminal; decoding stops.
    case done
    /// Decode `bytes` as `type` next.
    case next(LayerType, Data)
}

/// The product of decoding one layer: the layer itself, and what comes next.
public struct DecodeResult: Sendable {
    public let layer: any Layer
    public let next: NextDecode

    public init(layer: any Layer, next: NextDecode) {
        self.layer = layer
        self.next = next
    }
}

/// Decodes one layer from a byte buffer.
///
/// A decoder handles exactly its own layer and, via ``DecodeResult/next``,
/// names the layer type of whatever follows. The packet driver
/// (``Packet/decode(_:startingAt:using:layerLimit:)``) chains decoders together;
/// individual decoders never recurse.
public protocol LayerDecoder: Sendable {
    func decode(_ data: Data) throws -> DecodeResult
}

/// Maps layer types to their decoders, and link types to the first layer type
/// to decode.
///
/// A value type with no global mutable state: build one, register decoders,
/// pass it to decoding. Phase 3 will ship a populated ``standard`` registry.
public struct DecoderRegistry: Sendable {
    private var decoders: [LayerType: any LayerDecoder]
    private var linkMapping: [LinkType: LayerType]

    public init() {
        self.decoders = [:]
        self.linkMapping = [:]
    }

    /// Registers `decoder` as the handler for `type`.
    public mutating func register(_ type: LayerType, decoder: any LayerDecoder) {
        decoders[type] = decoder
    }

    /// Declares that captures with link type `link` begin decoding as `type`.
    public mutating func mapLink(_ link: LinkType, to type: LayerType) {
        linkMapping[link] = type
    }

    /// The decoder for `type`, if one is registered.
    public func decoder(for type: LayerType) -> (any LayerDecoder)? {
        decoders[type]
    }

    /// The first layer type to decode for `link`, if a mapping exists.
    public func initialLayerType(for link: LinkType) -> LayerType? {
        linkMapping[link]
    }

    /// An empty registry that decodes everything as opaque ``Payload``.
    public static let empty = DecoderRegistry()
}
