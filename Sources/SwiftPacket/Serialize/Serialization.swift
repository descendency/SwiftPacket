import Foundation

/// Controls automatic fix-ups during serialization.
public struct SerializeOptions: Sendable {
    /// Recompute length fields (IPv4 total length, UDP length, …) from the
    /// actual serialized payload.
    public var fixLengths: Bool
    /// Recompute checksums (IPv4 header, TCP/UDP over the pseudo-header).
    public var computeChecksums: Bool

    public init(fixLengths: Bool = true, computeChecksums: Bool = true) {
        self.fixLengths = fixLengths
        self.computeChecksums = computeChecksums
    }
}

/// A buffer that packets are serialized into, growing from the front.
///
/// Layers serialize inner-first; each prepends its header onto the payload that
/// inner layers have already written, so an outer layer can measure and check
/// what it wraps.
public struct SerializeBuffer {
    public private(set) var bytes: Data

    public init() {
        self.bytes = Data()
    }

    /// Prepends `prefix` to the front of the buffer.
    public mutating func prepend(_ prefix: Data) {
        var combined = Data()
        combined.append(prefix)
        combined.append(bytes)
        bytes = combined
    }

    /// Appends `suffix` to the end of the buffer.
    public mutating func append(_ suffix: Data) {
        bytes.append(suffix)
    }
}

/// Cross-layer information made available to each layer while serializing —
/// currently the network addresses needed for transport checksums.
public struct SerializationContext {
    let pseudoHeader: PseudoHeaderSource?

    /// An empty context (no network layer available for checksums).
    public init() {
        self.pseudoHeader = nil
    }

    /// Derives checksum context by finding the first IPv4/IPv6 layer in `layers`.
    public init(layers: [any SerializableLayer]) {
        var found: PseudoHeaderSource?
        for layer in layers {
            if let ip = layer as? IPv4 {
                found = PseudoHeaderSource(source: ip.sourceAddress.dataBytes, destination: ip.destinationAddress.dataBytes, isIPv6: false)
                break
            } else if let ip = layer as? IPv6 {
                found = PseudoHeaderSource(source: ip.sourceAddress.dataBytes, destination: ip.destinationAddress.dataBytes, isIPv6: true)
                break
            }
        }
        self.pseudoHeader = found
    }
}

/// A layer that can serialize itself into bytes.
public protocol SerializableLayer {
    /// Serializes this layer, prepending its bytes onto `buffer` (which already
    /// holds the serialized inner layers).
    func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws
}

/// Errors raised during serialization.
public enum SerializationError: Error, Sendable, Equatable {
    /// A transport checksum was requested but no enclosing IPv4/IPv6 layer was
    /// available to build the pseudo-header.
    case missingNetworkLayerForChecksum
    /// A layer in the packet does not conform to ``SerializableLayer``.
    case layerNotSerializable(LayerType)
}

/// Serializes `layers` (outermost first) into a single byte buffer.
public func serializeLayers(
    _ layers: [any SerializableLayer],
    options: SerializeOptions = SerializeOptions()
) throws -> Data {
    let context = SerializationContext(layers: layers)
    var buffer = SerializeBuffer()
    for layer in layers.reversed() {
        try layer.serialize(into: &buffer, context: context, options: options)
    }
    return buffer.bytes
}

extension Packet {
    /// Serializes this packet's layers back into bytes.
    ///
    /// Every layer must conform to ``SerializableLayer``; otherwise
    /// ``SerializationError/layerNotSerializable(_:)`` is thrown.
    public func serializedData(options: SerializeOptions = SerializeOptions()) throws -> Data {
        let serializable = try layers.map { layer -> any SerializableLayer in
            guard let s = layer as? any SerializableLayer else {
                throw SerializationError.layerNotSerializable(layer.layerType)
            }
            return s
        }
        return try serializeLayers(serializable, options: options)
    }
}
