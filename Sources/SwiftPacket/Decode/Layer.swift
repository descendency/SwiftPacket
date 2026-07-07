import Foundation

/// A decoded protocol layer within a packet.
///
/// Mirrors GoPacket's split between a layer's own bytes (``layerContents``) and
/// the bytes it hands to the next decoder (``layerPayload``).
public protocol Layer: Sendable {
    /// The type of this layer.
    static var layerType: LayerType { get }

    /// The bytes that make up this layer (typically its header).
    var layerContents: Data { get }

    /// The bytes remaining after this layer, handed to the next decoder.
    var layerPayload: Data { get }
}

extension Layer {
    /// The type of this layer, as an instance property.
    public var layerType: LayerType { Self.layerType }
}

/// Opaque, undecoded bytes. The terminal layer appended when no decoder is
/// registered for the next layer type, or when a protocol's payload is not
/// itself decoded further.
public struct Payload: Layer {
    public static let layerType = LayerType.payload

    /// The undecoded bytes.
    public let bytes: Data

    public init(_ bytes: Data) {
        self.bytes = bytes
    }

    public var layerContents: Data { bytes }
    public var layerPayload: Data { Data() }
}

/// The bytes a decoder could not process, together with a description of why.
///
/// Recorded (rather than thrown) so that a partially decoded packet is still
/// returned in full: earlier layers remain accessible, and the failure is
/// available via ``Packet/decodeFailure``.
public struct DecodeFailure: Layer {
    public static let layerType = LayerType.decodeFailure

    /// The bytes that were left undecoded at the point of failure.
    public let unconsumed: Data

    /// A human-readable description of the decoding error.
    public let reason: String

    public init(unconsumed: Data, reason: String) {
        self.unconsumed = unconsumed
        self.reason = reason
    }

    public var layerContents: Data { unconsumed }
    public var layerPayload: Data { Data() }
}
