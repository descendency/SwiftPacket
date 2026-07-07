import Foundation

/// An error raised while decoding packet bytes.
///
/// Decoders throw these instead of trapping, so malformed or truncated input is
/// always recoverable: the packet decoder catches the error and records a
/// ``DecodeFailure`` layer rather than crashing.
public enum DecodingError: Error, Sendable, Equatable, CustomStringConvertible {
    /// A read asked for more bytes than remain.
    case insufficientBytes(needed: Int, available: Int)
    /// A length or count was negative or otherwise nonsensical.
    case invalidLength(Int)
    /// A field held a value outside its permitted range.
    case invalidValue(field: String, value: UInt64)
    /// A structural constraint of the protocol was violated.
    case malformed(String)

    public var description: String {
        switch self {
        case let .insufficientBytes(needed, available):
            return "insufficient bytes: needed \(needed), \(available) available"
        case let .invalidLength(length):
            return "invalid length: \(length)"
        case let .invalidValue(field, value):
            return "invalid value \(value) for field \(field)"
        case let .malformed(reason):
            return "malformed: \(reason)"
        }
    }
}
