import Foundation

/// Computes the 16-bit one's-complement Internet checksum (RFC 1071) over
/// `data`.
///
/// Computing the checksum over a buffer that already contains its correct
/// checksum yields `0`, which is the basis for verification.
public func internetChecksum(_ data: Data) -> UInt16 {
    var sum: UInt32 = 0
    var index = data.startIndex
    let end = data.endIndex

    while index + 1 < end {
        sum &+= UInt32(data[index]) << 8 | UInt32(data[index + 1])
        index += 2
    }
    if index < end {  // trailing odd byte, padded with zero
        sum &+= UInt32(data[index]) << 8
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) &+ (sum >> 16)
    }
    return ~UInt16(truncatingIfNeeded: sum)
}

/// The source and destination addresses of the enclosing network layer, used to
/// build a transport-layer pseudo-header for TCP/UDP checksums.
struct PseudoHeaderSource {
    let source: Data
    let destination: Data
    let isIPv6: Bool
}

/// Builds the transport-checksum pseudo-header (12 bytes for IPv4, 40 for IPv6).
func pseudoHeaderBytes(
    _ source: PseudoHeaderSource,
    protocolNumber: UInt8,
    transportLength: Int
) -> Data {
    var writer = ByteWriter()
    writer.writeBytes(source.source)
    writer.writeBytes(source.destination)
    if source.isIPv6 {
        writer.writeUInt32(UInt32(transportLength))
        writer.writeUInt8(0)
        writer.writeUInt8(0)
        writer.writeUInt8(0)
        writer.writeUInt8(protocolNumber)
    } else {
        writer.writeUInt8(0)
        writer.writeUInt8(protocolNumber)
        writer.writeUInt16(UInt16(transportLength & 0xFFFF))
    }
    return writer.data
}

/// Computes a transport checksum over the pseudo-header plus `segment` (the
/// transport header — with its checksum field zeroed — followed by the payload).
func transportChecksum(
    pseudo: PseudoHeaderSource,
    protocolNumber: UInt8,
    transportLength: Int,
    segment: Data
) -> UInt16 {
    var buffer = pseudoHeaderBytes(pseudo, protocolNumber: protocolNumber, transportLength: transportLength)
    buffer.append(segment)
    return internetChecksum(buffer)
}
