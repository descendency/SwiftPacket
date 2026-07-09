import Foundation

// Verifying a checksum is the same one's-complement sum used to compute it:
// summing a header that already contains its correct checksum yields zero
// (RFC 1071). These accessors let a consumer flag corrupt IPv4 headers and
// TCP/UDP segments — the "bad checksum" weirds a monitor reports.

extension IPv4 {
    /// Whether the header checksum is correct.
    ///
    /// Self-contained: the IPv4 checksum covers only the header, so no
    /// pseudo-header (and thus no enclosing context) is needed.
    public var isChecksumValid: Bool {
        internetChecksum(layerContents) == 0
    }
}

extension TCP {
    /// Whether the segment checksum is correct, given the IPv4 addresses of the
    /// enclosing network layer (needed for the pseudo-header).
    public func isChecksumValid(source: IPv4Address, destination: IPv4Address) -> Bool {
        verifyChecksum(source: source.dataBytes, destination: destination.dataBytes, isIPv6: false)
    }

    /// Whether the segment checksum is correct, given the IPv6 addresses of the
    /// enclosing network layer.
    public func isChecksumValid(source: IPv6Address, destination: IPv6Address) -> Bool {
        verifyChecksum(source: source.dataBytes, destination: destination.dataBytes, isIPv6: true)
    }

    private func verifyChecksum(source: Data, destination: Data, isIPv6: Bool) -> Bool {
        var segment = layerContents
        segment.append(payload)
        let pseudo = PseudoHeaderSource(source: source, destination: destination, isIPv6: isIPv6)
        let buffer = pseudoHeaderBytes(pseudo, protocolNumber: 6, transportLength: segment.count)
            + segment
        return internetChecksum(buffer) == 0
    }
}

extension UDP {
    /// Whether the datagram checksum is correct, given the enclosing IPv4
    /// addresses.
    ///
    /// A zero checksum means "not computed" for UDP over IPv4 (RFC 768), so it
    /// is treated as valid. Over IPv6 the checksum is mandatory, so use the
    /// IPv6 overload, which does not special-case zero.
    public func isChecksumValid(source: IPv4Address, destination: IPv4Address) -> Bool {
        if checksum == 0 { return true }  // UDP/IPv4: 0 == "no checksum"
        return verifyChecksum(source: source.dataBytes, destination: destination.dataBytes, isIPv6: false)
    }

    /// Whether the datagram checksum is correct, given the enclosing IPv6
    /// addresses. The checksum is mandatory over IPv6.
    public func isChecksumValid(source: IPv6Address, destination: IPv6Address) -> Bool {
        verifyChecksum(source: source.dataBytes, destination: destination.dataBytes, isIPv6: true)
    }

    private func verifyChecksum(source: Data, destination: Data, isIPv6: Bool) -> Bool {
        var segment = layerContents
        segment.append(payload)
        let pseudo = PseudoHeaderSource(source: source, destination: destination, isIPv6: isIPv6)
        let buffer = pseudoHeaderBytes(pseudo, protocolNumber: 17, transportLength: segment.count)
            + segment
        return internetChecksum(buffer) == 0
    }
}

extension Packet {
    /// Whether the IPv4 header checksum is correct, or `nil` if the packet has
    /// no IPv4 layer.
    public var isNetworkChecksumValid: Bool? {
        layer(IPv4.self)?.isChecksumValid
    }

    /// Whether the TCP/UDP checksum is correct, pairing the transport layer with
    /// its enclosing IP addresses automatically; `nil` if the packet has no
    /// checksummed transport over a recognized IP layer.
    public var isTransportChecksumValid: Bool? {
        if let ipv4 = layer(IPv4.self) {
            if let tcp = layer(TCP.self) {
                return tcp.isChecksumValid(source: ipv4.sourceAddress, destination: ipv4.destinationAddress)
            }
            if let udp = layer(UDP.self) {
                return udp.isChecksumValid(source: ipv4.sourceAddress, destination: ipv4.destinationAddress)
            }
        }
        if let ipv6 = layer(IPv6.self) {
            if let tcp = layer(TCP.self) {
                return tcp.isChecksumValid(source: ipv6.sourceAddress, destination: ipv6.destinationAddress)
            }
            if let udp = layer(UDP.self) {
                return udp.isChecksumValid(source: ipv6.sourceAddress, destination: ipv6.destinationAddress)
            }
        }
        return nil
    }
}
