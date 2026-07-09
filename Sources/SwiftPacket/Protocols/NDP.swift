import Foundation

// Neighbor Discovery (RFC 4861) and Multicast Listener Discovery
// (RFC 2710 / RFC 3810) ride inside ICMPv6. Rather than mint a layer per
// message type, these are exposed as structured accessors on ``ICMPv6`` —
// matching how ``ICMPv4`` surfaces echo and quoted-packet detail.

/// One Neighbor Discovery option (RFC 4861 §4.6): a type/length-prefixed TLV
/// whose length counts 8-byte units, including the 2-byte header.
public struct NDPOption: Sendable, Hashable {
    public let type: UInt8
    /// The option value (the bytes after the 2-byte type/length header).
    public let value: Data

    /// Source (type 1) or target (type 2) link-layer address, when this option
    /// carries one of Ethernet size.
    public var linkLayerAddress: MACAddress? {
        guard type == 1 || type == 2 else { return nil }
        return MACAddress(value.prefix(6))
    }

    /// The MTU value, for an MTU option (type 5).
    public var mtu: UInt32? {
        guard type == 5, value.count >= 6 else { return nil }
        var reader = ByteReader(value.dropFirst(2))  // skip the 2 reserved bytes
        return try? reader.readUInt32()
    }

    /// The decoded prefix information, for a prefix-information option (type 3).
    public var prefixInformation: NDPPrefixInformation? {
        guard type == 3 else { return nil }
        return NDPPrefixInformation(value)
    }
}

/// The prefix-information option of a Router Advertisement (RFC 4861 §4.6.2).
public struct NDPPrefixInformation: Sendable, Hashable {
    public let prefixLength: UInt8
    public let onLink: Bool
    public let autonomous: Bool
    public let validLifetime: UInt32
    public let preferredLifetime: UInt32
    public let prefix: IPv6Address

    init?(_ value: Data) {
        var reader = ByteReader(value)
        guard let prefixLength = try? reader.readUInt8(),
            let flags = try? reader.readUInt8(),
            let valid = try? reader.readUInt32(),
            let preferred = try? reader.readUInt32(),
            (try? reader.skip(4)) != nil,  // reserved2
            let prefix = try? reader.readIPv6Address()
        else { return nil }
        self.prefixLength = prefixLength
        self.onLink = flags & 0x80 != 0
        self.autonomous = flags & 0x40 != 0
        self.validLifetime = valid
        self.preferredLifetime = preferred
        self.prefix = prefix
    }
}

/// A Router Advertisement (ICMPv6 type 134).
public struct NDPRouterAdvertisement: Sendable {
    public let hopLimit: UInt8
    public let managedAddressConfig: Bool
    public let otherConfig: Bool
    public let routerLifetime: UInt16
    public let reachableTime: UInt32
    public let retransTimer: UInt32
    public let options: [NDPOption]

    /// The advertised on-link/autoconf prefixes.
    public var prefixes: [NDPPrefixInformation] {
        options.compactMap(\.prefixInformation)
    }
    /// The advertised link MTU, if an MTU option is present.
    public var mtu: UInt32? { options.compactMap(\.mtu).first }
    /// The router's link-layer (MAC) address, if advertised.
    public var sourceLinkLayerAddress: MACAddress? {
        options.first { $0.type == 1 }?.linkLayerAddress
    }
}

/// A Neighbor Solicitation (type 135) or Advertisement (type 136).
public struct NDPNeighborMessage: Sendable {
    public let isAdvertisement: Bool
    /// Advertisement flags (meaningless for solicitations).
    public let router: Bool
    public let solicited: Bool
    public let override: Bool
    /// The target address being resolved or advertised.
    public let targetAddress: IPv6Address
    public let options: [NDPOption]

    /// The target's link-layer address (target option for advertisements,
    /// source option for solicitations), if present.
    public var linkLayerAddress: MACAddress? {
        let wanted: UInt8 = isAdvertisement ? 2 : 1
        return options.first { $0.type == wanted }?.linkLayerAddress
    }
}

extension ICMPv6 {
    /// Whether this is a Neighbor Discovery message (types 133–137).
    public var isNeighborDiscovery: Bool { (133...137).contains(type) }

    /// The Neighbor Discovery options carried after the message's fixed fields,
    /// for any NDP message type.
    public var ndpOptions: [NDPOption] {
        guard isNeighborDiscovery else { return [] }
        // The fixed body length before options differs per type.
        let fixed: Int
        switch type {
        case 133: fixed = 4  // Router Solicitation: reserved
        case 134: fixed = 12  // Router Advertisement
        case 135: fixed = 20  // Neighbor Solicitation: reserved + target
        case 136: fixed = 20  // Neighbor Advertisement: flags + target
        case 137: fixed = 36  // Redirect: reserved + target + destination
        default: return []
        }
        guard payload.count > fixed else { return [] }
        return Self.parseNDPOptions(payload.dropFirst(fixed))
    }

    /// The decoded Router Advertisement, if this is one (type 134).
    public var routerAdvertisement: NDPRouterAdvertisement? {
        guard type == 134 else { return nil }
        var reader = ByteReader(payload)
        guard let hopLimit = try? reader.readUInt8(),
            let flags = try? reader.readUInt8(),
            let lifetime = try? reader.readUInt16(),
            let reachable = try? reader.readUInt32(),
            let retrans = try? reader.readUInt32()
        else { return nil }
        return NDPRouterAdvertisement(
            hopLimit: hopLimit,
            managedAddressConfig: flags & 0x80 != 0,
            otherConfig: flags & 0x40 != 0,
            routerLifetime: lifetime,
            reachableTime: reachable,
            retransTimer: retrans,
            options: ndpOptions)
    }

    /// The decoded Neighbor Solicitation, if this is one (type 135).
    public var neighborSolicitation: NDPNeighborMessage? {
        neighborMessage(advertisement: false, type: 135)
    }

    /// The decoded Neighbor Advertisement, if this is one (type 136).
    public var neighborAdvertisement: NDPNeighborMessage? {
        neighborMessage(advertisement: true, type: 136)
    }

    private func neighborMessage(advertisement: Bool, type expected: UInt8) -> NDPNeighborMessage? {
        guard type == expected else { return nil }
        var reader = ByteReader(payload)
        guard let flags = try? reader.readUInt32(),
            let target = try? reader.readIPv6Address()
        else { return nil }
        return NDPNeighborMessage(
            isAdvertisement: advertisement,
            router: flags & 0x8000_0000 != 0,
            solicited: flags & 0x4000_0000 != 0,
            override: flags & 0x2000_0000 != 0,
            targetAddress: target,
            options: ndpOptions)
    }

    static func parseNDPOptions(_ data: Data) -> [NDPOption] {
        var options: [NDPOption] = []
        var reader = ByteReader(data)
        while reader.remaining >= 2 {
            guard let type = try? reader.readUInt8(), let units = try? reader.readUInt8(),
                units > 0
            else { break }
            let valueLength = Int(units) * 8 - 2
            guard let value = try? reader.readBytes(valueLength) else { break }
            options.append(NDPOption(type: type, value: value))
        }
        return options
    }
}

// MARK: - MLD

/// A Multicast Listener Discovery query (MLDv1 RFC 2710 / MLDv2 RFC 3810),
/// carried as ICMPv6 type 130.
public struct MLDQuery: Sendable {
    /// The maximum response delay/code (milliseconds for v1).
    public let maximumResponseCode: UInt16
    /// The multicast group being queried, or the all-zeros address for a
    /// general query.
    public let multicastAddress: IPv6Address
    /// MLDv2 source addresses (empty for MLDv1 and for v2 general/group queries).
    public let sourceAddresses: [IPv6Address]
    /// Whether the message used the longer MLDv2 query format.
    public let isVersion2: Bool
}

/// One MLDv2 multicast-address record (RFC 3810 §5.2.).
public struct MLDv2Record: Sendable {
    public let recordType: UInt8
    public let multicastAddress: IPv6Address
    public let sourceAddresses: [IPv6Address]
}

extension ICMPv6 {
    /// The MLD query, if this is one (type 130). Distinguishes MLDv1 (24-byte
    /// body) from MLDv2 (≥28 bytes, with a source list) by length.
    public var mldQuery: MLDQuery? {
        guard type == 130 else { return nil }
        var reader = ByteReader(payload)
        guard let responseCode = try? reader.readUInt16(),
            (try? reader.skip(2)) != nil,  // reserved
            let multicast = try? reader.readIPv6Address()
        else { return nil }

        var sources: [IPv6Address] = []
        var isV2 = false
        // MLDv2 appends: flags(1), QQIC(1), number of sources(2), sources…
        if reader.remaining >= 4 {
            isV2 = true
            _ = try? reader.skip(2)  // flags + QQIC
            if let count = try? reader.readUInt16() {
                for _ in 0..<min(Int(count), 512) {
                    guard let source = try? reader.readIPv6Address() else { break }
                    sources.append(source)
                }
            }
        }
        return MLDQuery(
            maximumResponseCode: responseCode, multicastAddress: multicast,
            sourceAddresses: sources, isVersion2: isV2)
    }

    /// The multicast group of an MLDv1 report (131) or done (132) message.
    public var mldv1MulticastAddress: IPv6Address? {
        guard type == 131 || type == 132 else { return nil }
        var reader = ByteReader(payload)
        guard (try? reader.skip(4)) != nil else { return nil }  // max resp delay + reserved
        return try? reader.readIPv6Address()
    }

    /// The records of an MLDv2 report (type 143).
    public var mldv2Records: [MLDv2Record]? {
        guard type == 143 else { return nil }
        var reader = ByteReader(payload)
        guard (try? reader.skip(2)) != nil,  // reserved
            let recordCount = try? reader.readUInt16()
        else { return nil }

        var records: [MLDv2Record] = []
        for _ in 0..<min(Int(recordCount), 512) {
            guard let recordType = try? reader.readUInt8(),
                let auxLength = try? reader.readUInt8(),
                let sourceCount = try? reader.readUInt16(),
                let multicast = try? reader.readIPv6Address()
            else { break }
            var sources: [IPv6Address] = []
            for _ in 0..<min(Int(sourceCount), 512) {
                guard let source = try? reader.readIPv6Address() else { break }
                sources.append(source)
            }
            _ = try? reader.skip(Int(auxLength) * 4)
            records.append(
                MLDv2Record(
                    recordType: recordType, multicastAddress: multicast, sourceAddresses: sources))
        }
        return records
    }
}
