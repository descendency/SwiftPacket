import Foundation

/// Reusable, typed storage for a decoded packet's layers — the destination for
/// ``StackDecoder``.
///
/// Unlike ``Packet`` (which holds a freshly allocated `[any Layer]` per
/// packet), a `DecodedStack` is meant to be created once and refilled for each
/// packet with ``reset()``, so a tight decode loop makes no per-packet
/// allocation for the common Ethernet/IP/transport stack. The hot layers land
/// in concrete optional slots; anything without a fast slot is decoded through
/// the registry and collected in ``overflow`` (the boxed slow path).
public struct DecodedStack {
    public var ethernet: Ethernet?
    public var loopback: Loopback?
    public var ipv4: IPv4?
    public var ipv6: IPv6?
    public var arp: ARP?
    public var tcp: TCP?
    public var udp: UDP?
    public var icmpv4: ICMPv4?
    public var icmpv6: ICMPv6?
    /// The trailing opaque payload, if the packet ended in undecoded bytes.
    public var payload: Payload?
    /// A decode failure, if one stopped the chain.
    public var decodeFailure: DecodeFailure?
    /// Layers decoded via the registry fallback (any type without a fast slot),
    /// in order — the only part of a decode that boxes.
    public var overflow: [any Layer] = []
    /// The layer types decoded, outermost first. The backing array's capacity
    /// is reused across ``reset()`` calls.
    public private(set) var layerTypes: [LayerType] = []

    public init() {}

    /// Clears every slot for reuse, keeping array capacity.
    public mutating func reset() {
        ethernet = nil
        loopback = nil
        ipv4 = nil
        ipv6 = nil
        arp = nil
        tcp = nil
        udp = nil
        icmpv4 = nil
        icmpv6 = nil
        payload = nil
        decodeFailure = nil
        overflow.removeAll(keepingCapacity: true)
        layerTypes.removeAll(keepingCapacity: true)
    }

    mutating func record(_ type: LayerType) {
        layerTypes.append(type)
    }

    /// A compact one-line summary, e.g. `"Ethernet | IPv4 | TCP"`.
    public var summary: String {
        layerTypes.map(\.name).joined(separator: " | ")
    }

    /// Whether a layer of the given type was decoded.
    public func contains(_ type: LayerType) -> Bool {
        layerTypes.contains(type)
    }

    /// The IP protocol number from whichever IP layer is present.
    public var ipProtocol: IPProtocol? {
        ipv4?.proto ?? ipv6?.nextHeader
    }

    // MARK: - Flows (parity with `Packet`, without re-boxing)

    /// The link-layer flow (source → destination MAC), if an Ethernet layer
    /// was decoded.
    public var linkFlow: Flow? {
        guard let ethernet else { return nil }
        return Flow(source: Endpoint(ethernet.source), destination: Endpoint(ethernet.destination))
    }

    /// The network-layer flow (source → destination IP).
    public var networkFlow: Flow? {
        if let ipv4 {
            return Flow(source: Endpoint(ipv4.sourceAddress), destination: Endpoint(ipv4.destinationAddress))
        }
        if let ipv6 {
            return Flow(source: Endpoint(ipv6.sourceAddress), destination: Endpoint(ipv6.destinationAddress))
        }
        return nil
    }

    /// The transport-layer flow (source → destination port), for TCP or UDP.
    public var transportFlow: Flow? {
        if let tcp {
            return Flow(source: Endpoint(port: tcp.sourcePort), destination: Endpoint(port: tcp.destinationPort))
        }
        if let udp {
            return Flow(source: Endpoint(port: udp.sourcePort), destination: Endpoint(port: udp.destinationPort))
        }
        return nil
    }

    /// A canonical bidirectional connection key, or `nil` without a network
    /// layer.
    public var connectionKey: ConnectionKey? {
        guard let networkFlow else { return nil }
        return ConnectionKey(network: networkFlow, transport: transportFlow)
    }

    /// Whether the TCP/UDP checksum is correct, pairing the decoded transport
    /// with its IP addresses; `nil` if there is no checksummed transport over a
    /// recognized IP layer.
    public var isTransportChecksumValid: Bool? {
        if let ipv4 {
            if let tcp { return tcp.isChecksumValid(source: ipv4.sourceAddress, destination: ipv4.destinationAddress) }
            if let udp { return udp.isChecksumValid(source: ipv4.sourceAddress, destination: ipv4.destinationAddress) }
        }
        if let ipv6 {
            if let tcp { return tcp.isChecksumValid(source: ipv6.sourceAddress, destination: ipv6.destinationAddress) }
            if let udp { return udp.isChecksumValid(source: ipv6.sourceAddress, destination: ipv6.destinationAddress) }
        }
        return nil
    }

    /// Whether the IPv4 header checksum is correct, or `nil` without an IPv4
    /// layer.
    public var isNetworkChecksumValid: Bool? { ipv4?.isChecksumValid }
}

/// A low-allocation decoder for the common protocol stack.
///
/// `StackDecoder` is the counterpart to GoPacket's `DecodingLayerParser`: it
/// decodes the hot layers (Ethernet, loopback, IPv4/IPv6, ARP, TCP, UDP,
/// ICMPv4/v6) into concrete value slots on a reusable ``DecodedStack``, with
/// no `any Layer` boxing and no per-packet array allocation. Layers outside
/// that set fall back to the registry and are collected (boxed) in
/// ``DecodedStack/overflow``, so correctness never depends on a layer being
/// "fast".
///
/// ```swift
/// let decoder = StackDecoder()
/// var stack = DecodedStack()
/// for try await captured in reader.packets() {
///     decoder.decode(captured, into: &stack)
///     if let tcp = stack.tcp { count(tcp.destinationPort) }
/// }
/// ```
///
/// For one-off decoding, ``Packet/decode(_:startingAt:using:layerLimit:)``
/// remains the simplest choice; reach for `StackDecoder` in throughput-bound
/// loops.
public struct StackDecoder: Sendable {
    private let registry: DecoderRegistry
    private let layerLimit: Int

    public init(registry: DecoderRegistry = .standard, layerLimit: Int = 32) {
        self.registry = registry
        self.layerLimit = layerLimit
    }

    /// Decodes `captured` into `stack`, choosing the starting layer from the
    /// packet's link type (falling back to raw payload if unmapped).
    public func decode(_ captured: CapturedPacket, into stack: inout DecodedStack) {
        stack.reset()
        guard let first = registry.initialLayerType(for: captured.linkType) else {
            if !captured.data.isEmpty {
                stack.payload = Payload(captured.data)
                stack.record(.payload)
            }
            return
        }
        decode(captured.data, startingAt: first, into: &stack)
    }

    /// Decodes `data` starting from `first` into `stack`. Clears `stack` first.
    public func decode(_ data: Data, startingAt first: LayerType, into stack: inout DecodedStack) {
        stack.reset()
        var type = first
        var current = data
        var produced = 0

        while produced < layerLimit {
            let next: NextDecode
            do {
                next = try step(type, current, into: &stack)
            } catch {
                let failure = DecodeFailure(unconsumed: current, reason: String(describing: error))
                stack.decodeFailure = failure
                stack.record(.decodeFailure)
                return
            }
            produced += 1

            switch next {
            case .done:
                return
            case let .next(nextType, rest):
                if rest.isEmpty { return }
                type = nextType
                current = rest
            }
        }

        // Layer budget exhausted: keep the remainder as opaque bytes.
        if !current.isEmpty {
            stack.payload = Payload(current)
            stack.record(.payload)
        }
    }

    /// Decodes exactly one layer, writing it into the right slot and returning
    /// what to decode next. The fast cases avoid boxing; the default case uses
    /// the registry and boxes into `overflow`.
    private func step(_ type: LayerType, _ data: Data, into stack: inout DecodedStack) throws
        -> NextDecode
    {
        switch type.id {
        case LayerType.ethernet.id:
            let (layer, next) = try Ethernet.decodeValue(data)
            stack.ethernet = layer
            stack.record(.ethernet)
            return next
        case LayerType.ipv4.id:
            let (layer, next) = try IPv4.decodeValue(data)
            stack.ipv4 = layer
            stack.record(.ipv4)
            return next
        case LayerType.ipv6.id:
            let (layer, next) = try IPv6.decodeValue(data)
            stack.ipv6 = layer
            stack.record(.ipv6)
            return next
        case LayerType.tcp.id:
            let (layer, next) = try TCP.decodeValue(data)
            stack.tcp = layer
            stack.record(.tcp)
            return next
        case LayerType.udp.id:
            let (layer, next) = try UDP.decodeValue(data)
            stack.udp = layer
            stack.record(.udp)
            return next
        case LayerType.payload.id:
            stack.payload = Payload(data)
            stack.record(.payload)
            return .done
        default:
            // Slow path: decode through the registry and box the result.
            guard let decoder = registry.decoder(for: type) else {
                stack.payload = Payload(data)
                stack.record(.payload)
                return .done
            }
            let result = try decoder.decode(data)
            place(result.layer, type: type, into: &stack)
            return result.next
        }
    }

    /// Routes a boxed fallback layer into a typed slot when we recognize it,
    /// otherwise into `overflow`.
    private func place(_ layer: any Layer, type: LayerType, into stack: inout DecodedStack) {
        switch layer {
        // The IP transports can arrive here — not just via the fast switch —
        // when a fallback decoder yields them: `.rawIP` (a defragmented,
        // link-type `.raw` packet) decodes straight to IPv4/IPv6, and tunnels
        // hand back an inner IP layer. Route them to their typed slots so
        // consumers don't have to dig through `overflow`.
        case let value as IPv4: stack.ipv4 = value
        case let value as IPv6: stack.ipv6 = value
        case let value as TCP: stack.tcp = value
        case let value as UDP: stack.udp = value
        case let value as Loopback: stack.loopback = value
        case let value as ARP: stack.arp = value
        case let value as ICMPv4: stack.icmpv4 = value
        case let value as ICMPv6: stack.icmpv6 = value
        case let value as Payload: stack.payload = value
        case let value as DecodeFailure: stack.decodeFailure = value
        default: stack.overflow.append(layer)
        }
        // Record the concrete layer's type, not the requested one — e.g. a
        // `.rawIP` decode is really an IPv4/IPv6 layer, matching `Packet.decode`.
        stack.record(layer.layerType)
    }
}
