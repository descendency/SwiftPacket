#if os(Linux)

    import CLinuxPacket
    import Cpcap
    import Dispatch
    import Foundation
    import Glibc

    /// Captures packets on Linux through a native `AF_PACKET` socket instead
    /// of libpcap.
    ///
    /// Packets are delivered through a memory-mapped `TPACKET_V3` RX ring —
    /// the kernel writes frames straight into shared memory and the reader
    /// walks them without a syscall per packet. If the ring cannot be set up
    /// the engine falls back to a plain `recvmsg` socket.
    ///
    /// The headline capability over ``LiveCapture`` is `PACKET_FANOUT`: open
    /// several `AFPacketCapture` instances on the same interface with the same
    /// ``fanoutGroup`` and the kernel load-balances flows across them (one per
    /// core), something libpcap's portable API cannot express. Filters still
    /// use tcpdump syntax — expressions are compiled by libpcap and attached
    /// natively via `SO_ATTACH_FILTER`, so semantics match ``LiveCapture``
    /// byte for byte.
    ///
    /// Requires root or `CAP_NET_RAW` (plus `CAP_NET_ADMIN` for promiscuous
    /// mode), like any packet capture on Linux. See `Docs/AFPacket.md` for the
    /// design.
    public final class AFPacketCapture: PacketSource, Sendable {
        private let engine: AFPacketEngine

        public var linkType: LinkType { engine.linkType }

        /// Opens a capture on the named interface.
        ///
        /// - Parameters:
        ///   - interface: The interface name, e.g. `"eth0"`.
        ///   - config: Snapshot length and promiscuous mode are honored;
        ///     `timeoutMilliseconds` bounds the internal poll interval.
        ///   - fanoutGroup: When set, joins the kernel fanout group with
        ///     flow-hash load balancing. All members of a group must set the
        ///     same id.
        /// - Throws: ``PcapError`` if the socket cannot be opened or configured.
        public init(
            interface: String, config: CaptureConfig = .default, fanoutGroup: UInt16? = nil
        ) throws {
            self.engine = try AFPacketEngine(
                interface: interface, config: config, fanoutGroup: fanoutGroup)
        }

        public func packets() -> PacketSequence {
            PacketSequence(engine: engine)
        }

        /// Installs a kernel filter (tcpdump syntax, e.g. `"tcp port 443"`).
        /// - Throws: ``PcapError`` if the expression fails to compile or attach.
        public func setFilter(_ expression: String) throws {
            try engine.setFilter(expression)
        }

        /// Injects a raw frame onto the interface.
        /// - Returns: the number of bytes sent.
        /// - Throws: ``PcapError`` on failure.
        @discardableResult
        public func send(_ data: Data) throws -> Int {
            try engine.send(data)
        }

        /// Reads (and resets) the socket's packet/drop counters. Because
        /// `PACKET_STATISTICS` is read-and-reset, each call reports the deltas
        /// since the previous one.
        public func statistics() throws -> CaptureStatistics {
            try engine.statistics()
        }

        /// Whether packets are being delivered through the `TPACKET_V3` ring
        /// (as opposed to the plain-socket fallback).
        public var usesRing: Bool { engine.usesRing }
    }

    /// The `AF_PACKET` counterpart of `PcapEngine`, with the same concurrency
    /// invariant: the socket is read only on one private serial queue, one
    /// packet per `next()`. Cancellation is a flag checked between poll
    /// timeouts (`AF_PACKET` sockets do not support `shutdown(2)`, so unlike
    /// libpcap there is no cross-thread interrupt; the poll interval bounds
    /// cancellation latency instead).
    final class AFPacketEngine: CaptureEngine, @unchecked Sendable {
        private let descriptor: Int32
        private let ring: OpaquePointer?
        private let queue = DispatchQueue(label: "com.swiftpacket.afpacket")
        private let lock = NSLock()
        private var closed = false
        private var stopRequested = false
        private var buffer: [UInt8]
        private let pollMilliseconds: Int32
        private let snapshotLength: Int32

        let linkType: LinkType

        var usesRing: Bool { ring != nil }

        init(interface: String, config: CaptureConfig, fanoutGroup: UInt16?) throws {
            var hardwareType: Int32 = -1
            let fd = interface.withCString {
                swiftpacket_afpacket_open($0, config.promiscuous ? 1 : 0, &hardwareType)
            }
            guard fd >= 0 else {
                throw PcapError(
                    message:
                        "AF_PACKET open on \(interface) failed: \(Self.errorText(-fd)) "
                        + "(needs root or CAP_NET_RAW)",
                    code: fd
                )
            }

            if let fanoutGroup {
                let status = swiftpacket_afpacket_set_fanout(fd, fanoutGroup)
                guard status == 0 else {
                    swiftpacket_afpacket_close(fd)
                    throw PcapError(
                        message: "PACKET_FANOUT failed: \(Self.errorText(-status))",
                        code: status
                    )
                }
            }

            self.descriptor = fd
            self.snapshotLength = config.snapshotLength
            self.pollMilliseconds = max(10, config.timeoutMilliseconds)
            // ARPHRD_ETHER (1) and the ethernet-framed pseudo devices (veth,
            // bridges, Linux loopback) all deliver Ethernet frames.
            self.linkType = .ethernet

            // Prefer the TPACKET_V3 ring; fall back to a plain recv socket
            // (with a snapshot-sized copy buffer) if the ring can't be built.
            var ringError: Int32 = 0
            let frameSize = Self.ringFrameSize(for: config)
            self.ring = swiftpacket_ring_setup(
                fd,
                UInt32(config.ringBlockSize),
                UInt32(config.ringBlockCount),
                frameSize,
                config.timeoutMilliseconds,
                &ringError)
            self.buffer =
                self.ring == nil
                ? [UInt8](repeating: 0, count: Int(config.snapshotLength))
                : []
        }

        /// A frame slot big enough for a full snapshot plus the TPACKET_V3
        /// header, and a divisor of the block size (a kernel requirement).
        private static func ringFrameSize(for config: CaptureConfig) -> UInt32 {
            let blockSize = UInt32(config.ringBlockSize)
            // Round the snapshot (plus generous header/alignment room) up to a
            // power of two, capped at the block size.
            var frame: UInt32 = 2048
            let needed = UInt32(config.snapshotLength) + 256
            while frame < needed && frame < blockSize { frame <<= 1 }
            return min(frame, blockSize)
        }

        deinit {
            lock.lock()
            let alreadyClosed = closed
            closed = true
            lock.unlock()
            if !alreadyClosed {
                if let ring { swiftpacket_ring_close(ring) }
                swiftpacket_afpacket_close(descriptor)
            }
        }

        /// Injects a raw frame. Serialized with reads on the private queue.
        func send(_ data: Data) throws -> Int {
            try queue.sync {
                let sent = data.withUnsafeBytes { raw -> Int in
                    Int(
                        swiftpacket_afpacket_send(
                            descriptor, raw.bindMemory(to: UInt8.self).baseAddress, raw.count))
                }
                guard sent >= 0 else {
                    throw PcapError(
                        message: "AF_PACKET send failed: \(Self.errorText(Int32(-sent)))",
                        code: Int32(sent))
                }
                return sent
            }
        }

        func statistics() throws -> CaptureStatistics {
            try queue.sync {
                var raw = swiftpacket_stats(packets: 0, drops: 0)
                let status = swiftpacket_afpacket_stats(descriptor, &raw)
                guard status == 0 else {
                    throw PcapError(
                        message: "PACKET_STATISTICS failed: \(Self.errorText(-status))",
                        code: status)
                }
                return CaptureStatistics(
                    received: raw.packets, dropped: raw.drops, interfaceDropped: 0)
            }
        }

        /// Compiles `expression` with libpcap (on a dead Ethernet handle, so
        /// no capture privileges are needed for compilation) and attaches the
        /// resulting classic-BPF program natively.
        func setFilter(_ expression: String, optimize: Bool = true) throws {
            try queue.sync {
                guard let dead = pcap_open_dead(LinkType.ethernet.rawValue, snapshotLength)
                else {
                    throw PcapError(message: "pcap_open_dead failed")
                }
                defer { pcap_close(dead) }

                var program = bpf_program()
                let compiled = expression.withCString {
                    pcap_compile(dead, &program, $0, optimize ? 1 : 0, 0xFFFF_FFFF)
                }
                guard compiled == 0 else {
                    let text = pcap_geterr(dead).map { String(cString: $0) } ?? "compile error"
                    throw PcapError(
                        message: "failed to compile filter \"\(expression)\": \(text)",
                        code: compiled
                    )
                }
                defer { pcap_freecode(&program) }

                let status = swiftpacket_afpacket_attach_filter(
                    descriptor, program.bf_insns, UInt16(program.bf_len))
                guard status == 0 else {
                    throw PcapError(
                        message: "SO_ATTACH_FILTER failed: \(Self.errorText(-status))",
                        code: status
                    )
                }
            }
        }

        func next() async throws -> CapturedPacket? {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    queue.async { [self] in
                        do {
                            continuation.resume(returning: try readOne())
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                }
            } onCancel: {
                requestStop()
            }
        }

        /// Runs on `queue`. Alternates short kernel polls with stop checks
        /// until a packet arrives, via the ring or the fallback socket.
        private func readOne() throws -> CapturedPacket? {
            ring != nil ? try readFromRing() : try readFromSocket()
        }

        private func readFromRing() throws -> CapturedPacket? {
            while true {
                if isStopRequested { return nil }

                var data: UnsafePointer<UInt8>?
                var captureLength: UInt32 = 0
                var wireLength: UInt32 = 0
                var timestamp = swiftpacket_timestamp(seconds: 0, nanoseconds: 0)
                let status = swiftpacket_ring_next(
                    ring, descriptor, &data, &captureLength, &wireLength,
                    &timestamp, pollMilliseconds)

                if status == 0 { continue }  // timeout: check stop, wait again
                guard status > 0, let data else {
                    throw PcapError(
                        message: "AF_PACKET ring read failed: \(Self.errorText(-status))",
                        code: status)
                }
                // Copy out of the mmap before the next ring_next call reclaims
                // the block.
                let bytes = Data(bytes: data, count: Int(captureLength))
                return makePacket(bytes, wireLength: Int(wireLength), timestamp: timestamp)
            }
        }

        private func readFromSocket() throws -> CapturedPacket? {
            while true {
                if isStopRequested { return nil }

                var timestamp = swiftpacket_timestamp(seconds: 0, nanoseconds: 0)
                let wireLength = buffer.withUnsafeMutableBufferPointer { pointer in
                    swiftpacket_afpacket_recv(
                        descriptor, pointer.baseAddress, pointer.count,
                        pollMilliseconds, &timestamp)
                }

                if wireLength == 0 { continue }  // poll timeout: check stop, wait again
                guard wireLength > 0 else {
                    throw PcapError(
                        message: "AF_PACKET read failed: \(Self.errorText(Int32(-wireLength)))",
                        code: Int32(wireLength)
                    )
                }

                // MSG_TRUNC semantics: the return value is the original wire
                // length; at most `buffer.count` bytes were stored.
                let captured = min(Int(wireLength), buffer.count)
                return makePacket(
                    Data(buffer[0..<captured]), wireLength: Int(wireLength), timestamp: timestamp)
            }
        }

        private func makePacket(
            _ bytes: Data, wireLength: Int, timestamp: swiftpacket_timestamp
        ) -> CapturedPacket {
            let seconds =
                Double(timestamp.seconds) + Double(timestamp.nanoseconds) / 1_000_000_000
            return CapturedPacket(
                data: bytes,
                info: CaptureInfo(
                    timestamp: Date(timeIntervalSince1970: seconds),
                    captureLength: bytes.count,
                    originalLength: wireLength
                ),
                linkType: linkType
            )
        }

        private var isStopRequested: Bool {
            lock.lock()
            defer { lock.unlock() }
            return stopRequested
        }

        private func requestStop() {
            lock.lock()
            defer { lock.unlock() }
            stopRequested = true
        }

        private static func errorText(_ errorNumber: Int32) -> String {
            String(cString: strerror(errorNumber))
        }
    }

#endif  // os(Linux)
