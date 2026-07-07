import Foundation

// MARK: - Address bytes

extension IPv4Address {
    /// The address as four bytes, most-significant first.
    var dataBytes: Data {
        var writer = ByteWriter()
        writer.writeUInt32(rawValue)
        return writer.data
    }
}

extension IPv6Address {
    /// The address as sixteen bytes.
    var dataBytes: Data { Data(bytes) }
}

// MARK: - Link layer

extension Ethernet: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        var writer = ByteWriter()
        writer.writeBytes(Data(destination.bytes))
        writer.writeBytes(Data(source.bytes))
        writer.writeUInt16(etherType.rawValue)
        buffer.prepend(writer.data)
    }
}

// MARK: - Network layer

extension IPv4: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        let payloadLength = buffer.bytes.count
        let ihl = headerLength / 4
        let total = options.fixLengths ? headerLength + payloadLength : totalLength

        var writer = ByteWriter()
        writer.writeUInt8((version << 4) | UInt8(ihl & 0x0F))
        writer.writeUInt8((dscp << 2) | (ecn & 0x03))
        writer.writeUInt16(UInt16(total & 0xFFFF))
        writer.writeUInt16(identification)

        var flagsAndFragment = fragmentOffset & 0x1FFF
        if dontFragment { flagsAndFragment |= 0x4000 }
        if moreFragments { flagsAndFragment |= 0x2000 }
        writer.writeUInt16(flagsAndFragment)

        writer.writeUInt8(ttl)
        writer.writeUInt8(proto.rawValue)
        writer.writeUInt16(0)  // checksum placeholder
        writer.writeUInt32(sourceAddress.rawValue)
        writer.writeUInt32(destinationAddress.rawValue)
        writer.writeBytes(self.options)

        var header = writer.data
        let checksumValue = options.computeChecksums ? internetChecksum(header) : headerChecksum
        header[header.startIndex + 10] = UInt8(checksumValue >> 8)
        header[header.startIndex + 11] = UInt8(checksumValue & 0xFF)
        buffer.prepend(header)
    }
}

extension IPv6: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        let length = options.fixLengths ? buffer.bytes.count : payloadLength
        var writer = ByteWriter()
        let word = (UInt32(version) << 28) | (UInt32(trafficClass) << 20) | (flowLabel & 0x000F_FFFF)
        writer.writeUInt32(word)
        writer.writeUInt16(UInt16(length & 0xFFFF))
        writer.writeUInt8(nextHeader.rawValue)
        writer.writeUInt8(hopLimit)
        writer.writeBytes(Data(sourceAddress.bytes))
        writer.writeBytes(Data(destinationAddress.bytes))
        buffer.prepend(writer.data)
    }
}

extension ARP: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        buffer.prepend(layerContents)
    }
}

// MARK: - Transport layer

extension UDP: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        let payload = buffer.bytes
        let udpLength = options.fixLengths ? 8 + payload.count : length

        var writer = ByteWriter()
        writer.writeUInt16(sourcePort)
        writer.writeUInt16(destinationPort)
        writer.writeUInt16(UInt16(udpLength & 0xFFFF))
        writer.writeUInt16(0)  // checksum placeholder
        var header = writer.data

        let checksumValue: UInt16
        if options.computeChecksums {
            guard let pseudo = context.pseudoHeader else {
                throw SerializationError.missingNetworkLayerForChecksum
            }
            var segment = header
            segment.append(payload)
            let computed = transportChecksum(pseudo: pseudo, protocolNumber: 17, transportLength: udpLength, segment: segment)
            checksumValue = computed == 0 ? 0xFFFF : computed  // 0 means "no checksum" in UDP
        } else {
            checksumValue = checksum
        }
        header[header.startIndex + 6] = UInt8(checksumValue >> 8)
        header[header.startIndex + 7] = UInt8(checksumValue & 0xFF)
        buffer.prepend(header)
    }
}

extension TCP: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        let payload = buffer.bytes
        let dataOffset = headerLength / 4

        var writer = ByteWriter()
        writer.writeUInt16(sourcePort)
        writer.writeUInt16(destinationPort)
        writer.writeUInt32(sequenceNumber)
        writer.writeUInt32(acknowledgmentNumber)

        var offsetAndFlags = UInt16(dataOffset & 0x0F) << 12
        if ns { offsetAndFlags |= 0x0100 }
        if cwr { offsetAndFlags |= 0x0080 }
        if ece { offsetAndFlags |= 0x0040 }
        if urg { offsetAndFlags |= 0x0020 }
        if ack { offsetAndFlags |= 0x0010 }
        if psh { offsetAndFlags |= 0x0008 }
        if rst { offsetAndFlags |= 0x0004 }
        if syn { offsetAndFlags |= 0x0002 }
        if fin { offsetAndFlags |= 0x0001 }
        writer.writeUInt16(offsetAndFlags)

        writer.writeUInt16(window)
        writer.writeUInt16(0)  // checksum placeholder
        writer.writeUInt16(urgentPointer)
        writer.writeBytes(self.options)
        var header = writer.data

        let checksumValue: UInt16
        if options.computeChecksums {
            guard let pseudo = context.pseudoHeader else {
                throw SerializationError.missingNetworkLayerForChecksum
            }
            var segment = header
            segment.append(payload)
            checksumValue = transportChecksum(pseudo: pseudo, protocolNumber: 6, transportLength: segment.count, segment: segment)
        } else {
            checksumValue = checksum
        }
        header[header.startIndex + 16] = UInt8(checksumValue >> 8)
        header[header.startIndex + 17] = UInt8(checksumValue & 0xFF)
        buffer.prepend(header)
    }
}

extension ICMPv4: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        buffer.prepend(layerContents)
    }
}

extension ICMPv6: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        buffer.prepend(layerContents)
    }
}

// MARK: - Application layer and payloads

extension DNS: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        buffer.prepend(layerContents)
    }
}

extension Payload: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        buffer.prepend(bytes)
    }
}

extension Loopback: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        buffer.prepend(layerContents)
    }
}

extension DecodeFailure: SerializableLayer {
    public func serialize(into buffer: inout SerializeBuffer, context: SerializationContext, options: SerializeOptions) throws {
        buffer.prepend(unconsumed)
    }
}
