import Foundation

// MARK: - Radiotap

/// A radiotap header (the de-facto capture format for 802.11 radios): a
/// version, a length, and a presence bitmap describing which radio fields
/// follow.
///
/// The most useful fields — the channel frequency and the received signal
/// strength — are decoded when present; the header as a whole is skipped to
/// reach the 802.11 frame regardless of which fields it carries.
public struct Radiotap: Layer {
    public static let layerType = LayerType.radiotap

    public let version: UInt8
    /// The total header length; the 802.11 frame follows it.
    public let headerLength: Int
    /// The presence bitmap (bit N set means field N is present).
    public let present: UInt32
    /// The channel frequency in MHz, if the Channel field was present.
    public let channelFrequency: UInt16?
    /// The antenna signal in dBm, if the Antenna-signal field was present.
    public let antennaSignal: Int8?
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }
}

/// Decodes a radiotap header (little-endian, per spec) and hands its payload to
/// the ``Dot11`` decoder.
///
/// Fields appear in a fixed order with natural alignment. This walks the
/// standard fields up to antenna signal — enough for the frequency/RSSI a
/// monitor wants — and otherwise trusts the header length to skip the rest.
public struct RadiotapDecoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let version = try reader.readUInt8()
        try reader.skip(1)  // pad
        let headerLength = Int(try reader.readUInt16LE())
        guard headerLength >= 8, headerLength <= data.count else {
            throw DecodingError.malformed("radiotap length \(headerLength)")
        }
        let present = try reader.readUInt32LE()

        // Skip any extended presence bitmaps (bit 31 chains another word).
        var morePresent = present & 0x8000_0000 != 0
        while morePresent {
            let word = try reader.readUInt32LE()
            morePresent = word & 0x8000_0000 != 0
        }

        // Walk the aligned fields we care about. Field sizes/alignment per the
        // radiotap spec; we stop after antenna signal (bit 5).
        let base = data.startIndex
        var offset = reader.bytesRead
        func align(_ n: Int) { offset = (offset + n - 1) / n * n }
        func has(_ bit: Int) -> Bool { present & (1 << bit) != 0 }

        var channelFrequency: UInt16?
        var antennaSignal: Int8?
        if has(0) { offset += 8 }  // TSFT (align 8; we are already 8-aligned here)
        if has(1) { offset += 1 }  // Flags
        if has(2) { offset += 1 }  // Rate
        if has(3) {  // Channel: align 2, freq(2) + flags(2)
            align(2)
            if base + offset + 2 <= data.endIndex {
                channelFrequency =
                    UInt16(data[base + offset]) | UInt16(data[base + offset + 1]) << 8
            }
            offset += 4
        }
        if has(4) { offset += 1 }  // FHSS
        if has(5) {  // Antenna signal (dBm), 1 byte signed
            if base + offset < data.endIndex {
                antennaSignal = Int8(bitPattern: data[base + offset])
            }
        }

        let payload =
            headerLength <= data.count ? data[(base + headerLength)..<data.endIndex] : Data()
        let layer = Radiotap(
            version: version, headerLength: headerLength, present: present,
            channelFrequency: channelFrequency, antennaSignal: antennaSignal,
            payload: payload, header: data.prefix(headerLength))

        return DecodeResult(
            layer: layer, next: payload.isEmpty ? .done : .next(.dot11, payload))
    }
}

// MARK: - 802.11

/// An IEEE 802.11 MAC frame header.
///
/// The address layout depends on the frame type and the to-DS/from-DS flags;
/// this decodes the frame-control fields and the addresses present for the
/// common management/data cases, and hands a data frame's body onward.
public struct Dot11: Layer {
    public static let layerType = LayerType.dot11

    /// 0 management, 1 control, 2 data.
    public let frameType: UInt8
    public let subtype: UInt8
    public let toDS: Bool
    public let fromDS: Bool
    public let retry: Bool
    public let isProtected: Bool
    public let durationID: UInt16
    /// Receiver / destination address (address 1).
    public let address1: MACAddress?
    /// Transmitter / source address (address 2).
    public let address2: MACAddress?
    /// BSSID or further address (address 3).
    public let address3: MACAddress?
    public let sequenceControl: UInt16?
    public let payload: Data

    fileprivate let header: Data
    public var layerContents: Data { header }
    public var layerPayload: Data { payload }

    public var isData: Bool { frameType == 2 }
    public var isManagement: Bool { frameType == 0 }
    public var isControl: Bool { frameType == 1 }

    /// The BSSID, i.e. address 3 for the common infrastructure cases.
    public var bssid: MACAddress? { address3 }

    public var typeName: String {
        switch frameType {
        case 0: return "Management"
        case 1: return "Control"
        case 2: return "Data"
        default: return "type-\(frameType)"
        }
    }
}

/// Decodes an 802.11 MAC header. Control frames are short (no address 2/3);
/// management and data frames carry three addresses and a sequence-control
/// field. QoS-data frames route their payload to the LLC decoder.
public struct Dot11Decoder: LayerDecoder {
    public init() {}

    public func decode(_ data: Data) throws -> DecodeResult {
        var reader = ByteReader(data)
        let frameControl = try reader.readUInt16LE()
        let durationID = try reader.readUInt16LE()

        let frameType = UInt8((frameControl >> 2) & 0x03)
        let subtype = UInt8((frameControl >> 4) & 0x0F)
        let toDS = frameControl & 0x0100 != 0
        let fromDS = frameControl & 0x0200 != 0

        let address1 = try? reader.readMACAddress()
        // Control frames (type 1) other than a few carry only address 1.
        var address2: MACAddress?
        var address3: MACAddress?
        var sequenceControl: UInt16?
        if frameType != 1 {
            address2 = try? reader.readMACAddress()
            address3 = try? reader.readMACAddress()
            sequenceControl = try? reader.readUInt16LE()
            // A 4th address appears only when both DS bits are set (WDS); it is
            // skipped here.
            if toDS && fromDS { _ = try? reader.skip(6) }
            // QoS data subtypes (0x08–0x0F) carry a 2-byte QoS control field.
            if frameType == 2 && subtype & 0x08 != 0 { _ = try? reader.skip(2) }
        }

        let headerLength = reader.bytesRead
        let payload = reader.readRemaining()
        let layer = Dot11(
            frameType: frameType, subtype: subtype, toDS: toDS, fromDS: fromDS,
            retry: frameControl & 0x0800 != 0, isProtected: frameControl & 0x4000 != 0,
            durationID: durationID, address1: address1, address2: address2, address3: address3,
            sequenceControl: sequenceControl, payload: payload, header: data.prefix(headerLength))

        if payload.isEmpty {
            return DecodeResult(layer: layer, next: .done)
        }
        // A data frame's body is an 802.2 LLC/SNAP frame; everything else is
        // opaque here.
        let next: LayerType = layer.isData ? .llc : .payload
        return DecodeResult(layer: layer, next: .next(next, payload))
    }
}
