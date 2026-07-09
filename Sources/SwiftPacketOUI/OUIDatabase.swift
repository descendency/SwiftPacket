import Foundation
import SwiftPacket

/// Maps MAC address prefixes to their registered vendor names, using the IEEE
/// OUI registry (as published in Wireshark's `manuf` file).
///
/// The table is a generated binary resource loaded once and memory-mapped;
/// lookups binary-search fixed-width keys, trying the longest IEEE allocation
/// first (36-bit MA-S, then 28-bit MA-M, then 24-bit MA-L), so a subdivided
/// block resolves to its specific assignee rather than the parent registrar.
///
/// ```swift
/// let database = try OUIDatabase.shared
/// database.vendor(for: someMAC)          // "Apple, Inc."
/// ```
public struct OUIDatabase: Sendable {
    /// One IEEE allocation size, longest first (longest prefix wins).
    private struct Section: Sendable {
        let count: Int
        let bits: Int
        /// Absolute offset of the 6-byte key array in `data`.
        let keysOffset: Int
        /// Absolute offset of the u32 name-offset array in `data`.
        let offsetsOffset: Int
        /// Absolute offset of the name blob in `data`.
        let blobOffset: Int
        let mask: UInt64
    }

    private let data: Data
    private let sections: [Section]

    /// The process-wide shared database, loaded from the bundled resource.
    public static let shared: Result<OUIDatabase, Error> = {
        Result { try OUIDatabase() }
    }()

    /// Loads the database from `url`, or the bundled resource when `url` is nil.
    public init(contentsOf url: URL? = nil) throws {
        let resolved: URL
        if let url {
            resolved = url
        } else {
            guard let bundled = Bundle.module.url(forResource: "oui", withExtension: "bin") else {
                throw OUIError.resourceMissing
            }
            resolved = bundled
        }
        // Memory-map: the table is read-only and shared across all lookups.
        let bytes = try Data(contentsOf: resolved, options: .mappedIfSafe)
        try self.init(data: bytes)
    }

    init(data: Data) throws {
        self.data = data
        var cursor = data.startIndex
        func readU32() throws -> Int {
            guard cursor + 4 <= data.endIndex else { throw OUIError.malformed }
            let value =
                UInt32(data[cursor]) | UInt32(data[cursor + 1]) << 8
                | UInt32(data[cursor + 2]) << 16 | UInt32(data[cursor + 3]) << 24
            cursor += 4
            return Int(value)
        }

        guard data.count >= 4, data[cursor] == 0x53, data[cursor + 1] == 0x50,
            data[cursor + 2] == 0x4F, data[cursor + 3] == 0x31  // "SPO1"
        else { throw OUIError.malformed }
        cursor += 4

        // Sections are stored 24, 28, 36; search order is longest-first.
        var parsed: [Int: Section] = [:]
        for bits in [24, 28, 36] {
            let count = try readU32()
            let keysOffset = cursor
            cursor += count * 6
            let offsetsOffset = cursor
            cursor += count * 4
            let blobLength = try readU32()
            let blobOffset = cursor
            cursor += blobLength
            guard cursor <= data.endIndex else { throw OUIError.malformed }
            parsed[bits] = Section(
                count: count,
                bits: bits,
                keysOffset: keysOffset,
                offsetsOffset: offsetsOffset,
                blobOffset: blobOffset,
                mask: bits == 48 ? .max : (((1 << bits) - 1) as UInt64) << (48 - bits)
            )
        }
        self.sections = [36, 28, 24].compactMap { parsed[$0] }
    }

    /// The registered vendor for `mac`'s OUI, or `nil` if unassigned.
    public func vendor(for mac: MACAddress) -> String? {
        var value: UInt64 = 0
        for byte in mac.bytes { value = value << 8 | UInt64(byte) }
        for section in sections {
            if let name = lookup(value & section.mask, in: section) {
                return name
            }
        }
        return nil
    }

    private func lookup(_ key: UInt64, in section: Section) -> String? {
        let base = data.startIndex
        var low = 0
        var high = section.count - 1
        while low <= high {
            let mid = (low + high) / 2
            let keyStart = base + section.keysOffset + mid * 6
            var candidate: UInt64 = 0
            for index in 0..<6 { candidate = candidate << 8 | UInt64(data[keyStart + index]) }

            if candidate == key {
                return name(at: mid, in: section)
            } else if candidate < key {
                low = mid + 1
            } else {
                high = mid - 1
            }
        }
        return nil
    }

    private func name(at index: Int, in section: Section) -> String? {
        let base = data.startIndex
        let offsetStart = base + section.offsetsOffset + index * 4
        let nameOffset =
            Int(data[offsetStart]) | Int(data[offsetStart + 1]) << 8
            | Int(data[offsetStart + 2]) << 16 | Int(data[offsetStart + 3]) << 24
        let entryStart = base + section.blobOffset + nameOffset
        guard entryStart + 2 <= data.endIndex else { return nil }
        let length = Int(data[entryStart]) | Int(data[entryStart + 1]) << 8
        let textStart = entryStart + 2
        guard textStart + length <= data.endIndex else { return nil }
        return String(decoding: data[textStart..<(textStart + length)], as: UTF8.self)
    }
}

public enum OUIError: Error, Sendable {
    /// The bundled `oui.bin` resource could not be located.
    case resourceMissing
    /// The table's bytes are not a valid `oui.bin`.
    case malformed
}

extension MACAddress {
    /// The registered vendor for this address's OUI, using ``OUIDatabase/shared``.
    /// Returns `nil` if the database failed to load or the OUI is unassigned.
    public var vendor: String? {
        guard case let .success(database) = OUIDatabase.shared else { return nil }
        return database.vendor(for: self)
    }
}
