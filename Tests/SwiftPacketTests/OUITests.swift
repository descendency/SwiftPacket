import Foundation
import Testing

@testable import SwiftPacket
@testable import SwiftPacketOUI

@Suite("OUI vendor lookup")
struct OUITests {

    /// The database loads from the bundled resource.
    func database() throws -> OUIDatabase {
        try OUIDatabase.shared.get()
    }

    @Test("well-known 24-bit OUIs resolve to their registered vendors")
    func macLookup() throws {
        let database = try database()
        #expect(database.vendor(for: MACAddress([0x00, 0x1B, 0x63, 0x11, 0x22, 0x33])!)
            == "Apple, Inc.")
        #expect(database.vendor(for: MACAddress([0x00, 0x00, 0x0C, 0xAA, 0xBB, 0xCC])!)
            == "Cisco Systems, Inc")
        #expect(database.vendor(for: MACAddress([0x00, 0x50, 0x56, 0x01, 0x02, 0x03])!)
            == "VMware, Inc.")
    }

    @Test("the low OUI byte does not change the vendor within a 24-bit block")
    func prefixInsensitivity() throws {
        let database = try database()
        let first = database.vendor(for: MACAddress([0x3C, 0xD0, 0xF8, 0x00, 0x00, 0x01])!)
        let second = database.vendor(for: MACAddress([0x3C, 0xD0, 0xF8, 0xFF, 0xFF, 0xFF])!)
        #expect(first == "Apple, Inc.")
        #expect(first == second)
    }

    @Test("36-bit MA-S blocks resolve to the specific assignee, not the parent")
    func longestPrefixWins() throws {
        let database = try database()
        // 00:1B:C5:00:0x/36 and 00:1B:C5:00:1x/36 are different companies that
        // share a 24-bit prefix — only a longest-match lookup tells them apart.
        #expect(database.vendor(for: MACAddress([0x00, 0x1B, 0xC5, 0x00, 0x00, 0x01])!)
            == "Converging Systems Inc.")
        #expect(database.vendor(for: MACAddress([0x00, 0x1B, 0xC5, 0x00, 0x10, 0x01])!)
            == "OpenRB.com, Direct SIA")
    }

    @Test("an unassigned OUI returns nil")
    func unassigned() throws {
        let database = try database()
        // The locally-administered / documentation range is not registered.
        #expect(database.vendor(for: MACAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])!) == nil)
    }

    @Test("the MACAddress.vendor convenience uses the shared database")
    func macConvenience() {
        #expect(MACAddress([0x00, 0x1B, 0x63, 0, 0, 1])!.vendor == "Apple, Inc.")
        #expect(MACAddress([0x02, 0x00, 0x00, 0, 0, 1])!.vendor == nil)
    }

    @Test("lookups are internally consistent across many random MACs")
    func consistency() throws {
        let database = try database()
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<2000 {
            var bytes = [UInt8]()
            for _ in 0..<6 { bytes.append(UInt8.random(in: .min ... .max, using: &generator)) }
            let mac = MACAddress(bytes)!
            // The result must be stable and must not trap.
            #expect(database.vendor(for: mac) == database.vendor(for: mac))
        }
    }
}
