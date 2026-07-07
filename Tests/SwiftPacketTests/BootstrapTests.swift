import Testing
@testable import SwiftPacket

@Suite("Phase 0 — bootstrap")
struct BootstrapTests {

    @Test("package version constant is exposed")
    func packageVersionExposed() {
        let version = SwiftPacket.version
        #expect(!version.isEmpty)
        // Expect a semantic version like "0.1.0" (optionally with a pre-release
        // suffix such as "1.0.0-beta"): three dot-separated numeric components.
        let core = version.split(separator: "-", maxSplits: 1).first.map(String.init) ?? version
        let components = core.split(separator: ".")
        #expect(components.count == 3)
        #expect(components.allSatisfy { $0.allSatisfy(\.isNumber) })
    }

    @Test("libpcap is linked and reports a version")
    func libpcapIsLinked() {
        let version = SwiftPacket.libpcapVersion
        #expect(version != "unknown")
        #expect(!version.isEmpty)
        // libpcap conventionally prefixes its version string with "libpcap".
        #expect(version.contains("libpcap"))
    }
}
