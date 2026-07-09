import Foundation

extension Data {
    /// A classic `hexdump`-style rendering: an 8-digit hex offset, sixteen
    /// space-separated hex byte columns (grouped 8 + 8), and the printable
    /// ASCII gutter.
    ///
    /// ```
    /// 0000  aa aa aa aa aa aa bb bb  bb bb bb bb 08 00 45 00  ..............E.
    /// ```
    public func hexDump() -> String {
        guard !isEmpty else { return "" }
        let bytes = [UInt8](self)
        var lines: [String] = []
        lines.reserveCapacity((bytes.count + 15) / 16)

        for rowStart in stride(from: 0, to: bytes.count, by: 16) {
            let row = bytes[rowStart..<Swift.min(rowStart + 16, bytes.count)]

            var hex = ""
            for column in 0..<16 {
                if column == 8 { hex += " " }  // split the two 8-byte halves
                let index = rowStart + column
                hex += index < bytes.count ? String(format: "%02x ", bytes[index]) : "   "
            }

            let ascii = String(
                row.map { (0x20...0x7E).contains($0) ? Character(UnicodeScalar($0)) : "." })

            lines.append(String(format: "%04x  %@ %@", rowStart, hex, ascii))
        }
        return lines.joined(separator: "\n")
    }
}

extension Packet {
    /// A per-layer legend followed by a full hex dump of the packet.
    ///
    /// The legend lists each decoded layer with the byte range its own
    /// contents occupy, so a reader can map dump offsets back to layers:
    ///
    /// ```
    /// Ethernet | IPv4 | UDP | DNS  (95 bytes)
    ///   [0x0000..<0x000e] Ethernet
    ///   [0x000e..<0x0022] IPv4
    ///   [0x0022..<0x002a] UDP
    ///   [0x002a..<0x005f] DNS
    ///
    /// 0000  ...
    /// ```
    ///
    /// Offsets are derived by walking each layer's ``Layer/layerContents``
    /// length from the front; a layer whose contents aren't a contiguous
    /// prefix (rare) simply shows a best-effort range.
    public func hexDump() -> String {
        var legend = ["\(summary)  (\(data.count) bytes)"]
        var offset = 0
        for layer in layers {
            let length = layer.layerContents.count
            let end = min(offset + length, data.count)
            legend.append(
                String(format: "  [0x%04x..<0x%04x] %@", offset, end, layer.layerType.name))
            offset = end
        }
        return legend.joined(separator: "\n") + "\n\n" + data.hexDump()
    }
}
