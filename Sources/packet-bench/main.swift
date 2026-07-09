import Foundation
import SwiftPacket

// A dependency-free throughput benchmark comparing the general decoder
// (`Packet.decode`, which allocates a boxed `[any Layer]` per packet) against
// the reusable fast path (`StackDecoder` + `DecodedStack`).
//
//   swift run -c release packet-bench [iterations]
//
// Always run in release configuration; a debug build is not representative.

let iterations = CommandLine.arguments.count > 1 ? Int(CommandLine.arguments[1]) ?? 2_000_000 : 2_000_000

// A representative Ethernet / IPv4 / TCP packet with a small HTTP payload.
func sampleFrame() -> Data {
    let payload = Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
    let total = 20 + 20 + payload.count
    var ip: [UInt8] = [0x45, 0x00, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0x40, 0x00, 0x40, 0x06, 0, 0]
    ip += [10, 0, 0, 1, 10, 0, 0, 2]
    var tcp: [UInt8] = [
        0x04, 0xD2, 0x00, 0x50, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00,
        0x50, 0x18, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    ]
    tcp += payload
    let ethernet: [UInt8] = [
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x08, 0x00,
    ]
    return Data(ethernet + ip + tcp)
}

let frame = sampleFrame()
let registry = DecoderRegistry.standard

// A sink that reads a field from each decode, so the optimizer can't elide the
// work.
var sink: UInt64 = 0

func time(_ label: String, _ body: () -> Void) -> Double {
    let start = DispatchTime.now().uptimeNanoseconds
    body()
    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start)
    let perPacket = elapsed / Double(iterations)
    let perSecond = 1_000_000_000.0 / perPacket
    print(
        String(
            format: "%-16@ %8.1f ns/packet   %10.0f packets/sec", label as NSString, perPacket,
            perSecond))
    return perPacket
}

// Warm up both paths (JIT of first-use metadata, caches).
do {
    var warmStack = DecodedStack()
    let warmDecoder = StackDecoder(registry: registry)
    for _ in 0..<100_000 {
        let packet = Packet.decode(frame, startingAt: .ethernet, using: registry)
        sink &+= UInt64(packet.layer(TCP.self)?.destinationPort ?? 0)
        warmDecoder.decode(frame, startingAt: .ethernet, into: &warmStack)
        sink &+= UInt64(warmStack.tcp?.destinationPort ?? 0)
    }
}

print("SwiftPacket decode benchmark — \(iterations) iterations, Ethernet/IPv4/TCP\n")

let general = time("Packet.decode") {
    for _ in 0..<iterations {
        let packet = Packet.decode(frame, startingAt: .ethernet, using: registry)
        sink &+= UInt64(packet.layer(TCP.self)?.destinationPort ?? 0)
    }
}

let stackDecoder = StackDecoder(registry: registry)
var stack = DecodedStack()
let fast = time("StackDecoder") {
    for _ in 0..<iterations {
        stackDecoder.decode(frame, startingAt: .ethernet, into: &stack)
        sink &+= UInt64(stack.tcp?.destinationPort ?? 0)
    }
}

print(String(format: "\nStackDecoder speedup: %.2fx", general / fast))
// Keep `sink` observable so nothing is optimized away.
if sink == .max { print("unreachable \(sink)") }
