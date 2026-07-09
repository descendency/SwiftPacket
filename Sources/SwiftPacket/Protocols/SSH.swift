import Foundation

/// An SSH identification string (the banner both peers send before the binary
/// protocol begins), e.g. `"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"`.
public struct SSHIdentification: Sendable, Equatable {
    /// The full banner line, without the trailing CR/LF.
    public let raw: String
    /// The protocol version, e.g. `"2.0"`.
    public let protocolVersion: String
    /// The software version token.
    public let softwareVersion: String
    /// Free-text comments after the first space, if any.
    public let comments: String?

    /// Parses an SSH banner from the start of `data`. Accepts a line ending in
    /// LF or CRLF; returns `nil` if the line is absent or not `SSH-…`.
    public static func parse(_ data: Data) -> SSHIdentification? {
        // The banner ends at the first LF; cap the scan (RFC 4253: ≤255 bytes).
        let bytes = [UInt8](data.prefix(255))
        guard let lf = bytes.firstIndex(of: 0x0A) else { return nil }
        var lineBytes = Array(bytes[0..<lf])
        if lineBytes.last == 0x0D { lineBytes.removeLast() }
        let line = String(decoding: lineBytes, as: UTF8.self)

        guard line.hasPrefix("SSH-") else { return nil }
        // SSH-<protoversion>-<softwareversion>[ <comments>]
        let afterPrefix = line.dropFirst(4)
        guard let dash = afterPrefix.firstIndex(of: "-") else { return nil }
        let protocolVersion = String(afterPrefix[afterPrefix.startIndex..<dash])
        let rest = String(afterPrefix[afterPrefix.index(after: dash)...])

        let software: String
        let comments: String?
        if let space = rest.firstIndex(of: " ") {
            software = String(rest[rest.startIndex..<space])
            comments = String(rest[rest.index(after: space)...])
        } else {
            software = rest
            comments = nil
        }
        return SSHIdentification(
            raw: line, protocolVersion: protocolVersion, softwareVersion: software,
            comments: comments)
    }
}

/// A parsed SSH `SSH_MSG_KEXINIT` (message 20) — the algorithm-negotiation
/// packet, and the input to the HASSH fingerprint.
public struct SSHKEXInit: Sendable {
    public let cookie: Data
    public let kexAlgorithms: [String]
    public let serverHostKeyAlgorithms: [String]
    public let encryptionAlgorithmsClientToServer: [String]
    public let encryptionAlgorithmsServerToClient: [String]
    public let macAlgorithmsClientToServer: [String]
    public let macAlgorithmsServerToClient: [String]
    public let compressionAlgorithmsClientToServer: [String]
    public let compressionAlgorithmsServerToClient: [String]
    public let languagesClientToServer: [String]
    public let languagesServerToClient: [String]

    /// Parses a KEXINIT from an SSH binary packet (`packet_length`,
    /// `padding_length`, payload, padding). Returns `nil` if the buffer does
    /// not hold a complete KEXINIT packet.
    public static func parse(_ data: Data) -> SSHKEXInit? {
        var reader = ByteReader(data)
        guard let packetLength = try? reader.readUInt32(),
            let paddingLength = try? reader.readUInt8(),
            packetLength >= 2
        else { return nil }
        let payloadLength = Int(packetLength) - Int(paddingLength) - 1
        guard payloadLength > 0, let payload = try? reader.readBytes(payloadLength) else {
            return nil
        }
        return parsePayload(payload)
    }

    /// Parses a KEXINIT directly from its payload (message code onward), for
    /// callers that have already removed the binary-packet framing.
    public static func parsePayload(_ payload: Data) -> SSHKEXInit? {
        var reader = ByteReader(payload)
        guard let messageCode = try? reader.readUInt8(), messageCode == 20,  // SSH_MSG_KEXINIT
            let cookie = try? reader.readBytes(16)
        else { return nil }

        func nameList() -> [String]? {
            guard let length = try? reader.readUInt32(),
                let bytes = try? reader.readBytes(Int(length))
            else { return nil }
            let text = String(decoding: bytes, as: UTF8.self)
            return text.isEmpty ? [] : text.split(separator: ",").map(String.init)
        }

        guard let kex = nameList(), let hostKey = nameList(),
            let encC2S = nameList(), let encS2C = nameList(),
            let macC2S = nameList(), let macS2C = nameList(),
            let compC2S = nameList(), let compS2C = nameList(),
            let langC2S = nameList(), let langS2C = nameList()
        else { return nil }

        return SSHKEXInit(
            cookie: Data(cookie),
            kexAlgorithms: kex, serverHostKeyAlgorithms: hostKey,
            encryptionAlgorithmsClientToServer: encC2S, encryptionAlgorithmsServerToClient: encS2C,
            macAlgorithmsClientToServer: macC2S, macAlgorithmsServerToClient: macS2C,
            compressionAlgorithmsClientToServer: compC2S,
            compressionAlgorithmsServerToClient: compS2C,
            languagesClientToServer: langC2S, languagesServerToClient: langS2C)
    }
}
