import Foundation

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

// Modern flow/handshake fingerprints. JA3/JA3S already live on the TLS hello
// types; this adds the JA4 family, SSH's HASSH, and the Community ID flow hash.

private func sha256Prefix12(_ string: String) -> String {
    SHA256.hash(data: Data(string.utf8))
        .map { String(format: "%02x", $0) }
        .joined()
        .prefix(12)
        .description
}

private func ja4Version(_ version: UInt16) -> String {
    switch version {
    case 0x0304: return "13"
    case 0x0303: return "12"
    case 0x0302: return "11"
    case 0x0301: return "10"
    case 0x0300: return "s3"
    default: return "00"
    }
}

private func hex4(_ value: UInt16) -> String { String(format: "%04x", value) }

extension TLSClientHello {
    /// The JA4 TLS client fingerprint (FoxIO spec), e.g.
    /// `t13d0306h2_<12hex>_<12hex>`.
    ///
    /// Assumes TCP transport (the `t` prefix). GREASE values are excluded, the
    /// cipher list is sorted for the `b` hash, and the extension list for the
    /// `c` hash excludes the SNI and ALPN extensions (their presence is already
    /// encoded in the `a` section).
    public var ja4: String {
        let ciphers = cipherSuites.filter { !isGREASE($0) }
        let extensions = extensionTypes.filter { !isGREASE($0) }

        // Section a.
        let version = supportedVersions.filter { !isGREASE($0) }.max() ?? legacyVersion
        let sni = serverName != nil ? "d" : "i"
        let cipherCount = String(format: "%02d", min(ciphers.count, 99))
        let extCount = String(format: "%02d", min(extensions.count, 99))
        let alpn: String
        if let first = alpnProtocols.first, let firstChar = first.first, let lastChar = first.last {
            alpn = "\(firstChar)\(lastChar)"
        } else {
            alpn = "00"
        }
        let a = "t\(ja4Version(version))\(sni)\(cipherCount)\(extCount)\(alpn)"

        // Section b: sorted ciphers.
        let b =
            ciphers.isEmpty
            ? "000000000000"
            : sha256Prefix12(ciphers.sorted().map(hex4).joined(separator: ","))

        // Section c: sorted extensions (minus SNI/ALPN) + "_" + sig algs in order.
        let hashedExtensions = extensions.filter { $0 != 0x0000 && $0 != 0x0010 }.sorted()
        let c: String
        if hashedExtensions.isEmpty && signatureAlgorithms.isEmpty {
            c = "000000000000"
        } else {
            let extString = hashedExtensions.map(hex4).joined(separator: ",")
            let sigString = signatureAlgorithms.map(hex4).joined(separator: ",")
            c = sha256Prefix12("\(extString)_\(sigString)")
        }

        return "\(a)_\(b)_\(c)"
    }
}

extension TLSServerHello {
    /// The JA4S TLS server fingerprint (FoxIO spec), e.g.
    /// `t120400_c02f_<12hex>`.
    ///
    /// The `b` section is the chosen cipher (not a hash); the `c` section
    /// hashes the server's extensions in the order they appear (not sorted).
    public var ja4s: String {
        let version = supportedVersion ?? legacyVersion
        let extCount = String(format: "%02d", min(extensionTypes.count, 99))
        let alpn: String
        if let selected = alpnProtocol, let firstChar = selected.first, let lastChar = selected.last {
            alpn = "\(firstChar)\(lastChar)"
        } else {
            alpn = "00"
        }
        let a = "t\(ja4Version(version))\(extCount)\(alpn)"
        let b = hex4(cipherSuite)
        let c =
            extensionTypes.isEmpty
            ? "000000000000"
            : sha256Prefix12(extensionTypes.map(hex4).joined(separator: ","))
        return "\(a)_\(b)_\(c)"
    }
}

extension SSHKEXInit {
    /// The HASSH fingerprint of an SSH client's KEXINIT: the MD5 of
    /// `kex;ciphers;macs;compression` using the client-to-server lists.
    public var hassh: String {
        md5Hex(
            [
                kexAlgorithms.joined(separator: ","),
                encryptionAlgorithmsClientToServer.joined(separator: ","),
                macAlgorithmsClientToServer.joined(separator: ","),
                compressionAlgorithmsClientToServer.joined(separator: ","),
            ].joined(separator: ";"))
    }

    /// The HASSH-Server fingerprint of an SSH server's KEXINIT: the MD5 of
    /// `kex;ciphers;macs;compression` using the server-to-client lists.
    public var hasshServer: String {
        md5Hex(
            [
                kexAlgorithms.joined(separator: ","),
                encryptionAlgorithmsServerToClient.joined(separator: ","),
                macAlgorithmsServerToClient.joined(separator: ","),
                compressionAlgorithmsServerToClient.joined(separator: ","),
            ].joined(separator: ";"))
    }
}

extension ConnectionKey {
    /// The Community ID flow hash (v1) for this connection, given its L4
    /// protocol. Deterministic and direction-insensitive, matching Zeek /
    /// Suricata so flows correlate across tools.
    ///
    /// - Parameters:
    ///   - proto: the IP protocol (TCP/UDP/SCTP contribute ports; others do
    ///     not).
    ///   - seed: the Community ID seed (default 0).
    public func communityID(proto: IPProtocol, seed: UInt16 = 0) -> String {
        // The connection key is already canonicalized so the lesser endpoint is
        // first — the ordering Community ID requires.
        var bytes = [UInt8]()
        bytes.append(UInt8(seed >> 8))
        bytes.append(UInt8(seed & 0xFF))
        bytes += network.source.bytes
        bytes += network.destination.bytes
        bytes.append(proto.rawValue)
        bytes.append(0)  // padding

        let portBearing: Set<IPProtocol> = [.tcp, .udp, .sctp, .udpLite]
        if portBearing.contains(proto), let transport,
            let sourcePort = transport.source.port, let destinationPort = transport.destination.port
        {
            bytes.append(UInt8(sourcePort >> 8))
            bytes.append(UInt8(sourcePort & 0xFF))
            bytes.append(UInt8(destinationPort >> 8))
            bytes.append(UInt8(destinationPort & 0xFF))
        }

        let digest = Insecure.SHA1.hash(data: Data(bytes))
        return "1:" + Data(digest).base64EncodedString()
    }
}

extension Packet {
    /// The Community ID flow hash (v1) for this packet's connection, or `nil`
    /// if it has no IP layer. Uses the packet's own L4 protocol.
    public func communityID(seed: UInt16 = 0) -> String? {
        guard let connectionKey, let proto = ipProtocol else { return nil }
        return connectionKey.communityID(proto: proto, seed: seed)
    }
}
