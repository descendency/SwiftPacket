import Foundation

/// One HTTP header field.
public struct HTTPHeader: Sendable, Hashable {
    public let name: String
    public let value: String
}

/// How an HTTP message's body is delimited — the output a stream reassembler
/// needs to know where the body ends.
public enum HTTPBodyFraming: Sendable, Equatable {
    /// A fixed `Content-Length`.
    case length(Int)
    /// `Transfer-Encoding: chunked`.
    case chunked
    /// No delimiter; the body runs until the connection closes (responses only).
    case untilClose
    /// No body (e.g. a request without a body, or a 204/304 response).
    case none
}

/// A parsed HTTP/1.x message head — the start line and headers, plus how the
/// body that follows is framed.
///
/// This is a **stateless** framer: it parses one message's head from a byte
/// buffer. A stream consumer (which correlates requests with responses and
/// accumulates bodies) is layered on top — the framer itself keeps no state.
public struct HTTPMessage: Sendable {
    public enum Kind: Sendable, Equatable {
        /// A request: `method`, `target`, `version`.
        case request(method: String, target: String, version: String)
        /// A response: `version`, `statusCode`, `reason`.
        case response(version: String, statusCode: Int, reason: String)
    }

    public let kind: Kind
    public let headers: [HTTPHeader]
    /// The number of bytes the head occupies, including the terminating blank
    /// line — i.e. where the body begins.
    public let headerLength: Int
    /// How the body that follows the head is delimited.
    public let bodyFraming: HTTPBodyFraming

    /// The first header value with the given name (case-insensitive).
    public func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    /// The `Content-Length`, if present and valid.
    public var contentLength: Int? { header("Content-Length").flatMap { Int($0) } }
    /// The `Host` request header.
    public var host: String? { header("Host") }
    /// Whether the message is a request.
    public var isRequest: Bool { if case .request = kind { return true } else { return false } }
}

/// The outcome of framing an HTTP message from a buffer.
public enum HTTPParseResult: Sendable {
    /// The header block is not yet complete; feed more bytes.
    case incomplete
    /// The bytes are not a plausible HTTP/1.x message head.
    case notHTTP
    /// A parsed message head.
    case message(HTTPMessage)
}

/// A stateless HTTP/1.x message framer.
public enum HTTPFramer {
    /// Frames the HTTP message head at the start of `data`.
    public static func parse(_ data: Data) -> HTTPParseResult {
        guard let headerEnd = endOfHeaders(data) else { return .incomplete }
        let headEnd = data.startIndex + headerEnd
        let head = String(decoding: data[data.startIndex..<headEnd], as: UTF8.self)

        var lines = head.split(separator: "\r\n", omittingEmptySubsequences: false)
        // A trailing empty element from the final CRLF pair is expected.
        while lines.last?.isEmpty == true { lines.removeLast() }
        guard let startLine = lines.first else { return .notHTTP }

        guard let kind = parseStartLine(String(startLine)) else { return .notHTTP }

        var headers: [HTTPHeader] = []
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !name.isEmpty { headers.append(HTTPHeader(name: name, value: value)) }
        }

        let framing = bodyFraming(kind: kind, headers: headers)
        let message = HTTPMessage(
            kind: kind, headers: headers, headerLength: headerEnd + 4, bodyFraming: framing)
        return .message(message)
    }

    /// Finds the offset (from `data.startIndex`) of the `\r\n\r\n` that ends the
    /// header block, or `nil` if it is not present yet. The returned offset is
    /// the index of the first terminating `\r`.
    private static func endOfHeaders(_ data: Data) -> Int? {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else { return nil }
        var index = 0
        while index <= bytes.count - 4 {
            if bytes[index] == 0x0D, bytes[index + 1] == 0x0A,
                bytes[index + 2] == 0x0D, bytes[index + 3] == 0x0A
            {
                return index
            }
            index += 1
        }
        return nil
    }

    private static func parseStartLine(_ line: String) -> HTTPMessage.Kind? {
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }

        if parts[0].hasPrefix("HTTP/") {
            // Response: VERSION STATUS REASON
            guard let status = Int(parts[1]) else { return nil }
            return .response(version: String(parts[0]), statusCode: status, reason: String(parts[2]))
        }
        if parts[2].hasPrefix("HTTP/") {
            // Request: METHOD TARGET VERSION
            let method = String(parts[0])
            guard method.allSatisfy({ $0.isLetter }) else { return nil }
            return .request(method: method, target: String(parts[1]), version: String(parts[2]))
        }
        return nil
    }

    private static func bodyFraming(kind: HTTPMessage.Kind, headers: [HTTPHeader]) -> HTTPBodyFraming {
        func value(_ name: String) -> String? {
            headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
        if let te = value("Transfer-Encoding"), te.lowercased().contains("chunked") {
            return .chunked
        }
        if let cl = value("Content-Length"), let length = Int(cl) {
            return .length(length)
        }
        switch kind {
        case .request:
            // A request with neither header has no body.
            return .none
        case .response(_, let status, _):
            // 1xx, 204, and 304 responses carry no body.
            if (100..<200).contains(status) || status == 204 || status == 304 {
                return .none
            }
            return .untilClose
        }
    }
}
