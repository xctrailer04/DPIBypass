import Foundation

/// HTTP request parser — finds Host header and HTTP methods
/// Ported from GoodbyeDPI's HTTP detection logic
enum HTTPParser {

    struct HTTPInfo {
        let method: String              // GET, POST, etc.
        let methodEndOffset: Int        // Offset after "GET "
        let hostHeaderOffset: Int       // Offset of "Host: " in payload
        let hostValueOffset: Int        // Offset of the hostname value
        let hostValue: String           // The hostname
        let hostValueLength: Int
    }

    /// HTTP methods to detect
    private static let httpMethods = ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT "]

    /// Check if TCP payload starts with an HTTP method
    static func isHTTPRequest(_ payload: Data) -> Bool {
        guard payload.count >= 4 else { return false }
        let prefix = String(data: payload.prefix(10), encoding: .ascii) ?? ""
        return httpMethods.contains(where: { prefix.hasPrefix($0) })
    }

    /// Parse HTTP request to find Host header
    static func parse(_ payload: Data) -> HTTPInfo? {
        guard payload.count >= 16 else { return nil }
        guard let text = String(data: payload, encoding: .ascii) else { return nil }

        // Find HTTP method
        var method = ""
        var methodEndOffset = 0
        for m in httpMethods {
            if text.hasPrefix(m) {
                method = String(m.dropLast()) // Remove trailing space
                methodEndOffset = m.count
                break
            }
        }
        guard !method.isEmpty else { return nil }

        // Find Host header (case-insensitive search like GoodbyeDPI)
        // Search for "\r\nHost: " pattern
        guard let hostRange = findHeader(in: payload, name: "Host") else { return nil }

        let hostValueOffset = hostRange.valueOffset
        let hostValue = extractHeaderValue(from: payload, offset: hostValueOffset)

        return HTTPInfo(
            method: method,
            methodEndOffset: methodEndOffset,
            hostHeaderOffset: hostRange.headerOffset,
            hostValueOffset: hostValueOffset,
            hostValue: hostValue,
            hostValueLength: hostValue.count
        )
    }

    // MARK: - Header Finding

    private struct HeaderLocation {
        let headerOffset: Int   // Offset of "\r\n" before header name
        let valueOffset: Int    // Offset of header value (after ": ")
    }

    /// Find a header in HTTP payload by name
    /// Searches for "\r\nName: " pattern (similar to GoodbyeDPI's dumb_memmem)
    private static func findHeader(in data: Data, name: String) -> HeaderLocation? {
        let bytes = [UInt8](data)
        let pattern = Array(("\r\n" + name + ": ").utf8)

        // Find end of HTTP headers (\r\n\r\n) to avoid matching in body
        let headerEnd = findEndOfHeaders(bytes) ?? bytes.count

        // Search only within headers
        for i in 0..<min(bytes.count - pattern.count, headerEnd) {
            var matched = true
            for j in 0..<pattern.count {
                // Case-insensitive comparison for the header name part
                let a = bytes[i + j]
                let b = pattern[j]
                if a != b {
                    // Allow case-insensitive match for letters
                    if j >= 2 && j < 2 + name.count { // Within header name
                        let aLower = a | 0x20
                        let bLower = b | 0x20
                        if aLower != bLower || aLower < 0x61 || aLower > 0x7A {
                            matched = false
                            break
                        }
                    } else {
                        matched = false
                        break
                    }
                }
            }
            if matched {
                return HeaderLocation(
                    headerOffset: i,
                    valueOffset: i + pattern.count
                )
            }
        }
        return nil
    }

    /// Find end of HTTP headers (\r\n\r\n)
    private static func findEndOfHeaders(_ bytes: [UInt8]) -> Int? {
        let pattern: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A] // \r\n\r\n
        for i in 0..<(bytes.count - 3) {
            if bytes[i] == pattern[0] && bytes[i+1] == pattern[1] &&
               bytes[i+2] == pattern[2] && bytes[i+3] == pattern[3] {
                return i
            }
        }
        return nil
    }

    /// Extract header value until \r\n
    private static func extractHeaderValue(from data: Data, offset: Int) -> String {
        let bytes = [UInt8](data)
        var end = offset
        while end < bytes.count - 1 {
            if bytes[end] == 0x0D && bytes[end + 1] == 0x0A { // \r\n
                break
            }
            end += 1
        }
        guard end > offset else { return "" }
        return String(bytes: Array(bytes[offset..<end]), encoding: .ascii) ?? ""
    }
}
