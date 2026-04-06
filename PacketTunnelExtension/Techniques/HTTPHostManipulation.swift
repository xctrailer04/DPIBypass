import Foundation

/// HTTP Host header manipulation techniques
/// Ported from GoodbyeDPI's HTTP modification logic in goodbyedpi.c
///
/// IMPORTANT: Operations that change byte count (insert/remove) must run LAST
/// to avoid invalidating offsets for other operations.
enum HTTPHostManipulation {

    /// Apply all enabled HTTP tricks to the payload
    /// Order matters: in-place modifications first, then size-changing ops
    static func apply(
        payload: Data,
        httpInfo: HTTPParser.HTTPInfo,
        config: DPIConfiguration
    ) -> Data {
        var bytes = [UInt8](payload)

        // Phase 1: In-place modifications (don't change array size)

        // 1. Replace "Host" with "hoSt" (GoodbyeDPI -r flag)
        if config.httpHostReplace {
            replaceHostHeader(&bytes, at: httpInfo.hostHeaderOffset)
        }

        // 2. Mix case of hostname (GoodbyeDPI -m flag)
        // Must run BEFORE removeSpace/addSpace which shift offsets
        if config.httpHostMixCase {
            mixCaseHostname(&bytes, offset: httpInfo.hostValueOffset, length: httpInfo.hostValueLength)
        }

        // Phase 2: Size-changing modifications (applied right-to-left by offset to preserve earlier offsets)
        // removeSpace is at hostHeaderOffset (~line 2+), addSpace is at methodEndOffset (~line 1)
        // Apply the one with the HIGHER offset first.

        // 3. Remove space after "Host:" (GoodbyeDPI -s flag)
        // This removes 1 byte, shifting everything after it left
        if config.httpHostRemoveSpace {
            let colonOffset = httpInfo.hostHeaderOffset + 2 + 4 // "\r\n" + "Host"
            if colonOffset + 2 <= bytes.count && bytes[colonOffset] == 0x3A && bytes[colonOffset + 1] == 0x20 {
                bytes.remove(at: colonOffset + 1)
            }
        }

        // 4. Add additional space after HTTP method (GoodbyeDPI -a flag)
        // This inserts 1 byte at a low offset — do it LAST
        if config.httpAdditionalSpace {
            let offset = httpInfo.methodEndOffset
            if offset > 0 && offset <= bytes.count {
                bytes.insert(0x20, at: offset)
            }
        }

        return Data(bytes)
    }

    // MARK: - Individual Techniques

    /// Replace "Host" with "hoSt"
    private static func replaceHostHeader(_ bytes: inout [UInt8], at offset: Int) {
        let hostNameStart = offset + 2 // skip "\r\n"
        guard hostNameStart + 4 <= bytes.count else { return }

        bytes[hostNameStart] = 0x68     // h
        bytes[hostNameStart + 1] = 0x6F // o
        bytes[hostNameStart + 2] = 0x53 // S
        bytes[hostNameStart + 3] = 0x74 // t
    }

    /// Mix case of hostname: "example.com" → "eXaMpLe.CoM"
    private static func mixCaseHostname(_ bytes: inout [UInt8], offset: Int, length: Int) {
        guard offset >= 0, offset + length <= bytes.count else { return }

        for i in 0..<length {
            let idx = offset + i
            let ch = bytes[idx]
            if ch >= 0x61 && ch <= 0x7A { // a-z
                if i % 2 == 1 { bytes[idx] = ch - 0x20 }
            } else if ch >= 0x41 && ch <= 0x5A { // A-Z
                if i % 2 == 0 { bytes[idx] = ch + 0x20 }
            }
        }
    }
}
