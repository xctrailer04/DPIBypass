import Foundation

/// TLS ClientHello parser — extracts SNI (Server Name Indication)
/// Ported from GoodbyeDPI's extract_sni() in goodbyedpi.c lines 435-476
enum TLSParser {

    struct SNIResult {
        let hostname: String
        let sniOffset: Int      // Byte offset of SNI value in payload
        let sniLength: Int      // Length of SNI hostname
        let recordLength: Int   // Full TLS record length
    }

    /// Check if payload is a TLS ClientHello
    static func isClientHello(_ payload: Data) -> Bool {
        guard payload.count >= 6 else { return false }
        let bytes = [UInt8](payload)

        // Content type: Handshake (0x16)
        guard bytes[0] == 0x16 else { return false }

        // Version: TLS 1.0 (0x0301), 1.1 (0x0302), 1.2 (0x0303), 1.3 (0x0301 in record layer)
        guard bytes[1] == 0x03 && (bytes[2] >= 0x01 && bytes[2] <= 0x03) else { return false }

        // Handshake type: ClientHello (0x01)
        guard bytes[5] == 0x01 else { return false }

        return true
    }

    /// Extract SNI from TLS ClientHello
    /// Returns the hostname and byte offset within the payload
    static func extractSNI(from payload: Data) -> SNIResult? {
        guard isClientHello(payload) else { return nil }
        let bytes = [UInt8](payload)
        guard bytes.count >= 44 else { return nil }

        // TLS Record header (5 bytes):
        //   [0] Content type (0x16 = Handshake)
        //   [1-2] Version
        //   [3-4] Record length
        let recordLength = Int(bytes[3]) << 8 | Int(bytes[4])

        // Handshake header (4 bytes at offset 5):
        //   [5] Handshake type (0x01 = ClientHello)
        //   [6-8] Handshake length (3 bytes)
        var offset = 5 + 4  // Skip record header + handshake header = offset 9

        // Client version (2 bytes)
        offset += 2  // offset 11

        // Client random (32 bytes)
        offset += 32  // offset 43

        // Session ID
        guard offset < bytes.count else { return nil }
        let sessionIDLen = Int(bytes[offset])
        offset += 1 + sessionIDLen

        // Cipher Suites
        guard offset + 2 <= bytes.count else { return nil }
        let cipherSuitesLen = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        offset += 2 + cipherSuitesLen

        // Compression Methods
        guard offset + 1 <= bytes.count else { return nil }
        let compressionLen = Int(bytes[offset])
        offset += 1 + compressionLen

        // Extensions
        guard offset + 2 <= bytes.count else { return nil }
        let extensionsLen = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        offset += 2

        let extensionsEnd = min(offset + extensionsLen, bytes.count)

        // Walk extensions to find SNI (type 0x0000)
        while offset + 4 <= extensionsEnd {
            let extType = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            let extLen = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
            offset += 4

            if extType == 0x0000 { // SNI extension
                // SNI extension format:
                //   [0-1] Server Name list length
                //   [2] Server Name type (0x00 = hostname)
                //   [3-4] Server Name length
                //   [5...] Server Name value
                guard offset + 5 <= extensionsEnd else { return nil }
                let nameType = bytes[offset + 2]
                guard nameType == 0x00 else { return nil } // Must be hostname

                let nameLen = Int(bytes[offset + 3]) << 8 | Int(bytes[offset + 4])
                let nameStart = offset + 5
                guard nameStart + nameLen <= extensionsEnd else { return nil }

                let hostname = String(bytes: Array(bytes[nameStart..<nameStart + nameLen]), encoding: .ascii) ?? ""

                return SNIResult(
                    hostname: hostname,
                    sniOffset: nameStart,
                    sniLength: nameLen,
                    recordLength: recordLength + 5 // +5 for TLS record header
                )
            }

            offset += extLen
        }

        return nil
    }
}
