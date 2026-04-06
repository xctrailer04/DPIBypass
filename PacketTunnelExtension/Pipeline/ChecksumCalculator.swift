import Foundation

/// IP and TCP/UDP checksum calculation
/// Ported from GoodbyeDPI's checksum handling
enum ChecksumCalculator {

    // MARK: - IP Header Checksum

    /// Calculate IPv4 header checksum (RFC 1071)
    /// Sets checksum field to 0 before calculating
    static func ipChecksum(_ data: inout Data) {
        guard data.count >= 20 else { return }
        let ihl = Int(data[0] & 0x0F) * 4
        guard ihl >= 20, data.count >= ihl else { return }

        // Zero out existing checksum
        data[10] = 0
        data[11] = 0

        var sum: UInt32 = 0
        for i in stride(from: 0, to: ihl, by: 2) {
            let word = UInt32(data[i]) << 8 | UInt32(data[i + 1])
            sum += word
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }

        let checksum = ~UInt16(sum & 0xFFFF)
        data[10] = UInt8(checksum >> 8)
        data[11] = UInt8(checksum & 0xFF)
    }

    // MARK: - TCP Checksum

    /// Calculate TCP checksum with IPv4 pseudo-header
    static func tcpChecksum(_ data: inout Data, ipHeaderLength: Int) {
        guard data.count >= ipHeaderLength + 20 else { return }

        let tcpOffset = ipHeaderLength
        let tcpLength = data.count - ipHeaderLength

        // Zero out existing TCP checksum
        data[tcpOffset + 16] = 0
        data[tcpOffset + 17] = 0

        var sum: UInt32 = 0

        // Pseudo-header: src IP (4 bytes) + dst IP (4 bytes) + zero + protocol + TCP length
        // Source IP
        sum += UInt32(data[12]) << 8 | UInt32(data[13])
        sum += UInt32(data[14]) << 8 | UInt32(data[15])
        // Destination IP
        sum += UInt32(data[16]) << 8 | UInt32(data[17])
        sum += UInt32(data[18]) << 8 | UInt32(data[19])
        // Zero + Protocol (TCP = 6)
        sum += UInt32(IPv4Header.PROTO_TCP)
        // TCP Length
        sum += UInt32(tcpLength)

        // TCP header + data
        for i in stride(from: tcpOffset, to: data.count - 1, by: 2) {
            let word = UInt32(data[i]) << 8 | UInt32(data[i + 1])
            sum += word
        }
        // Handle odd byte
        if (data.count - tcpOffset) % 2 != 0 {
            sum += UInt32(data[data.count - 1]) << 8
        }

        // Fold
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }

        let checksum = ~UInt16(sum & 0xFFFF)
        data[tcpOffset + 16] = UInt8(checksum >> 8)
        data[tcpOffset + 17] = UInt8(checksum & 0xFF)
    }

    // MARK: - UDP Checksum

    /// Calculate UDP checksum with IPv4 pseudo-header
    static func udpChecksum(_ data: inout Data, ipHeaderLength: Int) {
        guard data.count >= ipHeaderLength + 8 else { return }

        let udpOffset = ipHeaderLength
        let udpLength = data.count - ipHeaderLength

        // Zero out existing UDP checksum
        data[udpOffset + 6] = 0
        data[udpOffset + 7] = 0

        var sum: UInt32 = 0

        // Pseudo-header
        sum += UInt32(data[12]) << 8 | UInt32(data[13])
        sum += UInt32(data[14]) << 8 | UInt32(data[15])
        sum += UInt32(data[16]) << 8 | UInt32(data[17])
        sum += UInt32(data[18]) << 8 | UInt32(data[19])
        sum += UInt32(IPv4Header.PROTO_UDP)
        sum += UInt32(udpLength)

        // UDP header + data
        for i in stride(from: udpOffset, to: data.count - 1, by: 2) {
            let word = UInt32(data[i]) << 8 | UInt32(data[i + 1])
            sum += word
        }
        if (data.count - udpOffset) % 2 != 0 {
            sum += UInt32(data[data.count - 1]) << 8
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }

        var checksum = ~UInt16(sum & 0xFFFF)
        if checksum == 0 { checksum = 0xFFFF } // UDP special case
        data[udpOffset + 6] = UInt8(checksum >> 8)
        data[udpOffset + 7] = UInt8(checksum & 0xFF)
    }

    // MARK: - Recalculate All

    /// Recalculate both IP and TCP/UDP checksums for a modified packet
    static func recalculateChecksums(_ data: inout Data) {
        guard data.count >= 20 else { return }
        let ihl = Int(data[0] & 0x0F) * 4
        let proto = data[9]

        ipChecksum(&data)

        if proto == IPv4Header.PROTO_TCP {
            tcpChecksum(&data, ipHeaderLength: ihl)
        } else if proto == IPv4Header.PROTO_UDP {
            udpChecksum(&data, ipHeaderLength: ihl)
        }
    }
}
