import Foundation

// MARK: - IP Header Structures

/// Parsed IPv4 header
struct IPv4Header {
    var version: UInt8          // Always 4
    var ihl: UInt8              // Header length in 32-bit words
    var totalLength: UInt16
    var identification: UInt16
    var flags: UInt8
    var fragmentOffset: UInt16
    var ttl: UInt8
    var proto: UInt8            // 6=TCP, 17=UDP
    var headerChecksum: UInt16
    var srcIP: (UInt8, UInt8, UInt8, UInt8)
    var dstIP: (UInt8, UInt8, UInt8, UInt8)
    var headerLength: Int       // in bytes

    static let PROTO_TCP: UInt8 = 6
    static let PROTO_UDP: UInt8 = 17
}

/// Parsed TCP header
struct TCPHeader {
    var srcPort: UInt16
    var dstPort: UInt16
    var seqNumber: UInt32
    var ackNumber: UInt32
    var dataOffset: UInt8       // Header length in 32-bit words
    var flags: UInt8
    var windowSize: UInt16
    var checksum: UInt16
    var urgentPointer: UInt16
    var headerLength: Int       // in bytes

    // TCP Flags
    static let FIN: UInt8 = 0x01
    static let SYN: UInt8 = 0x02
    static let RST: UInt8 = 0x04
    static let PSH: UInt8 = 0x08
    static let ACK: UInt8 = 0x10
    static let URG: UInt8 = 0x20

    var isSYN: Bool { flags & Self.SYN != 0 }
    var isACK: Bool { flags & Self.ACK != 0 }
    var isRST: Bool { flags & Self.RST != 0 }
    var isPSH: Bool { flags & Self.PSH != 0 }
    var isFIN: Bool { flags & Self.FIN != 0 }
    var isSYNACK: Bool { isSYN && isACK }
}

/// Parsed UDP header
struct UDPHeader {
    var srcPort: UInt16
    var dstPort: UInt16
    var length: UInt16
    var checksum: UInt16
    static let headerSize = 8
}

/// Complete parsed packet
struct ParsedPacket {
    var rawData: Data
    var ipHeader: IPv4Header
    var tcpHeader: TCPHeader?
    var udpHeader: UDPHeader?
    var payloadOffset: Int      // Byte offset where payload starts
    var payload: Data           // TCP/UDP payload data

    var isTCP: Bool { tcpHeader != nil }
    var isUDP: Bool { udpHeader != nil }
    var dstPort: UInt16 { tcpHeader?.dstPort ?? udpHeader?.dstPort ?? 0 }
    var srcPort: UInt16 { tcpHeader?.srcPort ?? udpHeader?.srcPort ?? 0 }

    var isHTTP: Bool { isTCP && dstPort == 80 }
    var isHTTPS: Bool { isTCP && dstPort == 443 }
    var isDNS: Bool { isUDP && dstPort == 53 }
    var isQUIC: Bool { isUDP && dstPort == 443 }
}

// MARK: - PacketParser

enum PacketParser {

    /// Parse raw IP packet data into a ParsedPacket
    static func parse(_ data: Data) -> ParsedPacket? {
        guard data.count >= 20 else { return nil }

        // Check IP version
        let versionByte = data[data.startIndex]
        let version = (versionByte >> 4) & 0x0F
        guard version == 4 else { return nil } // IPv4 only for now

        return parseIPv4(data)
    }

    // MARK: - IPv4

    private static func parseIPv4(_ data: Data) -> ParsedPacket? {
        guard data.count >= 20 else { return nil }

        let bytes = [UInt8](data)

        let ihl = bytes[0] & 0x0F
        let headerLen = Int(ihl) * 4
        guard headerLen >= 20, data.count >= headerLen else { return nil }

        let ipHeader = IPv4Header(
            version: 4,
            ihl: ihl,
            totalLength: UInt16(bytes[2]) << 8 | UInt16(bytes[3]),
            identification: UInt16(bytes[4]) << 8 | UInt16(bytes[5]),
            flags: bytes[6] >> 5,
            fragmentOffset: (UInt16(bytes[6] & 0x1F) << 8) | UInt16(bytes[7]),
            ttl: bytes[8],
            proto: bytes[9],
            headerChecksum: UInt16(bytes[10]) << 8 | UInt16(bytes[11]),
            srcIP: (bytes[12], bytes[13], bytes[14], bytes[15]),
            dstIP: (bytes[16], bytes[17], bytes[18], bytes[19]),
            headerLength: headerLen
        )

        // Parse transport layer
        let transportStart = headerLen

        if ipHeader.proto == IPv4Header.PROTO_TCP {
            guard let tcp = parseTCP(bytes, offset: transportStart) else { return nil }
            let payloadOffset = transportStart + tcp.headerLength
            let payload = payloadOffset < bytes.count ? Data(bytes[payloadOffset...]) : Data()
            return ParsedPacket(
                rawData: data,
                ipHeader: ipHeader,
                tcpHeader: tcp,
                udpHeader: nil,
                payloadOffset: payloadOffset,
                payload: payload
            )
        } else if ipHeader.proto == IPv4Header.PROTO_UDP {
            guard let udp = parseUDP(bytes, offset: transportStart) else { return nil }
            let payloadOffset = transportStart + UDPHeader.headerSize
            let payload = payloadOffset < bytes.count ? Data(bytes[payloadOffset...]) : Data()
            return ParsedPacket(
                rawData: data,
                ipHeader: ipHeader,
                tcpHeader: nil,
                udpHeader: udp,
                payloadOffset: payloadOffset,
                payload: payload
            )
        }

        return nil
    }

    // MARK: - TCP

    private static func parseTCP(_ bytes: [UInt8], offset: Int) -> TCPHeader? {
        guard offset + 20 <= bytes.count else { return nil }

        let o = offset
        let dataOffset = (bytes[o + 12] >> 4) & 0x0F
        let headerLen = Int(dataOffset) * 4
        guard headerLen >= 20, offset + headerLen <= bytes.count else { return nil }

        return TCPHeader(
            srcPort: UInt16(bytes[o]) << 8 | UInt16(bytes[o + 1]),
            dstPort: UInt16(bytes[o + 2]) << 8 | UInt16(bytes[o + 3]),
            seqNumber: UInt32(bytes[o + 4]) << 24 | UInt32(bytes[o + 5]) << 16 |
                       UInt32(bytes[o + 6]) << 8 | UInt32(bytes[o + 7]),
            ackNumber: UInt32(bytes[o + 8]) << 24 | UInt32(bytes[o + 9]) << 16 |
                       UInt32(bytes[o + 10]) << 8 | UInt32(bytes[o + 11]),
            dataOffset: dataOffset,
            flags: bytes[o + 13],
            windowSize: UInt16(bytes[o + 14]) << 8 | UInt16(bytes[o + 15]),
            checksum: UInt16(bytes[o + 16]) << 8 | UInt16(bytes[o + 17]),
            urgentPointer: UInt16(bytes[o + 18]) << 8 | UInt16(bytes[o + 19]),
            headerLength: headerLen
        )
    }

    // MARK: - UDP

    private static func parseUDP(_ bytes: [UInt8], offset: Int) -> UDPHeader? {
        guard offset + 8 <= bytes.count else { return nil }

        let o = offset
        return UDPHeader(
            srcPort: UInt16(bytes[o]) << 8 | UInt16(bytes[o + 1]),
            dstPort: UInt16(bytes[o + 2]) << 8 | UInt16(bytes[o + 3]),
            length: UInt16(bytes[o + 4]) << 8 | UInt16(bytes[o + 5]),
            checksum: UInt16(bytes[o + 6]) << 8 | UInt16(bytes[o + 7])
        )
    }
}
