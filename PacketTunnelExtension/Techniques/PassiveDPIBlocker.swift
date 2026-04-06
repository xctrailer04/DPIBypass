import Foundation

/// Passive DPI detection and blocking
/// Drops TCP RST and HTTP 302 redirect packets injected by DPI systems
/// Ported from GoodbyeDPI's passive DPI detection in goodbyedpi.c
enum PassiveDPIBlocker {

    /// Check if an inbound packet is a DPI-injected HTTP 302 redirect
    /// GoodbyeDPI: is_passivedpi_redirect()
    static func isDPIRedirect(_ packet: ParsedPacket) -> Bool {
        guard packet.isTCP,
              packet.srcPort == 80,
              packet.payload.count >= 16 else { return false }

        let payload = [UInt8](packet.payload)

        // Check for "HTTP/1.0 302" or "HTTP/1.1 302" response
        let http10_302 = Array("HTTP/1.0 302".utf8)
        let http11_302 = Array("HTTP/1.1 302".utf8)

        let prefixMatch: Bool
        if payload.count >= http10_302.count {
            prefixMatch = payload.prefix(http10_302.count).elementsEqual(http10_302) ||
                          payload.prefix(http11_302.count).elementsEqual(http11_302)
        } else {
            return false
        }

        guard prefixMatch else { return false }

        // Heuristic: DPI-injected 302 redirects have low IP ID (0x0000-0x000F)
        // GoodbyeDPI checks: ip_id == 0x0000 || ip_id == 0x000F
        // We ONLY drop if IP ID is suspicious — don't drop legitimate 302s
        let ipId = packet.ipHeader.identification
        return ipId <= 0x000F
    }

    /// Check if an inbound packet is a DPI-injected TCP RST
    /// GoodbyeDPI drops RSTs with IP ID 0x0000 from port 80/443
    static func isDPIReset(_ packet: ParsedPacket) -> Bool {
        guard packet.isTCP,
              let tcp = packet.tcpHeader,
              tcp.isRST else { return false }

        // Check if from HTTP/HTTPS port
        guard packet.srcPort == 80 || packet.srcPort == 443 else { return false }

        // DPI RST packets often have IP ID of 0
        let ipId = packet.ipHeader.identification
        return ipId == 0x0000 || ipId <= 0x000F
    }

    /// Check if packet is QUIC (UDP port 443) — for blocking
    static func isQUIC(_ packet: ParsedPacket) -> Bool {
        guard packet.isUDP, packet.dstPort == 443, !packet.payload.isEmpty else { return false }

        let firstByte = packet.payload[packet.payload.startIndex]
        // QUIC v1: Long header (bit 7 set) or Short header (bit 6 set)
        return (firstByte & 0x80) != 0 || (firstByte & 0x40) != 0
    }

    /// Determine if a packet should be dropped
    static func shouldDrop(_ packet: ParsedPacket, config: DPIConfiguration) -> (drop: Bool, reason: String) {
        if config.blockPassiveDPI {
            if isDPIRedirect(packet) {
                return (true, "DPI HTTP 302 redirect blocked")
            }
            if isDPIReset(packet) {
                return (true, "DPI TCP RST blocked")
            }
        }

        if config.blockQUIC && isQUIC(packet) {
            return (true, "QUIC blocked (forcing TCP fallback)")
        }

        return (false, "")
    }
}
