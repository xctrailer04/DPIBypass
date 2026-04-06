import Foundation

/// DNS request redirection to alternative DNS servers
/// Ported from GoodbyeDPI's dnsredir.c
class DNSRedirector {

    /// Connection tracking entry (like conntrack_info_t in dnsredir.c)
    private struct ConntrackEntry {
        let srcIP: (UInt8, UInt8, UInt8, UInt8)
        let srcPort: UInt16
        let originalDstIP: (UInt8, UInt8, UInt8, UInt8)
        let originalDstPort: UInt16
        let timestamp: Date
    }

    /// Connection tracking table (keyed by src IP:port)
    /// Access must be synchronized via syncQueue
    private var conntrack: [String: ConntrackEntry] = [:]
    private let syncQueue = DispatchQueue(label: "com.voiplet.dpibypass.dns.sync")
    private let cleanupInterval: TimeInterval = 30
    private var lastCleanup = Date()

    private let targetDNSIP: (UInt8, UInt8, UInt8, UInt8)
    private let targetDNSPort: UInt16

    init(dnsServer: String, dnsPort: Int) {
        let parts = dnsServer.split(separator: ".").compactMap { UInt8($0) }
        if parts.count == 4 {
            targetDNSIP = (parts[0], parts[1], parts[2], parts[3])
        } else {
            targetDNSIP = (1, 1, 1, 1) // Default: Cloudflare
        }
        targetDNSPort = UInt16(dnsPort)
    }

    // MARK: - DNS Detection

    /// Check if payload is a DNS packet (like dns_is_dns_packet in dnsredir.c)
    static func isDNSPacket(_ payload: Data, isOutgoing: Bool) -> Bool {
        guard payload.count >= 12 else { return false }

        let bytes = [UInt8](payload)

        // DNS header: ID(2) + Flags(2) + Questions(2) + Answers(2) + ...
        let flags = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        let qr = (flags >> 15) & 1 // 0 = query, 1 = response

        if isOutgoing {
            return qr == 0 // Should be a query
        } else {
            return qr == 1 // Should be a response
        }
    }

    // MARK: - Outgoing DNS Handling

    /// Handle outgoing DNS request — redirect to alternative DNS server
    /// Returns modified packet data, or nil if no modification needed
    func handleOutgoing(_ data: Data, packet: ParsedPacket) -> Data? {
        guard packet.isUDP, packet.dstPort == 53 else { return nil }
        guard Self.isDNSPacket(packet.payload, isOutgoing: true) else { return nil }

        // Record the connection for response tracking
        let key = makeKey(ip: packet.ipHeader.srcIP, port: packet.srcPort)
        syncQueue.sync { conntrack[key] = ConntrackEntry(
            srcIP: packet.ipHeader.srcIP,
            srcPort: packet.srcPort,
            originalDstIP: packet.ipHeader.dstIP,
            originalDstPort: packet.dstPort,
            timestamp: Date()
        ) }

        // Modify destination IP to alternative DNS
        var modified = [UInt8](data)
        let ipHeaderLen = packet.ipHeader.headerLength

        // Replace destination IP (bytes 16-19 in IP header)
        modified[16] = targetDNSIP.0
        modified[17] = targetDNSIP.1
        modified[18] = targetDNSIP.2
        modified[19] = targetDNSIP.3

        // Replace destination port (bytes 2-3 in UDP header)
        modified[ipHeaderLen + 2] = UInt8(targetDNSPort >> 8)
        modified[ipHeaderLen + 3] = UInt8(targetDNSPort & 0xFF)

        // Recalculate checksums
        var result = Data(modified)
        ChecksumCalculator.recalculateChecksums(&result)

        // Periodic cleanup
        cleanupIfNeeded()

        return result
    }

    // MARK: - Incoming DNS Handling

    /// Handle incoming DNS response — restore original source IP/port
    /// Returns modified packet data, or nil if not a tracked DNS response
    func handleIncoming(_ data: Data, packet: ParsedPacket) -> Data? {
        guard packet.isUDP, packet.srcPort == targetDNSPort else { return nil }

        // Check source IP matches our target DNS
        let srcIP = packet.ipHeader.srcIP
        guard srcIP.0 == targetDNSIP.0 && srcIP.1 == targetDNSIP.1 &&
              srcIP.2 == targetDNSIP.2 && srcIP.3 == targetDNSIP.3 else { return nil }

        guard Self.isDNSPacket(packet.payload, isOutgoing: false) else { return nil }

        // Find the original destination from conntrack
        let key = makeKey(ip: packet.ipHeader.dstIP, port: packet.dstPort)
        guard let entry = syncQueue.sync(execute: { conntrack[key] }) else { return nil }

        // Restore original source IP/port
        var modified = [UInt8](data)
        let ipHeaderLen = packet.ipHeader.headerLength

        // Replace source IP to look like it came from original DNS
        modified[12] = entry.originalDstIP.0
        modified[13] = entry.originalDstIP.1
        modified[14] = entry.originalDstIP.2
        modified[15] = entry.originalDstIP.3

        // Replace source port
        modified[ipHeaderLen] = UInt8(entry.originalDstPort >> 8)
        modified[ipHeaderLen + 1] = UInt8(entry.originalDstPort & 0xFF)

        // Recalculate checksums
        var result = Data(modified)
        ChecksumCalculator.recalculateChecksums(&result)

        // Remove from conntrack
        syncQueue.sync { conntrack.removeValue(forKey: key) }

        return result
    }

    // MARK: - Helpers

    private func makeKey(ip: (UInt8, UInt8, UInt8, UInt8), port: UInt16) -> String {
        "\(ip.0).\(ip.1).\(ip.2).\(ip.3):\(port)"
    }

    private func cleanupIfNeeded() {
        syncQueue.sync {
            let now = Date()
            guard now.timeIntervalSince(lastCleanup) > cleanupInterval else { return }
            lastCleanup = now
            let cutoff = now.addingTimeInterval(-cleanupInterval)
            conntrack = conntrack.filter { $0.value.timestamp > cutoff }
        }
    }
}
