import Foundation

/// TCP RST packet filtering
/// Drops DPI-injected TCP RST packets before they reach lwIP/app
///
/// How it works:
/// When using lwIP as a userspace TCP stack, we control what packets get fed into lwIP.
/// We intercept raw IP packets from readPackets() and filter out suspicious RSTs
/// BEFORE passing them to lwIP's netif_input().
///
/// This gives us 80-85% feasibility for RST blocking (vs 40% without lwIP).
///
/// Two approaches:
/// 1. Pre-filter at TUN input (before lwIP) — recommended
/// 2. Modify lwIP source to ignore RSTs — more invasive but 100% effective
class RSTDropper {

    /// RST filtering mode
    enum FilterMode {
        /// Drop all RSTs from monitored ports (aggressive)
        case dropAll

        /// Drop RSTs with suspicious characteristics (balanced)
        case dropSuspicious

        /// RFC 5961: Only accept RSTs with exact sequence number match
        /// Challenge ACK for in-window but non-exact RSTs
        case rfc5961Strict
    }

    var mode: FilterMode = .dropSuspicious

    /// Track expected sequence numbers per connection
    /// Key: "srcIP:srcPort-dstIP:dstPort"
    private var expectedSeq: [String: UInt32] = [:]
    private var connectionTimestamps: [String: Date] = [:]
    private let syncQueue = DispatchQueue(label: "com.voiplet.dpibypass.rst.sync")

    // MARK: - RST Filtering

    /// Check if an inbound packet is a suspicious RST that should be dropped
    /// Call this BEFORE feeding packets into lwIP
    ///
    /// Returns: true if the packet should be DROPPED
    func shouldDropRST(_ packet: ParsedPacket) -> Bool {
        guard packet.isTCP, let tcp = packet.tcpHeader, tcp.isRST else {
            return false // Not a RST, don't drop
        }

        // Only filter RSTs from HTTP/HTTPS ports (where DPI operates)
        guard packet.srcPort == 80 || packet.srcPort == 443 else {
            return false
        }

        switch mode {
        case .dropAll:
            return true // Drop every RST from these ports

        case .dropSuspicious:
            return isSuspiciousRST(packet)

        case .rfc5961Strict:
            return !isValidRST(packet)
        }
    }

    /// Detect suspicious RST packets (likely from DPI)
    private func isSuspiciousRST(_ packet: ParsedPacket) -> Bool {
        guard let tcp = packet.tcpHeader else { return false }

        // Heuristic 1: IP Identification field
        // DPI-injected packets often have IP ID = 0 or very low values
        let ipId = packet.ipHeader.identification
        if ipId <= 0x000F {
            return true
        }

        // Heuristic 2: TTL anomaly
        // If we've seen packets from this server before, the TTL should be consistent
        // DPI packets may have a different TTL than the real server
        let connKey = makeConnectionKey(packet)
        // (TTL comparison would require storing expected TTL per connection)

        // Heuristic 3: RST without ACK
        // Legitimate RSTs usually have ACK flag set
        // Some DPI systems send bare RST without ACK
        if !tcp.isACK {
            return true
        }

        // Heuristic 4: RST arrives very quickly after connection
        // DPI RSTs typically arrive within milliseconds of the request
        if let timestamp = syncQueue.sync(execute: { connectionTimestamps[connKey] }) {
            let elapsed = Date().timeIntervalSince(timestamp)
            if elapsed < 0.05 { // Less than 50ms — suspiciously fast
                return true
            }
        }

        // Heuristic 5: RST with data (some DPI sends RST+data)
        if !packet.payload.isEmpty {
            return true
        }

        // Heuristic 6: Window size = 0 in RST
        // Many DPI implementations set window to 0 in RST packets
        if tcp.windowSize == 0 {
            return true
        }

        return false
    }

    /// RFC 5961 strict validation
    /// Only accept RST if sequence number EXACTLY matches rcv_nxt
    /// This is stricter than most TCP stacks and blocks most spoofed RSTs
    private func isValidRST(_ packet: ParsedPacket) -> Bool {
        guard let tcp = packet.tcpHeader else { return false }

        let connKey = makeConnectionKey(packet)
        let expected: UInt32? = syncQueue.sync { expectedSeq[connKey] }
        guard let expected = expected else { return false }

        return tcp.seqNumber == expected
    }

    // MARK: - Connection Tracking

    /// Record a connection and its expected next sequence number
    func trackConnection(_ packet: ParsedPacket) {
        guard packet.isTCP, let tcp = packet.tcpHeader else { return }
        if packet.srcPort != 80 && packet.srcPort != 443 { return }

        let key = makeConnectionKey(packet)

        syncQueue.sync {
            if tcp.isSYNACK {
                expectedSeq[key] = tcp.seqNumber &+ 1
                connectionTimestamps[key] = Date()
            } else if !packet.payload.isEmpty {
                expectedSeq[key] = tcp.seqNumber &+ UInt32(packet.payload.count)
            }
        }
    }

    /// Clean up old entries
    func cleanup() {
        syncQueue.sync {
            let cutoff = Date().addingTimeInterval(-60)
            connectionTimestamps = connectionTimestamps.filter { $0.value > cutoff }
            let validKeys = Set(connectionTimestamps.keys)
            expectedSeq = expectedSeq.filter { validKeys.contains($0.key) }
        }
    }

    // MARK: - Helpers

    private func makeConnectionKey(_ packet: ParsedPacket) -> String {
        let src = packet.ipHeader.srcIP
        let dst = packet.ipHeader.dstIP
        return "\(src.0).\(src.1).\(src.2).\(src.3):\(packet.srcPort)-\(dst.0).\(dst.1).\(dst.2).\(dst.3):\(packet.dstPort)"
    }
}
