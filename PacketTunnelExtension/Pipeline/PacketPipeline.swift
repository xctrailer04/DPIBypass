import Foundation
import NetworkExtension

/// Main packet processing pipeline
/// Orchestrates all DPI bypass techniques
/// This is the equivalent of GoodbyeDPI's main loop in goodbyedpi.c (lines 1175-1562)
class PacketPipeline {

    private var config: DPIConfiguration
    private let dnsRedirector: DNSRedirector
    private var stats = TunnelStatistics()
    private let startTime = Date()

    init(config: DPIConfiguration) {
        self.config = config
        self.dnsRedirector = DNSRedirector(
            dnsServer: config.dnsServer,
            dnsPort: config.dnsPort
        )
    }

    func updateConfig(_ newConfig: DPIConfiguration) {
        self.config = newConfig
    }

    // MARK: - Main Processing

    /// Process a packet from the TUN interface
    /// Returns: array of packets to send (may be fragmented into multiple)
    /// Returns nil if packet should be dropped
    func processPacket(_ data: Data, isOutbound: Bool) -> [Data]? {
        stats.totalPackets += 1

        guard let packet = PacketParser.parse(data) else {
            // Can't parse — pass through unmodified
            return [data]
        }

        if isOutbound {
            return processOutbound(data, packet: packet)
        } else {
            return processInbound(data, packet: packet)
        }
    }

    // MARK: - Outbound Processing

    private func processOutbound(_ data: Data, packet: ParsedPacket) -> [Data]? {

        // 1. DNS Redirection
        if config.dnsRedirectEnabled && packet.isDNS {
            if let modified = dnsRedirector.handleOutgoing(data, packet: packet) {
                stats.dnsRedirected += 1
                return [modified]
            }
        }

        // 2. QUIC Blocking (drop outbound UDP 443)
        if config.blockQUIC && PassiveDPIBlocker.isQUIC(packet) {
            stats.passiveDPIBlocked += 1
            return nil // DROP
        }

        // 3. HTTP tricks (port 80)
        if packet.isHTTP && !packet.payload.isEmpty {
            return processOutboundHTTP(data, packet: packet)
        }

        // 4. HTTPS/TLS tricks (port 443)
        if packet.isHTTPS && !packet.payload.isEmpty {
            return processOutboundHTTPS(data, packet: packet)
        }

        // 5. Pass through unmodified
        return [data]
    }

    /// Process outbound HTTP (port 80)
    /// Apply Host header manipulation and fragmentation
    private func processOutboundHTTP(_ data: Data, packet: ParsedPacket) -> [Data] {
        guard HTTPParser.isHTTPRequest(packet.payload) else { return [data] }
        guard let httpInfo = HTTPParser.parse(packet.payload) else { return [data] }

        // Check blacklist if enabled
        if config.useBlacklist && !config.blacklistedDomains.isEmpty {
            if !isBlacklisted(httpInfo.hostValue) {
                return [data] // Not in blacklist, pass through
            }
        }

        // Apply HTTP host manipulation
        let modifiedPayload = HTTPHostManipulation.apply(
            payload: packet.payload,
            httpInfo: httpInfo,
            config: config
        )

        stats.httpModified += 1
        stats.modifiedPackets += 1

        // Fragment if enabled
        if config.httpFragmentSize > 0 {
            let fragments = TCPFragmentation.fragment(
                payload: modifiedPayload,
                size: config.httpFragmentSize
            )
            return rebuildPacketsFromFragments(
                originalData: data,
                packet: packet,
                payloadFragments: fragments
            )
        }

        // Single modified packet
        return [rebuildPacket(originalData: data, packet: packet, newPayload: modifiedPayload)]
    }

    /// Process outbound HTTPS/TLS (port 443)
    /// Apply SNI fragmentation
    private func processOutboundHTTPS(_ data: Data, packet: ParsedPacket) -> [Data] {
        guard config.httpsFragmentEnabled else { return [data] }
        guard TLSParser.isClientHello(packet.payload) else { return [data] }

        // Try to fragment
        guard let result = SNIFragmentation.fragment(payload: packet.payload, config: config) else {
            return [data]
        }

        // Check blacklist
        if config.useBlacklist && !config.blacklistedDomains.isEmpty {
            if !isBlacklisted(result.hostname) {
                return [data]
            }
        }

        stats.httpsFragmented += 1
        stats.modifiedPackets += 1

        return rebuildPacketsFromFragments(
            originalData: data,
            packet: packet,
            payloadFragments: result.fragments
        )
    }

    // MARK: - Inbound Processing

    private func processInbound(_ data: Data, packet: ParsedPacket) -> [Data]? {

        // 1. DNS response handling (restore original source)
        if config.dnsRedirectEnabled && packet.isUDP {
            if let modified = dnsRedirector.handleIncoming(data, packet: packet) {
                return [modified]
            }
        }

        // 2. Passive DPI blocking (drop injected 302/RST)
        let (shouldDrop, _) = PassiveDPIBlocker.shouldDrop(packet, config: config)
        if shouldDrop {
            stats.passiveDPIBlocked += 1
            return nil // DROP
        }

        // 3. Pass through
        return [data]
    }

    // MARK: - Packet Reconstruction

    /// Rebuild a single packet with modified payload
    private func rebuildPacket(originalData: Data, packet: ParsedPacket, newPayload: Data) -> Data {
        var bytes = [UInt8](originalData)

        // Replace payload portion
        let payloadStart = packet.payloadOffset
        bytes.removeSubrange(payloadStart..<bytes.count)
        bytes.append(contentsOf: newPayload)

        // Update IP total length
        let totalLength = UInt16(bytes.count)
        bytes[2] = UInt8(totalLength >> 8)
        bytes[3] = UInt8(totalLength & 0xFF)

        // Recalculate checksums
        var result = Data(bytes)
        ChecksumCalculator.recalculateChecksums(&result)
        return result
    }

    /// Build multiple IP packets from payload fragments
    /// Each fragment becomes a separate TCP segment with correct seq numbers
    private func rebuildPacketsFromFragments(
        originalData: Data,
        packet: ParsedPacket,
        payloadFragments: [Data]
    ) -> [Data] {
        guard payloadFragments.count > 1, let tcp = packet.tcpHeader else {
            // Can't fragment or single fragment — just rebuild
            if let first = payloadFragments.first {
                return [rebuildPacket(originalData: originalData, packet: packet, newPayload: first)]
            }
            return [originalData]
        }

        var packets: [Data] = []
        var currentSeq = tcp.seqNumber

        for (index, fragment) in payloadFragments.enumerated() {
            var bytes = [UInt8](originalData.prefix(packet.payloadOffset))

            // Append fragment payload
            bytes.append(contentsOf: fragment)

            // Update IP total length
            let totalLength = UInt16(bytes.count)
            bytes[2] = UInt8(totalLength >> 8)
            bytes[3] = UInt8(totalLength & 0xFF)

            // Update TCP sequence number
            let tcpOffset = packet.ipHeader.headerLength
            bytes[tcpOffset + 4] = UInt8((currentSeq >> 24) & 0xFF)
            bytes[tcpOffset + 5] = UInt8((currentSeq >> 16) & 0xFF)
            bytes[tcpOffset + 6] = UInt8((currentSeq >> 8) & 0xFF)
            bytes[tcpOffset + 7] = UInt8(currentSeq & 0xFF)

            // Set PSH flag only on last fragment
            if index < payloadFragments.count - 1 {
                bytes[tcpOffset + 13] &= ~TCPHeader.PSH // Clear PSH
            }

            // Recalculate checksums
            var result = Data(bytes)
            ChecksumCalculator.recalculateChecksums(&result)
            packets.append(result)

            // Advance sequence number (wrapping addition for TCP seq space)
            currentSeq = currentSeq &+ UInt32(fragment.count)
        }

        return packets
    }

    // MARK: - Blacklist

    private func isBlacklisted(_ hostname: String) -> Bool {
        let domain = hostname.lowercased()
        return config.blacklistedDomains.contains { listed in
            let listed = listed.lowercased()
            return domain == listed || domain.hasSuffix("." + listed)
        }
    }

    // MARK: - Statistics

    func getStatistics() -> TunnelStatistics {
        var s = stats
        s.uptime = Date().timeIntervalSince(startTime)
        return s
    }
}
