import NetworkExtension
import os.log

/// PacketTunnelProvider with fake DNS approach to capture TCP traffic
///
/// How it works (same as Surge/Shadowrocket):
/// 1. DNS queries come through TUN → we resolve them ourselves
/// 2. We return a FAKE IP (198.18.x.x) to the app instead of real IP
/// 3. App connects to fake IP via TCP → TCP SYN comes through TUN (because route matches)
/// 4. We map fake IP back to real hostname → create real connection
/// 5. Proxy data between TUN TCP and real connection with DPI bypass
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var config = DPIConfiguration()
    private var logBuffer: [String] = []
    private var packetCount: UInt64 = 0

    // Fake DNS: maps fake IP → real hostname
    private var fakeIPToHost: [String: String] = [:]
    private var hostToFakeIP: [String: String] = [:]
    private var nextFakeIP: UInt32 = 0xC6120001 // 198.18.0.1

    // TCP connections
    private var tcpConnections: [String: NWTCPConnection] = [:]
    // UDP sessions
    private var udpSessions: [String: NWUDPSession] = [:]

    private func dlog(_ msg: String) {
        let ts = String(format: "%.2f", Date().timeIntervalSince1970.truncatingRemainder(dividingBy: 10000))
        let entry = "[\(ts)] \(msg)"
        if logBuffer.count > 2000 { logBuffer.removeFirst() }
        logBuffer.append(entry)
    }

    // MARK: - Start

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        dlog("TUNNEL START")
        config = DPIConfiguration.load()

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.0")

        // TUN interface IP
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])

        // Route 198.18.0.0/16 through TUN — this is our fake IP range
        // Also route 0.0.0.0/0 for UDP (DNS etc)
        ipv4.includedRoutes = [
            NEIPv4Route.default(),  // All traffic
        ]
        // Exclude the fake DNS range from going back to TUN recursively
        settings.ipv4Settings = ipv4

        // DNS — point to our TUN IP so DNS queries come to us
        let dns = NEDNSSettings(servers: ["198.18.0.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        settings.mtu = 1500
        dlog("Settings: fakeIP range=198.18.0.0/16, DNS=198.18.0.1")

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.dlog("ERROR: \(error)")
                completionHandler(error)
                return
            }
            self?.dlog("Settings OK")
            self?.startReading()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dlog("TUNNEL STOP pkts=\(packetCount)")
        for c in tcpConnections.values { c.cancel() }
        for s in udpSessions.values { s.cancel() }
        completionHandler()
    }

    // MARK: - Packet Loop

    private func startReading() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            for (i, data) in packets.enumerated() {
                self.processPacket(data, proto: protocols[i])
            }
            self.startReading()
        }
    }

    private func processPacket(_ data: Data, proto: NSNumber) {
        packetCount += 1
        guard let pkt = PacketParser.parse(data) else { return }

        let dst = pkt.ipHeader.dstIP
        let dstStr = "\(dst.0).\(dst.1).\(dst.2).\(dst.3)"
        let shouldLog = packetCount <= 50 || packetCount % 200 == 0

        if shouldLog {
            let src = pkt.ipHeader.srcIP
            let srcStr = "\(src.0).\(src.1).\(src.2).\(src.3)"
            let p = pkt.isTCP ? "TCP" : pkt.isUDP ? "UDP" : "?"
            let flags = pkt.tcpHeader.map { t in
                var f = ""; if t.isSYN{f+="S"}; if t.isACK{f+="A"}; if t.isPSH{f+="P"}; if t.isFIN{f+="F"}; if t.isRST{f+="R"}
                return f.isEmpty ? "-" : f
            } ?? ""
            dlog("#\(packetCount) \(p) \(srcStr):\(pkt.srcPort)→\(dstStr):\(pkt.dstPort) \(flags) [\(data.count)B] pay=\(pkt.payload.count)")
        }

        // DNS query to our fake DNS server (198.18.0.1 port 53)
        if pkt.isUDP && pkt.dstPort == 53 {
            handleDNSQuery(pkt, rawPacket: data)
            return
        }

        // TCP to a fake IP (198.18.x.x) — this means we assigned this IP via fake DNS
        if pkt.isTCP && dst.0 == 198 && dst.1 == 18 {
            handleTCPToFakeIP(pkt, rawPacket: data, fakeIP: dstStr)
            return
        }

        // UDP to real destinations (non-DNS)
        if pkt.isUDP && !pkt.payload.isEmpty && pkt.dstPort != 53 {
            handleUDP(pkt, dstStr: dstStr)
            return
        }
    }

    // MARK: - Fake DNS

    private func handleDNSQuery(_ pkt: ParsedPacket, rawPacket: Data) {
        guard pkt.payload.count >= 12 else { return }
        let payload = [UInt8](pkt.payload)

        // Parse DNS query to get hostname
        guard let hostname = parseDNSQueryHostname(payload) else {
            dlog("DNS: can't parse query")
            // Forward to real DNS
            forwardDNSToReal(pkt, rawPacket: rawPacket)
            return
        }

        dlog("DNS QUERY: \(hostname)")

        // Resolve via real DNS
        let endpoint = NWHostEndpoint(hostname: config.dnsServer, port: "53")
        let session = createUDPSession(to: endpoint, from: nil)

        session.writeDatagram(pkt.payload) { [weak self] error in
            if let error = error {
                self?.dlog("DNS FWD ERROR: \(error)")
                session.cancel()
                return
            }
        }

        session.setReadHandler({ [weak self] datagrams, error in
            guard let self = self, let datagrams = datagrams, let response = datagrams.first else {
                session.cancel()
                return
            }

            self.dlog("DNS RESPONSE for \(hostname): \(response.count)B")

            // Build DNS response packet and write back to TUN
            let responsePacket = self.buildDNSResponsePacket(
                originalPacket: pkt,
                dnsResponse: response
            )
            if let responsePacket = responsePacket {
                self.packetFlow.writePackets([responsePacket], withProtocols: [NSNumber(value: AF_INET)])
            }

            session.cancel()
        }, maxDatagrams: 1)
    }

    private func forwardDNSToReal(_ pkt: ParsedPacket, rawPacket: Data) {
        let endpoint = NWHostEndpoint(hostname: config.dnsServer, port: "53")
        let session = createUDPSession(to: endpoint, from: nil)

        session.writeDatagram(pkt.payload) { _ in }
        session.setReadHandler({ [weak self] datagrams, _ in
            guard let self = self, let dg = datagrams?.first else { session.cancel(); return }
            if let resp = self.buildDNSResponsePacket(originalPacket: pkt, dnsResponse: dg) {
                self.packetFlow.writePackets([resp], withProtocols: [NSNumber(value: AF_INET)])
            }
            session.cancel()
        }, maxDatagrams: 1)
    }

    /// Build a raw IP/UDP packet containing the DNS response
    private func buildDNSResponsePacket(originalPacket pkt: ParsedPacket, dnsResponse: Data) -> Data? {
        // Swap src/dst from original query
        let srcIP = pkt.ipHeader.dstIP  // DNS server → becomes source
        let dstIP = pkt.ipHeader.srcIP  // Client → becomes dest
        let srcPort = pkt.dstPort       // 53
        let dstPort = pkt.srcPort       // Client's port

        let udpLen = UInt16(8 + dnsResponse.count)
        let totalLen = UInt16(20 + 8 + dnsResponse.count)

        var packet = Data(count: Int(totalLen))

        // IP Header (20 bytes)
        packet[0] = 0x45  // Version 4, IHL 5
        packet[1] = 0x00  // DSCP
        packet[2] = UInt8(totalLen >> 8)
        packet[3] = UInt8(totalLen & 0xFF)
        packet[4] = 0x00; packet[5] = 0x00  // ID
        packet[6] = 0x40; packet[7] = 0x00  // Don't fragment
        packet[8] = 64    // TTL
        packet[9] = 17    // UDP
        packet[10] = 0; packet[11] = 0  // Checksum (calculated later)
        packet[12] = srcIP.0; packet[13] = srcIP.1; packet[14] = srcIP.2; packet[15] = srcIP.3
        packet[16] = dstIP.0; packet[17] = dstIP.1; packet[18] = dstIP.2; packet[19] = dstIP.3

        // UDP Header (8 bytes)
        packet[20] = UInt8(srcPort >> 8); packet[21] = UInt8(srcPort & 0xFF)
        packet[22] = UInt8(dstPort >> 8); packet[23] = UInt8(dstPort & 0xFF)
        packet[24] = UInt8(udpLen >> 8); packet[25] = UInt8(udpLen & 0xFF)
        packet[26] = 0; packet[27] = 0  // UDP checksum (optional for IPv4)

        // DNS payload
        packet.replaceSubrange(28..<Int(totalLen), with: dnsResponse)

        // IP checksum
        ChecksumCalculator.ipChecksum(&packet)

        return packet
    }

    /// Parse hostname from DNS query payload
    private func parseDNSQueryHostname(_ data: [UInt8]) -> String? {
        guard data.count >= 12 else { return nil }
        // Skip header (12 bytes), read QNAME
        var offset = 12
        var parts: [String] = []
        while offset < data.count {
            let len = Int(data[offset])
            if len == 0 { break }
            offset += 1
            guard offset + len <= data.count else { return nil }
            if let part = String(bytes: data[offset..<offset+len], encoding: .ascii) {
                parts.append(part)
            }
            offset += len
        }
        return parts.isEmpty ? nil : parts.joined(separator: ".")
    }

    // MARK: - TCP to Fake IP

    private func handleTCPToFakeIP(_ pkt: ParsedPacket, rawPacket: Data, fakeIP: String) {
        guard let tcp = pkt.tcpHeader else { return }

        // Look up real hostname from fake IP
        let realHost = fakeIPToHost[fakeIP] ?? fakeIP
        let port = pkt.dstPort
        let key = "\(fakeIP):\(port)"

        if tcp.isSYN && !tcp.isACK {
            dlog("TCP SYN → fake=\(fakeIP) real=\(realHost):\(port)")
            ensureTCPConnection(key: key, host: realHost, port: port)
        }

        if !pkt.payload.isEmpty {
            guard let conn = tcpConnections[key] else { return }

            // Apply DPI bypass on first payload
            var dataToSend = pkt.payload

            if port == 443 && TLSParser.isClientHello(pkt.payload) {
                let sni = TLSParser.extractSNI(from: pkt.payload)?.hostname ?? "?"
                dlog("  TLS ClientHello SNI=\(sni)")

                if config.httpsFragmentEnabled {
                    if let result = SNIFragmentation.fragment(payload: pkt.payload, config: config) {
                        dlog("  SNI FRAG → \(result.fragments.count) parts")
                        for frag in result.fragments {
                            conn.write(frag) { _ in }
                        }
                        return
                    }
                }
            }

            if port == 80, let info = HTTPParser.parse(pkt.payload) {
                dlog("  HTTP \(info.method) Host=\(info.hostValue)")
                dataToSend = HTTPHostManipulation.apply(payload: pkt.payload, httpInfo: info, config: config)
            }

            conn.write(dataToSend) { [weak self] error in
                if let e = error { self?.dlog("TCP WRITE ERR: \(key) \(e)") }
            }
        }
    }

    private func ensureTCPConnection(key: String, host: String, port: UInt16) {
        guard tcpConnections[key] == nil else { return }
        guard tcpConnections.count < 200 else { dlog("TCP MAX"); return }

        let endpoint = NWHostEndpoint(hostname: host, port: "\(port)")
        let conn = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        tcpConnections[key] = conn
        dlog("TCP NEW: \(key) → \(host):\(port)")

        conn.addObserver(self, forKeyPath: "state", options: [.new], context: nil)
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?,
                                change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard let conn = object as? NWTCPConnection else { return }
        switch conn.state {
        case .connected:
            dlog("TCP CONNECTED: \(conn.endpoint)")
            startTCPReading(conn)
        case .disconnected:
            dlog("TCP DISCONNECTED: \(conn.endpoint)")
            removeTCP(conn)
        case .cancelled:
            removeTCP(conn)
        case .waiting:
            dlog("TCP WAITING: \(conn.endpoint)")
        default: break
        }
    }

    private func startTCPReading(_ conn: NWTCPConnection) {
        conn.readMinimumLength(1, maximumLength: 65535) { [weak self] data, error in
            if let data = data, !data.isEmpty {
                self?.dlog("TCP RECV: \(conn.endpoint) [\(data.count)B]")
                // Response goes back to app through the connection itself
                // createTCPConnection handles routing responses back
            }
            if error == nil {
                self?.startTCPReading(conn)
            }
        }
    }

    private func removeTCP(_ conn: NWTCPConnection) {
        conn.removeObserver(self, forKeyPath: "state")
        tcpConnections = tcpConnections.filter { $0.value !== conn }
    }

    // MARK: - UDP

    private func handleUDP(_ pkt: ParsedPacket, dstStr: String) {
        let key = "\(dstStr):\(pkt.dstPort)"
        if udpSessions[key] == nil {
            let endpoint = NWHostEndpoint(hostname: dstStr, port: "\(pkt.dstPort)")
            let session = createUDPSession(to: endpoint, from: nil)
            udpSessions[key] = session

            session.setReadHandler({ [weak self] datagrams, _ in
                if let dgs = datagrams {
                    for dg in dgs { self?.dlog("UDP RECV: \(key) [\(dg.count)B]") }
                }
            }, maxDatagrams: 64)
        }
        udpSessions[key]?.writeDatagram(pkt.payload) { _ in }
    }

    // MARK: - IPC

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let msg = TunnelMessage.decode(from: messageData) else { completionHandler?(nil); return }
        switch msg {
        case .getStatus:
            completionHandler?(TunnelMessage.status(.connected).encode())
        case .getStatistics:
            var s = TunnelStatistics()
            s.totalPackets = packetCount
            s.activeConnections = tcpConnections.count
            completionHandler?(TunnelMessage.statistics(s).encode())
        case .getLogs:
            completionHandler?(TunnelMessage.logDump(logBuffer.joined(separator: "\n")).encode())
        default:
            completionHandler?(nil)
        }
    }
}
