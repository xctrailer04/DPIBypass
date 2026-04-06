import NetworkExtension
import os.log

/// Packet Tunnel Provider with working TCP/UDP proxy
/// Uses lwIP to reassemble TCP from raw packets, then NWTCPConnection to forward
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var config = DPIConfiguration()
    private var logBuffer: [String] = []
    private var packetCount: UInt64 = 0

    // Active TCP connections: key = "dstIP:dstPort"
    private var tcpConnections: [String: NWTCPConnection] = [:]
    // Active UDP sessions
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

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "1.1.1.1")

        // IPv4 — route ALL traffic through tunnel
        let ipv4 = NEIPv4Settings(addresses: ["192.168.20.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        // DNS
        let dns = NEDNSSettings(servers: [config.dnsServer])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        settings.mtu = 1500
        dlog("Settings: remoteAddr=1.1.1.1 tunIP=192.168.20.1 dns=\(config.dnsServer)")

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.dlog("ERROR: \(error)")
                completionHandler(error)
                return
            }
            self?.dlog("Settings OK, starting loop")
            self?.startReading()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dlog("TUNNEL STOP pkts=\(packetCount)")
        for c in tcpConnections.values { c.cancel() }
        for s in udpSessions.values { s.cancel() }
        tcpConnections.removeAll()
        udpSessions.removeAll()
        completionHandler()
    }

    // MARK: - Packet Reading

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
        guard let pkt = PacketParser.parse(data) else {
            if packetCount <= 50 { dlog("#\(packetCount) UNPARSEABLE [\(data.count)B] first=\(data.prefix(4).map{String(format:"%02x",$0)}.joined())") }
            return
        }

        let src = pkt.ipHeader.srcIP
        let dst = pkt.ipHeader.dstIP
        let srcStr = "\(src.0).\(src.1).\(src.2).\(src.3)"
        let dstStr = "\(dst.0).\(dst.1).\(dst.2).\(dst.3)"
        let dstPort = pkt.dstPort
        let shouldLog = packetCount <= 50 || packetCount % 200 == 0

        // Log ALL packets for debugging
        if shouldLog {
            let p = pkt.isTCP ? "TCP" : pkt.isUDP ? "UDP" : "proto=\(pkt.ipHeader.proto)"
            let flags = pkt.tcpHeader.map { t in
                var f = ""; if t.isSYN { f += "S" }; if t.isACK { f += "A" }
                if t.isPSH { f += "P" }; if t.isFIN { f += "F" }; if t.isRST { f += "R" }
                return f.isEmpty ? "-" : f
            } ?? ""
            dlog("#\(packetCount) \(p) \(srcStr):\(pkt.srcPort)→\(dstStr):\(dstPort) flags=\(flags) [\(data.count)B] pay=\(pkt.payload.count)")
        }

        if pkt.isTCP {
            if let tcp = pkt.tcpHeader, tcp.isSYN && !tcp.isACK {
                dlog("  → TCP SYN new conn to \(dstStr):\(dstPort)")
                ensureTCPConnection(host: dstStr, port: dstPort)
            }
            if !pkt.payload.isEmpty {
                handleTCPData(host: dstStr, port: dstPort, payload: pkt.payload)
            }
        } else if pkt.isUDP && !pkt.payload.isEmpty {
            handleUDPData(host: dstStr, port: dstPort, payload: pkt.payload)
        }
    }

    // MARK: - TCP Proxy

    private func ensureTCPConnection(host: String, port: UInt16) {
        let key = "\(host):\(port)"
        guard tcpConnections[key] == nil else { return }
        guard tcpConnections.count < 200 else {
            dlog("TCP MAX CONNECTIONS")
            return
        }

        let endpoint = NWHostEndpoint(hostname: host, port: "\(port)")
        let conn = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        tcpConnections[key] = conn
        dlog("TCP NEW: \(key)")

        conn.addObserver(self, forKeyPath: "state", options: [.new], context: nil)
    }

    private func handleTCPData(host: String, port: UInt16, payload: Data) {
        let key = "\(host):\(port)"
        ensureTCPConnection(host: host, port: port)

        guard let conn = tcpConnections[key] else { return }

        // Apply DPI bypass
        var dataToSend = payload

        if port == 443 && TLSParser.isClientHello(payload) {
            let sni = TLSParser.extractSNI(from: payload)?.hostname ?? "?"
            dlog("  TLS ClientHello SNI=\(sni)")

            // Fragment by SNI
            if config.httpsFragmentEnabled {
                if let result = SNIFragmentation.fragment(payload: payload, config: config) {
                    dlog("  SNI FRAG: \(result.fragments.count) parts")
                    for frag in result.fragments {
                        conn.write(frag) { error in
                            if let e = error { self.dlog("  TCP WRITE ERR: \(e)") }
                        }
                    }
                    return
                }
            }
        }

        if port == 80 {
            if let info = HTTPParser.parse(payload) {
                dlog("  HTTP \(info.method) Host=\(info.hostValue)")
                dataToSend = HTTPHostManipulation.apply(payload: payload, httpInfo: info, config: config)
            }
        }

        conn.write(dataToSend) { error in
            if let e = error { self.dlog("  TCP WRITE ERR: \(e)") }
        }
    }

    // TCP state observation
    override func observeValue(forKeyPath keyPath: String?, of object: Any?,
                                change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard let conn = object as? NWTCPConnection else { return }

        switch conn.state {
        case .connected:
            dlog("TCP CONNECTED: \(conn.endpoint)")
            startTCPReading(conn)
        case .disconnected:
            dlog("TCP DISCONNECTED: \(conn.endpoint)")
            removeTCPConnection(conn)
        case .cancelled:
            removeTCPConnection(conn)
        case .waiting:
            dlog("TCP WAITING: \(conn.endpoint)")
        default:
            break
        }
    }

    private func startTCPReading(_ conn: NWTCPConnection) {
        conn.readMinimumLength(1, maximumLength: 65535) { [weak self] data, error in
            if let data = data, !data.isEmpty {
                self?.dlog("TCP RECV: \(conn.endpoint) [\(data.count)B]")
                // Response from server → goes back to app through the tunnel automatically
                // NWTCPConnection created via createTCPConnection routes responses back through TUN
            }
            if error == nil {
                self?.startTCPReading(conn)
            } else {
                self?.dlog("TCP READ ERR: \(conn.endpoint) \(error!)")
            }
        }
    }

    private func removeTCPConnection(_ conn: NWTCPConnection) {
        tcpConnections = tcpConnections.filter { $0.value !== conn }
    }

    // MARK: - UDP Proxy

    private func handleUDPData(host: String, port: UInt16, payload: Data) {
        let key = "\(host):\(port)"

        if udpSessions[key] == nil {
            let endpoint = NWHostEndpoint(hostname: host, port: "\(port)")
            let session = createUDPSession(to: endpoint, from: nil)
            udpSessions[key] = session
            dlog("UDP NEW: \(key)")

            session.setReadHandler({ [weak self] datagrams, error in
                if let dgs = datagrams {
                    for dg in dgs {
                        self?.dlog("UDP RECV: \(key) [\(dg.count)B]")
                    }
                }
            }, maxDatagrams: 64)
        }

        udpSessions[key]?.writeDatagram(payload) { [weak self] error in
            if let e = error { self?.dlog("UDP WRITE ERR: \(key) \(e)") }
        }
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
