import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.voiplet.dpibypass.tunnel", category: "PacketTunnel")
    private var config = DPIConfiguration()
    private let lwipStack = LwIPStack.shared
    private let rstDropper = RSTDropper()

    // In-memory log buffer (no App Group dependency)
    private var logBuffer: [String] = []
    private let maxLogLines = 3000
    private var packetCount: UInt64 = 0
    private var droppedCount: UInt64 = 0

    private func dlog(_ msg: String) {
        let ts = String(format: "%.3f", Date().timeIntervalSince1970.truncatingRemainder(dividingBy: 100000))
        let entry = "[\(ts)] \(msg)"
        if logBuffer.count >= maxLogLines { logBuffer.removeFirst() }
        logBuffer.append(entry)
        os_log("%{public}@", log: log, type: .info, entry)
    }

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        dlog("========== TUNNEL START ==========")

        config = DPIConfiguration.load()
        dlog("Config: httpHost=\(config.httpHostReplace) httpsFrag=\(config.httpsFragmentEnabled) dns=\(config.dnsRedirectEnabled) dnsServer=\(config.dnsServer)")

        let settings = createTunnelSettings()

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.dlog("ERROR setTunnelNetworkSettings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }

            self?.dlog("Tunnel settings OK")

            // Init lwIP
            self?.dlog("Initializing lwIP...")
            self?.lwipStack.updateConfig(self?.config ?? DPIConfiguration())
            self?.lwipStack.outputBlock = { [weak self] packets, protocols in
                let sizes = packets.map { "\($0.count)" }.joined(separator: ",")
                self?.dlog("lwIP→TUN: \(packets.count) pkts sizes=[\(sizes)]")
                self?.packetFlow.writePackets(packets, withProtocols: protocols)
            }
            self?.lwipStack.initialize()
            self?.dlog("lwIP initialized")

            self?.startPacketProcessing()
            self?.dlog("Packet loop started")
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dlog("========== TUNNEL STOP reason=\(reason.rawValue) ==========")
        dlog("Final stats: packets=\(packetCount) dropped=\(droppedCount)")
        lwipStack.shutdown()
        completionHandler()
    }

    // MARK: - Settings

    private func createTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.255.255.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
        ]
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [config.dnsServer])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        settings.mtu = 1500
        return settings
    }

    // MARK: - Packet Processing

    private func startPacketProcessing() {
        readPacketsFromTUN()
    }

    private func readPacketsFromTUN() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            for (index, packetData) in packets.enumerated() {
                self.handlePacket(packetData, protocolFamily: protocols[index])
            }
            self.readPacketsFromTUN()
        }
    }

    private func handlePacket(_ data: Data, protocolFamily: NSNumber) {
        packetCount += 1
        let shouldLog = packetCount <= 30 || packetCount % 200 == 0

        let isOutbound = isOutboundPacket(data)

        if shouldLog, let pkt = PacketParser.parse(data) {
            let src = "\(pkt.ipHeader.srcIP.0).\(pkt.ipHeader.srcIP.1).\(pkt.ipHeader.srcIP.2).\(pkt.ipHeader.srcIP.3)"
            let dst = "\(pkt.ipHeader.dstIP.0).\(pkt.ipHeader.dstIP.1).\(pkt.ipHeader.dstIP.2).\(pkt.ipHeader.dstIP.3)"
            let p = pkt.isTCP ? "TCP" : (pkt.isUDP ? "UDP" : "?")
            let d = isOutbound ? "OUT" : "IN"
            dlog("#\(packetCount) \(d) \(p) \(src):\(pkt.srcPort)→\(dst):\(pkt.dstPort) [\(data.count)B]")

            if pkt.isHTTPS && pkt.isTCP && isOutbound && !pkt.payload.isEmpty {
                if TLSParser.isClientHello(pkt.payload) {
                    let sni = TLSParser.extractSNI(from: pkt.payload)?.hostname ?? "?"
                    dlog("  TLS ClientHello SNI=\(sni)")
                }
            }
        }

        if isOutbound {
            lwipStack.input(packet: data)
        } else {
            // Inbound: RST/302 filtering
            if let pkt = PacketParser.parse(data) {
                rstDropper.trackConnection(pkt)
                if rstDropper.shouldDropRST(pkt) {
                    dlog("DROPPED RST from \(pkt.srcPort)")
                    droppedCount += 1
                    return
                }
                let result = PassiveDPIBlocker.shouldDrop(pkt, config: config)
                if result.drop {
                    dlog("DROPPED: \(result.reason)")
                    droppedCount += 1
                    return
                }
            }
            packetFlow.writePackets([data], withProtocols: [protocolFamily])
        }
    }

    private func isOutboundPacket(_ data: Data) -> Bool {
        guard data.count >= 20 else { return true }
        return !(data[16] == 10 && data[17] == 0 && data[18] == 0 && data[19] == 2)
    }

    // MARK: - IPC

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let message = TunnelMessage.decode(from: messageData) else {
            completionHandler?(nil)
            return
        }

        switch message {
        case .getStatus:
            completionHandler?(TunnelMessage.status(.connected).encode())

        case .getStatistics:
            var stats = TunnelStatistics()
            stats.totalPackets = packetCount
            stats.passiveDPIBlocked = droppedCount
            completionHandler?(TunnelMessage.statistics(stats).encode())

        case .getLogs:
            let dump = logBuffer.joined(separator: "\n")
            completionHandler?(TunnelMessage.logDump(dump).encode())

        case .updateConfiguration(let newConfig):
            self.config = newConfig
            lwipStack.updateConfig(newConfig)
            dlog("CONFIG UPDATED via IPC")
            completionHandler?(nil)

        default:
            completionHandler?(nil)
        }
    }
}
