import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.voiplet.dpibypass.tunnel", category: "PacketTunnel")
    private let dlog = DebugLogger.shared
    private var config = DPIConfiguration()
    private var pipeline: PacketPipeline?
    private let lwipStack = LwIPStack.shared
    private let rstDropper = RSTDropper()
    private var packetCount: UInt64 = 0
    private var droppedCount: UInt64 = 0
    private var passedCount: UInt64 = 0

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        dlog.log("========== TUNNEL STARTING ==========")
        dlog.log("Config loaded: HTTP tricks=\(config.httpHostReplace), HTTPS frag=\(config.httpsFragmentEnabled), DNS=\(config.dnsRedirectEnabled)")

        config = DPIConfiguration.load()
        pipeline = PacketPipeline(config: config)

        let tunnelSettings = createTunnelSettings()
        dlog.log("Tunnel settings: DNS=\(config.dnsServer), routes=default")

        setTunnelNetworkSettings(tunnelSettings) { [weak self] error in
            if let error = error {
                self?.dlog.logError("setTunnelNetworkSettings failed: \(error.localizedDescription)")
                completionHandler(error)
                return
            }

            self?.dlog.log("Tunnel settings applied OK")
            self?.lwipStack.updateConfig(self?.config ?? DPIConfiguration())
            self?.lwipStack.outputBlock = { [weak self] packets, protocols in
                self?.dlog.log("lwIP OUTPUT: \(packets.count) packets, sizes=\(packets.map { $0.count })")
                self?.packetFlow.writePackets(packets, withProtocols: protocols)
            }
            self?.lwipStack.initialize()
            self?.dlog.log("lwIP initialized, starting packet processing")
            self?.startPacketProcessing()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dlog.log("========== TUNNEL STOPPING (reason=\(reason.rawValue)) ==========")
        dlog.log("Stats: total=\(packetCount), passed=\(passedCount), dropped=\(droppedCount)")
        dlog.flush()
        lwipStack.shutdown()
        completionHandler()
    }

    // MARK: - Tunnel Network Settings

    private func createTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.255.255.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
        ]
        settings.ipv4Settings = ipv4

        if config.dnsRedirectEnabled {
            let dns = NEDNSSettings(servers: [config.dnsServer])
            dns.matchDomains = [""]
            settings.dnsSettings = dns
            dlog.log("DNS configured: \(config.dnsServer)")
        }

        settings.mtu = 1500
        return settings
    }

    // MARK: - Packet Processing Loop

    private func startPacketProcessing() {
        dlog.log("Packet processing loop started")
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

        // Log every 100th packet summary + first 20 packets
        let shouldLog = packetCount <= 20 || packetCount % 100 == 0

        guard config.isEnabled else {
            if shouldLog { dlog.log("BYPASS OFF - passthrough pkt#\(packetCount) [\(data.count)B]") }
            packetFlow.writePackets([data], withProtocols: [protocolFamily])
            passedCount += 1
            return
        }

        let isOutbound = isOutboundPacket(data)

        // Parse for logging
        if let packet = PacketParser.parse(data) {
            let srcIP = "\(packet.ipHeader.srcIP.0).\(packet.ipHeader.srcIP.1).\(packet.ipHeader.srcIP.2).\(packet.ipHeader.srcIP.3)"
            let dstIP = "\(packet.ipHeader.dstIP.0).\(packet.ipHeader.dstIP.1).\(packet.ipHeader.dstIP.2).\(packet.ipHeader.dstIP.3)"
            let proto = packet.isTCP ? "TCP" : (packet.isUDP ? "UDP" : "OTHER")
            let dir = isOutbound ? "OUT" : "IN"
            let flags = packet.tcpHeader.map { tcp in
                var f = ""
                if tcp.isSYN { f += "S" }
                if tcp.isACK { f += "A" }
                if tcp.isPSH { f += "P" }
                if tcp.isFIN { f += "F" }
                if tcp.isRST { f += "R" }
                return f.isEmpty ? "-" : f
            } ?? "-"

            if shouldLog {
                dlog.log("\(dir) #\(packetCount) \(proto) \(srcIP):\(packet.srcPort)→\(dstIP):\(packet.dstPort) flags=\(flags) [\(data.count)B] payload=\(packet.payload.count)B")
            }

            // Detect specific traffic for detailed logging
            if packet.isHTTP && !packet.payload.isEmpty && isOutbound {
                if let httpInfo = HTTPParser.parse(packet.payload) {
                    dlog.log("  HTTP REQUEST: \(httpInfo.method) Host=\(httpInfo.hostValue)")
                }
            }
            if packet.isHTTPS && !packet.payload.isEmpty && isOutbound {
                if TLSParser.isClientHello(packet.payload) {
                    let sni = TLSParser.extractSNI(from: packet.payload)?.hostname ?? "unknown"
                    dlog.log("  TLS ClientHello SNI=\(sni)")
                }
            }
            if packet.isDNS {
                dlog.log("  DNS \(isOutbound ? "query" : "response") port=\(packet.dstPort)")
            }
        }

        if isOutbound {
            // Feed to lwIP
            if shouldLog { dlog.log("  → feeding to lwIP") }
            lwipStack.input(packet: data)
            passedCount += 1
        } else {
            // Inbound: RST filtering + passive DPI blocking
            if let packet = PacketParser.parse(data) {
                rstDropper.trackConnection(packet)

                if rstDropper.shouldDropRST(packet) {
                    dlog.log("  DROPPED: DPI RST detected")
                    droppedCount += 1
                    return
                }

                let result = PassiveDPIBlocker.shouldDrop(packet, config: config)
                if result.drop {
                    dlog.log("  DROPPED: \(result.reason)")
                    droppedCount += 1
                    return
                }
            }
            packetFlow.writePackets([data], withProtocols: [protocolFamily])
            passedCount += 1
        }
    }

    // MARK: - Direction Detection

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
            let response = TunnelMessage.status(.connected)
            completionHandler?(response.encode())

        case .getStatistics:
            let stats = pipeline?.getStatistics() ?? TunnelStatistics()
            let response = TunnelMessage.statistics(stats)
            completionHandler?(response.encode())

        case .updateConfiguration(let newConfig):
            self.config = newConfig
            pipeline?.updateConfig(newConfig)
            lwipStack.updateConfig(newConfig)
            dlog.log("CONFIG UPDATED via IPC")
            completionHandler?(nil)

        default:
            completionHandler?(nil)
        }
    }
}
