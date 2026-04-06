import NetworkExtension
import os.log

/// Main Packet Tunnel Provider — the heart of the extension
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.voiplet.dpibypass.tunnel", category: "PacketTunnel")
    private var config = DPIConfiguration()
    private var pipeline: PacketPipeline?
    private let lwipStack = LwIPStack.shared
    private let rstDropper = RSTDropper()

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting DPI Bypass tunnel", log: log, type: .info)

        config = DPIConfiguration.load()
        pipeline = PacketPipeline(config: config)

        let tunnelSettings = createTunnelSettings()

        setTunnelNetworkSettings(tunnelSettings) { [weak self] error in
            if let error = error {
                os_log("Failed to set tunnel settings: %{public}@", log: self?.log ?? .default, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }

            os_log("Tunnel settings applied", log: self?.log ?? .default, type: .info)

            // Initialize lwIP
            self?.lwipStack.updateConfig(self?.config ?? DPIConfiguration())
            self?.lwipStack.outputBlock = { [weak self] packets, protocols in
                self?.packetFlow.writePackets(packets, withProtocols: protocols)
            }
            self?.lwipStack.initialize()

            self?.startPacketProcessing()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping tunnel, reason: %{public}d", log: log, type: .info, reason.rawValue)
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
        }

        settings.mtu = 1500
        return settings
    }

    // MARK: - Packet Processing Loop

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
        guard config.isEnabled else {
            packetFlow.writePackets([data], withProtocols: [protocolFamily])
            return
        }

        let isOutbound = isOutboundPacket(data)

        if isOutbound {
            // Outbound: feed to lwIP → TCPRelay applies DPI bypass → BSD socket to server
            lwipStack.input(packet: data)
        } else {
            // Inbound: RST filtering + passive DPI blocking, then deliver to app
            if let packet = PacketParser.parse(data) {
                rstDropper.trackConnection(packet)
                if rstDropper.shouldDropRST(packet) { return }

                let result = PassiveDPIBlocker.shouldDrop(packet, config: config)
                if result.drop { return }
            }
            packetFlow.writePackets([data], withProtocols: [protocolFamily])
        }
    }

    // MARK: - Direction Detection

    private func isOutboundPacket(_ data: Data) -> Bool {
        guard data.count >= 20 else { return true }
        // If destination is our TUN IP (10.0.0.2) → inbound
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
            os_log("Configuration updated", log: log, type: .info)
            completionHandler?(nil)

        default:
            completionHandler?(nil)
        }
    }
}
