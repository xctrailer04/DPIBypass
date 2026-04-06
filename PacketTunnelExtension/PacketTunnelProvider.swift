import NetworkExtension
import os.log

/// Minimal PacketTunnelProvider — no lwIP, pure passthrough
/// Goal: verify extension actually starts and processes packets
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var logBuffer: [String] = []
    private var packetCount: UInt64 = 0

    private func dlog(_ msg: String) {
        let entry = "[\(Int(Date().timeIntervalSince1970) % 100000)] \(msg)"
        if logBuffer.count > 2000 { logBuffer.removeFirst() }
        logBuffer.append(entry)
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        dlog("TUNNEL START")

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.255.255.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
        ]
        settings.ipv4Settings = ipv4
        let dns = NEDNSSettings(servers: ["1.1.1.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.dlog("ERROR: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            self?.dlog("Settings OK, starting passthrough")
            self?.startPassthrough()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dlog("TUNNEL STOP")
        completionHandler()
    }

    private func startPassthrough() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            self.packetCount += UInt64(packets.count)
            if self.packetCount <= 10 || self.packetCount % 500 == 0 {
                self.dlog("PKT #\(self.packetCount) batch=\(packets.count)")
            }
            // Pass everything through unchanged
            self.packetFlow.writePackets(packets, withProtocols: protocols)
            self.startPassthrough()
        }
    }

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
            completionHandler?(TunnelMessage.statistics(stats).encode())
        case .getLogs:
            let dump = logBuffer.joined(separator: "\n")
            completionHandler?(TunnelMessage.logDump(dump).encode())
        default:
            completionHandler?(nil)
        }
    }
}
