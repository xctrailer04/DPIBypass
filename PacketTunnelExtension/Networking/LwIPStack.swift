import Foundation
import Network

// MARK: - Global C callbacks (cannot capture context)

private func lwipOutputCallback(_ data: UnsafeRawPointer?, _ len: Int32) {
    guard let data = data, len > 0 else { return }
    let packetData = Data(bytes: data, count: Int(len))
    LwIPStack.shared.outputBlock?([packetData], [NSNumber(value: AF_INET)])
}

/// Called when lwIP receives TCP data from the app (via TUN → lwIP → here)
/// We need to forward this to the correct TCPRelay so it gets sent to the real server
private func lwipTCPRecvCallback(_ srcIP: UnsafePointer<CChar>?, _ srcPort: Int32,
                                  _ dstIP: UnsafePointer<CChar>?, _ dstPort: Int32,
                                  _ data: UnsafeRawPointer?, _ len: Int32) {
    guard let srcIP = srcIP, let dstIP = dstIP, let data = data, len > 0 else { return }
    let host = String(cString: dstIP)
    let port = UInt16(dstPort)
    let payload = Data(bytes: data, count: Int(len))

    // Find the relay for this destination and forward data
    LwIPStack.shared.forwardToRelay(host: host, port: port, data: payload)
}

/// Called when lwIP accepts a new TCP connection from the TUN
private func lwipTCPAcceptCallback(_ srcIP: UnsafePointer<CChar>?, _ srcPort: Int32,
                                    _ dstIP: UnsafePointer<CChar>?, _ dstPort: Int32) {
    // Connection tracking is already handled in LwIPStack.input()
    // when we detect SYN packets. This callback is for additional notification.
}

/// lwIP userspace TCP/IP stack wrapper for iOS
class LwIPStack {

    static let shared = LwIPStack()

    /// GCD queue — ALL lwIP calls must happen on this single queue (not thread-safe)
    let queue = DispatchQueue(label: "com.voiplet.dpibypass.lwip", qos: .userInteractive)

    /// Output block: sends raw IP packets back to TUN
    var outputBlock: (([Data], [NSNumber]) -> Void)?

    private var timer: DispatchSourceTimer?

    /// Active TCP relays keyed by 5-tuple
    private var relays: [String: TCPRelay] = [:]

    /// Connection ID counter for lwIP pcb tracking
    private var nextConnectionID: Int32 = 1

    /// Maximum concurrent relays (memory protection)
    private let maxRelays = 200

    /// DPI bypass configuration — use updateConfig() for thread-safe writes
    private var _config = DPIConfiguration()
    var config: DPIConfiguration {
        get { queue.sync { _config } }
    }

    func updateConfig(_ newConfig: DPIConfiguration) {
        queue.async { [weak self] in
            self?._config = newConfig
        }
    }

    // MARK: - Initialization

    func initialize() {
        queue.async { [weak self] in
            self?.setupStack()
            self?.startTimer()
            print("[lwIP] Stack initialized")
        }
    }

    private func setupStack() {
        lwip_bridge_init()
        lwip_bridge_set_output_callback(lwipOutputCallback)
        lwip_bridge_set_tcp_recv_callback(lwipTCPRecvCallback)
        lwip_bridge_set_tcp_accept_callback(lwipTCPAcceptCallback)
    }

    /// Forward TCP data from lwIP to the correct TCPRelay
    /// Called from the global C callback on the lwIP queue
    func forwardToRelay(host: String, port: UInt16, data: Data) {
        // Find relay by destination
        for (_, relay) in relays {
            if relay.host == host && relay.port == port {
                relay.sendToServer(data)
                return
            }
        }
    }

    private func startTimer() {
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer?.schedule(deadline: .now(), repeating: .milliseconds(250))
        timer?.setEventHandler { [weak self] in
            lwip_bridge_check_timeouts()
            self?.cleanup()
        }
        timer?.resume()
    }

    func shutdown() {
        queue.sync {
            timer?.cancel()
            timer = nil
            for relay in relays.values { relay.disconnect() }
            relays.removeAll()
        }
    }

    // MARK: - Packet Input (TUN → lwIP)

    func input(packet: Data) {
        queue.async { [weak self] in
            guard let self = self else { return }

            if let parsed = PacketParser.parse(packet), parsed.isTCP {
                if let tcp = parsed.tcpHeader, tcp.isSYN && !tcp.isACK {
                    self.createRelay(for: parsed)
                }
            }

            packet.withUnsafeBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                lwip_bridge_input(base, Int32(packet.count))
            }
        }
    }

    // MARK: - TCP Relay Management

    private func createRelay(for packet: ParsedPacket) {
        let key = makeRelayKey(packet)
        guard relays[key] == nil else { return }
        guard relays.count < maxRelays else {
            print("[lwIP] Max relay limit reached (\(maxRelays)), dropping new connection")
            return
        }

        let dstIP = packet.ipHeader.dstIP
        let host = "\(dstIP.0).\(dstIP.1).\(dstIP.2).\(dstIP.3)"
        let connID = nextConnectionID
        nextConnectionID &+= 1

        let relay = TCPRelay(
            host: host,
            port: packet.dstPort,
            config: _config,
            queue: queue
        )
        relay.onOutput = { data in
            data.withUnsafeBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                lwip_bridge_tcp_write(connID, base, Int32(data.count))
            }
        }
        relay.connect()
        relays[key] = relay
    }

    /// Remove disconnected relays
    private func cleanup() {
        let before = relays.count
        relays = relays.filter { !$0.value.isClosed }
        let removed = before - relays.count
        if removed > 0 {
            print("[lwIP] Cleaned up \(removed) closed relays, active: \(relays.count)")
        }
    }

    // MARK: - Helpers

    private func makeRelayKey(_ packet: ParsedPacket) -> String {
        let s = packet.ipHeader.srcIP
        let d = packet.ipHeader.dstIP
        return "\(s.0).\(s.1).\(s.2).\(s.3):\(packet.srcPort)-\(d.0).\(d.1).\(d.2).\(d.3):\(packet.dstPort)"
    }
}
