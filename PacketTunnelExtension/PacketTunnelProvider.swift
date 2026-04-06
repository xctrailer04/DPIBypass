import NetworkExtension
import os.log
import Darwin

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var config = DPIConfiguration()
    private var logBuffer: [String] = []
    private var packetCount: UInt64 = 0

    private var httpsFragCount: UInt64 = 0
    private var httpModCount: UInt64 = 0

    // TCP state tracking
    private struct TCPState {
        var conn: NWTCPConnection?
        var socketFD: Int32 = -1             // BSD socket for DPI bypass (TLS/HTTP first payload)
        var localSeq: UInt32 = arc4random()
        var remoteSeq: UInt32 = 0
        var connected: Bool = false
        var host: String
        var port: UInt16
        var firstPayload: Bool = true
        var srcIP: (UInt8, UInt8, UInt8, UInt8) = (0,0,0,0)
        var dstIP: (UInt8, UInt8, UInt8, UInt8) = (0,0,0,0)
        var srcPort: UInt16 = 0
        var dstPort: UInt16 = 0
    }

    private var tcpStates: [String: TCPState] = [:]
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
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let dns = NEDNSSettings(servers: ["198.18.0.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = 1500

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
        dlog("STOP pkts=\(packetCount)")
        for s in tcpStates.values { s.conn?.cancel() }
        for s in udpSessions.values { s.cancel() }
        completionHandler()
    }

    // MARK: - Packet Loop

    private func startReading() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            for (i, data) in packets.enumerated() { self.processPacket(data, proto: protocols[i]) }
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

        // DNS
        if pkt.isUDP && pkt.dstPort == 53 {
            handleDNS(pkt)
            return
        }

        // TCP
        if pkt.isTCP {
            handleTCP(pkt, dstStr: dstStr)
            return
        }

        // Other UDP
        if pkt.isUDP && !pkt.payload.isEmpty && pkt.dstPort != 53 {
            handleUDP(pkt, dstStr: dstStr)
        }
    }

    // MARK: - TCP with handshake simulation

    private func handleTCP(_ pkt: ParsedPacket, dstStr: String) {
        guard let tcp = pkt.tcpHeader else { return }
        let key = "\(pkt.ipHeader.srcIP.0).\(pkt.ipHeader.srcIP.1).\(pkt.ipHeader.srcIP.2).\(pkt.ipHeader.srcIP.3):\(pkt.srcPort)-\(dstStr):\(pkt.dstPort)"

        // SYN — new connection
        if tcp.isSYN && !tcp.isACK {
            dlog("TCP SYN → \(dstStr):\(pkt.dstPort)")

            var state = TCPState(host: dstStr, port: pkt.dstPort)
            state.remoteSeq = tcp.seqNumber &+ 1
            state.srcIP = pkt.ipHeader.srcIP
            state.dstIP = pkt.ipHeader.dstIP
            state.srcPort = pkt.srcPort
            state.dstPort = pkt.dstPort

            // Send SYN+ACK back to app
            let synack = buildTCPPacket(
                srcIP: state.dstIP, dstIP: state.srcIP,
                srcPort: state.dstPort, dstPort: state.srcPort,
                seq: state.localSeq, ack: state.remoteSeq,
                flags: TCPHeader.SYN | TCPHeader.ACK,
                payload: Data(),
                isSYNACK: true
            )
            state.localSeq &+= 1
            packetFlow.writePackets([synack], withProtocols: [NSNumber(value: AF_INET)])
            dlog("  → SYN+ACK sent")

            // Create BSD socket (for DPI bypass) and NWTCPConnection (fallback)
            // BSD socket used for ports 80/443, NWTCPConnection for others
            if pkt.dstPort == 443 || pkt.dstPort == 80 {
                // BSD socket only — full control over TCP segments
                connectBSDSocket(&state)
            } else {
                let endpoint = NWHostEndpoint(hostname: dstStr, port: "\(pkt.dstPort)")
                let conn = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
                state.conn = conn
                conn.addObserver(self, forKeyPath: "state", options: [.new], context: nil)
            }
            tcpStates[key] = state
            return
        }

        // ACK (handshake completion or data ack)
        guard var state = tcpStates[key] else { return }

        // Data packet
        if !pkt.payload.isEmpty {
            state.remoteSeq = tcp.seqNumber &+ UInt32(pkt.payload.count)
            tcpStates[key] = state

            // Send ACK back to app
            let ack = buildTCPPacket(
                srcIP: state.dstIP, dstIP: state.srcIP,
                srcPort: state.dstPort, dstPort: state.srcPort,
                seq: state.localSeq, ack: state.remoteSeq,
                flags: TCPHeader.ACK,
                payload: Data()
            )
            packetFlow.writePackets([ack], withProtocols: [NSNumber(value: AF_INET)])

            // Forward to real server with DPI bypass
            var dataToSend = pkt.payload

            // BSD socket path (port 80/443)
            if state.socketFD >= 0 {
                var sendData = pkt.payload

                if state.firstPayload && pkt.dstPort == 443 && TLSParser.isClientHello(pkt.payload) {
                    let sni = TLSParser.extractSNI(from: pkt.payload)?.hostname ?? "?"
                    dlog("  TLS SNI=\(sni)")
                    if config.httpsFragmentEnabled,
                       let result = SNIFragmentation.fragment(payload: pkt.payload, config: config) {
                        dlog("  SNI FRAG → \(result.fragments.count) parts")
                        httpsFragCount += 1
                        let fd = state.socketFD
                        for (i, frag) in result.fragments.enumerated() {
                            let b = [UInt8](frag)
                            let sent = Darwin.send(fd, b, b.count, 0)
                            dlog("  FRAG[\(i)] sent \(sent)/\(b.count)B")
                            if i < result.fragments.count - 1 { usleep(1000) }
                        }
                        state.firstPayload = false
                        tcpStates[key] = state
                        return
                    }
                }

                if state.firstPayload && pkt.dstPort == 80, let info = HTTPParser.parse(pkt.payload) {
                    dlog("  HTTP Host=\(info.hostValue)")
                    sendData = HTTPHostManipulation.apply(payload: pkt.payload, httpInfo: info, config: config)
                    httpModCount += 1
                }

                state.firstPayload = false
                tcpStates[key] = state
                let b = [UInt8](sendData)
                Darwin.send(state.socketFD, b, b.count, 0)
                return
            }

            // NWTCPConnection path (other ports)
            state.firstPayload = false
            tcpStates[key] = state
            state.conn?.write(dataToSend) { [weak self] error in
                if let e = error { self?.dlog("TCP WRITE ERR: \(e)") }
            }
        }

        // FIN
        if tcp.isFIN {
            dlog("TCP FIN \(key)")
            state.conn?.cancel()
            tcpStates.removeValue(forKey: key)
        }
    }

    // MARK: - BSD Socket Connection (port 80/443)

    /// Create and connect BSD socket for DPI bypass
    private func connectBSDSocket(_ state: inout TCPState) {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { dlog("BSD SOCKET FAIL"); return }

        var noDelay: Int32 = 1
        Darwin.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, socklen_t(MemoryLayout<Int32>.size))

        // Bind to physical interface
        var ifindex = if_nametoindex("en0")
        if ifindex == 0 { ifindex = if_nametoindex("pdp_ip0") }
        if ifindex > 0 {
            var idx = ifindex
            Darwin.setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size))
        }

        // Non-blocking
        let flags = Darwin.fcntl(fd, F_GETFL, 0)
        Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = state.port.bigEndian
        inet_pton(AF_INET, state.host, &addr.sin_addr)

        withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        // EINPROGRESS is expected for non-blocking

        state.socketFD = fd
        dlog("BSD SOCKET \(fd): \(state.host):\(state.port)")

        // Start read loop on background queue
        let host = state.host
        let port = state.port
        let srcIP = state.srcIP
        let dstIP = state.dstIP
        let srcPort = state.srcPort
        let dstPort = state.dstPort

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // Wait for connect
            var writeSet = fd_set()
            withUnsafeMutablePointer(to: &writeSet) { ptr in
                __darwin_fd_zero(ptr)
                __darwin_fd_set(fd, ptr)
            }
            var timeout = timeval(tv_sec: 5, tv_usec: 0)
            let sel = select(fd + 1, nil, &writeSet, nil, &timeout)
            if sel <= 0 {
                self?.dlog("BSD CONNECT TIMEOUT: \(host):\(port)")
                Darwin.close(fd)
                return
            }

            var err: Int32 = 0
            var errLen = socklen_t(MemoryLayout<Int32>.size)
            Darwin.getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errLen)
            if err != 0 {
                self?.dlog("BSD CONNECT ERR: \(host):\(port) err=\(err)")
                Darwin.close(fd)
                return
            }

            self?.dlog("BSD CONNECTED: \(host):\(port)")

            // Read loop
            var buf = [UInt8](repeating: 0, count: 65535)
            while true {
                let n = Darwin.recv(fd, &buf, buf.count, 0)
                if n > 0 {
                    let data = Data(buf[0..<n])
                    self?.dlog("BSD RECV: \(host):\(port) [\(n)B]")
                    // Send to app via TUN
                    DispatchQueue.main.async {
                        self?.sendBSDDataToApp(host: host, port: port, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, data: data)
                    }
                } else if n == 0 {
                    self?.dlog("BSD CLOSED: \(host):\(port)")
                    break
                } else {
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        usleep(10000) // 10ms
                        continue
                    }
                    self?.dlog("BSD RECV ERR: \(host):\(port) errno=\(errno)")
                    break
                }
            }
            Darwin.close(fd)
        }
    }

    /// Write BSD socket data to TUN as TCP packets
    private func sendBSDDataToApp(host: String, port: UInt16, srcIP: (UInt8,UInt8,UInt8,UInt8), dstIP: (UInt8,UInt8,UInt8,UInt8), srcPort: UInt16, dstPort: UInt16, data: Data) {
        let lookupKey = "\(srcIP.0).\(srcIP.1).\(srcIP.2).\(srcIP.3):\(srcPort)-\(host):\(port)"
        guard var state = tcpStates[lookupKey] else {
            dlog("BSD→APP: state not found for \(lookupKey)")
            return
        }

        let mss = 1400
        var offset = 0
        var packets: [Data] = []
        while offset < data.count {
            let end = min(offset + mss, data.count)
            let chunk = data[offset..<end]
            let isLast = end >= data.count
            let flags: UInt8 = isLast ? (TCPHeader.ACK | TCPHeader.PSH) : TCPHeader.ACK
            let pkt = buildTCPPacket(
                srcIP: state.dstIP, dstIP: state.srcIP,
                srcPort: state.dstPort, dstPort: state.srcPort,
                seq: state.localSeq, ack: state.remoteSeq,
                flags: flags, payload: Data(chunk)
            )
            state.localSeq &+= UInt32(chunk.count)
            packets.append(pkt)
            offset = end
        }
        tcpStates[lookupKey] = state
        packetFlow.writePackets(packets, withProtocols: packets.map { _ in NSNumber(value: AF_INET) })
        dlog("BSD→APP: [\(data.count)B] \(packets.count) segs")
    }

    // TCP state observation
    override func observeValue(forKeyPath keyPath: String?, of object: Any?,
                                change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard let conn = object as? NWTCPConnection else { return }
        switch conn.state {
        case .connected:
            dlog("TCP REAL CONNECTED: \(conn.endpoint)")
            startTCPReading(conn)
        case .disconnected:
            dlog("TCP REAL DISCONN: \(conn.endpoint)")
            conn.removeObserver(self, forKeyPath: "state")
        case .cancelled:
            conn.removeObserver(self, forKeyPath: "state")
        default: break
        }
    }

    private func startTCPReading(_ conn: NWTCPConnection) {
        conn.readMinimumLength(1, maximumLength: 65535) { [weak self] data, error in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                self.dlog("TCP REAL RECV: \(conn.endpoint) [\(data.count)B]")
                // Find the state for this connection and send data back to app via TUN
                self.sendDataToApp(from: conn, data: data)
            }
            if error == nil {
                self.startTCPReading(conn)
            }
        }
    }

    /// Send server response back to app via TUN as TCP packets
    /// Splits large data into MSS-sized chunks (max 1400 bytes per packet)
    private func sendDataToApp(from conn: NWTCPConnection, data: Data) {
        for (key, var state) in tcpStates {
            if state.conn === conn {
                let mss = 1400
                var offset = 0
                var packets: [Data] = []

                while offset < data.count {
                    let end = min(offset + mss, data.count)
                    let chunk = data[offset..<end]
                    let isLast = end >= data.count
                    let flags: UInt8 = isLast ? (TCPHeader.ACK | TCPHeader.PSH) : TCPHeader.ACK

                    let packet = buildTCPPacket(
                        srcIP: state.dstIP, dstIP: state.srcIP,
                        srcPort: state.dstPort, dstPort: state.srcPort,
                        seq: state.localSeq, ack: state.remoteSeq,
                        flags: flags,
                        payload: Data(chunk)
                    )
                    state.localSeq &+= UInt32(chunk.count)
                    packets.append(packet)
                    offset = end
                }

                tcpStates[key] = state
                let protos = packets.map { _ in NSNumber(value: AF_INET) }
                packetFlow.writePackets(packets, withProtocols: protos)
                dlog("TCP→APP: \(key) [\(data.count)B] \(packets.count) segs")
                return
            }
        }
    }

    // MARK: - Build TCP Packet

    private func buildTCPPacket(srcIP: (UInt8,UInt8,UInt8,UInt8), dstIP: (UInt8,UInt8,UInt8,UInt8),
                                 srcPort: UInt16, dstPort: UInt16,
                                 seq: UInt32, ack: UInt32,
                                 flags: UInt8, payload: Data,
                                 isSYNACK: Bool = false) -> Data {
        // SYN+ACK needs TCP options (MSS, Window Scale, SACK permitted)
        let tcpOptionsLen: Int = isSYNACK ? 12 : 0  // MSS(4) + WS(3) + SACK(2) + NOP(1) + pad(2)
        let tcpHeaderLen = 20 + tcpOptionsLen
        let ipHeaderLen = 20
        let totalLen = ipHeaderLen + tcpHeaderLen + payload.count

        var pkt = Data(count: totalLen)

        // IP header
        pkt[0] = 0x45
        pkt[2] = UInt8((totalLen >> 8) & 0xFF)
        pkt[3] = UInt8(totalLen & 0xFF)
        pkt[6] = 0x40  // Don't fragment
        pkt[8] = 64    // TTL
        pkt[9] = 6     // TCP
        pkt[12] = srcIP.0; pkt[13] = srcIP.1; pkt[14] = srcIP.2; pkt[15] = srcIP.3
        pkt[16] = dstIP.0; pkt[17] = dstIP.1; pkt[18] = dstIP.2; pkt[19] = dstIP.3

        // TCP header
        let t = ipHeaderLen
        pkt[t]   = UInt8(srcPort >> 8); pkt[t+1] = UInt8(srcPort & 0xFF)
        pkt[t+2] = UInt8(dstPort >> 8); pkt[t+3] = UInt8(dstPort & 0xFF)
        pkt[t+4] = UInt8((seq >> 24) & 0xFF); pkt[t+5] = UInt8((seq >> 16) & 0xFF)
        pkt[t+6] = UInt8((seq >> 8) & 0xFF); pkt[t+7] = UInt8(seq & 0xFF)
        pkt[t+8] = UInt8((ack >> 24) & 0xFF); pkt[t+9] = UInt8((ack >> 16) & 0xFF)
        pkt[t+10] = UInt8((ack >> 8) & 0xFF); pkt[t+11] = UInt8(ack & 0xFF)
        pkt[t+12] = UInt8((tcpHeaderLen / 4) << 4)  // Data offset
        pkt[t+13] = flags
        pkt[t+14] = 0xFF; pkt[t+15] = 0xFF  // Window size: 65535

        // TCP Options for SYN+ACK
        if isSYNACK {
            let o = t + 20
            // MSS = 1460 (kind=2, len=4)
            pkt[o]   = 2; pkt[o+1] = 4; pkt[o+2] = 0x05; pkt[o+3] = 0xB4
            // SACK Permitted (kind=4, len=2)
            pkt[o+4] = 4; pkt[o+5] = 2
            // Window Scale = 6 (kind=3, len=3, shift=6)
            pkt[o+6] = 3; pkt[o+7] = 3; pkt[o+8] = 6
            // NOP padding (kind=1) x3
            pkt[o+9] = 1; pkt[o+10] = 1; pkt[o+11] = 1
        }

        // Payload
        if !payload.isEmpty {
            pkt.replaceSubrange((ipHeaderLen + tcpHeaderLen)..<totalLen, with: payload)
        }

        // Checksums
        ChecksumCalculator.recalculateChecksums(&pkt)
        return pkt
    }

    // MARK: - DNS

    private func handleDNS(_ pkt: ParsedPacket) {
        guard pkt.payload.count >= 12 else { return }
        let payload = [UInt8](pkt.payload)
        let hostname = parseDNSHostname(payload)
        if let h = hostname { dlog("DNS: \(h)") }

        let endpoint = NWHostEndpoint(hostname: config.dnsServer, port: "53")
        let session = createUDPSession(to: endpoint, from: nil)
        session.writeDatagram(pkt.payload) { _ in }
        session.setReadHandler({ [weak self] dgs, _ in
            guard let self = self, let dg = dgs?.first else { session.cancel(); return }
            if let h = hostname { self.dlog("DNS RESP: \(h) [\(dg.count)B]") }
            if let resp = self.buildDNSResponse(original: pkt, dns: dg) {
                self.packetFlow.writePackets([resp], withProtocols: [NSNumber(value: AF_INET)])
            }
            session.cancel()
        }, maxDatagrams: 1)
    }

    private func buildDNSResponse(original pkt: ParsedPacket, dns: Data) -> Data? {
        let srcIP = pkt.ipHeader.dstIP
        let dstIP = pkt.ipHeader.srcIP
        let totalLen = 20 + 8 + dns.count
        var p = Data(count: totalLen)
        p[0] = 0x45; p[2] = UInt8((totalLen>>8)&0xFF); p[3] = UInt8(totalLen&0xFF)
        p[6] = 0x40; p[8] = 64; p[9] = 17
        p[12]=srcIP.0; p[13]=srcIP.1; p[14]=srcIP.2; p[15]=srcIP.3
        p[16]=dstIP.0; p[17]=dstIP.1; p[18]=dstIP.2; p[19]=dstIP.3
        p[20]=UInt8(pkt.dstPort>>8); p[21]=UInt8(pkt.dstPort&0xFF)
        p[22]=UInt8(pkt.srcPort>>8); p[23]=UInt8(pkt.srcPort&0xFF)
        let udpLen = UInt16(8+dns.count)
        p[24]=UInt8(udpLen>>8); p[25]=UInt8(udpLen&0xFF)
        p.replaceSubrange(28..<totalLen, with: dns)
        ChecksumCalculator.ipChecksum(&p)
        return p
    }

    private func parseDNSHostname(_ data: [UInt8]) -> String? {
        guard data.count >= 12 else { return nil }
        var offset = 12; var parts: [String] = []
        while offset < data.count {
            let len = Int(data[offset]); if len == 0 { break }
            offset += 1; guard offset+len <= data.count else { return nil }
            if let s = String(bytes: data[offset..<offset+len], encoding: .ascii) { parts.append(s) }
            offset += len
        }
        return parts.isEmpty ? nil : parts.joined(separator: ".")
    }

    // MARK: - UDP

    private func handleUDP(_ pkt: ParsedPacket, dstStr: String) {
        let key = "\(dstStr):\(pkt.dstPort)"
        if udpSessions[key] == nil {
            let ep = NWHostEndpoint(hostname: dstStr, port: "\(pkt.dstPort)")
            let s = createUDPSession(to: ep, from: nil)
            udpSessions[key] = s
            s.setReadHandler({ [weak self] dgs, _ in
                if let dgs = dgs { for d in dgs { self?.dlog("UDP RECV: \(key) [\(d.count)B]") } }
            }, maxDatagrams: 64)
        }
        udpSessions[key]?.writeDatagram(pkt.payload) { _ in }
    }

    // MARK: - IPC

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let msg = TunnelMessage.decode(from: messageData) else { completionHandler?(nil); return }
        switch msg {
        case .getStatus: completionHandler?(TunnelMessage.status(.connected).encode())
        case .getStatistics:
            var s = TunnelStatistics()
            s.totalPackets = packetCount
            s.activeConnections = tcpStates.count
            s.httpsFragmented = httpsFragCount
            s.httpModified = httpModCount
            s.modifiedPackets = httpsFragCount + httpModCount
            completionHandler?(TunnelMessage.statistics(s).encode())
        case .getLogs: completionHandler?(TunnelMessage.logDump(logBuffer.joined(separator: "\n")).encode())
        default: completionHandler?(nil)
        }
    }
}
