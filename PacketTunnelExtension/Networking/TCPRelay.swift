import Foundation
import Network
import Darwin

/// TCP connection relay with DPI bypass techniques
class TCPRelay {

    let host: String
    let port: UInt16
    let config: DPIConfiguration
    let queue: DispatchQueue

    /// Callback to send data back through lwIP → TUN → app
    var onOutput: ((Data) -> Void)?

    /// BSD socket fd (for TTL manipulation)
    private var socketFD: Int32 = -1

    /// Retain dispatch sources so they aren't deallocated
    private var connectSource: DispatchSourceWrite?
    private var readSource: DispatchSourceRead?

    /// Connection state
    private var isConnected = false
    private var isFirstPayload = true

    /// Public closed state for cleanup
    var isClosed: Bool { socketFD < 0 && !isConnected }

    /// Fake packet injector
    private let fakeInjector = FakePacketInjector()

    init(host: String, port: UInt16, config: DPIConfiguration, queue: DispatchQueue) {
        self.host = host
        self.port = port
        self.config = config
        self.queue = queue
    }

    // MARK: - Connection

    func connect() {
        queue.async { [weak self] in
            self?.connectWithBSDSocket()
        }
    }

    private func connectWithBSDSocket() {
        socketFD = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard socketFD >= 0 else {
            print("[TCPRelay] socket() failed: \(errno)")
            return
        }

        // TCP_NODELAY for precise segment control
        var noDelay: Int32 = 1
        Darwin.setsockopt(socketFD, IPPROTO_TCP, TCP_NODELAY, &noDelay, socklen_t(MemoryLayout<Int32>.size))

        // Non-blocking
        let flags = Darwin.fcntl(socketFD, F_GETFL, 0)
        Darwin.fcntl(socketFD, F_SETFL, flags | O_NONBLOCK)

        // CRITICAL: Bind socket to physical interface to avoid routing loop
        // When all traffic routes through TUN, the relay socket's traffic would
        // also enter TUN causing infinite loop. IP_BOUND_IF forces the socket
        // to use the physical network interface directly.
        bindToPhysicalInterface()

        // Connect
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(socketFD, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if result < 0 && errno != EINPROGRESS {
            print("[TCPRelay] connect() failed: \(errno)")
            Darwin.close(socketFD)
            socketFD = -1
            return
        }

        // Wait for connect completion
        let source = DispatchSource.makeWriteSource(fileDescriptor: socketFD, queue: queue)
        self.connectSource = source // retain

        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.connectSource?.cancel()
            self.connectSource = nil

            // Check connect result
            var error: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            Darwin.getsockopt(self.socketFD, SOL_SOCKET, SO_ERROR, &error, &len)

            if error != 0 {
                print("[TCPRelay] connect async failed: \(error)")
                self.disconnect()
                return
            }

            self.isConnected = true
            self.startReceiving()
        }
        source.resume()
    }

    /// Bind socket to physical interface to bypass TUN routing
    /// This prevents the infinite routing loop
    private func bindToPhysicalInterface() {
        // Get the index of the primary physical interface (en0 = WiFi, pdp_ip0 = Cellular)
        // IP_BOUND_IF forces the socket to use a specific interface
        var ifindex: UInt32 = 0

        // Try en0 (WiFi) first
        ifindex = if_nametoindex("en0")
        if ifindex == 0 {
            // Try pdp_ip0 (Cellular)
            ifindex = if_nametoindex("pdp_ip0")
        }

        if ifindex > 0 {
            var idx = ifindex
            Darwin.setsockopt(socketFD, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size))
        }
    }

    // MARK: - Send Data with DPI Bypass

    func sendToServer(_ data: Data) {
        queue.async { [weak self] in
            guard let self = self, self.socketFD >= 0, self.isConnected else { return }
            let bytes = [UInt8](data)

            if self.port == 80 && self.isFirstPayload {
                self.sendHTTPWithBypass(bytes)
                self.isFirstPayload = false
            } else if self.port == 443 && self.isFirstPayload && TLSParser.isClientHello(data) {
                self.sendTLSWithBypass(bytes)
                self.isFirstPayload = false
            } else {
                Darwin.send(self.socketFD, bytes, bytes.count, 0)
            }
        }
    }

    private func sendHTTPWithBypass(_ bytes: [UInt8]) {
        var payload = Data(bytes)

        if let httpInfo = HTTPParser.parse(payload) {
            payload = HTTPHostManipulation.apply(
                payload: payload, httpInfo: httpInfo, config: config
            )
        }

        let modifiedBytes = [UInt8](payload)
        let fakeTTL = fakeInjector.getFakeTTL(dstIP: host)

        FakePacketInjector.desyncSend(
            fd: socketFD, realData: modifiedBytes,
            fakeData: FakePacketInjector.fakeHTTPRequest,
            fakeTTL: fakeTTL, splitPosition: config.httpFragmentSize
        )
    }

    private func sendTLSWithBypass(_ bytes: [UInt8]) {
        let payload = Data(bytes)
        var splitPoint = config.httpsFragmentSize

        if config.fragmentBySNI,
           let sni = TLSParser.extractSNI(from: payload) {
            splitPoint = sni.sniOffset
        }

        let fakeTTL = fakeInjector.getFakeTTL(dstIP: host)

        FakePacketInjector.desyncSend(
            fd: socketFD, realData: bytes,
            fakeData: FakePacketInjector.fakeTLSClientHello,
            fakeTTL: fakeTTL, splitPosition: splitPoint
        )
    }

    // MARK: - Receive Data

    private func startReceiving() {
        guard socketFD >= 0 else { return }

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        self.readSource = source

        source.setEventHandler { [weak self] in
            self?.readFromSocket()
        }
        source.setCancelHandler { [weak self] in
            self?.readSource = nil
        }
        source.resume()
    }

    private func readFromSocket() {
        guard socketFD >= 0 else { return }

        var buffer = [UInt8](repeating: 0, count: 65535)
        let bytesRead = Darwin.recv(socketFD, &buffer, buffer.count, 0)

        if bytesRead > 0 {
            let data = Data(buffer[0..<bytesRead])
            onOutput?(data)
        } else if bytesRead == 0 {
            disconnect()
        }
        // bytesRead < 0 && errno == EAGAIN: no data yet
    }

    // MARK: - Lifecycle

    func disconnect() {
        connectSource?.cancel()
        connectSource = nil
        readSource?.cancel()
        readSource = nil

        if socketFD >= 0 {
            Darwin.close(socketFD)
            socketFD = -1
        }
        isConnected = false
    }

    deinit {
        disconnect()
    }
}
