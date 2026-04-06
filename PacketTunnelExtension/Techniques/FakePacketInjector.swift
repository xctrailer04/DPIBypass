import Foundation
import Darwin

/// Fake packet injection using TTL manipulation on BSD sockets
/// Based on ByeDPI's desync technique (desync.c)
///
/// How it works:
/// 1. Set socket TTL to a very low value (e.g., 1-5 hops)
/// 2. Send fake/garbage data through the socket
/// 3. The fake data passes through nearby DPI but TTL expires before reaching the server
/// 4. Restore normal TTL and send real data
/// 5. DPI is confused because it saw the fake data first
///
/// This works with standard BSD sockets — NO raw sockets needed!
/// Apple confirms BSD sockets are permitted in packet tunnel extensions.
class FakePacketInjector {

    // MARK: - Configuration

    /// Default fake TTL — packet will expire after this many hops
    /// DPI equipment is typically 1-3 hops from the user
    private var fakeTTL: Int32 = 1

    /// Normal TTL for real packets
    private var normalTTL: Int32 = 64

    /// Auto-TTL: if enabled, calculate optimal fake TTL from server's SYN+ACK
    private var autoTTLEnabled: Bool = false

    /// Stored server TTL values (from SYN+ACK) keyed by destination IP
    private var serverTTLCache: [String: UInt8] = [:]

    // MARK: - Fake HTTP Request

    /// Default fake HTTP request (same as GoodbyeDPI's fake_http_request)
    static let fakeHTTPRequest: [UInt8] = Array(
        "GET / HTTP/1.1\r\nHost: www.w3.org\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n".utf8
    )

    /// Default fake TLS ClientHello (minimal, with fake SNI)
    /// Based on GoodbyeDPI's fake_https_request
    static let fakeTLSClientHello: [UInt8] = {
        // Minimal TLS 1.2 ClientHello with SNI "www.w3.org"
        var hello: [UInt8] = [
            0x16,                   // Content type: Handshake
            0x03, 0x01,             // TLS 1.0 (record layer)
            0x00, 0x00,             // Length (placeholder, filled below)
            0x01,                   // Handshake type: ClientHello
            0x00, 0x00, 0x00,       // Handshake length (placeholder)
            0x03, 0x03,             // Client version: TLS 1.2
        ]
        // Client random (32 bytes of zeros — it's fake anyway)
        hello += [UInt8](repeating: 0x00, count: 32)
        // Session ID length: 0
        hello += [0x00]
        // Cipher suites: TLS_AES_128_GCM_SHA256 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        hello += [0x00, 0x04, 0x13, 0x01, 0xC0, 0x2F]
        // Compression methods: null
        hello += [0x01, 0x00]
        // Extensions
        let sni = Array("www.w3.org".utf8)
        // SNI extension
        var ext: [UInt8] = [
            0x00, 0x00,                                 // Extension type: SNI
            UInt8((sni.count + 5) >> 8), UInt8((sni.count + 5) & 0xFF), // Extension length
            UInt8((sni.count + 3) >> 8), UInt8((sni.count + 3) & 0xFF), // Server name list length
            0x00,                                       // Name type: hostname
            UInt8(sni.count >> 8), UInt8(sni.count & 0xFF), // Name length
        ]
        ext += sni

        let extLen = ext.count
        hello += [UInt8(extLen >> 8), UInt8(extLen & 0xFF)]
        hello += ext

        // Fill in lengths
        let recordLen = hello.count - 5
        hello[3] = UInt8(recordLen >> 8)
        hello[4] = UInt8(recordLen & 0xFF)
        let handshakeLen = hello.count - 9
        hello[6] = UInt8((handshakeLen >> 16) & 0xFF)
        hello[7] = UInt8((handshakeLen >> 8) & 0xFF)
        hello[8] = UInt8(handshakeLen & 0xFF)

        return hello
    }()

    // MARK: - TTL Manipulation

    /// Set TTL on a socket (works on iOS!)
    /// Confirmed by Apple Developer Forums: setsockopt(IP_TTL) is available
    @discardableResult
    static func setTTL(fd: Int32, ttl: Int32) -> Bool {
        var ttlValue = ttl

        // Try IPv4
        let ret4 = setsockopt(fd, IPPROTO_IP, IP_TTL, &ttlValue, socklen_t(MemoryLayout<Int32>.size))

        // Try IPv6
        let ret6 = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttlValue, socklen_t(MemoryLayout<Int32>.size))

        return ret4 == 0 || ret6 == 0
    }

    /// Get current TTL from a socket
    static func getTTL(fd: Int32) -> Int32 {
        var ttl: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        let ret = getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &len)
        return ret == 0 ? ttl : 64
    }

    // MARK: - Desync Techniques (ByeDPI-style)

    /// Send fake data with low TTL, then real data with normal TTL
    /// This is the core ByeDPI desync technique
    ///
    /// - Parameters:
    ///   - fd: Socket file descriptor
    ///   - realData: The actual data to send (HTTP request or TLS ClientHello)
    ///   - fakeData: Fake/decoy data to send first
    ///   - fakeTTL: TTL for fake packet (default: 1)
    ///   - splitPosition: Where to split realData for fragmentation (0 = no split)
    /// - Returns: Total bytes of real data sent, or -1 on error
    static func desyncSend(
        fd: Int32,
        realData: [UInt8],
        fakeData: [UInt8],
        fakeTTL: Int32 = 1,
        splitPosition: Int = 0
    ) -> Int {
        // Save original TTL
        let originalTTL = getTTL(fd: fd)

        // Disable Nagle's algorithm for precise segment control
        var noDelay: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, socklen_t(MemoryLayout<Int32>.size))

        // Step 1: Set low TTL for fake packet
        guard setTTL(fd: fd, ttl: fakeTTL) else {
            return -1
        }

        // Step 2: Send fake data (DPI sees it, server doesn't — TTL expires)
        _ = send(fd, fakeData, fakeData.count, 0)

        // Step 3: Wait for socket buffer to drain
        // This ensures the fake packet is actually sent before we change TTL
        waitForBufferDrain(fd: fd)

        // Step 4: Restore normal TTL for real data
        setTTL(fd: fd, ttl: originalTTL)

        // Step 5: Send real data
        if splitPosition > 0 && splitPosition < realData.count {
            // Fragmented send: split real data at specified position
            let part1 = Array(realData[0..<splitPosition])
            let part2 = Array(realData[splitPosition...])

            let sent1 = send(fd, part1, part1.count, 0)
            waitForBufferDrain(fd: fd)
            let sent2 = send(fd, part2, part2.count, 0)

            return (sent1 >= 0 && sent2 >= 0) ? (sent1 + sent2) : -1
        } else {
            return send(fd, realData, realData.count, 0)
        }
    }

    /// ByeDPI "disorder" mode: send real data in reversed segment order
    /// Segment 1 sent with TTL=1 (lost, retransmitted later)
    /// Segment 2 sent with normal TTL (arrives first)
    /// Result: DPI sees segments out of order and can't reassemble
    static func disorderSend(
        fd: Int32,
        realData: [UInt8],
        splitPosition: Int,
        fakeTTL: Int32 = 1
    ) -> Int {
        guard splitPosition > 0 && splitPosition < realData.count else {
            return send(fd, realData, realData.count, 0)
        }

        let originalTTL = getTTL(fd: fd)
        var noDelay: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, socklen_t(MemoryLayout<Int32>.size))

        let part1 = Array(realData[0..<splitPosition])
        let part2 = Array(realData[splitPosition...])

        // Send part1 with TTL=1 (will be lost, OS will retransmit later)
        setTTL(fd: fd, ttl: fakeTTL)
        _ = send(fd, part1, part1.count, 0)
        waitForBufferDrain(fd: fd)

        // Send part2 with normal TTL (arrives at server first)
        setTTL(fd: fd, ttl: originalTTL)
        let sent2 = send(fd, part2, part2.count, 0)

        // OS will automatically retransmit part1 with normal TTL
        // Server receives: part2 first, then part1 (out of order)
        // DPI can't reassemble because it saw them in wrong order

        return sent2 >= 0 ? realData.count : -1
    }

    // MARK: - Auto-TTL

    /// Calculate optimal fake TTL based on server's TTL from SYN+ACK
    /// Ported from GoodbyeDPI's tcp_get_auto_ttl() in ttltrack.c
    ///
    /// Logic: Server sends SYN+ACK with initial TTL (usually 64 or 128)
    /// By the time it reaches us, TTL has been decremented by each hop
    /// Hops = initialTTL - receivedTTL
    /// Fake TTL should be: hops - margin (so it expires between us and server)
    static func calculateAutoTTL(
        serverTTL: UInt8,
        minTTL: Int = 1,
        maxTTL: Int = 10
    ) -> Int32 {
        // Estimate initial TTL
        let initial: Int
        if serverTTL > 128 {
            initial = 255
        } else if serverTTL > 64 {
            initial = 128
        } else {
            initial = 64
        }

        // Calculate hop count
        let hops = initial - Int(serverTTL)

        // Fake TTL = hops - 1 (expire one hop before server)
        // But at least minTTL, at most maxTTL
        var fakeTTL = max(hops - 1, minTTL)
        fakeTTL = min(fakeTTL, maxTTL)

        return Int32(fakeTTL)
    }

    /// Record server TTL from a SYN+ACK packet
    func recordServerTTL(dstIP: String, ttl: UInt8) {
        serverTTLCache[dstIP] = ttl
    }

    /// Get optimal fake TTL for a destination
    func getFakeTTL(dstIP: String) -> Int32 {
        if autoTTLEnabled, let serverTTL = serverTTLCache[dstIP] {
            return Self.calculateAutoTTL(serverTTL: serverTTL)
        }
        return fakeTTL
    }

    // MARK: - Helpers

    /// Wait for socket send buffer to drain
    /// Critical: setsockopt(IP_TTL) is synchronous but send() is async
    /// If we change TTL before previous send() completes, the old packet gets new TTL
    private static func waitForBufferDrain(fd: Int32, timeoutMS: Int = 500) {
        var nwrite: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        let deadline = DispatchTime.now() + .milliseconds(timeoutMS)

        while DispatchTime.now() < deadline {
            let ret = getsockopt(fd, SOL_SOCKET, SO_NWRITE, &nwrite, &len)
            if ret != 0 {
                // SO_NWRITE not available — fallback to short delay
                usleep(1000) // 1ms
                break
            }
            if nwrite == 0 { break }
            usleep(100) // 0.1ms
        }
    }
}
