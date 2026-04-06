import Foundation

/// TLS ClientHello SNI fragmentation
/// Splits the ClientHello at the SNI boundary so DPI cannot read the server name
/// Ported from GoodbyeDPI's fragment-by-sni logic
enum SNIFragmentation {

    struct FragmentResult {
        let fragments: [Data]   // TCP payload fragments to send separately
        let hostname: String
    }

    /// Fragment a TLS ClientHello payload at the SNI boundary
    /// Returns array of payload fragments that should be sent as separate TCP segments
    static func fragment(
        payload: Data,
        config: DPIConfiguration
    ) -> FragmentResult? {
        // Parse TLS to find SNI
        guard let sniResult = TLSParser.extractSNI(from: payload) else { return nil }

        if config.fragmentBySNI {
            // Fragment at SNI boundary (GoodbyeDPI --frag-by-sni)
            // Split point: right before the SNI hostname value
            return fragmentAtSNI(payload: payload, sniResult: sniResult)
        } else if config.httpsFragmentSize > 0 {
            // Fragment at fixed size (GoodbyeDPI -e N)
            return fragmentAtSize(payload: payload, size: config.httpsFragmentSize, hostname: sniResult.hostname)
        }

        return nil
    }

    /// Fragment at SNI boundary
    /// First fragment: everything up to SNI hostname
    /// Second fragment: SNI hostname + rest of ClientHello
    private static func fragmentAtSNI(
        payload: Data,
        sniResult: TLSParser.SNIResult
    ) -> FragmentResult {
        let splitPoint = sniResult.sniOffset

        guard splitPoint > 0 && splitPoint < payload.count else {
            // Can't split, return as single fragment
            return FragmentResult(fragments: [payload], hostname: sniResult.hostname)
        }

        let fragment1 = payload.prefix(splitPoint)
        let fragment2 = payload.suffix(from: splitPoint)

        return FragmentResult(
            fragments: [Data(fragment1), Data(fragment2)],
            hostname: sniResult.hostname
        )
    }

    /// Fragment at fixed byte size
    /// First fragment: N bytes
    /// Second fragment: rest
    private static func fragmentAtSize(
        payload: Data,
        size: Int,
        hostname: String
    ) -> FragmentResult {
        guard size > 0 && size < payload.count else {
            return FragmentResult(fragments: [payload], hostname: hostname)
        }

        let fragment1 = payload.prefix(size)
        let fragment2 = payload.suffix(from: size)

        return FragmentResult(
            fragments: [Data(fragment1), Data(fragment2)],
            hostname: hostname
        )
    }
}

/// TCP payload fragmentation for HTTP
/// Splits HTTP request into small TCP segments
enum TCPFragmentation {

    /// Fragment TCP payload into chunks of specified size
    static func fragment(payload: Data, size: Int) -> [Data] {
        guard size > 0, payload.count > size else { return [payload] }

        var fragments: [Data] = []
        var offset = 0

        while offset < payload.count {
            let end = min(offset + size, payload.count)
            fragments.append(payload[offset..<end])
            offset = end
        }

        return fragments
    }
}
