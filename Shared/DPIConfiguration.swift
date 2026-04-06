import Foundation

/// Shared configuration between main app and tunnel extension
/// Stored in App Group UserDefaults
public struct DPIConfiguration: Codable {
    // MARK: - Master Toggle
    public var isEnabled: Bool = true

    // MARK: - HTTP Tricks (Port 80)
    public var httpHostReplace: Bool = true        // Host: → hoSt:
    public var httpHostMixCase: Bool = true         // test.com → tEsT.cOm
    public var httpHostRemoveSpace: Bool = true     // "Host: x" → "Host:x"
    public var httpAdditionalSpace: Bool = false    // "GET / " → "GET  / "
    public var httpFragmentSize: Int = 2            // TCP fragment size for HTTP
    public var httpAllPorts: Bool = false            // Apply to all ports, not just 80

    // MARK: - HTTPS/TLS Tricks (Port 443)
    public var httpsFragmentEnabled: Bool = true
    public var httpsFragmentSize: Int = 2           // TCP fragment size for TLS ClientHello
    public var fragmentBySNI: Bool = true           // Fragment at SNI boundary

    // MARK: - Passive DPI Blocking
    public var blockPassiveDPI: Bool = true         // Drop HTTP 302 redirects from DPI
    public var blockQUIC: Bool = false              // Block UDP 443 (QUIC)

    // MARK: - DNS
    public var dnsRedirectEnabled: Bool = true
    public var dnsServer: String = "1.1.1.1"
    public var dnsPort: Int = 53

    // MARK: - Window Size
    public var windowSizeEnabled: Bool = false
    public var windowSize: Int = 2                  // Small window to force server fragmentation

    // MARK: - Domain Filtering
    public var useBlacklist: Bool = false
    public var blacklistedDomains: [String] = []

    // MARK: - Presets
    public enum Preset: String, Codable, CaseIterable {
        case minimal = "Minimal"
        case balanced = "Balanced"
        case maximum = "Maximum"
        case custom = "Custom"
    }
    public var activePreset: Preset = .balanced

    // MARK: - Apply Preset
    public mutating func applyPreset(_ preset: Preset) {
        activePreset = preset
        switch preset {
        case .minimal:
            httpHostReplace = true
            httpHostMixCase = false
            httpHostRemoveSpace = false
            httpAdditionalSpace = false
            httpFragmentSize = 0
            httpsFragmentEnabled = true
            httpsFragmentSize = 2
            fragmentBySNI = false
            blockPassiveDPI = false
            blockQUIC = false
            windowSizeEnabled = false
        case .balanced:
            httpHostReplace = true
            httpHostMixCase = true
            httpHostRemoveSpace = true
            httpAdditionalSpace = false
            httpFragmentSize = 2
            httpsFragmentEnabled = true
            httpsFragmentSize = 2
            fragmentBySNI = true
            blockPassiveDPI = true
            blockQUIC = false
            windowSizeEnabled = false
        case .maximum:
            httpHostReplace = true
            httpHostMixCase = true
            httpHostRemoveSpace = true
            httpAdditionalSpace = true
            httpFragmentSize = 2
            httpsFragmentEnabled = true
            httpsFragmentSize = 1
            fragmentBySNI = true
            blockPassiveDPI = true
            blockQUIC = true
            windowSizeEnabled = true
            windowSize = 2
        case .custom:
            break
        }
    }

    // MARK: - Persistence
    public static let appGroupID = "group.com.voiplet.dpibypass"
    private static let configKey = "dpi_configuration"

    public func save() {
        guard let defaults = UserDefaults(suiteName: Self.appGroupID),
              let data = try? JSONEncoder().encode(self) else { return }
        defaults.set(data, forKey: Self.configKey)
    }

    public static func load() -> DPIConfiguration {
        guard let defaults = UserDefaults(suiteName: Self.appGroupID),
              let data = defaults.data(forKey: configKey),
              let config = try? JSONDecoder().decode(DPIConfiguration.self, from: data)
        else { return DPIConfiguration() }
        return config
    }
}
