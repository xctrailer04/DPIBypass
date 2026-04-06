import Foundation
import NetworkExtension
import Combine

/// Manages the VPN tunnel profile and communicates with the extension
class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published var status: NEVPNStatus = .disconnected
    @Published var isConnected: Bool = false
    @Published var statistics: TunnelStatistics = TunnelStatistics()
    @Published var config: DPIConfiguration = DPIConfiguration.load()

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var statsTimer: Timer?

    init() {
        loadManager()
    }

    // MARK: - Manager Setup

    private func loadManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self = self else { return }

                if let error = error {
                    print("[VPNManager] Load error: \(error.localizedDescription)")
                    return
                }

                if let existing = managers?.first {
                    self.manager = existing
                } else {
                    self.createManager()
                }

                self.observeStatus()
                self.updateStatus()
            }
        }
    }

    private func createManager() {
        let manager = NETunnelProviderManager()
        manager.localizedDescription = "DPI Bypass"

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.voiplet.dpibypass.tunnel"
        proto.serverAddress = "localhost" // Local VPN, no remote server
        proto.disconnectOnSleep = false

        manager.protocolConfiguration = proto
        manager.isEnabled = true

        manager.saveToPreferences { [weak self] error in
            if let error = error {
                print("[VPNManager] Save error: \(error.localizedDescription)")
                return
            }
            self?.manager = manager
            print("[VPNManager] VPN profile created")
        }
    }

    // MARK: - Status Observation

    private func observeStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager?.connection,
            queue: .main
        ) { [weak self] _ in
            self?.updateStatus()
        }
    }

    private func updateStatus() {
        guard let connection = manager?.connection else { return }
        DispatchQueue.main.async {
            self.status = connection.status
            self.isConnected = connection.status == .connected
        }
    }

    // MARK: - Connect / Disconnect

    func connect() {
        guard let manager = manager else {
            print("[VPNManager] No manager available")
            return
        }

        // Save current config so extension can read it
        config.save()

        // Ensure manager is enabled
        manager.isEnabled = true
        manager.saveToPreferences { [weak self] error in
            if let error = error {
                print("[VPNManager] Enable error: \(error.localizedDescription)")
                return
            }

            do {
                try (manager.connection as? NETunnelProviderSession)?.startTunnel()
                print("[VPNManager] Tunnel started")
                self?.startStatsPolling()
            } catch {
                print("[VPNManager] Start error: \(error.localizedDescription)")
            }
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
        stopStatsPolling()
        print("[VPNManager] Tunnel stopped")
    }

    func toggle() {
        if isConnected {
            disconnect()
        } else {
            connect()
        }
    }

    // MARK: - Configuration

    func applyPreset(_ preset: DPIConfiguration.Preset) {
        config.applyPreset(preset)
        config.save()
        sendConfigToExtension()
    }

    func saveConfig() {
        config.save()
        sendConfigToExtension()
    }

    private func sendConfigToExtension() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        let message = TunnelMessage.updateConfiguration(config)
        guard let data = message.encode() else { return }

        try? session.sendProviderMessage(data) { _ in
            print("[VPNManager] Config sent to extension")
        }
    }

    // MARK: - Statistics Polling

    private func startStatsPolling() {
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.fetchStatistics()
        }
    }

    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
    }

    private func fetchStatistics() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        let message = TunnelMessage.getStatistics
        guard let data = message.encode() else { return }

        try? session.sendProviderMessage(data) { [weak self] response in
            guard let response = response,
                  let msg = TunnelMessage.decode(from: response),
                  case .statistics(let stats) = msg else { return }
            DispatchQueue.main.async {
                self?.statistics = stats
            }
        }
    }

    // MARK: - Logs (via IPC)

    func fetchLogs(completion: @escaping (String) -> Void) {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            completion("Tunnel not connected — no logs available")
            return
        }
        let message = TunnelMessage.getLogs
        guard let data = message.encode() else {
            completion("Failed to encode message")
            return
        }

        do {
            try session.sendProviderMessage(data) { response in
                guard let response = response,
                      let msg = TunnelMessage.decode(from: response),
                      case .logDump(let text) = msg else {
                    completion("No response from tunnel (extension may not be running)")
                    return
                }
                completion(text.isEmpty ? "Log buffer empty — tunnel running but no packets yet" : text)
            }
        } catch {
            completion("IPC error: \(error.localizedDescription)")
        }
    }

    // MARK: - Status Text

    var statusText: String {
        switch status {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .disconnected: return "Disconnected"
        case .reasserting: return "Reconnecting..."
        case .invalid: return "Invalid"
        @unknown default: return "Unknown"
        }
    }
}
