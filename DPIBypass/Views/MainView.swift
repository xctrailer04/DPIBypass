import SwiftUI

struct MainView: View {
    @ObservedObject private var vpn = VPNManager.shared

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Connection Card
                    connectionCard

                    // Statistics
                    if vpn.isConnected {
                        statisticsCard
                    }

                    // Quick Presets
                    presetsSection

                    // Navigation
                    NavigationLink(destination: SettingsView()) {
                        settingsRow(icon: "gearshape.fill", title: "Settings", subtitle: "Configure bypass techniques")
                    }

                    NavigationLink(destination: LogView()) {
                        settingsRow(icon: "doc.text.magnifyingglass", title: "Debug Log", subtitle: "View packet logs, share as TXT")
                    }
                }
                .padding()
            }
            .navigationTitle("DPI Bypass")
            .background(Color(.systemGroupedBackground))
        }
    }

    // MARK: - Connection Card

    private var connectionCard: some View {
        VStack(spacing: 16) {
            // Status indicator
            Circle()
                .fill(vpn.isConnected ? Color.green : Color.red.opacity(0.6))
                .frame(width: 80, height: 80)
                .overlay(
                    Image(systemName: vpn.isConnected ? "shield.checkered" : "shield.slash")
                        .font(.system(size: 32))
                        .foregroundColor(.white)
                )
                .shadow(color: vpn.isConnected ? .green.opacity(0.4) : .clear, radius: 12)

            Text(vpn.statusText)
                .font(.headline)
                .foregroundColor(vpn.isConnected ? .green : .secondary)

            // Connect/Disconnect button
            Button(action: { vpn.toggle() }) {
                Text(vpn.isConnected ? "Disconnect" : "Connect")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(vpn.isConnected ? Color.red : Color.blue)
                    .cornerRadius(14)
            }
        }
        .padding(24)
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(16)
    }

    // MARK: - Statistics Card

    private var statisticsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Statistics")
                .font(.headline)

            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
            ], spacing: 10) {
                statItem("Total Packets", value: "\(vpn.statistics.totalPackets)")
                statItem("Modified", value: "\(vpn.statistics.modifiedPackets)")
                statItem("HTTP Modified", value: "\(vpn.statistics.httpModified)")
                statItem("HTTPS Fragmented", value: "\(vpn.statistics.httpsFragmented)")
                statItem("DNS Redirected", value: "\(vpn.statistics.dnsRedirected)")
                statItem("DPI Blocked", value: "\(vpn.statistics.passiveDPIBlocked)")
            }
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(16)
    }

    private func statItem(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.title3.bold())
                .foregroundColor(.blue)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color(.tertiarySystemGroupedBackground))
        .cornerRadius(8)
    }

    // MARK: - Presets

    private var presetsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Quick Presets")
                .font(.headline)

            HStack(spacing: 10) {
                ForEach(DPIConfiguration.Preset.allCases, id: \.self) { preset in
                    if preset != .custom {
                        presetButton(preset)
                    }
                }
            }
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(16)
    }

    private func presetButton(_ preset: DPIConfiguration.Preset) -> some View {
        Button(action: { vpn.applyPreset(preset) }) {
            VStack(spacing: 4) {
                Image(systemName: presetIcon(preset))
                    .font(.title2)
                Text(preset.rawValue)
                    .font(.caption.bold())
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(vpn.config.activePreset == preset ? Color.blue : Color(.tertiarySystemGroupedBackground))
            .foregroundColor(vpn.config.activePreset == preset ? .white : .primary)
            .cornerRadius(10)
        }
    }

    private func presetIcon(_ preset: DPIConfiguration.Preset) -> String {
        switch preset {
        case .minimal: return "shield"
        case .balanced: return "shield.lefthalf.filled"
        case .maximum: return "shield.checkered"
        case .custom: return "slider.horizontal.3"
        }
    }

    // MARK: - Settings Row

    private func settingsRow(icon: String, title: String, subtitle: String) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(.blue)
                .frame(width: 36)
            VStack(alignment: .leading) {
                Text(title).font(.body.bold())
                Text(subtitle).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(16)
    }
}
