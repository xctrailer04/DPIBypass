import SwiftUI

struct MainView: View {
    @ObservedObject private var vpn = VPNManager.shared
    @State private var animatePulse = false

    var body: some View {
        NavigationStack {
            ZStack {
                // Background gradient
                LinearGradient(
                    colors: [Color(.systemBackground), Color(.systemGroupedBackground)],
                    startPoint: .top, endPoint: .bottom
                ).ignoresSafeArea()

                ScrollView(showsIndicators: false) {
                    VStack(spacing: 24) {
                        // Hero connection card
                        heroCard
                            .padding(.top, 8)

                        // Live stats
                        if vpn.isConnected {
                            statsGrid
                                .transition(.move(edge: .top).combined(with: .opacity))
                        }

                        // Presets
                        presetsCard

                        // Menu items
                        VStack(spacing: 12) {
                            NavigationLink(destination: SettingsView()) {
                                menuRow(
                                    icon: "slider.horizontal.3",
                                    iconColor: .blue,
                                    title: "Settings",
                                    subtitle: "Bypass techniques & DNS"
                                )
                            }
                            NavigationLink(destination: LogView()) {
                                menuRow(
                                    icon: "terminal",
                                    iconColor: .green,
                                    title: "Debug Console",
                                    subtitle: "Live packet logs"
                                )
                            }
                        }

                        // Version footer
                        Text("DPI Bypass v1.0 — Voiplet Teknoloji")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .padding(.bottom, 20)
                    }
                    .padding(.horizontal)
                }
            }
            .navigationTitle("DPI Bypass")
            .navigationBarTitleDisplayMode(.large)
            .animation(.easeInOut(duration: 0.3), value: vpn.isConnected)
        }
    }

    // MARK: - Hero Card

    private var heroCard: some View {
        VStack(spacing: 20) {
            ZStack {
                // Pulse ring
                if vpn.isConnected {
                    Circle()
                        .stroke(Color.green.opacity(0.3), lineWidth: 2)
                        .frame(width: 110, height: 110)
                        .scaleEffect(animatePulse ? 1.3 : 1.0)
                        .opacity(animatePulse ? 0 : 0.6)
                        .animation(.easeOut(duration: 1.5).repeatForever(autoreverses: false), value: animatePulse)
                }

                // Shield icon
                Circle()
                    .fill(
                        vpn.isConnected
                            ? LinearGradient(colors: [.green, .green.opacity(0.7)], startPoint: .topLeading, endPoint: .bottomTrailing)
                            : LinearGradient(colors: [.gray.opacity(0.3), .gray.opacity(0.15)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                    .frame(width: 90, height: 90)
                    .overlay(
                        Image(systemName: vpn.isConnected ? "shield.checkered" : "shield.slash")
                            .font(.system(size: 36, weight: .medium))
                            .foregroundStyle(vpn.isConnected ? .white : .secondary)
                    )
                    .shadow(color: vpn.isConnected ? .green.opacity(0.4) : .clear, radius: 16, y: 4)
            }
            .onAppear { animatePulse = true }

            VStack(spacing: 4) {
                Text(vpn.isConnected ? "Protected" : "Not Connected")
                    .font(.title2.bold())

                Text(vpn.statusText)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            // Connect button
            Button(action: { vpn.toggle() }) {
                HStack(spacing: 8) {
                    Image(systemName: vpn.isConnected ? "stop.fill" : "play.fill")
                        .font(.system(size: 14))
                    Text(vpn.isConnected ? "Disconnect" : "Connect")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(
                    vpn.isConnected
                        ? AnyShapeStyle(Color.red.gradient)
                        : AnyShapeStyle(Color.blue.gradient)
                )
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
        }
        .padding(24)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(.quaternary, lineWidth: 0.5)
        )
    }

    // MARK: - Stats Grid

    private var statsGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
            statCell("Packets", value: formatNumber(vpn.statistics.totalPackets), icon: "arrow.up.arrow.down", color: .blue)
            statCell("Modified", value: formatNumber(vpn.statistics.modifiedPackets), icon: "wand.and.stars", color: .purple)
            statCell("Blocked", value: formatNumber(vpn.statistics.passiveDPIBlocked), icon: "hand.raised.fill", color: .red)
            statCell("HTTP", value: formatNumber(vpn.statistics.httpModified), icon: "globe", color: .orange)
            statCell("HTTPS", value: formatNumber(vpn.statistics.httpsFragmented), icon: "lock.shield", color: .green)
            statCell("Conns", value: "\(vpn.statistics.activeConnections)", icon: "point.3.connected.trianglepath.dotted", color: .teal)
        }
    }

    private func statCell(_ title: String, value: String, icon: String, color: Color) -> some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundStyle(color)
            Text(value)
                .font(.system(.title3, design: .rounded).bold())
                .foregroundStyle(.primary)
            Text(title)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    // MARK: - Presets

    private var presetsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Presets", systemImage: "bolt.horizontal.fill")
                .font(.subheadline.bold())
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                ForEach(DPIConfiguration.Preset.allCases, id: \.self) { preset in
                    if preset != .custom {
                        presetChip(preset)
                    }
                }
            }
        }
        .padding(16)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private func presetChip(_ preset: DPIConfiguration.Preset) -> some View {
        let isActive = vpn.config.activePreset == preset
        return Button(action: { vpn.applyPreset(preset) }) {
            VStack(spacing: 6) {
                Image(systemName: presetIcon(preset))
                    .font(.system(size: 20))
                Text(preset.rawValue)
                    .font(.caption.bold())
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(
                isActive
                    ? AnyShapeStyle(Color.blue.gradient)
                    : AnyShapeStyle(Color(.tertiarySystemGroupedBackground))
            )
            .foregroundStyle(isActive ? .white : .primary)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }

    private func presetIcon(_ p: DPIConfiguration.Preset) -> String {
        switch p {
        case .minimal: return "shield"
        case .balanced: return "shield.lefthalf.filled"
        case .maximum: return "shield.checkered"
        case .custom: return "slider.horizontal.3"
        }
    }

    // MARK: - Menu Row

    private func menuRow(icon: String, iconColor: Color, title: String, subtitle: String) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 18))
                .foregroundStyle(iconColor)
                .frame(width: 36, height: 36)
                .background(iconColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))

            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.medium))
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.quaternary)
        }
        .padding(14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    // MARK: - Helpers

    private func formatNumber(_ n: UInt64) -> String {
        if n >= 1_000_000 { return String(format: "%.1fM", Double(n)/1_000_000) }
        if n >= 1_000 { return String(format: "%.1fK", Double(n)/1_000) }
        return "\(n)"
    }
}
