import SwiftUI

struct SettingsView: View {
    @ObservedObject private var vpn = VPNManager.shared

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $vpn.config.httpHostReplace) {
                    Label("Host Header Replace", systemImage: "textformat.alt")
                }
                Toggle(isOn: $vpn.config.httpHostMixCase) {
                    Label("Host Mixed Case", systemImage: "textformat.abc")
                }
                Toggle(isOn: $vpn.config.httpHostRemoveSpace) {
                    Label("Remove Space After Host:", systemImage: "space")
                }
                Toggle(isOn: $vpn.config.httpAdditionalSpace) {
                    Label("Extra Space After Method", systemImage: "plus.square")
                }
                Stepper("Fragment Size: \(vpn.config.httpFragmentSize)", value: $vpn.config.httpFragmentSize, in: 0...100)
            } header: {
                Label("HTTP Bypass (Port 80)", systemImage: "globe")
            }

            Section {
                Toggle(isOn: $vpn.config.httpsFragmentEnabled) {
                    Label("TLS Fragmentation", systemImage: "lock.shield")
                }
                Toggle(isOn: $vpn.config.fragmentBySNI) {
                    Label("Fragment by SNI", systemImage: "scissors")
                }
                if !vpn.config.fragmentBySNI {
                    Stepper("Fragment Size: \(vpn.config.httpsFragmentSize)", value: $vpn.config.httpsFragmentSize, in: 1...100)
                }
            } header: {
                Label("HTTPS/TLS Bypass (Port 443)", systemImage: "lock.fill")
            }

            Section {
                Toggle(isOn: $vpn.config.blockPassiveDPI) {
                    Label("Block DPI Redirects", systemImage: "hand.raised")
                }
                Toggle(isOn: $vpn.config.blockQUIC) {
                    Label("Block QUIC (Force TCP)", systemImage: "xmark.shield")
                }
            } header: {
                Label("Passive DPI Blocking", systemImage: "shield.slash")
            }

            Section {
                Toggle(isOn: $vpn.config.dnsRedirectEnabled) {
                    Label("DNS Redirection", systemImage: "arrow.triangle.branch")
                }
                if vpn.config.dnsRedirectEnabled {
                    HStack {
                        Text("Server")
                        Spacer()
                        TextField("1.1.1.1", text: $vpn.config.dnsServer)
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.decimalPad)
                            .foregroundStyle(.blue)
                    }
                }
            } header: {
                Label("DNS", systemImage: "network")
            }

            Section {
                Button(action: { vpn.saveConfig() }) {
                    HStack {
                        Spacer()
                        Label("Save & Apply", systemImage: "checkmark.circle.fill")
                            .fontWeight(.semibold)
                        Spacer()
                    }
                }
                .tint(.blue)
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.large)
    }
}
