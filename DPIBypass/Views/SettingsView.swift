import SwiftUI

struct SettingsView: View {
    @ObservedObject private var vpn = VPNManager.shared

    var body: some View {
        Form {
            // HTTP Tricks
            Section(header: Text("HTTP Bypass (Port 80)")) {
                Toggle("Host Header Replace (hoSt:)", isOn: $vpn.config.httpHostReplace)
                Toggle("Host Mixed Case (tEsT.cOm)", isOn: $vpn.config.httpHostMixCase)
                Toggle("Remove Space After Host:", isOn: $vpn.config.httpHostRemoveSpace)
                Toggle("Additional Space After Method", isOn: $vpn.config.httpAdditionalSpace)

                HStack {
                    Text("Fragment Size")
                    Spacer()
                    Stepper("\(vpn.config.httpFragmentSize)", value: $vpn.config.httpFragmentSize, in: 0...100)
                }
            }

            // HTTPS/TLS Tricks
            Section(header: Text("HTTPS/TLS Bypass (Port 443)")) {
                Toggle("TLS Fragmentation", isOn: $vpn.config.httpsFragmentEnabled)
                Toggle("Fragment by SNI", isOn: $vpn.config.fragmentBySNI)

                if !vpn.config.fragmentBySNI {
                    HStack {
                        Text("Fragment Size")
                        Spacer()
                        Stepper("\(vpn.config.httpsFragmentSize)", value: $vpn.config.httpsFragmentSize, in: 1...100)
                    }
                }
            }

            // Passive DPI
            Section(header: Text("Passive DPI Blocking")) {
                Toggle("Block DPI Redirects (302)", isOn: $vpn.config.blockPassiveDPI)
                Toggle("Block QUIC (Force TCP)", isOn: $vpn.config.blockQUIC)
            }

            // DNS
            Section(header: Text("DNS")) {
                Toggle("DNS Redirection", isOn: $vpn.config.dnsRedirectEnabled)
                if vpn.config.dnsRedirectEnabled {
                    HStack {
                        Text("DNS Server")
                        Spacer()
                        TextField("1.1.1.1", text: $vpn.config.dnsServer)
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.decimalPad)
                    }
                }
            }

            // Window Size
            Section(header: Text("Advanced")) {
                Toggle("Window Size Manipulation", isOn: $vpn.config.windowSizeEnabled)
                if vpn.config.windowSizeEnabled {
                    HStack {
                        Text("Window Size")
                        Spacer()
                        Stepper("\(vpn.config.windowSize)", value: $vpn.config.windowSize, in: 1...65535)
                    }
                }
            }

            // Save
            Section {
                Button(action: { vpn.saveConfig() }) {
                    HStack {
                        Spacer()
                        Text("Save & Apply")
                            .bold()
                        Spacer()
                    }
                }
            }
        }
        .navigationTitle("Settings")
    }
}
