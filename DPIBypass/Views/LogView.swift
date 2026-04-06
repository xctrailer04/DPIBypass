import SwiftUI

struct LogView: View {
    @ObservedObject private var vpn = VPNManager.shared
    @State private var logText: String = "Tap Refresh to load logs from tunnel..."
    @State private var autoRefresh = false
    @State private var showShareSheet = false
    private let timer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("\(logText.components(separatedBy: "\n").count) lines")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                Toggle("Auto", isOn: $autoRefresh)
                    .labelsHidden()
                    .scaleEffect(0.8)
                Text("Auto").font(.caption)

                Button(action: fetchLogs) {
                    Image(systemName: "arrow.clockwise")
                }
                Button(action: { showShareSheet = true }) {
                    Image(systemName: "square.and.arrow.up")
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            ScrollViewReader { proxy in
                ScrollView {
                    Text(logText)
                        .font(.system(.caption2, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .id("bottom")
                }
                .onChange(of: logText) { _ in
                    proxy.scrollTo("bottom", anchor: .bottom)
                }
            }
        }
        .navigationTitle("Debug Log")
        .onAppear { fetchLogs() }
        .onReceive(timer) { _ in
            if autoRefresh { fetchLogs() }
        }
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(text: logText)
        }
    }

    private func fetchLogs() {
        vpn.fetchLogs { text in
            DispatchQueue.main.async {
                self.logText = text
            }
        }
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let text: String
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("DPIBypass_log.txt")
        try? text.write(to: url, atomically: true, encoding: .utf8)
        return UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
