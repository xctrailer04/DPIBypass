import SwiftUI

struct LogView: View {
    @ObservedObject private var vpn = VPNManager.shared
    @State private var logText = "Tap refresh to load..."
    @State private var autoRefresh = false
    @State private var showShare = false
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack(spacing: 16) {
                Label("\(logText.components(separatedBy: "\n").count)", systemImage: "line.3.horizontal")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Spacer()

                Toggle(isOn: $autoRefresh) {
                    Image(systemName: "play.circle")
                }
                .toggleStyle(.button)
                .tint(autoRefresh ? .green : .gray)

                Button(action: fetch) {
                    Image(systemName: "arrow.clockwise")
                }
                Button(action: { showShare = true }) {
                    Image(systemName: "square.and.arrow.up")
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 10)
            .background(.ultraThinMaterial)

            // Log
            ScrollViewReader { proxy in
                ScrollView {
                    Text(logText)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .id("end")
                }
                .background(Color(.systemBackground))
                .onChange(of: logText) { _ in
                    if autoRefresh { proxy.scrollTo("end", anchor: .bottom) }
                }
            }
        }
        .navigationTitle("Console")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { fetch() }
        .onReceive(timer) { _ in if autoRefresh { fetch() } }
        .sheet(isPresented: $showShare) {
            ShareSheet(text: logText)
        }
    }

    private func fetch() {
        vpn.fetchLogs { text in
            DispatchQueue.main.async { logText = text }
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
