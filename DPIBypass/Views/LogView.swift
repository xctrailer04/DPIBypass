import SwiftUI

struct LogView: View {
    @State private var logText: String = "Loading..."
    @State private var autoRefresh = true
    @State private var showShareSheet = false
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Text("\(logText.components(separatedBy: "\n").count) lines")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                Toggle("Auto", isOn: $autoRefresh)
                    .labelsHidden()
                    .scaleEffect(0.8)

                Text("Auto")
                    .font(.caption)

                Button(action: refreshLog) {
                    Image(systemName: "arrow.clockwise")
                }

                Button(action: { showShareSheet = true }) {
                    Image(systemName: "square.and.arrow.up")
                }

                Button(action: clearLog) {
                    Image(systemName: "trash")
                        .foregroundColor(.red)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            // Log content
            ScrollViewReader { proxy in
                ScrollView {
                    Text(logText)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .id("logBottom")
                }
                .onChange(of: logText) { _ in
                    if autoRefresh {
                        withAnimation {
                            proxy.scrollTo("logBottom", anchor: .bottom)
                        }
                    }
                }
            }
        }
        .navigationTitle("Debug Log")
        .onAppear { refreshLog() }
        .onReceive(timer) { _ in
            if autoRefresh { refreshLog() }
        }
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(text: logText)
        }
    }

    private func refreshLog() {
        DebugLogger.shared.flush()
        logText = DebugLogger.shared.readLog()
    }

    private func clearLog() {
        DebugLogger.shared.clearLog()
        logText = ""
    }
}

/// UIKit share sheet wrapper
struct ShareSheet: UIViewControllerRepresentable {
    let text: String

    func makeUIViewController(context: Context) -> UIActivityViewController {
        // Write to temp file for sharing
        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("DPIBypass_debug_log.txt")
        try? text.write(to: tempURL, atomically: true, encoding: .utf8)
        return UIActivityViewController(activityItems: [tempURL], applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
