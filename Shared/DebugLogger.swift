import Foundation

/// Shared debug logger — writes to App Group file so both app and extension can access
/// Extension writes logs, App reads and displays them
public class DebugLogger {
    public static let shared = DebugLogger()

    private let fileManager = FileManager.default
    private let maxLines = 5000
    private let queue = DispatchQueue(label: "com.voiplet.dpibypass.logger")

    private var logURL: URL? {
        fileManager
            .containerURL(forSecurityApplicationGroupIdentifier: DPIConfiguration.appGroupID)?
            .appendingPathComponent("debug_log.txt")
    }

    private var buffer: [String] = []
    private var flushTimer: DispatchSourceTimer?

    private init() {
        // Flush buffer to disk every 2 seconds
        flushTimer = DispatchSource.makeTimerSource(queue: queue)
        flushTimer?.schedule(deadline: .now(), repeating: .seconds(2))
        flushTimer?.setEventHandler { [weak self] in
            self?.flushToDisk()
        }
        flushTimer?.resume()
    }

    // MARK: - Write

    public func log(_ message: String, file: String = #file, function: String = #function) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let fileName = (file as NSString).lastPathComponent.replacingOccurrences(of: ".swift", with: "")
        let entry = "[\(timestamp)] [\(fileName).\(function)] \(message)"

        queue.async { [weak self] in
            self?.buffer.append(entry)
        }

        #if DEBUG
        print(entry)
        #endif
    }

    public func logPacket(direction: String, proto: String, srcIP: String, srcPort: UInt16,
                          dstIP: String, dstPort: UInt16, size: Int, action: String) {
        let msg = "\(direction) \(proto) \(srcIP):\(srcPort) → \(dstIP):\(dstPort) [\(size)B] \(action)"
        log(msg)
    }

    public func logError(_ message: String, file: String = #file, function: String = #function) {
        log("ERROR: \(message)", file: file, function: function)
    }

    // MARK: - Flush

    private func flushToDisk() {
        guard !buffer.isEmpty, let url = logURL else { return }

        let lines = buffer
        buffer.removeAll()

        do {
            var existing = ""
            if fileManager.fileExists(atPath: url.path) {
                existing = try String(contentsOf: url, encoding: .utf8)
            }

            let newContent = existing + lines.joined(separator: "\n") + "\n"

            // Trim if too long
            let allLines = newContent.components(separatedBy: "\n")
            let trimmed: String
            if allLines.count > maxLines {
                trimmed = allLines.suffix(maxLines).joined(separator: "\n")
            } else {
                trimmed = newContent
            }

            try trimmed.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            // Can't log the error about logging...
        }
    }

    // MARK: - Read (called from App)

    public func readLog() -> String {
        guard let url = logURL else { return "Log file not available" }
        return (try? String(contentsOf: url, encoding: .utf8)) ?? "No logs yet"
    }

    public func clearLog() {
        guard let url = logURL else { return }
        try? "".write(to: url, atomically: true, encoding: .utf8)
    }

    /// Force flush (call before reading)
    public func flush() {
        queue.sync {
            flushToDisk()
        }
    }
}
