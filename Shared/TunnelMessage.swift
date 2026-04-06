import Foundation

/// IPC messages between main app and tunnel extension
public enum TunnelMessage: Codable {
    // App → Extension
    case getStatus
    case getStatistics
    case updateConfiguration(DPIConfiguration)
    case startLogging
    case stopLogging

    // Extension → App
    case status(TunnelStatus)
    case statistics(TunnelStatistics)
    case logEntry(LogEntry)

    public func encode() -> Data? {
        try? JSONEncoder().encode(self)
    }

    public static func decode(from data: Data) -> TunnelMessage? {
        try? JSONDecoder().decode(TunnelMessage.self, from: data)
    }
}

public enum TunnelStatus: String, Codable {
    case connected
    case connecting
    case disconnected
    case error
}

public struct TunnelStatistics: Codable {
    public var totalPackets: UInt64 = 0
    public var modifiedPackets: UInt64 = 0
    public var httpModified: UInt64 = 0
    public var httpsFragmented: UInt64 = 0
    public var dnsRedirected: UInt64 = 0
    public var passiveDPIBlocked: UInt64 = 0
    public var bytesIn: UInt64 = 0
    public var bytesOut: UInt64 = 0
    public var activeConnections: Int = 0
    public var uptime: TimeInterval = 0
}

public struct LogEntry: Codable {
    public let timestamp: Date
    public let domain: String
    public let technique: String
    public let direction: Direction
    public let port: UInt16
    public let result: String

    public enum Direction: String, Codable {
        case outbound
        case inbound
    }
}
