import Foundation

// JSON shapes from the admin's operator API (admin/api.py). The decoder uses
// `.convertFromSnakeCase`, so JSON `token_hash` / `revoked_at` map to camelCase here.

public struct LoginResponse: Codable, Sendable {
    public let token: String
    public let username: String
}

public struct BrokerStatus: Codable, Sendable, Equatable {
    public let running: Bool
    public let pid: Int?
    public let port: Int?
    public let healthy: Bool?

    public init(running: Bool, pid: Int? = nil, port: Int? = nil, healthy: Bool? = nil) {
        self.running = running; self.pid = pid; self.port = port; self.healthy = healthy
    }
}

public struct Caller: Codable, Sendable, Identifiable, Equatable {
    public let id: Int
    public let name: String
    public let revokedAt: Double?   // null when active (extra columns are ignored)
    public var isActive: Bool { revokedAt == nil }
}

public struct TokenInfo: Codable, Sendable, Identifiable, Equatable {
    public let tokenHash: String
    public let caller: String
    public let createdAt: Double?
    public let revokedAt: Double?
    public var id: String { tokenHash }
}

public struct CallersResponse: Codable, Sendable {
    public let callers: [Caller]
    public let tokens: [TokenInfo]
}

public struct CreatedCaller: Codable, Sendable {
    public let name: String
    public let token: String   // shown once
}

/// What went wrong talking to the admin API. `unauthorized` is special-cased so the UI can
/// drop back to the login screen; everything else carries a status + server message.
public enum ApiError: Error, Equatable, Sendable {
    case unauthorized
    case http(status: Int, message: String)
    case transport(String)
    case decoding(String)
}

extension ApiError {
    public var message: String {
        switch self {
        case .unauthorized: return "Not signed in (or the session expired)."
        case .http(let status, let message): return "Server error \(status): \(message)"
        case .transport(let m): return "Can't reach the admin: \(m)"
        case .decoding(let m): return "Unexpected response: \(m)"
        }
    }
}
