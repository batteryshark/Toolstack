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

public struct CallersResponse: Codable, Sendable {
    public let callers: [Caller]
}

public struct CreatedCaller: Codable, Sendable {
    public let name: String
    public let token: String   // shown once (create + rotate)
}

public struct RevokeResult: Codable, Sendable {
    public let name: String   // the revoke response is otherwise ignored
}

public struct OpInfo: Codable, Sendable, Identifiable, Equatable {
    public let op: String
    public let risk: String
    public let description: String
    public var id: String { op }
}

/// A tool's secret DECLARATION (not a value): the file the tool reads (`name`), the backend
/// `field` it resolves from, whether the tool may write it back, and the Infisical vault/item.
public struct SecretDecl: Codable, Sendable, Identifiable, Equatable {
    public let name: String
    public let field: String
    public let writable: Bool
    public let vault: String?
    public let item: String?
    public var id: String { name }

    public init(name: String, field: String, writable: Bool,
                vault: String? = nil, item: String? = nil) {
        self.name = name; self.field = field; self.writable = writable
        self.vault = vault; self.item = item
    }
}

/// Where a managed tool came from (the `.tsr-source.json` sidecar) — present only for tools added
/// through TSR, enabling "Update". `source` is set for a local-path tool; `url`/`subdir`/`ref` for
/// a github one.
public struct ToolSource: Codable, Sendable, Equatable {
    public let type: String      // "path" | "github"
    public let source: String?
    public let url: String?
    public let subdir: String?
    public let ref: String?
}

public struct ToolInfo: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let type: String
    public let description: String
    public let port: Int?
    public let running: Bool
    public let ops: [OpInfo]
    public let secrets: [SecretDecl]
    public let source: ToolSource?   // nil for hand-authored tools (no sidecar) → no Update

    enum CodingKeys: String, CodingKey { case id, type, description, port, running, ops, secrets, source }

    // Tolerate an admin that doesn't report `description` / `ops` / `running` / `secrets` / `source`
    // (e.g. an older version, or a different deployment) rather than failing the whole response.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        type = try c.decodeIfPresent(String.self, forKey: .type) ?? "api"
        description = try c.decodeIfPresent(String.self, forKey: .description) ?? ""
        port = try c.decodeIfPresent(Int.self, forKey: .port)
        running = try c.decodeIfPresent(Bool.self, forKey: .running) ?? false
        ops = try c.decodeIfPresent([OpInfo].self, forKey: .ops) ?? []
        secrets = try c.decodeIfPresent([SecretDecl].self, forKey: .secrets) ?? []
        source = try c.decodeIfPresent(ToolSource.self, forKey: .source)
    }
}

/// The echo returned by `POST /api/tools/{id}` — the edited fields only (ops/entrypoint are
/// preserved server-side and re-fetched via `listTools`).
public struct ToolEdit: Codable, Sendable {
    public let id: String
    public let description: String
    public let secrets: [SecretDecl]
}

/// What `POST /api/tools` returns after copying a tool's folder into the managed tools dir.
public struct CreatedTool: Codable, Sendable {
    public let id: String
    public let type: String
    public let description: String
    public let path: String   // where it now lives under the broker's tools dir
}

/// Result of removing a managed tool (`DELETE /api/tools/{id}`).
public struct RemovedTool: Codable, Sendable {
    public let removed: String
}

/// The active secret backend (deployment-wide). `path` (file/vault) or `host`/`environment`/
/// `defaultVault` (Infisical) are present depending on `name`.
public struct SecretBackend: Codable, Sendable {
    public let name: String   // "file" | "vault" | "infisical"
    public let path: String?
    public let host: String?
    public let environment: String?
    public let defaultVault: String?
}

public struct ToolsResponse: Codable, Sendable {
    public let tools: [ToolInfo]
    public let error: String?
}

/// A caller's policy: tool -> op -> effect ("allow" | "review"). An op absent from the map is
/// denied. (Dictionary keys are tool/op names, untouched by `.convertFromSnakeCase`.)
public struct Policy: Codable, Sendable, Equatable {
    public let tools: [String: [String: String]]
    public init(tools: [String: [String: String]] = [:]) { self.tools = tools }

    public func effect(tool: String, op: String) -> Effect {
        Effect(rawValue: tools[tool]?[op] ?? "deny") ?? .deny
    }
}

public enum Effect: String, Sendable, CaseIterable, Identifiable {
    case deny, review, allow
    public var id: String { rawValue }
}

public struct PolicyResponse: Codable, Sendable {
    public let name: String
    public let policy: Policy
    public let enabled: [String]   // tools this caller is enabled for (gates the policy editor)
}

public struct EnabledTools: Codable, Sendable {
    public let name: String
    public let enabled: [String]
}

/// The broker run-config (GET /api/config — masked). `nodToken` is "set" / "not set", never the
/// real token. (db_path / tool_dirs are also returned but ignored here.)
public struct BrokerConfigInfo: Codable, Sendable {
    public let port: Int
    public let toolsRoot: String
    public let nodUrl: String
    public let nodToken: String
    public let nodChannel: String
    public let approvalTtl: Int
    public let rateLimit: Int
    public var nodTokenSet: Bool { nodToken == "set" }
}

/// A decoded arbitrary JSON value — audit `details` can be any shape. Rendered compactly for a cell.
public indirect enum AnyJSON: Decodable, Sendable, Equatable {
    case string(String), number(Double), bool(Bool), object([String: AnyJSON]), array([AnyJSON]), null

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }       // before number: JSON true/false
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let o = try? c.decode([String: AnyJSON].self) { self = .object(o) }
        else if let a = try? c.decode([AnyJSON].self) { self = .array(a) }
        else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "unsupported JSON value") }
    }

    /// Compact one-line rendering for a table cell (not strict JSON — readability over fidelity).
    public var compact: String {
        switch self {
        case .string(let s): return s
        case .number(let n): return n == n.rounded() ? String(Int(n)) : String(n)
        case .bool(let b): return b ? "true" : "false"
        case .null: return "null"
        case .array(let a): return "[" + a.map(\.compact).joined(separator: ", ") + "]"
        case .object(let o):
            return "{" + o.sorted { $0.key < $1.key }
                .map { "\($0.key): \($0.value.compact)" }.joined(separator: ", ") + "}"
        }
    }
}

/// One audit event (admin.* or broker.*). `details` is free-form. (snake_case → camelCase.)
public struct AuditEvent: Decodable, Sendable, Identifiable, Equatable {
    public let id: Int
    public let at: Double
    public let component: String
    public let eventType: String
    public let outcome: String
    public let correlationId: String?
    public let requestId: Int?
    public let details: AnyJSON?
}

/// One broker request row (a caller's tool.op call + its status). Extra columns are ignored.
public struct RequestRow: Codable, Sendable, Identifiable, Equatable {
    public let id: Int
    public let correlationId: String
    public let callerId: Int
    public let tool: String
    public let op: String
    public let status: String
    public let error: String?
    public let createdAt: Double
    public let updatedAt: Double?
}

public struct AuditResponse: Decodable, Sendable {
    public let audit: [AuditEvent]
    public let requests: [RequestRow]
}

/// Set/unset status for a tool's declared secret fields. `settable` is true only for the local
/// vault backend; `provisioned` lists the fields that currently have a value (never the values).
public struct SecretStatus: Codable, Sendable, Equatable {
    public let backend: String
    public let settable: Bool
    public let fields: [String]
    public let provisioned: [String]
}

public struct SetSecretResult: Codable, Sendable {
    public let field: String
    public let set: Bool
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
