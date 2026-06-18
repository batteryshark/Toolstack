import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Typed client for the admin's JSON operator API (admin/api.py). An `actor` so the bearer
/// token is mutated/read safely from any task. Auth is a bearer token from `login(...)`; the
/// token is held here and (in the app) persisted to the Keychain via `TokenStore`.
///
/// Injectable `baseURL` + `URLSession` so tests drive it through a stubbed `URLProtocol`
/// (no real server, no real admin) — see ToolstackKitTests.
public actor ApiClient {
    private let baseURL: URL
    private let session: URLSession
    private var token: String?

    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()

    public init(baseURL: URL = URL(string: "http://127.0.0.1:8780")!,
                session: URLSession = .shared,
                token: String? = nil) {
        self.baseURL = baseURL
        self.session = session
        self.token = token
    }

    public var isAuthenticated: Bool { token != nil }

    /// Restore a previously stored token (e.g. from the Keychain on launch).
    public func setToken(_ token: String?) { self.token = token }

    // --- endpoints ------------------------------------------------------------

    @discardableResult
    public func login(password: String) async throws -> String {
        let resp: LoginResponse = try await send("POST", "/api/login",
                                                 body: ["password": password], authed: false)
        token = resp.token
        return resp.token
    }

    public func brokerStatus() async throws -> BrokerStatus {
        try await send("GET", "/api/broker")
    }

    /// `action` is "start", "stop", or "restart". Returns the resulting status.
    public func brokerAction(_ action: String) async throws -> BrokerStatus {
        try await send("POST", "/api/broker/\(action)", body: [:])
    }

    public func listCallers() async throws -> CallersResponse {
        try await send("GET", "/api/callers")
    }

    public func createCaller(name: String, allow: [String] = [],
                             review: [String] = []) async throws -> CreatedCaller {
        try await send("POST", "/api/callers",
                       body: ["name": name, "allow": allow, "review": review])
    }

    /// Replace the caller's token with a fresh one (one active token per caller). Shown once.
    @discardableResult
    public func rotateToken(caller: String) async throws -> CreatedCaller {
        try await send("POST", "/api/callers/\(caller)/rotate-token", body: [:])
    }

    @discardableResult
    public func revokeCaller(_ caller: String) async throws -> RevokeResult {
        try await send("POST", "/api/callers/\(caller)/revoke", body: [:])
    }

    public func config() async throws -> BrokerConfigInfo {
        try await send("GET", "/api/config")
    }

    /// Save broker settings. `nodToken` is sent only when non-nil/non-empty (write-only — an
    /// omitted token keeps the stored one).
    @discardableResult
    public func saveConfig(port: Int, toolsRoot: String, nodURL: String, nodChannel: String,
                           nodToken: String?, approvalTTL: Int, rateLimit: Int) async throws -> BrokerConfigInfo {
        var body: [String: Any] = [
            "port": port, "tools_root": toolsRoot, "nod_url": nodURL, "nod_channel": nodChannel,
            "approval_ttl": approvalTTL, "rate_limit": rateLimit,
        ]
        if let nodToken, !nodToken.isEmpty { body["nod_token"] = nodToken }
        return try await send("POST", "/api/config", body: body)
    }

    public func listTools() async throws -> [ToolInfo] {
        let response: ToolsResponse = try await send("GET", "/api/tools")
        return response.tools
    }

    public func secretBackend() async throws -> SecretBackend {
        try await send("GET", "/api/secret-backend")
    }

    public func policy(for caller: String) async throws -> PolicyResponse {
        try await send("GET", "/api/callers/\(caller)/policy")
    }

    /// Replace a caller's policy. `allow`/`review` are `tool.op` specs; an op in neither is denied.
    @discardableResult
    public func setPolicy(caller: String, allow: [String], review: [String]) async throws -> PolicyResponse {
        try await send("PUT", "/api/callers/\(caller)/policy", body: ["allow": allow, "review": review])
    }

    /// Set which tools a caller is enabled for (gates the policy editor). Returns the new list.
    @discardableResult
    public func setEnabledTools(caller: String, enabled: [String]) async throws -> [String] {
        let result: EnabledTools = try await send("PUT", "/api/callers/\(caller)/tools",
                                                  body: ["enabled": enabled])
        return result.enabled
    }

    // --- transport ------------------------------------------------------------

    private func send<T: Decodable>(_ method: String, _ path: String,
                                    body: [String: Any]? = nil, authed: Bool = true) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = method
        if authed, let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }

        let data: Data, response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw ApiError.transport(error.localizedDescription)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            if status == 401 { throw ApiError.unauthorized }
            throw ApiError.http(status: status, message: Self.serverMessage(data))
        }
        // Every operator endpoint returns a JSON object on success (errors use HTTPException),
        // so a 2xx always has a body to decode. A future 204/empty-body route would need a
        // separate path here.
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw ApiError.decoding(error.localizedDescription)
        }
    }

    /// FastAPI errors are `{"detail": "..."}`; fall back to the raw text.
    private static func serverMessage(_ data: Data) -> String {
        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let detail = obj["detail"] as? String {
            return detail
        }
        return String(data: data, encoding: .utf8) ?? ""
    }
}
