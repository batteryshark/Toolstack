import Foundation
import SwiftUI
import ToolstackKit

/// The app's single source of UI state. Wraps the `ApiClient` (an actor) and republishes
/// results on the main actor for SwiftUI. The bearer token lives in the client for the
/// session (Keychain persistence is a T-031 item). Auth errors drop back to the login screen.
@MainActor
final class AppModel: ObservableObject {
    @Published var authenticated = false
    @Published var broker: BrokerStatus?
    @Published var callers: [Caller] = []
    @Published var tokens: [TokenInfo] = []
    @Published var tools: [ToolInfo] = []
    @Published var banner: String?   // e.g. a freshly minted token to copy once
    @Published var error: String?
    @Published var busy = false

    /// The admin URL the user signs in against — editable on the login screen, remembered
    /// across launches. Works for a local admin (the default) or a remote one (a tailnet /
    /// tunnelled homeserver), as long as it's reachable.
    @Published var serverURL: String
    private var client: ApiClient
    private static let urlDefaultsKey = "ToolstackAdminURL"

    init() {
        let saved = UserDefaults.standard.string(forKey: AppModel.urlDefaultsKey)
        self.serverURL = saved ?? AppModel.adminURL().absoluteString
        self.client = ApiClient(baseURL: AppModel.adminURL())  // rebuilt from serverURL on login
    }

    /// The default admin URL — `$TOOLSTACK_ADMIN_URL` or loopback.
    nonisolated static func adminURL() -> URL {
        if let raw = ProcessInfo.processInfo.environment["TOOLSTACK_ADMIN_URL"],
           let url = URL(string: raw) { return url }
        return URL(string: "http://127.0.0.1:8780")!
    }

    func login(password: String) async {
        let trimmed = serverURL.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: trimmed), url.scheme != nil, url.host != nil else {
            error = "Enter a valid admin URL — e.g. http://127.0.0.1:8780"
            return
        }
        serverURL = trimmed
        UserDefaults.standard.set(trimmed, forKey: AppModel.urlDefaultsKey)
        client = ApiClient(baseURL: url)   // point at whatever admin the user entered
        await run {
            _ = try await self.client.login(password: password)
            self.authenticated = true
            await self.refreshAll()
        }
    }

    func logout() async {
        await client.setToken(nil)
        authenticated = false
        broker = nil; callers = []; tokens = []; banner = nil
    }

    func refreshAll() async {
        await refreshBroker()
        await refreshCallers()
        await refreshTools()
    }

    func refreshTools() async {
        await run { self.tools = try await self.client.listTools() }
    }

    func updateTool(id: String, description: String, secrets: [SecretDecl]) async {
        await run {
            _ = try await self.client.updateTool(id: id, description: description, secrets: secrets)
            await self.refreshTools()
            self.banner = "Saved \(id). Restart the tool if you changed its secrets."
        }
    }

    /// Re-pull a tool from its recorded source, keeping the operator's description/secret edits.
    func resyncTool(id: String) async {
        await run {
            _ = try await self.client.resyncTool(id: id)
            await self.refreshTools()
            self.banner = "Updated \(id) from its source. Restart the broker if its entrypoint or operations changed."
        }
    }

    /// Add a tool by copying a local folder into the broker's tools dir.
    func addTool(source: String) async {
        await performAdd { try await self.client.addTool(source: source) }
    }

    /// Add a tool by cloning a git repo (optionally a subdir, at a branch/tag) into the tools dir.
    func addToolFromGitHub(repo: String, subdir: String, ref: String) async {
        await performAdd { try await self.client.addToolFromGitHub(repo: repo, subdir: subdir, ref: ref) }
    }

    /// Shared add bookkeeping. A source without a toolyard.toml comes back 422 — surfaced as a
    /// friendly note (in-app authoring is the next step) rather than a raw server error.
    private func performAdd(_ op: @escaping () async throws -> CreatedTool) async {
        busy = true
        error = nil
        do {
            let created = try await op()
            await refreshTools()
            banner = "Added \(created.id). Restart the broker to register it, then grant a caller access."
        } catch ApiError.http(422, _) {
            error = "No toolyard.toml at that location — it's code, not a tool yet. "
                  + "Authoring a manifest in-app is the next step."
        } catch ApiError.unauthorized {
            authenticated = false
            error = ApiError.unauthorized.message
        } catch let apiError as ApiError {
            error = apiError.message
        } catch let other {
            error = other.localizedDescription
        }
        busy = false
    }

    @Published var secretBackend: SecretBackend?

    func refreshSecretBackend() async {
        await run { self.secretBackend = try await self.client.secretBackend() }
    }

    @Published var config: BrokerConfigInfo?

    func refreshConfig() async {
        await run { self.config = try await self.client.config() }
    }

    func saveConfig(port: Int, toolsRoot: String, nodURL: String, nodChannel: String,
                    nodToken: String?, approvalTTL: Int, rateLimit: Int) async {
        await run {
            self.config = try await self.client.saveConfig(
                port: port, toolsRoot: toolsRoot, nodURL: nodURL, nodChannel: nodChannel,
                nodToken: nodToken, approvalTTL: approvalTTL, rateLimit: rateLimit)
            self.banner = "Saved broker config. Restart the broker to apply."
        }
    }

    /// Load one caller's policy + enabled tools for the editors (returns it rather than storing).
    func loadPolicy(for caller: String) async -> PolicyResponse? {
        do {
            return try await client.policy(for: caller)
        } catch let apiError as ApiError {
            if case .unauthorized = apiError { authenticated = false }
            error = apiError.message
            return nil
        } catch let other {
            error = other.localizedDescription
            return nil
        }
    }

    func setEnabledTools(caller: String, enabled: [String]) async {
        await run {
            _ = try await self.client.setEnabledTools(caller: caller, enabled: enabled)
            await self.refreshCallers()
        }
    }

    func rotateToken(caller: String) async {
        await run {
            let result = try await self.client.rotateToken(caller: caller)
            self.banner = "New token for \(result.name) — copy it now, it won't be shown again:\n\(result.token)"
            await self.refreshCallers()
        }
    }

    func revokeCaller(_ caller: String) async {
        await run {
            _ = try await self.client.revokeCaller(caller)
            await self.refreshCallers()
        }
    }

    func savePolicy(caller: String, allow: [String], review: [String]) async {
        await run {
            _ = try await self.client.setPolicy(caller: caller, allow: allow, review: review)
            await self.refreshCallers()
        }
    }

    func refreshBroker() async {
        await run { self.broker = try await self.client.brokerStatus() }
    }

    func brokerAction(_ action: String) async {
        await run { self.broker = try await self.client.brokerAction(action) }
    }

    func refreshCallers() async {
        await run {
            let response = try await self.client.listCallers()
            self.callers = response.callers
            self.tokens = response.tokens
        }
    }

    func createCaller(name: String) async {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        await run {
            let created = try await self.client.createCaller(name: trimmed)
            self.banner = "Token for \(created.name) — copy it now, it won't be shown again:\n\(created.token)"
            await self.refreshCallers()
        }
    }

    /// Run an async operation with busy/error bookkeeping; an `unauthorized` drops to login.
    private func run(_ operation: @escaping () async throws -> Void) async {
        busy = true
        error = nil
        do {
            try await operation()
        } catch let apiError as ApiError {
            if case .unauthorized = apiError { authenticated = false }
            error = apiError.message
        } catch let other {
            error = other.localizedDescription
        }
        busy = false
    }
}
